using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Core.Otp;

namespace SimplySignAuto.Agent.SimplySign;

public interface ISimplySignClock
{
    DateTimeOffset UtcNow { get; }

    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public interface ISimplySignSessionDriver
{
    int VerifiedSessionId { get; }

    DateTimeOffset UtcNow { get; }

    SimplySignProcessState CheckProcessOnly();

    Task CloseAsync(CancellationToken cancellationToken);

    Task<OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken);

    Task DeleteOtpAsync(CancellationToken cancellationToken) =>
        Task.FromException(new SimplySignException("simplysign_configuration_invalid"));

    Task<long> StartLoginAsync(OtpauthProfile profile, CancellationToken cancellationToken);

    Task WaitForCounterAfterAsync(
        OtpauthProfile profile,
        long priorCounter,
        CancellationToken cancellationToken);

    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class SystemSimplySignClock : ISimplySignClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

public sealed class SimplySignController : ISimplySignSessionDriver, IDisposable
{
    private static readonly TimeSpan CloseCommandTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan CloseWaitTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MinimumOtpLifetime = TimeSpan.FromSeconds(3);

    private readonly ISimplySignProbe _probe;
    private readonly IProcessRunner _processRunner;
    private readonly ISimplySignProcessSource _processSource;
    private readonly IOtpStore _otpStore;
    private readonly ISimplySignClock _clock;
    private readonly string _desktopExecutable;
    private readonly IAgentDiagnosticSink _diagnostics;

    public SimplySignController(
        ISimplySignProbe probe,
        IProcessRunner processRunner,
        ISimplySignProcessSource processSource,
        IOtpStore otpStore,
        ISimplySignClock clock,
        InteractiveSessionInfo verifiedSession,
        string desktopExecutable,
        IAgentDiagnosticSink? diagnostics = null)
    {
        _probe = probe ?? throw new ArgumentNullException(nameof(probe));
        _processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        _processSource = processSource ?? throw new ArgumentNullException(nameof(processSource));
        _otpStore = otpStore ?? throw new ArgumentNullException(nameof(otpStore));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _diagnostics = diagnostics.Safe();
        ArgumentNullException.ThrowIfNull(verifiedSession);
        if (verifiedSession.SessionId <= 0 ||
            string.IsNullOrWhiteSpace(desktopExecutable) ||
            !Path.IsPathFullyQualified(desktopExecutable))
        {
            throw new SimplySignException("simplysign_configuration_invalid");
        }

        VerifiedSessionId = verifiedSession.SessionId;
        _desktopExecutable = Path.GetFullPath(desktopExecutable);
    }

    public int VerifiedSessionId { get; }

    public DateTimeOffset UtcNow => _clock.UtcNow;

    public SimplySignProcessState CheckProcessOnly() =>
        _processSource.Read(VerifiedSessionId);

    public async Task CloseAsync(CancellationToken cancellationToken)
    {
        var close = await _processRunner.RunAsync(
            _desktopExecutable,
            ["/close"],
            CloseCommandTimeout,
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (close.Termination == ProcessTermination.LaunchFailed)
        {
            _diagnostics.Report(new AgentDiagnostic(
                "simplysign_close",
                "simplysign_exe_missing",
                close.FailureException,
                close));
            throw new SimplySignException("simplysign_exe_missing");
        }

        var deadline = _clock.UtcNow + CloseWaitTimeout;
        while (_processSource.IsRunningInSession(VerifiedSessionId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = deadline - _clock.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                throw new SimplySignException("simplysign_close_timeout");
            }

            await _clock.DelayAsync(
                remaining < ProbeInterval ? remaining : ProbeInterval,
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken) =>
        _otpStore.LoadAsync(cancellationToken);

    public Task DeleteOtpAsync(CancellationToken cancellationToken) =>
        _otpStore.DeleteAsync(cancellationToken);

    public async Task<long> StartLoginAsync(
        OtpauthProfile profile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var counter = await WaitForSafeCurrentWindowAsync(profile, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var otp = TotpGenerator.Generate(profile, _clock.UtcNow);
        var launch = await _processRunner.StartDetachedAsync(
            _desktopExecutable,
            ["/autologin", profile.Account, otp],
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!launch.Started)
        {
            _diagnostics.Report(
                new AgentDiagnostic(
                    "simplysign_login_launch",
                    "simplysign_exe_missing",
                    launch.FailureException),
                profile.Secret);
            throw new SimplySignException("simplysign_exe_missing");
        }

        return counter;
    }

    public async Task WaitForCounterAfterAsync(
        OtpauthProfile profile,
        long priorCounter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var periodTicks = TimeSpan.FromSeconds(profile.Period).Ticks;
        var currentTicks = checked((_clock.UtcNow - DateTimeOffset.UnixEpoch).Ticks);
        var targetTicks = checked((priorCounter + 1) * periodTicks);
        if (currentTicks < targetTicks)
        {
            await _clock.DelayAsync(
                TimeSpan.FromTicks(targetTicks - currentTicks),
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        _clock.DelayAsync(delay, cancellationToken);

    public void Dispose() => GC.SuppressFinalize(this);

    private async Task<long> WaitForSafeCurrentWindowAsync(
        OtpauthProfile profile,
        CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var elapsedTicks = checked((now - DateTimeOffset.UnixEpoch).Ticks);
        var periodTicks = TimeSpan.FromSeconds(profile.Period).Ticks;
        var currentCounter = elapsedTicks / periodTicks;
        var remaining = TimeSpan.FromTicks(periodTicks - (elapsedTicks % periodTicks));
        if (remaining < MinimumOtpLifetime)
        {
            await _clock.DelayAsync(remaining, cancellationToken).ConfigureAwait(false);
            now = _clock.UtcNow;
            currentCounter = checked((now - DateTimeOffset.UnixEpoch).Ticks) / periodTicks;
        }

        return currentCounter;
    }
}
