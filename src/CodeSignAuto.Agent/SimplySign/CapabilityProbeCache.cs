using CodeSignAuto.Protocol;
using CodeSignAuto.Agent.Diagnostics;
using CodeSignAuto.Agent.Signing;

namespace CodeSignAuto.Agent.SimplySign;

public sealed class CapabilityProbeCache : IDisposable
{
    private const int InstalledPdfCatalogCompletionAttempts = 5;
    private readonly object _stateSync = new();
    private readonly ISimplySignSessionManager _manager;
    private readonly int _verifiedSessionId;
    private readonly bool _authenticodeConfigured;
    private readonly bool _pdfConfigured;
    private readonly IInstalledPdfToolResolver? _pdfToolResolver;
    private readonly IAgentDiagnosticSink _diagnostics;
    private readonly Queue<SessionTransitionEvidence> _sessionTransitions = new();
    private CacheState _state;
    private long _nextTransitionSequence = 1;
    private int _batchDepth;
    private int _disposed;

    public CapabilityProbeCache(
        ISimplySignSessionManager manager,
        int verifiedSessionId,
        bool authenticodeConfigured,
        bool pdfConfigured,
        IAgentDiagnosticSink? diagnostics = null,
        IInstalledPdfToolResolver? pdfToolResolver = null)
    {
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        if (verifiedSessionId <= 0 || !authenticodeConfigured && !pdfConfigured)
        {
            throw new ArgumentException("At least one configured capability and a verified session are required.");
        }

        _verifiedSessionId = verifiedSessionId;
        _authenticodeConfigured = authenticodeConfigured;
        _pdfConfigured = pdfConfigured;
        _pdfToolResolver = pdfToolResolver;
        _diagnostics = diagnostics.Safe();
        _state = CaptureCompleteState();
        _manager.SnapshotChanged += OnManagerSnapshotChanged;
        ReplaceState(CaptureCompleteState());
    }

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(SessionTrigger.ManualRefresh, cancellationToken).ConfigureAwait(false);
    }

    public async Task RunHealthCheckAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _ = await _manager.CheckAsync(SessionTrigger.BackgroundHealth, cancellationToken).ConfigureAwait(false);
        await RefreshPdfToolResolutionAsync(cancellationToken).ConfigureAwait(false);
        ReplaceState(CaptureCompleteState());
    }

    private async Task RefreshAsync(
        SessionTrigger trigger,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        Interlocked.Increment(ref _batchDepth);
        try
        {
            _ = await _manager.CheckAsync(trigger, cancellationToken).ConfigureAwait(false);
            await RefreshPdfToolResolutionAsync(cancellationToken).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();
            ReplaceState(CaptureCompleteState());
        }
        finally
        {
            Interlocked.Decrement(ref _batchDepth);
        }
    }

    public async Task ReloginAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        Interlocked.Increment(ref _batchDepth);
        try
        {
            _ = await _manager.EnsureReadyAsync(
                SessionTrigger.ManualRelogin,
                cancellationToken).ConfigureAwait(false);
            await RefreshPdfToolResolutionAsync(cancellationToken).ConfigureAwait(false);
            await CompleteInstalledPdfCatalogAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            ReplaceState(CaptureCompleteState());
        }
        finally
        {
            Interlocked.Decrement(ref _batchDepth);
        }
    }

    public async Task ClearOtpAndLogoutAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        Interlocked.Increment(ref _batchDepth);
        try
        {
            _ = await _manager.ClearOtpAndLogoutAsync(cancellationToken).ConfigureAwait(false);
            await RefreshPdfToolResolutionAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            ReplaceState(CaptureCompleteState());
        }
        finally
        {
            Interlocked.Decrement(ref _batchDepth);
        }
    }

    public async Task LogoutAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        Interlocked.Increment(ref _batchDepth);
        try
        {
            _ = await _manager.LogoutAsync(cancellationToken).ConfigureAwait(false);
            await RefreshPdfToolResolutionAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            ReplaceState(CaptureCompleteState());
        }
        finally
        {
            Interlocked.Decrement(ref _batchDepth);
        }
    }

    public async Task<PrepareSimplySignSessionResult> PrepareStartupAsync(
        PrepareSimplySignSessionCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        try
        {
            var snapshot = await _manager.PrepareStartupAsync(cancellationToken).ConfigureAwait(false);
            await RefreshPdfToolResolutionAsync(cancellationToken).ConfigureAwait(false);
            await CompleteInstalledPdfCatalogAsync(cancellationToken).ConfigureAwait(false);
            ReplaceState(CaptureCompleteState());
            return snapshot.Ready
                ? new PrepareSimplySignSessionResult(command.RequestId, SimplySignSessionState.Ready, null)
                : new PrepareSimplySignSessionResult(
                    command.RequestId,
                    SimplySignSessionState.Failed,
                    "simplysign_login_failed");
        }
        catch (Signing.SigningException error) when (error.Code == "certificate_catalog_unavailable")
        {
            _diagnostics.Report(new AgentDiagnostic(
                "startup_catalog",
                "certificate_catalog_unavailable",
                error));
            return new PrepareSimplySignSessionResult(
                command.RequestId,
                SimplySignSessionState.Failed,
                "certificate_catalog_unavailable");
        }
        catch (SimplySignException error)
        {
            _diagnostics.Report(new AgentDiagnostic(
                "startup_login",
                "simplysign_login_failed",
                error));
            return new PrepareSimplySignSessionResult(
                command.RequestId,
                SimplySignSessionState.Failed,
                "simplysign_login_failed");
        }
    }

    public AgentHeartbeat CreateHeartbeat(Guid? currentJobId)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        CacheState state;
        SessionTransitionEvidence[] transitions;
        lock (_stateSync)
        {
            state = _state;
            transitions = _sessionTransitions.ToArray();
        }

        var configured = new[] { state.Authenticode, state.Pdf }
            .Where(static capability => capability.Configured)
            .ToArray();
        var processReady = state.ProcessRunning && state.ProcessSessionId == _verifiedSessionId;
        return new AgentHeartbeat(
            _verifiedSessionId,
            processReady ? "ready" : "not_ready",
            configured.All(static capability => capability.TokenPresent && capability.TokenMatches)
                ? "ready"
                : "not_ready",
            configured.All(static capability => capability.CertificatePresent && capability.CertificateMatches)
                ? "ready"
                : "not_ready",
            configured.All(static capability => capability.PrivateKeyPresent && capability.PrivateKeyMatches)
                ? "ready"
                : "not_ready",
            currentJobId,
            state.ProcessRunning ? state.ProcessSessionId : null,
            state.Authenticode,
            state.Pdf,
            state.SessionGeneration,
            transitions,
            state.Certificates);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _manager.SnapshotChanged -= OnManagerSnapshotChanged;
        }
    }

    private void OnManagerSnapshotChanged(
        object? sender,
        SimplySignSessionSnapshot snapshot)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        lock (_stateSync)
        {
            AppendTransitionUnsafe(snapshot);
            if (snapshot.SessionGeneration == _state.SessionGeneration &&
                (Volatile.Read(ref _batchDepth) != 0 ||
                    snapshot.State == SimplySignSessionState.Checking))
            {
                return;
            }
        }

        ReplaceState(CaptureCompleteState());
    }

    private void AppendTransitionUnsafe(SimplySignSessionSnapshot snapshot)
    {
        _sessionTransitions.Enqueue(new SessionTransitionEvidence(
            _nextTransitionSequence++,
            snapshot.State,
            snapshot.SessionGeneration,
            snapshot.TransitionedAtUtc,
            snapshot.Attempt));
        while (_sessionTransitions.Count > SessionTransitionEvidence.MaximumRetained)
        {
            _sessionTransitions.Dequeue();
        }
    }

    private CacheState CaptureCompleteState()
    {
        var group = _manager.GetCapabilityGroup();
        var authenticode = !_authenticodeConfigured
            ? CapabilitySnapshot.NotConfigured()
            : ToCapability(group.Session);
        var pdf = !_pdfConfigured
            ? CapabilitySnapshot.NotConfigured()
            : ApplyPdfToolResolution(ToCapability(group.Session));
        var session = authenticode.Session ?? pdf.Session
            ?? throw new InvalidOperationException("capability_session_missing");
        return new CacheState(
            group.SessionGeneration,
            session.SimplySignProcessRunning == true,
            session.SimplySignProcessRunning == true ? session.SimplySignProcessSessionId : null,
            authenticode,
            pdf,
            (group.DisplaySummaries ?? [])
                .Select(ToProtocolSummary)
                .ToArray());
    }

    private static CertificateSummary ToProtocolSummary(CertificateDisplaySummary summary) =>
        new(
            summary.CommonName,
            summary.SerialNumber,
            summary.NotBeforeUtc,
            summary.NotAfterUtc,
            summary.AuthenticodeUsable,
            summary.PdfUsable,
            summary.CatalogCurrent,
            summary.UnavailableReason);

    private static CapabilitySnapshot ToCapability(SimplySignSessionSnapshot session) =>
        new(
            configured: true,
            session.TokenPresent,
            session.TokenMatches,
            tokenSuffix: null,
            session.CertificatePresent,
            session.CertificateMatches,
            certificateSuffix: null,
            session.PrivateKeyPresent,
            session.PrivateKeyMatches,
            privateKeySuffix: null,
            session.Ready,
            session.ReasonCode,
            certificateNotAfterUtc: null,
            certificateThumbprintSuffix: null,
            session);

    private CapabilitySnapshot ApplyPdfToolResolution(CapabilitySnapshot capability)
    {
        InstalledPdfToolResolution? resolution;
        lock (_stateSync)
        {
            resolution = _pdfToolResolution;
        }

        if (resolution is null ||
            resolution.Status == InstalledPdfToolStatus.Ready)
        {
            return capability;
        }

        return new CapabilitySnapshot(
            configured: true,
            capability.TokenPresent,
            capability.TokenMatches,
            capability.TokenSuffix,
            capability.CertificatePresent,
            capability.CertificateMatches,
            capability.CertificateSuffix,
            capability.PrivateKeyPresent,
            capability.PrivateKeyMatches,
            capability.PrivateKeySuffix,
            ready: false,
            resolution.FailureCode,
            capability.CertificateNotAfterUtc,
            capability.CertificateThumbprintSuffix,
            capability.Session);
    }

    private InstalledPdfToolResolution? _pdfToolResolution;

    private async Task RefreshPdfToolResolutionAsync(CancellationToken cancellationToken)
    {
        if (!_pdfConfigured || _pdfToolResolver is null)
        {
            return;
        }

        var resolution = await _pdfToolResolver.ResolveAsync(cancellationToken).ConfigureAwait(false);
        lock (_stateSync)
        {
            _pdfToolResolution = resolution;
        }
    }

    private async Task CompleteInstalledPdfCatalogAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0;
             attempt < InstalledPdfCatalogCompletionAttempts && NeedsInstalledPdfCertificate();
             attempt++)
        {
            _ = await _manager.CheckAsync(
                SessionTrigger.ManualRefresh,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private bool NeedsInstalledPdfCertificate()
    {
        lock (_stateSync)
        {
            if (!_pdfConfigured || _pdfToolResolution?.Status != InstalledPdfToolStatus.Ready)
            {
                return false;
            }
        }

        return !(_manager.GetCapabilityGroup().DisplaySummaries ?? [])
            .Any(static certificate => certificate.CatalogCurrent && certificate.PdfUsable);
    }

    private void ReplaceState(CacheState state)
    {
        lock (_stateSync)
        {
            if (state.SessionGeneration < _state.SessionGeneration)
            {
                return;
            }

            _state = state;
        }
    }

    private sealed record CacheState(
        long SessionGeneration,
        bool ProcessRunning,
        int? ProcessSessionId,
        CapabilitySnapshot Authenticode,
        CapabilitySnapshot Pdf,
        IReadOnlyList<CertificateSummary> Certificates);
}
