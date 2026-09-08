using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.App.UI.Localization;
using CodeSignAuto.App.UI.Status;
using CodeSignAuto.Core.Otp;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Protocol;

namespace CodeSignAuto.App.UI.ViewModels;

public sealed record CertificateCardViewModel(
    CertificateSummary Summary,
    IReadOnlyList<string> LogicalRows,
    string ValidityText,
    string StatusText)
{
    public string CommonName => Summary.CommonName;
    public string SerialNumber => Summary.SerialNumber;
}

public interface IClipboardService
{
    string? GetText();
    void SetText(string value);
    void Clear();
}

public interface IOtpClearConfirmation
{
    Task<bool> ConfirmAsync(CancellationToken cancellationToken);
}

public sealed class ActivationViewModel : INotifyPropertyChanged, IDisposable
{
    private static readonly JsonSerializerOptions DiagnosticJson = new(JsonSerializerDefaults.Web);
    private readonly IAgentManagementClient _management;
    private readonly IAgentAdministrationClient _administration;
    private readonly IClipboardService _clipboard;
    private readonly ILocalTotpCodeProvider? _totpProvider;
    private readonly TimeProvider _timeProvider;
    private readonly IReloginConfirmation _confirmation;
    private readonly IOtpClearConfirmation _clearConfirmation;
    private readonly IUiDispatcher _dispatcher;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private string _otpauthInput = string.Empty;
    private string _displaySummary = string.Empty;
    private string? _errorCode;
    private string _totpCode = string.Empty;
    private int _totpRemainingSeconds;
    private DateTimeOffset? _totpExpiresAtUtc;
    private ITimer? _totpDisplayTimer;
    private int _disposed;
    private IReadOnlyList<CertificateCardViewModel> _certificates = [];

    public ActivationViewModel(
        IAgentManagementClient management,
        IAgentAdministrationClient administration,
        IClipboardService clipboard,
        IReloginConfirmation? confirmation = null,
        IOtpClearConfirmation? clearConfirmation = null,
        IUiDispatcher? dispatcher = null,
        ILocalTotpCodeProvider? totpProvider = null,
        TimeProvider? timeProvider = null)
    {
        _management = management ?? throw new ArgumentNullException(nameof(management));
        _administration = administration ?? throw new ArgumentNullException(nameof(administration));
        _clipboard = clipboard ?? throw new ArgumentNullException(nameof(clipboard));
        _totpProvider = totpProvider;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _confirmation = confirmation ?? DenyReloginConfirmation.Instance;
        _clearConfirmation = clearConfirmation ?? DenyOtpClearConfirmation.Instance;
        _dispatcher = dispatcher ?? InlineActivationDispatcher.Instance;
        _management.SnapshotChanged += HandleSnapshotChanged;
        RefreshCertificates();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    internal IAgentManagementClient ManagementClient => _management;

    internal IAgentAdministrationClient AdministrationClient => _administration;

    internal IClipboardService ClipboardService => _clipboard;

    internal IUiDispatcher Dispatcher => _dispatcher;

    public string OtpauthInput
    {
        get => _otpauthInput;
        set => SetField(ref _otpauthInput, value ?? string.Empty);
    }

    public string DisplaySummary
    {
        get => _displaySummary;
        private set => SetField(ref _displaySummary, value);
    }

    public string? ErrorCode
    {
        get => _errorCode;
        private set
        {
            if (SetField(ref _errorCode, value))
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ErrorText)));
            }
        }
    }

    public string? ErrorText => ErrorCode switch
    {
        null => null,
        "management_unavailable" =>
            UiCulture.Text("ActivationAgentNotReady"),
        "clipboard_unavailable" => UiCulture.Text("ActivationClipboardUnavailable"),
        _ => ErrorCode,
    };

    public string TotpCode
    {
        get => _totpCode;
        private set
        {
            if (SetField(ref _totpCode, value))
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasTotpCode)));
            }
        }
    }

    public int TotpRemainingSeconds
    {
        get => _totpRemainingSeconds;
        private set => SetField(ref _totpRemainingSeconds, value);
    }

    public bool HasTotpCode => TotpCode.Length != 0;

    public IReadOnlyList<CertificateCardViewModel> Certificates => _certificates;

    public string TotpInstruction => UiCulture.Text("ActivationManualLoginInstruction");

    public bool CanValidateLogin =>
        _management.LatestSnapshot is { ActiveJobCount: 0, CurrentJob: null };

    public bool CanClearOtp => CanValidateLogin;

    public string SessionText => _management.LatestSnapshot is { } snapshot
        ? UiCulture.Format(
            "ActivationSessionFormat",
            snapshot.AgentSessionId,
            UiCulture.Text(snapshot.SimplySignProcessRunning ? "ActivationRunning" : "ActivationNotRunning"))
        : UiCulture.Text("ActivationSessionUnavailable");

    public string HeartbeatText => _management.LatestSnapshot is { } snapshot
        ? UiCulture.Format(
            "ActivationHeartbeatFormat",
            snapshot.HeartbeatAgeMilliseconds?.ToString("N0", UiCulture.Current) ?? UiCulture.Text("StatusUnknown"),
            snapshot.GeneratedAtUtc.ToString("g", UiCulture.Current))
        : UiCulture.Text("ActivationHeartbeatUnavailable");

    public string AuthenticodeCertificateText
    {
        get
        {
            var snapshot = _management.LatestSnapshot;
            return CapabilityText(snapshot, snapshot?.Authenticode);
        }
    }

    public string PdfCertificateText
    {
        get
        {
            var snapshot = _management.LatestSnapshot;
            return CapabilityText(snapshot, snapshot?.Pdf);
        }
    }

    public async Task<bool> ValidateAndSaveAsync(string uri, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(uri);
        await ApplyAsync(ClearTotpDisplay).ConfigureAwait(false);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        var gateEntered = false;
        try
        {
            await _operationGate.WaitAsync(operation.Token).ConfigureAwait(false);
            gateEntered = true;
            OtpauthProfile profile;
            try
            {
                profile = OtpauthProfile.Parse(uri);
            }
            catch (OtpauthException error)
            {
                await ApplyAsync(() => ErrorCode = error.Code).ConfigureAwait(false);
                return false;
            }

            try
            {
                await _administration.SaveOtpAsync(profile, operation.Token).ConfigureAwait(false);
                await ClearMatchingClipboardAsync(uri, operation.Token).ConfigureAwait(false);
                await ApplyAsync(() =>
                {
                    DisplaySummary = UiCulture.Format(
                        "ActivationProfileSummary",
                        profile.Issuer,
                        profile.Account,
                        profile.Digits,
                        profile.Period);
                    ErrorCode = null;
                }).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException) when (operation.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (error is ManagementUnavailableException or Agent.Security.OtpStoreException or PlatformNotSupportedException)
            {
                var code = error switch
                {
                    Agent.Security.OtpStoreException otp => otp.Code,
                    _ => "management_unavailable",
                };
                await ApplyAsync(() => ErrorCode = code).ConfigureAwait(false);
                return false;
            }
        }
        finally
        {
            uri = string.Empty;
            await ApplyAsync(() => OtpauthInput = string.Empty).ConfigureAwait(false);
            if (gateEntered)
            {
                _operationGate.Release();
            }
        }
    }

    public async Task<bool> GenerateTotpAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_totpProvider is null)
        {
            await ApplyAsync(() => ErrorCode = "management_unavailable").ConfigureAwait(false);
            return false;
        }

        using var operation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        await _operationGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            try
            {
                var current = await _totpProvider
                    .GenerateCurrentAsync(operation.Token)
                    .ConfigureAwait(false);
                await ApplyAsync(() =>
                {
                    ClearTotpDisplay();
                    TotpCode = current.Code;
                    TotpRemainingSeconds = current.RemainingSeconds;
                    _totpExpiresAtUtc = current.ExpiresAtUtc;
                    _totpDisplayTimer = _timeProvider.CreateTimer(
                        static state => ((ActivationViewModel)state!).QueueTotpLifetimeUpdate(),
                        this,
                        TimeSpan.FromSeconds(1),
                        TimeSpan.FromSeconds(1));
                    ErrorCode = null;
                }).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException) when (operation.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (
                error is ManagementUnavailableException or Agent.Security.OtpStoreException or PlatformNotSupportedException)
            {
                var code = error is Agent.Security.OtpStoreException otp
                    ? otp.Code
                    : "management_unavailable";
                await ApplyAsync(() =>
                {
                    ClearTotpDisplay();
                    ErrorCode = code;
                }).ConfigureAwait(false);
                return false;
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task<bool> CopyTotpAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        var copied = false;
        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                UpdateTotpLifetime();
                if (!HasTotpCode || _totpExpiresAtUtc is not { } expiresAt)
                {
                    return;
                }

                var code = TotpCode;
                _clipboard.SetText(code);
                ScheduleClipboardExpiry(code, expiresAt);
                copied = true;
            }, cancellationToken).ConfigureAwait(false);
            await ApplyAsync(() => ErrorCode = null).ConfigureAwait(false);
        }
        catch (Exception error) when (
            error is InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.ExternalException)
        {
            await ApplyAsync(() => ErrorCode = "clipboard_unavailable").ConfigureAwait(false);
        }

        return copied;
    }

    public async Task<bool> CopyCertificateSerialAsync(
        CertificateCardViewModel certificate,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(certificate);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await _dispatcher.InvokeAsync(
                () => _clipboard.SetText(certificate.SerialNumber),
                cancellationToken).ConfigureAwait(false);
            await ApplyAsync(() => ErrorCode = null).ConfigureAwait(false);
            return true;
        }
        catch (Exception error) when (
            error is InvalidOperationException or UnauthorizedAccessException or
                System.Runtime.InteropServices.ExternalException)
        {
            await ApplyAsync(() => ErrorCode = "clipboard_unavailable").ConfigureAwait(false);
            return false;
        }
    }

    public void BeginOtpImport()
    {
        ThrowIfDisposed();
        ClearTotpDisplay();
    }

    public void DeactivateTotp()
    {
        if (Volatile.Read(ref _disposed) == 0)
        {
            ClearTotpDisplay();
        }
    }

    public async Task<bool> ValidateLoginAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanValidateLogin || !await _confirmation.ConfirmAsync(cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await _operationGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            if (!CanValidateLogin)
            {
                return false;
            }

            try
            {
                await _management.ReloginAsync(operation.Token).ConfigureAwait(false);
                await ApplyAsync(() => ErrorCode = null).ConfigureAwait(false);
                return true;
            }
            catch (ManagementUnavailableException)
            {
                await ApplyAsync(() => ErrorCode = "management_unavailable").ConfigureAwait(false);
                return false;
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task<bool> ClearOtpAndLogoutAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!CanClearOtp ||
            !await _clearConfirmation.ConfirmAsync(cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        using var operation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        await _operationGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            if (!CanClearOtp)
            {
                return false;
            }

            try
            {
                _ = await _administration
                    .ClearOtpAndLogoutAsync(operation.Token)
                    .ConfigureAwait(false);
                await ApplyAsync(() =>
                {
                    ClearTotpDisplay();
                    OtpauthInput = string.Empty;
                    DisplaySummary = UiCulture.Text("ActivationCleared");
                    ErrorCode = null;
                    _certificates = [];
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Certificates)));
                }).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException) when (operation.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (
                error is ManagementUnavailableException or Agent.Security.OtpStoreException or PlatformNotSupportedException)
            {
                await ApplyAsync(() => ErrorCode = error is Agent.Security.OtpStoreException otp
                    ? otp.Code
                    : "management_unavailable").ConfigureAwait(false);
                return false;
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task<string> CopyRedactedDiagnosticsAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = _management.LatestSnapshot;
        var document = new
        {
            schemaVersion = 1,
            agentSessionValid = snapshot is { AgentSessionId: > 0 } && snapshot.AgentSessionId == snapshot.HeartbeatSessionId,
            heartbeatAgeMilliseconds = snapshot?.HeartbeatAgeMilliseconds,
            simplySignProcessRunning = snapshot?.SimplySignProcessRunning ?? false,
            authenticode = SafeCapability(snapshot?.Authenticode),
            pdf = SafeCapability(snapshot?.Pdf),
            queue = new { queued = snapshot?.QueuedJobCount ?? 0, active = snapshot?.ActiveJobCount ?? 0 },
            current = snapshot?.CurrentJob is { } current
                ? new { kind = current.Kind, state = current.State, stage = current.Stage, correlationId = (string?)null }
                : null,
        };
        var json = JsonSerializer.Serialize(document, DiagnosticJson);
        StrictJson.RejectDuplicatePropertiesAndSecretShapes(json);
        try
        {
            await _dispatcher.InvokeAsync(() => _clipboard.SetText(json), cancellationToken).ConfigureAwait(false);
            await ApplyAsync(() => ErrorCode = null).ConfigureAwait(false);
        }
        catch (Exception error) when (
            error is InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.ExternalException)
        {
            await ApplyAsync(() => ErrorCode = "clipboard_unavailable").ConfigureAwait(false);
        }

        return json;
    }

    internal Task ReportUiFailureAsync(string errorCode)
    {
        if (errorCode is not ("management_unavailable" or "clipboard_unavailable"))
        {
            throw new ArgumentException("The UI error code is invalid.", nameof(errorCode));
        }

        return ApplyAsync(() => ErrorCode = errorCode);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _management.SnapshotChanged -= HandleSnapshotChanged;
        _lifetime.Cancel();
        _operationGate.Wait();
        _operationGate.Release();
        _otpauthInput = string.Empty;
        ClearTotpDisplay();
        _operationGate.Dispose();
        _lifetime.Dispose();
    }

    private void QueueTotpLifetimeUpdate() => _ = ApplyAsync(UpdateTotpLifetime);

    private void UpdateTotpLifetime()
    {
        if (_totpExpiresAtUtc is not { } expiresAt)
        {
            return;
        }

        var remaining = expiresAt - _timeProvider.GetUtcNow().ToUniversalTime();
        if (remaining <= TimeSpan.Zero)
        {
            ClearTotpDisplay();
            return;
        }

        TotpRemainingSeconds = Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));
    }

    private void ClearTotpDisplay()
    {
        Interlocked.Exchange(ref _totpDisplayTimer, null)?.Dispose();
        _totpExpiresAtUtc = null;
        TotpCode = string.Empty;
        TotpRemainingSeconds = 0;
    }

    private void ScheduleClipboardExpiry(string code, DateTimeOffset expiresAtUtc)
    {
        ITimer? timer = null;
        var due = expiresAtUtc - _timeProvider.GetUtcNow().ToUniversalTime();
        if (due < TimeSpan.Zero)
        {
            due = TimeSpan.Zero;
        }

        timer = _timeProvider.CreateTimer(
            _ =>
            {
                _ = ClearCopiedCodeAsync(code, timer!);
            },
            null,
            due,
            Timeout.InfiniteTimeSpan);
    }

    private async Task ClearCopiedCodeAsync(string code, ITimer timer)
    {
        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                if (string.Equals(_clipboard.GetText(), code, StringComparison.Ordinal))
                {
                    _clipboard.Clear();
                }
            }, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception error) when (
            error is InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.ExternalException)
        {
        }
        finally
        {
            timer.Dispose();
        }
    }

    private async Task ClearMatchingClipboardAsync(string submitted, CancellationToken cancellationToken)
    {
        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                if (string.Equals(_clipboard.GetText(), submitted, StringComparison.Ordinal))
                {
                    _clipboard.Clear();
                }
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (
            error is InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.ExternalException)
        {
        }
    }

    private static object SafeCapability(CapabilitySnapshot? capability) => new
    {
        configured = capability?.Configured ?? false,
        ready = capability?.Ready ?? false,
        reason = capability?.ReasonCode ?? "management_unavailable",
        tokenSuffix = capability?.TokenSuffix,
        certificateSuffix = capability?.CertificateSuffix,
        privateKeySuffix = capability?.PrivateKeySuffix,
        certificateNotAfterUtc = capability?.CertificateNotAfterUtc,
        certificateThumbprintSuffix = capability?.CertificateThumbprintSuffix,
    };

    private static string CapabilityText(
        ManagementSnapshot? snapshot,
        CapabilitySnapshot? capability)
    {
        if (snapshot is null ||
            !ReadinessStatusMapper.HasCurrentSession(snapshot.SessionGeneration, capability))
        {
            return UiCulture.Text("StatusUnknown");
        }

        var session = capability!.Session!;
        var expiry = capability.CertificateNotAfterUtc is { } notAfter
            ? $"{notAfter.ToString("g", UiCulture.Current)} UTC"
            : UiCulture.Text("StatusUnknown");
        return UiCulture.Format(
            "ActivationCapabilityFormat",
            ReadinessStatusMapper.CapabilityStateText(snapshot.SessionGeneration, capability),
            session.ReasonCode,
            capability.TokenSuffix ?? UiCulture.Text("StatusNone"),
            capability.CertificateThumbprintSuffix ?? capability.CertificateSuffix ?? UiCulture.Text("StatusNone"),
            capability.PrivateKeySuffix ?? UiCulture.Text("StatusNone"),
            expiry);
    }

    private void HandleSnapshotChanged(object? sender, EventArgs eventArgs) => _ = ApplyAsync(() =>
    {
        RefreshCertificates();
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanValidateLogin)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanClearOtp)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SessionText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HeartbeatText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(AuthenticodeCertificateText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(PdfCertificateText)));
    });

    private void RefreshCertificates()
    {
        _certificates = (_management.LatestSnapshot?.Certificates ?? [])
            .Select(ToCertificateCard)
            .ToArray();
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Certificates)));
    }

    private static CertificateCardViewModel ToCertificateCard(CertificateSummary summary)
    {
        var validity = $"{summary.NotBeforeUtc.ToLocalTime().ToString("g", UiCulture.Current)} — " +
            summary.NotAfterUtc.ToLocalTime().ToString("g", UiCulture.Current);
        return new CertificateCardViewModel(
            summary,
            Array.AsReadOnly(
            [
                $"CN: {summary.CommonName}",
                UiCulture.Format("ActivationDiagnosticsSerial", summary.SerialNumber),
                UiCulture.Format("ActivationDiagnosticsValidity", validity),
            ]),
            validity,
            CertificateStatusText(summary));
    }

    private static string CertificateStatusText(CertificateSummary summary) =>
        summary.UnavailableReason switch
        {
            null => summary.AuthenticodeUsable && summary.PdfUsable
                ? UiCulture.Text("CertificateCodeAndPdfUsable")
                : summary.AuthenticodeUsable
                    ? UiCulture.Text("CertificateCodeUsable")
                    : UiCulture.Text("CertificatePdfUsable"),
            "not_yet_valid" => UiCulture.Text("CertificateNotYetValid"),
            "expired" => UiCulture.Text("CertificateExpired"),
            "private_key_missing" => UiCulture.Text("CertificatePrivateKeyMissing"),
            "private_key_ambiguous" => UiCulture.Text("CertificatePrivateKeyAmbiguous"),
            "certificate_serial_ambiguous" => UiCulture.Text("CertificateSerialAmbiguous"),
            "unsupported_purpose" => UiCulture.Text("CertificateUnsupportedPurpose"),
            "catalog_stale" => UiCulture.Text("CertificateCatalogStale"),
            _ => UiCulture.Text("StatusUnavailable"),
        };

    private async Task ApplyAsync(Action action)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    action();
                }
            }, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception error) when (
            Volatile.Read(ref _disposed) != 0 &&
            error is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    private sealed class DenyReloginConfirmation : IReloginConfirmation
    {
        public static DenyReloginConfirmation Instance { get; } = new();
        public Task<bool> ConfirmAsync(CancellationToken cancellationToken) => Task.FromResult(false);
    }

    private sealed class DenyOtpClearConfirmation : IOtpClearConfirmation
    {
        public static DenyOtpClearConfirmation Instance { get; } = new();
        public Task<bool> ConfirmAsync(CancellationToken cancellationToken) => Task.FromResult(false);
    }

    private sealed class InlineActivationDispatcher : IUiDispatcher
    {
        public static InlineActivationDispatcher Instance { get; } = new();
        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }
}

public sealed class DesktopClipboardService : IClipboardService
{
#if CODESIGNAUTO_WPF
    public string? GetText() => System.Windows.Clipboard.ContainsText()
        ? System.Windows.Clipboard.GetText(System.Windows.TextDataFormat.UnicodeText)
        : null;
    public void SetText(string value) => System.Windows.Clipboard.SetText(value);
    public void Clear() => System.Windows.Clipboard.Clear();
#else
    public string? GetText() => throw new PlatformNotSupportedException("clipboard_windows_required");
    public void SetText(string value) => throw new PlatformNotSupportedException("clipboard_windows_required");
    public void Clear() => throw new PlatformNotSupportedException("clipboard_windows_required");
#endif
}
