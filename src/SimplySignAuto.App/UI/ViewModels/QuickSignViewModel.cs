using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.App.UI.ViewModels;

public enum QuickSignState
{
    Idle,
    Validating,
    Copying,
    Finalizing,
    Accepted,
    Failed,
    Canceled,
}

public sealed class QuickSignViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly ILocalJobClient _localJobs;
    private readonly IAgentManagementClient _management;
    private readonly Action<Guid> _openJob;
    private readonly IUiDispatcher _dispatcher;
    private readonly ITerminalJobFeed? _terminalJobs;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly ConcurrentDictionary<Guid, byte> _activeLocalJobs = new();
    private string? _selectedPath;
    private FileKind? _selectedKind;
    private string _selectedFileName = string.Empty;
    private string _selectedSizeText = string.Empty;
    private QuickSignState _state;
    private string? _errorCode;
    private int _copyProgressPercent;
    private Guid? _acceptedJobId;
    private CancellationTokenSource? _operationCancellation;
    private long _selectionVersion;
    private int _submitting;
    private int _disposed;
    private long _acceptedTerminalSequence;
    private string? _acceptedTerminalState;
    private IReadOnlyList<CertificateSummary> _availableCertificates = [];
    private CertificateSummary? _selectedCertificate;

    public QuickSignViewModel(
        ILocalJobClient localJobs,
        IAgentManagementClient management,
        Action<Guid> openJob,
        IUiDispatcher? dispatcher = null)
        : this(localJobs, management, openJob, dispatcher, null)
    {
    }

    internal QuickSignViewModel(
        ILocalJobClient localJobs,
        IAgentManagementClient management,
        Action<Guid> openJob,
        IUiDispatcher? dispatcher,
        ITerminalJobFeed? terminalJobs)
    {
        _localJobs = localJobs ?? throw new ArgumentNullException(nameof(localJobs));
        _management = management ?? throw new ArgumentNullException(nameof(management));
        _openJob = openJob ?? throw new ArgumentNullException(nameof(openJob));
        _dispatcher = dispatcher ?? InlineQuickSignDispatcher.Instance;
        _terminalJobs = terminalJobs;
        _management.SnapshotChanged += HandleSnapshotChanged;
        if (_terminalJobs is not null)
        {
            _terminalJobs.ItemsChanged += HandleTerminalJobsChanged;
        }
        SubmitCommand = new AsyncCommand(
            async () => await SubmitAsync(CancellationToken.None).ConfigureAwait(false),
            () => CanSubmit);
        ClearCommand = new DelegateCommand(ClearSelection, () => HasSelection);
        RefreshAvailableCertificates();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    internal ILocalJobClient LocalJobsClient => _localJobs;

    public QuickSignState State
    {
        get => _state;
        private set
        {
            if (_state != value)
            {
                _state = value;
                RaiseStateProperties();
            }
        }
    }

    public string SelectedFileName
    {
        get => _selectedFileName;
        private set => SetField(ref _selectedFileName, value);
    }

    public string SelectedSizeText
    {
        get => _selectedSizeText;
        private set => SetField(ref _selectedSizeText, value);
    }

    public string DetectedTypeText => _selectedKind switch
    {
        FileKind.Authenticode => UiCulture.Text("AuthenticodeTitle"),
        FileKind.Pdf => UiCulture.Text("PdfSigningTitle"),
        _ => UiCulture.Text("QuickSignNoSelection"),
    };

    public bool HasSelection => _selectedPath is not null;

    public bool IsPdfSelection => _selectedKind == FileKind.Pdf;

    public string SelectedFileDisplayText => HasSelection
        ? SelectedFileName
        : UiCulture.Text("QuickSignSelectPrompt");

    public string SelectedFileDetailsText => HasSelection
        ? $"{DetectedTypeText} · {SelectedSizeText}"
        : string.Empty;

    public IReadOnlyList<CertificateSummary> AvailableCertificates => _availableCertificates;

    public CertificateSummary? SelectedCertificate
    {
        get => _selectedCertificate;
        set
        {
            if (value is not null && !_availableCertificates.Contains(value))
            {
                throw new ArgumentException("The selected certificate is not available.", nameof(value));
            }

            if (SetField(ref _selectedCertificate, value))
            {
                OnPropertyChanged(nameof(CanSubmit));
                OnPropertyChanged(nameof(ReadinessText));
                OnPropertyChanged(nameof(InlineStatusText));
                OnPropertyChanged(nameof(HasInlineStatus));
                RaiseCommandStates();
            }
        }
    }

    public bool CanSubmit =>
        HasSelection &&
        SelectedCertificate is not null &&
        Volatile.Read(ref _submitting) == 0 &&
        State is QuickSignState.Idle or QuickSignState.Failed or QuickSignState.Canceled &&
        ReadinessFailure() is null;

    public int CopyProgressPercent
    {
        get => _copyProgressPercent;
        private set => SetField(ref _copyProgressPercent, value);
    }

    public string CopyProgressText => State == QuickSignState.Copying
        ? UiCulture.Format("QuickSignCopyProgress", CopyProgressPercent)
        : string.Empty;

    public bool IsCopying => State == QuickSignState.Copying;

    public Guid? AcceptedJobId
    {
        get => _acceptedJobId;
        private set => SetField(ref _acceptedJobId, value);
    }

    internal bool HasActiveJob =>
        Volatile.Read(ref _submitting) != 0 ||
        !_activeLocalJobs.IsEmpty ||
        State is QuickSignState.Validating or QuickSignState.Copying or QuickSignState.Finalizing ||
        AcceptedJobId is { } jobId && !IsAcceptedJobTerminal(jobId);

    public string? ErrorCode
    {
        get => _errorCode;
        private set => SetField(ref _errorCode, value);
    }

    private bool HasSucceededAcceptedResult =>
        AcceptedJobId is { } jobId &&
        (_acceptedTerminalState == "succeeded" ||
         _management.LatestSnapshot?.RecentJobs.Any(job =>
             job.JobId == jobId && job.TerminalState == "succeeded") == true);

    private bool IsAcceptedJobTerminal(Guid jobId) =>
        _acceptedTerminalState is "succeeded" or "failed" or "expired" ||
        _management.LatestSnapshot?.RecentJobs.Any(job => job.JobId == jobId) == true;

    public string ReadinessText => ReadinessFailure() ?? UiCulture.Text("QuickSignReadyToSubmit");

    public bool PdfExtensionVisible => _management.LatestSnapshot?.Pdf is { Configured: true } pdf &&
        !string.Equals(
            pdf.ReasonCode,
            "pdf_support_not_installed",
            StringComparison.Ordinal);

    public string FileDialogFilter => PdfExtensionVisible
        ? UiCulture.Text("QuickSignFilterAll")
        : UiCulture.Text("QuickSignFilterCode");

    public string FileDialogTitle => UiCulture.Text("QuickSignDialogTitle");

    public string StatusText => State switch
    {
        QuickSignState.Validating => UiCulture.Text("QuickSignValidating"),
        QuickSignState.Copying => CopyProgressText,
        QuickSignState.Finalizing => UiCulture.Text("QuickSignFinalizing"),
        QuickSignState.Accepted when HasSucceededAcceptedResult => UiCulture.Text("QuickSignCompleted"),
        QuickSignState.Accepted => UiCulture.Text("QuickSignAccepted"),
        QuickSignState.Failed => MapError(ErrorCode),
        QuickSignState.Canceled => UiCulture.Text("QuickSignCanceled"),
        _ => HasSelection ? UiCulture.Text("QuickSignFileReady") : UiCulture.Text("QuickSignChoosePrompt"),
    };

    public string InlineStatusText => State == QuickSignState.Idle
        ? HasSelection ? ReadinessFailure() ?? UiCulture.Text("QuickSignFileReady") : string.Empty
        : StatusText;

    public bool HasInlineStatus => InlineStatusText.Length > 0;

    public string StatusIcon => State switch
    {
        QuickSignState.Accepted => "✓",
        QuickSignState.Failed => "×",
        QuickSignState.Canceled => "!",
        QuickSignState.Validating or QuickSignState.Copying or QuickSignState.Finalizing => "…",
        _ => "○",
    };

    public int PdfPage { get; set; } = 1;

    public double PdfLeft { get; set; } = 36;

    public double PdfBottom { get; set; } = 36;

    public double PdfRight { get; set; } = 180;

    public double PdfTop { get; set; } = 72;

    public string PdfReason { get; set; } = string.Empty;

    public string PdfLocation { get; set; } = string.Empty;

    public ICommand SubmitCommand { get; }

    public ICommand ClearCommand { get; }

    public async Task SelectFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        var version = Interlocked.Increment(ref _selectionVersion);
        Interlocked.Exchange(ref _operationCancellation, null)?.Cancel();
        try
        {
            await InvokeUiAsync(() =>
            {
                if (version == Volatile.Read(ref _selectionVersion))
                {
                    ReleaseAcceptedSource();
                }
            }, cancellationToken).ConfigureAwait(false);
            var selection = ValidateSelection(path);
            if (selection.Kind == FileKind.Pdf && !PdfExtensionVisible)
            {
                throw new LocalJobException("local_capability_unavailable");
            }

            await InvokeUiAsync(() =>
            {
                if (version != Volatile.Read(ref _selectionVersion))
                {
                    return;
                }

                _selectedPath = selection.Path;
                _selectedKind = selection.Kind;
                RefreshAvailableCertificates();
                SelectedFileName = selection.Name;
                SelectedSizeText = UiCulture.Format("BytesFormat", selection.Size);
                AcceptedJobId = null;
                ErrorCode = null;
                CopyProgressPercent = 0;
                State = QuickSignState.Idle;
                RaiseSelectionProperties();
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            _lifetime.IsCancellationRequested &&
            !cancellationToken.IsCancellationRequested)
        {
        }
        catch (LocalJobException error)
        {
            await InvokeUiAsync(() =>
            {
                if (version == Volatile.Read(ref _selectionVersion))
                {
                    ClearSelectionFields();
                    ErrorCode = error.Code;
                    State = QuickSignState.Failed;
                }
            }, cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    public async Task<Guid?> SubmitAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        var version = Volatile.Read(ref _selectionVersion);
        var path = _selectedPath;
        var kind = _selectedKind;
        var snapshot = _management.LatestSnapshot;
        var selectedCertificate = _selectedCertificate;
        if (Interlocked.CompareExchange(ref _submitting, 1, 0) != 0)
        {
            return null;
        }

        using var operation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        Interlocked.Exchange(ref _operationCancellation, operation)?.Cancel();
        try
        {
            if (path is null || kind is null)
            {
                return null;
            }

            if (ReadinessFailure(snapshot, kind.Value, selectedCertificate) is { })
            {
                throw new LocalJobException("local_capability_unavailable");
            }

            await ApplyIfCurrentAsync(version, () =>
            {
                ErrorCode = null;
                State = QuickSignState.Validating;
            }).ConfigureAwait(false);
            var parameters = BuildParameters(kind.Value, selectedCertificate!);
            await ApplyIfCurrentAsync(version, () =>
            {
                CopyProgressPercent = 0;
                State = QuickSignState.Copying;
            }).ConfigureAwait(false);
            var progress = new CopyProgress(this, version);
            var jobId = await _localJobs
                .CreateAndUploadAsync(path, parameters, progress, operation.Token)
                .ConfigureAwait(false);
            TrackActiveLocalJob(jobId);
            var applied = await ApplyIfCurrentAsync(version, () =>
            {
                _selectedPath = null;
                ResetAcceptedTerminalState();
                AcceptedJobId = jobId;
                CopyProgressPercent = 0;
                State = QuickSignState.Accepted;
                ApplyAcceptedTerminalItem(FindLatestTerminalItem(jobId, _terminalJobs?.Items));
                RaiseSelectionProperties();
                _openJob(jobId);
            }).ConfigureAwait(false);
            if (!applied)
            {
                _localJobs.ReleaseAcceptedSource(jobId);
            }

            return jobId;
        }
        catch (OperationCanceledException) when (operation.IsCancellationRequested)
        {
            await ApplyIfCurrentAsync(version, () =>
            {
                CopyProgressPercent = 0;
                State = QuickSignState.Canceled;
            }).ConfigureAwait(false);
            return null;
        }
        catch (LocalJobException error)
        {
            await ApplyIfCurrentAsync(version, () =>
            {
                ErrorCode = error.Code;
                CopyProgressPercent = 0;
                State = QuickSignState.Failed;
            }).ConfigureAwait(false);
            return null;
        }
        finally
        {
            Interlocked.CompareExchange(ref _operationCancellation, null, operation);
            Interlocked.Exchange(ref _submitting, 0);
            await InvokeUiAsync(RaiseCommandStates, CancellationToken.None).ConfigureAwait(false);
        }
    }

    public void ClearSelection()
    {
        ThrowIfDisposed();
        Interlocked.Increment(ref _selectionVersion);
        Interlocked.Exchange(ref _operationCancellation, null)?.Cancel();
        ReleaseAcceptedSource();
        ClearSelectionFields();
        ErrorCode = null;
        CopyProgressPercent = 0;
        State = QuickSignState.Idle;
        RaiseSelectionProperties();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _management.SnapshotChanged -= HandleSnapshotChanged;
        if (_terminalJobs is not null)
        {
            _terminalJobs.ItemsChanged -= HandleTerminalJobsChanged;
        }
        _lifetime.Cancel();
        Interlocked.Exchange(ref _operationCancellation, null)?.Cancel();
        if (_acceptedJobId is { } jobId)
        {
            _acceptedJobId = null;
            _localJobs.ReleaseAcceptedSource(jobId);
        }

        _selectedPath = null;
    }

    private Selection ValidateSelection(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl) || !Path.IsPathFullyQualified(path))
            {
                throw new LocalJobException("local_source_invalid");
            }

            var canonical = Path.GetFullPath(path);
            if (!string.Equals(canonical, path, PathComparison()))
            {
                throw new LocalJobException("local_source_invalid");
            }

            var attributes = File.GetAttributes(canonical);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
                new FileInfo(canonical).LinkTarget is not null)
            {
                throw new LocalJobException("local_source_invalid");
            }

            using var stream = new FileStream(canonical, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length == 0)
            {
                throw new LocalJobException("local_source_empty");
            }

            if (stream.Length > LocalJobClient.MaximumInputBytes)
            {
                throw new LocalJobException("file_too_large");
            }

            Span<byte> prefix = stackalloc byte[8];
            var read = stream.Read(prefix);
            FileKind kind;
            try
            {
                kind = SigningRequestValidator.ValidateFile(Path.GetFileName(canonical), prefix[..read]);
            }
            catch (ValidationException error)
            {
                throw new LocalJobException(error.Code);
            }

            return new Selection(canonical, Path.GetFileName(canonical), stream.Length, kind);
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new LocalJobException("local_source_invalid");
        }
    }

    private SigningParameters BuildParameters(FileKind kind, CertificateSummary certificate)
    {
        SigningParameters parameters = kind switch
        {
            FileKind.Authenticode =>
                new AuthenticodeParameters(
                    certificate.SerialNumber,
                    "sha256",
                    false),
            FileKind.Pdf =>
                new PdfParameters(
                    certificate.SerialNumber,
                    "sha256",
                    PdfPage,
                    new PdfBox(PdfLeft, PdfBottom, PdfRight, PdfTop),
                    "SimplySignAutoSignature",
                    NullIfEmpty(PdfReason),
                    NullIfEmpty(PdfLocation)),
            _ => throw new LocalJobException("local_capability_unavailable"),
        };

        try
        {
            return SigningParameters.Parse(SigningParameters.SerializeCanonical(parameters));
        }
        catch (ValidationException error)
        {
            throw new LocalJobException(error.Code);
        }
    }

    private string? ReadinessFailure() => _selectedKind is { } kind
        ? ReadinessFailure(kind)
        : UiCulture.Text("QuickSignChoosePrompt");

    private string? ReadinessFailure(FileKind kind) =>
        ReadinessFailure(_management.LatestSnapshot, kind, SelectedCertificate);

    private static string? ReadinessFailure(
        ManagementSnapshot? snapshot,
        FileKind kind,
        CertificateSummary? selectedCertificate)
    {
        if (snapshot is null)
        {
            return UiCulture.Text("QuickSignAgentUnknown");
        }

        if (!snapshot.ServiceAvailable || !snapshot.AgentConnected ||
            snapshot.AgentSessionId <= 0 || snapshot.HeartbeatSessionId != snapshot.AgentSessionId ||
            !snapshot.SimplySignProcessRunning || snapshot.SimplySignProcessSessionId != snapshot.AgentSessionId)
        {
            return UiCulture.Text("QuickSignServiceNotReady");
        }

        if (snapshot.HeartbeatAgeMilliseconds is null or < 0)
        {
            return UiCulture.Text("QuickSignAgentUnknown");
        }

        if (snapshot.HeartbeatAgeMilliseconds > 15_000)
        {
            return UiCulture.Text("QuickSignAgentStale");
        }

        var capability = kind == FileKind.Authenticode ? snapshot.Authenticode : snapshot.Pdf;
        if (!capability.Configured || !capability.Ready)
        {
            return kind == FileKind.Authenticode
                ? UiCulture.Text("QuickSignAuthenticodeNotReady")
                : UiCulture.Text("QuickSignPdfNotReady");
        }

        var availableCertificates = snapshot.Certificates
            .Where(certificate => certificate.CatalogCurrent &&
                (kind == FileKind.Authenticode
                    ? certificate.AuthenticodeUsable
                    : certificate.PdfUsable))
            .ToArray();
        if (availableCertificates.Length == 0)
        {
            return kind == FileKind.Authenticode
                ? UiCulture.Text("QuickSignNoAuthenticodeCertificate")
                : UiCulture.Text("QuickSignNoPdfCertificate");
        }

        if (selectedCertificate is null || !availableCertificates.Contains(selectedCertificate))
        {
            return UiCulture.Text("SelectSigningCertificate");
        }

        return null;
    }

    private void HandleSnapshotChanged(object? sender, EventArgs eventArgs)
    {
        var snapshot = _management.LatestSnapshot;
        _ = InvokeUiAsync(() =>
        {
            RemoveTerminalLocalJobs(snapshot?.RecentJobs.Select(static job => job.JobId));
            RefreshAvailableCertificates();
            if (AcceptedJobId is { } acceptedJobId &&
                snapshot?.RecentJobs.FirstOrDefault(
                    job => job.JobId == acceptedJobId) is { TerminalState: "failed" or "expired" })
            {
                ReleaseAcceptedSource();
            }

            OnPropertyChanged(nameof(ReadinessText));
            OnPropertyChanged(nameof(CanSubmit));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(PdfExtensionVisible));
            OnPropertyChanged(nameof(FileDialogFilter));
            OnPropertyChanged(nameof(InlineStatusText));
            OnPropertyChanged(nameof(HasInlineStatus));
            RaiseCommandStates();
        }, _lifetime.Token);
    }

    private void HandleTerminalJobsChanged(object? sender, EventArgs eventArgs)
    {
        var items = _terminalJobs?.Items;
        _ = InvokeUiAsync(() =>
        {
            RemoveTerminalLocalJobs(items?
                .Where(static item => item.Item.State is "succeeded" or "failed" or "expired")
                .Select(static item => item.Item.JobId));
            if (AcceptedJobId is { } acceptedJobId)
            {
                ApplyAcceptedTerminalItem(FindLatestTerminalItem(acceptedJobId, items));
            }

            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(InlineStatusText));
            OnPropertyChanged(nameof(HasInlineStatus));
            RaiseCommandStates();
        }, _lifetime.Token);
    }

    private void ApplyAcceptedTerminalItem(TerminalJobEventItem? terminal)
    {
        if (terminal is null || terminal.Sequence <= _acceptedTerminalSequence)
        {
            return;
        }

        _acceptedTerminalSequence = terminal.Sequence;
        _acceptedTerminalState = terminal.Item.State;
        if (_acceptedTerminalState is "failed" or "expired")
        {
            ReleaseAcceptedSource();
        }
    }

    private static TerminalJobEventItem? FindLatestTerminalItem(
        Guid jobId,
        IReadOnlyList<TerminalJobEventItem>? items) =>
        items?
            .Where(item => item.Item.JobId == jobId)
            .OrderByDescending(static item => item.Sequence)
            .FirstOrDefault();

    private void TrackActiveLocalJob(Guid jobId)
    {
        _activeLocalJobs.TryAdd(jobId, 0);
        RemoveTerminalLocalJobs(
            _management.LatestSnapshot?.RecentJobs.Select(static job => job.JobId));
        RemoveTerminalLocalJobs(_terminalJobs?.Items
            .Where(static item => item.Item.State is "succeeded" or "failed" or "expired")
            .Select(static item => item.Item.JobId));
    }

    private void RemoveTerminalLocalJobs(IEnumerable<Guid>? jobIds)
    {
        if (jobIds is null)
        {
            return;
        }

        foreach (var jobId in jobIds)
        {
            _activeLocalJobs.TryRemove(jobId, out _);
        }
    }

    private async Task<bool> ApplyIfCurrentAsync(long version, Action action)
    {
        var applied = false;
        await InvokeUiAsync(() =>
        {
            if (version == Volatile.Read(ref _selectionVersion))
            {
                action();
                applied = true;
            }
        }, _lifetime.Token).ConfigureAwait(false);
        return applied;
    }

    private async Task InvokeUiAsync(Action action, CancellationToken cancellationToken)
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
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (InvalidOperationException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
    }

    private void ApplyProgress(long version, int percent) => _ = InvokeUiAsync(() =>
    {
        if (version == Volatile.Read(ref _selectionVersion) && State == QuickSignState.Copying)
        {
            CopyProgressPercent = Math.Clamp(percent, 0, 100);
            if (CopyProgressPercent == 100)
            {
                State = QuickSignState.Finalizing;
            }

            OnPropertyChanged(nameof(CopyProgressText));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(InlineStatusText));
        }
    }, _lifetime.Token);

    private void ClearSelectionFields()
    {
        _selectedPath = null;
        _selectedKind = null;
        RefreshAvailableCertificates();
        SelectedFileName = string.Empty;
        SelectedSizeText = string.Empty;
    }

    private void ReleaseAcceptedSource()
    {
        if (AcceptedJobId is not { } jobId)
        {
            ResetAcceptedTerminalState();
            return;
        }

        AcceptedJobId = null;
        ResetAcceptedTerminalState();
        _localJobs.ReleaseAcceptedSource(jobId);
    }

    private void ResetAcceptedTerminalState()
    {
        _acceptedTerminalSequence = 0;
        _acceptedTerminalState = null;
    }

    private void RaiseSelectionProperties()
    {
        OnPropertyChanged(nameof(DetectedTypeText));
        OnPropertyChanged(nameof(IsPdfSelection));
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(SelectedFileDisplayText));
        OnPropertyChanged(nameof(SelectedFileDetailsText));
        OnPropertyChanged(nameof(CanSubmit));
        OnPropertyChanged(nameof(ReadinessText));
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(InlineStatusText));
        OnPropertyChanged(nameof(HasInlineStatus));
        RaiseCommandStates();
    }

    private void RefreshAvailableCertificates()
    {
        var filtered = _selectedKind is { } kind
            ? (_management.LatestSnapshot?.Certificates ?? [])
                .Where(certificate => certificate.CatalogCurrent &&
                    (kind == FileKind.Authenticode
                        ? certificate.AuthenticodeUsable
                        : certificate.PdfUsable))
                .ToArray()
            : [];
        if (_availableCertificates.SequenceEqual(filtered))
        {
            return;
        }

        _availableCertificates = filtered;
        _selectedCertificate = filtered.Length == 1 ? filtered[0] : null;
        OnPropertyChanged(nameof(AvailableCertificates));
        OnPropertyChanged(nameof(SelectedCertificate));
        OnPropertyChanged(nameof(CanSubmit));
        OnPropertyChanged(nameof(ReadinessText));
        OnPropertyChanged(nameof(InlineStatusText));
        OnPropertyChanged(nameof(HasInlineStatus));
    }

    private void RaiseStateProperties()
    {
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(CanSubmit));
        OnPropertyChanged(nameof(CopyProgressText));
        OnPropertyChanged(nameof(IsCopying));
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(StatusIcon));
        OnPropertyChanged(nameof(InlineStatusText));
        OnPropertyChanged(nameof(HasInlineStatus));
        RaiseCommandStates();
    }

    private void RaiseCommandStates()
    {
        ((AsyncCommand)SubmitCommand).RaiseCanExecuteChanged();
        ((DelegateCommand)ClearCommand).RaiseCanExecuteChanged();
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string MapError(string? code) => code switch
    {
        "file_signature_mismatch" => UiCulture.Text("ErrorFileSignatureMismatch"),
        "unsupported_type" => UiCulture.Text("ErrorUnsupportedType"),
        "file_too_large" => UiCulture.Text("ErrorFileTooLarge"),
        "local_source_empty" => UiCulture.Text("ErrorLocalSourceEmpty"),
        "local_capability_unavailable" => UiCulture.Text("ErrorLocalCapabilityUnavailable"),
        "local_job_unavailable" => UiCulture.Text("ErrorLocalJobUnavailable"),
        _ => UiCulture.Text("ErrorLocalJobSubmit"),
    };

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private sealed record Selection(string Path, string Name, long Size, FileKind Kind);

    private sealed class CopyProgress(QuickSignViewModel owner, long version) : IProgress<LocalCopyProgress>
    {
        public void Report(LocalCopyProgress value) => owner.ApplyProgress(version, value.Percent);
    }

    private sealed class DelegateCommand(Action execute, Func<bool> canExecute) : ICommand
    {
        public event EventHandler? CanExecuteChanged;

        public bool CanExecute(object? parameter) => canExecute();

        public void Execute(object? parameter) => execute();

        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }

    private sealed class AsyncCommand(Func<Task> execute, Func<bool> canExecute) : ICommand
    {
        public event EventHandler? CanExecuteChanged;

        public bool CanExecute(object? parameter) => canExecute();

        public async void Execute(object? parameter)
        {
            try
            {
                await execute().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Command handlers expose stable error state and must never tear down the UI thread.
            }
        }

        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }

    private sealed class InlineQuickSignDispatcher : IUiDispatcher
    {
        public static InlineQuickSignDispatcher Instance { get; } = new();

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }
}
