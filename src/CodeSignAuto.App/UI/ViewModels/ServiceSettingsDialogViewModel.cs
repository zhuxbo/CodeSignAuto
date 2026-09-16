using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.App.Commands;
using CodeSignAuto.App.UI.Localization;
using CodeSignAuto.Protocol;

namespace CodeSignAuto.App.UI.ViewModels;

internal enum ServiceSettingsDialogState
{
    Editing,
    Applying,
    Restarting,
    Reconnecting,
    Succeeded,
    Failed,
}

internal interface IServiceSettingsDialogService
{
    Task ShowAsync(
        ServiceSettingsDialogViewModel viewModel,
        CancellationToken cancellationToken);
}

internal interface IServiceSettingsDialogServiceProvider
{
    IServiceSettingsDialogService ServiceSettingsDialogs { get; }
}

internal sealed class UnavailableServiceConfigurationEditor : IServiceConfigurationEditor
{
    public static UnavailableServiceConfigurationEditor Instance { get; } = new();

    public Task<ServiceConfigurationEditResult> ApplyAsync(
        ServiceConfigurationEditRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        throw new ConfigureServiceException("administrator_required");
    }
}

internal sealed class UnavailableServiceSettingsDialogService : IServiceSettingsDialogService
{
    public static UnavailableServiceSettingsDialogService Instance { get; } = new();

    public Task ShowAsync(
        ServiceSettingsDialogViewModel viewModel,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        cancellationToken.ThrowIfCancellationRequested();
        throw new ManagementUnavailableException(Guid.NewGuid());
    }
}

internal sealed class DeferredServiceSettingsDialogService : IServiceSettingsDialogService
{
    private IServiceSettingsDialogService? _target;

    internal void SetTarget(IServiceSettingsDialogService target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (Interlocked.CompareExchange(ref _target, target, null) is not null)
        {
            throw new InvalidOperationException("service_settings_dialog_already_initialized");
        }
    }

    internal void ClearTarget() => Interlocked.Exchange(ref _target, null);

    public Task ShowAsync(
        ServiceSettingsDialogViewModel viewModel,
        CancellationToken cancellationToken) =>
        (_target ?? throw new InvalidOperationException("service_settings_dialog_not_initialized"))
            .ShowAsync(viewModel, cancellationToken);
}

internal sealed class ServiceSettingsDialogViewModel : INotifyPropertyChanged, IDisposable
{
    private const int DefaultReconnectAttempts = 30;
    private static readonly TimeSpan DefaultReconnectDelay = TimeSpan.FromMilliseconds(500);
    private static readonly HashSet<string> SafeEditorErrors = new(StringComparer.Ordinal)
    {
        "administrator_required",
        "configure_service_busy",
        "configure_service_failed",
        "configure_service_input_invalid",
        "configure_service_state_uncertain",
        "service_restart_failed",
    };

    private readonly IServiceConfigurationEditor _editor;
    private readonly IAgentAdministrationClient _administration;
    private readonly IClipboardService _clipboard;
    private readonly IUiDispatcher _dispatcher;
    private readonly int _reconnectAttempts;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly CancellationTokenSource _lifetime = new();
    private string _listenPortText;
    private string _retentionHoursText;
    private bool _rotateToken;
    private string? _apiToken;
    private ServiceSettingsDialogState _state = ServiceSettingsDialogState.Editing;
    private string? _errorCode;
    private string? _oneTimeApiToken;
    private ServiceSettingsSummary? _confirmedSummary;
    private int _mutationOwned;
    private int _disposed;

    internal ServiceSettingsDialogViewModel(
        ServiceSettingsSummary settings,
        IServiceConfigurationEditor editor,
        IAgentAdministrationClient administration,
        IClipboardService clipboard,
        IUiDispatcher dispatcher,
        int reconnectAttempts = DefaultReconnectAttempts,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _editor = editor ?? throw new ArgumentNullException(nameof(editor));
        _administration = administration ?? throw new ArgumentNullException(nameof(administration));
        _clipboard = clipboard ?? throw new ArgumentNullException(nameof(clipboard));
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        if (reconnectAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(reconnectAttempts));
        }

        _reconnectAttempts = reconnectAttempts;
        _delay = delay ?? (static (duration, token) => Task.Delay(duration, token));
        _listenPortText = settings.ListenPort.ToString(CultureInfo.InvariantCulture);
        _retentionHoursText = settings.RetentionHours.ToString(CultureInfo.InvariantCulture);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string ListenPortText
    {
        get => _listenPortText;
        set => SetField(ref _listenPortText, value);
    }

    public string RetentionHoursText
    {
        get => _retentionHoursText;
        set
        {
            if (SetField(ref _retentionHoursText, value))
            {
                OnPropertyChanged(nameof(RetentionDisplay));
            }
        }
    }

    public string RetentionDisplay =>
        TryParseAsciiInteger(RetentionHoursText, out var retentionHours) &&
        retentionHours is >= 0 and <= 168
            ? retentionHours == 0
                ? UiCulture.Text("ServiceSettingsKeepForever")
                : UiCulture.Format("ServiceSettingsHoursFormat", retentionHours)
            : UiCulture.Text("ServiceSettingsRetentionInvalid");

    public bool RotateToken
    {
        get => _rotateToken;
        set => SetField(ref _rotateToken, value);
    }

    public string? ApiToken
    {
        get => _apiToken;
        set => SetField(ref _apiToken, value);
    }

    public ServiceSettingsDialogState State
    {
        get => _state;
        private set
        {
            if (SetField(ref _state, value))
            {
                OnPropertyChanged(nameof(StateText));
                OnPropertyChanged(nameof(CanApply));
                OnPropertyChanged(nameof(CanClose));
            }
        }
    }

    public string StateText => State switch
    {
        ServiceSettingsDialogState.Editing => UiCulture.Text("ServiceSettingsStateEditing"),
        ServiceSettingsDialogState.Applying => UiCulture.Text("ServiceSettingsStateApplying"),
        ServiceSettingsDialogState.Restarting => UiCulture.Text("ServiceSettingsStateRestarting"),
        ServiceSettingsDialogState.Reconnecting => UiCulture.Text("ServiceSettingsStateReconnecting"),
        ServiceSettingsDialogState.Succeeded => UiCulture.Text("ServiceSettingsStateSucceeded"),
        ServiceSettingsDialogState.Failed => UiCulture.Text("ServiceSettingsStateFailed"),
        _ => throw new InvalidOperationException("service_settings_state_invalid"),
    };

    public string? ErrorCode
    {
        get => _errorCode;
        private set => SetField(ref _errorCode, value);
    }

    public string? OneTimeApiToken
    {
        get => _oneTimeApiToken;
        private set
        {
            if (SetField(ref _oneTimeApiToken, value))
            {
                OnPropertyChanged(nameof(HasOneTimeApiToken));
                OnPropertyChanged(nameof(CanClose));
            }
        }
    }

    public bool HasOneTimeApiToken => OneTimeApiToken is not null;

    public ServiceSettingsSummary? ConfirmedSummary
    {
        get => _confirmedSummary;
        private set => SetField(ref _confirmedSummary, value);
    }

    public bool CanApply => Volatile.Read(ref _mutationOwned) == 0 &&
        State is ServiceSettingsDialogState.Editing or ServiceSettingsDialogState.Failed;

    public bool CanClose => Volatile.Read(ref _mutationOwned) == 0 && !HasOneTimeApiToken;

    public async Task<bool> ApplyAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (Interlocked.CompareExchange(ref _mutationOwned, 1, 0) != 0)
        {
            return false;
        }

        OnPropertyChanged(nameof(CanApply));
        OnPropertyChanged(nameof(CanClose));
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        try
        {
            var request = CreateRequest();
            await ApplyOnUiAsync(() => ApiToken = null).ConfigureAwait(false);
            if (request is null)
            {
                await SetFailureAsync("configure_service_input_invalid").ConfigureAwait(false);
                return false;
            }

            await ApplyOnUiAsync(() =>
            {
                ErrorCode = null;
                ConfirmedSummary = null;
                ClearOneTimeToken();
                State = ServiceSettingsDialogState.Applying;
            }).ConfigureAwait(false);

            var result = await _editor.ApplyAsync(request, operation.Token).ConfigureAwait(false);
            await ApplyOnUiAsync(() =>
            {
                OneTimeApiToken = result.OneTimeApiToken;
                State = ServiceSettingsDialogState.Restarting;
            }).ConfigureAwait(false);
            await Task.Yield();
            await ApplyOnUiAsync(() => State = ServiceSettingsDialogState.Reconnecting)
                .ConfigureAwait(false);

            for (var attempt = 0; attempt < _reconnectAttempts; attempt++)
            {
                ServiceSettingsSummary? observed = null;
                try
                {
                    observed = await _administration.GetServiceSettingsAsync(operation.Token)
                        .ConfigureAwait(false);
                }
                catch (ManagementUnavailableException)
                {
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                }

                if (observed == result.Summary)
                {
                    await ApplyOnUiAsync(() =>
                    {
                        ConfirmedSummary = observed;
                        ErrorCode = null;
                        State = ServiceSettingsDialogState.Succeeded;
                    }).ConfigureAwait(false);
                    return true;
                }

                if (attempt + 1 < _reconnectAttempts)
                {
                    await _delay(DefaultReconnectDelay, operation.Token).ConfigureAwait(false);
                }
            }

            await SetFailureAsync("management_unavailable").ConfigureAwait(false);
            return false;
        }
        catch (OperationCanceledException) when (operation.IsCancellationRequested)
        {
            throw;
        }
        catch (ConfigureServiceException error)
        {
            await SetFailureAsync(SafeEditorErrors.Contains(error.Code)
                ? error.Code
                : "configure_service_failed").ConfigureAwait(false);
            return false;
        }
        catch (Exception)
        {
            await SetFailureAsync("configure_service_failed").ConfigureAwait(false);
            return false;
        }
        finally
        {
            Volatile.Write(ref _mutationOwned, 0);
            await ApplyOnUiAsync(() =>
            {
                OnPropertyChanged(nameof(CanApply));
                OnPropertyChanged(nameof(CanClose));
            }).ConfigureAwait(false);
        }
    }

    public bool CopyOneTimeToken()
    {
        ThrowIfDisposed();
        var token = OneTimeApiToken;
        if (token is null)
        {
            return false;
        }

        try
        {
            _clipboard.SetText(token);
            return true;
        }
        catch (Exception error) when (
            error is InvalidOperationException or ExternalException or SystemException)
        {
            ErrorCode = "clipboard_unavailable";
            return false;
        }
    }

    public void AcknowledgeOneTimeToken()
    {
        ThrowIfDisposed();
        ClearOneTimeToken();
    }

    public void ClearSensitiveResult()
    {
        ApiToken = null;
        ClearOneTimeToken();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _lifetime.Cancel();
            ClearSensitiveResult();
            _lifetime.Dispose();
        }
    }

    public override string ToString() =>
        $"ServiceSettingsDialogViewModel {{ State = {State}, " +
        $"OneTimeApiToken = {(OneTimeApiToken is null ? "[ABSENT]" : "[PRESENT]")} }}";

    private ServiceConfigurationEditRequest? CreateRequest()
    {
        if (!TryParseAsciiInteger(ListenPortText, out var listenPort) ||
            listenPort is < 1 or > 65535 ||
            !TryParseAsciiInteger(RetentionHoursText, out var retentionHours) ||
            retentionHours is < 0 or > 168)
        {
            return null;
        }

        return new ServiceConfigurationEditRequest(
            listenPort,
            retentionHours,
            RotateToken,
            RotateToken ? ApiToken : null);
    }

    private static bool TryParseAsciiInteger(string? text, out int value)
    {
        value = default;
        return !string.IsNullOrEmpty(text) &&
            text.All(static character => character is >= '0' and <= '9') &&
            int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private Task SetFailureAsync(string errorCode) => ApplyOnUiAsync(() =>
    {
        ErrorCode = errorCode;
        ConfirmedSummary = null;
        State = ServiceSettingsDialogState.Failed;
    });

    private void ClearOneTimeToken() => OneTimeApiToken = null;

    private Task ApplyOnUiAsync(Action action) =>
        Volatile.Read(ref _disposed) == 0
            ? _dispatcher.InvokeAsync(action, CancellationToken.None)
            : Task.CompletedTask;

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
}
