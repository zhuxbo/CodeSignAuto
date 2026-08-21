using System.ComponentModel;
using System.Runtime.CompilerServices;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.App.UI.ViewModels;

public sealed class ServiceSettingsViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly IAgentAdministrationClient _administration;
    private readonly IServiceConfigurationEditor _editor;
    private readonly IServiceSettingsDialogService _dialogs;
    private readonly IClipboardService _clipboard;
    private readonly IUiDispatcher _dispatcher;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private ServiceSettingsSummary? _settings;
    private string? _errorCode;
    private int _disposed;

    internal ServiceSettingsViewModel(
        IAgentAdministrationClient administration,
        IServiceConfigurationEditor editor,
        IServiceSettingsDialogService dialogs,
        IClipboardService clipboard,
        IUiDispatcher? dispatcher = null)
    {
        _administration = administration ?? throw new ArgumentNullException(nameof(administration));
        _editor = editor ?? throw new ArgumentNullException(nameof(editor));
        _dialogs = dialogs ?? throw new ArgumentNullException(nameof(dialogs));
        _clipboard = clipboard ?? throw new ArgumentNullException(nameof(clipboard));
        _dispatcher = dispatcher ?? InlineSettingsDispatcher.Instance;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    internal IAgentAdministrationClient AdministrationClient => _administration;

    internal IServiceConfigurationEditor ConfigurationEditor => _editor;

    internal IServiceSettingsDialogService DialogService => _dialogs;

    internal IUiDispatcher Dispatcher => _dispatcher;

    public ServiceSettingsSummary? Settings
    {
        get => _settings;
        private set
        {
            if (SetField(ref _settings, value))
            {
                OnPropertyChanged(nameof(ProductVersionText));
                OnPropertyChanged(nameof(RetentionText));
                OnPropertyChanged(nameof(MaximumUploadText));
            }
        }
    }

    public string? ProductVersionText => Settings is null
        ? null
        : UiCulture.Format("VersionFormat", Settings.ProductVersion);

    public string? RetentionText => Settings is null
        ? null
        : Settings.RetentionHours == 0
            ? UiCulture.Text("ServiceSettingsKeepForever")
            : UiCulture.Format("ServiceSettingsHoursFormat", Settings.RetentionHours);

    public string? MaximumUploadText => Settings is null
        ? null
        : $"{Settings.MaximumUploadBytes / (1024L * 1024L)} MB";

    public string? ErrorCode
    {
        get => _errorCode;
        private set => SetField(ref _errorCode, value);
    }

    public async Task LoadAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await _operationGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            var settings = await _administration.GetServiceSettingsAsync(operation.Token).ConfigureAwait(false);
            await ApplyAsync(() =>
            {
                Settings = settings;
                ErrorCode = null;
            }).ConfigureAwait(false);
        }
        catch (ManagementUnavailableException)
        {
            await ApplyAsync(() => ErrorCode = "management_unavailable").ConfigureAwait(false);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async Task<bool> EditAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await _operationGate.WaitAsync(operation.Token).ConfigureAwait(false);
        try
        {
            var settings = Settings;
            if (settings is null)
            {
                await ApplyAsync(() => ErrorCode = "management_unavailable").ConfigureAwait(false);
                return false;
            }

            using var dialog = new ServiceSettingsDialogViewModel(
                settings,
                _editor,
                _administration,
                _clipboard,
                _dispatcher);
            await _dialogs.ShowAsync(dialog, operation.Token).ConfigureAwait(false);
            await ApplyAsync(() =>
            {
                if (dialog.ConfirmedSummary is not null)
                {
                    Settings = dialog.ConfirmedSummary;
                    ErrorCode = null;
                }
                else if (dialog.ErrorCode is not null)
                {
                    ErrorCode = dialog.ErrorCode;
                }
            }).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ManagementUnavailableException)
        {
            await ApplyAsync(() => ErrorCode = "management_unavailable").ConfigureAwait(false);
            return false;
        }
        catch (Exception)
        {
            await ApplyAsync(() => ErrorCode = "configure_service_failed").ConfigureAwait(false);
            return false;
        }
        finally
        {
            _operationGate.Release();
        }
    }

    internal Task ReportUiFailureAsync(string errorCode)
    {
        if (errorCode is not ("management_unavailable" or "configure_service_failed"))
        {
            throw new ArgumentException("The UI error code is invalid.", nameof(errorCode));
        }

        return ApplyAsync(() => ErrorCode = errorCode);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _lifetime.Cancel();
            _operationGate.Wait();
            _operationGate.Release();
            _operationGate.Dispose();
            _lifetime.Dispose();
        }
    }

    private async Task ApplyAsync(Action action)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        await _dispatcher.InvokeAsync(() =>
        {
            if (Volatile.Read(ref _disposed) == 0)
            {
                action();
            }
        }, CancellationToken.None).ConfigureAwait(false);
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

    private sealed class InlineSettingsDispatcher : IUiDispatcher
    {
        public static InlineSettingsDispatcher Instance { get; } = new();

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }
}
