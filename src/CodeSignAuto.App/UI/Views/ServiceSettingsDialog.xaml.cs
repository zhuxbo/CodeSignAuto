#if CODESIGNAUTO_WPF
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI.Views;

public partial class ServiceSettingsDialog : System.Windows.Window
{
    private readonly ServiceSettingsDialogViewModel _viewModel;

    internal ServiceSettingsDialog(ServiceSettingsDialogViewModel viewModel)
    {
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        InitializeComponent();
        DataContext = viewModel;
    }

    private void OnTokenChanged(object sender, System.Windows.RoutedEventArgs eventArgs) =>
        _viewModel.ApiToken = ApiTokenInput.Password;

    private async void OnApply(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        var applying = _viewModel.ApplyAsync(CancellationToken.None);
        ApiTokenInput.Clear();
        _ = await applying.ConfigureAwait(true);
    }

    private void OnCopyToken(object sender, System.Windows.RoutedEventArgs eventArgs) =>
        _ = _viewModel.CopyOneTimeToken();

    private void OnAcknowledgeToken(object sender, System.Windows.RoutedEventArgs eventArgs) =>
        _viewModel.AcknowledgeOneTimeToken();

    private void OnClose(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (_viewModel.CanClose)
        {
            Close();
        }
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs eventArgs)
    {
        if (!_viewModel.CanClose)
        {
            eventArgs.Cancel = true;
        }
    }

    private void OnClosed(object? sender, EventArgs eventArgs)
    {
        ApiTokenInput.Clear();
        _viewModel.ClearSensitiveResult();
    }
}

internal sealed class WpfServiceSettingsDialogService : IServiceSettingsDialogService
{
    private readonly System.Windows.Window _owner;

    internal WpfServiceSettingsDialogService(System.Windows.Window owner) =>
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));

    internal ServiceSettingsDialog CreateOwnedDialog(ServiceSettingsDialogViewModel viewModel) =>
        new(viewModel)
        {
            Owner = _owner,
        };

    public async Task ShowAsync(
        ServiceSettingsDialogViewModel viewModel,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        cancellationToken.ThrowIfCancellationRequested();
        await _owner.Dispatcher.InvokeAsync(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ = CreateOwnedDialog(viewModel).ShowDialog();
        }).Task.ConfigureAwait(false);
    }
}
#endif
