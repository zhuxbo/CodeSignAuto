#if CODESIGNAUTO_WPF
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI.Views;

public partial class ServiceSettingsView : System.Windows.Controls.UserControl
{
    private bool _loaded;

    public ServiceSettingsView() => InitializeComponent();

    private async void OnLoaded(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (_loaded || DataContext is not ServiceSettingsViewModel viewModel)
        {
            return;
        }

        _loaded = true;
        await UiAsyncExceptionBoundary.RunAsync(
            () => viewModel.LoadAsync(),
            () => viewModel.ReportUiFailureAsync("management_unavailable")).ConfigureAwait(true);
    }

    private async void OnEdit(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is ServiceSettingsViewModel viewModel)
        {
            await UiAsyncExceptionBoundary.RunAsync(
                () => viewModel.EditAsync(),
                () => viewModel.ReportUiFailureAsync("configure_service_failed")).ConfigureAwait(true);
        }
    }
}
#endif
