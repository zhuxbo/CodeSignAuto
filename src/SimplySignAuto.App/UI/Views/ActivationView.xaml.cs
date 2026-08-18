#if SIMPLYSIGN_WPF
using SimplySignAuto.App.UI.ViewModels;

namespace SimplySignAuto.App.UI.Views;

public partial class ActivationView : System.Windows.Controls.UserControl
{
    public ActivationView() => InitializeComponent();

    private void OnOpenImport(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is not ActivationViewModel viewModel)
        {
            return;
        }

        viewModel.BeginOtpImport();

        var dialog = new ActivationImportDialog(viewModel)
        {
            Owner = System.Windows.Window.GetWindow(this),
        };
        _ = dialog.ShowDialog();
        OpenImportButton.Focus();
    }

    private async void OnGenerateTotp(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is ActivationViewModel viewModel)
        {
            await UiAsyncExceptionBoundary.RunAsync(
                () => viewModel.GenerateTotpAsync(),
                () => viewModel.ReportUiFailureAsync("management_unavailable")).ConfigureAwait(true);
        }
    }

    private async void OnCopyTotp(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is ActivationViewModel viewModel)
        {
            await UiAsyncExceptionBoundary.RunAsync(
                () => viewModel.CopyTotpAsync(),
                () => viewModel.ReportUiFailureAsync("clipboard_unavailable")).ConfigureAwait(true);
        }
    }

    private void OnVisibilityChanged(
        object sender,
        System.Windows.DependencyPropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.NewValue is false && DataContext is ActivationViewModel viewModel)
        {
            viewModel.DeactivateTotp();
        }
    }

    private void OnUnloaded(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is ActivationViewModel viewModel)
        {
            viewModel.DeactivateTotp();
        }
    }

    private async void OnClearOtpAndLogout(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is ActivationViewModel viewModel)
        {
            await UiAsyncExceptionBoundary.RunAsync(
                () => viewModel.ClearOtpAndLogoutAsync(),
                () => viewModel.ReportUiFailureAsync("management_unavailable")).ConfigureAwait(true);
        }
    }

    private async void OnCopyDiagnostics(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is ActivationViewModel viewModel)
        {
            await UiAsyncExceptionBoundary.RunAsync(
                () => viewModel.CopyRedactedDiagnosticsAsync(),
                () => viewModel.ReportUiFailureAsync("clipboard_unavailable")).ConfigureAwait(true);
        }
    }

    private async void OnSerialDoubleClick(
        object sender,
        System.Windows.Input.MouseButtonEventArgs eventArgs)
    {
        if (DataContext is ActivationViewModel viewModel &&
            sender is System.Windows.FrameworkElement { DataContext: CertificateCardViewModel certificate })
        {
            eventArgs.Handled = true;
            await UiAsyncExceptionBoundary.RunAsync(
                () => viewModel.CopyCertificateSerialAsync(certificate),
                () => viewModel.ReportUiFailureAsync("clipboard_unavailable")).ConfigureAwait(true);
        }
    }
}
#endif
