#if CODESIGNAUTO_WPF
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI.Views;

public partial class ApplicationSettingsView : System.Windows.Controls.UserControl
{
    public ApplicationSettingsView() => InitializeComponent();

    private async void OnSave(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is ApplicationSettingsViewModel viewModel)
        {
            await UiAsyncExceptionBoundary.RunAsync(
                () => viewModel.SaveAsync(),
                static () => Task.CompletedTask).ConfigureAwait(true);
        }
    }
}
#endif
