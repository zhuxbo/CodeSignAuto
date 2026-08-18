#if SIMPLYSIGN_WPF
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.App.UI.ViewModels;

namespace SimplySignAuto.App.UI.Views;

public partial class QuickSignView : System.Windows.Controls.UserControl
{
    public QuickSignView() => InitializeComponent();

    private async void OnChooseFile(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is not QuickSignViewModel viewModel)
        {
            return;
        }

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            CheckFileExists = true,
            CheckPathExists = true,
            Multiselect = false,
            Filter = viewModel.FileDialogFilter,
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            await viewModel.SelectFileAsync(dialog.FileName).ConfigureAwait(true);
        }
        catch (LocalJobException)
        {
            // ViewModel already exposes a stable, path-free error state.
        }
    }
}
#endif
