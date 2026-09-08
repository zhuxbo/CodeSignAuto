#if CODESIGNAUTO_WPF
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI.Views;

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
            Title = viewModel.FileDialogTitle,
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
