#if CODESIGNAUTO_WPF
using CodeSignAuto.App.UI.Localization;
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI.Views;

public partial class JobsView : System.Windows.Controls.UserControl
{
    private bool _loaded;

    public JobsView() => InitializeComponent();

    private async void OnLoaded(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (_loaded || DataContext is not JobsViewModel viewModel)
        {
            return;
        }

        _loaded = true;
        await RefreshAsync(viewModel).ConfigureAwait(true);
    }

    private async void OnRefresh(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is JobsViewModel viewModel)
        {
            await RefreshAsync(viewModel).ConfigureAwait(true);
        }
    }

    private async void OnLoadMore(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is not JobsViewModel viewModel)
        {
            return;
        }

        try
        {
            await viewModel.LoadNextPageAsync(CancellationToken.None).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async void OnSaveResult(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (DataContext is not JobsViewModel viewModel ||
            sender is not System.Windows.Controls.Button { Tag: Guid jobId })
        {
            return;
        }

        var item = viewModel.Items.FirstOrDefault(candidate => candidate.JobId == jobId);
        if (item is null || !item.HasResult)
        {
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = item.DefaultSignedCopyName,
            AddExtension = true,
            OverwritePrompt = item.CanOverwriteResult,
            Filter = item.IsPdf
                ? UiCulture.Text("JobsPdfFilter")
                : UiCulture.Text("JobsSoftwareFilter"),
            Title = UiCulture.Text("JobsSaveDialogTitle"),
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        await viewModel.SaveResultAsAsync(
            jobId,
            dialog.FileName,
            File.Exists(dialog.FileName),
            CancellationToken.None).ConfigureAwait(true);
    }

    private static async Task RefreshAsync(JobsViewModel viewModel)
    {
        try
        {
            await viewModel.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
        }
    }
}
#endif
