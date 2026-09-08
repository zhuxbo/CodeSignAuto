#if CODESIGNAUTO_WPF
using CodeSignAuto.App.UI.Localization;
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI.Views;

public partial class ActivationImportDialog : System.Windows.Window
{
    private readonly ActivationViewModel _viewModel;
    private readonly ActivationImportDialogState _state = new();

    public ActivationImportDialog(ActivationViewModel viewModel)
    {
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        InitializeComponent();
        DataContext = viewModel;
    }

    private void OnLoaded(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        SecretInput.Focus();
        System.Windows.Input.Keyboard.Focus(SecretInput);
    }

    private async void OnSave(object sender, System.Windows.RoutedEventArgs eventArgs)
    {
        if (!_state.TryBeginSave())
        {
            return;
        }

        SetSavingUi(saving: true);
        var saved = false;
        try
        {
            await UiAsyncExceptionBoundary.RunAsync(
                async () => saved = await _viewModel.ValidateAndSaveAsync(_viewModel.OtpauthInput)
                    .ConfigureAwait(true),
                () => _viewModel.ReportUiFailureAsync("management_unavailable")).ConfigureAwait(true);
        }
        finally
        {
            var closeAfterSave = _state.CompleteSave(saved);
            if (_state.RequestUserClose() != ActivationImportCloseDecision.AlreadyClosed)
            {
                SetSavingUi(saving: false);
            }

            if (closeAfterSave && IsLoaded)
            {
                DialogResult = true;
            }
        }
    }

    private void OnCancel(object sender, System.Windows.RoutedEventArgs eventArgs) => CancelAndClose();

    private void OnPreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs eventArgs)
    {
        if (eventArgs.Key == System.Windows.Input.Key.Escape)
        {
            eventArgs.Handled = true;
            CancelAndClose();
        }
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs eventArgs)
    {
        if (_state.RequestUserClose() == ActivationImportCloseDecision.SaveInProgress)
        {
            eventArgs.Cancel = true;
            ShowSaveInProgress();
        }
    }

    private void OnClosed(object? sender, EventArgs eventArgs)
    {
        _state.MarkClosed();
        SecretInput.Clear();
        _viewModel.OtpauthInput = string.Empty;
    }

    private void CancelAndClose()
    {
        if (_state.RequestUserClose() != ActivationImportCloseDecision.Allowed)
        {
            ShowSaveInProgress();
            return;
        }

        SecretInput.Clear();
        _viewModel.OtpauthInput = string.Empty;
        DialogResult = false;
    }

    private void SetSavingUi(bool saving)
    {
        SecretInput.IsEnabled = !saving;
        SaveButton.IsEnabled = !saving;
        SaveStatus.Text = saving
            ? UiCulture.Text("ActivationSaving")
            : UiCulture.Text("ActivationImportStorageNotice");
    }

    private void ShowSaveInProgress()
    {
        SaveStatus.Text = UiCulture.Text("ActivationSaving");
        CancelButton.Focus();
    }
}
#endif
