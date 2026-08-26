#if SIMPLYSIGN_WPF
using System.Globalization;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.UI;

internal enum GraphicalUninstallProduct
{
    Main,
    PdfExtension,
}

internal sealed class UninstallForm : System.Windows.Forms.Form
{
    private readonly GraphicalUninstallProduct _product;
    private readonly CultureInfo _culture;
    private readonly bool _restartRequired;
    private readonly Func<TextWriter, TextWriter, CancellationToken, Task<int>> _operation;
    private readonly System.Windows.Forms.Label _status;
    private readonly System.Windows.Forms.ProgressBar _progress;
    private readonly System.Windows.Forms.Button _action;
    private readonly System.Windows.Forms.Button _cancel;
    private readonly CancellationToken _cancellationToken;
    private bool _running;
    private bool _finished;

    internal UninstallForm(
        GraphicalUninstallProduct product,
        CultureInfo culture,
        InstallationMode? mode,
        Func<TextWriter, TextWriter, CancellationToken, Task<int>> operation,
        CancellationToken cancellationToken)
    {
        _product = product;
        _culture = culture ?? throw new ArgumentNullException(nameof(culture));
        _restartRequired = UninstallPresentation.RequiresRestart(product);
        _operation = operation ?? throw new ArgumentNullException(nameof(operation));
        _cancellationToken = cancellationToken;

        Text = TextFor(product == GraphicalUninstallProduct.Main
            ? "UninstallTitle"
            : "PdfUninstallTitle");
        StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
        FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(560, 270);
        AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;

        var title = new System.Windows.Forms.Label
        {
            Name = "UninstallTitle",
            AutoSize = false,
            Font = new Font(Font, FontStyle.Bold),
            Location = new Point(28, 24),
            Size = new Size(504, 28),
            Text = Text,
        };
        var description = new System.Windows.Forms.Label
        {
            Name = "UninstallDescription",
            AutoSize = false,
            Location = new Point(28, 64),
            Size = new Size(504, 54),
            Text = UninstallPresentation.DescribeProduct(product, mode, culture),
        };
        _status = new System.Windows.Forms.Label
        {
            Name = "UninstallStatus",
            AutoSize = false,
            Location = new Point(28, 128),
            Size = new Size(504, 58),
            Text = TextFor("UninstallReady"),
        };
        _progress = new System.Windows.Forms.ProgressBar
        {
            Name = "UninstallProgress",
            Location = new Point(28, 194),
            Size = new Size(504, 18),
            Minimum = 0,
            Maximum = 100,
        };
        _action = new System.Windows.Forms.Button
        {
            Name = "UninstallAction",
            Location = new Point(366, 228),
            Size = new Size(80, 30),
            Text = TextFor("UninstallAction"),
        };
        _action.Click += StartClicked;
        _cancel = new System.Windows.Forms.Button
        {
            Name = "UninstallCancel",
            DialogResult = System.Windows.Forms.DialogResult.Cancel,
            Location = new Point(452, 228),
            Size = new Size(80, 30),
            Text = TextFor("ActionCancel"),
        };
        Controls.AddRange([title, description, _status, _progress, _action, _cancel]);
        AcceptButton = _action;
        CancelButton = _cancel;
        FormClosing += HandleFormClosing;
    }

    internal int ExitCode { get; private set; } = 2;

    private async void StartClicked(object? sender, EventArgs eventArgs)
    {
        if (_finished)
        {
            Close();
            return;
        }

        if (_running)
        {
            return;
        }

        _running = true;
        _action.Enabled = false;
        _cancel.Enabled = false;
        _progress.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
        _status.Text = TextFor("UninstallRunning");
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        try
        {
            ExitCode = await _operation(output, error, _cancellationToken);
        }
        catch (Exception failure) when (
            failure is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ExitCode = 1;
            await error.WriteLineAsync("uninstall_failed");
        }

        _running = false;
        _finished = true;
        _progress.Style = System.Windows.Forms.ProgressBarStyle.Blocks;
        _progress.Value = ExitCode == 0 ? 100 : 0;
        _status.Text = ExitCode == 0
            ? TextFor(_product == GraphicalUninstallProduct.PdfExtension
                ? "PdfUninstallComplete"
                : _restartRequired
                    ? "UninstallCompleteRestart"
                    : "UninstallComplete")
            : UninstallPresentation.DescribeFailure(
                UninstallPresentation.NormalizeFailureCode(error.ToString()),
                _culture);
        _action.Text = TextFor("ActionClose");
        _action.Enabled = true;
        _cancel.Visible = false;
        AcceptButton = _action;
    }

    private void HandleFormClosing(object? sender, System.Windows.Forms.FormClosingEventArgs eventArgs)
    {
        if (_running)
        {
            eventArgs.Cancel = true;
        }
    }

    private string TextFor(string key) => UiCulture.GetString(key, _culture);
}

internal static class GraphicalUninstallHost
{
    internal static int RunMain(
        TextWriter diagnostics,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);
        var mode = TryReadMainMode(() =>
            new WindowsInstallationReceiptStore()
                .LoadOptionalAsync(cancellationToken)
                .GetAwaiter()
                .GetResult()?
                .Mode);

        return Run(
            GraphicalUninstallProduct.Main,
            mode,
            (output, error, token) => UninstallCommand.ExecuteAsync(
                [],
                output,
                error,
                token,
                diagnostics),
            cancellationToken);
    }

    internal static InstallationMode? TryReadMainMode(Func<InstallationMode?> readMode)
    {
        ArgumentNullException.ThrowIfNull(readMode);
        try
        {
            return readMode();
        }
        catch (Exception error) when (
            error is InstallException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            // The uninstall command will report the authoritative ownership error.
            return null;
        }
    }

    internal static int RunPdfExtension(CancellationToken cancellationToken) => Run(
        GraphicalUninstallProduct.PdfExtension,
        mode: null,
        static (output, error, token) => PdfExtensionCommand.ExecuteAsync(
            ["uninstall"],
            output,
            error,
            token,
            new WindowsPdfExtensionOperations()),
        cancellationToken);

    private static int Run(
        GraphicalUninstallProduct product,
        InstallationMode? mode,
        Func<TextWriter, TextWriter, CancellationToken, Task<int>> operation,
        CancellationToken cancellationToken)
    {
        var culture = LoadCulture(cancellationToken);
        UiCulture.Apply(culture);
        System.Windows.Forms.Application.EnableVisualStyles();
        System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
        using var form = new UninstallForm(
            product,
            culture,
            mode,
            operation,
            cancellationToken);
        System.Windows.Forms.Application.Run(form);
        return form.ExitCode;
    }

    private static CultureInfo LoadCulture(CancellationToken cancellationToken)
    {
        try
        {
            return new UiPreferenceStore()
                .LoadAsync(CultureInfo.InstalledUICulture, cancellationToken)
                .GetAwaiter()
                .GetResult();
        }
        catch (Exception error) when (
            error is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return UiCulture.ResolveDefault(CultureInfo.InstalledUICulture);
        }
    }
}
#endif
