using System.Globalization;

namespace SimplySignAuto.Setup;

internal sealed class SetupForm : Form
{
    private readonly SetupBootstrapper _bootstrapper;
    private readonly SetupProductKind _productKind;
    private readonly Label _title;
    private readonly Label _description;
    private readonly Label _languageLabel;
    private readonly ComboBox _language;
    private readonly Label _status;
    private readonly ProgressBar _progress;
    private readonly Button _install;
    private readonly Button _close;
    private CultureInfo _culture;
    private string _statusResourceKey = "StatusReady";
    private object?[] _statusArguments = [];
    private bool _updatingLanguage;
    private bool _running;
    private bool _finished;

    public SetupForm(
        SetupBootstrapper bootstrapper,
        SetupProductKind productKind,
        CultureInfo initialCulture)
    {
        _bootstrapper = bootstrapper ?? throw new ArgumentNullException(nameof(bootstrapper));
        _productKind = productKind;
        _culture = SetupCulture.ResolveSelection(initialCulture?.Name ?? string.Empty);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(620, 230);
        AutoScaleMode = AutoScaleMode.Dpi;

        _title = new Label
        {
            Name = "SetupTitle",
            AutoSize = false,
            Font = new Font(Font, FontStyle.Bold),
            Location = new Point(28, 24),
            Size = new Size(350, 28),
        };
        _languageLabel = new Label
        {
            Name = "SetupLanguageLabel",
            AutoSize = false,
            TextAlign = ContentAlignment.MiddleRight,
            Location = new Point(390, 20),
            Size = new Size(92, 28),
        };
        _language = new ComboBox
        {
            Name = "SetupLanguage",
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location = new Point(488, 21),
            Size = new Size(104, 28),
        };
        _description = new Label
        {
            Name = "SetupDescription",
            AutoSize = false,
            Location = new Point(28, 62),
            Size = new Size(564, 38),
        };
        _status = new Label
        {
            Name = "SetupStatus",
            AutoSize = false,
            Location = new Point(28, 109),
            Size = new Size(564, 24),
        };
        _progress = new ProgressBar
        {
            Name = "SetupProgress",
            Location = new Point(28, 136),
            Size = new Size(564, 18),
            Style = ProgressBarStyle.Blocks,
        };
        _install = new Button
        {
            Name = "SetupInstall",
            Location = new Point(426, 178),
            Size = new Size(80, 30),
        };
        _install.Click += InstallClicked;
        _close = new Button
        {
            Name = "SetupClose",
            DialogResult = DialogResult.Cancel,
            Location = new Point(512, 178),
            Size = new Size(80, 30),
        };
        _close.Click += (_, _) => Close();
        _language.SelectedIndexChanged += LanguageChanged;
        Controls.AddRange(
            [_title, _languageLabel, _language, _description, _status, _progress, _install, _close]);
        CancelButton = _close;
        AcceptButton = _install;
        FormClosing += HandleFormClosing;
        ApplyCulture();
    }

    public int ExitCode { get; private set; } = 2;

    private async void InstallClicked(object? sender, EventArgs eventArgs)
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
        _install.Enabled = false;
        _close.Enabled = false;
        _progress.Minimum = 0;
        _progress.Maximum = 100;
        _progress.Value = 0;
        SetStatus("StatusVerifyingMedia");
        try
        {
            var progress = new Progress<SetupProgress>(value =>
            {
                _progress.Value = value.Percent;
                SetStatus(value.Message);
            });
            ExitCode = await _bootstrapper.RunAsync(progress, CancellationToken.None);
            if (ExitCode == 0)
            {
                SetStatus("StatusInstallComplete");
            }
            else
            {
                SetStatus("StatusInstallFailedCode", ExitCode);
            }
        }
        catch (SetupBootstrapperException error)
        {
            ExitCode = 1;
            SetStatus("StatusInstallFailed");
            MessageBox.Show(
                this,
                error.GetLocalizedMessage(_culture),
                Text,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        catch
        {
            ExitCode = 1;
            SetStatus("StatusInstallFailed");
            var failure = new SetupBootstrapperException("setup_failed");
            MessageBox.Show(
                this,
                failure.GetLocalizedMessage(_culture),
                Text,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            _running = false;
            _finished = true;
            _install.Enabled = true;
            _close.Visible = false;
            AcceptButton = _install;
            ApplyCulture();
        }
    }

    private void LanguageChanged(object? sender, EventArgs eventArgs)
    {
        if (_updatingLanguage || _language.SelectedIndex is < 0 or > 1)
        {
            return;
        }

        _culture = SetupCulture.ResolveSelection(
            _language.SelectedIndex == 0 ? SetupCulture.ChineseName : SetupCulture.EnglishName);
        ApplyCulture();
    }

    private void ApplyCulture()
    {
        var isPdfExtension = _productKind == SetupProductKind.PdfExtension;
        Text = SetupCulture.GetString(isPdfExtension ? "WindowPdfTitle" : "WindowMainTitle", _culture);
        _title.Text = SetupCulture.GetString(isPdfExtension ? "PdfTitle" : "MainTitle", _culture);
        _description.Text = SetupCulture.GetString(
            isPdfExtension ? "PdfDescription" : "MainDescription",
            _culture);
        _languageLabel.Text = SetupCulture.GetString("LanguageLabel", _culture);
        _status.Text = SetupCulture.Format(_statusResourceKey, _culture, _statusArguments);
        _install.Text = SetupCulture.GetString(_finished ? "CloseButton" : "InstallButton", _culture);
        _close.Text = SetupCulture.GetString("CancelButton", _culture);

        _updatingLanguage = true;
        try
        {
            _language.Items.Clear();
            _language.Items.Add(SetupCulture.GetString("LanguageChinese", _culture));
            _language.Items.Add(SetupCulture.GetString("LanguageEnglish", _culture));
            _language.SelectedIndex = _culture.Name == SetupCulture.ChineseName ? 0 : 1;
        }
        finally
        {
            _updatingLanguage = false;
        }
    }

    private void SetStatus(string resourceKey, params object?[] arguments)
    {
        _statusResourceKey = resourceKey;
        _statusArguments = arguments;
        _status.Text = SetupCulture.Format(resourceKey, _culture, arguments);
    }

    private void HandleFormClosing(object? sender, FormClosingEventArgs eventArgs)
    {
        if (_running)
        {
            eventArgs.Cancel = true;
        }
    }
}
