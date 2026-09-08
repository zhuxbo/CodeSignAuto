using System.Globalization;

namespace CodeSignAuto.Setup;

internal sealed class SetupForm : Form
{
    private readonly SetupBootstrapper _bootstrapper;
    private readonly SetupProductKind _productKind;
    private readonly Label _title;
    private readonly Label _description;
    private readonly Label _languageLabel;
    private readonly ComboBox _language;
    private readonly Label _modeLabel;
    private readonly ComboBox _mode;
    private readonly Label _modeDescription;
    private readonly Label _modeWarning;
    private readonly Label _status;
    private readonly ProgressBar _progress;
    private readonly Button _install;
    private readonly Button _close;
    private readonly bool _canChangeMode;
    private CultureInfo _culture;
    private string _statusResourceKey = "StatusReady";
    private object?[] _statusArguments = [];
    private bool _updatingLanguage;
    private bool _updatingMode;
    private bool _running;
    private bool _finished;

    public SetupForm(
        SetupBootstrapper bootstrapper,
        SetupProductKind productKind,
        CultureInfo initialCulture,
        SetupInstallationSelection? installationSelection)
    {
        _bootstrapper = bootstrapper ?? throw new ArgumentNullException(nameof(bootstrapper));
        _productKind = productKind;
        _canChangeMode = installationSelection?.CanChange == true;
        if (productKind == SetupProductKind.Main != (installationSelection is not null))
        {
            throw new ArgumentException("The installation selection must match the product kind.", nameof(installationSelection));
        }

        _culture = SetupCulture.ResolveSelection(initialCulture?.Name ?? string.Empty);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(620, productKind == SetupProductKind.Main ? 350 : 230);
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
        _modeLabel = new Label
        {
            Name = "SetupModeLabel",
            AutoSize = false,
            TextAlign = ContentAlignment.MiddleRight,
            Location = new Point(28, 108),
            Size = new Size(100, 28),
            Visible = productKind == SetupProductKind.Main,
        };
        _mode = new ComboBox
        {
            Name = "SetupMode",
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location = new Point(134, 109),
            Size = new Size(180, 28),
            Enabled = installationSelection?.CanChange == true,
            Visible = productKind == SetupProductKind.Main,
        };
        _modeDescription = new Label
        {
            Name = "SetupModeDescription",
            AutoSize = false,
            Location = new Point(28, 146),
            Size = new Size(564, 40),
            Visible = productKind == SetupProductKind.Main,
        };
        _modeWarning = new Label
        {
            Name = "SetupModeWarning",
            AutoSize = false,
            ForeColor = SystemColors.GrayText,
            Location = new Point(28, 190),
            Size = new Size(564, 30),
            Visible = productKind == SetupProductKind.Main,
        };
        _status = new Label
        {
            Name = "SetupStatus",
            AutoSize = false,
            Location = new Point(28, productKind == SetupProductKind.Main ? 229 : 109),
            Size = new Size(564, 24),
        };
        _progress = new ProgressBar
        {
            Name = "SetupProgress",
            Location = new Point(28, productKind == SetupProductKind.Main ? 256 : 136),
            Size = new Size(564, 18),
            Style = ProgressBarStyle.Blocks,
        };
        _install = new Button
        {
            Name = "SetupInstall",
            Location = new Point(426, productKind == SetupProductKind.Main ? 298 : 178),
            Size = new Size(80, 30),
        };
        _install.Click += InstallClicked;
        _close = new Button
        {
            Name = "SetupClose",
            DialogResult = DialogResult.Cancel,
            Location = new Point(512, productKind == SetupProductKind.Main ? 298 : 178),
            Size = new Size(80, 30),
        };
        _close.Click += (_, _) => Close();
        _language.SelectedIndexChanged += LanguageChanged;
        _mode.SelectedIndexChanged += ModeChanged;
        Controls.AddRange(
            [
                _title, _languageLabel, _language, _description, _modeLabel, _mode,
                _modeDescription, _modeWarning, _status, _progress, _install, _close,
            ]);
        CancelButton = _close;
        AcceptButton = _install;
        FormClosing += HandleFormClosing;
        ApplyCulture();
        if (installationSelection is not null)
        {
            _mode.SelectedIndex = installationSelection.Mode == SetupInstallationMode.Manual ? 0 : 1;
            ApplyModeText();
        }
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
        var returnToModeSelection = false;
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
            SetupInstallationMode? mode = _productKind == SetupProductKind.Main
                ? _mode.SelectedIndex switch
                {
                    0 => SetupInstallationMode.Manual,
                    1 => SetupInstallationMode.Service,
                    _ => throw new SetupBootstrapperException("setup_mode_invalid"),
                }
                : null;
            while (true)
            {
                try
                {
                    ExitCode = await _bootstrapper.RunAsync(mode, progress, CancellationToken.None);
                    SetStatus(
                        ExitCode == 0 ? "StatusInstallComplete" : "StatusInstallFailedCode",
                        ExitCode == 0 ? [] : [ExitCode]);
                    break;
                }
                catch (SetupBootstrapperException error) when (
                    mode == SetupInstallationMode.Service &&
                    SetupFailurePolicy.CanReturnToModeSelection(
                        _productKind,
                        SetupInstallationMode.Service,
                        _canChangeMode,
                        error.Code))
                {
                    using var resolution = new SetupAutoLogonResolutionDialog(
                        _culture,
                        error.Code,
                        error.Code == "autologon_conflict"
                            ? SetupAutoLogonConflict.ReadAccountName()
                            : null);
                    _ = resolution.ShowDialog(this);
                    if (resolution.Resolution == SetupAutoLogonResolution.UseManualMode)
                    {
                        _mode.SelectedIndex = 0;
                        mode = SetupInstallationMode.Manual;
                        returnToModeSelection = true;
                        ResetForModeSelection();
                        break;
                    }

                    if (resolution.Resolution != SetupAutoLogonResolution.DisableAndContinue)
                    {
                        returnToModeSelection = true;
                        ResetForModeSelection();
                        break;
                    }

                    try
                    {
                        _progress.Value = 0;
                        SetStatus("StatusDisablingAutoLogon");
                        await _bootstrapper.DisableAutoLogonAsync(
                            progress,
                            CancellationToken.None);
                        _progress.Value = 0;
                        SetStatus("StatusRetryingInstallation");
                    }
                    catch (SetupBootstrapperException cleanupError)
                    {
                        ShowFailure(cleanupError);
                        returnToModeSelection = true;
                        ResetForModeSelection();
                        break;
                    }
                    catch
                    {
                        ShowFailure(new SetupBootstrapperException("autologon_cleanup_failed"));
                        returnToModeSelection = true;
                        ResetForModeSelection();
                        break;
                    }
                }
                catch (SetupBootstrapperException error)
                {
                    ShowFailure(error);
                    break;
                }
            }
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
            _finished = !returnToModeSelection;
            _install.Enabled = true;
            _close.Enabled = true;
            _close.Visible = returnToModeSelection;
            AcceptButton = _install;
            ApplyCulture();
        }
    }

    private void ResetForModeSelection()
    {
        ExitCode = 2;
        _progress.Value = 0;
        SetStatus("StatusReady");
    }

    private void ShowFailure(SetupBootstrapperException error)
    {
        ExitCode = 1;
        SetStatus("StatusInstallFailed");
        MessageBox.Show(
            this,
            error.GetLocalizedMessage(
                _culture,
                error.Code == "autologon_conflict"
                    ? SetupAutoLogonConflict.ReadAccountName()
                    : null),
            Text,
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }

    private void ModeChanged(object? sender, EventArgs eventArgs)
    {
        if (_updatingMode || _mode.SelectedIndex is < 0 or > 1)
        {
            return;
        }

        ApplyModeText();
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
        _modeLabel.Text = SetupCulture.GetString("ModeLabel", _culture);
        _modeWarning.Text = SetupCulture.GetString("ModeSwitchRequiresReinstall", _culture);
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

        if (!isPdfExtension)
        {
            var selected = _mode.SelectedIndex is 0 or 1 ? _mode.SelectedIndex : 0;
            _updatingMode = true;
            try
            {
                _mode.Items.Clear();
                _mode.Items.Add(SetupCulture.GetString("ModeManualName", _culture));
                _mode.Items.Add(SetupCulture.GetString("ModeServiceName", _culture));
                _mode.SelectedIndex = selected;
            }
            finally
            {
                _updatingMode = false;
            }

            ApplyModeText();
        }
    }

    private void ApplyModeText()
    {
        _modeDescription.Text = SetupCulture.GetString(
            _mode.SelectedIndex == 0 ? "ModeManualDescription" : "ModeServiceDescription",
            _culture);
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
