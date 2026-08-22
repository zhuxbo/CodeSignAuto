using System.Globalization;

namespace SimplySignAuto.Setup;

internal enum SetupAutoLogonResolution
{
    Cancel,
    DisableAndContinue,
    UseManualMode,
}

internal sealed class SetupAutoLogonResolutionDialog : Form
{
    public SetupAutoLogonResolutionDialog(
        CultureInfo culture,
        string failureCode,
        string? accountName)
    {
        var selectedCulture = SetupCulture.ResolveSelection(culture?.Name ?? string.Empty);
        if (failureCode is not ("autologon_conflict" or "autologon_plaintext_password_present"))
        {
            throw new ArgumentException("autologon_resolution_code_invalid", nameof(failureCode));
        }

        Text = SetupCulture.GetString("AutoLogonResolutionTitle", selectedCulture);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(650, 290);
        AutoScaleMode = AutoScaleMode.Dpi;

        var detail = new Label
        {
            Name = "AutoLogonResolutionDetail",
            AutoSize = false,
            Location = new Point(24, 22),
            Size = new Size(602, 68),
            Text = failureCode == "autologon_conflict"
                ? SetupCulture.Format(
                    "AutoLogonActiveDetail",
                    selectedCulture,
                    accountName ?? SetupCulture.GetString("AutoLogonAccountUnknown", selectedCulture))
                : SetupCulture.GetString("AutoLogonResidualDetail", selectedCulture),
        };
        var scope = new Label
        {
            Name = "AutoLogonResolutionScope",
            AutoSize = false,
            Location = new Point(24, 96),
            Size = new Size(602, 62),
            ForeColor = SystemColors.GrayText,
            Text = SetupCulture.GetString("AutoLogonCleanupScope", selectedCulture),
        };
        var disable = new Button
        {
            Name = "AutoLogonDisableAndContinue",
            AutoSize = false,
            Enabled = false,
            Location = new Point(122, 225),
            Size = new Size(180, 34),
            Text = SetupCulture.GetString("AutoLogonDisableAndContinueButton", selectedCulture),
        };
        disable.Click += (_, _) => Complete(SetupAutoLogonResolution.DisableAndContinue);
        var acknowledgement = new CheckBox
        {
            Name = "AutoLogonCleanupAcknowledge",
            AutoSize = false,
            Location = new Point(24, 163),
            Size = new Size(602, 48),
            Text = SetupCulture.GetString("AutoLogonCleanupAcknowledge", selectedCulture),
        };
        acknowledgement.CheckedChanged += (_, _) => disable.Enabled = acknowledgement.Checked;
        var manual = new Button
        {
            Name = "AutoLogonUseManualMode",
            AutoSize = false,
            Location = new Point(308, 225),
            Size = new Size(190, 34),
            Text = SetupCulture.GetString("AutoLogonUseManualModeButton", selectedCulture),
        };
        manual.Click += (_, _) => Complete(SetupAutoLogonResolution.UseManualMode);
        var cancel = new Button
        {
            Name = "AutoLogonCancel",
            AutoSize = false,
            DialogResult = DialogResult.Cancel,
            Location = new Point(504, 225),
            Size = new Size(122, 34),
            Text = SetupCulture.GetString("CancelButton", selectedCulture),
        };
        cancel.Click += (_, _) => Complete(SetupAutoLogonResolution.Cancel);

        Controls.AddRange([detail, scope, acknowledgement, disable, manual, cancel]);
        CancelButton = cancel;
    }

    public SetupAutoLogonResolution Resolution { get; private set; } =
        SetupAutoLogonResolution.Cancel;

    private void Complete(SetupAutoLogonResolution resolution)
    {
        Resolution = resolution;
        DialogResult = resolution == SetupAutoLogonResolution.Cancel
            ? DialogResult.Cancel
            : DialogResult.OK;
        Close();
    }
}
