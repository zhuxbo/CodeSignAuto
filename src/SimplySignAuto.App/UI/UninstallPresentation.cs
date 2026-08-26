using System.Globalization;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI.Localization;

namespace SimplySignAuto.App.UI;

internal static class UninstallPresentation
{
    internal static string DescribeProduct(
        GraphicalUninstallProduct product,
        InstallationMode? mode,
        CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        var key = product switch
        {
            GraphicalUninstallProduct.PdfExtension => "PdfUninstallDescription",
            GraphicalUninstallProduct.Main when mode == InstallationMode.Manual =>
                "ManualUninstallDescription",
            GraphicalUninstallProduct.Main => "ServiceUninstallDescription",
            _ => throw new ArgumentOutOfRangeException(nameof(product)),
        };
        return UiCulture.GetString(key, culture);
    }

    internal static bool RequiresRestart(GraphicalUninstallProduct product) => product switch
    {
        GraphicalUninstallProduct.Main => true,
        GraphicalUninstallProduct.PdfExtension => false,
        _ => throw new ArgumentOutOfRangeException(nameof(product)),
    };

    internal static string NormalizeFailureCode(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return "uninstall_failed";
        }

        var code = output.Trim();
        return code.Length <= 80 && code.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_')
            ? code
            : "uninstall_failed";
    }

    internal static string DescribeFailure(string code, CultureInfo culture)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentNullException.ThrowIfNull(culture);
        var reasonKey = code switch
        {
            "uninstall_busy" => "UninstallErrorBusy",
            "owned_resource_mismatch" or "uninstall_state_uncertain" or
                "install_state_uncertain" or "service_configuration_missing" or
                "service_configuration_invalid" or "installation_receipt_invalid" or
                "uninstall_installation_state_missing" => "UninstallErrorState",
            _ => "UninstallErrorGeneric",
        };
        var reason = UiCulture.GetString(reasonKey, culture);
        var codeLine = string.Format(
            culture,
            UiCulture.GetString("UninstallErrorCode", culture),
            code);
        return reason + Environment.NewLine + Environment.NewLine + codeLine;
    }
}
