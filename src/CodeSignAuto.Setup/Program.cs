using System.Text.Json;
using Microsoft.Win32;

namespace CodeSignAuto.Setup;

internal static class SetupCommandLine
{
    public static void Validate(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count != 0)
        {
            throw new SetupBootstrapperException("setup_arguments_invalid");
        }
    }
}

internal static class Program
{
    [STAThread]
    private static int Main(string[] arguments)
    {
        var culture = SetupCulture.ResolveDefault(System.Globalization.CultureInfo.CurrentUICulture);
        try
        {
            SetupCommandLine.Validate(arguments);
        }
        catch (SetupBootstrapperException error)
        {
            MessageBox.Show(
                error.GetLocalizedMessage(culture),
                SetupCulture.GetString("WindowMainTitle", culture),
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 2;
        }

        ApplicationConfiguration.Initialize();
        try
        {
            var powerShell = SetupPowerShell.ResolveSystemPath();
            var payloadSource = new EmbeddedSetupPayloadSource();
            var productKind = SetupPayloadMetadataCodec.Decode(
                payloadSource.ReadMetadata()).ProductKind;
            var operations = new SetupBootstrapperOperations(
                payloadSource,
                new WindowsSetupPublisherVerifier(powerShell),
                new WindowsSetupWorkspace(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
                new WindowsSetupProcessRunner(
                    powerShell,
                    new PowerShellSetupProcessInvoker(),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
            var selection = SetupInstallationDiscovery.Resolve(productKind);
            using var form = new SetupForm(
                new SetupBootstrapper(operations),
                productKind,
                culture,
                selection);
            Application.Run(form);
            return form.ExitCode;
        }
        catch (SetupBootstrapperException error)
        {
            MessageBox.Show(
                error.GetLocalizedMessage(culture),
                SetupCulture.GetString("WindowMainTitle", culture),
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
        catch
        {
            var error = new SetupBootstrapperException("setup_failed");
            MessageBox.Show(
                error.GetLocalizedMessage(culture),
                SetupCulture.GetString("WindowMainTitle", culture),
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
    }
}

internal static class SetupInstallationDiscovery
{
    private static readonly HashSet<string> RequiredReceiptProperties =
    [
        "schemaVersion",
        "mode",
        "installInstanceId",
        "signingUserSid",
        "executablePath",
    ];

    public static SetupInstallationSelection? Resolve(SetupProductKind productKind)
    {
        var dataRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CodeSignAuto");
        return Resolve(productKind, dataRoot, SetupWindowsProductType.Read);
    }

    internal static SetupInstallationSelection? Resolve(
        SetupProductKind productKind,
        string dataRoot,
        Func<byte> productTypeReader)
    {
        if (productKind == SetupProductKind.PdfExtension)
        {
            return null;
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        ArgumentNullException.ThrowIfNull(productTypeReader);
        var receiptPath = Path.Combine(dataRoot, "install.json");
        if (File.Exists(receiptPath))
        {
            return new SetupInstallationSelection(ReadReceiptMode(receiptPath), CanChange: false);
        }

        if (File.Exists(Path.Combine(dataRoot, "service.json")))
        {
            return new SetupInstallationSelection(SetupInstallationMode.Service, CanChange: false);
        }

        return new SetupInstallationSelection(
            SetupModeSelection.ResolveDefault(productTypeReader()),
            CanChange: true);
    }

    internal static SetupInstallationMode ReadReceiptMode(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length is <= 0 or > 32 * 1024)
            {
                throw InvalidReceipt();
            }

            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw InvalidReceipt();
            }

            var properties = document.RootElement.EnumerateObject().ToArray();
            if (properties.Select(property => property.Name)
                    .Distinct(StringComparer.Ordinal).Count() != properties.Length ||
                RequiredReceiptProperties.Any(name => !properties.Any(property => property.Name == name)) ||
                properties.Any(property =>
                    !RequiredReceiptProperties.Contains(property.Name) && property.Name != "userDataRoot") ||
                document.RootElement.GetProperty("schemaVersion").ValueKind != JsonValueKind.Number ||
                document.RootElement.GetProperty("schemaVersion").GetInt32() != 1)
            {
                throw InvalidReceipt();
            }

            var mode = document.RootElement.GetProperty("mode");
            if (mode.ValueKind != JsonValueKind.String)
            {
                throw InvalidReceipt();
            }

            return mode.GetString() switch
            {
                "manual" => SetupInstallationMode.Manual,
                "service" => SetupInstallationMode.Service,
                _ => throw InvalidReceipt(),
            };
        }
        catch (SetupBootstrapperException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or JsonException or
                InvalidOperationException or FormatException)
        {
            throw InvalidReceipt();
        }
    }

    private static SetupBootstrapperException InvalidReceipt() =>
        new("installation_receipt_invalid");
}

internal static class SetupWindowsProductType
{
    public static byte Read()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new SetupBootstrapperException("windows_required");
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\ProductOptions",
                writable: false);
            return (key?.GetValue("ProductType") as string) switch
            {
                "WinNT" => 1,
                "LanmanNT" => 2,
                "ServerNT" => 3,
                _ => throw new SetupBootstrapperException("machine_lookup_failed"),
            };
        }
        catch (SetupBootstrapperException)
        {
            throw;
        }
        catch
        {
            throw new SetupBootstrapperException("machine_lookup_failed");
        }
    }
}
