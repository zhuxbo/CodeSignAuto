using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using SimplySignAuto.Agent;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.App.UI.Testing;
using SimplySignAuto.Service;

namespace SimplySignAuto.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args) => RunAsync(args).GetAwaiter().GetResult();

    internal static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        var route = ApplicationEntryRoute.Parse(args);
        switch (route.Kind)
        {
            case ApplicationEntryKind.Pkcs11Helper:
                return await Pkcs11HelperHost.ExecuteAsync(
                    route.Arguments,
                    Console.Out,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.Desktop:
            {
                if (!AdminDesktopElevation.IsElevated())
                {
                    return AdminDesktopElevation.RelaunchElevated(Console.Error);
                }

                try
                {
                    var culture = await new UiPreferenceStore().LoadAsync(
                        CultureInfo.InstalledUICulture,
                        cancellationToken).ConfigureAwait(false);
                    UiCulture.Apply(culture);
                }
                catch (InvalidDataException preferenceError)
                {
                    Console.Error.WriteLine(preferenceError.Message);
                    return 1;
                }

                if (ShouldDetachConsole(route))
                {
                    DetachDesktopConsole();
                }

                using var diagnostics = DesktopDiagnosticLog.Open();
                return await new AdminDesktopApplication(diagnostics)
                    .ExecuteAsync(route.ShowInitially, diagnostics, cancellationToken);
            }
            case ApplicationEntryKind.UiTest:
                return await UiTestProgramGate.DispatchAsync(
                    route.Arguments,
                    ReadUiTestEnvironment(),
                    Environment.ProcessId,
                    ExecuteUiTestAsync,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.AgentConsole:
            {
                if (route.Arguments is ["--background"])
                {
                    if (ShouldDetachConsole(route))
                    {
                        DetachConsole();
                    }

                    using var diagnostics = DesktopDiagnosticLog.Open();
                    return await AgentCommand.ExecuteAsync(
                        route.Arguments,
                        diagnostics,
                        cancellationToken);
                }

                return await AgentCommand.ExecuteAsync(
                    route.Arguments,
                    Console.Error,
                    cancellationToken);
            }
            case ApplicationEntryKind.Service:
                await ServiceHost.RunAsync(
                    route.Arguments,
                    new ProductComponentVersions(
                        ApplicationVersion.ReadIdentity(typeof(AgentHost).Assembly),
                        ApplicationVersion.ReadIdentity(typeof(Program).Assembly)));
                return 0;
            case ApplicationEntryKind.ConfigureOtp:
                return await ConfigureOtpCommand.ExecuteAsync(
                    route.Arguments,
                    Console.In,
                    Console.Out,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.ConfigureService:
                return await ConfigureServiceCommand.ExecuteAsync(
                    route.Arguments,
                    Console.In,
                    Console.Out,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.Install:
                return await InstallCommand.ExecuteAsync(
                    route.Arguments,
                    Console.Out,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.Setup:
                return await SetupCommand.ExecuteAsync(
                    route.Arguments,
                    Console.Out,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.ProvisionAgentUser:
                return await ProvisionAgentUserCommand.ExecuteAsync(
                    route.Arguments,
                    Console.Out,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.Uninstall:
                if (!AdminDesktopElevation.IsElevated())
                {
                    return UninstallElevation.RelaunchElevatedAndWait(
                        Environment.ProcessPath,
                        route.Arguments,
                        Console.Error);
                }

                return await UninstallCommand.ExecuteAsync(
                    route.Arguments,
                    Console.Out,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.PdfExtension:
                if (!AdminDesktopElevation.IsElevated())
                {
                    return PdfExtensionElevation.RelaunchElevatedAndWait(
                        Environment.ProcessPath,
                        route.Arguments,
                        Console.Error);
                }

                return await PdfExtensionCommand.ExecuteAsync(
                    route.Arguments,
                    Console.Out,
                    Console.Error,
                    cancellationToken,
                    new WindowsPdfExtensionOperations());
            case ApplicationEntryKind.PurgeQuarantine:
                return await PurgeQuarantineCommand.ExecuteAsync(
                    route.Arguments,
                    Console.Error,
                    cancellationToken);
            case ApplicationEntryKind.Version:
                Console.WriteLine(ApplicationVersion.Read(typeof(Program).Assembly));
                return 0;
            default:
                Console.Error.WriteLine(
                    "Install: run the signed SimplySignAutoSetup-<version>-win-x64.exe with no arguments. Usage: SimplySignAuto.exe | SimplySignAuto.exe --version | SimplySignAuto.exe uninstall [--purge-data --confirm PURGE] | agent (--console|--background) | service [--console [--allow-http-loopback]] | advanced: configure-otp < stdin | provision-agent-user --mode (existing-user|provision-user|repair-user) --user LOCAL_NAME | install --signing-user DOMAIN\\user --agent-config ABSOLUTE_JSON [--listen-port 7080] [--open-firewall]");
                return 2;
        }
    }

    private static IReadOnlyDictionary<string, string?> ReadUiTestEnvironment() =>
        new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [UiTestLaunchOptions.ModeEnvironmentVariable] =
                Environment.GetEnvironmentVariable(UiTestLaunchOptions.ModeEnvironmentVariable),
            [UiTestLaunchOptions.PipeEnvironmentVariable] =
                Environment.GetEnvironmentVariable(UiTestLaunchOptions.PipeEnvironmentVariable),
            [UiTestLaunchOptions.NonceEnvironmentVariable] =
                Environment.GetEnvironmentVariable(UiTestLaunchOptions.NonceEnvironmentVariable),
            [UiTestLaunchOptions.CultureEnvironmentVariable] =
                Environment.GetEnvironmentVariable(UiTestLaunchOptions.CultureEnvironmentVariable),
        };

    private static async Task<int> ExecuteUiTestAsync(
        UiTestLaunchOptions options,
        CancellationToken cancellationToken)
    {
        try
        {
            UiCulture.Apply(UiCulture.ResolveSelection(options.CultureName));
            return await new UiTestDesktopApplication().ExecuteAsync(options, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 0;
        }
        catch (Exception error) when (
            error is UiTestHostException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine("ui_test_start_failed");
            return 1;
        }
    }

    internal static bool ShouldDetachConsole(ApplicationEntryRoute route) =>
        route.Kind == ApplicationEntryKind.Desktop ||
        route is { Kind: ApplicationEntryKind.AgentConsole, Arguments: ["--background"] };

    private static void DetachDesktopConsole() => DetachConsole();

    private static void DetachConsole()
    {
        if (OperatingSystem.IsWindows())
        {
            _ = FreeConsole();
            Console.SetIn(TextReader.Null);
            Console.SetOut(TextWriter.Null);
            Console.SetError(TextWriter.Null);
        }
    }

    [DllImport("kernel32.dll")]
    [SupportedOSPlatform("windows")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeConsole();
}

internal static class PdfExtensionElevation
{
    internal static int RelaunchElevatedAndWait(
        string? executablePath,
        string[] arguments,
        TextWriter error,
        IUninstallElevationLauncher? launcher = null)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(error);
        var route = ApplicationEntryRoute.Parse(["pdf-extension", .. arguments]);
        if (string.IsNullOrWhiteSpace(executablePath) ||
            !Path.IsPathFullyQualified(executablePath) ||
            route.Kind != ApplicationEntryKind.PdfExtension ||
            !route.Arguments.SequenceEqual(arguments, StringComparer.Ordinal))
        {
            error.WriteLine("pdf_extension_elevation_failed");
            return 1;
        }

        try
        {
            return (launcher ?? new WindowsUninstallElevationLauncher()).LaunchAndWait(
                Path.GetFullPath(executablePath),
                ["pdf-extension", .. arguments],
                "runas");
        }
        catch (Exception elevationError) when (
            elevationError is Win32Exception or InvalidOperationException or ArgumentException)
        {
            error.WriteLine("pdf_extension_elevation_failed");
            return 1;
        }
    }
}

internal interface IUninstallElevationLauncher
{
    int LaunchAndWait(
        string executablePath,
        IReadOnlyList<string> arguments,
        string verb);
}

internal sealed class WindowsUninstallElevationLauncher : IUninstallElevationLauncher
{
    public int LaunchAndWait(
        string executablePath,
        IReadOnlyList<string> arguments,
        string verb)
    {
        var start = new ProcessStartInfo(executablePath)
        {
            UseShellExecute = true,
            Verb = verb,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("uninstall_elevation_failed");
        process.WaitForExit();
        return process.ExitCode;
    }
}

internal static class UninstallElevation
{
    public static int RelaunchElevatedAndWait(
        string? executablePath,
        string[] arguments,
        TextWriter error,
        IUninstallElevationLauncher? launcher = null)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(error);
        if (string.IsNullOrWhiteSpace(executablePath) ||
            !Path.IsPathFullyQualified(executablePath) ||
            !UninstallCommand.TryParse(arguments, out _))
        {
            error.WriteLine("uninstall_elevation_failed");
            return 1;
        }

        try
        {
            var elevatedArguments = new[] { "uninstall" }.Concat(arguments).ToArray();
            return (launcher ?? new WindowsUninstallElevationLauncher()).LaunchAndWait(
                Path.GetFullPath(executablePath),
                elevatedArguments,
                "runas");
        }
        catch (Exception elevationError) when (
            elevationError is Win32Exception or InvalidOperationException or ArgumentException)
        {
            error.WriteLine("uninstall_elevation_failed");
            return 1;
        }
    }
}

internal static class AdminDesktopElevation
{
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return true;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static int RelaunchElevated(TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(error);
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.ProcessPath))
        {
            error.WriteLine("admin_control_elevation_failed");
            return 1;
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo(Environment.ProcessPath)
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            return process is null ? 1 : 0;
        }
        catch (Exception elevationError) when (
            elevationError is Win32Exception or InvalidOperationException)
        {
            error.WriteLine("admin_control_elevation_failed");
            return 1;
        }
    }
}
