namespace SimplySignAuto.App;

public enum ApplicationEntryKind
{
    Desktop,
    UiTest,
    AgentConsole,
    Service,
    ConfigureOtp,
    ConfigureService,
    Install,
    Setup,
    ProvisionAgentUser,
    Uninstall,
    PurgeQuarantine,
    Version,
    PdfExtension,
    Pkcs11Helper,
    Invalid,
}

public sealed record ApplicationEntryRoute(
    ApplicationEntryKind Kind,
    string[] Arguments,
    bool ShowInitially)
{
    public static ApplicationEntryRoute Parse(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        return arguments switch
        {
            [] => new(ApplicationEntryKind.Desktop, [], ShowInitially: true),
            ["--ui-test-state", var state] when UI.Testing.UiTestState.TryParse(state, out _) =>
                new(ApplicationEntryKind.UiTest, [state], ShowInitially: true),
            ["agent", "--background"] => new(ApplicationEntryKind.AgentConsole, ["--background"], ShowInitially: false),
            ["agent", "--console"] => new(ApplicationEntryKind.AgentConsole, ["--console"], ShowInitially: false),
            ["service", .. var tail] => new(ApplicationEntryKind.Service, tail, ShowInitially: false),
            ["configure-otp", .. var tail] => new(ApplicationEntryKind.ConfigureOtp, tail, ShowInitially: false),
            ["configure-service"] => new(ApplicationEntryKind.ConfigureService, [], ShowInitially: false),
            ["install", .. var tail] => new(ApplicationEntryKind.Install, tail, ShowInitially: false),
            ["setup", "--mode", var mode] when mode is "manual" or "service" =>
                new(ApplicationEntryKind.Setup, ["--mode", mode], ShowInitially: false),
            ["provision-agent-user", .. var tail] =>
                new(ApplicationEntryKind.ProvisionAgentUser, tail, ShowInitially: false),
            ["uninstall", .. var tail] => new(ApplicationEntryKind.Uninstall, tail, ShowInitially: false),
            ["purge-quarantine", .. var tail] => new(ApplicationEntryKind.PurgeQuarantine, tail, ShowInitially: false),
            ["--version"] => new(ApplicationEntryKind.Version, [], ShowInitially: false),
            ["pdf-extension", "install", "--media-root", var mediaRoot]
                when Path.IsPathFullyQualified(mediaRoot) && !mediaRoot.Any(char.IsControl) =>
                new(
                    ApplicationEntryKind.PdfExtension,
                    ["install", "--media-root", mediaRoot],
                    ShowInitially: false),
            ["pdf-extension", "uninstall"] =>
                new(ApplicationEntryKind.PdfExtension, ["uninstall"], ShowInitially: false),
            ["--internal-pkcs11-helper", var command, "--request", var request]
                when command is "catalog" or "probe" =>
                new(ApplicationEntryKind.Pkcs11Helper, [command, "--request", request], ShowInitially: false),
            _ => new(ApplicationEntryKind.Invalid, [], ShowInitially: false),
        };
    }
}
