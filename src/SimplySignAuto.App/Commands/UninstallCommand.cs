using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

public sealed record UninstallOptions(bool PurgeData, string? Confirmation);

public abstract record UninstallAction;

public sealed record RemoveOwnedFirewallRule(string OwnerMarker, int TcpPort) : UninstallAction;

public sealed record RemoveOwnedInteractiveLogonTask(
    string Name,
    string SigningUserSid,
    string ExecutablePath,
    string OwnerMarker) : UninstallAction;

public sealed record RemoveOwnedWindowsService(
    string Name,
    string ExecutablePath,
    string OwnerMarker) : UninstallAction;

public sealed record RemoveOwnedPdfExtension : UninstallAction;

public sealed record RemoveOwnedDesktopShortcut(
    string Path,
    string TargetPath,
    string SigningUserSid,
    string OwnerMarker) : UninstallAction;

public sealed record RemoveOwnedAutoLogon(
    string SigningUserSid,
    string OwnerMarker,
    string? AccountName = null,
    string? ProfilePath = null) : UninstallAction;

public enum UninstallSigningUserOwnership
{
    ExistingUser,
    ProductManaged,
}

public sealed record UninstallSigningIdentity(
    string AccountName,
    string UserName,
    string Sid,
    string ProfilePath,
    string OwnerMarker,
    UninstallSigningUserOwnership Ownership);

public sealed record EndOwnedSigningUserSession(
    UninstallSigningIdentity Identity) : UninstallAction;

public sealed record RemoveOwnedAccountRights(
    UninstallSigningIdentity Identity) : UninstallAction;

public sealed record PurgeControlledData(
    string DataRoot,
    string AgentDirectory,
    bool IncludeAgentDirectory) : UninstallAction;

public sealed record DeleteOwnedWindowsProfile(
    UninstallSigningIdentity Identity) : UninstallAction;

public sealed record DeleteOwnedLocalUser(
    UninstallSigningIdentity Identity) : UninstallAction;

public sealed record RemoveOwnedProductUninstall(
    ProductUninstallRegistration Registration) : UninstallAction;

public sealed record RemoveOwnedInstallationReceipt(
    InstallationReceipt Receipt) : UninstallAction;

public sealed record UninstallPlan(
    ServiceConfiguration Configuration,
    UninstallSigningIdentity Identity,
    IReadOnlyList<UninstallAction> Actions,
    InstallationReceipt? Receipt = null);

public sealed record ManualUninstallPlan(
    InstallationReceipt Receipt,
    UninstallSigningIdentity Identity,
    string DataRoot,
    IReadOnlyList<UninstallAction> Actions);

public interface IManualUninstallEnvironment
{
    bool IsWindows { get; }

    string CommonDesktopDirectory { get; }

    string ProgramDataRoot { get; }

    Task<InstallationReceipt> LoadReceiptAsync(CancellationToken cancellationToken);
}

public sealed class ManualUninstallPlanner(IManualUninstallEnvironment environment)
{
    public async Task<ManualUninstallPlan> PlanAsync(
        UninstallOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(environment);
        if (!environment.IsWindows)
        {
            throw new InstallException("windows_required");
        }

        if (options.PurgeData && !string.Equals(options.Confirmation, "PURGE", StringComparison.Ordinal))
        {
            throw new InstallException("purge_confirmation_required");
        }

        if (!options.PurgeData && options.Confirmation is not null)
        {
            throw new InstallException("uninstall_arguments_invalid");
        }

        var receipt = InstallationReceiptValidator.Validate(
            await environment.LoadReceiptAsync(cancellationToken).ConfigureAwait(false));
        if (receipt.Mode != InstallationMode.Manual)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var marker = InstallOwnershipMarker.Create(receipt.InstallInstanceId);
        var dataRoot = Canonical(Path.Combine(environment.ProgramDataRoot, "SimplySignAuto"));
        var desktop = Canonical(environment.CommonDesktopDirectory);
        var identity = new UninstallSigningIdentity(
            string.Empty,
            string.Empty,
            receipt.SigningUserSid,
            receipt.UserDataRoot!,
            marker,
            UninstallSigningUserOwnership.ExistingUser);
        UninstallAction[] actions =
        [
            new RemoveOwnedPdfExtension(),
            new PurgeControlledData(
                dataRoot,
                receipt.UserDataRoot!,
                IncludeAgentDirectory: options.PurgeData),
            new RemoveOwnedDesktopShortcut(
                Canonical(Path.Combine(desktop, "SimplySignAuto.lnk")),
                receipt.ExecutablePath,
                receipt.SigningUserSid,
                marker),
            new RemoveOwnedProductUninstall(ProductUninstallRegistration.Create(
                receipt.ExecutablePath,
                SimplySignAuto.App.ApplicationVersion.ReadIdentity(typeof(ManualUninstallPlanner).Assembly),
                marker)),
        ];
        return new ManualUninstallPlan(receipt, identity, dataRoot, actions);
    }

    private static string Canonical(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new InstallException("uninstall_configuration_invalid");
        }

        var canonical = Path.GetFullPath(path);
        if (!string.Equals(path, canonical, PathComparison()))
        {
            throw new InstallException("uninstall_configuration_invalid");
        }

        return canonical;
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public interface IUninstallEnvironment
{
    bool IsWindows { get; }

    string CommonDesktopDirectory { get; }

    Task<ServiceConfiguration> LoadConfigurationAsync(CancellationToken cancellationToken);

    Task<InstallationReceipt?> LoadInstallationReceiptAsync(
        CancellationToken cancellationToken) => Task.FromResult<InstallationReceipt?>(null);

    void ValidateControlledPaths(ServiceConfiguration configuration);

    UninstallSigningIdentity? InspectSigningIdentity(
        ServiceConfiguration configuration,
        string ownerMarker) => null;
}

public sealed class UninstallPlanner(IUninstallEnvironment environment)
{
    public async Task<UninstallPlan> PlanAsync(
        UninstallOptions options,
        CancellationToken cancellationToken)
    {
        if (!environment.IsWindows)
        {
            throw new InstallException("windows_required");
        }

        if (options.PurgeData && !string.Equals(options.Confirmation, "PURGE", StringComparison.Ordinal))
        {
            throw new InstallException("purge_confirmation_required");
        }

        if (!options.PurgeData && options.Confirmation is not null)
        {
            throw new InstallException("uninstall_arguments_invalid");
        }

        var receipt = await environment.LoadInstallationReceiptAsync(cancellationToken)
            .ConfigureAwait(false);
        if (receipt is not null &&
            InstallationReceiptValidator.Validate(receipt).Mode != InstallationMode.Service)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var configuration = ServiceConfigurationLoader.Validate(
            await environment.LoadConfigurationAsync(cancellationToken).ConfigureAwait(false));
        if (receipt is not null)
        {
            InstallationReceiptValidator.RequireServiceMatch(receipt, configuration);
        }

        environment.ValidateControlledPaths(configuration);
        var exactOwnerMarker = InstallOwnershipMarker.Create(configuration.InstallInstanceId);
        var identity = environment.InspectSigningIdentity(configuration, exactOwnerMarker);
        if (identity is null)
        {
            return LegacyPlan(configuration, exactOwnerMarker, options.PurgeData, receipt);
        }

        ValidateIdentity(configuration, identity, exactOwnerMarker);
        var agentDirectory = Path.GetDirectoryName(configuration.AgentConfigurationPath)
            ?? throw new InstallException("uninstall_configuration_invalid");
        ValidatePurgePath(configuration.DataRoot, "SimplySignAuto");
        ValidatePurgePath(agentDirectory, "SimplySignAuto");
        var actions = new List<UninstallAction>
        {
            new RemoveOwnedInteractiveLogonTask(
                "SimplySignAuto.Agent",
                configuration.SigningUserSid,
                configuration.ExecutablePath,
                exactOwnerMarker),
            new RemoveOwnedWindowsService(
                "SimplySignAuto.Service",
                configuration.ExecutablePath,
                exactOwnerMarker),
            new RemoveOwnedFirewallRule(exactOwnerMarker, configuration.ListenPort),
            new RemoveOwnedPdfExtension(),
        };
        if (identity.Ownership == UninstallSigningUserOwnership.ProductManaged)
        {
            actions.Add(new EndOwnedSigningUserSession(identity));
        }

        actions.Add(new RemoveOwnedAutoLogon(
            configuration.SigningUserSid,
            exactOwnerMarker,
            identity.AccountName,
            identity.ProfilePath));
        if (identity.Ownership == UninstallSigningUserOwnership.ProductManaged)
        {
            actions.Add(new RemoveOwnedAccountRights(identity));
            actions.Add(new DeleteOwnedLocalUser(identity));
            actions.Add(new DeleteOwnedWindowsProfile(identity));
        }

        actions.Add(new PurgeControlledData(
            configuration.DataRoot,
            agentDirectory,
            IncludeAgentDirectory: identity.Ownership == UninstallSigningUserOwnership.ExistingUser));
        actions.Add(CreateDesktopShortcutAction(configuration, exactOwnerMarker));
        actions.Add(CreateProductUninstallAction(configuration, exactOwnerMarker));
        if (receipt is not null && !actions.Any(action => action is PurgeControlledData))
        {
            actions.Add(new RemoveOwnedInstallationReceipt(receipt));
        }

        return new UninstallPlan(configuration, identity, actions, receipt);
    }

    private static UninstallPlan LegacyPlan(
        ServiceConfiguration configuration,
        string ownerMarker,
        bool includePurge,
        InstallationReceipt? receipt)
    {
        var profilePath = Path.GetDirectoryName(configuration.AgentConfigurationPath)
            ?? throw new InstallException("uninstall_configuration_invalid");
        var identity = new UninstallSigningIdentity(
            string.Empty,
            string.Empty,
            configuration.SigningUserSid,
            profilePath,
            ownerMarker,
            UninstallSigningUserOwnership.ExistingUser);
        var actions = new List<UninstallAction>
        {
            new RemoveOwnedFirewallRule(ownerMarker, configuration.ListenPort),
            new RemoveOwnedInteractiveLogonTask(
                "SimplySignAuto.Agent",
                configuration.SigningUserSid,
                configuration.ExecutablePath,
                ownerMarker),
            new RemoveOwnedWindowsService(
                "SimplySignAuto.Service",
                configuration.ExecutablePath,
                ownerMarker),
            new RemoveOwnedPdfExtension(),
        };
        if (includePurge)
        {
            actions.Add(new RemoveOwnedAutoLogon(configuration.SigningUserSid, ownerMarker));
            actions.Add(new PurgeControlledData(configuration.DataRoot, profilePath, IncludeAgentDirectory: true));
        }

        if (receipt is not null && !actions.Any(action => action is PurgeControlledData))
        {
            actions.Add(new RemoveOwnedInstallationReceipt(receipt));
        }

        return new UninstallPlan(configuration, identity, actions, receipt);
    }

    private static RemoveOwnedProductUninstall CreateProductUninstallAction(
        ServiceConfiguration configuration,
        string ownerMarker) => new(ProductUninstallRegistration.Create(
            configuration.ExecutablePath,
            SimplySignAuto.App.ApplicationVersion.ReadIdentity(typeof(UninstallPlanner).Assembly),
            ownerMarker));

    private RemoveOwnedDesktopShortcut CreateDesktopShortcutAction(
        ServiceConfiguration configuration,
        string ownerMarker)
    {
        var desktop = Path.GetFullPath(environment.CommonDesktopDirectory);
        if (!Path.IsPathFullyQualified(desktop))
        {
            throw new InstallException("uninstall_configuration_invalid");
        }

        return new RemoveOwnedDesktopShortcut(
            Path.GetFullPath(Path.Combine(desktop, "SimplySignAuto.lnk")),
            configuration.ExecutablePath,
            configuration.SigningUserSid,
            ownerMarker);
    }

    private static void ValidateIdentity(
        ServiceConfiguration configuration,
        UninstallSigningIdentity identity,
        string ownerMarker)
    {
        if (!string.Equals(identity.Sid, configuration.SigningUserSid, StringComparison.Ordinal) ||
            !string.Equals(identity.OwnerMarker, ownerMarker, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(identity.AccountName) ||
            string.IsNullOrWhiteSpace(identity.UserName) ||
            !Path.IsPathFullyQualified(identity.ProfilePath) ||
            !string.Equals(Path.GetFullPath(identity.ProfilePath), identity.ProfilePath, PathComparison()))
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    private static void ValidatePurgePath(string path, string expectedName)
    {
        if (!Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, PathComparison()) ||
            !string.Equals(Path.GetFileName(path), expectedName, StringComparison.OrdinalIgnoreCase) ||
            Path.GetPathRoot(path) == path)
        {
            throw new InstallException("uninstall_configuration_invalid");
        }
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public interface IUninstallActionExecutor
{
    Task PreflightAsync(
        UninstallPlan plan,
        CancellationToken cancellationToken);

    Task ExecuteAsync(UninstallAction action, CancellationToken cancellationToken);
}

internal interface IInstalledMediaUninstallPreflight
{
    Task VerifyAsync(UninstallPlan plan, CancellationToken cancellationToken);
}

internal sealed class WindowsInstalledMediaUninstallPreflight : IInstalledMediaUninstallPreflight
{
    private readonly IInstallMediaVerifier _verifier;

    public WindowsInstalledMediaUninstallPreflight()
        : this(new WindowsInstallMediaVerifier())
    {
    }

    internal WindowsInstalledMediaUninstallPreflight(IInstallMediaVerifier verifier) =>
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));

    public async Task VerifyAsync(UninstallPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var root = Path.GetDirectoryName(plan.Configuration.ExecutablePath)
                ?? throw new InstallException("owned_resource_mismatch");
            var expectedRoot = InstallMediaPaths.GetTargetRoot(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            if (!string.Equals(root, expectedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var scriptPath = Path.Combine(root, InstallMediaPaths.VerificationScriptFileName);
            var publisher = _verifier.VerifyInitialPublisher(
                plan.Configuration.ExecutablePath,
                scriptPath);
            await _verifier.VerifyMediaAsync(root, publisher, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }
}

public sealed class UninstallOrchestrator(IUninstallActionExecutor executor)
{
    public async Task ExecuteAsync(
        UninstallPlan plan,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(output);
        await executor.PreflightAsync(plan, cancellationToken).ConfigureAwait(false);
        if (plan.Actions.Any(action => action is PurgeControlledData))
        {
            await output.WriteLineAsync(
                "WARNING: exact-owned product data will be quarantined; physical data deletion is deferred until SYSTEM cleanup after restart.")
                .ConfigureAwait(false);
        }

        foreach (var action in plan.Actions)
        {
            await executor.ExecuteAsync(action, cancellationToken).ConfigureAwait(false);
        }

        await output.WriteLineAsync(plan.Identity.Ownership == UninstallSigningUserOwnership.ProductManaged
            ? "Product data was isolated; the exact-owned profile and managed signing user were removed. Physical cleanup will complete after restart."
            : "Product data was isolated; the pre-existing signing user and profile were preserved. Physical cleanup will complete after restart.")
            .ConfigureAwait(false);
    }
}

public sealed class WindowsUninstallEnvironment : IUninstallEnvironment
{
    public bool IsWindows => OperatingSystem.IsWindows();

    public string CommonDesktopDirectory => Path.GetFullPath(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));

    internal static string ConfigurationPath => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SimplySignAuto",
        "service.json"));

    public async Task<ServiceConfiguration> LoadConfigurationAsync(CancellationToken cancellationToken)
    {
        var path = ConfigurationPath;
        var configuration = await new ServiceConfigurationLoader(path)
            .LoadAsync(cancellationToken).ConfigureAwait(false);
        WindowsInstallAcl.VerifyFile(
            path,
            InstallAclProfile.AdministratorsOnly,
            new System.Security.Principal.SecurityIdentifier(configuration.SigningUserSid));
        return configuration;
    }

    public Task<InstallationReceipt?> LoadInstallationReceiptAsync(
        CancellationToken cancellationToken) =>
        new WindowsInstallationReceiptStore().LoadOptionalAsync(cancellationToken);

    public void ValidateControlledPaths(ServiceConfiguration configuration)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        var expectedDataRoot = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SimplySignAuto"));
        using var profileKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
            $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{configuration.SigningUserSid}",
            writable: false);
        var profilePath = profileKey?.GetValue(
            "ProfileImagePath",
            null,
            Microsoft.Win32.RegistryValueOptions.None) as string;
        var disabled = string.IsNullOrWhiteSpace(profilePath)
            ? WindowsAutoLogonPlatform.ReadDisabledAutoLogon(
                InstallOwnershipMarker.Create(configuration.InstallInstanceId))
            : null;
        var expectedAgentPath = ResolveExpectedAgentPath(configuration, profilePath, disabled);
        var currentExecutable = Environment.ProcessPath is null ? null : Path.GetFullPath(Environment.ProcessPath);
        if (!string.Equals(configuration.DataRoot, expectedDataRoot, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(configuration.AgentConfigurationPath, expectedAgentPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(configuration.ExecutablePath, currentExecutable, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("uninstall_configuration_invalid");
        }
    }

    internal static string ResolveExpectedAgentPath(
        ServiceConfiguration configuration,
        string? profileListPath,
        DisabledOwnedAutoLogon? disabled)
    {
        var profilePath = profileListPath;
        if (string.IsNullOrWhiteSpace(profilePath))
        {
            var ownerMarker = InstallOwnershipMarker.Create(configuration.InstallInstanceId);
            if (disabled is null ||
                !string.Equals(disabled.OwnerMarker, ownerMarker, StringComparison.Ordinal) ||
                !string.Equals(disabled.SigningUserSid, configuration.SigningUserSid, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(disabled.AccountName))
            {
                throw new InstallException("uninstall_configuration_invalid");
            }

            profilePath = disabled.ProfilePath;
        }

        if (!Path.IsPathFullyQualified(profilePath) ||
            !string.Equals(
                Path.GetFullPath(profilePath),
                profilePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("uninstall_configuration_invalid");
        }

        return Path.GetFullPath(Path.Combine(
            profilePath,
            "AppData",
            "Local",
            "SimplySignAuto",
            "agent.json"));
    }

    public UninstallSigningIdentity InspectSigningIdentity(
        ServiceConfiguration configuration,
        string ownerMarker) => WindowsUninstallIdentity.Inspect(configuration, ownerMarker);
}

public sealed class WindowsManualUninstallEnvironment(InstallationReceipt receipt)
    : IManualUninstallEnvironment
{
    private readonly InstallationReceipt _receipt =
        InstallationReceiptValidator.Validate(receipt);

    public bool IsWindows => OperatingSystem.IsWindows();

    public string CommonDesktopDirectory => Path.GetFullPath(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));

    public string ProgramDataRoot => Path.GetFullPath(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

    public Task<InstallationReceipt> LoadReceiptAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_receipt);
    }
}

internal interface IManualInstalledMediaUninstallPreflight
{
    Task VerifyAsync(InstallationReceipt receipt, CancellationToken cancellationToken);
}

internal sealed class WindowsManualInstalledMediaUninstallPreflight
    : IManualInstalledMediaUninstallPreflight
{
    private readonly IInstallMediaVerifier _verifier;

    public WindowsManualInstalledMediaUninstallPreflight()
        : this(new WindowsInstallMediaVerifier())
    {
    }

    internal WindowsManualInstalledMediaUninstallPreflight(IInstallMediaVerifier verifier) =>
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));

    public async Task VerifyAsync(
        InstallationReceipt receipt,
        CancellationToken cancellationToken)
    {
        receipt = InstallationReceiptValidator.Validate(receipt);
        try
        {
            var root = Path.GetDirectoryName(receipt.ExecutablePath)
                ?? throw new InstallException("owned_resource_mismatch");
            var expectedRoot = InstallMediaPaths.GetTargetRoot(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            if (!string.Equals(root, expectedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var publisher = _verifier.VerifyInitialPublisher(
                receipt.ExecutablePath,
                Path.Combine(root, InstallMediaPaths.VerificationScriptFileName));
            await _verifier.VerifyMediaAsync(root, publisher, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }
}

internal static class WindowsManualUninstallOwnership
{
    private const string AdministratorsSid = "S-1-5-32-544";

    public static void Verify(ManualUninstallPlan plan) => Verify(
        plan,
        Environment.ProcessPath is null
            ? throw new InstallException("owned_resource_mismatch")
            : Path.GetFullPath(Environment.ProcessPath));

    internal static void Verify(ManualUninstallPlan plan, string expectedExecutable)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var receipt = InstallationReceiptValidator.Validate(plan.Receipt);
        var executable = Path.GetFullPath(expectedExecutable);
        var expectedDataRoot = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SimplySignAuto"));
        if (receipt.Mode != InstallationMode.Manual ||
            !string.Equals(receipt.ExecutablePath, executable, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.DataRoot, expectedDataRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        using var profileKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
            $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{receipt.SigningUserSid}",
            writable: false);
        var profilePath = profileKey?.GetValue(
            "ProfileImagePath",
            null,
            Microsoft.Win32.RegistryValueOptions.None) as string;
        if (string.IsNullOrWhiteSpace(profilePath) || !Path.IsPathFullyQualified(profilePath))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var expectedUserData = Path.GetFullPath(Path.Combine(
            profilePath,
            "AppData",
            "Local",
            "SimplySignAuto",
            "manual"));
        if (!string.Equals(receipt.UserDataRoot, expectedUserData, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var signingUser = new System.Security.Principal.SecurityIdentifier(receipt.SigningUserSid);
        WindowsInstallAcl.VerifyDirectory(
            plan.DataRoot,
            InstallAclProfile.AdministratorsOnly,
            signingUser);
        WindowsInstallAcl.VerifyFile(
            Path.Combine(plan.DataRoot, "install.json"),
            InstallAclProfile.AdministratorsOnly,
            signingUser);
        if (Directory.Exists(expectedUserData))
        {
            VerifyUserDataSnapshot(
                WindowsNoFollowSecurity.ReadDirectory(expectedUserData),
                receipt.SigningUserSid);
        }
        else if (WindowsPathSafety.EntryExists(expectedUserData))
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    internal static void VerifyUserDataSnapshot(
        WindowsNoFollowSecuritySnapshot snapshot,
        string signingUserSid)
    {
        var ownerSid = snapshot.Security.Owner?.Value;
        if ((snapshot.Attributes & FileAttributes.ReparsePoint) != 0 ||
            !string.Equals(ownerSid, signingUserSid, StringComparison.Ordinal) &&
            !string.Equals(ownerSid, AdministratorsSid, StringComparison.Ordinal))
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }
}

internal interface IWindowsUninstallNative
{
    void VerifySigningIdentityOwnership(
        UninstallSigningIdentity identity,
        ServiceConfiguration configuration);

    void VerifyFirewallOwnership(RemoveOwnedFirewallRule action);

    Task VerifyTaskOwnershipAsync(
        RemoveOwnedInteractiveLogonTask action,
        CancellationToken cancellationToken);

    void VerifyServiceOwnership(RemoveOwnedWindowsService action);

    void VerifyAutoLogonOwnership(RemoveOwnedAutoLogon action);

    void VerifySigningSessionOwnership(EndOwnedSigningUserSession action);

    void VerifyAccountRightsOwnership(RemoveOwnedAccountRights action);

    void VerifyControlledDataOwnership(
        PurgeControlledData action,
        UninstallSigningIdentity identity);

    ManagedProfileRemovalState VerifyProfileOwnership(DeleteOwnedWindowsProfile action);

    void VerifyLocalUserOwnership(DeleteOwnedLocalUser action);

    void VerifyProductRegistrationOwnership(RemoveOwnedProductUninstall action);

    void VerifyDesktopShortcutOwnership(RemoveOwnedDesktopShortcut action);

    void RemoveFirewall(RemoveOwnedFirewallRule action);

    Task EndAndRemoveTaskAsync(
        RemoveOwnedInteractiveLogonTask action,
        CancellationToken cancellationToken);

    Task StopAndRemoveServiceAsync(
        RemoveOwnedWindowsService action,
        CancellationToken cancellationToken);

    void RemoveAutoLogon(RemoveOwnedAutoLogon action);

    Task EndSigningUserSessionsAsync(
        EndOwnedSigningUserSession action,
        CancellationToken cancellationToken);

    void RemoveAccountRights(RemoveOwnedAccountRights action);

    Task DeleteProfileAsync(
        DeleteOwnedWindowsProfile action,
        CancellationToken cancellationToken);

    void DeleteLocalUser(DeleteOwnedLocalUser action);

    void RemoveProductRegistration(RemoveOwnedProductUninstall action);

    void RemoveDesktopShortcut(RemoveOwnedDesktopShortcut action);

    Task RemovePdfExtensionAsync(CancellationToken cancellationToken);
}

public sealed class ManualUninstallOrchestrator(WindowsManualUninstallActionExecutor executor)
{
    public async Task ExecuteAsync(
        ManualUninstallPlan plan,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(output);
        await executor.PreflightAsync(plan, cancellationToken).ConfigureAwait(false);
        foreach (var action in plan.Actions)
        {
            await executor.ExecuteAsync(action, cancellationToken).ConfigureAwait(false);
        }

        await output.WriteLineAsync(
            plan.Actions.OfType<PurgeControlledData>().Single().IncludeAgentDirectory
                ? "SimplySignAuto was removed with the exact-owned manual task data."
                : "SimplySignAuto was removed; manual task history and signed results were preserved.")
            .ConfigureAwait(false);
    }
}

public sealed class WindowsManualUninstallActionExecutor
{
    private readonly IWindowsUninstallNative _native;
    private readonly IPurgeIsolationFileSystem _purgeFileSystem;
    private readonly IOptionalToolUninstallPreflight _optionalToolPreflight;
    private readonly IManualInstalledMediaUninstallPreflight _mediaPreflight;
    private readonly IInstallationReceiptStore _receiptStore;
    private PurgeIsolationPlan? _preparedPurgePlan;
    private PurgeControlledData? _preparedPurgeAction;

    public WindowsManualUninstallActionExecutor()
        : this(
            new WindowsUninstallNative(),
            new WindowsPurgeIsolationFileSystem(),
            new WindowsOptionalToolUninstallPreflight(),
            new WindowsManualInstalledMediaUninstallPreflight(),
            new WindowsInstallationReceiptStore())
    {
    }

    internal WindowsManualUninstallActionExecutor(
        IWindowsUninstallNative native,
        IPurgeIsolationFileSystem purgeFileSystem,
        IOptionalToolUninstallPreflight optionalToolPreflight,
        IManualInstalledMediaUninstallPreflight mediaPreflight,
        IInstallationReceiptStore receiptStore)
    {
        _native = native ?? throw new ArgumentNullException(nameof(native));
        _purgeFileSystem = purgeFileSystem ?? throw new ArgumentNullException(nameof(purgeFileSystem));
        _optionalToolPreflight = optionalToolPreflight ??
            throw new ArgumentNullException(nameof(optionalToolPreflight));
        _mediaPreflight = mediaPreflight ?? throw new ArgumentNullException(nameof(mediaPreflight));
        _receiptStore = receiptStore ?? throw new ArgumentNullException(nameof(receiptStore));
    }

    public async Task PreflightAsync(
        ManualUninstallPlan plan,
        CancellationToken cancellationToken)
    {
        _preparedPurgePlan = null;
        _preparedPurgeAction = null;
        await _mediaPreflight.VerifyAsync(plan.Receipt, cancellationToken).ConfigureAwait(false);
        WindowsManualUninstallOwnership.Verify(plan);
        if (await _receiptStore.LoadOptionalAsync(cancellationToken).ConfigureAwait(false) != plan.Receipt)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        await _optionalToolPreflight.VerifyAsync(
                new InstalledProductIdentity(
                    plan.Receipt.ExecutablePath,
                    plan.Receipt.SigningUserSid),
                cancellationToken)
            .ConfigureAwait(false);

        foreach (var action in plan.Actions)
        {
            switch (action)
            {
                case RemoveOwnedPdfExtension:
                    break;
                case PurgeControlledData:
                    break;
                case RemoveOwnedDesktopShortcut shortcut:
                    _native.VerifyDesktopShortcutOwnership(shortcut);
                    break;
                case RemoveOwnedProductUninstall product:
                    _native.VerifyProductRegistrationOwnership(product);
                    break;
                default:
                    throw new InstallException("uninstall_action_invalid");
            }
        }

        var purge = plan.Actions.OfType<PurgeControlledData>().Single();
        _preparedPurgePlan = _purgeFileSystem.Plan(
            purge.DataRoot,
            purge.IncludeAgentDirectory ? purge.AgentDirectory : null,
            new PurgeInstallIdentity(
                plan.Identity.OwnerMarker,
                plan.Receipt.SigningUserSid,
                plan.Receipt.InstallInstanceId,
                UninstallSigningUserOwnership.ExistingUser,
                plan.Receipt.ExecutablePath));
        _preparedPurgeAction = purge;
    }

    public async Task ExecuteAsync(
        UninstallAction action,
        CancellationToken cancellationToken)
    {
        switch (action)
        {
            case RemoveOwnedPdfExtension:
                await _native.RemovePdfExtensionAsync(cancellationToken).ConfigureAwait(false);
                break;
            case PurgeControlledData purge:
                if (_preparedPurgePlan is null || _preparedPurgeAction != purge)
                {
                    throw new InstallException("uninstall_state_uncertain");
                }

                await new PurgeIsolationCoordinator(_purgeFileSystem)
                    .ExecuteAsync(_preparedPurgePlan, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case RemoveOwnedDesktopShortcut shortcut:
                _native.RemoveDesktopShortcut(shortcut);
                break;
            case RemoveOwnedProductUninstall product:
                _native.RemoveProductRegistration(product);
                break;
            default:
                throw new InstallException("uninstall_action_invalid");
        }
    }
}

public sealed class WindowsUninstallActionExecutor : IUninstallActionExecutor
{
    private readonly IWindowsUninstallNative _native;
    private readonly IPurgeIsolationFileSystem _purgeFileSystem;
    private readonly IOptionalToolUninstallPreflight _optionalToolPreflight;
    private readonly IInstalledMediaUninstallPreflight _installedMediaPreflight;
    private readonly IInstallationReceiptStore _receiptStore;
    private PurgeIsolationPlan? _preparedPurgePlan;
    private PurgeControlledData? _preparedPurgeAction;
    private string? _managedProfileDirectoryForPurge;

    public WindowsUninstallActionExecutor()
        : this(
            new WindowsUninstallNative(),
            new WindowsPurgeIsolationFileSystem(),
            new WindowsOptionalToolUninstallPreflight(),
            new WindowsInstalledMediaUninstallPreflight(),
            new WindowsInstallationReceiptStore())
    {
    }

    internal WindowsUninstallActionExecutor(
        IWindowsUninstallNative native,
        IPurgeIsolationFileSystem purgeFileSystem,
        IOptionalToolUninstallPreflight optionalToolPreflight,
        IInstalledMediaUninstallPreflight installedMediaPreflight,
        IInstallationReceiptStore? receiptStore = null)
    {
        _native = native ?? throw new ArgumentNullException(nameof(native));
        _purgeFileSystem = purgeFileSystem ?? throw new ArgumentNullException(nameof(purgeFileSystem));
        _optionalToolPreflight = optionalToolPreflight ??
            throw new ArgumentNullException(nameof(optionalToolPreflight));
        _installedMediaPreflight = installedMediaPreflight ??
            throw new ArgumentNullException(nameof(installedMediaPreflight));
        _receiptStore = receiptStore ?? new WindowsInstallationReceiptStore();
    }

    public async Task PreflightAsync(
        UninstallPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        _preparedPurgePlan = null;
        _preparedPurgeAction = null;
        _managedProfileDirectoryForPurge = null;
        cancellationToken.ThrowIfCancellationRequested();
        await _installedMediaPreflight.VerifyAsync(plan, cancellationToken).ConfigureAwait(false);
        if (plan.Actions.Any(static action =>
                action is PurgeControlledData or RemoveOwnedPdfExtension))
        {
            await _optionalToolPreflight.VerifyAsync(
                    new InstalledProductIdentity(
                        plan.Configuration.ExecutablePath,
                        plan.Identity.Sid),
                    cancellationToken)
                .ConfigureAwait(false);
        }

        _native.VerifySigningIdentityOwnership(plan.Identity, plan.Configuration);
        foreach (var action in plan.Actions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (action)
            {
                case RemoveOwnedFirewallRule firewall:
                    _native.VerifyFirewallOwnership(firewall);
                    break;
                case RemoveOwnedInteractiveLogonTask task:
                    await _native.VerifyTaskOwnershipAsync(task, cancellationToken).ConfigureAwait(false);
                    break;
                case RemoveOwnedWindowsService service:
                    _native.VerifyServiceOwnership(service);
                    break;
                case RemoveOwnedAutoLogon autoLogon:
                    _native.VerifyAutoLogonOwnership(autoLogon);
                    break;
                case EndOwnedSigningUserSession session:
                    _native.VerifySigningSessionOwnership(session);
                    break;
                case RemoveOwnedAccountRights rights:
                    _native.VerifyAccountRightsOwnership(rights);
                    break;
                case PurgeControlledData purge:
                    _native.VerifyControlledDataOwnership(purge, plan.Identity);
                    break;
                case DeleteOwnedWindowsProfile profile:
                    var profileState = _native.VerifyProfileOwnership(profile);
                    if (ManagedProfileRemovalPolicy.RequiresCombinedPurge(profileState))
                    {
                        _managedProfileDirectoryForPurge = profile.Identity.ProfilePath;
                    }
                    break;
                case DeleteOwnedLocalUser user:
                    _native.VerifyLocalUserOwnership(user);
                    break;
                case RemoveOwnedProductUninstall product:
                    _native.VerifyProductRegistrationOwnership(product);
                    break;
                case RemoveOwnedDesktopShortcut shortcut:
                    _native.VerifyDesktopShortcutOwnership(shortcut);
                    break;
                case RemoveOwnedPdfExtension:
                    break;
                case RemoveOwnedInstallationReceipt receipt:
                    if (await _receiptStore.LoadOptionalAsync(cancellationToken).ConfigureAwait(false) !=
                        receipt.Receipt)
                    {
                        throw new InstallException("owned_resource_mismatch");
                    }

                    break;
                default:
                    throw new InstallException("uninstall_action_invalid");
            }
        }

        var purgeAction = plan.Actions.OfType<PurgeControlledData>().SingleOrDefault();
        if (purgeAction is not null)
        {
            if (purgeAction.IncludeAgentDirectory && _managedProfileDirectoryForPurge is not null)
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            var secondaryDirectory = purgeAction.IncludeAgentDirectory
                ? purgeAction.AgentDirectory
                : _managedProfileDirectoryForPurge;
            _preparedPurgePlan = _purgeFileSystem.Plan(
                purgeAction.DataRoot,
                secondaryDirectory,
                new PurgeInstallIdentity(
                    plan.Identity.OwnerMarker,
                    plan.Configuration.SigningUserSid,
                    plan.Configuration.InstallInstanceId,
                    plan.Identity.Ownership,
                    plan.Configuration.ExecutablePath));
            _preparedPurgeAction = purgeAction;
        }
    }

    public async Task ExecuteAsync(UninstallAction action, CancellationToken cancellationToken)
    {
        switch (action)
        {
            case RemoveOwnedFirewallRule firewall:
                _native.RemoveFirewall(firewall);
                break;
            case RemoveOwnedInteractiveLogonTask task:
                await _native.EndAndRemoveTaskAsync(task, cancellationToken).ConfigureAwait(false);
                break;
            case RemoveOwnedWindowsService service:
                await _native.StopAndRemoveServiceAsync(service, cancellationToken).ConfigureAwait(false);
                break;
            case RemoveOwnedAutoLogon autoLogon:
                _native.RemoveAutoLogon(autoLogon);
                break;
            case EndOwnedSigningUserSession session:
                await _native.EndSigningUserSessionsAsync(session, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case RemoveOwnedAccountRights rights:
                _native.RemoveAccountRights(rights);
                break;
            case PurgeControlledData purge:
                if (_preparedPurgePlan is null || _preparedPurgeAction != purge)
                {
                    throw new InstallException("uninstall_state_uncertain");
                }

                await new PurgeIsolationCoordinator(_purgeFileSystem)
                    .ExecuteAsync(_preparedPurgePlan, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case DeleteOwnedWindowsProfile profile:
                await _native.DeleteProfileAsync(profile, cancellationToken).ConfigureAwait(false);
                break;
            case DeleteOwnedLocalUser user:
                _native.DeleteLocalUser(user);
                break;
            case RemoveOwnedProductUninstall product:
                _native.RemoveProductRegistration(product);
                break;
            case RemoveOwnedDesktopShortcut shortcut:
                _native.RemoveDesktopShortcut(shortcut);
                break;
            case RemoveOwnedPdfExtension:
                await _native.RemovePdfExtensionAsync(cancellationToken).ConfigureAwait(false);
                break;
            case RemoveOwnedInstallationReceipt receipt:
                await _receiptStore.DeleteExactAsync(receipt.Receipt, cancellationToken)
                    .ConfigureAwait(false);
                break;
            default:
                throw new InstallException("uninstall_action_invalid");
        }
    }
}

public static class UninstallCommand
{
    public static async Task<int> ExecuteAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        using var lease = new ServiceConfigurationWriterLeaseFactory().TryAcquire();
        if (lease is null)
        {
            await error.WriteLineAsync("uninstall_busy").ConfigureAwait(false);
            return 1;
        }

        if (!TryParse(args, out var options))
        {
            await error.WriteLineAsync("uninstall_arguments_invalid").ConfigureAwait(false);
            return 2;
        }

        try
        {
            var receipt = await new WindowsInstallationReceiptStore()
                .LoadOptionalAsync(cancellationToken)
                .ConfigureAwait(false);
            if (receipt?.Mode == InstallationMode.Manual)
            {
                var manualPlan = await new ManualUninstallPlanner(
                        new WindowsManualUninstallEnvironment(receipt))
                    .PlanAsync(options!, cancellationToken)
                    .ConfigureAwait(false);
                await new ManualUninstallOrchestrator(
                        new WindowsManualUninstallActionExecutor())
                    .ExecuteAsync(manualPlan, output, cancellationToken)
                    .ConfigureAwait(false);
                return 0;
            }

            if (!options!.PurgeData &&
                !File.Exists(WindowsUninstallEnvironment.ConfigurationPath) &&
                !WindowsPathSafety.EntryExists(WindowsInstallationReceiptStore.ReceiptPath) &&
                await new WindowsInterruptedPurgeResume()
                    .TryResumeAsync(cancellationToken)
                    .ConfigureAwait(false))
            {
                await output.WriteLineAsync(
                    "Interrupted product data isolation resumed; physical cleanup will complete after restart.")
                    .ConfigureAwait(false);
                return 0;
            }

            var plan = await new UninstallPlanner(new WindowsUninstallEnvironment())
                .PlanAsync(options, cancellationToken).ConfigureAwait(false);
            await new UninstallOrchestrator(new WindowsUninstallActionExecutor())
                .ExecuteAsync(plan, output, cancellationToken).ConfigureAwait(false);
            return 0;
        }
        catch (ServiceConfigurationException configurationError)
        {
            await error.WriteLineAsync(configurationError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (InstallException uninstallError)
        {
            await error.WriteLineAsync(uninstallError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 1;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            await error.WriteLineAsync("uninstall_failed").ConfigureAwait(false);
            return 1;
        }
    }

    internal static bool TryParse(string[] args, out UninstallOptions? options)
    {
        options = null;
        if (args.Length == 0)
        {
            options = new UninstallOptions(false, null);
            return true;
        }

        if (args is ["--purge-data", "--confirm", var confirmation])
        {
            options = new UninstallOptions(true, confirmation);
            return true;
        }

        return false;
    }
}
