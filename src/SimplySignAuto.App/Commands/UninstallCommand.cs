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

public sealed record UninstallPlan(
    ServiceConfiguration Configuration,
    UninstallSigningIdentity Identity,
    IReadOnlyList<UninstallAction> Actions);

public interface IUninstallEnvironment
{
    bool IsWindows { get; }

    string CommonDesktopDirectory { get; }

    Task<ServiceConfiguration> LoadConfigurationAsync(CancellationToken cancellationToken);

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

        var configuration = ServiceConfigurationLoader.Validate(
            await environment.LoadConfigurationAsync(cancellationToken).ConfigureAwait(false));
        environment.ValidateControlledPaths(configuration);
        var exactOwnerMarker = InstallOwnershipMarker.Create(configuration.InstallInstanceId);
        var identity = environment.InspectSigningIdentity(configuration, exactOwnerMarker);
        if (identity is null)
        {
            return LegacyPlan(configuration, exactOwnerMarker, options.PurgeData);
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

        return new UninstallPlan(configuration, identity, actions);
    }

    private static UninstallPlan LegacyPlan(
        ServiceConfiguration configuration,
        string ownerMarker,
        bool includePurge)
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

        return new UninstallPlan(configuration, identity, actions);
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

public sealed class WindowsUninstallActionExecutor : IUninstallActionExecutor
{
    private readonly IWindowsUninstallNative _native;
    private readonly IPurgeIsolationFileSystem _purgeFileSystem;
    private readonly IOptionalToolUninstallPreflight _optionalToolPreflight;
    private readonly IInstalledMediaUninstallPreflight _installedMediaPreflight;
    private PurgeIsolationPlan? _preparedPurgePlan;
    private PurgeControlledData? _preparedPurgeAction;
    private string? _managedProfileDirectoryForPurge;

    public WindowsUninstallActionExecutor()
        : this(
            new WindowsUninstallNative(),
            new WindowsPurgeIsolationFileSystem(),
            new WindowsOptionalToolUninstallPreflight(),
            new WindowsInstalledMediaUninstallPreflight())
    {
    }

    internal WindowsUninstallActionExecutor(
        IWindowsUninstallNative native,
        IPurgeIsolationFileSystem purgeFileSystem,
        IOptionalToolUninstallPreflight optionalToolPreflight,
        IInstalledMediaUninstallPreflight installedMediaPreflight)
    {
        _native = native ?? throw new ArgumentNullException(nameof(native));
        _purgeFileSystem = purgeFileSystem ?? throw new ArgumentNullException(nameof(purgeFileSystem));
        _optionalToolPreflight = optionalToolPreflight ??
            throw new ArgumentNullException(nameof(optionalToolPreflight));
        _installedMediaPreflight = installedMediaPreflight ??
            throw new ArgumentNullException(nameof(installedMediaPreflight));
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
                    plan.Configuration,
                    plan.Identity,
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
            if (!options!.PurgeData &&
                !File.Exists(WindowsUninstallEnvironment.ConfigurationPath) &&
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
