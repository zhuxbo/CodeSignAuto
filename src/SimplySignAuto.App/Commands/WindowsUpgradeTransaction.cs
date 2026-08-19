using System.Security.Principal;
using Microsoft.Win32;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.Control;
using SimplySignAuto.Core.Versioning;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;

namespace SimplySignAuto.App.Commands;

internal interface IUpgradeControlClient : IDisposable
{
    Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken);

    Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken);

    Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken);

    Task<bool> DrainForUpgradeAsync(int timeoutSeconds, CancellationToken cancellationToken);

    Task ResumeAfterUpgradeFailureAsync(CancellationToken cancellationToken);
}

internal interface IUpgradeRegistrationStore
{
    void ReplaceExact(
        ProductUninstallRegistration expected,
        ProductUninstallRegistration replacement,
        string errorCode);
}

internal sealed class UpgradeControlClient : IUpgradeControlClient
{
    private readonly AdminControlClient _inner = new();

    public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) =>
        _inner.GetServiceSettingsAsync(cancellationToken);

    public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
        _inner.RefreshAsync(cancellationToken);

    public Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken) =>
        _inner.LogoutAsync(cancellationToken);

    public Task<bool> DrainForUpgradeAsync(int timeoutSeconds, CancellationToken cancellationToken) =>
        _inner.DrainForUpgradeAsync(timeoutSeconds, cancellationToken);

    public Task ResumeAfterUpgradeFailureAsync(CancellationToken cancellationToken) =>
        _inner.ResumeAfterUpgradeFailureAsync(cancellationToken);

    public void Dispose() => _inner.Dispose();
}

internal sealed class UpgradeRegistrationStore : IUpgradeRegistrationStore
{
    public void ReplaceExact(
        ProductUninstallRegistration expected,
        ProductUninstallRegistration replacement,
        string errorCode) => WindowsProductUninstallRegistry.ReplaceExact(expected, replacement, errorCode);
}

internal sealed class WindowsUpgradeTransaction : IUpgradeTransaction
{
    private const string ServiceName = "SimplySignAuto.Service";
    private const string AgentTaskName = "SimplySignAuto.Agent";
    private const int DrainTimeoutSeconds = 120;
    private static readonly TimeSpan RuntimeTimeout = TimeSpan.FromSeconds(30);

    private readonly ServiceConfiguration _configuration;
    private readonly ProductUninstallRegistration _oldRegistration;
    private readonly ProductUninstallRegistration _newRegistration;
    private readonly IUpgradeMediaTransaction _media;
    private readonly IWindowsInstallStartupRuntime _startup;
    private readonly IUpgradeControlClient _control;
    private readonly IUpgradeRegistrationStore _registrations;
    private readonly bool _expectAuthenticode;
    private readonly bool _expectPdf;
    private readonly TimeSpan _runtimeTimeout;
    private readonly Func<bool> _interactiveSessionAvailable;
    private InstallMediaPlan? _mediaPlan;
    private bool _drainAttempted;
    private bool _drained;
    private bool _agentStopAttempted;
    private bool _serviceStopAttempted;
    private bool _activated;
    private bool _registrationUpdated;
    private bool _committed;

    internal WindowsUpgradeTransaction(
        ServiceConfiguration configuration,
        ProductUninstallRegistration oldRegistration,
        ProductUninstallRegistration newRegistration,
        IUpgradeMediaTransaction media,
        IWindowsInstallStartupRuntime startup,
        IUpgradeControlClient control,
        IUpgradeRegistrationStore registrations,
        bool hasInteractiveSigningSession,
        bool expectAuthenticode,
        bool expectPdf,
        TimeSpan? runtimeTimeout = null,
        Func<bool>? interactiveSessionAvailable = null)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _oldRegistration = oldRegistration ?? throw new ArgumentNullException(nameof(oldRegistration));
        _newRegistration = newRegistration ?? throw new ArgumentNullException(nameof(newRegistration));
        _media = media ?? throw new ArgumentNullException(nameof(media));
        _startup = startup ?? throw new ArgumentNullException(nameof(startup));
        _control = control ?? throw new ArgumentNullException(nameof(control));
        _registrations = registrations ?? throw new ArgumentNullException(nameof(registrations));
        _expectAuthenticode = expectAuthenticode;
        _expectPdf = expectPdf;
        _runtimeTimeout = runtimeTimeout ?? RuntimeTimeout;
        _interactiveSessionAvailable = interactiveSessionAvailable ??
            (() => hasInteractiveSigningSession);
        if (_runtimeTimeout <= TimeSpan.Zero || _runtimeTimeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(runtimeTimeout));
        }

        HasInteractiveSigningSession = hasInteractiveSigningSession;
    }

    public bool HasInteractiveSigningSession { get; }

    internal static async Task<WindowsUpgradeTransaction?> TryCreateAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(WindowsUninstallEnvironment.ConfigurationPath))
        {
            return null;
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new SetupException("windows_required");
        }

        var environment = new WindowsUpgradeEnvironment();
        var plan = await new UninstallPlanner(environment)
            .PlanAsync(new UninstallOptions(false, null), cancellationToken)
            .ConfigureAwait(false);
        await VerifyOwnedInstallationAsync(plan, cancellationToken).ConfigureAwait(false);
        var configuration = plan.Configuration;
        var ownerMarker = InstallOwnershipMarker.Create(configuration.InstallInstanceId);
        var oldRegistration = WindowsProductUninstallRegistry.ReadExact(
            configuration.ExecutablePath,
            ownerMarker,
            "owned_resource_mismatch");
        var oldVersion = ProductVersion.Parse(oldRegistration.DisplayVersion);
        var newVersion = ProductVersion.Parse(
            SimplySignAuto.App.ApplicationVersion.ReadIdentity(typeof(WindowsUpgradeTransaction).Assembly));
        if (newVersion.ComparePrecedenceTo(oldVersion) <= 0)
        {
            throw new SetupException("upgrade_version_not_newer");
        }

        await VerifyPersistedCompatibilityAsync(configuration, cancellationToken).ConfigureAwait(false);
        var control = new UpgradeControlClient();
        try
        {
            var current = await control.GetServiceSettingsAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(current.ProductVersion, oldVersion.Display, StringComparison.Ordinal))
            {
                throw new SetupException("owned_resource_mismatch");
            }

            var snapshot = await control.RefreshAsync(cancellationToken).ConfigureAwait(false);
            var expectAuthenticode = snapshot.Authenticode.Configured;
            var expectPdf = snapshot.Pdf.Configured;
            if (!IsRuntimeSnapshotAcceptable(snapshot, expectAuthenticode, expectPdf))
            {
                throw new SetupException("restart_required");
            }

            var sourceRoot = Environment.ProcessPath is { } processPath
                ? Path.GetDirectoryName(Path.GetFullPath(processPath))
                : null;
            if (sourceRoot is null)
            {
                throw new SetupException("install_media_source_invalid");
            }

            var newRegistration = ProductUninstallRegistration.Create(
                configuration.ExecutablePath,
                newVersion.Identity,
                ownerMarker);
            var sessions = new WindowsActiveSessionLookup();
            var hasInteractiveSession = sessions.HasActiveSession(configuration.SigningUserSid);
            return new WindowsUpgradeTransaction(
                configuration,
                oldRegistration,
                newRegistration,
                new WindowsInstallMediaStager(
                    sourceRoot,
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    new WindowsInstallMediaVerifier(),
                    () => Guid.NewGuid().ToString("N"),
                    new WindowsAtomicProtectedDirectoryOperations(),
                    upgrade: true),
                new WindowsInstallStartupRuntime(),
                control,
                new UpgradeRegistrationStore(),
                hasInteractiveSession,
                expectAuthenticode,
                expectPdf,
                interactiveSessionAvailable: () =>
                    sessions.HasActiveSession(configuration.SigningUserSid));
        }
        catch (ManagementUnavailableException)
        {
            control.Dispose();
            throw new SetupException("restart_required");
        }
        catch
        {
            control.Dispose();
            throw;
        }
    }

    public async Task StageAsync(CancellationToken cancellationToken)
    {
        _mediaPlan = await _media.PlanAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(
                _mediaPlan.TargetExecutablePath,
                _configuration.ExecutablePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new SetupException("owned_resource_mismatch");
        }

        await _media.StageAsync(_mediaPlan, cancellationToken).ConfigureAwait(false);
        await _media.AuthorizeAsync(
                _mediaPlan,
                _configuration.SigningUserSid,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> DrainAsync(CancellationToken cancellationToken)
    {
        _drainAttempted = true;
        try
        {
            _drained = await _control
                .DrainForUpgradeAsync(DrainTimeoutSeconds, cancellationToken)
                .ConfigureAwait(false);
            return _drained;
        }
        catch (ManagementUnavailableException)
        {
            try
            {
                await _control.ResumeAfterUpgradeFailureAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (ManagementUnavailableException)
            {
                _ = await _control.GetServiceSettingsAsync(cancellationToken).ConfigureAwait(false);
            }

            _drainAttempted = false;
            throw new SetupException("restart_required");
        }
    }

    public async Task LogoutAsync(CancellationToken cancellationToken)
    {
        try
        {
            var snapshot = await _control.LogoutAsync(cancellationToken).ConfigureAwait(false);
            if (snapshot.SimplySignProcessRunning)
            {
                throw new SetupException("restart_required");
            }
        }
        catch (ManagementUnavailableException)
        {
            throw new SetupException("restart_required");
        }
    }

    public async Task StopAgentAsync(CancellationToken cancellationToken)
    {
        _agentStopAttempted = true;
        try
        {
            await _startup.StopTaskAsync(AgentTaskName, cancellationToken).ConfigureAwait(false);
        }
        catch (InstallException error)
        {
            throw new SetupException(error.Code);
        }
    }

    public async Task StopServiceAsync(CancellationToken cancellationToken)
    {
        _serviceStopAttempted = true;
        try
        {
            await _startup.StopServiceAsync(ServiceName, cancellationToken).ConfigureAwait(false);
        }
        catch (InstallException error)
        {
            throw new SetupException(error.Code);
        }
    }

    public Task VerifyReplaceableAsync(CancellationToken cancellationToken) =>
        _media.VerifyUpgradeTargetReplaceableAsync(
            _mediaPlan ?? throw new SetupException("upgrade_state_uncertain"),
            cancellationToken);

    public async Task ActivateAsync(CancellationToken cancellationToken)
    {
        await _media.ActivateUpgradeAsync(
                _mediaPlan ?? throw new SetupException("upgrade_state_uncertain"),
                cancellationToken)
            .ConfigureAwait(false);
        _activated = true;
    }

    public async Task StartServiceAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _startup.StartAndVerifyServiceAsync(ServiceName, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InstallException error)
        {
            throw new SetupException(error.Code);
        }
    }

    public async Task StartAgentAsync(CancellationToken cancellationToken)
    {
        if (!_interactiveSessionAvailable())
        {
            throw new SetupException("restart_required");
        }

        try
        {
            await _startup.StartAndVerifyTaskAsync(
                    AgentTaskName,
                    requireRunning: true,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InstallException error)
        {
            throw new SetupException(error.Code);
        }
    }

    public Task VerifyAsync(CancellationToken cancellationToken) =>
        VerifyRuntimeAsync(_newRegistration.DisplayVersion, cancellationToken);

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        _registrations.ReplaceExact(
            _oldRegistration,
            _newRegistration,
            "product_registration_failed");
        _registrationUpdated = true;
        await _media.CommitUpgradeAsync(
                _mediaPlan ?? throw new SetupException("upgrade_state_uncertain"),
                cancellationToken)
            .ConfigureAwait(false);
        _committed = true;
        _control.Dispose();
    }

    public async Task RollbackAsync()
    {
        if (_committed)
        {
            return;
        }

        var uncertain = false;
        if (_activated || _serviceStopAttempted)
        {
            uncertain |= !await TryAsync(() => _startup.StopTaskAsync(
                    AgentTaskName,
                    CancellationToken.None))
                .ConfigureAwait(false);
            uncertain |= !await TryAsync(() => _startup.StopServiceAsync(
                    ServiceName,
                    CancellationToken.None))
                .ConfigureAwait(false);
        }

        if (_registrationUpdated)
        {
            try
            {
                _registrations.ReplaceExact(
                    _newRegistration,
                    _oldRegistration,
                    "upgrade_state_uncertain");
                _registrationUpdated = false;
            }
            catch
            {
                uncertain = true;
            }
        }

        if (_mediaPlan is not null)
        {
            uncertain |= !await TryAsync(() => _media.RollbackAsync(_mediaPlan))
                .ConfigureAwait(false);
        }

        if (_serviceStopAttempted)
        {
            uncertain |= !await TryAsync(() => _startup.StartAndVerifyServiceAsync(
                    ServiceName,
                    CancellationToken.None))
                .ConfigureAwait(false);
        }

        if (_agentStopAttempted && HasInteractiveSigningSession)
        {
            uncertain |= !await TryAsync(() => _startup.StartAndVerifyTaskAsync(
                    AgentTaskName,
                    requireRunning: true,
                    CancellationToken.None))
                .ConfigureAwait(false);
        }

        if (_serviceStopAttempted || _agentStopAttempted)
        {
            uncertain |= !await TryAsync(() => VerifyRuntimeAsync(
                    _oldRegistration.DisplayVersion,
                    CancellationToken.None))
                .ConfigureAwait(false);
        }

        if (_drainAttempted && !_serviceStopAttempted)
        {
            uncertain |= !await TryAsync(() => _control.ResumeAfterUpgradeFailureAsync(
                    CancellationToken.None))
                .ConfigureAwait(false);
        }

        _control.Dispose();
        if (uncertain)
        {
            throw new SetupException("upgrade_state_uncertain");
        }
    }

    private async Task VerifyRuntimeAsync(
        string expectedVersion,
        CancellationToken cancellationToken)
    {
        var expectedDisplay = ProductVersion.Parse(expectedVersion).Display;
        var deadline = DateTimeOffset.UtcNow + _runtimeTimeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var settings = await _control.GetServiceSettingsAsync(cancellationToken)
                    .ConfigureAwait(false);
                var snapshot = await _control.RefreshAsync(cancellationToken).ConfigureAwait(false);
                if (string.Equals(settings.ProductVersion, expectedDisplay, StringComparison.Ordinal) &&
                    IsRuntimeSnapshotAcceptable(snapshot, _expectAuthenticode, _expectPdf))
                {
                    return;
                }
            }
            catch (ManagementUnavailableException)
            {
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new SetupException("upgrade_verification_failed");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task VerifyPersistedCompatibilityAsync(
        ServiceConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var signingUser = new SecurityIdentifier(configuration.SigningUserSid);
        var agentDirectory = Path.GetDirectoryName(configuration.AgentConfigurationPath)
            ?? throw new SetupException("owned_resource_mismatch");
        var jobsPath = Path.Combine(configuration.DataRoot, "jobs.db");
        var tokenPath = Path.Combine(configuration.DataRoot, "install-token.txt");
        WindowsInstallAcl.VerifyDirectory(
            configuration.DataRoot,
            InstallAclProfile.AdministratorsOnly,
            signingUser);
        WindowsInstallAcl.VerifyDirectory(
            Path.Combine(configuration.DataRoot, "jobs"),
            InstallAclProfile.SigningUserModify,
            signingUser);
        WindowsInstallAcl.VerifyDirectory(
            Path.Combine(configuration.DataRoot, "tools"),
            InstallAclProfile.SigningUserRead,
            signingUser);
        WindowsInstallAcl.VerifyDirectory(
            Path.Combine(configuration.DataRoot, "logs"),
            InstallAclProfile.AdministratorsOnly,
            signingUser);
        WindowsInstallAcl.VerifyDirectory(
            configuration.SpoolRoot,
            InstallAclProfile.SigningUserRead,
            signingUser);
        WindowsInstallAcl.VerifyDirectory(
            agentDirectory,
            InstallAclProfile.SigningUserData,
            signingUser);
        WindowsInstallAcl.VerifyFile(
            WindowsUninstallEnvironment.ConfigurationPath,
            InstallAclProfile.AdministratorsOnly,
            signingUser);
        WindowsInstallAcl.VerifyFile(jobsPath, InstallAclProfile.AdministratorsOnly, signingUser);
        VerifyOptionalProtectedFile(
            tokenPath,
            WindowsNoFollowSecurity.FileEntryExists,
            path => WindowsInstallAcl.VerifyFile(
                path,
                InstallAclProfile.AdministratorsOnly,
                signingUser));
        WindowsInstallAcl.VerifyFile(
            configuration.AgentConfigurationPath,
            InstallAclProfile.SigningUserRead,
            signingUser);
        var agent = await new AgentConfigurationLoader(configuration.AgentConfigurationPath)
            .LoadAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(agent.SigningUserSid, configuration.SigningUserSid, StringComparison.Ordinal) ||
            !string.Equals(agent.SpoolPath, configuration.SpoolRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new SetupException("owned_resource_mismatch");
        }

        using var jobs = new SqliteJobStore(jobsPath);
        await jobs.CheckHealthAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static void VerifyOptionalProtectedFile(
        string path,
        Func<string, bool> entryExists,
        Action<string> verify)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(entryExists);
        ArgumentNullException.ThrowIfNull(verify);
        if (entryExists(path))
        {
            verify(path);
        }
    }

    internal static bool IsRuntimeSnapshotAcceptable(
        ManagementSnapshot snapshot,
        bool expectAuthenticode,
        bool expectPdf)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return snapshot.ServiceAvailable &&
            snapshot.AgentConnected &&
            snapshot.AgentSessionId > 0 &&
            snapshot.AgentSessionId == snapshot.HeartbeatSessionId &&
            snapshot.HeartbeatAgeMilliseconds is >= 0 &&
            snapshot.HeartbeatAgeMilliseconds <=
                (long)AgentPipeServer.HeartbeatTimeout.TotalMilliseconds &&
            CapabilityMatches(snapshot.Authenticode, expectAuthenticode) &&
            CapabilityMatches(snapshot.Pdf, expectPdf);
    }

    private static bool CapabilityMatches(CapabilitySnapshot capability, bool expected) =>
        expected
            ? capability is
            {
                Configured: true,
                Session.State: SimplySignSessionState.Ready or
                    SimplySignSessionState.LoginRequired or
                    SimplySignSessionState.WaitToken,
            }
            : !capability.Configured;

    private static async Task VerifyOwnedInstallationAsync(
        UninstallPlan plan,
        CancellationToken cancellationToken)
    {
        var native = new WindowsUninstallNative();
        await new WindowsInstalledMediaUninstallPreflight()
            .VerifyAsync(plan, cancellationToken)
            .ConfigureAwait(false);
        await new WindowsOptionalToolUninstallPreflight()
            .VerifyAsync(plan.Configuration, plan.Identity, cancellationToken)
            .ConfigureAwait(false);
        native.VerifySigningIdentityOwnership(plan.Identity, plan.Configuration);
        foreach (var action in plan.Actions)
        {
            switch (action)
            {
                case RemoveOwnedFirewallRule firewall:
                    native.VerifyFirewallOwnership(firewall);
                    break;
                case RemoveOwnedInteractiveLogonTask task:
                    await native.VerifyTaskOwnershipAsync(task, cancellationToken).ConfigureAwait(false);
                    break;
                case RemoveOwnedWindowsService service:
                    native.VerifyServiceOwnership(service);
                    break;
                case RemoveOwnedAutoLogon autoLogon:
                    native.VerifyAutoLogonOwnership(autoLogon);
                    break;
                case EndOwnedSigningUserSession session:
                    native.VerifySigningSessionOwnership(session);
                    break;
                case RemoveOwnedAccountRights rights:
                    native.VerifyAccountRightsOwnership(rights);
                    break;
                case PurgeControlledData data:
                    native.VerifyControlledDataOwnership(data, plan.Identity);
                    break;
                case DeleteOwnedWindowsProfile profile:
                    _ = native.VerifyProfileOwnership(profile);
                    break;
                case DeleteOwnedLocalUser user:
                    native.VerifyLocalUserOwnership(user);
                    break;
                case RemoveOwnedDesktopShortcut shortcut:
                    native.VerifyDesktopShortcutOwnership(shortcut);
                    break;
                case RemoveOwnedProductUninstall or RemoveOwnedPdfExtension:
                    break;
                default:
                    throw new SetupException("owned_resource_mismatch");
            }
        }
    }

    private static async Task<bool> TryAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }
}

internal sealed class WindowsUpgradeEnvironment : IUninstallEnvironment
{
    private readonly WindowsUninstallEnvironment _inner = new();

    public bool IsWindows => _inner.IsWindows;
    public string CommonDesktopDirectory => _inner.CommonDesktopDirectory;

    public Task<ServiceConfiguration> LoadConfigurationAsync(CancellationToken cancellationToken) =>
        _inner.LoadConfigurationAsync(cancellationToken);

    public void ValidateControlledPaths(ServiceConfiguration configuration)
    {
        var expectedDataRoot = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SimplySignAuto"));
        var expectedExecutable = InstallMediaPaths.GetTargetExecutablePath(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        using var profileKey = Registry.LocalMachine.OpenSubKey(
            $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{configuration.SigningUserSid}",
            writable: false);
        var profilePath = profileKey?.GetValue(
            "ProfileImagePath",
            null,
            RegistryValueOptions.None) as string;
        var disabled = string.IsNullOrWhiteSpace(profilePath)
            ? WindowsAutoLogonPlatform.ReadDisabledAutoLogon(
                InstallOwnershipMarker.Create(configuration.InstallInstanceId))
            : null;
        var expectedAgentPath = WindowsUninstallEnvironment.ResolveExpectedAgentPath(
            configuration,
            profilePath,
            disabled);
        if (!string.Equals(configuration.DataRoot, expectedDataRoot, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(configuration.AgentConfigurationPath, expectedAgentPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(configuration.ExecutablePath, expectedExecutable, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("uninstall_configuration_invalid");
        }
    }

    public UninstallSigningIdentity? InspectSigningIdentity(
        ServiceConfiguration configuration,
        string ownerMarker) => _inner.InspectSigningIdentity(configuration, ownerMarker);
}
