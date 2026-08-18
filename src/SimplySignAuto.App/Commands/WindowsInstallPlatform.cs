using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using Microsoft.Win32;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

public sealed class WindowsInstallEnvironment : IInstallEnvironment
{
    private readonly object _validatedOwnerSync = new();
    private readonly Dictionary<string, string> _validatedOwners = new(StringComparer.Ordinal);
    private readonly IWindowsAutoLogonPlatform _autoLogonPlatform;

    public WindowsInstallEnvironment()
        : this(
            new WindowsAutoLogonPlatform(),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))
    {
    }

    internal WindowsInstallEnvironment(IWindowsAutoLogonPlatform autoLogonPlatform)
        : this(
            autoLogonPlatform,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))
    {
    }

    internal WindowsInstallEnvironment(
        IWindowsAutoLogonPlatform autoLogonPlatform,
        string programFilesRoot)
    {
        _autoLogonPlatform = autoLogonPlatform ?? throw new ArgumentNullException(nameof(autoLogonPlatform));
        ExecutablePath = InstallMediaPaths.GetTargetExecutablePath(programFilesRoot);
    }

    public bool IsWindows => OperatingSystem.IsWindows();

    public string ExecutablePath { get; }

    public string ProgramDataRoot => Path.GetFullPath(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

    public string CommonDesktopDirectory => Path.GetFullPath(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));

    public void ValidateExecutableSecurity(ResolvedSigningAccount account)
    {
        EnsureWindows();
        try
        {
            WindowsExecutableSecurity.Verify(ExecutablePath, account.Sid);
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException or SystemException)
        {
            throw new InstallException("install_executable_insecure");
        }
    }

    public Task<ResolvedSigningAccount> ResolveSigningAccountAsync(
        string account,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        try
        {
            var requested = new NTAccount(account);
            var sid = (SecurityIdentifier)requested.Translate(typeof(SecurityIdentifier));
            var canonicalAccount = (NTAccount)sid.Translate(typeof(NTAccount));
            if (!string.Equals(canonicalAccount.Value, account, StringComparison.OrdinalIgnoreCase) ||
                !CanonicalWindowsSid.IsValid(sid.Value))
            {
                throw new InstallException("signing_user_invalid");
            }

            using var profileKey = Registry.LocalMachine.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid.Value}",
                writable: false);
            var profilePath = profileKey?.GetValue(
                "ProfileImagePath",
                null,
                RegistryValueOptions.None) as string;
            if (string.IsNullOrWhiteSpace(profilePath) || !Path.IsPathFullyQualified(profilePath))
            {
                throw new InstallException("signing_user_profile_missing");
            }

            return Task.FromResult(new ResolvedSigningAccount(
                canonicalAccount.Value,
                sid.Value,
                Path.GetFullPath(Path.Combine(profilePath, "AppData", "Local"))));
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IdentityNotMappedException or UnauthorizedAccessException or
                SystemException)
        {
            throw new InstallException("signing_user_invalid");
        }
    }

    public async Task ValidateAutomaticLogonAsync(
        ResolvedSigningAccount account,
        CancellationToken cancellationToken)
    {
        try
        {
            var userName = account.AccountName[(account.AccountName.IndexOf('\\') + 1)..];
            var inspection = await _autoLogonPlatform
                .InspectAsync(userName, cancellationToken)
                .ConfigureAwait(false);
            ProvisionAgentUserOrchestrator.ValidateEnvironment(inspection);
            var resolved = await _autoLogonPlatform
                .ResolveExistingUserAsync(userName, cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(resolved.AccountName, account.AccountName, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(resolved.Sid, account.Sid, StringComparison.Ordinal))
            {
                throw new InstallException("autologon_not_ready");
            }

            var readback = await _autoLogonPlatform
                .ReadbackAsync(resolved, string.Empty, cancellationToken)
                .ConfigureAwait(false);
            var instanceId = ProvisionAgentUserOrchestrator.ValidateExistingReadback(
                resolved,
                inspection,
                readback);
            lock (_validatedOwnerSync)
            {
                _validatedOwners[account.Sid] = instanceId;
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw new InstallException("autologon_not_ready");
        }
    }

    public Task<string?> GetProvisionedInstallInstanceIdAsync(
        ResolvedSigningAccount account,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_validatedOwnerSync)
        {
            return Task.FromResult(
                _validatedOwners.TryGetValue(account.Sid, out var instanceId)
                    ? instanceId
                    : null);
        }
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }
    }
}

public sealed class WindowsInstallActionExecutor : IInstallActionExecutor
{
    private readonly string _signingUserSid;
    private readonly IWindowsCommandRunner _runner;
    private readonly IWindowsInstallResourceLookup _resourceLookup;
    private readonly IWindowsInstallStartupRuntime _startupRuntime;
    private readonly IWindowsServiceRecoveryInspector _recoveryInspector;
    private readonly IWindowsInstallRollbackOwnershipVerifier _rollbackOwnershipVerifier;
    private readonly WindowsOwnedTaskRollback _ownedTaskRollback;
    private readonly WindowsOwnedServiceRollback _ownedServiceRollback;

    public WindowsInstallActionExecutor(string signingUserSid)
        : this(
            signingUserSid,
            new DefaultWindowsCommandRunner(),
            new WindowsInstallResourceLookup(),
            new WindowsInstallStartupRuntime(),
            new WindowsServiceRecoveryInspector(),
            rollbackOwnershipVerifier: null)
    {
    }

    internal WindowsInstallActionExecutor(
        string signingUserSid,
        IWindowsCommandRunner runner,
        IWindowsInstallResourceLookup resourceLookup)
        : this(
            signingUserSid,
            runner,
            resourceLookup,
            new WindowsInstallStartupRuntime(),
            new WindowsServiceRecoveryInspector(),
            rollbackOwnershipVerifier: null)
    {
    }

    internal WindowsInstallActionExecutor(
        string signingUserSid,
        IWindowsCommandRunner runner,
        IWindowsInstallResourceLookup resourceLookup,
        IWindowsInstallStartupRuntime startupRuntime)
        : this(
            signingUserSid,
            runner,
            resourceLookup,
            startupRuntime,
            new WindowsServiceRecoveryInspector(),
            rollbackOwnershipVerifier: null)
    {
    }

    internal WindowsInstallActionExecutor(
        string signingUserSid,
        IWindowsCommandRunner runner,
        IWindowsInstallResourceLookup resourceLookup,
        IWindowsInstallStartupRuntime startupRuntime,
        IWindowsInstallRollbackOwnershipVerifier rollbackOwnershipVerifier)
        : this(
            signingUserSid,
            runner,
            resourceLookup,
            startupRuntime,
            new WindowsServiceRecoveryInspector(),
            rollbackOwnershipVerifier)
    {
    }

    internal WindowsInstallActionExecutor(
        string signingUserSid,
        IWindowsCommandRunner runner,
        IWindowsInstallResourceLookup resourceLookup,
        IWindowsInstallStartupRuntime startupRuntime,
        IWindowsServiceRecoveryInspector recoveryInspector,
        IWindowsInstallRollbackOwnershipVerifier? rollbackOwnershipVerifier = null)
    {
        _signingUserSid = CanonicalWindowsSid.IsValid(signingUserSid)
            ? signingUserSid
            : throw new ArgumentException("Signing user SID is invalid.", nameof(signingUserSid));
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _resourceLookup = resourceLookup ?? throw new ArgumentNullException(nameof(resourceLookup));
        _startupRuntime = startupRuntime ?? throw new ArgumentNullException(nameof(startupRuntime));
        _recoveryInspector = recoveryInspector ?? throw new ArgumentNullException(nameof(recoveryInspector));
        _rollbackOwnershipVerifier = rollbackOwnershipVerifier ??
            new WindowsInstallRollbackOwnershipVerifier(
                _signingUserSid,
                _runner,
                _resourceLookup,
                _recoveryInspector);
        _ownedTaskRollback = new WindowsOwnedTaskRollback(
            _runner,
            _resourceLookup,
            _startupRuntime);
        _ownedServiceRollback = new WindowsOwnedServiceRollback(
            _runner,
            _resourceLookup,
            _startupRuntime);
    }

    public async Task<AppliedInstallAction> ApplyAsync(
        InstallAction action,
        InstallExecutionMaterial material,
        CancellationToken cancellationToken)
    {
        if (action is StartAndVerifyWindowsService or StartInteractiveAgentTask)
        {
            return await ApplyStartupActionAsync(action, cancellationToken).ConfigureAwait(false);
        }

        EnsureWindows();
        return action switch
        {
            RegisterProductUninstall product => ApplyProductRegistration(product),
            CreateDesktopShortcut shortcut => ApplyDesktopShortcut(shortcut),
            CreateProtectedDirectory directory => ApplyDirectory(directory),
            WriteProtectedFile file => await ApplyFileAsync(file, material, cancellationToken).ConfigureAwait(false),
            CreateWindowsService service => await CreateServiceRegistrationAsync(service, cancellationToken).ConfigureAwait(false),
            CreateInteractiveLogonTask task => await CreateTaskRegistrationAsync(task, cancellationToken).ConfigureAwait(false),
            CreateOwnedFirewallRule firewall => ApplyFirewall(firewall),
            VerifyInstallSecurity verify => await VerifyAsync(verify, cancellationToken).ConfigureAwait(false),
            _ => throw new InstallException("install_action_invalid"),
        };
    }

    public async Task RollbackAsync(
        AppliedInstallAction applied,
        CancellationToken cancellationToken)
    {
        if (RequiresOwnedResourceMutation(applied))
        {
            await _rollbackOwnershipVerifier
                .VerifyAsync(applied, cancellationToken)
                .ConfigureAwait(false);
        }

        switch (applied.Action)
        {
            case StartInteractiveAgentTask task when
                applied.RollbackState is AgentTaskStartStatus { StartedForActiveSession: true }:
                await StopStartedTaskAsync(task.Name, cancellationToken).ConfigureAwait(false);
                return;
            case StartInteractiveAgentTask:
                return;
            case StartAndVerifyWindowsService service:
                await StopStartedServiceAsync(service.Name, cancellationToken).ConfigureAwait(false);
                return;
        }

        EnsureWindows();
        switch (applied.Action)
        {
            case RegisterProductUninstall product when applied.Created:
                WindowsProductUninstallRegistry.Rollback(product.Registration);
                break;
            case CreateDesktopShortcut shortcut when applied.Created:
                WindowsDesktopShortcut.RemoveExact(
                    shortcut,
                    "install_state_uncertain",
                    new SecurityIdentifier(_signingUserSid));
                break;
            case CreateOwnedFirewallRule firewall when applied.Created:
                RollbackFirewall(firewall);
                break;
            case CreateInteractiveLogonTask task when applied.Created:
                await _ownedTaskRollback.ExecuteAsync(task.Name, cancellationToken).ConfigureAwait(false);
                break;
            case CreateWindowsService service when applied.Created:
                await _ownedServiceRollback.ExecuteAsync(service.Name, cancellationToken).ConfigureAwait(false);
                break;
            case WriteProtectedFile file when applied.Created:
                if (File.Exists(file.Path) && !WindowsPathSafety.IsReparse(file.Path))
                {
                    File.Delete(file.Path);
                }
                break;
            case WriteProtectedFile file when applied.RollbackState is ExistingFileState previous:
                RestoreFile(file.Path, previous);
                break;
            case CreateProtectedDirectory directory when applied.Created:
                if (Directory.Exists(directory.Path) &&
                    !WindowsPathSafety.IsReparse(directory.Path) &&
                    !Directory.EnumerateFileSystemEntries(directory.Path).Any())
                {
                    Directory.Delete(directory.Path);
                }
                break;
            case CreateProtectedDirectory directory when applied.RollbackState is byte[] previousAcl:
                RestoreDirectoryAcl(directory.Path, previousAcl);
                break;
        }
    }

    private async Task StopStartedTaskAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            await _startupRuntime.StopTaskAsync(name, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    private async Task StopStartedServiceAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            await _startupRuntime.StopServiceAsync(name, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    private static void RollbackFirewall(CreateOwnedFirewallRule firewall)
    {
        try
        {
            WindowsFirewall.RemoveOwned(firewall.Name, firewall.OwnerMarker, firewall.TcpPort);
            WindowsFirewall.VerifyMissing(firewall.Name);
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    private static bool RequiresOwnedResourceMutation(AppliedInstallAction applied) =>
        applied.Action switch
        {
            StartInteractiveAgentTask =>
                applied.RollbackState is AgentTaskStartStatus { StartedForActiveSession: true },
            StartAndVerifyWindowsService => true,
            CreateOwnedFirewallRule or CreateInteractiveLogonTask or CreateWindowsService => applied.Created,
            _ => false,
        };

    private async Task<AppliedInstallAction> ApplyStartupActionAsync(
        InstallAction action,
        CancellationToken cancellationToken)
    {
        switch (action)
        {
            case StartAndVerifyWindowsService service:
                await _startupRuntime
                    .StartAndVerifyServiceAsync(service.Name, cancellationToken)
                    .ConfigureAwait(false);
                return new AppliedInstallAction(service, Created: false, RollbackState: null);
            case StartInteractiveAgentTask task:
                if (!_startupRuntime.HasInteractiveSession(task.SigningUserSid))
                {
                    return new AppliedInstallAction(
                        task,
                        Created: false,
                        new AgentTaskStartStatus(
                            StartedForActiveSession: false,
                            ActivationRequired: false));
                }

                var otpConfigured = _startupRuntime.IsOtpConfiguredForSigningUser(
                    task.OtpPath,
                    task.SigningUserSid);
                await _startupRuntime
                    .StartAndVerifyTaskAsync(
                        task.Name,
                        requireRunning: otpConfigured,
                        cancellationToken)
                    .ConfigureAwait(false);
                return new AppliedInstallAction(
                    task,
                    Created: false,
                    new AgentTaskStartStatus(
                        StartedForActiveSession: true,
                        ActivationRequired: !otpConfigured));
            default:
                throw new InstallException("install_action_invalid");
        }
    }

    private static AppliedInstallAction ApplyProductRegistration(RegisterProductUninstall action)
    {
        WindowsProductUninstallRegistry.Create(action.Registration);
        return new AppliedInstallAction(action, Created: true, RollbackState: null);
    }

    private AppliedInstallAction ApplyDesktopShortcut(CreateDesktopShortcut action)
    {
        WindowsDesktopShortcut.CreateExact(
            action,
            new SecurityIdentifier(_signingUserSid));
        return new AppliedInstallAction(action, Created: true, RollbackState: null);
    }

    private AppliedInstallAction ApplyDirectory(CreateProtectedDirectory action)
    {
        var signingUser = new SecurityIdentifier(_signingUserSid);
        if (WindowsPathSafety.EntryExists(action.Path) &&
            (!Directory.Exists(action.Path) || WindowsPathSafety.IsReparse(action.Path)))
        {
            throw new InstallException("install_path_invalid");
        }

        var created = !Directory.Exists(action.Path);
        byte[]? previousAcl = null;
        if (created)
        {
            Directory.CreateDirectory(action.Path);
        }
        else
        {
            previousAcl = new DirectoryInfo(action.Path).GetAccessControl().GetSecurityDescriptorBinaryForm();
        }

        try
        {
            WindowsInstallAcl.ApplyDirectory(action.Path, action.Acl, signingUser);
            return new AppliedInstallAction(action, created, previousAcl);
        }
        catch
        {
            if (!created && previousAcl is not null && Directory.Exists(action.Path))
            {
                RestoreDirectoryAcl(action.Path, previousAcl);
            }
            else if (created && Directory.Exists(action.Path) && !Directory.EnumerateFileSystemEntries(action.Path).Any())
            {
                Directory.Delete(action.Path);
            }

            throw;
        }
    }

    private async Task<AppliedInstallAction> ApplyFileAsync(
        WriteProtectedFile action,
        InstallExecutionMaterial material,
        CancellationToken cancellationToken)
    {
        var signingUser = new SecurityIdentifier(_signingUserSid);
        if (WindowsPathSafety.EntryExists(action.Path) &&
            (!File.Exists(action.Path) || WindowsPathSafety.IsReparse(action.Path)))
        {
            throw new InstallException("install_path_invalid");
        }

        var parent = Path.GetDirectoryName(action.Path) ?? throw new InstallException("install_path_invalid");
        if (!Directory.Exists(parent) || WindowsPathSafety.IsReparse(parent))
        {
            throw new InstallException("install_path_invalid");
        }

        var exists = File.Exists(action.Path);
        ExistingFileState? previous = null;
        if (exists)
        {
            WindowsInstallAcl.VerifyFile(action.Path, action.Acl, signingUser);
            if (action.Content == InstallContent.Empty)
            {
                return new AppliedInstallAction(action, Created: false, RollbackState: null);
            }

            var fileInfo = new FileInfo(action.Path);
            if (fileInfo.Length > 1024 * 1024)
            {
                throw new InstallException("install_resource_invalid");
            }

            previous = new ExistingFileState(
                await File.ReadAllBytesAsync(action.Path, cancellationToken).ConfigureAwait(false),
                fileInfo.GetAccessControl().GetSecurityDescriptorBinaryForm());
        }

        var temporary = Path.Combine(parent, $".{Path.GetFileName(action.Path)}.{Guid.NewGuid():N}.tmp");
        var moved = false;
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(material.GetFile(action.Content), cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            WindowsInstallAcl.ApplyFile(temporary, action.Acl, signingUser);
            File.Move(temporary, action.Path, overwrite: exists);
            moved = true;
            WindowsInstallAcl.VerifyFile(action.Path, action.Acl, signingUser);
            return new AppliedInstallAction(action, Created: !exists, RollbackState: previous);
        }
        catch
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }

            if (moved && previous is not null)
            {
                RestoreFile(action.Path, previous);
            }
            else if (moved && File.Exists(action.Path) && !WindowsPathSafety.IsReparse(action.Path))
            {
                File.Delete(action.Path);
            }

            throw;
        }
    }

    internal async Task<AppliedInstallAction> CreateServiceRegistrationAsync(
        CreateWindowsService action,
        CancellationToken cancellationToken)
    {
        if (_resourceLookup.ServiceExists(action.Name))
        {
            throw new InstallException("install_resource_exists");
        }

        var imagePath = WindowsCommandLine.Quote(action.ExecutablePath) + " service";
        try
        {
            await _runner.RunCheckedAsync(
                "sc.exe",
                [
                    "create", action.Name,
                    "binPath=", imagePath,
                    "obj=", action.Account,
                    "start=", action.AutomaticDelayedStart ? "delayed-auto" : "auto",
                    "DisplayName=", action.OwnerMarker,
                ],
                "service_registration_failed",
                cancellationToken).ConfigureAwait(false);
            _resourceLookup.MarkServiceOwner(action);
            await _runner.RunCheckedAsync(
                "sc.exe",
                ["config", action.Name, "DisplayName=", action.Name],
                "service_registration_failed",
                cancellationToken).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "sc.exe",
                ["failure", action.Name, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000"],
                "service_registration_failed",
                cancellationToken).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "sc.exe",
                ["failureflag", action.Name, "1"],
                "service_registration_failed",
                cancellationToken).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "sc.exe",
                ["description", action.Name, action.OwnerMarker],
                "service_registration_failed",
                cancellationToken).ConfigureAwait(false);
            await WindowsServiceVerification.VerifyAsync(
                action,
                _recoveryInspector,
                cancellationToken).ConfigureAwait(false);
            return new AppliedInstallAction(action, Created: true, RollbackState: null);
        }
        catch (Exception original)
        {
            if (ReconcileServiceOwnership(action))
            {
                try
                {
                    await _ownedServiceRollback
                        .ExecuteAsync(action.Name, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                    throw new InstallException("install_state_uncertain");
                }
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }
    }

    internal async Task<AppliedInstallAction> CreateTaskRegistrationAsync(
        CreateInteractiveLogonTask action,
        CancellationToken cancellationToken)
    {
        if (_resourceLookup.TaskExists(action.Name))
        {
            if (_resourceLookup.TaskMatchesOwner(action))
            {
                return new AppliedInstallAction(action, Created: false, RollbackState: null);
            }

            throw new InstallException("install_resource_exists");
        }

        var xmlPath = Path.Combine(Path.GetTempPath(), $"SimplySignAuto-task-{Guid.NewGuid():N}.xml");
        try
        {
            await File.WriteAllTextAsync(
                xmlPath,
                WindowsTaskXml.Create(action),
                new UTF8Encoding(false),
                cancellationToken).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Create", "/TN", action.Name, "/XML", xmlPath],
                "task_registration_failed",
                cancellationToken).ConfigureAwait(false);
            await WindowsTaskXml.VerifyRegisteredAsync(
                action,
                _runner,
                cancellationToken).ConfigureAwait(false);
            return new AppliedInstallAction(action, Created: true, RollbackState: null);
        }
        catch (Exception original)
        {
            if (ReconcileTaskOwnership(action))
            {
                try
                {
                    await _ownedTaskRollback
                        .ExecuteAsync(action.Name, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                    throw new InstallException("install_state_uncertain");
                }
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }
        finally
        {
            if (File.Exists(xmlPath))
            {
                File.Delete(xmlPath);
            }
        }
    }

    private bool ReconcileServiceOwnership(CreateWindowsService action)
    {
        try
        {
            return _resourceLookup.ServiceMatchesOwner(action);
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    private bool ReconcileTaskOwnership(CreateInteractiveLogonTask action)
    {
        try
        {
            return _resourceLookup.TaskMatchesOwner(action);
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    private static AppliedInstallAction ApplyFirewall(CreateOwnedFirewallRule action)
    {
        WindowsFirewall.Create(action.Name, action.OwnerMarker, action.TcpPort);
        return new AppliedInstallAction(action, Created: true, RollbackState: null);
    }

    private async Task<AppliedInstallAction> VerifyAsync(
        VerifyInstallSecurity action,
        CancellationToken cancellationToken)
    {
        var signingUser = new SecurityIdentifier(_signingUserSid);
        try
        {
            WindowsInstallAcl.VerifyDirectory(action.Paths.DataRoot, InstallAclProfile.AdministratorsOnly, signingUser);
            WindowsInstallAcl.VerifyDirectory(action.Paths.JobsRoot, InstallAclProfile.SigningUserModify, signingUser);
            WindowsInstallAcl.VerifyDirectory(action.Paths.ToolsRoot, InstallAclProfile.SigningUserRead, signingUser);
            WindowsInstallAcl.VerifyDirectory(action.Paths.LogsRoot, InstallAclProfile.AdministratorsOnly, signingUser);
            WindowsInstallAcl.VerifyDirectory(action.Paths.SpoolRoot, InstallAclProfile.SigningUserRead, signingUser);
            WindowsInstallAcl.VerifyDirectory(action.Paths.AgentDirectory, InstallAclProfile.SigningUserData, signingUser);
            WindowsInstallAcl.VerifyFile(action.Paths.ServiceConfigurationPath, InstallAclProfile.AdministratorsOnly, signingUser);
            WindowsInstallAcl.VerifyFile(action.Paths.JobsDatabasePath, InstallAclProfile.AdministratorsOnly, signingUser);
            WindowsInstallAcl.VerifyFile(action.Paths.AgentConfigurationPath, InstallAclProfile.SigningUserRead, signingUser);
            WindowsInstallAcl.VerifyFile(action.Paths.InstallTokenPath, InstallAclProfile.AdministratorsOnly, signingUser);
            _ = await new ServiceConfigurationLoader(action.Paths.ServiceConfigurationPath)
                .LoadAsync(cancellationToken).ConfigureAwait(false);
            _ = await new AgentConfigurationLoader(action.Paths.AgentConfigurationPath)
                .LoadAsync(cancellationToken).ConfigureAwait(false);
            if (action.FirewallExpected)
            {
                WindowsFirewall.Verify(
                    "SimplySignAuto API",
                    action.OwnerMarker,
                    action.FirewallPort,
                    allowConfiguredPort: true);
            }

            return new AppliedInstallAction(action, Created: false, RollbackState: null);
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("acl_verification_failed");
        }
    }

    private static void RestoreDirectoryAcl(string path, byte[] binary)
    {
        if (!Directory.Exists(path) || WindowsPathSafety.IsReparse(path))
        {
            return;
        }

        var security = new DirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(binary);
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void RestoreFile(string path, ExistingFileState previous)
    {
        if (WindowsPathSafety.EntryExists(path) &&
            (!File.Exists(path) || WindowsPathSafety.IsReparse(path)))
        {
            throw new InstallException("install_path_invalid");
        }

        var parent = Path.GetDirectoryName(path) ?? throw new InstallException("install_path_invalid");
        var temporary = Path.Combine(parent, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.rollback");
        File.WriteAllBytes(temporary, previous.Content);
        var security = new FileSecurity();
        security.SetSecurityDescriptorBinaryForm(previous.Acl);
        new FileInfo(temporary).SetAccessControl(security);
        File.Move(temporary, path, overwrite: true);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }
    }
}

internal sealed record ExistingFileState(byte[] Content, byte[] Acl);

internal static class WindowsExecutableSecurity
{
    private const string LocalSystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string TrustedInstallerSid =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    private static readonly HashSet<string> TrustedWriters = new(StringComparer.Ordinal)
    {
        LocalSystemSid,
        AdministratorsSid,
        TrustedInstallerSid,
    };

    public static void Verify(string executablePath, string signingUserSid)
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!IsRequiredLocation(executablePath, programFiles) ||
            !string.Equals(
                Path.GetFullPath(executablePath),
                executablePath,
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(executablePath))
        {
            throw new InstallException("install_executable_insecure");
        }

        VerifyEntry(WindowsNoFollowSecurity.ReadFile(executablePath), signingUserSid, requireReadExecute: true);
        var directory = Path.GetDirectoryName(executablePath)
            ?? throw new InstallException("install_executable_insecure");
        VerifyEntry(WindowsNoFollowSecurity.ReadDirectory(directory), signingUserSid, requireReadExecute: true);
        directory = Directory.GetParent(directory)?.FullName;
        if (directory is not null)
        {
            VerifyEntry(WindowsNoFollowSecurity.ReadDirectory(directory), signingUserSid, requireReadExecute: true);
            directory = Directory.GetParent(directory)?.FullName;
        }

        while (directory is not null)
        {
            VerifyTraversal(WindowsNoFollowSecurity.ReadDirectory(directory), signingUserSid);
            directory = Directory.GetParent(directory)?.FullName;
        }
    }

    internal static bool IsRequiredLocation(string executablePath, string programFiles) =>
        Path.IsPathFullyQualified(executablePath) &&
        Path.IsPathFullyQualified(programFiles) &&
        string.Equals(
            Path.GetDirectoryName(Path.GetFullPath(executablePath)),
            Path.GetFullPath(Path.Combine(programFiles, "SimplySignAuto")),
            StringComparison.OrdinalIgnoreCase) &&
        string.Equals(
            Path.GetFileName(executablePath),
            "SimplySignAuto.exe",
            StringComparison.OrdinalIgnoreCase);

    internal static void VerifyForSetup(string executablePath)
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!IsRequiredLocation(executablePath, programFiles))
        {
            throw new InstallException("install_executable_insecure");
        }

        Verify(executablePath, string.Empty);
    }

    internal static void VerifyEntry(
        WindowsNoFollowSecuritySnapshot snapshot,
        string signingUserSid,
        bool requireReadExecute)
    {
        if ((snapshot.Attributes & FileAttributes.ReparsePoint) != 0 ||
            snapshot.Security.Owner is not { Value: var owner } ||
            !IsTrustedWriter(owner) ||
            snapshot.Security.DiscretionaryAcl is not { } dacl)
        {
            throw new InstallException("install_executable_insecure");
        }

        var signingReadExecute = false;
        foreach (GenericAce ace in dacl)
        {
            if (ace is not QualifiedAce qualified ||
                qualified.AceFlags.HasFlag(AceFlags.InheritOnly) ||
                qualified.AceQualifier != AceQualifier.AccessAllowed)
            {
                continue;
            }

            var identity = qualified.SecurityIdentifier.Value;
            const int dangerous = (int)(
                FileSystemRights.WriteData |
                FileSystemRights.AppendData |
                FileSystemRights.CreateFiles |
                FileSystemRights.CreateDirectories |
                FileSystemRights.Delete |
                FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.ChangePermissions |
                FileSystemRights.TakeOwnership);
            if ((qualified.AccessMask & dangerous) != 0 && !IsTrustedWriter(identity))
            {
                throw new InstallException("install_executable_insecure");
            }

            var readExecute = (int)(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize);
            if ((string.Equals(identity, signingUserSid, StringComparison.Ordinal) ||
                    string.Equals(identity, "S-1-5-32-545", StringComparison.Ordinal) ||
                    string.Equals(identity, "S-1-1-0", StringComparison.Ordinal) ||
                    string.Equals(identity, "S-1-5-11", StringComparison.Ordinal)) &&
                (qualified.AccessMask & readExecute) == readExecute)
            {
                signingReadExecute = true;
            }
        }

        if (requireReadExecute && !signingReadExecute)
        {
            throw new InstallException("install_executable_insecure");
        }
    }

    private static void VerifyTraversal(
        WindowsNoFollowSecuritySnapshot snapshot,
        string signingUserSid)
    {
        if ((snapshot.Attributes & FileAttributes.ReparsePoint) != 0 ||
            snapshot.Security.DiscretionaryAcl is not { } dacl)
        {
            throw new InstallException("install_executable_insecure");
        }

        var allowed = false;
        foreach (GenericAce ace in dacl)
        {
            if (ace is QualifiedAce
                {
                    AceQualifier: AceQualifier.AccessAllowed,
                    SecurityIdentifier.Value: var identity,
                } qualified &&
                !qualified.AceFlags.HasFlag(AceFlags.InheritOnly) &&
                (string.Equals(identity, signingUserSid, StringComparison.Ordinal) ||
                    string.Equals(identity, "S-1-5-32-545", StringComparison.Ordinal) ||
                    string.Equals(identity, "S-1-1-0", StringComparison.Ordinal) ||
                    string.Equals(identity, "S-1-5-11", StringComparison.Ordinal)) &&
                (qualified.AccessMask & (int)FileSystemRights.ReadAndExecute) ==
                    (int)FileSystemRights.ReadAndExecute)
            {
                allowed = true;
            }
        }

        if (!allowed)
        {
            throw new InstallException("install_executable_insecure");
        }
    }

    private static bool IsTrustedWriter(string identity)
    {
        if (TrustedWriters.Contains(identity))
        {
            return true;
        }

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var current = WindowsIdentity.GetCurrent();
        return string.Equals(current.User?.Value, identity, StringComparison.Ordinal) &&
            new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

internal static class WindowsInstallAcl
{
    private const string LocalSystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private static SecurityIdentifier LocalSystem => new(WellKnownSidType.LocalSystemSid, null);
    private static SecurityIdentifier Administrators => new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static bool IsExpectedOwner(string? ownerSid) =>
        string.Equals(ownerSid, AdministratorsSid, StringComparison.Ordinal) ||
        string.Equals(ownerSid, LocalSystemSid, StringComparison.Ordinal);

    public static void ApplyDirectory(string path, InstallAclProfile profile, SecurityIdentifier signingUser)
    {
        var expected = Rules(profile, signingUser, directory: true);
        var security = CreateDirectorySecurity(profile, signingUser);

        new DirectoryInfo(path).SetAccessControl(security);
        Verify(new DirectoryInfo(path).GetAccessControl(), expected);
    }

    public static void ApplyFile(string path, InstallAclProfile profile, SecurityIdentifier signingUser)
    {
        var expected = Rules(profile, signingUser, directory: false);
        var security = CreateFileSecurity(profile, signingUser);

        new FileInfo(path).SetAccessControl(security);
        Verify(new FileInfo(path).GetAccessControl(), expected);
    }

    public static void VerifyDirectory(string path, InstallAclProfile profile, SecurityIdentifier signingUser) =>
        Verify(new DirectoryInfo(path).GetAccessControl(), Rules(profile, signingUser, directory: true));

    public static void VerifyFile(string path, InstallAclProfile profile, SecurityIdentifier signingUser) =>
        Verify(new FileInfo(path).GetAccessControl(), Rules(profile, signingUser, directory: false));

    internal static DirectorySecurity CreateDirectorySecurity(
        InstallAclProfile profile,
        SecurityIdentifier signingUser)
    {
        var security = new DirectorySecurity();
        PopulateSecurity(security, Rules(profile, signingUser, directory: true));
        return security;
    }

    internal static FileSecurity CreateFileSecurity(
        InstallAclProfile profile,
        SecurityIdentifier signingUser)
    {
        var security = new FileSecurity();
        PopulateSecurity(security, Rules(profile, signingUser, directory: false));
        return security;
    }

    private static void PopulateSecurity(
        FileSystemSecurity security,
        IReadOnlyList<FileSystemAccessRule> rules)
    {
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        foreach (var rule in rules)
        {
            security.AddAccessRule(rule);
        }
    }

    private static IReadOnlyList<FileSystemAccessRule> Rules(
        InstallAclProfile profile,
        SecurityIdentifier signingUser,
        bool directory)
    {
        var inheritance = directory && profile != InstallAclProfile.SigningUserRead
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        var rules = new List<FileSystemAccessRule>
        {
            Rule(LocalSystem, FileSystemRights.FullControl, inheritance),
            Rule(Administrators, FileSystemRights.FullControl, inheritance),
        };
        if (profile == InstallAclProfile.SigningUserModify)
        {
            rules.Add(Rule(signingUser, FileSystemRights.Modify, inheritance));
        }
        else if (profile == InstallAclProfile.SigningUserRead)
        {
            rules.Add(Rule(signingUser, FileSystemRights.ReadAndExecute, inheritance));
        }
        else if (profile == InstallAclProfile.SigningUserData)
        {
            rules.Add(Rule(
                signingUser,
                FileSystemRights.ReadAndExecute | FileSystemRights.Write | FileSystemRights.Synchronize,
                inheritance));
        }

        return rules;
    }

    private static FileSystemAccessRule Rule(
        SecurityIdentifier identity,
        FileSystemRights rights,
        InheritanceFlags inheritance) => new(
            identity,
            rights,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow);

    private static void Verify(FileSystemSecurity security, IReadOnlyList<FileSystemAccessRule> expected)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var actual = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();
        if (!security.AreAccessRulesProtected ||
            !IsExpectedOwner(owner?.Value) ||
            actual.Length != expected.Count ||
            expected.Any(wanted => !actual.Any(rule => Same(rule, wanted))))
        {
            throw new InstallException("acl_verification_failed");
        }
    }

    private static bool Same(FileSystemAccessRule left, FileSystemAccessRule right) =>
        left.IdentityReference.Equals(right.IdentityReference) &&
        left.FileSystemRights == right.FileSystemRights &&
        left.AccessControlType == right.AccessControlType &&
        left.InheritanceFlags == right.InheritanceFlags &&
        left.PropagationFlags == right.PropagationFlags &&
        !left.IsInherited;
}

internal sealed record WindowsProcessResult(int ExitCode, string StandardOutput);

internal interface IWindowsCommandRunner
{
    Task<WindowsProcessResult> RunCheckedAsync(
        string executable,
        IReadOnlyList<string> arguments,
        string errorCode,
        CancellationToken cancellationToken);

    Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken);
}

internal sealed class DefaultWindowsCommandRunner : IWindowsCommandRunner
{
    public Task<WindowsProcessResult> RunCheckedAsync(
        string executable,
        IReadOnlyList<string> arguments,
        string errorCode,
        CancellationToken cancellationToken) =>
        WindowsProcess.RunCheckedAsync(executable, arguments, errorCode, cancellationToken);

    public Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken) =>
        WindowsProcess.RunIgnoreExitCodeAsync(executable, arguments, cancellationToken);
}

internal interface IWindowsInstallResourceLookup
{
    bool ServiceExists(string name);

    bool TaskExists(string name);

    void MarkServiceOwner(CreateWindowsService action);

    bool ServiceMatchesOwner(CreateWindowsService action);

    bool TaskMatchesOwner(CreateInteractiveLogonTask action);
}

internal sealed class WindowsInstallResourceLookup : IWindowsInstallResourceLookup
{
    internal const string InstallOwnerValueName = "SimplySignAutoInstallOwner";

    public bool ServiceExists(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{name}",
                writable: false);
            return key is not null;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or SystemException)
        {
            throw new InstallException("resource_preflight_failed");
        }
    }

    public bool TaskExists(string name)
    {
        dynamic? service = null;
        dynamic? folder = null;
        dynamic? task = null;
        try
        {
            service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
            service.Connect();
            folder = service.GetFolder("\\");
            try
            {
                task = folder.GetTask(name);
                return true;
            }
            catch (Exception error) when (IsTaskNotFound(error))
            {
                return false;
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("resource_preflight_failed");
        }
        finally
        {
            ReleaseCom(task);
            ReleaseCom(folder);
            ReleaseCom(service);
        }
    }

    public void MarkServiceOwner(CreateWindowsService action)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{action.Name}",
                writable: true) ?? throw new InstallException("install_state_uncertain");
            if (!ServiceBaseMatches(key, action) ||
                !string.Equals(
                    key.GetValue("DisplayName") as string,
                    action.OwnerMarker,
                    StringComparison.Ordinal))
            {
                throw new InstallException("install_state_uncertain");
            }

            key.SetValue(InstallOwnerValueName, action.OwnerMarker, RegistryValueKind.String);
            if (!string.Equals(
                    key.GetValue(InstallOwnerValueName) as string,
                    action.OwnerMarker,
                    StringComparison.Ordinal))
            {
                throw new InstallException("install_state_uncertain");
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or SystemException)
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    public bool ServiceMatchesOwner(CreateWindowsService action)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{action.Name}",
                writable: false);
            return key is not null &&
                ServiceBaseMatches(key, action) &&
                (string.Equals(
                    key.GetValue("DisplayName") as string,
                    action.OwnerMarker,
                    StringComparison.Ordinal) ||
                string.Equals(
                    key.GetValue(InstallOwnerValueName) as string,
                    action.OwnerMarker,
                    StringComparison.Ordinal));
        }
        catch (Exception error) when (error is UnauthorizedAccessException or SystemException)
        {
            throw new InstallException("resource_preflight_failed");
        }
    }

    private static bool ServiceBaseMatches(
        RegistryKey key,
        CreateWindowsService action)
    {
        var expectedImage = WindowsCommandLine.Quote(action.ExecutablePath) + " service";
        var delayed = key.GetValue("DelayedAutoStart") as int?;
        return string.Equals(key.GetValue("ImagePath") as string, expectedImage, StringComparison.Ordinal) &&
            string.Equals(key.GetValue("ObjectName") as string, action.Account, StringComparison.OrdinalIgnoreCase) &&
            key.GetValue("Start") is 2 &&
            (action.AutomaticDelayedStart ? delayed is 1 : delayed is null or 0);
    }

    public bool TaskMatchesOwner(CreateInteractiveLogonTask action)
    {
        dynamic? service = null;
        dynamic? folder = null;
        dynamic? task = null;
        try
        {
            service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
            service.Connect();
            folder = service.GetFolder("\\");
            try
            {
                task = folder.GetTask(action.Name);
                return WindowsTaskXml.IsOwned((string)task.Xml, action);
            }
            catch (Exception error) when (IsTaskNotFound(error))
            {
                return false;
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("resource_preflight_failed");
        }
        finally
        {
            ReleaseCom(task);
            ReleaseCom(folder);
            ReleaseCom(service);
        }
    }

    private static void ReleaseCom(object? value)
    {
        if (value is not null && System.Runtime.InteropServices.Marshal.IsComObject(value))
        {
            _ = System.Runtime.InteropServices.Marshal.FinalReleaseComObject(value);
        }
    }

    internal static bool IsTaskNotFound(Exception error) =>
        error.HResult is unchecked((int)0x80070002) or unchecked((int)0x8004130F);
}

internal static class WindowsProductUninstallRegistry
{
    private const string InstallOwnerPrefix = "SimplySignAuto/v1/";
    internal const string KeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SimplySignAuto";

    public static void Create(ProductUninstallRegistration registration)
    {
        ValidateRegistration(registration);
        try
        {
            using (var existing = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false))
            {
                if (existing is not null)
                {
                    throw new InstallException("resource_preflight_failed");
                }
            }

            using var key = Registry.LocalMachine.CreateSubKey(KeyPath, writable: true)
                ?? throw new InstallException("product_registration_failed");
            if (key.GetValueNames().Length != 0 || key.GetSubKeyNames().Length != 0)
            {
                throw new InstallException("resource_preflight_failed");
            }

            key.SetValue(
                WindowsInstallResourceLookup.InstallOwnerValueName,
                registration.OwnerMarker,
                RegistryValueKind.String);
            foreach (var expected in ExpectedValues(registration))
            {
                if (string.Equals(
                        expected.Key,
                        WindowsInstallResourceLookup.InstallOwnerValueName,
                        StringComparison.Ordinal))
                {
                    continue;
                }

                key.SetValue(expected.Key, expected.Value, RegistryValueKind.String);
            }

            VerifyKey(key, registration, "install_state_uncertain");
        }
        catch (InstallException error) when (error.Code == "resource_preflight_failed")
        {
            throw;
        }
        catch
        {
            if (!TryDeletePartialOwnedRegistration(registration))
            {
                throw new InstallException("install_state_uncertain");
            }

            throw new InstallException("product_registration_failed");
        }
    }

    public static void Verify(ProductUninstallRegistration registration, string errorCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
        ValidateRegistration(registration);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false)
                ?? throw new InstallException(errorCode);
            VerifyKey(key, registration, errorCode);
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or SystemException)
        {
            throw new InstallException(errorCode);
        }
    }

    public static void Rollback(ProductUninstallRegistration registration) =>
        DeleteExact(registration, "install_state_uncertain");

    public static void Remove(ProductUninstallRegistration registration) =>
        DeleteExact(registration, "uninstall_state_uncertain");

    private static void DeleteExact(ProductUninstallRegistration registration, string errorCode)
    {
        try
        {
            Verify(registration, errorCode);
            Registry.LocalMachine.DeleteSubKey(KeyPath, throwOnMissingSubKey: true);
            using var remaining = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false);
            if (remaining is not null)
            {
                throw new InstallException(errorCode);
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or SystemException)
        {
            throw new InstallException(errorCode);
        }
    }

    private static void VerifyKey(
        RegistryKey key,
        ProductUninstallRegistration registration,
        string errorCode)
    {
        var expected = ExpectedValues(registration);
        if (key.GetSubKeyNames().Length != 0 ||
            !key.GetValueNames().Order(StringComparer.Ordinal).SequenceEqual(
                expected.Keys.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InstallException(errorCode);
        }

        foreach (var pair in expected)
        {
            if (key.GetValueKind(pair.Key) != RegistryValueKind.String ||
                !string.Equals(
                    key.GetValue(
                        pair.Key,
                        null,
                        RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                    pair.Value,
                    StringComparison.Ordinal))
            {
                throw new InstallException(errorCode);
            }
        }
    }

    private static IReadOnlyDictionary<string, string> ExpectedValues(
        ProductUninstallRegistration registration) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["DisplayName"] = registration.DisplayName,
            ["DisplayVersion"] = registration.DisplayVersion,
            ["Publisher"] = registration.Publisher,
            ["InstallLocation"] = registration.InstallLocation,
            ["DisplayIcon"] = registration.DisplayIcon,
            ["UninstallString"] = registration.UninstallString,
            [WindowsInstallResourceLookup.InstallOwnerValueName] = registration.OwnerMarker,
        };

    private static bool TryDeletePartialOwnedRegistration(
        ProductUninstallRegistration registration)
    {
        try
        {
            using (var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false))
            {
                if (key is null)
                {
                    return true;
                }

                if (key.GetSubKeyNames().Length != 0)
                {
                    return false;
                }

                var expected = ExpectedValues(registration);
                var names = key.GetValueNames();
                if (names.Length != 0 &&
                    (!names.Contains(
                        WindowsInstallResourceLookup.InstallOwnerValueName,
                        StringComparer.Ordinal) ||
                    names.Any(name =>
                        !expected.TryGetValue(name, out var expectedValue) ||
                        key.GetValueKind(name) != RegistryValueKind.String ||
                        !string.Equals(
                            key.GetValue(
                                name,
                                null,
                                RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                            expectedValue,
                            StringComparison.Ordinal))))
                {
                    return false;
                }
            }

            Registry.LocalMachine.DeleteSubKey(KeyPath, throwOnMissingSubKey: false);
            using var remaining = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false);
            return remaining is null;
        }
        catch
        {
            return false;
        }
    }

    private static void ValidateRegistration(ProductUninstallRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        if (!Path.IsPathFullyQualified(registration.ExecutablePath) ||
            !string.Equals(
                Path.GetFullPath(registration.ExecutablePath),
                registration.ExecutablePath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(registration.DisplayName, "SimplySignAuto", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(registration.DisplayVersion) ||
            !string.Equals(registration.Publisher, "SimplySignAuto", StringComparison.Ordinal) ||
            !string.Equals(
                Path.GetDirectoryName(registration.ExecutablePath),
                registration.InstallLocation,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                registration.DisplayIcon,
                $"\"{registration.ExecutablePath}\",0",
                StringComparison.Ordinal) ||
            !string.Equals(
                registration.UninstallString,
                $"\"{registration.ExecutablePath}\" uninstall",
                StringComparison.Ordinal) ||
            !registration.OwnerMarker.StartsWith(InstallOwnerPrefix, StringComparison.Ordinal) ||
            !InstallOwnershipMarker.IsInstanceId(registration.OwnerMarker[InstallOwnerPrefix.Length..]))
        {
            throw new InstallException("install_arguments_invalid");
        }
    }
}

internal static class WindowsProcess
{
    public static async Task<WindowsProcessResult> RunCheckedAsync(
        string executable,
        IReadOnlyList<string> arguments,
        string errorCode,
        CancellationToken cancellationToken)
    {
        var result = await RunIgnoreExitCodeAsync(executable, arguments, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new InstallException(errorCode);
        }

        return result;
    }

    public static async Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken) => await RunIgnoreExitCodeAsync(
            executable,
            arguments,
            TimeSpan.FromSeconds(30),
            cancellationToken).ConfigureAwait(false);

    internal static async Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
        string executable,
        IReadOnlyList<string> arguments,
        TimeSpan timeoutDuration,
        CancellationToken cancellationToken)
    {
        if (timeoutDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeoutDuration));
        }

        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InstallException("windows_process_failed");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutDuration);
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            _ = await stderr.ConfigureAwait(false);
            return new WindowsProcessResult(process.ExitCode, await stdout.ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await KillJoinAndDrainAsync(process, stdout, stderr).ConfigureAwait(false);
            throw new InstallException("windows_process_timeout");
        }
        catch (OperationCanceledException)
        {
            await KillJoinAndDrainAsync(process, stdout, stderr).ConfigureAwait(false);
            throw;
        }
        catch
        {
            await KillJoinAndDrainAsync(process, stdout, stderr).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task KillJoinAndDrainAsync(
        Process process,
        Task<string> stdout,
        Task<string> stderr)
    {
        TryKill(process);
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
            await Task.WhenAll(stdout, stderr).WaitAsync(cleanup.Token).ConfigureAwait(false);
        }
        catch (Exception error) when (
            error is OperationCanceledException or InvalidOperationException or SystemException)
        {
            throw new InstallException("windows_process_termination_failed");
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception error) when (error is InvalidOperationException or SystemException)
        {
        }
    }
}

internal static class WindowsServiceVerification
{
    public static Task VerifyAsync(
        CreateWindowsService action,
        IWindowsServiceRecoveryInspector recoveryInspector,
        CancellationToken cancellationToken)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{action.Name}",
            writable: false) ?? throw new InstallException("service_registration_failed");
        var imagePath = key.GetValue("ImagePath") as string;
        var objectName = key.GetValue("ObjectName") as string;
        var start = key.GetValue("Start") as int?;
        var delayed = key.GetValue("DelayedAutoStart") as int?;
        var displayName = key.GetValue("DisplayName") as string;
        var description = key.GetValue("Description") as string;
        var installOwner = key.GetValue(WindowsInstallResourceLookup.InstallOwnerValueName) as string;
        var expectedImage = WindowsCommandLine.Quote(action.ExecutablePath) + " service";
        if (!string.Equals(imagePath, expectedImage, StringComparison.Ordinal) ||
            !string.Equals(objectName, action.Account, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(displayName, action.Name, StringComparison.Ordinal) ||
            !string.Equals(description, action.OwnerMarker, StringComparison.Ordinal) ||
            !string.Equals(installOwner, action.OwnerMarker, StringComparison.Ordinal) ||
            start != 2 ||
            (action.AutomaticDelayedStart ? delayed != 1 : delayed is not (null or 0)))
        {
            throw new InstallException("service_registration_failed");
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!WindowsServiceRecoveryContract.IsExact(
                recoveryInspector.Read(action.Name),
                action.RestartDelaysSeconds))
        {
            throw new InstallException("service_registration_failed");
        }

        return Task.CompletedTask;
    }
}

internal static class WindowsTaskXml
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static string Create(CreateInteractiveLogonTask action)
    {
        if (action.RestartIntervalSeconds is < 1 or > 3600 ||
            action.RestartCount is < 1 or > 10)
        {
            throw new InstallException("task_registration_failed");
        }

        return new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(Ns + "Task",
                new XAttribute("version", "1.4"),
                new XElement(
                    Ns + "RegistrationInfo",
                    new XElement(Ns + "Description", "SimplySignAuto/v1"),
                    new XElement(Ns + "Source", action.OwnerMarker)),
                new XElement(Ns + "Triggers",
                    new XElement(Ns + "LogonTrigger",
                        new XElement(Ns + "Enabled", "true"),
                        new XElement(Ns + "UserId", action.SigningUserSid))),
                new XElement(Ns + "Principals",
                    new XElement(Ns + "Principal",
                        new XAttribute("id", "Author"),
                        new XElement(Ns + "UserId", action.SigningUserSid),
                        new XElement(Ns + "LogonType", action.LogonType),
                        new XElement(Ns + "RunLevel", "HighestAvailable"))),
                new XElement(Ns + "Settings",
                    new XElement(Ns + "MultipleInstancesPolicy", "IgnoreNew"),
                    new XElement(Ns + "DisallowStartIfOnBatteries", "false"),
                    new XElement(Ns + "StopIfGoingOnBatteries", "false"),
                    new XElement(Ns + "RunOnlyIfNetworkAvailable", "true"),
                    new XElement(Ns + "Enabled", "true"),
                    new XElement(Ns + "ExecutionTimeLimit", "PT0S"),
                    new XElement(Ns + "RestartOnFailure",
                        new XElement(
                            Ns + "Interval",
                            System.Xml.XmlConvert.ToString(TimeSpan.FromSeconds(action.RestartIntervalSeconds))),
                        new XElement(
                            Ns + "Count",
                            action.RestartCount.ToString(System.Globalization.CultureInfo.InvariantCulture)))),
                new XElement(Ns + "Actions",
                    new XAttribute("Context", "Author"),
                    new XElement(Ns + "Exec",
                        new XElement(Ns + "Command", action.ExecutablePath),
                        new XElement(Ns + "Arguments", string.Join(' ', action.Arguments))))))
            .ToString(SaveOptions.DisableFormatting);
    }

    public static async Task VerifyRegisteredAsync(
        CreateInteractiveLogonTask action,
        IWindowsCommandRunner runner,
        CancellationToken cancellationToken)
    {
        var result = await runner.RunCheckedAsync(
            "schtasks.exe",
            ["/Query", "/TN", action.Name, "/XML"],
            "task_registration_failed",
            cancellationToken).ConfigureAwait(false);
        try
        {
            var document = XDocument.Parse(result.StandardOutput, LoadOptions.None);
            var root = document.Root ?? throw new InstallException("task_registration_failed");
            if (!Matches(
                    root,
                    action.SigningUserSid,
                    action.ExecutablePath,
                    action.OwnerMarker))
            {
                throw new InstallException("task_registration_failed");
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("task_registration_failed");
        }
    }

    public static bool IsOwned(
        string xml,
        string signingUserSid,
        string executablePath,
        string ownerMarker)
    {
        try
        {
            var root = XDocument.Parse(xml, LoadOptions.None).Root;
            if (root is null)
            {
                return false;
            }

            return Matches(
                root,
                signingUserSid,
                executablePath,
                ownerMarker);
        }
        catch
        {
            return false;
        }
    }

    public static bool IsOwned(string xml, CreateInteractiveLogonTask action) =>
        IsOwned(xml, action.SigningUserSid, action.ExecutablePath, action.OwnerMarker);

    private static bool Matches(
        XElement root,
        string signingUserSid,
        string executablePath,
        string ownerMarker)
    {
        var triggerContainers = root.Elements(Ns + "Triggers").ToArray();
        var principalContainers = root.Elements(Ns + "Principals").ToArray();
        var actionContainers = root.Elements(Ns + "Actions").ToArray();
        var registrationContainers = root.Elements(Ns + "RegistrationInfo").ToArray();
        var settingsContainers = root.Elements(Ns + "Settings").ToArray();
        if (triggerContainers.Length != 1 ||
            principalContainers.Length != 1 ||
            actionContainers.Length != 1 ||
            registrationContainers.Length != 1 ||
            settingsContainers.Length != 1)
        {
            return false;
        }

        var triggers = triggerContainers[0].Elements().ToArray();
        var principals = principalContainers[0].Elements().ToArray();
        var actions = actionContainers[0].Elements().ToArray();
        var registration = registrationContainers[0];
        var settings = settingsContainers[0];
        if (triggers.Length != 1 || triggers[0].Name != Ns + "LogonTrigger" ||
            principals.Length != 1 || principals[0].Name != Ns + "Principal" ||
            actions.Length != 1 || actions[0].Name != Ns + "Exec")
        {
            return false;
        }

        var restartPolicies = settings.Elements(Ns + "RestartOnFailure").ToArray();
        var triggerChildren = triggers[0].Elements().ToArray();
        var triggerEnabled = triggerChildren.Where(child => child.Name == Ns + "Enabled").ToArray();
        var settingsEnabled = settings.Elements(Ns + "Enabled").ToArray();
        return triggerChildren.All(child => child.Name == Ns + "Enabled" || child.Name == Ns + "UserId") &&
            triggerEnabled.Length <= 1 &&
            triggerChildren.Count(child => child.Name == Ns + "UserId") == 1 &&
            (triggerEnabled.Length == 0 || triggerEnabled[0].Value == "true") &&
            TriggerUserMatches(SingleValue(triggers[0], "UserId"), signingUserSid) &&
            principals[0].Attribute("id")?.Value == "Author" &&
            SingleValue(principals[0], "UserId") == signingUserSid &&
            SingleValue(principals[0], "LogonType") == "InteractiveToken" &&
            SingleValue(principals[0], "RunLevel") == "HighestAvailable" &&
            actionContainers[0].Attribute("Context")?.Value == "Author" &&
            SingleValue(actions[0], "Command") == executablePath &&
            SingleValue(actions[0], "Arguments") == "agent --background" &&
            SingleValue(registration, "Description") == "SimplySignAuto/v1" &&
            SingleValue(registration, "Source") == ownerMarker &&
            SingleValue(settings, "MultipleInstancesPolicy") == "IgnoreNew" &&
            SingleValue(settings, "DisallowStartIfOnBatteries") == "false" &&
            SingleValue(settings, "StopIfGoingOnBatteries") == "false" &&
            SingleValue(settings, "RunOnlyIfNetworkAvailable") == "true" &&
            settingsEnabled.Length <= 1 &&
            (settingsEnabled.Length == 0 || settingsEnabled[0].Value == "true") &&
            SingleValue(settings, "ExecutionTimeLimit") == "PT0S" &&
            restartPolicies.Length == 1 &&
            SingleValue(restartPolicies[0], "Interval") == "PT1M" &&
            SingleValue(restartPolicies[0], "Count") == "3";
    }

    private static bool TriggerUserMatches(string? observedUser, string signingUserSid)
    {
        if (string.Equals(observedUser, signingUserSid, StringComparison.Ordinal))
        {
            return true;
        }

        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(observedUser))
        {
            return false;
        }

        try
        {
            var translated = new NTAccount(observedUser).Translate(typeof(SecurityIdentifier));
            return translated is SecurityIdentifier sid &&
                string.Equals(sid.Value, signingUserSid, StringComparison.Ordinal);
        }
        catch (IdentityNotMappedException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string? SingleValue(XElement parent, string localName)
    {
        var values = parent.Elements(Ns + localName).ToArray();
        return values.Length == 1 ? values[0].Value : null;
    }
}

internal sealed record WindowsFirewallRuleSnapshot(
    string Name,
    string Description,
    string Grouping,
    int Protocol,
    string LocalPorts,
    int Direction,
    int Action,
    bool Enabled,
    int Profiles);

internal static class WindowsFirewallRuleContract
{
    public static WindowsFirewallRuleSnapshot Expected(
        string name,
        string ownerMarker,
        int port) => new(
        name,
        ownerMarker,
        ownerMarker,
        6,
        port.ToString(System.Globalization.CultureInfo.InvariantCulture),
        1,
        1,
        true,
        int.MaxValue);

    public static bool IsExact(
        WindowsFirewallRuleSnapshot rule,
        string name,
        string ownerMarker,
        int port) => IsExact(rule, Expected(name, ownerMarker, port));

    public static bool IsExact(
        WindowsFirewallRuleSnapshot rule,
        WindowsFirewallRuleSnapshot expected) =>
        string.Equals(rule.Name, expected.Name, StringComparison.Ordinal) &&
        string.Equals(rule.Description, expected.Description, StringComparison.Ordinal) &&
        string.Equals(rule.Grouping, expected.Grouping, StringComparison.Ordinal) &&
        rule.Protocol == expected.Protocol &&
        string.Equals(rule.LocalPorts, expected.LocalPorts, StringComparison.Ordinal) &&
        rule.Direction == expected.Direction &&
        rule.Action == expected.Action &&
        rule.Enabled == expected.Enabled &&
        rule.Profiles == expected.Profiles;
}

internal interface IWindowsFirewallPolicy
{
    WindowsFirewallRuleSnapshot? FindUnique(string name);

    void Add(WindowsFirewallRuleSnapshot rule);

    void RemoveExact(WindowsFirewallRuleSnapshot expected);
}

internal sealed class WindowsFirewallCreationCoordinator(IWindowsFirewallPolicy policy)
{
    public void Create(string name, string ownerMarker, int port)
    {
        var expected = WindowsFirewallRuleContract.Expected(name, ownerMarker, port);
        if (policy.FindUnique(name) is not null)
        {
            throw new InstallException("install_resource_exists");
        }

        var addAttempted = false;
        try
        {
            addAttempted = true;
            policy.Add(expected);
            var current = policy.FindUnique(name);
            if (current is null || !WindowsFirewallRuleContract.IsExact(current, expected))
            {
                throw new InstallException("firewall_verification_failed");
            }
        }
        catch (Exception original) when (addAttempted)
        {
            WindowsFirewallRuleSnapshot? current;
            try
            {
                current = policy.FindUnique(name);
            }
            catch
            {
                throw new InstallException("install_state_uncertain");
            }

            if (current is not null)
            {
                if (!WindowsFirewallRuleContract.IsExact(current, expected))
                {
                    throw new InstallException("install_state_uncertain");
                }

                try
                {
                    policy.RemoveExact(expected);
                    if (policy.FindUnique(name) is not null)
                    {
                        throw new InstallException("install_state_uncertain");
                    }
                }
                catch
                {
                    throw new InstallException("install_state_uncertain");
                }
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }
    }
}

internal static class WindowsFirewall
{
    public static void Create(string name, string ownerMarker, int port) =>
        new WindowsFirewallCreationCoordinator(new WindowsFirewallComPolicy())
            .Create(name, ownerMarker, port);

    public static void Verify(string name, string ownerMarker, int port, bool allowConfiguredPort)
    {
        _ = allowConfiguredPort;
        var rule = new WindowsFirewallComPolicy().FindUnique(name) ??
            throw new InstallException("firewall_verification_failed");
        if (!WindowsFirewallRuleContract.IsExact(rule, name, ownerMarker, port))
        {
            throw new InstallException("firewall_verification_failed");
        }
    }

    public static void VerifyOwnedOrMissing(string name, string ownerMarker, int port)
    {
        var rule = new WindowsFirewallComPolicy().FindUnique(name);
        if (rule is null)
        {
            return;
        }

        if (!WindowsFirewallRuleContract.IsExact(rule, name, ownerMarker, port))
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    public static void VerifyMissing(string name)
    {
        if (new WindowsFirewallComPolicy().FindUnique(name) is not null)
        {
            throw new InstallException("uninstall_failed");
        }
    }

    public static void RemoveOwned(string name, string ownerMarker, int port)
    {
        var policy = new WindowsFirewallComPolicy();
        var expected = WindowsFirewallRuleContract.Expected(name, ownerMarker, port);
        var rule = policy.FindUnique(name);
        if (rule is null)
        {
            return;
        }

        if (!WindowsFirewallRuleContract.IsExact(rule, expected))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        policy.RemoveExact(expected);
    }
}

internal sealed class WindowsFirewallComPolicy : IWindowsFirewallPolicy
{
    public WindowsFirewallRuleSnapshot? FindUnique(string name)
    {
        dynamic policy = CreateCom("HNetCfg.FwPolicy2");
        dynamic? rule = null;
        try
        {
            rule = FindUniqueRule(policy, name);
            return rule is null ? null : Snapshot(rule);
        }
        finally
        {
            Release(rule);
            Release(policy);
        }
    }

    public void Add(WindowsFirewallRuleSnapshot expected)
    {
        dynamic policy = CreateCom("HNetCfg.FwPolicy2");
        dynamic? rule = null;
        try
        {
            rule = CreateCom("HNetCfg.FWRule");
            rule.Name = expected.Name;
            rule.Description = expected.Description;
            rule.Grouping = expected.Grouping;
            rule.Protocol = expected.Protocol;
            rule.LocalPorts = expected.LocalPorts;
            rule.Direction = expected.Direction;
            rule.Enabled = expected.Enabled;
            rule.Action = expected.Action;
            rule.Profiles = expected.Profiles;
            policy.Rules.Add(rule);
        }
        finally
        {
            Release(rule);
            Release(policy);
        }
    }

    public void RemoveExact(WindowsFirewallRuleSnapshot expected)
    {
        dynamic policy = CreateCom("HNetCfg.FwPolicy2");
        dynamic? rule = null;
        try
        {
            rule = FindUniqueRule(policy, expected.Name);
            if (rule is null || !WindowsFirewallRuleContract.IsExact(Snapshot(rule), expected))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            policy.Rules.Remove(expected.Name);
        }
        finally
        {
            Release(rule);
            Release(policy);
        }
    }

    private static dynamic? FindUniqueRule(dynamic policy, string name)
    {
        dynamic? found = null;
        foreach (dynamic candidate in policy.Rules)
        {
            var matches = string.Equals((string)candidate.Name, name, StringComparison.Ordinal);
            if (!matches)
            {
                Release(candidate);
                continue;
            }

            if (found is not null)
            {
                Release(candidate);
                Release(found);
                throw new InstallException("owned_resource_mismatch");
            }

            found = candidate;
        }

        return found;
    }

    private static WindowsFirewallRuleSnapshot Snapshot(dynamic rule) => new(
        (string)rule.Name,
        (string)rule.Description,
        (string)rule.Grouping,
        (int)rule.Protocol,
        (string)rule.LocalPorts,
        (int)rule.Direction,
        (int)rule.Action,
        (bool)rule.Enabled,
        (int)rule.Profiles);

    private static dynamic CreateCom(string programId) =>
        Activator.CreateInstance(Type.GetTypeFromProgID(programId, throwOnError: true)!)!;

    private static void Release(object? value)
    {
        if (value is not null && System.Runtime.InteropServices.Marshal.IsComObject(value))
        {
            _ = System.Runtime.InteropServices.Marshal.FinalReleaseComObject(value);
        }
    }
}

internal static class WindowsCommandLine
{
    public static string Quote(string value) => '"' + value.Replace("\"", "\\\"") + '"';
}

internal static class WindowsPathSafety
{
    public static bool EntryExists(string path) =>
        File.Exists(path) || Directory.Exists(path) || IsReparse(path);

    public static bool IsReparse(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
                new FileInfo(path).LinkTarget is not null;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }
}
