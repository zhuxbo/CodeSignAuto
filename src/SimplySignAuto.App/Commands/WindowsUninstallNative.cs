using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

internal sealed class WindowsUninstallNative : IWindowsUninstallNative
{
    internal static InstallAclProfile ExpectedOptionalToolsAclProfile =>
        InstallAclProfile.SigningUserRead;

    private static readonly TimeSpan NativeStateTimeout = TimeSpan.FromSeconds(30);
    private static readonly string[] OwnedAccountRights =
    [
        "SeInteractiveLogonRight",
        "SeDenyNetworkLogonRight",
        "SeDenyRemoteInteractiveLogonRight",
    ];
    private readonly IWindowsCommandRunner _runner = new DefaultWindowsCommandRunner();
    private readonly IWindowsInstallResourceLookup _lookup = new WindowsInstallResourceLookup();

    public void VerifySigningIdentityOwnership(
        UninstallSigningIdentity identity,
        ServiceConfiguration configuration)
    {
        EnsureWindows();
        var current = WindowsUninstallIdentity.Inspect(configuration, identity.OwnerMarker);
        if (current != identity)
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    public void VerifyFirewallOwnership(RemoveOwnedFirewallRule action)
    {
        EnsureWindows();
        WindowsFirewall.VerifyOwnedOrMissing(
            "SimplySignAuto API",
            action.OwnerMarker,
            action.TcpPort);
    }

    public async Task VerifyTaskOwnershipAsync(
        RemoveOwnedInteractiveLogonTask action,
        CancellationToken cancellationToken)
    {
        EnsureWindows();
        _ = await VerifyTaskOwnershipCoreAsync(action, cancellationToken).ConfigureAwait(false);
    }

    public void VerifyServiceOwnership(RemoveOwnedWindowsService action)
    {
        EnsureWindows();
        _ = VerifyServiceOwnershipCore(action);
    }

    public void VerifyAutoLogonOwnership(RemoveOwnedAutoLogon action)
    {
        EnsureWindows();
        WindowsAutoLogonPlatform.VerifyOwnedAutoLogon(
            action.SigningUserSid,
            action.OwnerMarker);
    }

    public void VerifySigningSessionOwnership(EndOwnedSigningUserSession action)
    {
        EnsureWindows();
        _ = WindowsSigningSession.FindExact(action.Identity.Sid);
    }

    public void VerifyAccountRightsOwnership(RemoveOwnedAccountRights action)
    {
        EnsureWindows();
        if (action.Identity.Ownership != UninstallSigningUserOwnership.ProductManaged)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        if (WindowsLocalAccount.Exists(action.Identity.UserName))
        {
            WindowsUninstallIdentity.VerifyManagedAccount(action.Identity);
        }
        else
        {
            VerifyDisabledIdentity(action.Identity);
        }

        var rights = WindowsLsaAccountRights.Read(action.Identity.Sid);
        if (rights.Except(OwnedAccountRights, StringComparer.Ordinal).Any())
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    public void VerifyControlledDataOwnership(
        PurgeControlledData action,
        UninstallSigningIdentity identity)
    {
        EnsureWindows();
        var expectedAgentDirectory = Path.GetFullPath(Path.Combine(
            identity.ProfilePath,
            "AppData",
            "Local",
            "SimplySignAuto"));
        if (!string.Equals(action.AgentDirectory, expectedAgentDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        try
        {
            var signingUser = new SecurityIdentifier(identity.Sid);
            WindowsInstallAcl.VerifyDirectory(
                action.DataRoot,
                InstallAclProfile.AdministratorsOnly,
                signingUser);
            WindowsInstallAcl.VerifyDirectory(
                Path.Combine(action.DataRoot, "jobs"),
                InstallAclProfile.SigningUserModify,
                signingUser);
            WindowsInstallAcl.VerifyDirectory(
                Path.Combine(action.DataRoot, "tools"),
                ExpectedOptionalToolsAclProfile,
                signingUser);
            WindowsInstallAcl.VerifyDirectory(
                Path.Combine(action.DataRoot, "logs"),
                InstallAclProfile.AdministratorsOnly,
                signingUser);
            WindowsInstallAcl.VerifyDirectory(
                Path.Combine(action.DataRoot, "spool"),
                InstallAclProfile.SigningUserRead,
                signingUser);
            if (Directory.Exists(action.AgentDirectory))
            {
                WindowsInstallAcl.VerifyDirectory(
                    action.AgentDirectory,
                    InstallAclProfile.SigningUserData,
                    signingUser);
            }
            else if (action.IncludeAgentDirectory ||
                WindowsAutoLogonPlatform.ReadDisabledAutoLogon(identity.OwnerMarker) is null)
            {
                throw new InstallException("owned_resource_mismatch");
            }
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

    public ManagedProfileRemovalState VerifyProfileOwnership(DeleteOwnedWindowsProfile action)
    {
        EnsureWindows();
        WindowsUninstallIdentity.VerifyManagedProfile(action.Identity);
        return WindowsUninstallIdentity.GetManagedProfileRemovalState(action.Identity);
    }

    public void VerifyLocalUserOwnership(DeleteOwnedLocalUser action)
    {
        EnsureWindows();
        if (!WindowsLocalAccount.Exists(action.Identity.UserName) &&
            WindowsAutoLogonPlatform.ReadDisabledAutoLogon(action.Identity.OwnerMarker) is { } disabled &&
            string.Equals(disabled.SigningUserSid, action.Identity.Sid, StringComparison.Ordinal) &&
            string.Equals(disabled.AccountName, action.Identity.AccountName, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        WindowsUninstallIdentity.VerifyManagedAccount(action.Identity);
    }

    public void VerifyProductRegistrationOwnership(RemoveOwnedProductUninstall action)
    {
        EnsureWindows();
        WindowsProductUninstallRegistry.Verify(
            action.Registration,
            "owned_resource_mismatch");
    }

    public void VerifyDesktopShortcutOwnership(RemoveOwnedDesktopShortcut action)
    {
        EnsureWindows();
        WindowsDesktopShortcut.VerifyExact(
            new CreateDesktopShortcut(action.Path, action.TargetPath, action.OwnerMarker),
            new SecurityIdentifier(action.SigningUserSid),
            "owned_resource_mismatch");
    }

    public void VerifyManualActivationOwnership(RemoveOwnedManualActivation action) =>
        WindowsManualActivationCredential.VerifyExact(action);

    public void RemoveFirewall(RemoveOwnedFirewallRule action)
    {
        try
        {
            VerifyFirewallOwnership(action);
            WindowsFirewall.RemoveOwned("SimplySignAuto API", action.OwnerMarker, action.TcpPort);
            WindowsFirewall.VerifyMissing("SimplySignAuto API");
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    public void RemoveProductRegistration(RemoveOwnedProductUninstall action)
    {
        EnsureWindows();
        WindowsProductUninstallRegistry.Remove(action.Registration);
    }

    public void RemoveDesktopShortcut(RemoveOwnedDesktopShortcut action)
    {
        VerifyDesktopShortcutOwnership(action);
        WindowsDesktopShortcut.RemoveExact(
            new CreateDesktopShortcut(action.Path, action.TargetPath, action.OwnerMarker),
            "uninstall_state_uncertain",
            new SecurityIdentifier(action.SigningUserSid));
    }

    public void RemoveManualActivation(RemoveOwnedManualActivation action) =>
        WindowsManualActivationCredential.RemoveExact(action);

    public Task RemovePdfExtensionAsync(CancellationToken cancellationToken) =>
        new WindowsPdfExtensionOperations().UninstallAsync(cancellationToken);

    public async Task EndAndRemoveTaskAsync(
        RemoveOwnedInteractiveLogonTask action,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!await VerifyTaskOwnershipCoreAsync(action, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            await WindowsScheduledTaskControl.StopAndWaitAsync(
                action.Name,
                NativeStateTimeout,
                cancellationToken).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Delete", "/TN", action.Name, "/F"],
                "uninstall_failed",
                cancellationToken).ConfigureAwait(false);
            await WaitForAsync(
                () => !_lookup.TaskExists(action.Name),
                "uninstall_state_uncertain",
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    public async Task StopAndRemoveServiceAsync(
        RemoveOwnedWindowsService action,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!VerifyServiceOwnershipCore(action))
            {
                return;
            }

            await StopServiceAndWaitAsync(action.Name, cancellationToken).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "sc.exe",
                ["delete", action.Name],
                "uninstall_failed",
                cancellationToken).ConfigureAwait(false);
            await WaitForAsync(
                () => !_lookup.ServiceExists(action.Name),
                "uninstall_state_uncertain",
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    public void RemoveAutoLogon(RemoveOwnedAutoLogon action)
    {
        try
        {
            VerifyAutoLogonOwnership(action);
            WindowsAutoLogonPlatform.RemoveOwnedAutoLogon(
                action.SigningUserSid,
                action.OwnerMarker,
                action.AccountName,
                action.ProfilePath);
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    public async Task EndSigningUserSessionsAsync(
        EndOwnedSigningUserSession action,
        CancellationToken cancellationToken)
    {
        VerifySigningSessionOwnership(action);
        await WindowsSigningSession.LogoffAndWaitForProfileUnloadAsync(
            action.Identity.Sid,
            NativeStateTimeout,
            cancellationToken).ConfigureAwait(false);
    }

    public void RemoveAccountRights(RemoveOwnedAccountRights action)
    {
        try
        {
            VerifyDisabledIdentity(action.Identity);
            var rights = WindowsLsaAccountRights.Read(action.Identity.Sid);
            if (rights.Except(OwnedAccountRights, StringComparer.Ordinal).Any())
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            if (rights.Count > 0)
            {
                WindowsLsaAccountRights.Remove(action.Identity.Sid, rights.ToArray());
            }

            UninstallStateReadback.Require(
                WindowsLsaAccountRights.Read(action.Identity.Sid).Count == 0);
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    public async Task DeleteProfileAsync(
        DeleteOwnedWindowsProfile action,
        CancellationToken cancellationToken)
    {
        try
        {
            var state = VerifyProfileOwnership(action);
            await WindowsUserProfile.DeleteOwnedForUninstallAsync(
                    action.Identity,
                    cancellationToken)
                .ConfigureAwait(false);
            var profileEntryRemoved = !WindowsUserProfile.ProfileEntryExists(action.Identity.Sid);
            var profileDirectoryStateExact = ManagedProfileRemovalPolicy.RequiresCombinedPurge(state)
                ? Directory.Exists(action.Identity.ProfilePath) &&
                    !WindowsPathSafety.IsReparse(action.Identity.ProfilePath)
                : !Directory.Exists(action.Identity.ProfilePath);
            UninstallStateReadback.Require(profileEntryRemoved && profileDirectoryStateExact);
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    public void DeleteLocalUser(DeleteOwnedLocalUser action)
    {
        try
        {
            VerifyLocalUserOwnership(action);
            if (!WindowsLocalAccount.Exists(action.Identity.UserName))
            {
                return;
            }

            var profile = WindowsUserProfile.ReadReceipt(action.Identity.Sid);
            UninstallStateReadback.Require(profile.ProfileExists && profile.HasOwnershipValues);
            WindowsUninstallIdentity.VerifyManagedAccount(action.Identity);
            WindowsLocalAccount.Delete(action.Identity.UserName);
            UninstallStateReadback.Require(!WindowsLocalAccount.Exists(action.Identity.UserName));
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private static void VerifyDisabledIdentity(UninstallSigningIdentity identity)
    {
        var disabled = WindowsAutoLogonPlatform.ReadDisabledAutoLogon(identity.OwnerMarker);
        if (disabled is null ||
            !string.Equals(disabled.OwnerMarker, identity.OwnerMarker, StringComparison.Ordinal) ||
            !string.Equals(disabled.SigningUserSid, identity.Sid, StringComparison.Ordinal) ||
            !string.Equals(disabled.AccountName, identity.AccountName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(disabled.ProfilePath, identity.ProfilePath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    private async Task<bool> VerifyTaskOwnershipCoreAsync(
        RemoveOwnedInteractiveLogonTask action,
        CancellationToken cancellationToken)
    {
        if (!_lookup.TaskExists(action.Name))
        {
            return false;
        }

        WindowsProcessResult query;
        try
        {
            query = await _runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Query", "/TN", action.Name, "/XML"],
                "resource_preflight_failed",
                cancellationToken).ConfigureAwait(false);
        }
        catch (InstallException error) when (error.Code != "owned_resource_mismatch")
        {
            throw new InstallException("resource_preflight_failed");
        }

        if (!WindowsTaskXml.IsOwned(
                query.StandardOutput,
                action.SigningUserSid,
                action.ExecutablePath,
                action.OwnerMarker))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        return true;
    }

    private bool VerifyServiceOwnershipCore(RemoveOwnedWindowsService action)
    {
        if (!_lookup.ServiceExists(action.Name))
        {
            return false;
        }

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{action.Name}",
                writable: false) ?? throw new InstallException("resource_preflight_failed");
            var expectedImage = WindowsCommandLine.Quote(action.ExecutablePath) + " service";
            if (!string.Equals(key.GetValue("ImagePath") as string, expectedImage, StringComparison.Ordinal) ||
                !string.Equals(key.GetValue("Description") as string, action.OwnerMarker, StringComparison.Ordinal) ||
                !string.Equals(
                    key.GetValue(WindowsInstallResourceLookup.InstallOwnerValueName) as string,
                    action.OwnerMarker,
                    StringComparison.Ordinal))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            return true;
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or SystemException)
        {
            throw new InstallException("resource_preflight_failed");
        }
    }

    private static async Task StopServiceAndWaitAsync(
        string name,
        CancellationToken cancellationToken)
    {
        try
        {
            using var service = new ServiceController(name);
            service.Refresh();
            if (service.Status != ServiceControllerStatus.Stopped)
            {
                service.Stop();
            }

            var deadline = DateTimeOffset.UtcNow + NativeStateTimeout;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                service.Refresh();
                if (service.Status == ServiceControllerStatus.Stopped)
                {
                    return;
                }

                if (DateTimeOffset.UtcNow >= deadline)
                {
                    throw new InstallException("uninstall_failed");
                }

                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is InvalidOperationException or Win32Exception or SystemException)
        {
            throw new InstallException("uninstall_failed");
        }
    }

    private static async Task WaitForAsync(
        Func<bool> completed,
        string errorCode,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + NativeStateTimeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (completed())
            {
                return;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new InstallException(errorCode);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
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

internal static class WindowsManualActivationCredential
{
    private const string LocalSystemSid = "S-1-5-18";

    public static void VerifyExact(RemoveOwnedManualActivation action)
    {
        EnsureValid(action);
        var kind = NoFollowFile.InspectPathEntry(action.Path);
        if (kind == NoFollowPathEntryKind.Missing)
        {
            return;
        }

        if (kind != NoFollowPathEntryKind.RegularFile)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        try
        {
            using var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(action.Path);
            VerifyHandle(handle, action.SigningUserSid);
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

    public static void RemoveExact(RemoveOwnedManualActivation action)
    {
        try
        {
            EnsureValid(action);
            if (NoFollowFile.InspectPathEntry(action.Path) == NoFollowPathEntryKind.Missing)
            {
                return;
            }

            using (var handle = WindowsNoFollowSecurity.OpenRenameSourceHandle(action.Path))
            {
                VerifyHandle(handle, action.SigningUserSid);
                WindowsHandleBoundFile.DeleteByHandle(handle);
            }

            if (NoFollowFile.InspectPathEntry(action.Path) != NoFollowPathEntryKind.Missing)
            {
                throw new InstallException("uninstall_state_uncertain");
            }
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private static void EnsureValid(RemoveOwnedManualActivation action)
    {
        if (!OperatingSystem.IsWindows() ||
            !CanonicalWindowsSid.IsValid(action.SigningUserSid) ||
            !Path.IsPathFullyQualified(action.Path) ||
            !Path.IsPathFullyQualified(action.UserDataRoot) ||
            !string.Equals(Path.GetFullPath(action.Path), action.Path, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFullPath(action.UserDataRoot), action.UserDataRoot, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                action.Path,
                Path.Combine(action.UserDataRoot, "otp.dat"),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    private static void VerifyHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        string signingUserSid)
    {
        var snapshot = WindowsNoFollowSecurity.Read(handle);
        var dacl = snapshot.Security.DiscretionaryAcl;
        if ((snapshot.Attributes & FileAttributes.ReparsePoint) != 0 ||
            snapshot.Security.Owner?.Value != signingUserSid ||
            !snapshot.Security.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            dacl is not { Count: 2 } ||
            !PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(handle, out var identity) ||
            identity.LinkCount != 1)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var expectedSids = new HashSet<string>(StringComparer.Ordinal)
        {
            LocalSystemSid,
            signingUserSid,
        };
        foreach (GenericAce ace in dacl)
        {
            if (ace is not CommonAce common ||
                common.AceQualifier != AceQualifier.AccessAllowed ||
                common.AceFlags != AceFlags.None ||
                common.AccessMask != (int)FileSystemRights.FullControl ||
                !expectedSids.Remove(common.SecurityIdentifier.Value))
            {
                throw new InstallException("owned_resource_mismatch");
            }
        }

        if (expectedSids.Count != 0)
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }
}

internal static class UninstallStateReadback
{
    internal static void Require(bool exact)
    {
        if (!exact)
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }
}

internal enum ManagedProfileRemovalState
{
    RegisteredAndPresent,
    RegistryOnly,
    DirectoryOnly,
    Complete,
}

internal static class ManagedProfileRemovalPolicy
{
    internal static bool RequiresCombinedPurge(ManagedProfileRemovalState state) =>
        state == ManagedProfileRemovalState.DirectoryOnly;

    internal static ManagedProfileRemovalState Validate(
        UninstallSigningIdentity identity,
        OwnedUserProfileReceipt receipt,
        DisabledOwnedAutoLogon? disabled,
        bool directoryExists,
        bool directoryIsReparse,
        bool pathUnderTrustedProfilesRoot)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(receipt);
        if (identity.Ownership != UninstallSigningUserOwnership.ProductManaged ||
            !pathUnderTrustedProfilesRoot ||
            (directoryExists && directoryIsReparse))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var instanceId = identity.OwnerMarker["SimplySignAuto/v1/".Length..];
        var receiptExact = receipt.ProfileExists &&
            receipt.HasOwnershipValues &&
            string.Equals(receipt.RegisteredPath, identity.ProfilePath, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(receipt.OwnerMarker, identity.OwnerMarker, StringComparison.Ordinal) &&
            string.Equals(receipt.InstallInstanceId, instanceId, StringComparison.Ordinal) &&
            string.Equals(receipt.Sid, identity.Sid, StringComparison.Ordinal) &&
            string.Equals(receipt.AccountName, identity.AccountName, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(receipt.RecordedPath, identity.ProfilePath, StringComparison.OrdinalIgnoreCase);
        var disabledExact = disabled is not null &&
            string.Equals(disabled.OwnerMarker, identity.OwnerMarker, StringComparison.Ordinal) &&
            string.Equals(disabled.SigningUserSid, identity.Sid, StringComparison.Ordinal) &&
            string.Equals(disabled.AccountName, identity.AccountName, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(disabled.ProfilePath, identity.ProfilePath, StringComparison.OrdinalIgnoreCase);
        if (disabled is not null && !disabledExact)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        if (receipt.ProfileExists)
        {
            if (!receiptExact)
            {
                throw new InstallException("owned_resource_mismatch");
            }

            if (directoryExists)
            {
                return ManagedProfileRemovalState.RegisteredAndPresent;
            }

            if (!disabledExact)
            {
                throw new InstallException("owned_resource_mismatch");
            }

            return ManagedProfileRemovalState.RegistryOnly;
        }

        if (receipt.HasOwnershipValues ||
            receipt.RegisteredPath is not null ||
            receipt.OwnerMarker is not null ||
            receipt.InstallInstanceId is not null ||
            receipt.Sid is not null ||
            receipt.AccountName is not null ||
            receipt.RecordedPath is not null ||
            !disabledExact)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        return directoryExists
            ? ManagedProfileRemovalState.DirectoryOnly
            : ManagedProfileRemovalState.Complete;
    }
}

internal static class WindowsUninstallIdentity
{
    internal static UninstallSigningIdentity Inspect(
        ServiceConfiguration configuration,
        string ownerMarker)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        try
        {
            var disabled = WindowsAutoLogonPlatform.ReadDisabledAutoLogon(ownerMarker);
            var receipt = WindowsUserProfile.ReadReceipt(configuration.SigningUserSid);
            var profilePath = receipt.ProfileExists
                ? receipt.RegisteredPath
                : disabled?.ProfilePath;
            var accountName = receipt.HasOwnershipValues
                ? receipt.AccountName
                : disabled?.AccountName;
            if (accountName is null)
            {
                var sid = new SecurityIdentifier(configuration.SigningUserSid);
                accountName = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
            }

            if (string.IsNullOrWhiteSpace(profilePath) ||
                string.IsNullOrWhiteSpace(accountName) ||
                !Path.IsPathFullyQualified(profilePath) ||
                !string.Equals(
                    Path.GetFullPath(profilePath),
                    profilePath,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var separator = accountName.IndexOf('\\');
            if (separator <= 0 || separator == accountName.Length - 1)
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var domain = accountName[..separator];
            var userName = accountName[(separator + 1)..];
            if (!string.Equals(domain, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var expectedAgentPath = Path.GetFullPath(Path.Combine(
                profilePath,
                "AppData",
                "Local",
                "SimplySignAuto",
                "agent.json"));
            if (!string.Equals(
                    configuration.AgentConfigurationPath,
                    expectedAgentPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var userExists = WindowsLocalAccount.Exists(userName);
            var managed = receipt.HasOwnershipValues || (!userExists && disabled is not null);
            var identity = new UninstallSigningIdentity(
                accountName,
                userName,
                configuration.SigningUserSid,
                profilePath,
                ownerMarker,
                managed
                    ? UninstallSigningUserOwnership.ProductManaged
                    : UninstallSigningUserOwnership.ExistingUser);
            if (managed)
            {
                if (disabled is null && !userExists)
                {
                    throw new InstallException("owned_resource_mismatch");
                }

                if (userExists)
                {
                    VerifyManagedAccount(identity);
                }

                VerifyManagedProfile(identity);
            }
            else
            {
                if (!userExists ||
                    !receipt.ProfileExists ||
                    receipt.HasOwnershipValues ||
                    !Directory.Exists(profilePath) ||
                    IsReparsePoint(profilePath))
                {
                    throw new InstallException("owned_resource_mismatch");
                }

                VerifyAccountSid(identity);
            }

            return identity;
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is ProvisionAgentUserException or SystemException)
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    internal static ProvisionedAgentUser AsProvisionedUser(UninstallSigningIdentity identity) =>
        new(
            identity.AccountName,
            identity.Sid,
            Environment.MachineName,
            identity.ProfilePath,
            identity.OwnerMarker);

    internal static UninstallSigningUserOwnership InspectInterruptedOwnership(
        DisabledOwnedAutoLogon disabled)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(disabled);
            var separator = disabled.AccountName.IndexOf('\\');
            if (separator <= 0 || separator == disabled.AccountName.Length - 1 ||
                !string.Equals(
                    disabled.AccountName[..separator],
                    Environment.MachineName,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var userName = disabled.AccountName[(separator + 1)..];
            var receipt = WindowsUserProfile.ReadReceipt(disabled.SigningUserSid);
            var hasReceiptValues = receipt.HasOwnershipValues ||
                receipt.OwnerMarker is not null ||
                receipt.InstallInstanceId is not null ||
                receipt.Sid is not null ||
                receipt.AccountName is not null ||
                receipt.RecordedPath is not null;
            var baseIdentity = new UninstallSigningIdentity(
                disabled.AccountName,
                userName,
                disabled.SigningUserSid,
                disabled.ProfilePath,
                disabled.OwnerMarker,
                UninstallSigningUserOwnership.ExistingUser);
            if (!WindowsUserProfile.IsSafeOwnedProfilePath(baseIdentity))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            var userExists = WindowsLocalAccount.Exists(userName);
            if (receipt.ProfileExists)
            {
                if (!userExists || hasReceiptValues ||
                    !string.Equals(
                        receipt.RegisteredPath,
                        disabled.ProfilePath,
                        StringComparison.OrdinalIgnoreCase) ||
                    !Directory.Exists(disabled.ProfilePath) ||
                    WindowsPathSafety.IsReparse(disabled.ProfilePath))
                {
                    throw new InstallException("owned_resource_mismatch");
                }

                VerifyAccountSid(baseIdentity);
                return UninstallSigningUserOwnership.ExistingUser;
            }

            if (userExists || hasReceiptValues || receipt.RegisteredPath is not null)
            {
                throw new InstallException("owned_resource_mismatch");
            }

            return UninstallSigningUserOwnership.ProductManaged;
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

    internal static void VerifyManagedProfile(UninstallSigningIdentity identity)
    {
        try
        {
            if (identity.Ownership != UninstallSigningUserOwnership.ProductManaged)
            {
                throw new InstallException("owned_resource_mismatch");
            }

            if (WindowsLocalAccount.Exists(identity.UserName))
            {
                VerifyManagedAccount(identity);
            }

            _ = GetManagedProfileRemovalState(identity);
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

    internal static ManagedProfileRemovalState GetManagedProfileRemovalState(
        UninstallSigningIdentity identity)
    {
        var entryExists = WindowsPathSafety.EntryExists(identity.ProfilePath);
        var directoryExists = Directory.Exists(identity.ProfilePath);
        return ManagedProfileRemovalPolicy.Validate(
            identity,
            WindowsUserProfile.ReadReceipt(identity.Sid),
            WindowsAutoLogonPlatform.ReadDisabledAutoLogon(identity.OwnerMarker),
            directoryExists,
            directoryExists && WindowsPathSafety.IsReparse(identity.ProfilePath),
            (!entryExists || directoryExists) && WindowsUserProfile.IsSafeOwnedProfilePath(identity));
    }

    internal static void VerifyManagedAccount(UninstallSigningIdentity identity)
    {
        try
        {
            if (identity.Ownership != UninstallSigningUserOwnership.ProductManaged ||
                !WindowsLocalAccount.Exists(identity.UserName) ||
                !WindowsLocalAccount.IsManaged(identity.UserName))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            VerifyAccountSid(identity);
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

    private static void VerifyAccountSid(UninstallSigningIdentity identity)
    {
        try
        {
            var account = new NTAccount(Environment.MachineName, identity.UserName);
            var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
            var roundTrip = (NTAccount)sid.Translate(typeof(NTAccount));
            if (!string.Equals(sid.Value, identity.Sid, StringComparison.Ordinal) ||
                !string.Equals(roundTrip.Value, identity.AccountName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }
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

    private static bool IsReparsePoint(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        return directory.LinkTarget is not null ||
            (directory.Attributes & FileAttributes.ReparsePoint) != 0;
    }
}

internal static class WindowsSigningSession
{
    private static readonly IntPtr CurrentServer = IntPtr.Zero;

    internal static IReadOnlyList<uint> FindExact(string expectedSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSEnumerateSessions(CurrentServer, 0, 1, out buffer, out var count))
            {
                throw new InstallException("resource_preflight_failed");
            }

            if (count is < 0 or > 65536)
            {
                throw new InstallException("resource_preflight_failed");
            }

            var result = new List<uint>();
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<WtsSessionInfo>(IntPtr.Add(buffer, checked(index * size)));
                var userName = QueryString(session.SessionId, WtsInfoClass.UserName);
                if (string.IsNullOrWhiteSpace(userName))
                {
                    continue;
                }

                var domain = QueryString(session.SessionId, WtsInfoClass.DomainName);
                if (string.IsNullOrWhiteSpace(domain))
                {
                    throw new InstallException("resource_preflight_failed");
                }

                SecurityIdentifier sid;
                try
                {
                    sid = (SecurityIdentifier)new NTAccount(domain, userName)
                        .Translate(typeof(SecurityIdentifier));
                }
                catch
                {
                    throw new InstallException("resource_preflight_failed");
                }

                if (string.Equals(sid.Value, expectedSid, StringComparison.Ordinal))
                {
                    result.Add(session.SessionId);
                }
            }

            return result;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                WTSFreeMemory(buffer);
            }
        }
    }

    internal static async Task LogoffAndWaitForProfileUnloadAsync(
        string expectedSid,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        try
        {
            foreach (var sessionId in FindExact(expectedSid))
            {
                if (!WTSLogoffSession(CurrentServer, sessionId, true))
                {
                    throw new InstallException("uninstall_state_uncertain");
                }
            }

            var deadline = DateTimeOffset.UtcNow + timeout;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var loadedProfile = Registry.Users.OpenSubKey(expectedSid, writable: false);
                if (FindExact(expectedSid).Count == 0 && loadedProfile is null)
                {
                    return;
                }

                if (DateTimeOffset.UtcNow >= deadline)
                {
                    throw new InstallException("uninstall_state_uncertain");
                }

                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private static string QueryString(uint sessionId, WtsInfoClass infoClass)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSQuerySessionInformation(
                    CurrentServer,
                    sessionId,
                    infoClass,
                    out buffer,
                    out _))
            {
                throw new InstallException("resource_preflight_failed");
            }

            return Marshal.PtrToStringUni(buffer) ?? string.Empty;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                WTSFreeMemory(buffer);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public uint SessionId;
        public nint WinStationName;
        public int State;
    }

    private enum WtsInfoClass
    {
        UserName = 5,
        DomainName = 7,
    }

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessions(
        IntPtr server,
        int reserved,
        int version,
        out IntPtr sessionInfo,
        out int count);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr server,
        uint sessionId,
        WtsInfoClass infoClass,
        out IntPtr buffer,
        out uint bytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSLogoffSession(
        IntPtr server,
        uint sessionId,
        [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}

internal static class WindowsScheduledTaskControl
{
    private const int RunningState = 4;

    public static async Task StopAndWaitAsync(
        string name,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        var stopRequested = false;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            dynamic? service = null;
            dynamic? folder = null;
            dynamic? task = null;
            try
            {
                service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
                service.Connect();
                folder = service.GetFolder("\\");
                task = folder.GetTask(name);
                if ((int)task.State != RunningState)
                {
                    return;
                }

                if (!stopRequested)
                {
                    task.Stop(0);
                    stopRequested = true;
                }
            }
            catch (System.Runtime.InteropServices.COMException error) when (
                error.HResult is unchecked((int)0x80070002) or unchecked((int)0x8004130F))
            {
                return;
            }
            catch
            {
                throw new InstallException("uninstall_failed");
            }
            finally
            {
                Release(task);
                Release(folder);
                Release(service);
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new InstallException("uninstall_failed");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void Release(object? value)
    {
        if (value is not null && System.Runtime.InteropServices.Marshal.IsComObject(value))
        {
            _ = System.Runtime.InteropServices.Marshal.FinalReleaseComObject(value);
        }
    }
}
