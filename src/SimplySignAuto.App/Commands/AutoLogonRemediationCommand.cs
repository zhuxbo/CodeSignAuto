using System.Security.Principal;
using Microsoft.Win32;

namespace SimplySignAuto.App.Commands;

internal sealed record AutoLogonRemediationInspection(
    bool IsAdministrator,
    bool AutoAdminLogonValueValid,
    bool DefaultPasswordValueValid,
    bool ProductStatePresent,
    bool ManagedAgentUserExists,
    bool AutoAdminLogonEnabled,
    bool RegistryDefaultPasswordPresent,
    bool LsaDefaultPasswordPresent);

internal interface IAutoLogonRemediationPlatform
{
    Task<AutoLogonRemediationInspection> InspectAsync(CancellationToken cancellationToken);

    Task DisableRegistryAutoLogonAsync(CancellationToken cancellationToken);

    Task RemoveLsaDefaultPasswordAsync(CancellationToken cancellationToken);
}

internal sealed class AutoLogonRemediationRegistry(IWinlogonValueStore store)
{
    public AutoLogonRemediationInspection Inspect(
        bool isAdministrator,
        bool managedAgentUserExists,
        bool lsaDefaultPasswordPresent,
        bool externalProductStatePresent = false)
    {
        ArgumentNullException.ThrowIfNull(store);
        var valueNames = store.GetValueNames();
        var autoAdminLogon = store.Read("AutoAdminLogon");
        var autoAdminLogonValueValid = !autoAdminLogon.Present ||
            autoAdminLogon is { Kind: RegistryValueKind.String, Value: string value } &&
            value is "0" or "1";
        var defaultPasswordPresent = valueNames.Contains(
            "DefaultPassword",
            StringComparer.OrdinalIgnoreCase);
        return new AutoLogonRemediationInspection(
            isAdministrator,
            autoAdminLogonValueValid,
            !defaultPasswordPresent ||
                store.ReadKind("DefaultPassword") == RegistryValueKind.String,
            externalProductStatePresent || valueNames.Any(name =>
                name.StartsWith("SimplySignAuto", StringComparison.OrdinalIgnoreCase)),
            managedAgentUserExists,
            autoAdminLogon == WinlogonStoredValue.String("1"),
            defaultPasswordPresent,
            lsaDefaultPasswordPresent);
    }

    public void DisableAndVerify()
    {
        var before = Inspect(
            isAdministrator: true,
            managedAgentUserExists: false,
            lsaDefaultPasswordPresent: false);
        ValidateRegistryState(before);

        store.Write("AutoAdminLogon", WinlogonStoredValue.String("0"));
        store.Flush();
        if (store.Read("AutoAdminLogon") != WinlogonStoredValue.String("0"))
        {
            throw new ProvisionAgentUserException("autologon_cleanup_failed");
        }

        store.Delete("DefaultPassword");
        store.Flush();
        if (HasValue("DefaultPassword"))
        {
            throw new ProvisionAgentUserException("autologon_cleanup_failed");
        }

        var after = Inspect(
            isAdministrator: true,
            managedAgentUserExists: false,
            lsaDefaultPasswordPresent: false);
        if (!after.AutoAdminLogonValueValid ||
            !after.DefaultPasswordValueValid ||
            after.ProductStatePresent)
        {
            throw new ProvisionAgentUserException("autologon_cleanup_failed");
        }
        if (after.AutoAdminLogonEnabled ||
            store.Read("AutoAdminLogon") != WinlogonStoredValue.String("0") ||
            after.RegistryDefaultPasswordPresent)
        {
            throw new ProvisionAgentUserException("autologon_cleanup_failed");
        }
    }

    public void VerifyReadyForLsaRemoval()
    {
        var state = Inspect(
            isAdministrator: true,
            managedAgentUserExists: false,
            lsaDefaultPasswordPresent: false);
        ValidateRegistryState(state);
        if (state.AutoAdminLogonEnabled ||
            store.Read("AutoAdminLogon") != WinlogonStoredValue.String("0") ||
            state.RegistryDefaultPasswordPresent)
        {
            throw new ProvisionAgentUserException("autologon_cleanup_failed");
        }
    }

    private static void ValidateRegistryState(AutoLogonRemediationInspection inspection)
    {
        if (inspection.ProductStatePresent)
        {
            throw new ProvisionAgentUserException("autologon_cleanup_owned_state");
        }

        if (!inspection.AutoAdminLogonValueValid || !inspection.DefaultPasswordValueValid)
        {
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain");
        }
    }

    private bool HasValue(string name) =>
        store.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase);
}

internal static class WindowsAutoLogonRemediationProductState
{
    private const string ServiceName = "SimplySignAuto.Service";
    private const string AgentTaskName = "SimplySignAuto.Agent";
    private const string UninstallPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SimplySignAuto";

    public static bool Exists()
    {
        try
        {
            var lookup = new WindowsInstallResourceLookup();
            var programDataRoot = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);
            var programFilesRoot = Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);
            var profilesRoot = WindowsProfilesDirectory.Resolve();
            using var uninstall = Registry.LocalMachine.OpenSubKey(UninstallPath, writable: false);
            return lookup.ServiceExists(ServiceName) ||
                lookup.TaskExists(AgentTaskName) ||
                WindowsPathSafety.EntryExists(Path.Combine(programDataRoot, "SimplySignAuto")) ||
                WindowsPathSafety.EntryExists(Path.Combine(programFilesRoot, "SimplySignAuto")) ||
                WindowsPathSafety.EntryExists(Path.Combine(profilesRoot, "SimplySignAgent")) ||
                uninstall is not null;
        }
        catch
        {
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain");
        }
    }
}

internal sealed class WindowsAutoLogonRemediationPlatform : IAutoLogonRemediationPlatform
{
    private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string ManagedAgentUser = "SimplySignAgent";
    private readonly IWindowsLsaSecretStore _lsaSecretStore = new WindowsLsaSecretStore();

    public Task<AutoLogonRemediationInspection> InspectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false) ??
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain");
        var registry = new AutoLogonRemediationRegistry(new RegistryWinlogonValueStore(key));
        var inspection = registry.Inspect(
            IsAdministrator(),
            WindowsLocalAccount.Exists(ManagedAgentUser),
            lsaDefaultPasswordPresent: false,
            externalProductStatePresent: WindowsAutoLogonRemediationProductState.Exists());
        if (!inspection.IsAdministrator ||
            !inspection.AutoAdminLogonValueValid ||
            !inspection.DefaultPasswordValueValid ||
            inspection.ProductStatePresent ||
            inspection.ManagedAgentUserExists)
        {
            return Task.FromResult(inspection);
        }

        try
        {
            return Task.FromResult(inspection with
            {
                LsaDefaultPasswordPresent = _lsaSecretStore.Exists(),
            });
        }
        catch
        {
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain");
        }
    }

    public Task DisableRegistryAutoLogonAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindowsAdministrator();
        EnsureManagedAgentAbsent();
        EnsureProductStateAbsent();
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain");
        new AutoLogonRemediationRegistry(new RegistryWinlogonValueStore(key)).DisableAndVerify();
        return Task.CompletedTask;
    }

    public Task RemoveLsaDefaultPasswordAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindowsAdministrator();
        EnsureManagedAgentAbsent();
        EnsureProductStateAbsent();
        using (var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false) ??
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain"))
        {
            new AutoLogonRemediationRegistry(new RegistryWinlogonValueStore(key))
                .VerifyReadyForLsaRemoval();
        }

        if (_lsaSecretStore.Exists())
        {
            _lsaSecretStore.Remove();
        }

        if (_lsaSecretStore.Exists())
        {
            throw new ProvisionAgentUserException("autologon_cleanup_failed");
        }

        return Task.CompletedTask;
    }

    private static void EnsureWindowsAdministrator()
    {
        EnsureWindows();
        if (!IsAdministrator())
        {
            throw new ProvisionAgentUserException("administrator_required");
        }
    }

    private static void EnsureManagedAgentAbsent()
    {
        if (WindowsLocalAccount.Exists(ManagedAgentUser))
        {
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain");
        }
    }

    private static void EnsureProductStateAbsent()
    {
        if (WindowsAutoLogonRemediationProductState.Exists())
        {
            throw new ProvisionAgentUserException("autologon_cleanup_owned_state");
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows is required.");
        }
    }
}

internal sealed class AutoLogonRemediationOrchestrator(IAutoLogonRemediationPlatform platform)
{
    public async Task ExecuteAsync(TextWriter output, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(output);

        var initial = await platform.InspectAsync(cancellationToken).ConfigureAwait(false);
        ValidateSafeState(initial);
        if (!HasAutoLogonState(initial))
        {
            await output.WriteLineAsync("autologon_disabled").ConfigureAwait(false);
            return;
        }

        try
        {
            await platform.DisableRegistryAutoLogonAsync(cancellationToken).ConfigureAwait(false);
            var registryReadback = await platform.InspectAsync(cancellationToken).ConfigureAwait(false);
            ValidateSafeState(registryReadback);
            if (registryReadback.AutoAdminLogonEnabled ||
                registryReadback.RegistryDefaultPasswordPresent)
            {
                throw new ProvisionAgentUserException("autologon_cleanup_failed");
            }

            await platform.RemoveLsaDefaultPasswordAsync(cancellationToken).ConfigureAwait(false);
            var final = await platform.InspectAsync(cancellationToken).ConfigureAwait(false);
            ValidateSafeState(final);
            if (HasAutoLogonState(final))
            {
                throw new ProvisionAgentUserException("autologon_cleanup_failed");
            }
        }
        catch (ProvisionAgentUserException error) when (
            error.Code != "autologon_cleanup_failed")
        {
            throw new ProvisionAgentUserException("autologon_cleanup_failed");
        }

        await output.WriteLineAsync("autologon_disabled").ConfigureAwait(false);
    }

    private static bool HasAutoLogonState(AutoLogonRemediationInspection inspection) =>
        inspection.AutoAdminLogonEnabled ||
        inspection.RegistryDefaultPasswordPresent ||
        inspection.LsaDefaultPasswordPresent;

    private static void ValidateSafeState(AutoLogonRemediationInspection inspection)
    {
        if (!inspection.IsAdministrator)
        {
            throw new ProvisionAgentUserException("administrator_required");
        }

        if (inspection.ProductStatePresent)
        {
            throw new ProvisionAgentUserException("autologon_cleanup_owned_state");
        }

        if (!inspection.AutoAdminLogonValueValid ||
            !inspection.DefaultPasswordValueValid ||
            inspection.ManagedAgentUserExists)
        {
            throw new ProvisionAgentUserException("autologon_cleanup_state_uncertain");
        }
    }
}

internal static class DisableAutoLogonCommand
{
    public static async Task<int> ExecuteAsync(
        string[] arguments,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        using var lease = new ServiceConfigurationWriterLeaseFactory().TryAcquire();
        if (lease is null)
        {
            await error.WriteLineAsync("autologon_cleanup_busy").ConfigureAwait(false);
            return 1;
        }

        return await ExecuteAsync(
                arguments,
                new WindowsAutoLogonRemediationPlatform(),
                output,
                error,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async Task<int> ExecuteAsync(
        string[] arguments,
        IAutoLogonRemediationPlatform platform,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        if (arguments.Length != 0)
        {
            await error.WriteLineAsync("autologon_cleanup_arguments_invalid").ConfigureAwait(false);
            return 2;
        }

        try
        {
            await new AutoLogonRemediationOrchestrator(platform)
                .ExecuteAsync(output, cancellationToken)
                .ConfigureAwait(false);
            return 0;
        }
        catch (ProvisionAgentUserException known)
        {
            await error.WriteLineAsync(ProvisionAgentUserCommand.FormatFailure(known))
                .ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 1;
        }
        catch
        {
            await error.WriteLineAsync("autologon_cleanup_failed").ConfigureAwait(false);
            return 1;
        }
    }
}
