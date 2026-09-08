using System.Security.Principal;
using CodeSignAuto.Service;

namespace CodeSignAuto.App.Commands;

internal interface IWindowsInstallRollbackOwnershipVerifier
{
    Task VerifyAsync(
        AppliedInstallAction applied,
        CancellationToken cancellationToken);
}

internal sealed class WindowsOwnedTaskRollback(
    IWindowsCommandRunner runner,
    IWindowsInstallResourceLookup resourceLookup,
    IWindowsInstallStartupRuntime startupRuntime)
{
    public async Task ExecuteAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            await startupRuntime.StopTaskAsync(name, cancellationToken).ConfigureAwait(false);
            _ = await runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Delete", "/TN", name, "/F"],
                "install_state_uncertain",
                cancellationToken).ConfigureAwait(false);
            if (resourceLookup.TaskExists(name))
            {
                throw new InstallException("install_state_uncertain");
            }
        }
        catch (InstallException error) when (error.Code == "install_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }
}

internal sealed class WindowsOwnedServiceRollback(
    IWindowsCommandRunner runner,
    IWindowsInstallResourceLookup resourceLookup,
    IWindowsInstallStartupRuntime startupRuntime)
{
    public async Task ExecuteAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            await startupRuntime.StopServiceAsync(name, cancellationToken).ConfigureAwait(false);
            _ = await runner.RunCheckedAsync(
                "sc.exe",
                ["delete", name],
                "install_state_uncertain",
                cancellationToken).ConfigureAwait(false);
            if (resourceLookup.ServiceExists(name))
            {
                throw new InstallException("install_state_uncertain");
            }
        }
        catch (InstallException error) when (error.Code == "install_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }
}

internal sealed class WindowsInstallRollbackOwnershipVerifier(
    string signingUserSid,
    IWindowsCommandRunner runner,
    IWindowsInstallResourceLookup resourceLookup,
    IWindowsServiceRecoveryInspector recoveryInspector) : IWindowsInstallRollbackOwnershipVerifier
{
    public async Task VerifyAsync(
        AppliedInstallAction applied,
        CancellationToken cancellationToken)
    {
        try
        {
            EnsureWindows();
            var expected = ServiceConfigurationLoader.Validate(
                applied.OwnershipConfiguration ??
                throw new InstallException("install_state_uncertain"));
            var exactMarker = InstallOwnershipMarker.Create(expected.InstallInstanceId);
            if (!HasExactOwnerMarker(applied.Action, exactMarker))
            {
                throw new InstallException("install_state_uncertain");
            }

            var configurationPath = Path.Combine(expected.DataRoot, "service.json");
            if (!File.Exists(configurationPath) || WindowsPathSafety.IsReparse(configurationPath))
            {
                throw new InstallException("install_state_uncertain");
            }

            WindowsInstallAcl.VerifyFile(
                configurationPath,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(signingUserSid));
            var persisted = await new ServiceConfigurationLoader(configurationPath)
                .LoadAsync(cancellationToken).ConfigureAwait(false);
            if (!ServiceConfigurationLoader.MatchesExpected(persisted, expected) ||
                !InstallOwnershipMarker.IsExact(exactMarker, persisted.InstallInstanceId))
            {
                throw new InstallException("install_state_uncertain");
            }

            await VerifyResourceAsync(applied.Action, expected, exactMarker, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InstallException error) when (error.Code == "install_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    private async Task VerifyResourceAsync(
        InstallAction action,
        ServiceConfiguration configuration,
        string exactMarker,
        CancellationToken cancellationToken)
    {
        switch (action)
        {
            case CreateWindowsService service:
                await VerifyServiceAsync(service, cancellationToken).ConfigureAwait(false);
                return;
            case StartAndVerifyWindowsService service:
                await VerifyServiceAsync(
                    CreateExpectedService(service, configuration, exactMarker),
                    cancellationToken).ConfigureAwait(false);
                return;
            case CreateInteractiveLogonTask task:
                await WindowsTaskXml.VerifyRegisteredAsync(task, runner, cancellationToken)
                    .ConfigureAwait(false);
                return;
            case StartInteractiveAgentTask task:
                await WindowsTaskXml.VerifyRegisteredAsync(
                    new CreateInteractiveLogonTask(
                        task.Name,
                        string.Empty,
                        task.SigningUserSid,
                        configuration.ExecutablePath,
                        ["agent", "--background"],
                        "InteractiveToken",
                        Highest: true,
                        RunOnlyIfNetworkAvailable: true,
                        exactMarker),
                    runner,
                    cancellationToken).ConfigureAwait(false);
                return;
            case CreateOwnedFirewallRule firewall:
                WindowsFirewall.Verify(
                    firewall.Name,
                    exactMarker,
                    firewall.TcpPort,
                    allowConfiguredPort: false);
                return;
            default:
                throw new InstallException("install_state_uncertain");
        }
    }

    internal static CreateWindowsService CreateExpectedService(
        StartAndVerifyWindowsService service,
        ServiceConfiguration configuration,
        string exactMarker) =>
        new(
            service.Name,
            "LocalSystem",
            configuration.ExecutablePath,
            ["service"],
            AutomaticDelayedStart: false,
            [5, 15, 60],
            exactMarker);

    private async Task VerifyServiceAsync(
        CreateWindowsService action,
        CancellationToken cancellationToken)
    {
        if (!resourceLookup.ServiceMatchesOwner(action))
        {
            throw new InstallException("install_state_uncertain");
        }

        await WindowsServiceVerification.VerifyAsync(
            action,
            recoveryInspector,
            cancellationToken).ConfigureAwait(false);
    }

    private static bool HasExactOwnerMarker(InstallAction action, string exactMarker) =>
        action switch
        {
            CreateWindowsService service => service.OwnerMarker == exactMarker,
            CreateInteractiveLogonTask task => task.OwnerMarker == exactMarker,
            CreateOwnedFirewallRule firewall => firewall.OwnerMarker == exactMarker,
            StartAndVerifyWindowsService service => service.OwnerMarker == exactMarker,
            StartInteractiveAgentTask task => task.OwnerMarker == exactMarker,
            _ => false,
        };

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("install_state_uncertain");
        }
    }
}
