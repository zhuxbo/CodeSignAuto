using System.Text.Json;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

internal sealed class SetupException : Exception
{
    public SetupException(string code)
        : base(code) => Code = code;

    public string Code { get; }
}

internal sealed record SetupPreflightResult(
    string SimplySignDesktopPath,
    string Pkcs11ModulePath,
    string? SignToolPath);

internal sealed record SetupGeneratedConfiguration(
    string Path,
    AgentConfiguration Configuration);

internal sealed record SetupInstallResourceInspection(
    bool ServiceExists,
    bool AgentTaskExists,
    bool DataRootEntryExists,
    bool ProfileRootEntryExists,
    bool ProgramDataRootSecure,
    bool ProfilesRootSecure,
    bool ServiceControlAvailable,
    bool TaskSchedulerAvailable);

internal static class SetupInstallResourcePreflight
{
    public static void Validate(SetupInstallResourceInspection inspection)
    {
        ArgumentNullException.ThrowIfNull(inspection);
        if (inspection.ServiceExists ||
            inspection.AgentTaskExists ||
            inspection.DataRootEntryExists ||
            inspection.ProfileRootEntryExists)
        {
            throw new SetupException("setup_resource_conflict");
        }

        if (!inspection.ProgramDataRootSecure ||
            !inspection.ProfilesRootSecure ||
            !inspection.ServiceControlAvailable ||
            !inspection.TaskSchedulerAvailable)
        {
            throw new SetupException("resource_preflight_failed");
        }
    }
}

internal interface ISetupPreflight
{
    Task<SetupPreflightResult> InspectAsync(
        string userName,
        CancellationToken cancellationToken);
}

internal interface ISetupProvisioner
{
    Task<ProvisionedAgentUser> ProvisionAsync(
        string userName,
        Func<ProvisionedAgentUser, CancellationToken, Task> afterUserCreated,
        CancellationToken cancellationToken);

    Task RollbackAsync(ProvisionedAgentUser user);
}

internal interface ISetupResourceReservation
{
    string Reserve();

    Task RollbackAsync(string dataRoot);
}

internal interface ISetupConfigurationWriter
{
    Task<SetupGeneratedConfiguration> WriteAsync(
        ProvisionedAgentUser user,
        SetupPreflightResult preflight,
        CancellationToken cancellationToken);

    Task DeleteAsync(SetupGeneratedConfiguration configuration);
}

internal interface ISetupInstaller
{
    Task InstallAsync(
        ProvisionedAgentUser user,
        SetupGeneratedConfiguration configuration,
        TextWriter output,
        CancellationToken cancellationToken);
}

internal sealed class SetupOrchestrator(
    IInstallMediaStager mediaStager,
    ISetupPreflight preflight,
    ISetupResourceReservation resourceReservation,
    ISetupProvisioner provisioner,
    ISetupConfigurationWriter configurationWriter,
    ISetupInstaller installer)
{
    internal const string ManagedUserName = "SimplySignAgent";

    public async Task ExecuteAsync(TextWriter output, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        var mediaPlan = await mediaStager.PlanAsync(cancellationToken).ConfigureAwait(false);
        SetupPreflightResult? inspection = null;
        string? reservedDataRoot = null;
        ProvisionedAgentUser? user = null;
        SetupGeneratedConfiguration? generated = null;
        try
        {
            inspection = await preflight.InspectAsync(ManagedUserName, cancellationToken)
                .ConfigureAwait(false);
            await mediaStager.StageAsync(mediaPlan, cancellationToken).ConfigureAwait(false);
            reservedDataRoot = resourceReservation.Reserve();
            user = await provisioner.ProvisionAsync(
                    ManagedUserName,
                    (createdUser, hookCancellationToken) => mediaStager.AuthorizeAsync(
                        mediaPlan,
                        createdUser.Sid,
                        hookCancellationToken),
                    cancellationToken)
                .ConfigureAwait(false);
            generated = await configurationWriter.WriteAsync(user, inspection, cancellationToken)
                .ConfigureAwait(false);
            await installer.InstallAsync(user, generated, output, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception original)
        {
            var uncertain = OriginalStateIsUncertain(original);
            if (generated is not null)
            {
                try
                {
                    await configurationWriter.DeleteAsync(generated).ConfigureAwait(false);
                }
                catch
                {
                    uncertain = true;
                }
            }

            if (user is not null)
            {
                try
                {
                    await provisioner.RollbackAsync(user).ConfigureAwait(false);
                }
                catch
                {
                    uncertain = true;
                }
            }

            if (reservedDataRoot is not null)
            {
                try
                {
                    await resourceReservation.RollbackAsync(reservedDataRoot).ConfigureAwait(false);
                }
                catch
                {
                    uncertain = true;
                }
            }

            if (!uncertain)
            {
                try
                {
                    await mediaStager.RollbackAsync(mediaPlan).ConfigureAwait(false);
                }
                catch
                {
                    uncertain = true;
                }
            }

            if (uncertain)
            {
                throw new SetupException("setup_state_uncertain");
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }

        try
        {
            await configurationWriter.DeleteAsync(generated).ConfigureAwait(false);
        }
        catch
        {
            await output.WriteLineAsync("setup_temporary_configuration_cleanup_failed")
                .ConfigureAwait(false);
        }

        if (inspection!.SignToolPath is null)
        {
            await output.WriteLineAsync("authenticode_disabled_signtool_missing")
                .ConfigureAwait(false);
        }

        await output.WriteLineAsync("restart_required").ConfigureAwait(false);
    }

    private static bool OriginalStateIsUncertain(Exception error) => error switch
    {
        SetupException setup => string.Equals(
            setup.Code,
            "setup_state_uncertain",
            StringComparison.Ordinal),
        InstallException install => string.Equals(
            install.Code,
            "install_state_uncertain",
            StringComparison.Ordinal),
        ProvisionAgentUserException provision => provision.RollbackStateUncertain,
        _ => false,
    };
}

internal static class SetupAgentConfigurationFactory
{
    public static AgentConfiguration Create(
        ProvisionedAgentUser user,
        SetupPreflightResult preflight,
        string programDataRoot)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(preflight);
        ArgumentException.ThrowIfNullOrWhiteSpace(programDataRoot);
        if (string.IsNullOrWhiteSpace(user.ProfilePath) ||
            string.IsNullOrWhiteSpace(user.OwnerMarker))
        {
            throw new SetupException("profile_readback_failed");
        }

        var dataRoot = Path.GetFullPath(Path.Combine(programDataRoot, "SimplySignAuto"));
        var configuration = new AgentConfiguration(
            user.Sid,
            Path.GetFullPath(Path.Combine(dataRoot, "spool")),
            preflight.SimplySignDesktopPath,
            preflight.Pkcs11ModulePath,
            preflight.SignToolPath is null
                ? null
                : new AgentAuthenticodeConfiguration(preflight.SignToolPath),
            new AgentPdfConfiguration());
        try
        {
            return AgentConfigurationLoader.Validate(configuration);
        }
        catch (AgentConfigurationException error)
        {
            throw new SetupException(error.Code);
        }
    }
}

internal sealed class WindowsSetupPreflight(IWindowsAutoLogonPlatform autoLogonPlatform) : ISetupPreflight
{
    private const string AgentTaskName = "SimplySignAuto.Agent";
    private const string ServiceName = "SimplySignAuto.Service";
    private const string SimplySignDesktopPath =
        @"C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe";
    private const string Pkcs11ModulePath = @"C:\Windows\System32\SimplySignPKCS.dll";

    public async Task<SetupPreflightResult> InspectAsync(
        string userName,
        CancellationToken cancellationToken)
    {
        var userInspection = await autoLogonPlatform.InspectAsync(userName, cancellationToken)
            .ConfigureAwait(false);
        ProvisionAgentUserOrchestrator.ValidateEnvironment(userInspection);
        ProvisionAgentUserOrchestrator.ValidateFreshProvision(userInspection);

        VerifyInstallResources(userName);

        if (!IsPlainFile(SimplySignDesktopPath))
        {
            throw new SetupException("simplysign_desktop_missing");
        }

        if (!IsPlainFile(Pkcs11ModulePath))
        {
            throw new SetupException("simplysign_pkcs11_missing");
        }

        return new SetupPreflightResult(
            SimplySignDesktopPath,
            Pkcs11ModulePath,
            FindSignTool());
    }

    private static string? FindSignTool()
    {
        var root = @"C:\Program Files (x86)\Windows Kits\10\bin";
        if (!Directory.Exists(root) || IsReparsePoint(root))
        {
            return null;
        }

        try
        {
            return Directory.EnumerateDirectories(root)
                .Where(path => !IsReparsePoint(path))
                .OrderByDescending(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
                .Select(path => Path.Combine(path, "x64", "signtool.exe"))
                .Prepend(Path.Combine(root, "x64", "signtool.exe"))
                .FirstOrDefault(IsPlainFile);
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private static void VerifyInstallResources(string userName)
    {
        try
        {
            var programDataRoot = Path.GetFullPath(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            var profilesRoot = WindowsProfilesDirectory.Resolve();
            var dataRoot = Path.GetFullPath(Path.Combine(programDataRoot, "SimplySignAuto"));
            var profileRoot = Path.GetFullPath(Path.Combine(profilesRoot, userName));
            var lookup = new WindowsInstallResourceLookup();
            SetupInstallResourcePreflight.Validate(new SetupInstallResourceInspection(
                lookup.ServiceExists(ServiceName),
                lookup.TaskExists(AgentTaskName),
                WindowsPathSafety.EntryExists(dataRoot),
                WindowsPathSafety.EntryExists(profileRoot),
                IsTrustedAnchor(programDataRoot),
                IsTrustedAnchor(profilesRoot),
                IsPlainFile(Path.Combine(Environment.SystemDirectory, "sc.exe")),
                IsPlainFile(Path.Combine(Environment.SystemDirectory, "schtasks.exe"))));
        }
        catch (SetupException)
        {
            throw;
        }
        catch (InstallException error)
        {
            throw new SetupException(error.Code);
        }
        catch
        {
            throw new SetupException("resource_preflight_failed");
        }
    }

    private static bool IsTrustedAnchor(string path)
    {
        try
        {
            WindowsNoFollowSecurity.VerifyTrustedAnchor(
                WindowsNoFollowSecurity.ReadDirectory(path));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsPlainFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            var file = new FileInfo(path);
            file.Refresh();
            return file.LinkTarget is null &&
                (file.Attributes & FileAttributes.ReparsePoint) == 0;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
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

internal sealed class WindowsSetupProvisioner(ProvisionAgentUserOrchestrator orchestrator) : ISetupProvisioner
{
    public Task<ProvisionedAgentUser> ProvisionAsync(
        string userName,
        Func<ProvisionedAgentUser, CancellationToken, Task> afterUserCreated,
        CancellationToken cancellationToken) =>
        orchestrator.ExecuteAsync(
            new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, userName),
            afterUserCreated,
            cancellationToken);

    public Task RollbackAsync(ProvisionedAgentUser user) =>
        orchestrator.RollbackOwnedProvisionAsync(user);
}

internal sealed class WindowsSetupResourceReservation : ISetupResourceReservation
{
    public string Reserve()
    {
        var programData = Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var dataRoot = Path.GetFullPath(Path.Combine(programData, "SimplySignAuto"));
        try
        {
            new AtomicProtectedDirectoryCreator(new WindowsAtomicProtectedDirectoryOperations())
                .Create(programData, dataRoot);
            return dataRoot;
        }
        catch (InstallException error)
        {
            throw new SetupException(error.Code == "uninstall_path_invalid"
                ? "setup_resource_conflict"
                : "setup_state_uncertain");
        }
    }

    public Task RollbackAsync(string dataRoot)
    {
        try
        {
            if (!WindowsNoFollowSecurity.DirectoryEntryExists(dataRoot))
            {
                throw new SetupException("setup_state_uncertain");
            }

            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadDirectory(dataRoot),
                directory: true);
            if (Directory.EnumerateFileSystemEntries(dataRoot).Any())
            {
                throw new SetupException("setup_state_uncertain");
            }

            Directory.Delete(dataRoot, recursive: false);
            if (WindowsNoFollowSecurity.DirectoryEntryExists(dataRoot))
            {
                throw new SetupException("setup_state_uncertain");
            }

            return Task.CompletedTask;
        }
        catch (SetupException)
        {
            throw;
        }
        catch
        {
            throw new SetupException("setup_state_uncertain");
        }
    }
}

internal sealed class TemporarySetupConfigurationWriter : ISetupConfigurationWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public async Task<SetupGeneratedConfiguration> WriteAsync(
        ProvisionedAgentUser user,
        SetupPreflightResult preflight,
        CancellationToken cancellationToken)
    {
        var configuration = SetupAgentConfigurationFactory.Create(
            user,
            preflight,
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var instanceId = user.OwnerMarker!["SimplySignAuto/v1/".Length..];
        var path = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            $"SimplySignAuto.setup.{instanceId}.agent.json"));
        if (File.Exists(path))
        {
            throw new SetupException("setup_configuration_conflict");
        }

        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(configuration, SerializerOptions);
            await using (var stream = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            var readback = await new AgentConfigurationLoader(path)
                .LoadAsync(cancellationToken).ConfigureAwait(false);
            if (readback != configuration)
            {
                throw new SetupException("setup_configuration_readback_failed");
            }

            return new SetupGeneratedConfiguration(path, configuration);
        }
        catch (Exception original)
        {
            try
            {
                File.Delete(path);
            }
            catch
            {
                throw new SetupException("setup_state_uncertain");
            }

            if (original is SetupException)
            {
                throw;
            }

            throw new SetupException("setup_configuration_write_failed");
        }
    }

    public Task DeleteAsync(SetupGeneratedConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        try
        {
            File.Delete(configuration.Path);
            if (File.Exists(configuration.Path))
            {
                throw new SetupException("setup_state_uncertain");
            }

            return Task.CompletedTask;
        }
        catch (SetupException)
        {
            throw;
        }
        catch
        {
            throw new SetupException("setup_state_uncertain");
        }
    }
}

internal sealed class ExistingInstallSetupInstaller(
    IInstallEnvironment environment,
    Func<string, IInstallActionExecutor> executorFactory,
    IApiTokenGenerator tokenGenerator) : ISetupInstaller
{
    public async Task InstallAsync(
        ProvisionedAgentUser user,
        SetupGeneratedConfiguration configuration,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var plan = await new InstallPlanner(environment)
            .PlanAsync(
                new InstallOptions(
                    user.AccountName,
                    configuration.Path,
                    ListenPort: 7080,
                    OpenFirewall: false),
                cancellationToken)
            .ConfigureAwait(false);
        _ = await new InstallOrchestrator(executorFactory(plan.Account.Sid), tokenGenerator)
            .ExecuteAsync(plan, output, cancellationToken).ConfigureAwait(false);
    }
}

public static class SetupCommand
{
    public static bool TryParse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Length == 0;
    }

    public static async Task<int> ExecuteAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        if (!TryParse(args))
        {
            await error.WriteLineAsync("setup_arguments_invalid").ConfigureAwait(false);
            return 2;
        }

        using var lease = new ServiceConfigurationWriterLeaseFactory().TryAcquire();
        if (lease is null)
        {
            await error.WriteLineAsync("setup_busy").ConfigureAwait(false);
            return 1;
        }

        try
        {
            var upgrade = await WindowsUpgradeTransaction.TryCreateAsync(cancellationToken)
                .ConfigureAwait(false);
            if (upgrade is not null)
            {
                await new UpgradeOrchestrator()
                    .ExecuteAsync(upgrade, output, cancellationToken)
                    .ConfigureAwait(false);
                return 0;
            }

            var platform = new WindowsAutoLogonPlatform();
            var provisionOrchestrator = new ProvisionAgentUserOrchestrator(
                platform,
                new CryptographicAgentUserPasswordGenerator(),
                new RandomProvisionOwnerGenerator());
            await new SetupOrchestrator(
                    new WindowsInstallMediaStager(),
                    new WindowsSetupPreflight(platform),
                    new WindowsSetupResourceReservation(),
                    new WindowsSetupProvisioner(provisionOrchestrator),
                    new TemporarySetupConfigurationWriter(),
                    new ExistingInstallSetupInstaller(
                        new WindowsInstallEnvironment(platform),
                        sid => new WindowsInstallActionExecutor(sid),
                        new RandomApiTokenGenerator()))
                .ExecuteAsync(output, cancellationToken).ConfigureAwait(false);
            return 0;
        }
        catch (SetupException setupError)
        {
            await error.WriteLineAsync(FormatFailure(setupError.Code)).ConfigureAwait(false);
            return 1;
        }
        catch (ProvisionAgentUserException provisionError)
        {
            await error.WriteLineAsync(ProvisionAgentUserCommand.FormatFailure(provisionError))
                .ConfigureAwait(false);
            return 1;
        }
        catch (AgentConfigurationException configurationError)
        {
            await error.WriteLineAsync(configurationError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (ServiceConfigurationException configurationError)
        {
            await error.WriteLineAsync(configurationError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (InstallException installError)
        {
            await error.WriteLineAsync(installError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 1;
        }
        catch
        {
            await error.WriteLineAsync("setup_failed").ConfigureAwait(false);
            return 1;
        }
    }

    internal static string FormatFailure(string code) => code switch
    {
        "simplysign_desktop_missing" =>
            "simplysign_desktop_missing install_simplysign_desktop_required",
        "simplysign_pkcs11_missing" =>
            "simplysign_pkcs11_missing install_simplysign_desktop_required",
        _ => code,
    };
}
