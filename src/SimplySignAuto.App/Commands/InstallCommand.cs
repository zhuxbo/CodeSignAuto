using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SimplySignAuto.App.Manual;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

public sealed class InstallException : Exception
{
    public InstallException(string code)
        : base(code) => Code = code;

    public string Code { get; }
}

public sealed record InstallOptions(
    string SigningUser,
    string AgentConfigurationPath,
    int ListenPort,
    bool OpenFirewall);

public sealed record ResolvedSigningAccount(
    string AccountName,
    string Sid,
    string LocalApplicationDataPath);

public sealed record InstallPaths(
    string DataRoot,
    string JobsRoot,
    string ToolsRoot,
    string LogsRoot,
    string SpoolRoot,
    string InstallationReceiptPath,
    string ServiceConfigurationPath,
    string JobsDatabasePath,
    string InstallTokenPath,
    string AgentDirectory,
    string AgentConfigurationPath,
    string ExecutablePath);

public enum InstallAclProfile
{
    AdministratorsOnly,
    SigningUserModify,
    SigningUserRead,
    SigningUserData,
}

public enum InstallContent
{
    Empty,
    ServiceConfiguration,
    AgentConfiguration,
    InstallToken,
    InstallationReceipt,
}

public abstract record InstallAction;

public sealed record CreateProtectedDirectory(string Path, InstallAclProfile Acl) : InstallAction;

public sealed record WriteProtectedFile(string Path, InstallAclProfile Acl, InstallContent Content) : InstallAction;

public sealed record ProductUninstallRegistration(
    string ExecutablePath,
    string DisplayName,
    string DisplayVersion,
    string Publisher,
    string InstallLocation,
    string DisplayIcon,
    string UninstallString,
    string OwnerMarker)
{
    public static ProductUninstallRegistration Create(
        string executablePath,
        string displayVersion,
        string ownerMarker)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayVersion);
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerMarker);
        var canonicalExecutable = Path.GetFullPath(executablePath);
        var installLocation = Path.GetDirectoryName(canonicalExecutable)
            ?? throw new InstallException("install_arguments_invalid");
        return new ProductUninstallRegistration(
            canonicalExecutable,
            "SimplySignAuto",
            displayVersion,
            "SimplySignAuto",
            installLocation,
            $"\"{canonicalExecutable}\",0",
            $"\"{canonicalExecutable}\" uninstall",
            ownerMarker);
    }
}

public sealed record RegisterProductUninstall(ProductUninstallRegistration Registration) : InstallAction;

public sealed record CreateDesktopShortcut(
    string Path,
    string TargetPath,
    string OwnerMarker) : InstallAction;

public sealed record CreateWindowsService(
    string Name,
    string Account,
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    bool AutomaticDelayedStart,
    IReadOnlyList<int> RestartDelaysSeconds,
    string OwnerMarker) : InstallAction;

public sealed record CreateInteractiveLogonTask(
    string Name,
    string AccountName,
    string SigningUserSid,
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    string LogonType,
    bool Highest,
    bool RunOnlyIfNetworkAvailable,
    string OwnerMarker) : InstallAction
{
    public int RestartIntervalSeconds => 60;

    public int RestartCount => 3;
}

public sealed record CreateOwnedFirewallRule(
    string Name,
    string OwnerMarker,
    int TcpPort) : InstallAction;

public sealed record VerifyInstallSecurity(
    InstallPaths Paths,
    bool FirewallExpected,
    int FirewallPort,
    string OwnerMarker) : InstallAction;

public sealed record ManualInstallPaths(
    string DataRoot,
    string InstallationReceiptPath,
    string DesktopShortcutPath,
    string ExecutablePath);

public sealed record VerifyManualInstallSecurity(
    ManualInstallPaths Paths,
    InstallationReceipt Receipt,
    ProductUninstallRegistration Registration) : InstallAction;

public sealed record StartAndVerifyWindowsService(
    string Name,
    string OwnerMarker) : InstallAction;

public sealed record StartInteractiveAgentTask(
    string Name,
    string SigningUserSid,
    string OtpPath,
    string OwnerMarker) : InstallAction;

public sealed record AgentTaskStartStatus(
    bool StartedForActiveSession,
    bool ActivationRequired);

public sealed record InstallPlan(
    InstallOptions Options,
    ResolvedSigningAccount Account,
    AgentConfiguration AgentConfiguration,
    InstallPaths Paths,
    string InstallInstanceId,
    IReadOnlyList<InstallAction> Actions);

public sealed record ManualInstallPlan(
    InstallationReceipt Receipt,
    ManualInstallPaths Paths,
    IReadOnlyList<InstallAction> Actions);

public interface IManualInstallEnvironment
{
    bool IsWindows { get; }

    string ExecutablePath { get; }

    string ProgramDataRoot { get; }

    string CommonDesktopDirectory { get; }

    string SigningUserSid { get; }

    string LocalApplicationDataPath { get; }

    string InstallInstanceId { get; }
}

public sealed class ManualInstallPlanner(IManualInstallEnvironment environment)
{
    public ManualInstallPlan Plan()
    {
        ArgumentNullException.ThrowIfNull(environment);
        if (!environment.IsWindows)
        {
            throw new InstallException("windows_required");
        }

        if (!CanonicalWindowsSid.IsValid(environment.SigningUserSid) ||
            !InstallOwnershipMarker.IsInstanceId(environment.InstallInstanceId))
        {
            throw new InstallException("install_arguments_invalid");
        }

        var executablePath = Canonical(environment.ExecutablePath);
        var dataRoot = Canonical(Path.Combine(environment.ProgramDataRoot, "SimplySignAuto"));
        var userDataRoot = ManualRuntimePaths
            .ForLocalApplicationData(environment.LocalApplicationDataPath)
            .DataRoot;
        var commonDesktop = Canonical(environment.CommonDesktopDirectory);
        if (!Path.IsPathFullyQualified(commonDesktop) ||
            InstallControlledPath.IsSameOrDescendant(dataRoot, executablePath) ||
            InstallControlledPath.IsSameOrDescendant(userDataRoot, executablePath))
        {
            throw new InstallException("install_arguments_invalid");
        }

        var receipt = InstallationReceipt.ForManual(
            environment.InstallInstanceId,
            environment.SigningUserSid,
            executablePath,
            userDataRoot);
        var marker = InstallOwnershipMarker.Create(receipt.InstallInstanceId);
        var registration = ProductUninstallRegistration.Create(
            executablePath,
            SimplySignAuto.App.ApplicationVersion.ReadIdentity(typeof(ManualInstallPlanner).Assembly),
            marker);
        var paths = new ManualInstallPaths(
            dataRoot,
            Canonical(Path.Combine(dataRoot, "install.json")),
            Canonical(Path.Combine(commonDesktop, "SimplySignAuto.lnk")),
            executablePath);
        InstallAction[] actions =
        [
            new WriteProtectedFile(
                paths.InstallationReceiptPath,
                InstallAclProfile.AdministratorsOnly,
                InstallContent.InstallationReceipt),
            new RegisterProductUninstall(registration),
            new CreateDesktopShortcut(paths.DesktopShortcutPath, executablePath, marker),
            new VerifyManualInstallSecurity(paths, receipt, registration),
        ];
        return new ManualInstallPlan(receipt, paths, actions);
    }

    private static string Canonical(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new InstallException("install_arguments_invalid");
        }

        var canonical = Path.GetFullPath(path);
        if (!string.Equals(path, canonical, PathComparison()))
        {
            throw new InstallException("install_arguments_invalid");
        }

        return canonical;
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public interface IInstallInstanceIdGenerator
{
    string Generate();
}

public sealed class RandomInstallInstanceIdGenerator : IInstallInstanceIdGenerator
{
    public string Generate() => Guid.NewGuid().ToString("N");
}

public interface IInstallEnvironment
{
    bool IsWindows { get; }

    string ExecutablePath { get; }

    string ProgramDataRoot { get; }

    string CommonDesktopDirectory { get; }

    Task<ResolvedSigningAccount> ResolveSigningAccountAsync(
        string account,
        CancellationToken cancellationToken);

    Task ValidateAutomaticLogonAsync(
        ResolvedSigningAccount account,
        CancellationToken cancellationToken) => Task.CompletedTask;

    Task<string?> GetProvisionedInstallInstanceIdAsync(
        ResolvedSigningAccount account,
        CancellationToken cancellationToken) => Task.FromResult<string?>(null);

    void ValidateExecutableSecurity(ResolvedSigningAccount account) { }
}

public sealed class InstallPlanner
{
    private readonly IInstallEnvironment _environment;

    public InstallPlanner(IInstallEnvironment environment) =>
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));

    public async Task<InstallPlan> PlanAsync(
        InstallOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!_environment.IsWindows)
        {
            throw new InstallException("windows_required");
        }

        ValidateOptions(options);
        var account = await _environment.ResolveSigningAccountAsync(
            options.SigningUser,
            cancellationToken).ConfigureAwait(false);
        await _environment.ValidateAutomaticLogonAsync(account, cancellationToken)
            .ConfigureAwait(false);
        _environment.ValidateExecutableSecurity(account);
        var configuration = await new AgentConfigurationLoader(options.AgentConfigurationPath)
            .LoadAsync(cancellationToken).ConfigureAwait(false);

        var dataRoot = Canonical(Path.Combine(_environment.ProgramDataRoot, "SimplySignAuto"));
        var spoolRoot = Canonical(Path.Combine(dataRoot, "spool"));
        if (!string.Equals(account.AccountName, options.SigningUser, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(configuration.SigningUserSid, account.Sid, StringComparison.Ordinal) ||
            !PathEquals(configuration.SpoolPath, spoolRoot))
        {
            throw new InstallException("agent_configuration_mismatch");
        }

        var agentDirectory = Canonical(Path.Combine(
            account.LocalApplicationDataPath,
            "SimplySignAuto"));
        var paths = new InstallPaths(
            dataRoot,
            Canonical(Path.Combine(dataRoot, "jobs")),
            Canonical(Path.Combine(dataRoot, "tools")),
            Canonical(Path.Combine(dataRoot, "logs")),
            spoolRoot,
            Canonical(Path.Combine(dataRoot, "install.json")),
            Canonical(Path.Combine(dataRoot, "service.json")),
            Canonical(Path.Combine(dataRoot, "jobs.db")),
            Canonical(Path.Combine(dataRoot, "install-token.txt")),
            agentDirectory,
            Canonical(Path.Combine(agentDirectory, "agent.json")),
            Canonical(_environment.ExecutablePath));
        if (InstallControlledPath.IsSameOrDescendant(paths.DataRoot, paths.ExecutablePath) ||
            InstallControlledPath.IsSameOrDescendant(paths.AgentDirectory, paths.ExecutablePath))
        {
            throw new InstallException("install_arguments_invalid");
        }

        var installInstanceId = await _environment
            .GetProvisionedInstallInstanceIdAsync(account, cancellationToken)
            .ConfigureAwait(false);
        if (installInstanceId is null || !InstallOwnershipMarker.IsInstanceId(installInstanceId))
        {
            throw new InstallException("autologon_not_ready");
        }

        var exactOwnerMarker = InstallOwnershipMarker.Create(installInstanceId);
        var commonDesktop = Canonical(_environment.CommonDesktopDirectory);
        if (!Path.IsPathFullyQualified(commonDesktop) ||
            !string.Equals(Path.GetFullPath(commonDesktop), commonDesktop, PathComparison()))
        {
            throw new InstallException("install_arguments_invalid");
        }
        var productRegistration = ProductUninstallRegistration.Create(
            paths.ExecutablePath,
            SimplySignAuto.App.ApplicationVersion.ReadIdentity(typeof(InstallPlanner).Assembly),
            exactOwnerMarker);
        var actions = new List<InstallAction>
        {
            new RegisterProductUninstall(productRegistration),
            new CreateDesktopShortcut(
                Canonical(Path.Combine(commonDesktop, "SimplySignAuto.lnk")),
                paths.ExecutablePath,
                exactOwnerMarker),
        };
        actions.AddRange(
        [
            new CreateProtectedDirectory(paths.DataRoot, InstallAclProfile.AdministratorsOnly),
            new CreateProtectedDirectory(paths.JobsRoot, InstallAclProfile.SigningUserModify),
            new CreateProtectedDirectory(paths.ToolsRoot, InstallAclProfile.SigningUserRead),
            new CreateProtectedDirectory(paths.LogsRoot, InstallAclProfile.AdministratorsOnly),
            new CreateProtectedDirectory(paths.SpoolRoot, InstallAclProfile.SigningUserRead),
            new CreateProtectedDirectory(paths.AgentDirectory, InstallAclProfile.SigningUserData),
            new WriteProtectedFile(paths.InstallationReceiptPath, InstallAclProfile.AdministratorsOnly, InstallContent.InstallationReceipt),
            new WriteProtectedFile(paths.ServiceConfigurationPath, InstallAclProfile.AdministratorsOnly, InstallContent.ServiceConfiguration),
            new WriteProtectedFile(paths.JobsDatabasePath, InstallAclProfile.AdministratorsOnly, InstallContent.Empty),
            new WriteProtectedFile(paths.AgentConfigurationPath, InstallAclProfile.SigningUserRead, InstallContent.AgentConfiguration),
            new WriteProtectedFile(paths.InstallTokenPath, InstallAclProfile.AdministratorsOnly, InstallContent.InstallToken),
            new CreateWindowsService(
                "SimplySignAuto.Service",
                "LocalSystem",
                paths.ExecutablePath,
                ["service"],
                AutomaticDelayedStart: false,
                [5, 15, 60],
                exactOwnerMarker),
            new CreateInteractiveLogonTask(
                "SimplySignAuto.Agent",
                account.AccountName,
                account.Sid,
                paths.ExecutablePath,
                ["agent", "--background"],
                "InteractiveToken",
                Highest: true,
                RunOnlyIfNetworkAvailable: true,
                exactOwnerMarker),
        ]);
        if (options.OpenFirewall)
        {
            actions.Add(new CreateOwnedFirewallRule(
                "SimplySignAuto API",
                exactOwnerMarker,
                options.ListenPort));
        }

        actions.Add(new VerifyInstallSecurity(
            paths,
            options.OpenFirewall,
            options.ListenPort,
            exactOwnerMarker));
        actions.Add(new StartAndVerifyWindowsService("SimplySignAuto.Service", exactOwnerMarker));
        actions.Add(new StartInteractiveAgentTask(
            "SimplySignAuto.Agent",
            account.Sid,
            Canonical(Path.Combine(paths.AgentDirectory, "otp.dat")),
            exactOwnerMarker));
        return new InstallPlan(
            options,
            account,
            configuration,
            paths,
            installInstanceId,
            actions);
    }

    private static void ValidateOptions(InstallOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SigningUser) ||
            !Path.IsPathFullyQualified(options.AgentConfigurationPath) ||
            !string.Equals(Path.GetFullPath(options.AgentConfigurationPath), options.AgentConfigurationPath, PathComparison()) ||
            options.ListenPort is < 1 or > 65535)
        {
            throw new InstallException("install_arguments_invalid");
        }
    }

    private static string Canonical(string path) => Path.GetFullPath(path);

    private static bool PathEquals(string left, string right) =>
        string.Equals(left, right, PathComparison());

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public static class InstallCommand
{
    public static async Task<int> ExecuteAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        using var lease = new ServiceConfigurationWriterLeaseFactory().TryAcquire();
        if (lease is null)
        {
            await error.WriteLineAsync("install_busy").ConfigureAwait(false);
            return 1;
        }

        return await ExecuteAsync(
                args,
                output,
                error,
                new WindowsInstallEnvironment(),
                signingUserSid => new WindowsInstallActionExecutor(signingUserSid),
                new RandomApiTokenGenerator(),
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async Task<int> ExecuteAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        IInstallEnvironment environment,
        Func<string, IInstallActionExecutor> executorFactory,
        IApiTokenGenerator tokenGenerator,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(executorFactory);
        ArgumentNullException.ThrowIfNull(tokenGenerator);
        if (!TryParse(args, out var options))
        {
            await error.WriteLineAsync("install_arguments_invalid").ConfigureAwait(false);
            return 2;
        }

        try
        {
            var plan = await new InstallPlanner(environment)
                .PlanAsync(options!, cancellationToken).ConfigureAwait(false);
            await new InstallOrchestrator(
                    executorFactory(plan.Account.Sid),
                    tokenGenerator)
                .ExecuteAsync(plan, output, cancellationToken).ConfigureAwait(false);
            return 0;
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
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            await error.WriteLineAsync("install_failed").ConfigureAwait(false);
            return 1;
        }
    }

    internal static bool TryParse(string[] args, out InstallOptions? options)
    {
        options = null;
        string? signingUser = null;
        string? agentConfiguration = null;
        var port = 7080;
        var openFirewall = false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index++)
        {
            var name = args[index];
            if (!seen.Add(name))
            {
                return false;
            }

            if (name == "--open-firewall")
            {
                openFirewall = true;
                continue;
            }

            if (name is not ("--signing-user" or "--agent-config" or "--listen-port") ||
                ++index >= args.Length)
            {
                return false;
            }

            var value = args[index];
            switch (name)
            {
                case "--signing-user":
                    signingUser = value;
                    break;
                case "--agent-config":
                    agentConfiguration = value;
                    break;
                case "--listen-port" when int.TryParse(
                    value,
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var parsed):
                    port = parsed;
                    break;
                default:
                    return false;
            }
        }

        if (signingUser is null || agentConfiguration is null)
        {
            return false;
        }

        options = new InstallOptions(
            signingUser,
            agentConfiguration,
            port,
            openFirewall);
        return true;
    }
}

public interface IApiTokenGenerator
{
    byte[] Generate();
}

public sealed class RandomApiTokenGenerator : IApiTokenGenerator
{
    public byte[] Generate() => RandomNumberGenerator.GetBytes(32);
}

public sealed record InstallExecutionMaterial(
    byte[] ServiceConfiguration,
    byte[] AgentConfiguration,
    byte[] InstallToken,
    byte[] InstallationReceipt)
{
    public byte[] GetFile(InstallContent content) => content switch
    {
        InstallContent.Empty => [],
        InstallContent.ServiceConfiguration => ServiceConfiguration,
        InstallContent.AgentConfiguration => AgentConfiguration,
        InstallContent.InstallToken => InstallToken,
        InstallContent.InstallationReceipt => InstallationReceipt,
        _ => throw new ArgumentOutOfRangeException(nameof(content)),
    };
}

public sealed record AppliedInstallAction(
    InstallAction Action,
    bool Created,
    object? RollbackState,
    ServiceConfiguration? OwnershipConfiguration = null);

public interface IInstallActionExecutor
{
    Task<AppliedInstallAction> ApplyAsync(
        InstallAction action,
        InstallExecutionMaterial material,
        CancellationToken cancellationToken);

    Task RollbackAsync(
        AppliedInstallAction applied,
        CancellationToken cancellationToken);
}

public sealed record InstallResult(string ApiToken);

public sealed class InstallOrchestrator(
    IInstallActionExecutor executor,
    IApiTokenGenerator tokenGenerator)
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public async Task<InstallResult> ExecuteAsync(
        InstallPlan plan,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(output);
        var tokenBytes = tokenGenerator.Generate();
        if (tokenBytes.Length != 32)
        {
            throw new InstallException("token_generation_failed");
        }

        var token = Convert.ToBase64String(tokenBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var serviceConfiguration = BuildServiceConfiguration(plan, token);
        var installationReceipt = InstallationReceipt.ForService(serviceConfiguration);
        var material = new InstallExecutionMaterial(
            JsonSerializer.SerializeToUtf8Bytes(serviceConfiguration, SerializerOptions),
            JsonSerializer.SerializeToUtf8Bytes(plan.AgentConfiguration, SerializerOptions),
            Encoding.UTF8.GetBytes(token + Environment.NewLine),
            InstallationReceiptCodec.Serialize(installationReceipt));
        var applied = new List<AppliedInstallAction>();
        try
        {
            foreach (var action in plan.Actions)
            {
                var result = await executor.ApplyAsync(action, material, cancellationToken).ConfigureAwait(false);
                applied.Add(result with { OwnershipConfiguration = serviceConfiguration });
            }
        }
        catch (Exception original)
        {
            var stateUncertain = false;
            foreach (var action in applied.AsEnumerable().Reverse())
            {
                try
                {
                    await executor.RollbackAsync(action, CancellationToken.None).ConfigureAwait(false);
                }
                catch (InstallException rollbackError) when (
                    rollbackError.Code == "install_state_uncertain")
                {
                    stateUncertain = true;
                }
                catch
                {
                    // Continue rolling back independent resources.
                    stateUncertain = true;
                }
            }

            if (stateUncertain)
            {
                throw new InstallException("install_state_uncertain");
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }

        await output.WriteLineAsync($"API token (copy once): {token}").ConfigureAwait(false);
        await output.WriteLineAsync($"A protected copy is at {plan.Paths.InstallTokenPath}; delete it after copying.").ConfigureAwait(false);
        var agentStart = applied
            .Select(result => result.RollbackState)
            .OfType<AgentTaskStartStatus>()
            .SingleOrDefault();
        if (agentStart is { StartedForActiveSession: false })
        {
            await output.WriteLineAsync(
                "The signing user has no active interactive session; readiness is unavailable until that user logs on.")
                .ConfigureAwait(false);
        }
        else if (agentStart is { ActivationRequired: true })
        {
            await output.WriteLineAsync(
                "The agent task was triggered, but activation is required; readiness is unavailable until OTP is configured.")
                .ConfigureAwait(false);
        }

        return new InstallResult(token);
    }

    private static ServiceConfiguration BuildServiceConfiguration(InstallPlan plan, string token)
    {
        return ServiceConfigurationLoader.Validate(new ServiceConfiguration(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant(),
            plan.Account.Sid,
            plan.Paths.DataRoot,
            plan.Paths.SpoolRoot,
            plan.Options.ListenPort,
            "SimplySignAuto/v1",
            plan.InstallInstanceId,
            plan.Paths.ExecutablePath,
            plan.Paths.AgentConfigurationPath,
            24));
    }
}

public sealed class ManualInstallOrchestrator(IInstallActionExecutor executor)
{
    public async Task ExecuteAsync(
        ManualInstallPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var material = new InstallExecutionMaterial(
            ServiceConfiguration: [],
            AgentConfiguration: [],
            InstallToken: [],
            InstallationReceipt: InstallationReceiptCodec.Serialize(plan.Receipt));
        var applied = new List<AppliedInstallAction>();
        try
        {
            foreach (var action in plan.Actions)
            {
                applied.Add(await executor.ApplyAsync(action, material, cancellationToken)
                    .ConfigureAwait(false));
            }
        }
        catch (Exception original)
        {
            var stateUncertain = false;
            foreach (var action in applied.AsEnumerable().Reverse())
            {
                try
                {
                    await executor.RollbackAsync(action, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    stateUncertain = true;
                }
            }

            if (stateUncertain)
            {
                throw new InstallException("install_state_uncertain");
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }
    }
}
