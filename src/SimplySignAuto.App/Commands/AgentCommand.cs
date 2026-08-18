using System.Text.Json;
using System.Text.Json.Serialization;
using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Core.Security;

namespace SimplySignAuto.App.Commands;

public sealed record AgentAuthenticodeConfiguration(
    string SignToolPath,
    string TimestampUrl = "http://time.certum.pl/");

public sealed record AgentPdfConfiguration(
    string TimestampUrl = "http://time.certum.pl/");

public sealed record AgentConfiguration(
    string SigningUserSid,
    string SpoolPath,
    string SimplySignDesktopPath,
    string Pkcs11ModulePath,
    AgentAuthenticodeConfiguration? Authenticode,
    AgentPdfConfiguration? Pdf);

public class AgentConfigurationException : Exception
{
    public AgentConfigurationException(string code)
        : base(code)
    {
        Code = code;
    }

    public AgentConfigurationException(string code, Exception innerException)
        : base(code, innerException)
    {
        Code = code;
    }

    public string Code { get; }
}

public interface IAgentConfigurationLoader
{
    Task<AgentConfiguration> LoadAsync(CancellationToken cancellationToken);
}

public interface IAgentRunner
{
    Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken);
}

public interface IDesktopAgentRunner
{
    Task RunAsync(
        AgentConfiguration configuration,
        IAgentLifetime lifetime,
        CancellationToken cancellationToken);
}

public sealed class AgentConfigurationLoader : IAgentConfigurationLoader
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly string _path;

    public AgentConfigurationLoader()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SimplySignAuto",
            "agent.json"))
    {
    }

    public AgentConfigurationLoader(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async Task<AgentConfiguration> LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var json = await File.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false);
            StrictJson.RejectDuplicatePropertiesAndSecretShapes(json);
            var configuration = JsonSerializer.Deserialize<AgentConfiguration>(json, SerializerOptions);
            return Validate(configuration);
        }
        catch (FileNotFoundException error)
        {
            throw new AgentConfigurationException("agent_configuration_missing", error);
        }
        catch (DirectoryNotFoundException error)
        {
            throw new AgentConfigurationException("agent_configuration_missing", error);
        }
        catch (AgentConfigurationException)
        {
            throw;
        }
        catch (Exception error) when (
            error is JsonException
                or IOException
                or UnauthorizedAccessException
                or ArgumentException
                or NotSupportedException
                or SimplySignException)
        {
            throw new AgentConfigurationException("agent_configuration_invalid", error);
        }
    }

    internal static AgentConfiguration Validate(AgentConfiguration? configuration)
    {
        if (configuration is null ||
            !CanonicalWindowsSid.IsValid(configuration.SigningUserSid) ||
            !IsCanonicalAbsolutePath(configuration.SpoolPath) ||
            !IsCanonicalExecutable(configuration.SimplySignDesktopPath, "SimplySignDesktop.exe") ||
            !IsCanonicalAbsolutePath(configuration.Pkcs11ModulePath) ||
            configuration.Authenticode is null && configuration.Pdf is null)
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }

        if (configuration.Authenticode is { } authenticode)
        {
            if (!IsAcceptedCertumTimestamp(authenticode.TimestampUrl))
            {
                throw new AgentConfigurationException("agent_configuration_invalid");
            }

            _ = AuthenticodeSigningProfile.Create(
                authenticode.SignToolPath,
                authenticode.TimestampUrl);
        }

        if (configuration.Pdf is { } pdf)
        {
            if (!IsAcceptedCertumTimestamp(pdf.TimestampUrl))
            {
                throw new AgentConfigurationException("agent_configuration_invalid");
            }

            _ = PdfSigningProfile.Create(pdf.TimestampUrl);
        }

        return configuration;
    }

    private static bool IsCanonicalAbsolutePath(string? path)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(path) &&
                !path.Any(char.IsControl) &&
                Path.IsPathFullyQualified(path) &&
                string.Equals(Path.GetFullPath(path), path, StringComparison.Ordinal);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsCanonicalExecutable(string? path, string expectedName) =>
        IsCanonicalAbsolutePath(path) &&
        string.Equals(Path.GetFileName(path), expectedName, StringComparison.OrdinalIgnoreCase);

    private static bool IsAcceptedCertumTimestamp(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        string.Equals(uri.AbsoluteUri, "http://time.certum.pl/", StringComparison.Ordinal);
}

public interface IDesktopManagementSource
{
    IAgentManagementClient Management { get; }
}

public interface IDesktopLocalJobSource
{
    ILocalJobClient LocalJobs { get; }
}

public sealed class DefaultAgentRunner :
    IAgentRunner,
    IDesktopAgentRunner,
    IDesktopManagementSource,
    IDesktopLocalJobSource
{
    private readonly IOtpStore _otpStore;
    private readonly AgentManagementBridge _management;
    private readonly IAgentDiagnosticSink _diagnostics;

    public DefaultAgentRunner(TextWriter? diagnosticWriter = null)
    {
        _otpStore = new DpapiOtpStore();
        _management = new AgentManagementBridge(otpStore: _otpStore);
        _diagnostics = new TextWriterAgentDiagnosticSink(diagnosticWriter ?? Console.Error).Safe();
    }

    public IAgentManagementClient Management => _management;

    public ILocalJobClient LocalJobs => _management;

    public async Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken)
    {
        using var lifetime = new WindowsAgentLifetime();
        await RunAsync(configuration, lifetime, cancellationToken).ConfigureAwait(false);
    }

    public async Task RunAsync(
        AgentConfiguration configuration,
        IAgentLifetime lifetime,
        CancellationToken cancellationToken)
    {
        configuration = AgentConfigurationLoader.Validate(configuration);
        ArgumentNullException.ThrowIfNull(lifetime);
        var resolver = DefaultAgentSigningBackendFactory.CreatePdfToolResolver(configuration);
        _ = await ResolveOptionalPdfToolAtStartupAsync(configuration, resolver, cancellationToken)
            .ConfigureAwait(false);
        await using var sessions = new AgentRuntimePipeSessionFactory(
            configuration,
            _otpStore,
            _management,
            _diagnostics);
        var host = new AgentHost(
            new InteractiveSessionGuard(),
            _otpStore,
            new LocalAgentInstanceLockFactory(),
            sessions,
            lifetime,
            new SystemAgentShutdownWaiter(),
            new SystemAgentReconnectDelay(),
            _diagnostics);
        await host.RunAsync(configuration.SigningUserSid, cancellationToken).ConfigureAwait(false);
    }

    internal static Task<InstalledPdfToolResolution> ResolveOptionalPdfToolAtStartupAsync(
        AgentConfiguration configuration,
        IInstalledPdfToolResolver resolver,
        CancellationToken cancellationToken)
    {
        _ = AgentConfigurationLoader.Validate(configuration);
        ArgumentNullException.ThrowIfNull(resolver);
        return resolver.ResolveAsync(cancellationToken);
    }
}

public static class AgentCommand
{
    public static Task<int> ExecuteAsync(
        string[] args,
        TextWriter error,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(
            args,
            error,
            new AgentConfigurationLoader(),
            new DefaultAgentRunner(error),
            cancellationToken);

    public static async Task<int> ExecuteAsync(
        string[] args,
        TextWriter error,
        IAgentConfigurationLoader configurationLoader,
        IAgentRunner runner,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(configurationLoader);
        ArgumentNullException.ThrowIfNull(runner);

        if (args is not ["--console"] and not ["--background"])
        {
            await error.WriteLineAsync("agent_arguments_invalid").ConfigureAwait(false);
            return 2;
        }

        var diagnostics = new TextWriterAgentDiagnosticSink(error);
        try
        {
            var configuration = await configurationLoader.LoadAsync(cancellationToken).ConfigureAwait(false);
            await runner.RunAsync(configuration, cancellationToken).ConfigureAwait(false);
            return 0;
        }
        catch (AgentConfigurationException configurationError)
        {
            diagnostics.Report(new AgentDiagnostic(
                "agent_configuration",
                configurationError.Code,
                configurationError));
            await error.WriteLineAsync(configurationError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (AgentStartupException startupError)
        {
            diagnostics.Report(new AgentDiagnostic(
                "agent_startup",
                startupError.Code,
                startupError));
            await error.WriteLineAsync(startupError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 0;
        }
        catch (Exception startError) when (startError is IOException or UnauthorizedAccessException)
        {
            diagnostics.Report(new AgentDiagnostic(
                "agent_startup",
                "agent_start_failed",
                startError));
            await error.WriteLineAsync("agent_start_failed").ConfigureAwait(false);
            return 1;
        }
        catch (Exception unexpectedError)
        {
            diagnostics.Report(new AgentDiagnostic(
                "agent_startup",
                "agent_start_failed",
                unexpectedError));
            await error.WriteLineAsync("agent_start_failed").ConfigureAwait(false);
            return 1;
        }
    }
}
