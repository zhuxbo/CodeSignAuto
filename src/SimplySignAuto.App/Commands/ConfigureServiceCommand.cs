using System.Security.Cryptography;
using System.Security.Principal;
using System.Runtime.ExceptionServices;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

public sealed class ConfigureServiceException : Exception
{
    public ConfigureServiceException(string code)
        : base(code) => Code = code;

    public string Code { get; }
}

public sealed record ConfigureServiceLoadResult
{
    public ConfigureServiceLoadResult(
        ServiceConfiguration configuration,
        ConfigureServiceRevision revision)
    {
        Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        Revision = revision ?? throw new ArgumentNullException(nameof(revision));
    }

    public ServiceConfiguration Configuration { get; }
    public ConfigureServiceRevision Revision { get; }
}

internal interface IConfigureServicePlatform
{
    bool IsAdministratorElevated();

    IDisposable? TryAcquireInstanceLease() => ConfigureServiceNoopLease.Instance;

    Task<ConfigureServiceLoadResult> LoadProtectedAsync(CancellationToken cancellationToken);

    Task ApplyAndRestartAsync(
        ConfigureServiceLoadResult original,
        ServiceConfiguration updated,
        CancellationToken cancellationToken);

    ServiceSettingsSummary CreateSettingsSummary(ServiceConfiguration configuration);
}

internal sealed class ConfigureServiceNoopLease : IDisposable
{
    public static ConfigureServiceNoopLease Instance { get; } = new();
    public void Dispose() { }
}

internal sealed class ServiceConfigurationWriterLeaseFactory(
    string mutexName = @"Global\SimplySignAuto.ServiceConfigurationWriter.v1")
{
    public IDisposable? TryAcquire()
    {
        var mutex = new Mutex(initiallyOwned: false, mutexName, out var createdNew);
        if (!createdNew)
        {
            mutex.Dispose();
            return null;
        }

        return new Lease(mutex);
    }

    private sealed class Lease(Mutex mutex) : IDisposable
    {
        private Mutex? _mutex = mutex;

        public void Dispose() => Interlocked.Exchange(ref _mutex, null)?.Dispose();
    }
}

internal interface IConfigureServiceMutationRuntime
{
    Task<ConfigureServiceState> GetServiceStateAsync(CancellationToken cancellationToken);

    Task VerifyOwnershipAsync(ServiceConfiguration configuration, CancellationToken cancellationToken);

    Task<ConfigureServiceRevision> ReplaceProtectedAsync(
        ServiceConfiguration configuration,
        ConfigureServiceRevision expected,
        CancellationToken cancellationToken);

    Task StopServiceAsync(CancellationToken cancellationToken);

    Task StartServiceAsync(CancellationToken cancellationToken);

    Task<ConfigureServiceLoadResult> ReadBackAsync(CancellationToken cancellationToken);

    Task WaitUntilReadyAsync(ServiceConfiguration configuration, CancellationToken cancellationToken);
}

internal enum ConfigureServiceState
{
    Running,
    Stopped,
}

internal sealed class TransactionalConfigureServiceExecutor(IConfigureServiceMutationRuntime runtime)
{
    public async Task ExecuteAsync(
        ConfigureServiceLoadResult originalLoad,
        ServiceConfiguration updated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(originalLoad);
        ArgumentNullException.ThrowIfNull(updated);
        var original = originalLoad.Configuration;
        ConfigureServiceState originalState;
        try
        {
            originalState = await runtime.GetServiceStateAsync(cancellationToken).ConfigureAwait(false);
            await runtime.VerifyOwnershipAsync(original, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }

        Exception? originalFailure = null;
        ConfigureServiceRevision? updatedRevision = null;
        try
        {
            updatedRevision = await runtime.ReplaceProtectedAsync(
                updated,
                originalLoad.Revision,
                cancellationToken).ConfigureAwait(false);
            if (originalState == ConfigureServiceState.Running)
            {
                await runtime.StopServiceAsync(cancellationToken).ConfigureAwait(false);
            }

            await runtime.StartServiceAsync(cancellationToken).ConfigureAwait(false);
            var persisted = await runtime.ReadBackAsync(cancellationToken).ConfigureAwait(false);
            if (!ServiceConfigurationLoader.MatchesExpected(persisted.Configuration, updated) ||
                persisted.Revision != updatedRevision)
            {
                throw new ConfigureServiceException("service_restart_failed");
            }

            await runtime.VerifyOwnershipAsync(updated, cancellationToken).ConfigureAwait(false);
            await runtime.WaitUntilReadyAsync(updated, cancellationToken).ConfigureAwait(false);
            if (originalState == ConfigureServiceState.Stopped)
            {
                await runtime.StopServiceAsync(cancellationToken).ConfigureAwait(false);
                if (await runtime.GetServiceStateAsync(cancellationToken).ConfigureAwait(false) !=
                    ConfigureServiceState.Stopped)
                {
                    throw new ConfigureServiceException("service_restart_failed");
                }
            }

            return;
        }
        catch (Exception error)
        {
            originalFailure = error;
        }

        if (updatedRevision is null)
        {
            if (originalFailure is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                ExceptionDispatchInfo.Capture(originalFailure).Throw();
            }

            if (originalFailure is ConfigureServiceException preWrite)
            {
                throw preWrite;
            }

            throw new ConfigureServiceException("configure_service_state_uncertain");
        }

        try
        {
            await runtime.StopServiceAsync(CancellationToken.None).ConfigureAwait(false);
            var restoredRevision = await runtime.ReplaceProtectedAsync(
                original,
                updatedRevision,
                CancellationToken.None).ConfigureAwait(false);
            if (originalState == ConfigureServiceState.Running)
            {
                await runtime.StartServiceAsync(CancellationToken.None).ConfigureAwait(false);
            }
            var restored = await runtime.ReadBackAsync(CancellationToken.None).ConfigureAwait(false);
            if (!ServiceConfigurationLoader.MatchesExpected(restored.Configuration, original) ||
                restored.Revision != restoredRevision)
            {
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }

            await runtime.VerifyOwnershipAsync(original, CancellationToken.None).ConfigureAwait(false);
            if (originalState == ConfigureServiceState.Running)
            {
                await runtime.WaitUntilReadyAsync(original, CancellationToken.None).ConfigureAwait(false);
            }
            else if (await runtime.GetServiceStateAsync(CancellationToken.None).ConfigureAwait(false) !=
                ConfigureServiceState.Stopped)
            {
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }
        }
        catch
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }

        if (originalFailure is OperationCanceledException && cancellationToken.IsCancellationRequested)
        {
            ExceptionDispatchInfo.Capture(originalFailure).Throw();
        }

        if (originalFailure is ConfigureServiceException command)
        {
            throw command;
        }

        throw new ConfigureServiceException("service_restart_failed");
    }
}

internal static class ConfigureServiceTokenSecret
{
    public static string HashAndZero(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        byte[]? hash = null;
        try
        {
            hash = SHA256.HashData(plaintext);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (hash is not null)
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
    }
}

public static class ConfigureServiceCommand
{
    public static Task<int> ExecuteAsync(
        string[] args,
        TextReader input,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync(args, input, output, error, new WindowsConfigureServicePlatform(), cancellationToken);

    internal static async Task<int> ExecuteAsync(
        string[] args,
        TextReader input,
        TextWriter output,
        TextWriter error,
        IConfigureServicePlatform platform,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(platform);
        if (args.Length != 0)
        {
            await error.WriteLineAsync("configure_service_arguments_invalid").ConfigureAwait(false);
            return 2;
        }

        if (!platform.IsAdministratorElevated())
        {
            await error.WriteLineAsync("administrator_required").ConfigureAwait(false);
            return 1;
        }

        string? rotatedToken = null;
        IDisposable? instanceLease = null;
        try
        {
            instanceLease = platform.TryAcquireInstanceLease();
            if (instanceLease is null)
            {
                await error.WriteLineAsync("configure_service_busy").ConfigureAwait(false);
                return 1;
            }

            var originalLoad = await platform.LoadProtectedAsync(cancellationToken).ConfigureAwait(false);
            var original = ServiceConfigurationLoader.Validate(originalLoad.Configuration);
            var validatedOriginalLoad = new ConfigureServiceLoadResult(original, originalLoad.Revision);
            var port = ParseInt(
                await PromptAsync(input, output, $"监听端口（当前 {original.ListenPort}，留空保持）：", cancellationToken).ConfigureAwait(false),
                original.ListenPort,
                1,
                65535);
            var retention = ParseInt(
                await PromptAsync(input, output, $"结果保留小时（当前 {original.RetentionHours}，0-168，留空保持）：", cancellationToken).ConfigureAwait(false),
                original.RetentionHours,
                0,
                168);
            var rotate = string.Equals(
                (await PromptAsync(input, output, "轮换 API token？输入 y 确认（默认 n）：", cancellationToken).ConfigureAwait(false))?.Trim(),
                "y",
                StringComparison.OrdinalIgnoreCase);
            var request = new ServiceConfigurationEditRequest(
                port,
                retention,
                rotate);
            var editor = new ServiceConfigurationEditor(platform, validatedOriginalLoad, instanceLease);
            instanceLease = null;
            var result = await editor.ApplyAsync(request, cancellationToken).ConfigureAwait(false);
            rotatedToken = result.OneTimeApiToken;
            if (rotatedToken is not null)
            {
                await output.WriteLineAsync($"API token (copy once): {rotatedToken}").ConfigureAwait(false);
                rotatedToken = null;
                while (true)
                {
                    var confirmation = await PromptAsync(
                        input,
                        output,
                        "确认已安全保存 token 后输入 y 关闭：",
                        CancellationToken.None).ConfigureAwait(false);
                    if (string.Equals(confirmation?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    if (confirmation is null)
                    {
                        await Task.Delay(Timeout.InfiniteTimeSpan, CancellationToken.None).ConfigureAwait(false);
                    }
                }
            }

            return 0;
        }
        catch (ConfigureServiceException commandError)
        {
            await error.WriteLineAsync(commandError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (ServiceConfigurationException configurationError)
        {
            await error.WriteLineAsync(configurationError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 0;
        }
        catch (Exception)
        {
            await error.WriteLineAsync("configure_service_failed").ConfigureAwait(false);
            return 1;
        }
        finally
        {
            rotatedToken = null;
            instanceLease?.Dispose();
        }
    }

    private static async Task<string?> PromptAsync(
        TextReader input,
        TextWriter output,
        string prompt,
        CancellationToken cancellationToken)
    {
        await output.WriteLineAsync(prompt).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        return await input.ReadLineAsync(cancellationToken).ConfigureAwait(false);
    }

    private static int ParseInt(string? value, int current, int minimum, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return current;
        }

        return int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
            parsed >= minimum && parsed <= maximum
            ? parsed
            : throw new ConfigureServiceException("configure_service_input_invalid");
    }

}

internal sealed class WindowsConfigureServicePlatform : IConfigureServicePlatform
{
    private const string ServiceName = "SimplySignAuto.Service";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _configurationPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SimplySignAuto",
        "service.json");
    private readonly WindowsInstallStartupRuntime _services = new();
    private readonly ProtectedConfigurationStorage _storage = new(new WindowsProtectedConfigurationOperations());
    private readonly ServiceConfigurationWriterLeaseFactory _instanceLeases = new();
    private readonly IConfigureServiceMutationRuntime _mutations;

    public WindowsConfigureServicePlatform() => _mutations = new WindowsMutationRuntime(this);

    public bool IsAdministratorElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public IDisposable? TryAcquireInstanceLease()
    {
        EnsureWindows();
        return _instanceLeases.TryAcquire();
    }

    public async Task<ConfigureServiceLoadResult> LoadProtectedAsync(CancellationToken cancellationToken)
    {
        EnsureWindows();
        var snapshot = await _storage.ReadSnapshotAsync(_configurationPath, cancellationToken).ConfigureAwait(false);
        try
        {
            return new ConfigureServiceLoadResult(
                ServiceConfigurationLoader.Deserialize(Encoding.UTF8.GetString(snapshot.Content)),
                snapshot.Revision);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(snapshot.Content);
        }
    }

    public async Task ApplyAndRestartAsync(
        ConfigureServiceLoadResult original,
        ServiceConfiguration updated,
        CancellationToken cancellationToken) =>
        await new TransactionalConfigureServiceExecutor(_mutations)
            .ExecuteAsync(original, updated, cancellationToken).ConfigureAwait(false);

    public ServiceSettingsSummary CreateSettingsSummary(ServiceConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return new ServiceSettingsSummary(
            configuration.ListenPort,
            ServiceSettingsSummary.FixedMaximumUploadBytes,
            configuration.RetentionHours,
            ApplicationVersion.ReadIdentity(typeof(ConfigureServiceCommand).Assembly));
    }

    private static async Task VerifyServiceOwnershipAsync(
        ServiceConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var marker = InstallOwnershipMarker.Create(configuration.InstallInstanceId);
        var verifier = new WindowsInstallRollbackOwnershipVerifier(
            configuration.SigningUserSid,
            new DefaultWindowsCommandRunner(),
            new WindowsInstallResourceLookup(),
            new WindowsServiceRecoveryInspector());
        await verifier.VerifyAsync(
            new AppliedInstallAction(
                new StartAndVerifyWindowsService(ServiceName, marker),
                Created: false,
                RollbackState: null,
                OwnershipConfiguration: configuration),
            cancellationToken).ConfigureAwait(false);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new ConfigureServiceException("administrator_required");
        }
    }

    private sealed class WindowsMutationRuntime(WindowsConfigureServicePlatform owner) :
        IConfigureServiceMutationRuntime
    {
        private static readonly TimeSpan ReadinessTimeout = TimeSpan.FromSeconds(30);

        public Task<ConfigureServiceState> GetServiceStateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureWindows();
            try
            {
                using var service = new ServiceController(ServiceName);
                service.Refresh();
                return Task.FromResult(service.Status switch
                {
                    ServiceControllerStatus.Running => ConfigureServiceState.Running,
                    ServiceControllerStatus.Stopped => ConfigureServiceState.Stopped,
                    _ => throw new ConfigureServiceException("configure_service_state_uncertain"),
                });
            }
            catch (ConfigureServiceException)
            {
                throw;
            }
            catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception or SystemException)
            {
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }
        }

        public Task VerifyOwnershipAsync(
            ServiceConfiguration configuration,
            CancellationToken cancellationToken) =>
            VerifyServiceOwnershipAsync(configuration, cancellationToken);

        public async Task<ConfigureServiceRevision> ReplaceProtectedAsync(
            ServiceConfiguration configuration,
            ConfigureServiceRevision expected,
            CancellationToken cancellationToken)
        {
            EnsureWindows();
            var bytes = JsonSerializer.SerializeToUtf8Bytes(configuration, JsonOptions);
            try
            {
                return await owner._storage.ReplaceAsync(
                    owner._configurationPath,
                    expected,
                    bytes,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        public Task StopServiceAsync(CancellationToken cancellationToken) =>
            owner._services.StopServiceAsync(ServiceName, cancellationToken);

        public Task StartServiceAsync(CancellationToken cancellationToken) =>
            owner._services.StartAndVerifyServiceAsync(ServiceName, cancellationToken);

        public Task<ConfigureServiceLoadResult> ReadBackAsync(CancellationToken cancellationToken) =>
            owner.LoadProtectedAsync(cancellationToken);

        public async Task WaitUntilReadyAsync(
            ServiceConfiguration configuration,
            CancellationToken cancellationToken)
        {
            var endpoint = new UriBuilder(
                Uri.UriSchemeHttp,
                IPAddress.Loopback.ToString(),
                configuration.ListenPort,
                "health/live").Uri;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(ReadinessTimeout);
            using var handler = new SocketsHttpHandler
            {
                ConnectCallback = async (context, token) =>
                {
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(
                            IPAddress.Loopback,
                            context.DnsEndPoint.Port,
                            token).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                },
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
            while (true)
            {
                try
                {
                    using var response = await client.GetAsync(
                        endpoint,
                        HttpCompletionOption.ResponseHeadersRead,
                        deadline.Token).ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        return;
                    }
                }
                catch (OperationCanceledException) when (
                    deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new ConfigureServiceException("service_restart_failed");
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                }
                catch (HttpRequestException)
                {
                }

                try
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(250), deadline.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (
                    deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new ConfigureServiceException("service_restart_failed");
                }
            }
        }
    }
}
