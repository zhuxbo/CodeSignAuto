using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Text;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service;
using CodeSignAuto.Service.Api;
using CodeSignAuto.Service.Ipc;
using CodeSignAuto.Service.Jobs;

namespace CodeSignAuto.EndToEnd.Tests;

internal sealed class EndToEndHarness : IAsyncDisposable
{
    private readonly WebApplication _application;
    private readonly string _pipeName;
    private readonly string _signingUserSid;
    private readonly bool _deleteRoot;
    private readonly string _token;
    private readonly TestLogSink _logSink;
    private int _disposed;

    private EndToEndHarness(
        string root,
        WebApplication application,
        HttpClient client,
        string pipeName,
        string signingUserSid,
        bool deleteRoot,
        string token,
        TestLogSink logSink)
    {
        Root = root;
        _application = application;
        Client = client;
        _pipeName = pipeName;
        _signingUserSid = signingUserSid;
        _deleteRoot = deleteRoot;
        _token = token;
        _logSink = logSink;
        Jobs = application.Services.GetRequiredService<IJobStore>();
        Spool = AssertSpool(application.Services.GetRequiredService<ISpoolStore>());
        Pipe = application.Services.GetRequiredService<AgentPipeServer>();
    }

    public string Root { get; }

    public HttpClient Client { get; }

    public IJobStore Jobs { get; }

    public SpoolStore Spool { get; }

    public AgentPipeServer Pipe { get; }

    public FakeAgent Agent { get; private set; } = null!;

    public bool UsesTestServer => false;

    public string CapturedLog => _logSink.ReadAll();

    public IServiceProvider Services => _application.Services;

    public string BearerToken => _token;

    public static Task<EndToEndHarness> StartAsync() =>
        StartAsync(Directory.CreateTempSubdirectory("SSA-E2E-").FullName, deleteRoot: true);

    public static Task<EndToEndHarness> StartAsync(bool dropLocalCompleteResponseOnce) =>
        StartAsync(
            Directory.CreateTempSubdirectory("SSA-E2E-").FullName,
            deleteRoot: true,
            dropLocalCompleteResponseOnce);

    public static async Task<EndToEndHarness> StartAsync(
        string root,
        bool deleteRoot,
        bool dropLocalCompleteResponseOnce = false,
        ISpoolPromotionObserver? promotionObserver = null,
        TimeProvider? timeProvider = null,
        ILocalLeaseProtector? localLeaseProtector = null,
        IJobWaitRegistrationObserver? waitRegistrationObserver = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        root = Path.GetFullPath(root);
        Directory.CreateDirectory(root);
        WebApplication? application = null;
        HttpClient? client = null;
        try
        {
            var builder = WebApplication.CreateSlimBuilder();
            var logSink = new TestLogSink();
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(logSink);
            builder.WebHost.ConfigureKestrel(server =>
            {
                server.Limits.MaxRequestBodySize = JobEndpoints.MaxRequestBodyBytes;
                server.Listen(IPAddress.Loopback, 0);
            });
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var pipeName = "SSA.E2E." + Guid.NewGuid().ToString("N");
            const string signingUserSid = "S-1-5-21-1000-1001-1002-1003";
            var pipeEndpoint = new TestPipeEndpoint(pipeName);
            var spoolPath = Path.Combine(root, "spool");
            if (timeProvider is not null)
            {
                builder.Services.AddSingleton<TimeProvider>(timeProvider);
            }

            ServiceHost.Configure(
                builder,
                new ServiceHostOptions(
                    SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)),
                    Path.Combine(root, "jobs.db"),
                    spoolPath)
                {
                    ProductVersionIdentity = "1.0.0",
                    SigningUserSid = signingUserSid,
                    SpoolAclPolicy = TestSpoolAclPolicy.Instance,
                });
            if (waitRegistrationObserver is not null)
            {
                builder.Services.RemoveAll<IJobCompletionNotifier>();
                builder.Services.AddSingleton<IJobCompletionNotifier>(services =>
                    new JobCompletionNotifier(
                        services.GetRequiredService<IJobStore>(),
                        waitRegistrationObserver));
            }

            if (promotionObserver is not null)
            {
                builder.Services.RemoveAll<ISpoolStore>();
                builder.Services.AddSingleton<ISpoolStore>(
                    new SpoolStore(spoolPath, TestSpoolAclPolicy.Instance, promotionObserver));
            }

            ReplaceRuntimeForPortablePipe(
                builder,
                pipeEndpoint,
                signingUserSid,
                dropLocalCompleteResponseOnce,
                localLeaseProtector);
            application = builder.Build();
            ServiceHost.MapPipeline(application);
            await application.StartAsync().ConfigureAwait(false);

            var server = application.Services.GetRequiredService<IServer>();
            var address = server.Features.Get<IServerAddressesFeature>()?.Addresses.Single()
                ?? throw new InvalidOperationException("kestrel_address_missing");
            client = new HttpClient
            {
                BaseAddress = new Uri(address, UriKind.Absolute),
                Timeout = TimeSpan.FromSeconds(10),
            };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return new EndToEndHarness(
                root,
                application,
                client,
                pipeName,
                signingUserSid,
                deleteRoot,
                token,
                logSink);
        }
        catch (Exception startFailure)
        {
            await RunCleanupPreservingFirstAsync(
                startFailure,
                () =>
                {
                    client?.Dispose();
                    return ValueTask.CompletedTask;
                },
                async () =>
                {
                    if (application is not null)
                    {
                        await application.DisposeAsync().ConfigureAwait(false);
                    }
                },
                () =>
                {
                    if (deleteRoot)
                    {
                        DeleteOrdinaryTree(root);
                    }

                    return ValueTask.CompletedTask;
                }).ConfigureAwait(false);
            throw;
        }
    }

    public async Task StartAgentAsync(FakeAgentBehavior behavior = FakeAgentBehavior.Complete)
    {
        if (Agent is not null)
        {
            throw new InvalidOperationException("fake_agent_already_started");
        }

        Agent = new FakeAgent(_pipeName, Spool.Root, _signingUserSid, sessionId: 7);
        Agent.Start(behavior);
        await Agent.Connected.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        if ((behavior & FakeAgentBehavior.InvalidHeartbeatIdentity) != 0)
        {
            return;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (Pipe.CurrentConnection is null ||
               Pipe.CurrentHealth?.Heartbeat?.Certificates.Count is not 2)
        {
            await Task.Delay(10, timeout.Token).ConfigureAwait(false);
        }
    }

    public async Task WaitForAgentConnectionsAsync(int count, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (Agent.ConnectionCount < count)
        {
            await Task.Delay(10, cancellation.Token).ConfigureAwait(false);
        }
    }

    public async Task<JobStatusResponse> WaitForStateAsync(Guid jobId, string state)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (true)
        {
            using var response = await Client.GetAsync($"/v1/jobs/{jobId:D}", timeout.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var status = await response.Content
                .ReadFromJsonAsync<JobStatusResponse>(cancellationToken: timeout.Token)
                .ConfigureAwait(false)
                ?? throw new InvalidOperationException("job_status_missing");
            if (string.Equals(status.State, state, StringComparison.Ordinal))
            {
                return status;
            }

            if (status.State is "succeeded" or "failed" or "expired")
            {
                throw new InvalidOperationException($"job_reached_unexpected_terminal_state:{status.State}");
            }

            await Task.Delay(10, timeout.Token).ConfigureAwait(false);
        }
    }

    public async Task<int> SendHeadersOnlyAsync(long contentLength)
    {
        if (contentLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(contentLength));
        }

        var endpoint = Client.BaseAddress ?? throw new InvalidOperationException("kestrel_address_missing");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(endpoint.Host, endpoint.Port, timeout.Token).ConfigureAwait(false);
        await using var stream = tcp.GetStream();
        var headers = Encoding.ASCII.GetBytes(
            $"POST /v1/jobs HTTP/1.1\r\nHost: localhost:{endpoint.Port}\r\n" +
            $"Authorization: Bearer {_token}\r\n" +
            "Content-Type: multipart/form-data; boundary=ssa-no-body\r\n" +
            $"Content-Length: {contentLength}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(headers, timeout.Token).ConfigureAwait(false);
        await stream.FlushAsync(timeout.Token).ConfigureAwait(false);
        using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
        var statusLine = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false)
            ?? throw new InvalidOperationException("http_status_missing");
        var fields = statusLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return fields.Length >= 2 && int.TryParse(fields[1], out var status)
            ? status
            : throw new InvalidOperationException("http_status_invalid");
    }

    public async Task<bool> SendOversizedPipeFrameAsync()
    {
        await using var pipe = await ConnectPipeAsync().ConfigureAwait(false);
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(header, LengthPrefixedJsonProtocol.MaximumPayloadLength + 1);
        await pipe.WriteAsync(header).ConfigureAwait(false);
        await pipe.FlushAsync().ConfigureAwait(false);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var buffer = new byte[1];
        return await pipe.ReadAsync(buffer, timeout.Token).ConfigureAwait(false) == 0;
    }

    public async Task<bool> SendHelloAndObserveCloseAsync(AgentHello hello)
    {
        await using var pipe = await ConnectPipeAsync().ConfigureAwait(false);
        try
        {
            await LengthPrefixedJsonProtocol.WriteAsync(pipe, hello, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException or ProtocolException)
        {
            return true;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var buffer = new byte[1];
        return await pipe.ReadAsync(buffer, timeout.Token).ConfigureAwait(false) == 0;
    }

    public async Task<bool> SendRawPipeFrameAndObserveCloseAsync(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        await using var pipe = await ConnectPipeAsync().ConfigureAwait(false);
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await pipe.WriteAsync(header).ConfigureAwait(false);
        await pipe.WriteAsync(payload).ConfigureAwait(false);
        await pipe.FlushAsync().ConfigureAwait(false);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var buffer = new byte[1];
        return await pipe.ReadAsync(buffer, timeout.Token).ConfigureAwait(false) == 0;
    }

    public async Task<bool> SendHelloThenMessageAndObserveCloseAsync(AgentMessage message)
    {
        await using var pipe = await ConnectPipeAsync().ConfigureAwait(false);
        await LengthPrefixedJsonProtocol.WriteAsync(
            pipe,
            new AgentHello(
                LengthPrefixedJsonProtocol.ProtocolVersion,
                Environment.ProcessId,
                7,
                _signingUserSid,
                "1.0.0",
                ["pdf"]),
            CancellationToken.None).ConfigureAwait(false);
        await LengthPrefixedJsonProtocol.WriteAsync(pipe, message, CancellationToken.None).ConfigureAwait(false);
        return await ObserveCloseAfterOptionalStartupPreparationAsync(pipe).ConfigureAwait(false);
    }

    private static async Task<bool> ObserveCloseAfterOptionalStartupPreparationAsync(Stream pipe)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var preparationCommands = 0;
        while (true)
        {
            try
            {
                var serverMessage = await LengthPrefixedJsonProtocol
                    .ReadAsync<AgentMessage>(pipe, timeout.Token)
                    .ConfigureAwait(false);
                if (serverMessage is not PrepareSimplySignSessionCommand || ++preparationCommands > 1)
                {
                    return false;
                }
            }
            catch (ProtocolException error) when (error.Code == "unexpected_eof")
            {
                return true;
            }
            catch (Exception error) when (error is IOException or ObjectDisposedException)
            {
                return true;
            }
        }
    }

    private async Task<NamedPipeClientStream> ConnectPipeAsync()
    {
        var pipe = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            return pipe;
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await RunCleanupPreservingFirstAsync(
            null,
            () =>
            {
                Client.Dispose();
                return ValueTask.CompletedTask;
            },
            async () =>
            {
                if (Agent is not null)
                {
                    await Agent.DisposeAsync().ConfigureAwait(false);
                }
            },
            async () =>
            {
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await _application.StopAsync(stop.Token).ConfigureAwait(false);
            },
            async () => await _application.DisposeAsync().ConfigureAwait(false),
            () =>
            {
                if (_deleteRoot)
                {
                    DeleteOrdinaryTree(Root);
                }

                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);
    }

    internal static async ValueTask RunCleanupPreservingFirstAsync(
        Exception? first,
        params Func<ValueTask>[] cleanupSteps)
    {
        ArgumentNullException.ThrowIfNull(cleanupSteps);
        foreach (var cleanup in cleanupSteps)
        {
            ArgumentNullException.ThrowIfNull(cleanup);
            try
            {
                await cleanup().ConfigureAwait(false);
            }
            catch (Exception error)
            {
                first ??= error;
            }
        }

        if (first is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(first).Throw();
        }
    }

    private static void ReplaceRuntimeForPortablePipe(
        WebApplicationBuilder builder,
        TestPipeEndpoint endpoint,
        string signingUserSid,
        bool dropLocalCompleteResponseOnce,
        ILocalLeaseProtector? localLeaseProtector)
    {
        builder.Services.RemoveAll<AgentPipeServer>();
        builder.Services.RemoveAll<IAgentPipeRuntime>();
        builder.Services.RemoveAll<IAgentPipeTransport>();
        builder.Services.RemoveAll<IAgentStartupPreparationTransport>();
        builder.Services.RemoveAll<IAgentHealthStatusSource>();
        builder.Services.AddSingleton(services => new AgentPipeServer(
            signingUserSid,
            "1.0.0",
            new TestIdentityVerifier(Environment.ProcessId, 7, signingUserSid),
            clock: new TimeProviderAgentClock(services.GetRequiredService<TimeProvider>()),
            acceptConnection: endpoint.AcceptAsync,
            managementProvider: services.GetRequiredService<IServiceManagementSnapshotProvider>()));
        builder.Services.AddSingleton<IAgentPipeRuntime>(services => services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<IAgentPipeTransport>(services => services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<IAgentStartupPreparationTransport>(services =>
            services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<IAgentHealthStatusSource>(services => services.GetRequiredService<AgentPipeServer>());

        builder.Services.RemoveAll<IAdminControlRuntime>();
        builder.Services.AddSingleton<IAdminControlRuntime, TestAdminControlRuntime>();

        builder.Services.RemoveAll<LocalJobUploadCoordinator>();
        builder.Services.RemoveAll<ILocalJobRequestHandler>();
        builder.Services.RemoveAll<ILocalUploadCleanup>();
        builder.Services.AddSingleton(services => new LocalJobUploadCoordinator(
            services.GetRequiredService<IJobStore>(),
            services.GetRequiredService<ISpoolStore>(),
            services.GetRequiredService<IJobDispatcher>(),
            services.GetRequiredService<TimeProvider>(),
            signingUserSid,
            localLeaseProtector ?? new TestLeaseProtector(),
            acceptanceObserver: dropLocalCompleteResponseOnce
                ? new DropAcceptedResponseOnce(endpoint)
                : null));
        builder.Services.AddSingleton<ILocalJobRequestHandler>(services =>
            services.GetRequiredService<LocalJobUploadCoordinator>());
        builder.Services.AddSingleton<ILocalUploadCleanup>(services =>
            services.GetRequiredService<LocalJobUploadCoordinator>());
    }

    private sealed class TimeProviderAgentClock(TimeProvider timeProvider) : IAgentClock
    {
        public DateTimeOffset UtcNow => timeProvider.GetUtcNow().ToUniversalTime();

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(delay, timeProvider, cancellationToken);
    }

    private sealed class TestAdminControlRuntime : IAdminControlRuntime
    {
        public Task RunAsync(CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private static SpoolStore AssertSpool(ISpoolStore spool) =>
        spool as SpoolStore ?? throw new InvalidOperationException("real_spool_required");

    private static void DeleteOrdinaryTree(string root)
    {
        if (!Directory.Exists(root))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("test_cleanup_reparse_refused");
            }
        }

        Directory.Delete(root, recursive: true);
    }

    private sealed class TestPipeEndpoint(string pipeName)
    {
        private readonly object _sync = new();
        private Stream? _current;

        public async Task<Stream> AcceptAsync(CancellationToken cancellationToken)
        {
            var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
            try
            {
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    _current = server;
                }

                return server;
            }
            catch
            {
                await server.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        public void DisconnectCurrent()
        {
            Stream? current;
            lock (_sync)
            {
                current = _current;
                _current = null;
            }

            current?.Dispose();
        }
    }

    private sealed class DropAcceptedResponseOnce(TestPipeEndpoint endpoint) : ILocalJobAcceptanceObserver
    {
        private int _dropped;

        public Task AfterAcceptedAsync(Guid requestId, Guid jobId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref _dropped, 1) == 0)
            {
                endpoint.DisconnectCurrent();
            }

            return Task.CompletedTask;
        }
    }

    private sealed class TestIdentityVerifier(int processId, int sessionId, string userSid)
        : IAgentConnectionIdentityVerifier
    {
        public ValueTask<AgentConnectionIdentity> VerifyAsync(Stream connection, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (connection is not NamedPipeServerStream { IsConnected: true })
            {
                throw new InvalidOperationException("real_named_pipe_required");
            }

            return ValueTask.FromResult(new AgentConnectionIdentity(processId, sessionId, userSid));
        }
    }

    internal sealed class TestLeaseProtector : ILocalLeaseProtector
    {
        private readonly byte[] _mask = RandomNumberGenerator.GetBytes(32);

        public byte[] Protect(ReadOnlySpan<byte> lease) => Transform(lease);

        public byte[] Unprotect(ReadOnlySpan<byte> protectedLease) => Transform(protectedLease);

        private byte[] Transform(ReadOnlySpan<byte> value)
        {
            var transformed = value.ToArray();
            for (var index = 0; index < transformed.Length; index++)
            {
                transformed[index] ^= _mask[index % _mask.Length];
            }

            return transformed;
        }
    }

    private sealed class TestSpoolAclPolicy : ISpoolAclPolicy
    {
        public static TestSpoolAclPolicy Instance { get; } = new();

        public void ProtectRoot(string path) => AssertOrdinary(path, directory: true);

        public void ProtectJobDirectory(string path) => AssertOrdinary(path, directory: true);

        public void ProtectInput(string path) => AssertOrdinary(path, directory: false);

        public void ProtectFinalResult(string path) => AssertOrdinary(path, directory: false);

        private static void AssertOrdinary(string path, bool directory)
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                ((attributes & FileAttributes.Directory) != 0) != directory)
            {
                throw new SpoolAclException();
            }
        }
    }

    private sealed class TestLogSink : ILoggerProvider
    {
        private readonly object _sync = new();
        private readonly List<string> _messages = [];

        public ILogger CreateLogger(string categoryName) => new CaptureLogger(this);

        public void Dispose()
        {
        }

        public string ReadAll()
        {
            lock (_sync)
            {
                return string.Join('\n', _messages);
            }
        }

        private void Add(string message)
        {
            lock (_sync)
            {
                _messages.Add(message);
            }
        }

        private sealed class CaptureLogger(TestLogSink owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner.Add(
                    $"{logLevel}: {formatter(state, exception)}" +
                    (exception is null ? string.Empty : Environment.NewLine + exception));
        }
    }
}
