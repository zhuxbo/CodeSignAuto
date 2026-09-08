using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Ipc;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class AgentPipeIdentityTests
{
    [Fact]
    public void Control_timeouts_cover_relogin_and_preserve_outer_transport_margin()
    {
        Assert.Equal(TimeSpan.FromSeconds(105), AgentPipeServer.ControlTimeout);
        Assert.Equal(TimeSpan.FromSeconds(110), AdminControlPipeServer.ManagementDispatchTimeout);
        Assert.True(AdminControlPipeServer.ManagementDispatchTimeout > AgentPipeServer.ControlTimeout);
    }

    private const string AllowedSid = "S-1-5-21-1000";

    [Fact]
    public async Task Rejects_hello_when_verified_sid_does_not_match_configuration()
    {
        var server = Server(new AgentConnectionIdentity(321, 7, "S-1-5-21-2000"));
        await using var connection = await ConnectionAsync(Hello());

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            server.ProcessConnectionAsync(connection, CancellationToken.None));

        Assert.Equal("agent_identity_mismatch", error.Code);
    }

    [Fact]
    public async Task Rejects_session_zero_even_when_hello_claims_an_interactive_session()
    {
        var server = Server(new AgentConnectionIdentity(321, 0, AllowedSid));
        await using var connection = await ConnectionAsync(Hello());

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            server.ProcessConnectionAsync(connection, CancellationToken.None));

        Assert.Equal("non_interactive_session", error.Code);
    }

    [Fact]
    public async Task Rejects_hello_claims_that_differ_from_pipe_identity()
    {
        (int ProcessId, int SessionId, string Sid)[] cases =
        [
            (322, 7, "S-1-5-21-1000"),
            (321, 8, "S-1-5-21-1000"),
            (321, 7, "S-1-5-21-2000"),
        ];
        foreach (var (processId, sessionId, sid) in cases)
        {
            var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid));
            await using var connection = await ConnectionAsync(
                Hello(processId: processId, sessionId: sessionId, sid: sid));

            var error = await Assert.ThrowsAsync<ProtocolException>(() =>
                server.ProcessConnectionAsync(connection, CancellationToken.None));

            Assert.Equal("agent_identity_mismatch", error.Code);
        }
    }

    [Fact]
    public async Task Rejects_hello_when_full_product_identity_differs_even_if_display_matches()
    {
        var server = Server(
            new AgentConnectionIdentity(321, 7, AllowedSid),
            expectedProductIdentity: "1.0.0+service.7");
        await using var connection = await ConnectionAsync(
            Hello(agentIdentity: "1.0.0+agent.7"));

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            server.ProcessConnectionAsync(connection, CancellationToken.None));

        Assert.Equal("product_version_mismatch", error.Code);
    }

    [Fact]
    public async Task Rejects_hello_payload_protocol_version_that_is_not_exactly_three()
    {
        var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid));
        await using var connection = RawConnection(
            "{\"version\":3,\"type\":\"agent_hello\",\"payload\":{\"protocolVersion\":2,\"processId\":321,\"sessionId\":7,\"userSid\":\"S-1-5-21-1000\",\"agentVersion\":\"1.0.0\",\"capabilities\":[\"authenticode\",\"pdf\"]}}");

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            server.ProcessConnectionAsync(connection, CancellationToken.None));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public async Task Rejects_second_connection_while_current_agent_is_fresh()
    {
        var clock = new FakeAgentClock();
        var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid), clock);
        await using var first = await BlockingConnection.CreateAsync(Hello());
        var firstTask = server.ProcessConnectionAsync(first, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection is not null);

        await using var second = await ConnectionAsync(Hello());
        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            server.ProcessConnectionAsync(second, CancellationToken.None));

        Assert.Equal("agent_already_connected", error.Code);
        Assert.False(first.IsDisposed);
        await first.DisposeAsync();
        await firstTask;
    }

    [Fact]
    public async Task Startup_preparation_is_not_sent_until_pipe_identity_is_verified()
    {
        var verifier = new ControlledIdentityVerifier(
            new AgentConnectionIdentity(321, 7, AllowedSid));
        var server = new AgentPipeServer(AllowedSid, "1.0.0", verifier, new FakeAgentClock());
        var coordinator = new AgentStartupPreparationCoordinator(server, () => Guid.Parse(
            "11111111-1111-1111-1111-111111111111"));
        using var cancellation = new CancellationTokenSource();
        var coordinatorRun = coordinator.RunAsync(cancellation.Token);
        await using var connection = await BlockingConnection.CreateAsync(Hello());
        var connectionRun = server.ProcessConnectionAsync(connection, CancellationToken.None);
        await verifier.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Empty(connection.WrittenBytes);
        Assert.Equal(AgentStartupPreparationStatus.Pending, coordinator.Current.Status);
        verifier.Release();
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1)))
        {
            while (!HasCompleteFrame(connection.WrittenBytes))
            {
                await Task.Delay(10, timeout.Token);
            }
        }
        await using var sent = new MemoryStream(connection.WrittenBytes);
        var command = Assert.IsType<PrepareSimplySignSessionCommand>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(sent, default));

        Assert.Equal(coordinator.Current.RequestId, command.RequestId);
        await connection.DisposeAsync();
        await connectionRun;
        cancellation.Cancel();
        await coordinatorRun;
    }

    [Fact]
    public async Task Replaces_and_closes_stale_connection_after_heartbeat_timeout()
    {
        var clock = new FakeAgentClock();
        var verifier = new QueueIdentityVerifier(
            new AgentConnectionIdentity(321, 7, AllowedSid),
            new AgentConnectionIdentity(654, 9, AllowedSid));
        var server = new AgentPipeServer(AllowedSid, "1.0.0", verifier, clock);
        await using var first = await BlockingConnection.CreateAsync(Hello());
        var firstTask = server.ProcessConnectionAsync(first, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection?.ProcessId == 321);

        clock.Advance(TimeSpan.FromSeconds(16));
        await firstTask;
        Assert.True(first.IsDisposed);
        Assert.Null(server.CurrentConnection);

        await using var second = await BlockingConnection.CreateAsync(Hello(processId: 654, sessionId: 9));
        var secondTask = server.ProcessConnectionAsync(second, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection?.ProcessId == 654);

        Assert.Equal(9, server.CurrentConnection!.SessionId);
        await second.DisposeAsync();
        await secondTask;
    }

    [Fact]
    public async Task Register_replaces_a_stale_live_connection_without_old_cleanup_clearing_the_new_one()
    {
        var clock = new FakeAgentClock();
        var verifier = new QueueIdentityVerifier(
            new AgentConnectionIdentity(321, 7, AllowedSid),
            new AgentConnectionIdentity(654, 9, AllowedSid));
        var server = new AgentPipeServer(AllowedSid, "1.0.0", verifier, clock);
        await using var first = await BlockingConnection.CreateAsync(Hello());
        var firstTask = server.ProcessConnectionAsync(first, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection?.ProcessId == 321);
        clock.AdvanceWithoutCompletingDelays(TimeSpan.FromSeconds(16));

        await using var second = await BlockingConnection.CreateAsync(Hello(processId: 654, sessionId: 9));
        var secondTask = server.ProcessConnectionAsync(second, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection?.ProcessId == 654);
        await firstTask;

        Assert.True(first.IsDisposed);
        Assert.Equal(654, server.CurrentConnection!.ProcessId);
        await second.DisposeAsync();
        await secondTask;
    }

    [Fact]
    public async Task Heartbeat_updates_status_and_non_dispatch_messages_are_exposed()
    {
        var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid));
        var heartbeat = ProtocolV3TestFixtures.Heartbeat(
            currentJobId: Guid.NewGuid(),
            tokenStatus: "present",
            certificateStatus: "valid",
            keyStatus: "available");
        var progress = new JobProgress(heartbeat.CurrentJobId!.Value, Guid.NewGuid(), 25, "signing");
        await using var connection = await ConnectionAsync(Hello(), heartbeat, progress);
        var messages = new List<AgentMessageReceivedEventArgs>();
        server.MessageReceived += (_, message) => messages.Add(message);

        await server.ProcessConnectionAsync(connection, CancellationToken.None);

        Assert.Null(server.LastHeartbeat);
        Assert.Equal([heartbeat, progress], messages.Select(message => message.Message));
        Assert.Single(messages.Select(message => message.ConnectionId).Distinct());
        Assert.All(messages, message => Assert.NotEqual(Guid.Empty, message.ConnectionId));
        Assert.Null(server.CurrentConnection);
    }

    [Fact]
    public async Task Replacement_connection_has_no_health_heartbeat_until_its_own_first_heartbeat()
    {
        var clock = new FakeAgentClock();
        var verifier = new QueueIdentityVerifier(
            new AgentConnectionIdentity(321, 7, AllowedSid),
            new AgentConnectionIdentity(654, 9, AllowedSid));
        var server = new AgentPipeServer(AllowedSid, "1.0.0", verifier, clock);
        await using var first = await ConnectionAsync(
            Hello(),
            ProtocolV3TestFixtures.Heartbeat());

        await server.ProcessConnectionAsync(first, CancellationToken.None);
        clock.AdvanceWithoutCompletingDelays(TimeSpan.FromSeconds(16));
        await using var replacement = await BlockingConnection.CreateAsync(Hello(processId: 654, sessionId: 9));
        var replacementTask = server.ProcessConnectionAsync(replacement, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection?.ProcessId == 654);

        var health = server.CurrentHealth;
        Assert.NotNull(health);
        Assert.Equal(server.CurrentConnection!.ConnectionId, health.ConnectionId);
        Assert.Null(health.Heartbeat);
        Assert.Null(health.LastHeartbeatUtc);
        Assert.Null(server.LastHeartbeat);
        Assert.Null(server.CurrentConnection!.LastHeartbeatUtc);

        await replacement.DisposeAsync();
        await replacementTask;
    }

    [Fact]
    public async Task Connection_id_is_exposed_and_targeted_send_rejects_stale_or_wrong_connections()
    {
        var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid));
        await using var connection = await BlockingConnection.CreateAsync(Hello());
        var events = new List<AgentConnectionStateChangedEventArgs>();
        server.ConnectionStateChanged += (_, change) => events.Add(change);
        var run = server.ProcessConnectionAsync(connection, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection is not null);
        var connectionId = server.CurrentConnection!.ConnectionId;
        var command = new SignJobCommand(
            Guid.NewGuid(),
            Guid.NewGuid(),
            1,
            ".pdf",
            "{}",
            12,
            new string('a', 64));

        await server.SendAsync(connectionId, command, CancellationToken.None);
        var staleError = await Assert.ThrowsAsync<ProtocolException>(() =>
            server.SendAsync(Guid.NewGuid(), command, CancellationToken.None));

        Assert.NotEqual(Guid.Empty, connectionId);
        Assert.Equal("agent_not_connected", staleError.Code);
        Assert.Equal(connectionId, Assert.Single(events).ConnectionId);
        await using var written = new MemoryStream(connection.WrittenBytes);
        Assert.Equal(command, await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        await connection.DisposeAsync();
        await run;
        Assert.Equal(connectionId, events[^1].ConnectionId);
        Assert.Equal(AgentConnectionStatus.Disconnected, events[^1].Status);
    }

    [Fact]
    public async Task Partial_send_failure_disconnects_the_exact_active_connection()
    {
        var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid));
        await using var connection = await ControlledWriteConnection.CreateAsync(failAfterPartialPayload: true);
        var events = new List<AgentConnectionStateChangedEventArgs>();
        server.ConnectionStateChanged += (_, change) => events.Add(change);
        var run = server.ProcessConnectionAsync(connection, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection is not null);
        var connectionId = server.CurrentConnection!.ConnectionId;

        await Assert.ThrowsAsync<IOException>(() =>
            server.SendAsync(connectionId, Command(), CancellationToken.None));
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Null(server.CurrentConnection);
        Assert.True(connection.IsDisposed);
        Assert.Equal(2, events.Count);
        Assert.Equal(AgentConnectionStatus.Disconnected, events[1].Status);
        Assert.Equal("send_failed", events[1].Reason);
        Assert.InRange(connection.WrittenBytes.Length, 5, 7);
    }

    [Fact]
    public async Task Send_failure_after_connection_switch_does_not_clear_the_replacement()
    {
        var clock = new FakeAgentClock();
        var server = new AgentPipeServer(
            AllowedSid,
            "1.0.0",
            new QueueIdentityVerifier(
                new AgentConnectionIdentity(321, 7, AllowedSid),
                new AgentConnectionIdentity(654, 9, AllowedSid)),
            clock);
        await using var first = await ControlledWriteConnection.CreateAsync(pauseFirstWrite: true);
        var firstRun = server.ProcessConnectionAsync(first, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection?.ProcessId == 321);
        var firstId = server.CurrentConnection!.ConnectionId;
        var send = server.SendAsync(firstId, Command(), CancellationToken.None);
        await first.WriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        clock.AdvanceWithoutCompletingDelays(TimeSpan.FromSeconds(16));
        await using var second = await BlockingConnection.CreateAsync(Hello(processId: 654, sessionId: 9));
        var secondRun = server.ProcessConnectionAsync(second, CancellationToken.None);
        await WaitUntilAsync(() => server.CurrentConnection?.ProcessId == 654);
        first.ContinueWrite();

        await Assert.ThrowsAsync<IOException>(() => send);
        Assert.Equal(654, server.CurrentConnection!.ProcessId);
        await firstRun.WaitAsync(TimeSpan.FromSeconds(1));
        await second.DisposeAsync();
        await secondRun.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Rejects_heartbeat_from_a_different_session()
    {
        var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid));
        await using var connection = await ConnectionAsync(
            Hello(),
            ProtocolV3TestFixtures.Heartbeat(
                sessionId: 8,
                tokenStatus: "present",
                certificateStatus: "valid",
                keyStatus: "available"));

        var error = await Assert.ThrowsAsync<ProtocolException>(() =>
            server.ProcessConnectionAsync(connection, CancellationToken.None));

        Assert.Equal("agent_identity_mismatch", error.Code);
    }

    [Fact]
    public async Task Cancellation_closes_the_active_connection_and_exits()
    {
        var server = Server(new AgentConnectionIdentity(321, 7, AllowedSid));
        await using var connection = await BlockingConnection.CreateAsync(Hello());
        using var cancellation = new CancellationTokenSource();
        var run = server.ProcessConnectionAsync(connection, cancellation.Token);
        await WaitUntilAsync(() => server.CurrentConnection is not null);

        cancellation.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.True(connection.IsDisposed);
        Assert.Null(server.CurrentConnection);
    }

    [Fact]
    public async Task Run_stops_accepting_and_propagates_an_unexpected_connection_handler_fault()
    {
        var expected = new InvalidOperationException("identity verifier fault");
        await using var connection = await ConnectionAsync(Hello());
        var acceptor = new QueueConnectionAcceptor(connection);
        var verifier = new ControlledThrowingIdentityVerifier(expected);
        var server = new AgentPipeServer(
            AllowedSid,
            "1.0.0",
            verifier,
            new FakeAgentClock(),
            acceptor.AcceptAsync);

        var run = server.RunAsync(CancellationToken.None);
        await verifier.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await acceptor.NextAcceptStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        verifier.Fail();
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await run.WaitAsync(TimeSpan.FromSeconds(1)));

        Assert.Same(expected, failure);
        Assert.True(acceptor.AcceptCancellationObserved.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Run_treats_an_expected_single_connection_rejection_as_nonfatal_and_keeps_accepting()
    {
        await using var rejected = RawConnection("{\"version\":3,\"type\":\"unknown\",\"payload\":{}}");
        var acceptor = new QueueConnectionAcceptor(rejected);
        var server = new AgentPipeServer(
            AllowedSid,
            "1.0.0",
            new QueueIdentityVerifier(new AgentConnectionIdentity(321, 7, AllowedSid)),
            new FakeAgentClock(),
            acceptor.AcceptAsync);
        using var cancellation = new CancellationTokenSource();

        var run = server.RunAsync(cancellation.Token);
        await acceptor.NextAcceptStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(run.IsFaulted);
        cancellation.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.True(acceptor.AcceptCancellationObserved.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Run_isolates_a_semantically_invalid_heartbeat_to_its_connection_and_keeps_accepting()
    {
        var heartbeat = new AgentHeartbeat(
            7,
            "ready",
            "ready",
            "ready",
            "ready",
            null,
            7,
            new CapabilitySnapshot(
                true, true, true, "34567890", true, true, "abcdef12", true, true, "1234abcd", true, "ready",
                DateTimeOffset.Parse("2027-08-09T00:00:00Z"), "89ABCDEF",
                ProtocolV3TestFixtures.ReadySession("authenticode")),
            CapabilitySnapshot.NotConfigured(),
            1);
        var json = await SerializeAsync(heartbeat);
        var malformed = json.Replace(
            "\"configured\":true",
            "\"configured\":false",
            StringComparison.Ordinal);
        await using var rejected = await BlockingConnection.CreateRawAsync(Hello(), malformed);
        var acceptor = new QueueConnectionAcceptor(rejected);
        var server = new AgentPipeServer(
            AllowedSid,
            "1.0.0",
            new QueueIdentityVerifier(new AgentConnectionIdentity(321, 7, AllowedSid)),
            new FakeAgentClock(),
            acceptor.AcceptAsync);
        using var cancellation = new CancellationTokenSource();

        var run = server.RunAsync(cancellation.Token);
        await WaitUntilAsync(() => rejected.IsDisposed);
        var completed = await Task.WhenAny(run, Task.Delay(25));

        Assert.NotSame(run, completed);
        Assert.False(run.IsFaulted);
        cancellation.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(acceptor.AcceptCancellationObserved.Task.IsCompletedSuccessfully);
    }

    [WindowsFact]
    public void Windows_pipe_acl_grants_only_system_and_configured_user()
    {
        var serverSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("current_sid_missing");
        var localSystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var configuredSid = serverSid == localSystemSid
            ? new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null)
            : localSystemSid;
        var pipeName = $"CodeSignAuto.Agent.Tests.{Guid.NewGuid():N}";
        using var pipe = AgentPipeServer.CreateNamedPipeServer(pipeName, configuredSid.Value, serverSid);

        var rules = pipe.GetAccessControl()
            .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .ToArray();

        Assert.Equal(
            new[] { serverSid.Value, configuredSid.Value }
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            rules.Select(rule => rule.IdentityReference.Value).Order(StringComparer.Ordinal).ToArray());
        Assert.All(rules, rule => Assert.Equal(PipeAccessRights.ReadWrite, rule.PipeAccessRights & PipeAccessRights.ReadWrite));
        Assert.Contains(
            rules,
            rule => rule.IdentityReference.Value == serverSid.Value &&
                    rule.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance));
        Assert.DoesNotContain(
            rules,
            rule => rule.IdentityReference.Value == configuredSid.Value &&
                    rule.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance));
    }

    [WindowsFact]
    public void Windows_service_can_create_parallel_pipe_server_instances()
    {
        var serverSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("current_sid_missing");
        var localSystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var configuredSid = serverSid == localSystemSid
            ? new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null)
            : localSystemSid;
        var pipeName = $"CodeSignAuto.Agent.Tests.{Guid.NewGuid():N}";
        using var first = AgentPipeServer.CreateNamedPipeServer(pipeName, configuredSid.Value, serverSid);
        using var second = AgentPipeServer.CreateNamedPipeServer(pipeName, configuredSid.Value, serverSid);
    }

    private static AgentPipeServer Server(
        AgentConnectionIdentity identity,
        IAgentClock? clock = null,
        string expectedProductIdentity = "1.0.0") =>
        new(
            AllowedSid,
            expectedProductIdentity,
            new QueueIdentityVerifier(identity, identity),
            clock ?? new FakeAgentClock());

    private static AgentHello Hello(
        int protocolVersion = LengthPrefixedJsonProtocol.ProtocolVersion,
        int processId = 321,
        int sessionId = 7,
        string sid = AllowedSid,
        string agentIdentity = "1.0.0") =>
        new(protocolVersion, processId, sessionId, sid, agentIdentity, ["authenticode", "pdf"]);

    private static SignJobCommand Command() =>
        new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            1,
            ".pdf",
            "{}",
            12,
            new string('a', 64));

    private static MemoryStream RawConnection(string json)
    {
        var payload = System.Text.Encoding.UTF8.GetBytes(json);
        var bytes = new byte[payload.Length + 4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes, payload.Length);
        payload.CopyTo(bytes, 4);
        return new MemoryStream(bytes);
    }

    private static async Task<MemoryStream> ConnectionAsync(params AgentMessage[] messages)
    {
        var stream = new MemoryStream();
        foreach (var message in messages)
        {
            await LengthPrefixedJsonProtocol.WriteAsync(stream, message, CancellationToken.None);
        }

        stream.Position = 0;
        return stream;
    }

    private static async Task<string> SerializeAsync(AgentMessage message)
    {
        await using var stream = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(stream, message, default);
        return System.Text.Encoding.UTF8.GetString(stream.ToArray().AsSpan(sizeof(int)));
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 100 && !condition(); attempt++)
        {
            await Task.Yield();
        }

        Assert.True(condition());
    }

    private static bool HasCompleteFrame(byte[] bytes) =>
        bytes.Length >= sizeof(int) &&
        System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(bytes) is var length &&
        length > 0 && bytes.Length >= sizeof(int) + length;

    private sealed class QueueIdentityVerifier(params AgentConnectionIdentity[] identities) : IAgentConnectionIdentityVerifier
    {
        private readonly ConcurrentQueue<AgentConnectionIdentity> _identities = new(identities);

        public ValueTask<AgentConnectionIdentity> VerifyAsync(Stream connection, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                _identities.TryDequeue(out var identity) ? identity : throw new InvalidOperationException("No identity configured."));
        }
    }

    private sealed class ControlledThrowingIdentityVerifier(Exception error) : IAgentConnectionIdentityVerifier
    {
        private readonly TaskCompletionSource _fail = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<AgentConnectionIdentity> VerifyAsync(
            Stream connection,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            await _fail.Task.WaitAsync(cancellationToken);
            throw error;
        }

        public void Fail() => _fail.TrySetResult();
    }

    private sealed class ControlledIdentityVerifier(AgentConnectionIdentity identity) : IAgentConnectionIdentityVerifier
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<AgentConnectionIdentity> VerifyAsync(
            Stream connection,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
            return identity;
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class QueueConnectionAcceptor(params Stream[] connections)
    {
        private readonly ConcurrentQueue<Stream> _connections = new(connections);

        public TaskCompletionSource NextAcceptStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource AcceptCancellationObserved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<Stream> AcceptAsync(CancellationToken cancellationToken)
        {
            if (_connections.TryDequeue(out var connection))
            {
                return connection;
            }

            NextAcceptStarted.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("Infinite accept unexpectedly completed.");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                AcceptCancellationObserved.TrySetResult();
                throw;
            }
        }
    }

    private sealed class FakeAgentClock : IAgentClock
    {
        private readonly object _sync = new();
        private readonly List<ScheduledDelay> _delays = [];

        public DateTimeOffset UtcNow { get; private set; } = new(2026, 8, 8, 0, 0, 0, TimeSpan.Zero);

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            lock (_sync)
            {
                var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var registration = cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
                _delays.Add(new ScheduledDelay(UtcNow + delay, completion, registration));
                return completion.Task;
            }
        }

        public void Advance(TimeSpan elapsed)
        {
            ScheduledDelay[] due;
            lock (_sync)
            {
                UtcNow += elapsed;
                due = _delays.Where(delay => delay.DueAt <= UtcNow).ToArray();
                _delays.RemoveAll(delay => delay.DueAt <= UtcNow);
            }

            foreach (var delay in due)
            {
                delay.Registration.Dispose();
                delay.Completion.TrySetResult();
            }
        }

        public void AdvanceWithoutCompletingDelays(TimeSpan elapsed)
        {
            lock (_sync)
            {
                UtcNow += elapsed;
            }
        }

        private sealed record ScheduledDelay(
            DateTimeOffset DueAt,
            TaskCompletionSource Completion,
            CancellationTokenRegistration Registration);
    }

    private sealed class BlockingConnection : Stream
    {
        private readonly MemoryStream _prefix;
        private readonly MemoryStream _written = new();
        private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private BlockingConnection(byte[] prefix)
        {
            _prefix = new MemoryStream(prefix);
        }

        public bool IsDisposed { get; private set; }
        public byte[] WrittenBytes => _written.ToArray();
        public override bool CanRead => !IsDisposed;
        public override bool CanSeek => false;
        public override bool CanWrite => !IsDisposed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public static async Task<BlockingConnection> CreateAsync(params AgentMessage[] messages)
        {
            await using var prefix = await ConnectionAsync(messages);
            return new BlockingConnection(prefix.ToArray());
        }

        public static async Task<BlockingConnection> CreateRawAsync(
            AgentMessage initial,
            string rawJson)
        {
            await using var prefix = await ConnectionAsync(initial);
            prefix.Position = prefix.Length;
            var payload = System.Text.Encoding.UTF8.GetBytes(rawJson);
            var header = new byte[sizeof(int)];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
            await prefix.WriteAsync(header);
            await prefix.WriteAsync(payload);
            return new BlockingConnection(prefix.ToArray());
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _prefix.ReadAsync(buffer, cancellationToken);
            if (read > 0)
            {
                return read;
            }

            await _closed.Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                IsDisposed = true;
                _prefix.Dispose();
                _closed.TrySetResult();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ControlledWriteConnection : Stream
    {
        private readonly MemoryStream _prefix;
        private readonly MemoryStream _written = new();
        private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _continueWrite = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly bool _failAfterPartialPayload;
        private readonly bool _pauseFirstWrite;
        private int _writeCalls;

        private ControlledWriteConnection(byte[] prefix, bool failAfterPartialPayload, bool pauseFirstWrite)
        {
            _prefix = new MemoryStream(prefix);
            _failAfterPartialPayload = failAfterPartialPayload;
            _pauseFirstWrite = pauseFirstWrite;
        }

        public TaskCompletionSource WriteStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool IsDisposed { get; private set; }
        public byte[] WrittenBytes => _written.ToArray();
        public override bool CanRead => !IsDisposed;
        public override bool CanSeek => false;
        public override bool CanWrite => !IsDisposed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public static async Task<ControlledWriteConnection> CreateAsync(
            bool failAfterPartialPayload = false,
            bool pauseFirstWrite = false)
        {
            await using var prefix = await ConnectionAsync(Hello());
            return new ControlledWriteConnection(prefix.ToArray(), failAfterPartialPayload, pauseFirstWrite);
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await _prefix.ReadAsync(buffer, cancellationToken);
            if (read > 0)
            {
                return read;
            }

            await _closed.Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var call = Interlocked.Increment(ref _writeCalls);
            if (_pauseFirstWrite && call == 1)
            {
                WriteStarted.TrySetResult();
                await _continueWrite.Task.WaitAsync(cancellationToken);
                if (IsDisposed)
                {
                    throw new IOException("connection replaced during write");
                }
            }

            if (_failAfterPartialPayload && call == 2)
            {
                _written.Write(buffer.Span[..Math.Min(3, buffer.Length)]);
                throw new IOException("partial payload write");
            }

            _written.Write(buffer.Span);
        }

        public void ContinueWrite() => _continueWrite.TrySetResult();

        protected override void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                IsDisposed = true;
                _prefix.Dispose();
                _closed.TrySetResult();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows named-pipe ACL support.";
            }
        }
    }
}
