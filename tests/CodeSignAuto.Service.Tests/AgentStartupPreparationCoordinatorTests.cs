using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Ipc;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class AgentStartupPreparationCoordinatorTests
{
    [Fact]
    public async Task On_demand_login_shares_one_inflight_relogin_command()
    {
        var transport = new RecordingControlTransport();
        var login = new AgentOnDemandLogin(transport);

        var first = login.LoginAsync(default);
        var second = login.LoginAsync(default);
        var request = await transport.Request.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(AdminControlContract.Relogin, request.Operation);
        Assert.Equal(1, transport.Calls);
        transport.Completion.SetResult(new AgentControlResponse(
            request.RequestId,
            request.Operation,
            ProtocolV3TestFixtures.Heartbeat(),
            null,
            null,
            null,
            null,
            null));
        Assert.True(await first);
        Assert.True(await second);
    }

    [Fact]
    public async Task Completed_on_demand_attempt_is_not_reused_for_a_later_request()
    {
        var transport = new ImmediateFailureControlTransport();
        var login = new AgentOnDemandLogin(transport);

        Assert.False(await login.LoginAsync(default));
        Assert.False(await login.LoginAsync(default));

        Assert.Equal(2, transport.Calls);
    }

    [Fact]
    public async Task Delayed_first_verified_connection_starts_once_and_completion_prevents_same_process_reconnect_duplicate()
    {
        var transport = new RecordingPreparationTransport();
        var requestId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var coordinator = new AgentStartupPreparationCoordinator(transport, () => requestId);
        using var cancellation = new CancellationTokenSource();
        var run = coordinator.RunAsync(cancellation.Token);
        Assert.Equal(AgentStartupPreparationStatus.Pending, coordinator.Current.Status);

        transport.Connect(Guid.NewGuid());
        var first = await transport.NextSendAsync();
        Assert.Equal(requestId, first.Command.RequestId);
        Assert.Equal(AgentStartupPreparationStatus.Running, coordinator.Current.Status);
        transport.Complete(first.ConnectionId, new PrepareSimplySignSessionResult(
            requestId, SimplySignSessionState.Ready, null));
        await WaitUntilAsync(() => coordinator.Current.Status == AgentStartupPreparationStatus.Completed);
        transport.Disconnect(first.ConnectionId);
        transport.Connect(Guid.NewGuid());

        await Task.Delay(20);
        Assert.False(transport.HasPendingSend);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Completed_preparation_runs_again_for_a_restarted_agent_process()
    {
        var transport = new RecordingPreparationTransport();
        var firstRequestId = Guid.NewGuid();
        var restartedRequestId = Guid.NewGuid();
        var requestIds = new Queue<Guid>([firstRequestId, restartedRequestId]);
        var coordinator = new AgentStartupPreparationCoordinator(transport, requestIds.Dequeue);
        using var cancellation = new CancellationTokenSource();
        var run = coordinator.RunAsync(cancellation.Token);
        var firstConnection = Guid.NewGuid();
        transport.Connect(firstConnection, processId: 101);
        var first = await transport.NextSendAsync();
        transport.Complete(firstConnection, new PrepareSimplySignSessionResult(
            firstRequestId, SimplySignSessionState.Ready, null));
        await WaitUntilAsync(() => coordinator.Current.Status == AgentStartupPreparationStatus.Completed);

        transport.Disconnect(firstConnection);
        var restartedConnection = Guid.NewGuid();
        transport.Connect(restartedConnection, processId: 202);

        var restarted = await transport.NextSendAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(restartedConnection, restarted.ConnectionId);
        Assert.Equal(restartedRequestId, restarted.Command.RequestId);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Connection_replacement_resends_running_request_but_failed_result_completes_without_retry()
    {
        var transport = new RecordingPreparationTransport();
        var requestId = Guid.NewGuid();
        var coordinator = new AgentStartupPreparationCoordinator(transport, () => requestId);
        using var cancellation = new CancellationTokenSource();
        var run = coordinator.RunAsync(cancellation.Token);
        var firstConnection = Guid.NewGuid();
        transport.Connect(firstConnection);
        _ = await transport.NextSendAsync();
        transport.Disconnect(firstConnection);
        var replacement = Guid.NewGuid();
        transport.Connect(replacement);

        var resumed = await transport.NextSendAsync();
        Assert.Equal(replacement, resumed.ConnectionId);
        Assert.Equal(requestId, resumed.Command.RequestId);
        transport.Complete(replacement, new PrepareSimplySignSessionResult(
            requestId, SimplySignSessionState.Failed, "simplysign_login_failed"));
        await WaitUntilAsync(() => coordinator.Current.Status == AgentStartupPreparationStatus.Completed);
        Assert.Equal("simplysign_login_failed", coordinator.Current.Result!.ErrorCode);
        Assert.Equal(requestId, coordinator.Current.RequestId);
        Assert.False(transport.HasPendingSend);

        transport.Disconnect(replacement);
        transport.Connect(Guid.NewGuid());
        await Task.Delay(20);
        Assert.False(transport.HasPendingSend);
        Assert.False(run.IsCompleted);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Failed_result_does_not_start_a_background_retry_on_the_same_connection()
    {
        var transport = new RecordingPreparationTransport();
        var requestId = Guid.NewGuid();
        var coordinator = new AgentStartupPreparationCoordinator(transport, () => requestId);
        using var cancellation = new CancellationTokenSource();
        var run = coordinator.RunAsync(cancellation.Token);
        var connectionId = Guid.NewGuid();
        transport.Connect(connectionId);
        var first = await transport.NextSendAsync();

        transport.Complete(connectionId, new PrepareSimplySignSessionResult(
            requestId, SimplySignSessionState.Failed, "simplysign_login_failed"));
        await WaitUntilAsync(() => coordinator.Current.Status == AgentStartupPreparationStatus.Completed);
        Assert.False(transport.HasPendingSend);

        await Task.Delay(20);
        Assert.False(transport.HasPendingSend);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task New_service_process_coordinator_gets_new_request_and_shutdown_is_joined()
    {
        var transport = new RecordingPreparationTransport();
        var ids = new Queue<Guid>([Guid.NewGuid(), Guid.NewGuid()]);
        var first = new AgentStartupPreparationCoordinator(transport, ids.Dequeue);
        using (var cancellation = new CancellationTokenSource())
        {
            var run = first.RunAsync(cancellation.Token);
            transport.Connect(Guid.NewGuid());
            var sent = await transport.NextSendAsync();
            Assert.Equal(first.Current.RequestId, sent.Command.RequestId);
            transport.Disconnect(sent.ConnectionId);
            cancellation.Cancel();
            await run;
        }

        var second = new AgentStartupPreparationCoordinator(transport, ids.Dequeue);
        using var secondCancellation = new CancellationTokenSource();
        var secondRun = second.RunAsync(secondCancellation.Token);
        transport.Connect(Guid.NewGuid());
        var secondSent = await transport.NextSendAsync();
        Assert.NotEqual(first.Current.RequestId, secondSent.Command.RequestId);
        secondCancellation.Cancel();
        await secondRun;
    }

    [Fact]
    public async Task Connection_lifetime_cancellation_during_send_waits_for_reconnect_with_same_request()
    {
        var transport = new RecordingPreparationTransport { CancelNextSend = true };
        var requestId = Guid.NewGuid();
        var coordinator = new AgentStartupPreparationCoordinator(transport, () => requestId);
        using var cancellation = new CancellationTokenSource();
        var run = coordinator.RunAsync(cancellation.Token);
        transport.Connect(Guid.NewGuid());
        await transport.SendAttempted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.False(run.IsCompleted);
        transport.Connect(Guid.NewGuid());
        var resumed = await transport.NextSendAsync();

        Assert.Equal(requestId, resumed.Command.RequestId);
        cancellation.Cancel();
        await run;
    }

    [Fact]
    public async Task Result_from_replaced_connection_cannot_complete_the_current_request()
    {
        var transport = new RecordingPreparationTransport();
        var requestId = Guid.NewGuid();
        var coordinator = new AgentStartupPreparationCoordinator(transport, () => requestId);
        using var cancellation = new CancellationTokenSource();
        var run = coordinator.RunAsync(cancellation.Token);
        var oldConnection = Guid.NewGuid();
        transport.Connect(oldConnection);
        _ = await transport.NextSendAsync();
        var currentConnection = Guid.NewGuid();
        transport.Connect(currentConnection);
        var replacementSend = await transport.NextSendAsync();
        Assert.Equal(currentConnection, replacementSend.ConnectionId);

        transport.Complete(oldConnection, new PrepareSimplySignSessionResult(
            requestId,
            SimplySignSessionState.Ready,
            null));
        await Task.Delay(20);

        Assert.Equal(AgentStartupPreparationStatus.Running, coordinator.Current.Status);
        transport.Complete(currentConnection, new PrepareSimplySignSessionResult(
            requestId,
            SimplySignSessionState.Ready,
            null));
        await WaitUntilAsync(() => coordinator.Current.Status == AgentStartupPreparationStatus.Completed);
        cancellation.Cancel();
        await run;
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        while (!condition())
        {
            await Task.Delay(10, timeout.Token);
        }
    }

    private sealed class RecordingPreparationTransport : IAgentStartupPreparationTransport
    {
        private readonly System.Threading.Channels.Channel<(Guid ConnectionId, PrepareSimplySignSessionCommand Command)> _sends =
            System.Threading.Channels.Channel.CreateUnbounded<(Guid, PrepareSimplySignSessionCommand)>();

        public event EventHandler<AgentConnectionStateChangedEventArgs>? ConnectionStateChanged;
        public event EventHandler<AgentMessageReceivedEventArgs>? MessageReceived;
        public AgentConnectionSnapshot? CurrentConnection { get; private set; }
        public bool HasPendingSend => _sends.Reader.TryPeek(out _);
        public bool CancelNextSend { get; set; }
        public TaskCompletionSource SendAttempted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task SendPreparationAsync(Guid connectionId, PrepareSimplySignSessionCommand command, CancellationToken cancellationToken)
        {
            SendAttempted.TrySetResult();
            if (CancelNextSend)
            {
                CancelNextSend = false;
                return Task.FromCanceled(new CancellationToken(canceled: true));
            }

            return _sends.Writer.WriteAsync((connectionId, command), cancellationToken).AsTask();
        }

        public ValueTask<(Guid ConnectionId, PrepareSimplySignSessionCommand Command)> NextSendAsync() =>
            _sends.Reader.ReadAsync();

        public void Connect(Guid connectionId, int processId = 1)
        {
            CurrentConnection = new AgentConnectionSnapshot(connectionId, processId, 7, null);
            ConnectionStateChanged?.Invoke(this, new AgentConnectionStateChangedEventArgs(
                connectionId, AgentConnectionStatus.Connected, processId, 7, "verified"));
        }

        public void Disconnect(Guid connectionId)
        {
            if (CurrentConnection?.ConnectionId == connectionId)
            {
                CurrentConnection = null;
            }
            ConnectionStateChanged?.Invoke(this, new AgentConnectionStateChangedEventArgs(
                connectionId, AgentConnectionStatus.Disconnected, 1, 7, "closed"));
        }

        public void Complete(Guid connectionId, PrepareSimplySignSessionResult result) =>
            MessageReceived?.Invoke(this, new AgentMessageReceivedEventArgs(connectionId, result));
    }

    private sealed class RecordingControlTransport : IAgentControlTransport
    {
        public TaskCompletionSource<AgentControlRequest> Request { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<AgentControlResponse> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Calls { get; private set; }

        public Task<AgentControlResponse> SendControlAsync(
            AgentControlRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            Request.TrySetResult(request);
            return Completion.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class ImmediateFailureControlTransport : IAgentControlTransport
    {
        public int Calls { get; private set; }

        public Task<AgentControlResponse> SendControlAsync(
            AgentControlRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new AgentControlResponse(
                request.RequestId,
                request.Operation,
                null,
                null,
                null,
                null,
                "management_unavailable",
                Guid.NewGuid()));
        }
    }
}
