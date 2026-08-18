using System.Text;
using SimplySignAuto.App.UI;

namespace SimplySignAuto.UI.Tests;

public sealed class SingleInstanceActivatorTests
{
    private const string SigningSid = "S-1-5-21-1000";
    private const string CurrentExecutable = @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe";

    [Fact]
    public void Activation_server_identity_rejects_evidence_unavailable_to_a_low_privilege_client()
    {
        IActivationServerIdentityVerifier verifier = new ActivationServerIdentityVerifier();

        Assert.False(verifier.IsTrusted(
            ActivationServerIdentityEvidence.Unavailable,
            SigningSid,
            currentSessionId: 7,
            CurrentExecutable));
    }

    [Fact]
    public void Activation_server_identity_rejects_a_different_or_zero_session()
    {
        IActivationServerIdentityVerifier verifier = new ActivationServerIdentityVerifier();
        var wrongSession = new ActivationServerIdentityEvidence(
            InspectionSucceeded: true,
            SigningSid,
            SessionId: 8,
            CurrentExecutable);
        var zeroSession = wrongSession with { SessionId = 0 };

        Assert.False(verifier.IsTrusted(wrongSession, SigningSid, 7, CurrentExecutable));
        Assert.False(verifier.IsTrusted(zeroSession, SigningSid, 0, CurrentExecutable));
    }

    [Fact]
    public void Activation_server_identity_rejects_a_different_executable_or_user()
    {
        IActivationServerIdentityVerifier verifier = new ActivationServerIdentityVerifier();
        var trusted = new ActivationServerIdentityEvidence(
            InspectionSucceeded: true,
            SigningSid,
            SessionId: 7,
            CurrentExecutable);

        Assert.False(verifier.IsTrusted(
            trusted with { ExecutablePath = @"C:\Temp\SimplySignAuto.exe" },
            SigningSid,
            7,
            CurrentExecutable));
        Assert.False(verifier.IsTrusted(
            trusted with { UserSid = "S-1-5-21-2000" },
            SigningSid,
            7,
            CurrentExecutable));
        Assert.True(verifier.IsTrusted(trusted, SigningSid, 7, CurrentExecutable));
    }

    [Fact]
    public async Task Untrusted_server_identity_is_rejected_before_show_is_written()
    {
        await using var stream = new ScriptedDuplexStream([5, (byte)'s', (byte)'h', (byte)'o', (byte)'w', (byte)'n']);

        var accepted = await ActivationWireProtocol.TrySendShowAndAwaitAcknowledgementAsync(
            stream,
            ActivationServerIdentityEvidence.Unavailable,
            new ActivationServerIdentityVerifier(),
            SigningSid,
            currentSessionId: 7,
            CurrentExecutable,
            CancellationToken.None);

        Assert.False(accepted);
        Assert.Empty(stream.Written);
    }

    [Fact]
    public void Activation_names_are_versioned_and_derived_without_exposing_the_sid()
    {
        var names = ActivationNames.ForSigningUser(SigningSid);

        Assert.Equal(
            "SimplySignAuto.Activation.v1.f051b5cbf3c10c7c27e426dc66de5275d4588f456c9875ed690e47ccda569634",
            names.PipeName);
        Assert.Equal("Local\\SimplySignAuto.Agent.S-1-5-21-1000", names.AgentMutexName);
        Assert.DoesNotContain(SigningSid, names.PipeName, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Existing_instance_receives_show_without_starting_another_agent()
    {
        var transport = new ScriptedActivationTransport(sendResults: [true]);
        var activator = new SingleInstanceActivator(transport, new RecordingDelay());
        var starts = 0;

        var exitCode = await activator.RunSingleAsync(
            SigningSid,
            (_, _) =>
            {
                starts++;
                return Task.FromResult(9);
            },
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(0, starts);
        Assert.Equal(0, transport.CreateServerCalls);
    }

    [Fact]
    public async Task First_start_race_retries_activation_with_a_fixed_bound()
    {
        var transport = new ScriptedActivationTransport(
            sendResults: [false, false, false, true],
            agentInstanceExists: true);
        var delay = new RecordingDelay();
        var activator = new SingleInstanceActivator(transport, delay);

        var exitCode = await activator.RunSingleAsync(
            SigningSid,
            (_, _) => throw new InvalidOperationException("must not start"),
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(3, delay.Calls);
        Assert.Equal(0, transport.CreateServerCalls);
    }

    [Fact]
    public async Task Unreachable_existing_instance_fails_after_the_bounded_retry_count()
    {
        var transport = new ScriptedActivationTransport(
            sendResults: [false, false, false, false, false],
            agentInstanceExists: true);
        var delay = new RecordingDelay();
        var activator = new SingleInstanceActivator(transport, delay);

        var failure = await Assert.ThrowsAsync<ActivationException>(() => activator.RunSingleAsync(
            SigningSid,
            (_, _) => Task.FromResult(0),
            CancellationToken.None));

        Assert.Equal("activation_unavailable", failure.Code);
        Assert.Equal(5, transport.SendCalls);
        Assert.Equal(4, delay.Calls);
    }

    [Fact]
    public async Task A_new_instance_claims_the_activation_server_before_starting_the_agent()
    {
        var server = new RecordingActivationServer();
        var transport = new ScriptedActivationTransport([false], server: server);
        var activator = new SingleInstanceActivator(transport, new RecordingDelay());
        IActivationServer? ownedServer = null;

        var exitCode = await activator.RunSingleAsync(
            SigningSid,
            (claimed, _) =>
            {
                ownedServer = claimed;
                return Task.FromResult(17);
            },
            CancellationToken.None);

        Assert.Equal(17, exitCode);
        Assert.Same(server, ownedServer);
        Assert.Equal(1, transport.CreateServerCalls);
    }

    [Fact]
    public async Task Lost_server_claim_retries_the_winning_instance_instead_of_starting()
    {
        var transport = new ScriptedActivationTransport([false, false, true], server: null);
        var activator = new SingleInstanceActivator(transport, new RecordingDelay());
        var starts = 0;

        var exitCode = await activator.RunSingleAsync(
            SigningSid,
            (_, _) =>
            {
                starts++;
                return Task.FromResult(0);
            },
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(0, starts);
    }

    [Theory]
    [InlineData("SHOW")]
    [InlineData("show\n")]
    [InlineData("showshow")]
    [InlineData("")]
    public async Task Activation_handler_rejects_unknown_duplicate_or_oversized_messages(string message)
    {
        var dispatcher = new GuardedDispatcher();
        var window = new GuardedWindow(dispatcher);
        var handler = new ActivationCommandHandler(dispatcher, window);

        var accepted = await handler.HandleAsync(Encoding.ASCII.GetBytes(message), CancellationToken.None);

        Assert.False(accepted);
        Assert.False(window.WasShown);
    }

    [Fact]
    public async Task Show_is_dispatched_before_window_controls_are_touched()
    {
        var dispatcher = new GuardedDispatcher();
        var window = new GuardedWindow(dispatcher);
        var handler = new ActivationCommandHandler(dispatcher, window);

        var accepted = await handler.HandleAsync("show"u8.ToArray(), CancellationToken.None);

        Assert.True(accepted);
        Assert.True(window.WasShown);
        Assert.Equal(1, dispatcher.Invocations);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\u0005wrong")]
    [InlineData("shown")]
    public async Task Activation_transport_rejects_missing_unframed_or_incorrect_acknowledgements(
        string acknowledgement)
    {
        await using var stream = new ScriptedDuplexStream(Encoding.ASCII.GetBytes(acknowledgement));

        var accepted = await ActivationWireProtocol.TrySendShowAndAwaitAcknowledgementAsync(
            stream,
            CancellationToken.None);

        Assert.False(accepted);
        Assert.Equal([4, (byte)'s', (byte)'h', (byte)'o', (byte)'w'], stream.Written);
    }

    [Fact]
    public async Task Activation_transport_accepts_only_the_exact_framed_acknowledgement()
    {
        await using var stream = new ScriptedDuplexStream([5, (byte)'s', (byte)'h', (byte)'o', (byte)'w', (byte)'n']);

        var accepted = await ActivationWireProtocol.TrySendShowAndAwaitAcknowledgementAsync(
            stream,
            CancellationToken.None);

        Assert.True(accepted);
        Assert.Equal(1, stream.WriteCalls);
    }

    [Fact]
    public async Task Activation_transport_rejects_concatenated_acknowledgements()
    {
        await using var stream = new ScriptedDuplexStream(
            [5, (byte)'s', (byte)'h', (byte)'o', (byte)'w', (byte)'n',
             5, (byte)'s', (byte)'h', (byte)'o', (byte)'w', (byte)'n']);

        var accepted = await ActivationWireProtocol.TrySendShowAndAwaitAcknowledgementAsync(
            stream,
            CancellationToken.None);

        Assert.False(accepted);
    }

    [Theory]
    [InlineData(new byte[] { 4, (byte)'s', (byte)'h', (byte)'o', (byte)'w', 4, (byte)'s', (byte)'h', (byte)'o', (byte)'w' })]
    [InlineData(new byte[] { 4, (byte)'s', (byte)'h', (byte)'o', (byte)'w', 0 })]
    public async Task Concatenated_or_trailing_show_frame_is_rejected_without_an_ack(byte[] message)
    {
        var dispatcher = new GuardedDispatcher();
        var window = new GuardedWindow(dispatcher);
        var handler = new ActivationCommandHandler(dispatcher, window);
        await using var output = new ScriptedDuplexStream([]);

        var accepted = await ActivationWireProtocol.TryHandleShowMessageAsync(
            message,
            handler,
            output,
            CancellationToken.None);

        Assert.False(accepted);
        Assert.False(window.WasShown);
        Assert.Empty(output.Written);
    }

    private sealed class ScriptedActivationTransport(
        IReadOnlyList<bool> sendResults,
        bool agentInstanceExists = false,
        IActivationServer? server = null) : IActivationTransport
    {
        private readonly Queue<bool> _sendResults = new(sendResults);

        public int SendCalls { get; private set; }

        public int CreateServerCalls { get; private set; }

        public Task<bool> TrySendShowAsync(
            ActivationNames names,
            string signingUserSid,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SendCalls++;
            return Task.FromResult(_sendResults.Count > 0 && _sendResults.Dequeue());
        }

        public bool AgentInstanceExists(ActivationNames names) => agentInstanceExists;

        public ValueTask<IActivationServer?> TryCreateServerAsync(
            ActivationNames names,
            string signingUserSid,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CreateServerCalls++;
            return ValueTask.FromResult(server);
        }
    }

    private sealed class RecordingDelay : IActivationRetryDelay
    {
        public int Calls { get; private set; }

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingActivationServer : IActivationServer
    {
        public Task RunAsync(ActivationCommandHandler handler, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class GuardedDispatcher : IUiDispatcher
    {
        public bool IsDispatching { get; private set; }

        public int Invocations { get; private set; }

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Invocations++;
            IsDispatching = true;
            try
            {
                action();
            }
            finally
            {
                IsDispatching = false;
            }

            return Task.CompletedTask;
        }
    }

    private sealed class GuardedWindow(GuardedDispatcher dispatcher) : IWindowController
    {
        public bool WasShown { get; private set; }

        public void ShowRestoreActivate()
        {
            Assert.True(dispatcher.IsDispatching);
            WasShown = true;
        }

        public void Hide()
        {
        }

        public void CloseForExit()
        {
        }

        public void ShowNotice(string message)
        {
        }
    }

    private sealed class ScriptedDuplexStream(byte[] response) : Stream
    {
        private readonly MemoryStream _read = new(response, writable: false);
        private readonly MemoryStream _written = new();

        public byte[] Written => _written.ToArray();

        public int WriteCalls { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public override int Read(byte[] buffer, int offset, int count) => _read.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _read.ReadAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => _written.Write(buffer, offset, count);

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            WriteCalls++;
            await _written.WriteAsync(buffer, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _read.Dispose();
                _written.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
