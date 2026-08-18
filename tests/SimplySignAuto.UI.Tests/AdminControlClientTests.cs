using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.App.Control;
using SimplySignAuto.App.UI;
using SimplySignAuto.Protocol;
using System.IO.Pipes;

namespace SimplySignAuto.UI.Tests;

public sealed class AdminControlClientTests
{
    [Theory]
    [InlineData(false, "S-1-5-18", 0)]
    [InlineData(true, "S-1-5-21-1000", 0)]
    [InlineData(true, "S-1-5-18", 7)]
    public void Control_server_must_be_an_inspectable_local_system_session_zero_process(
        bool inspectionSucceeded,
        string userSid,
        uint sessionId)
    {
        var evidence = new ActivationServerIdentityEvidence(
            inspectionSucceeded,
            userSid,
            sessionId,
            "C:\\Program Files\\SimplySignAuto\\SimplySignAuto.exe");

        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsAdminControlServerIdentityVerifier.ValidateEvidence(evidence));
    }

    [Fact]
    public async Task Client_authenticates_the_pipe_server_before_sending_hello_or_otp_data()
    {
        using var connection = new NonDisposingMemoryStream();
        var verifier = new RejectingServerIdentityVerifier();
        using var client = new AdminControlClient(
            _ => ValueTask.FromResult<Stream>(connection),
            new FixedClientIdentity(),
            serverIdentityVerifier: verifier);

        await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            client.RefreshAsync(CancellationToken.None));

        Assert.Equal(1, verifier.Calls);
        Assert.Equal(0, connection.Length);
    }

    [WindowsFact]
    public async Task Real_named_pipe_server_not_running_as_local_system_is_rejected()
    {
        var pipeName = $"SimplySignAuto.Control.Tests.{Guid.NewGuid():N}";
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        using var client = new AdminControlClient(
            async cancellationToken =>
            {
                var pipe = new NamedPipeClientStream(
                    ".",
                    pipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous);
                await pipe.ConnectAsync(cancellationToken);
                return pipe;
            },
            new FixedClientIdentity());
        var accept = server.WaitForConnectionAsync();

        await Assert.ThrowsAsync<ManagementUnavailableException>(() =>
            client.RefreshAsync(CancellationToken.None));
        await accept;
    }

    [Fact]
    public void Local_job_operations_retain_the_established_operation_timeouts()
    {
        Assert.Equal(TimeSpan.FromSeconds(15), AdminControlClient.LocalCreateTimeout);
        Assert.Equal(TimeSpan.FromMinutes(10), AdminControlClient.LocalCompleteTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), AdminControlClient.LocalResultTimeout);
    }

    [Fact]
    public async Task Local_transport_failure_is_transient_instead_of_losing_pending_submission()
    {
        using var client = new AdminControlClient(
            _ => ValueTask.FromResult<Stream>(new NonDisposingMemoryStream()),
            new FixedClientIdentity(),
            serverIdentityVerifier: new RejectingServerIdentityVerifier());
        var request = new LocalJobCreateRequest(
            Guid.NewGuid(),
            "document.pdf",
            ".pdf",
            128,
            "{\"kind\":\"pdf\",\"digest_algorithm\":\"sha256\"}");

        var error = await Assert.ThrowsAsync<LocalJobException>(() =>
            client.CreateLocalJobAsync(request, CancellationToken.None));

        Assert.Equal("local_job_unavailable", error.Code);
        Assert.Equal(LocalJobRejectionDisposition.Transient, error.Disposition);
    }

    [Fact]
    public async Task Complete_retries_the_same_request_on_a_fresh_authenticated_connection()
    {
        var request = new LocalJobUploadCompleted(
            Guid.NewGuid(),
            Guid.NewGuid(),
            new string('b', 32),
            128,
            new string('a', 64));
        var first = await ScriptedClientStream.CreateAsync(
            new AdminControlAccepted(AdminControlContract.ProtocolVersion),
            failAfterInput: true);
        var second = await ScriptedClientStream.CreateAsync(
            new AdminControlAccepted(AdminControlContract.ProtocolVersion),
            new LocalJobAccepted(request.RequestId, request.JobId));
        var connections = new Queue<ScriptedClientStream>([first, second]);
        using var client = new AdminControlClient(
            _ => ValueTask.FromResult<Stream>(connections.Dequeue()),
            new FixedClientIdentity(),
            serverIdentityVerifier: new AcceptingServerIdentityVerifier());

        var accepted = await client.CompleteLocalJobAsync(request, CancellationToken.None);

        Assert.Equal(request.JobId, accepted.JobId);
        Assert.Empty(connections);
        Assert.Equal(request, await ReadRequestAsync(first.Written));
        Assert.Equal(request, await ReadRequestAsync(second.Written));
    }

    private static async Task<AgentMessage> ReadRequestAsync(byte[] written)
    {
        await using var stream = new MemoryStream(written, writable: false);
        Assert.IsType<AdminControlHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(
            stream,
            CancellationToken.None));
        return await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(
            stream,
            CancellationToken.None);
    }

    private sealed class RejectingServerIdentityVerifier : IAdminControlServerIdentityVerifier
    {
        public int Calls { get; private set; }

        public void Verify(Stream connection)
        {
            Calls++;
            throw new UnauthorizedAccessException("admin_control_server_identity_mismatch");
        }
    }

    private sealed class AcceptingServerIdentityVerifier : IAdminControlServerIdentityVerifier
    {
        public void Verify(Stream connection)
        {
        }
    }

    private sealed class FixedClientIdentity : IAdminControlClientIdentityProvider
    {
        public AdminControlClientIdentity GetCurrent() =>
            new(321, 7, "S-1-5-21-1000");
    }

    private sealed class NonDisposingMemoryStream : MemoryStream
    {
        protected override void Dispose(bool disposing)
        {
        }
    }

    private sealed class ScriptedClientStream : Stream
    {
        private readonly MemoryStream _input;
        private readonly MemoryStream _output = new();
        private readonly bool _failAfterInput;

        private ScriptedClientStream(byte[] input, bool failAfterInput)
        {
            _input = new MemoryStream(input, writable: false);
            _failAfterInput = failAfterInput;
        }

        public byte[] Written => _output.ToArray();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public static async Task<ScriptedClientStream> CreateAsync(
            AgentMessage first,
            AgentMessage? second = null,
            bool failAfterInput = false)
        {
            await using var input = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(input, first, CancellationToken.None);
            if (second is not null)
            {
                await LengthPrefixedJsonProtocol.WriteAsync(input, second, CancellationToken.None);
            }

            return new ScriptedClientStream(input.ToArray(), failAfterInput);
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await _input.ReadAsync(buffer, cancellationToken);
            if (read == 0 && _failAfterInput)
            {
                throw new IOException("simulated_disconnect");
            }

            return read;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _output.WriteAsync(buffer, cancellationToken);

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
        }

        public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }


    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows named-pipe server identity APIs.";
            }
        }
    }
}
