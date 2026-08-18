using System.IO.Pipes;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class AdminControlPipeTests
{
    private const string AdministratorSid = "S-1-5-21-1000";

    [Theory]
    [InlineData(false, true, 7)]
    [InlineData(true, false, 7)]
    [InlineData(true, true, 0)]
    public void Identity_must_be_local_elevated_and_interactive(
        bool isLocal,
        bool isAdministrator,
        int sessionId)
    {
        var hello = new AdminControlHello(
            AdminControlContract.ProtocolVersion,
            321,
            7,
            AdministratorSid);
        var identity = new AdminControlIdentity(
            321,
            sessionId,
            AdministratorSid,
            isAdministrator,
            isLocal);

        Assert.Throws<UnauthorizedAccessException>(() =>
            AdminControlPipeServer.ValidateIdentity(hello, identity));
    }

    [Fact]
    public void Identity_claims_must_match_the_verified_pipe_client()
    {
        var identity = new AdminControlIdentity(
            321,
            7,
            AdministratorSid,
            IsAdministrator: true,
            IsLocal: true);

        AdminControlPipeServer.ValidateIdentity(
            new AdminControlHello(
                AdminControlContract.ProtocolVersion,
                identity.ProcessId,
                identity.SessionId,
                identity.UserSid),
            identity);

        Assert.Throws<UnauthorizedAccessException>(() =>
            AdminControlPipeServer.ValidateIdentity(
                new AdminControlHello(
                    AdminControlContract.ProtocolVersion,
                    identity.ProcessId + 1,
                    identity.SessionId,
                    identity.UserSid),
                identity));
    }

    [WindowsFact]
    public void Windows_pipe_acl_grants_only_system_and_builtin_administrators()
    {
        using var pipe = AdminControlPipeServer.CreateNamedPipeServer();

        var rules = pipe.GetAccessControl()
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .ToArray();

        Assert.Equal(
            new[]
            {
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
            }.Order(StringComparer.Ordinal).ToArray(),
            rules.Select(rule => rule.IdentityReference.Value)
                .Order(StringComparer.Ordinal)
                .ToArray());
        Assert.All(
            rules,
            rule => Assert.Equal(
                PipeAccessRights.ReadWrite,
                rule.PipeAccessRights & PipeAccessRights.ReadWrite));
    }

    [WindowsFact]
    public async Task Windows_identity_verifier_recognizes_a_local_pipe_client()
    {
        using var server = AdminControlPipeServer.CreateNamedPipeServer();
        await using var client = new NamedPipeClientStream(
            ".",
            AdminControlPipeServer.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        var accept = server.WaitForConnectionAsync();

        await client.ConnectAsync(CancellationToken.None);
        await accept;
        var identity = await new WindowsAdminControlIdentityVerifier()
            .VerifyAsync(server, CancellationToken.None);

        using var current = WindowsIdentity.GetCurrent();
        Assert.True(identity.IsLocal);
        Assert.Equal(Environment.ProcessId, identity.ProcessId);
        Assert.Equal(Process.GetCurrentProcess().SessionId, identity.SessionId);
        Assert.Equal(current.User?.Value, identity.UserSid);
        Assert.Equal(
            new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator),
            identity.IsAdministrator);
    }

    [Fact]
    public async Task A_second_control_connection_is_rejected_while_the_verified_client_is_active()
    {
        var identity = new AdminControlIdentity(
            321,
            7,
            AdministratorSid,
            IsAdministrator: true,
            IsLocal: true);
        var server = new AdminControlPipeServer(
            new UnusedManagement(),
            new UnusedAgentControl(),
            new DisconnectedAgentHealthStatusSource(),
            new UnusedLocalJobs(),
            new FixedIdentityVerifier(identity));
        using var cancellation = new CancellationTokenSource();
        await using var first = new BlockingAfterHelloStream(await EncodeAsync(Hello()));
        var firstRun = server.ProcessConnectionAsync(first, cancellation.Token);
        await first.FirstWrite.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await using var second = new MemoryStream(await EncodeAsync(Hello()));

        var conflict = await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            server.ProcessConnectionAsync(second, CancellationToken.None));

        Assert.Equal("admin_control_connection_conflict", conflict.Message);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstRun);
    }

    [Fact]
    public async Task Client_identity_is_verified_before_the_server_reads_any_frame()
    {
        var verifier = new RejectingIdentityVerifier();
        var server = new AdminControlPipeServer(
            new UnusedManagement(),
            new UnusedAgentControl(),
            new DisconnectedAgentHealthStatusSource(),
            new UnusedLocalJobs(),
            verifier);
        await using var connection = new ReadCountingStream(await EncodeAsync(Hello()));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            server.ProcessConnectionAsync(connection, CancellationToken.None));

        Assert.Equal(1, verifier.Calls);
        Assert.Equal(0, connection.ReadCalls);
    }

    [Fact]
    public async Task Silent_accepted_client_is_timed_out_and_releases_the_connection_slot()
    {
        var identity = new AdminControlIdentity(
            321,
            7,
            AdministratorSid,
            IsAdministrator: true,
            IsLocal: true);
        var server = new AdminControlPipeServer(
            new UnusedManagement(),
            new UnusedAgentControl(),
            new DisconnectedAgentHealthStatusSource(),
            new UnusedLocalJobs(),
            new FixedIdentityVerifier(identity),
            requestReadTimeout: TimeSpan.FromMilliseconds(50));
        await using var first = new BlockingAfterHelloStream(await EncodeAsync(Hello()));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            server.ProcessConnectionAsync(first, CancellationToken.None));

        await using var second = new BlockingAfterHelloStream(await EncodeAsync(Hello()));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            server.ProcessConnectionAsync(second, CancellationToken.None));
        Assert.True(second.FirstWrite.Task.IsCompleted);
    }

    private static AdminControlHello Hello() => new(
        AdminControlContract.ProtocolVersion,
        321,
        7,
        AdministratorSid);

    private static async Task<byte[]> EncodeAsync(AgentMessage message)
    {
        await using var encoded = new MemoryStream();
        await LengthPrefixedJsonProtocol.WriteAsync(encoded, message, CancellationToken.None);
        return encoded.ToArray();
    }

    private sealed class FixedIdentityVerifier(AdminControlIdentity identity)
        : IAdminControlIdentityVerifier
    {
        public ValueTask<AdminControlIdentity> VerifyAsync(
            Stream connection,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(identity);
        }
    }

    private sealed class RejectingIdentityVerifier : IAdminControlIdentityVerifier
    {
        public int Calls { get; private set; }

        public ValueTask<AdminControlIdentity> VerifyAsync(
            Stream connection,
            CancellationToken cancellationToken)
        {
            Calls++;
            throw new UnauthorizedAccessException("admin_control_identity_mismatch");
        }
    }

    private sealed class UnusedManagement : IServiceManagementSnapshotProvider
    {
        public Task<ManagementSnapshot> CreateAsync(
            AgentHealthSnapshot health,
            CancellationToken cancellationToken) => throw new InvalidOperationException("unused");
    }

    private sealed class UnusedAgentControl : IAgentControlTransport
    {
        public Task<AgentControlResponse> SendControlAsync(
            AgentControlRequest request,
            CancellationToken cancellationToken) => throw new InvalidOperationException("unused");
    }

    private sealed class UnusedLocalJobs : IAdministratorLocalJobRequestHandler
    {
        public Task<AgentMessage> HandleAdministratorAsync(
            AgentMessage request,
            AgentConnectionIdentity identity,
            CancellationToken cancellationToken) => throw new InvalidOperationException("unused");
    }

    private sealed class BlockingAfterHelloStream(byte[] hello) : Stream
    {
        private readonly MemoryStream _input = new(hello, writable: false);

        public TaskCompletionSource FirstWrite { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var read = await _input.ReadAsync(buffer, cancellationToken);
            if (read != 0)
            {
                return read;
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FirstWrite.TrySetResult();
            return ValueTask.CompletedTask;
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class ReadCountingStream(byte[] input) : MemoryStream(input)
    {
        public int ReadCalls { get; private set; }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ReadCalls++;
            return base.ReadAsync(buffer, cancellationToken);
        }
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
