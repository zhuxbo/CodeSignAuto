using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Threading.Channels;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Jobs;

namespace CodeSignAuto.EndToEnd.Tests;

[Flags]
public enum FakeAgentBehavior
{
    Complete = 0,
    HoldBeforeSigning = 1,
    HoldBeforeTerminal = 2,
    Fail = 4,
    ForgeHash = 8,
    ForgeSize = 16,
    HoldSecondBeforeSigning = 32,
    HoldSecondBeforeTerminal = 64,
    DisconnectAfterSign = 128,
    DuplicateTerminal = 256,
    StaleTerminal = 512,
    InvalidHeartbeatIdentity = 1024,
    WrongJobTerminal = 2048,
    DisconnectFirstAfterSign = 4096,
    PartialResult = 8192,
    AppendAfterMetadata = 16384,
}

internal sealed class FakeAgent : IAsyncDisposable
{
    public static readonly byte[] SafeTrailer = "\n% SSA-E2E deterministic unsigned orchestration result\n"u8.ToArray();

    private readonly string _pipeName;
    private readonly string _spoolRoot;
    private readonly string _userSid;
    private readonly int _sessionId;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly TaskCompletionSource _connected = NewSignal();
    private readonly TaskCompletionSource _beforeSigning = NewSignal();
    private readonly TaskCompletionSource _beforeTerminal = NewSignal();
    private readonly TaskCompletionSource _heldBeforeSigning = NewSignal();
    private readonly TaskCompletionSource _heldBeforeTerminal = NewSignal();
    private readonly TaskCompletionSource _releaseSigning = NewSignal();
    private readonly TaskCompletionSource _releaseTerminal = NewSignal();
    private readonly TaskCompletionSource<SignJobCommand> _firstCommand =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentQueue<SignJobCommand> _received = new();
    private readonly Channel<SignJobCommand> _commandEvents = Channel.CreateUnbounded<SignJobCommand>(
        new UnboundedChannelOptions { SingleReader = false, SingleWriter = true });
    private readonly AgentPipeClient _client;
    private readonly AgentStartupPreparationCache _startupPreparation;
    private Task? _runTask;
    private FakeAgentBehavior _behavior;
    private int _active;
    private int _maxConcurrency;
    private int _terminalCount;
    private int _connectionCount;
    private int _writtenAndFlushedAttemptCount;
    private int _disconnectAfterSignCount;

    public FakeAgent(string pipeName, string spoolRoot, string userSid, int sessionId)
    {
        _pipeName = pipeName;
        _spoolRoot = Path.GetFullPath(spoolRoot);
        _userSid = userSid;
        _sessionId = sessionId;
        _client = new AgentPipeClient(
            ConnectAsync,
            new SystemAgentDelay(),
            admissionLocked: null,
            postTerminalMessages: CreatePostTerminalMessages);
        _startupPreparation = new AgentStartupPreparationCache((command, _) =>
            Task.FromResult(new PrepareSimplySignSessionResult(
                command.RequestId,
                SimplySignSessionState.Ready,
                null)));
    }

    public IReadOnlyList<SignJobCommand> ReceivedCommands => _received.ToArray();

    public int MaxConcurrency => Volatile.Read(ref _maxConcurrency);

    public int TerminalCount => Volatile.Read(ref _terminalCount);

    public int ConnectionCount => Volatile.Read(ref _connectionCount);

    public int WrittenAndFlushedAttemptCount => Volatile.Read(ref _writtenAndFlushedAttemptCount);

    public int DisconnectAfterSignCount => Volatile.Read(ref _disconnectAfterSignCount);

    public AgentPipeClient Client => _client;

    public Task Connected => _connected.Task;

    public Task BeforeSigningReached => _beforeSigning.Task;

    public Task BeforeTerminalReached => _beforeTerminal.Task;

    public Task HeldBeforeSigningReached => _heldBeforeSigning.Task;

    public Task HeldBeforeTerminalReached => _heldBeforeTerminal.Task;

    public void Start(FakeAgentBehavior behavior = FakeAgentBehavior.Complete)
    {
        if (_runTask is not null)
        {
            throw new InvalidOperationException("fake_agent_already_started");
        }

        _behavior = behavior;
        var hello = new AgentHello(
            LengthPrefixedJsonProtocol.ProtocolVersion,
            Environment.ProcessId,
            _sessionId,
            _userSid,
            "1.0.0",
            ["authenticode", "pdf"]);
        _runTask = RunLoopAsync(
            hello,
            () => new AgentHeartbeat(
                (_behavior & FakeAgentBehavior.InvalidHeartbeatIdentity) != 0 ? _sessionId + 1 : _sessionId,
                "ready",
                "ready",
                "ready",
                "ready",
                _client.CurrentJobId,
                _sessionId,
                ReadyCapability("authenticode"),
                ReadyCapability("pdf"),
                1,
                certificates:
                [
                    ReadyCertificate("AA00"),
                    ReadyCertificate("CC00"),
                ]),
            ExecuteAsync);
    }

    public async Task<SignJobCommand> WaitForCommandAsync() =>
        await _firstCommand.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);

    public async Task<SignJobCommand> ReadNextCommandAsync() =>
        await _commandEvents.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);

    public void ReleaseBeforeSigning() => _releaseSigning.TrySetResult();

    public void ReleaseBeforeTerminal() => _releaseTerminal.TrySetResult();

    private CapabilitySnapshot ReadyCapability(string alias)
    {
        var now = DateTimeOffset.UtcNow;
        return new CapabilitySnapshot(
            true,
            true,
            true,
            "34567890",
            true,
            true,
            "abcdef12",
            true,
            true,
            "1234abcd",
            true,
            "ready",
            now.AddDays(1),
            "89ABCDEF",
            new SimplySignSessionSnapshot(
                SimplySignSessionState.Ready,
                1,
                now,
                now,
                _sessionId,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                "ready",
                0,
                null,
                true,
                _sessionId));
    }

    private static CertificateSummary ReadyCertificate(string serialNumber)
    {
        var now = DateTimeOffset.UtcNow;
        return new CertificateSummary(
            $"Test certificate {serialNumber}",
            serialNumber,
            now.AddDays(-1),
            now.AddDays(30),
            true,
            true,
            true,
            null);
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel();
        _releaseSigning.TrySetResult();
        _releaseTerminal.TrySetResult();
        if (_runTask is not null)
        {
            try
            {
                await _runTask.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _lifetime.Dispose();
        _startupPreparation.Dispose();
    }

    private async ValueTask<Stream> ConnectAsync(CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _connectionCount);
            _connected.TrySetResult();
            return pipe;
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task RunLoopAsync(
        AgentHello hello,
        Func<AgentHeartbeat> heartbeatFactory,
        SignJobCommandHandler handler)
    {
        while (!_lifetime.IsCancellationRequested)
        {
            try
            {
                await _client.RunWithPublicationAsync(
                    hello,
                    heartbeatFactory,
                    async (command, progress, token) => new JobTerminalPublication(
                        await handler(command, progress, token).ConfigureAwait(false)),
                    _lifetime.Token,
                    _startupPreparation).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error) when (
                !_lifetime.IsCancellationRequested &&
                error is IOException or ProtocolException or ObjectDisposedException)
            {
            }
        }
    }

    private async Task<JobTerminalMessage> ExecuteAsync(
        SignJobCommand command,
        JobProgressReporter progress,
        CancellationToken cancellationToken)
    {
        _received.Enqueue(command);
        _commandEvents.Writer.TryWrite(command);
        _firstCommand.TrySetResult(command);
        var ordinal = _received.Count;
        var active = Interlocked.Increment(ref _active);
        UpdateMaximum(active);
        try
        {
            _beforeSigning.TrySetResult();
            var holdSigning = (_behavior & FakeAgentBehavior.HoldBeforeSigning) != 0 ||
                (_behavior & FakeAgentBehavior.HoldSecondBeforeSigning) != 0 && ordinal == 2;
            if (holdSigning)
            {
                _heldBeforeSigning.TrySetResult();
                await _releaseSigning.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            await progress(20, "signing", cancellationToken).ConfigureAwait(false);
            if ((_behavior & FakeAgentBehavior.Fail) != 0)
            {
                Interlocked.Increment(ref _terminalCount);
                return new JobFailed(command.JobId, command.DispatchId, "pdf_sign_failed", "Synthetic signing failure.");
            }

            var inputPath = GetControlledPath(command.JobId, "input" + command.Extension);
            byte[] input;
            await using (var source = NoFollowFile.OpenRead(inputPath, FileShare.Read, 81_920))
            {
                if (!PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(source.SafeFileHandle, out var identity) ||
                    identity.LinkCount != 1 ||
                    source.Length != command.InputSize)
                {
                    return Corrupt(command);
                }

                input = new byte[checked((int)source.Length)];
                await source.ReadExactlyAsync(input, cancellationToken).ConfigureAwait(false);
            }

            var inputHash = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
            if (!string.Equals(inputHash, command.InputSha256, StringComparison.Ordinal))
            {
                return Corrupt(command);
            }

            var result = input.Concat(SafeTrailer).ToArray();
            var resultHash = Convert.ToHexString(SHA256.HashData(result)).ToLowerInvariant();
            var partPath = GetControlledPath(command.JobId, "result.part" + command.Extension);
            DeleteOrdinaryStalePart(partPath);
            await using (var output = new FileStream(
                partPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                81_920,
                FileOptions.Asynchronous))
            {
                var writtenResult = (_behavior & FakeAgentBehavior.PartialResult) != 0
                    ? result.AsMemory(0, Math.Max(1, result.Length / 2))
                    : result.AsMemory();
                await output.WriteAsync(writtenResult, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
                if ((_behavior & FakeAgentBehavior.AppendAfterMetadata) != 0)
                {
                    await output.WriteAsync("metadata-trailing-bytes"u8.ToArray(), cancellationToken)
                        .ConfigureAwait(false);
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
            }

            Interlocked.Increment(ref _writtenAndFlushedAttemptCount);

            await progress(70, "verifying", cancellationToken).ConfigureAwait(false);
            if ((_behavior & FakeAgentBehavior.DisconnectAfterSign) != 0 ||
                (_behavior & FakeAgentBehavior.DisconnectFirstAfterSign) != 0 && ordinal == 1)
            {
                Interlocked.Increment(ref _disconnectAfterSignCount);
                throw new IOException("synthetic_agent_disconnect_after_sign");
            }

            _beforeTerminal.TrySetResult();
            var holdTerminal = (_behavior & FakeAgentBehavior.HoldBeforeTerminal) != 0 ||
                (_behavior & FakeAgentBehavior.HoldSecondBeforeTerminal) != 0 && ordinal == 2;
            if (holdTerminal)
            {
                _heldBeforeTerminal.TrySetResult();
                await _releaseTerminal.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            Interlocked.Increment(ref _terminalCount);
            return new JobCompleted(
                command.JobId,
                command.DispatchId,
                (_behavior & FakeAgentBehavior.ForgeSize) != 0 ? result.LongLength + 1 : result.LongLength,
                (_behavior & FakeAgentBehavior.ForgeHash) != 0 ? new string('0', 64) : resultHash);
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    private JobFailed Corrupt(SignJobCommand command)
    {
        Interlocked.Increment(ref _terminalCount);
        return new JobFailed(command.JobId, command.DispatchId, "result_corrupt", "Synthetic input integrity failure.");
    }

    private string GetControlledPath(Guid jobId, string name)
    {
        var directory = Path.GetFullPath(Path.Combine(_spoolRoot, jobId.ToString("N")));
        var rootPrefix = _spoolRoot.EndsWith(Path.DirectorySeparatorChar)
            ? _spoolRoot
            : _spoolRoot + Path.DirectorySeparatorChar;
        if (!directory.StartsWith(rootPrefix, StringComparison.Ordinal) ||
            (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("fake_agent_spool_path_invalid");
        }

        return Path.Combine(directory, name);
    }

    private static void DeleteOrdinaryStalePart(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            if (info.LinkTarget is not null || Directory.Exists(path))
            {
                throw new IOException("fake_agent_stale_part_invalid");
            }

            return;
        }

        if ((info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
            info.LinkTarget is not null)
        {
            throw new IOException("fake_agent_stale_part_invalid");
        }

        using var first = NoFollowFile.OpenRead(path, FileShare.Read | FileShare.Delete, 81_920);
        if (!PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(first.SafeFileHandle, out var identity) ||
            identity.LinkCount != 1)
        {
            throw new IOException("fake_agent_stale_part_invalid");
        }

        using var current = NoFollowFile.OpenRead(path, FileShare.Read | FileShare.Delete, 81_920);
        if (!PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(current.SafeFileHandle, out var currentIdentity) ||
            currentIdentity.LinkCount != 1 || !currentIdentity.RefersToSameFile(identity))
        {
            throw new IOException("fake_agent_stale_part_invalid");
        }

        File.Delete(path);
    }

    private void UpdateMaximum(int active)
    {
        while (true)
        {
            var current = Volatile.Read(ref _maxConcurrency);
            if (active <= current || Interlocked.CompareExchange(ref _maxConcurrency, active, current) == current)
            {
                return;
            }
        }
    }

    private IReadOnlyList<AgentMessage> CreatePostTerminalMessages(JobTerminalMessage terminal)
    {
        if ((_behavior & FakeAgentBehavior.DuplicateTerminal) != 0)
        {
            return [terminal];
        }

        if ((_behavior & FakeAgentBehavior.StaleTerminal) != 0 && terminal is JobCompleted completed)
        {
            return
            [
                new JobCompleted(
                    completed.JobId,
                    Guid.NewGuid(),
                    completed.OutputSize,
                    completed.OutputSha256),
            ];
        }

        if ((_behavior & FakeAgentBehavior.WrongJobTerminal) != 0 && terminal is JobCompleted wrong)
        {
            return
            [
                new JobCompleted(
                    Guid.NewGuid(),
                    wrong.DispatchId,
                    wrong.OutputSize,
                    wrong.OutputSha256),
            ];
        }

        return [];
    }

    private static TaskCompletionSource NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);
}
