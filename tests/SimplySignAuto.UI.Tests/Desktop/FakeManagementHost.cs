using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using SimplySignAuto.App.UI.Testing;

namespace SimplySignAuto.UI.Tests.Desktop;

internal sealed class FakeManagementHost : IAsyncDisposable
{
    private readonly UiTestLaunchOptions _expected;
    private readonly TaskCompletionSource<int> _expectedProcessId =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly NamedPipeServerStream _server;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _heartbeat = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _run;
    private StreamWriter? _writer;
    private int _disposed;

    public FakeManagementHost(UiTestLaunchOptions expected, bool deferProcessBinding = false)
    {
        _expected = expected ?? throw new ArgumentNullException(nameof(expected));
        _server = new NamedPipeServerStream(
            expected.PipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        if (!deferProcessBinding)
        {
            _expectedProcessId.TrySetResult(expected.ProcessId);
        }

        _run = RunAsync();
    }

    public Task Connected => _connected.Task;

    public Task HeartbeatReceived => _heartbeat.Task;

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public void BindProcessId(int processId)
    {
        if (processId <= 0 || !_expectedProcessId.TrySetResult(processId))
        {
            throw new InvalidOperationException("fake_host_process_already_bound");
        }
    }

    public async Task RequestExitAsync(CancellationToken cancellationToken = default)
    {
        await Connected.WaitAsync(cancellationToken);
        var writer = _writer ?? throw new InvalidOperationException("fake_host_not_connected");
        await writer.WriteLineAsync("{\"schemaVersion\":1,\"kind\":\"exit\"}")
            .WaitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetime.Cancel();
        _server.Dispose();
        try
        {
            await _run.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or ObjectDisposedException)
        {
        }

        _lifetime.Dispose();
    }

    private async Task RunAsync()
    {
        await _server.WaitForConnectionAsync(_lifetime.Token);
        using var reader = new StreamReader(
            _server,
            new UTF8Encoding(false, true),
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024,
            leaveOpen: true);
        _writer = new StreamWriter(
            _server,
            new UTF8Encoding(false, true),
            bufferSize: 1024,
            leaveOpen: true)
        {
            AutoFlush = true,
            NewLine = "\n",
        };
        var line = await reader.ReadLineAsync(_lifetime.Token);
        var handshake = line is null ? null : ParseHandshake(line);
        var expected = _expected with
        {
            ProcessId = await _expectedProcessId.Task.WaitAsync(_lifetime.Token),
        };
        var accepted = handshake?.IsValidFor(expected) == true;
        await _writer.WriteLineAsync(accepted
            ? $"{{\"schemaVersion\":1,\"accepted\":true,\"state\":\"{expected.State.Code}\"}}"
            : "{\"schemaVersion\":1,\"accepted\":false}");
        if (!accepted)
        {
            return;
        }

        _connected.TrySetResult();
        while (!_lifetime.IsCancellationRequested &&
            await reader.ReadLineAsync(_lifetime.Token) is { } message)
        {
            using var document = JsonDocument.Parse(message);
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 3 &&
                root.TryGetProperty("schemaVersion", out var schema) && schema.ValueKind == JsonValueKind.Number &&
                schema.TryGetInt32(out var version) && version == 1 &&
                root.TryGetProperty("kind", out var kind) && kind.ValueKind == JsonValueKind.String &&
                kind.GetString() == "heartbeat" &&
                root.TryGetProperty("processId", out var process) && process.ValueKind == JsonValueKind.Number &&
                process.TryGetInt32(out var heartbeatPid) && heartbeatPid == expected.ProcessId)
            {
                _heartbeat.TrySetResult();
                continue;
            }

            throw new InvalidDataException("fake_host_protocol_invalid");
        }
    }

    private static UiTestHandshake? ParseHandshake(string line)
    {
        using var document = JsonDocument.Parse(line);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 4 ||
            !root.TryGetProperty("schemaVersion", out var schema) || schema.ValueKind != JsonValueKind.Number ||
            !schema.TryGetInt32(out var version) ||
            !root.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String ||
            !root.TryGetProperty("processId", out var process) || process.ValueKind != JsonValueKind.Number ||
            !process.TryGetInt32(out var processId) ||
            !root.TryGetProperty("nonce", out var nonce) || nonce.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return new UiTestHandshake(version, state.GetString()!, processId, nonce.GetString()!);
    }
}
