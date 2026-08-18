using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace SimplySignAuto.App.UI.Testing;

public sealed class UiTestHostException : Exception
{
    public UiTestHostException(string code)
        : base(code) => Code = code;

    public string Code { get; }
}

public interface IUiTestHostConnection : IAsyncDisposable
{
    Task<bool> WaitForExitRequestAsync(CancellationToken cancellationToken);
}

public interface IUiTestHostConnectionFactory
{
    Task<IUiTestHostConnection> ConnectAsync(
        UiTestLaunchOptions options,
        CancellationToken cancellationToken);
}

public sealed class UiTestHostConnectionFactory : IUiTestHostConnectionFactory
{
    public async Task<IUiTestHostConnection> ConnectAsync(
        UiTestLaunchOptions options,
        CancellationToken cancellationToken) =>
        await UiTestHostConnection.ConnectAsync(options, cancellationToken).ConfigureAwait(false);
}

public sealed class UiTestHostConnection : IUiTestHostConnection
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly NamedPipeClientStream _pipe;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly UiTestLaunchOptions _options;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _heartbeat;
    private int _readStarted;
    private int _disposed;

    private UiTestHostConnection(
        NamedPipeClientStream pipe,
        StreamReader reader,
        StreamWriter writer,
        UiTestLaunchOptions options)
    {
        _pipe = pipe;
        _reader = reader;
        _writer = writer;
        _options = options;
        _heartbeat = RunHeartbeatAsync();
    }

    public static async Task<UiTestHostConnection> ConnectAsync(
        UiTestLaunchOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var pipe = new NamedPipeClientStream(
            ".",
            options.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            var reader = new StreamReader(
                pipe,
                new UTF8Encoding(false, true),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 1024,
                leaveOpen: true);
            var writer = new StreamWriter(
                pipe,
                new UTF8Encoding(false, true),
                bufferSize: 1024,
                leaveOpen: true)
            {
                AutoFlush = true,
                NewLine = "\n",
            };
            await writer.WriteLineAsync(JsonSerializer.Serialize(UiTestHandshake.Create(options), Json))
                .WaitAsync(timeout.Token).ConfigureAwait(false);
            var response = await ReadBoundedLineAsync(reader, timeout.Token).ConfigureAwait(false);
            if (!IsAcceptedResponse(response, options.State.Code))
            {
                reader.Dispose();
                writer.Dispose();
                pipe.Dispose();
                throw new UiTestHostException("ui_test_handshake_rejected");
            }

            return new UiTestHostConnection(pipe, reader, writer, options);
        }
        catch (UiTestHostException)
        {
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            pipe.Dispose();
            throw new UiTestHostException("ui_test_host_timeout");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            pipe.Dispose();
            throw new UiTestHostException("ui_test_host_unavailable");
        }
    }

    public async Task<bool> WaitForExitRequestAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (Interlocked.Exchange(ref _readStarted, 1) != 0)
        {
            throw new InvalidOperationException("ui_test_host_reader_already_started");
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        try
        {
            while (await ReadBoundedLineAsync(_reader, linked.Token).ConfigureAwait(false) is { } line)
            {
                if (IsExitRequest(line))
                {
                    return true;
                }

                throw new UiTestHostException("ui_test_host_protocol_invalid");
            }

            return false;
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            return false;
        }
        catch (JsonException)
        {
            throw new UiTestHostException("ui_test_host_protocol_invalid");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetime.Cancel();
        try
        {
            await _heartbeat.ConfigureAwait(false);
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or ObjectDisposedException)
        {
        }

        _reader.Dispose();
        _writer.Dispose();
        _pipe.Dispose();
        _lifetime.Dispose();
    }

    private async Task RunHeartbeatAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        do
        {
            var line = $"{{\"schemaVersion\":1,\"kind\":\"heartbeat\",\"processId\":{_options.ProcessId}}}";
            await _writer.WriteLineAsync(line).WaitAsync(_lifetime.Token).ConfigureAwait(false);
        }
        while (await timer.WaitForNextTickAsync(_lifetime.Token).ConfigureAwait(false));
    }

    private static async Task<string?> ReadBoundedLineAsync(
        StreamReader reader,
        CancellationToken cancellationToken)
    {
        var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (line is { Length: > 1024 })
        {
            throw new UiTestHostException("ui_test_host_protocol_invalid");
        }

        return line;
    }

    private static bool IsAcceptedResponse(string? line, string expectedState)
    {
        if (line is null)
        {
            return false;
        }

        using var document = JsonDocument.Parse(line);
        var root = document.RootElement;
        return root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 3 &&
            root.TryGetProperty("schemaVersion", out var schema) && schema.ValueKind == JsonValueKind.Number &&
            schema.TryGetInt32(out var version) && version == 1 &&
            root.TryGetProperty("accepted", out var accepted) && accepted.ValueKind == JsonValueKind.True &&
            root.TryGetProperty("state", out var state) && state.ValueKind == JsonValueKind.String &&
            string.Equals(state.GetString(), expectedState, StringComparison.Ordinal);
    }

    private static bool IsExitRequest(string line)
    {
        using var document = JsonDocument.Parse(line);
        var root = document.RootElement;
        return root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 2 &&
            root.TryGetProperty("schemaVersion", out var schema) && schema.ValueKind == JsonValueKind.Number &&
            schema.TryGetInt32(out var version) && version == 1 &&
            root.TryGetProperty("kind", out var kind) && kind.ValueKind == JsonValueKind.String &&
            kind.GetString() == "exit";
    }
}
