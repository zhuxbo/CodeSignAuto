using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SimplySignAuto.Core.Security;

namespace SimplySignAuto.App.UI;

public sealed record ActivationNames(string PipeName, string AgentMutexName)
{
    public static ActivationNames ForSigningUser(string signingUserSid)
    {
        if (!CanonicalWindowsSid.IsValid(signingUserSid))
        {
            throw new ActivationException("activation_identity_invalid");
        }

        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signingUserSid)))
            .ToLowerInvariant();
        return new ActivationNames(
            $"SimplySignAuto.Activation.v1.{digest}",
            $"Local\\SimplySignAuto.Agent.{signingUserSid}");
    }
}

public sealed class ActivationException : Exception
{
    public ActivationException(string code)
        : base(code) => Code = code;

    public string Code { get; }
}

public sealed record ActivationServerIdentityEvidence(
    bool InspectionSucceeded,
    string? UserSid,
    uint SessionId,
    string? ExecutablePath)
{
    public static ActivationServerIdentityEvidence Unavailable { get; } =
        new(false, null, 0, null);
}

public interface IActivationServerIdentityVerifier
{
    bool IsTrusted(
        ActivationServerIdentityEvidence evidence,
        string signingUserSid,
        uint currentSessionId,
        string currentExecutablePath);
}

public sealed class ActivationServerIdentityVerifier : IActivationServerIdentityVerifier
{
    public bool IsTrusted(
        ActivationServerIdentityEvidence evidence,
        string signingUserSid,
        uint currentSessionId,
        string currentExecutablePath)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return evidence.InspectionSucceeded &&
            CanonicalWindowsSid.IsValid(signingUserSid) &&
            string.Equals(evidence.UserSid, signingUserSid, StringComparison.Ordinal) &&
            currentSessionId != 0 &&
            evidence.SessionId == currentSessionId &&
            !string.IsNullOrWhiteSpace(currentExecutablePath) &&
            string.Equals(
                evidence.ExecutablePath,
                currentExecutablePath,
                StringComparison.OrdinalIgnoreCase);
    }
}

public interface IActivationServer : IAsyncDisposable
{
    Task RunAsync(ActivationCommandHandler handler, CancellationToken cancellationToken);
}

public interface IActivationTransport
{
    Task<bool> TrySendShowAsync(
        ActivationNames names,
        string signingUserSid,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    bool AgentInstanceExists(ActivationNames names);

    ValueTask<IActivationServer?> TryCreateServerAsync(
        ActivationNames names,
        string signingUserSid,
        CancellationToken cancellationToken);
}

public interface IActivationRetryDelay
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public interface ISingleInstanceActivator
{
    Task<int> RunSingleAsync(
        string signingUserSid,
        Func<IActivationServer, CancellationToken, Task<int>> startOwnedInstance,
        CancellationToken cancellationToken);
}

public interface IUiDispatcher
{
    Task InvokeAsync(Action action, CancellationToken cancellationToken);
}

internal sealed class InlineAppUiDispatcher : IUiDispatcher
{
    public static InlineAppUiDispatcher Instance { get; } = new();

    public Task InvokeAsync(Action action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();
        action();
        return Task.CompletedTask;
    }
}

public sealed class SystemActivationRetryDelay : IActivationRetryDelay
{
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

public sealed class ActivationCommandHandler
{
    private static readonly byte[] ShowCommand = "show"u8.ToArray();
    private readonly IUiDispatcher _dispatcher;
    private readonly IWindowController _window;

    public ActivationCommandHandler(IUiDispatcher dispatcher, IWindowController window)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _window = window ?? throw new ArgumentNullException(nameof(window));
    }

    public async Task<bool> HandleAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        if (!message.Span.SequenceEqual(ShowCommand))
        {
            return false;
        }

        await _dispatcher.InvokeAsync(_window.ShowRestoreActivate, cancellationToken).ConfigureAwait(false);
        return true;
    }
}

public static class ActivationWireProtocol
{
    private static readonly byte[] Show = "show"u8.ToArray();
    private static readonly byte[] Acknowledgement = "shown"u8.ToArray();
    private static readonly byte[] FramedShow = [4, (byte)'s', (byte)'h', (byte)'o', (byte)'w'];
    private static readonly byte[] FramedAcknowledgement =
        [5, (byte)'s', (byte)'h', (byte)'o', (byte)'w', (byte)'n'];

    public static Task<bool> TrySendShowAndAwaitAcknowledgementAsync(
        Stream stream,
        ActivationServerIdentityEvidence evidence,
        IActivationServerIdentityVerifier verifier,
        string signingUserSid,
        uint currentSessionId,
        string currentExecutablePath,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        return verifier.IsTrusted(
            evidence,
            signingUserSid,
            currentSessionId,
            currentExecutablePath)
            ? TrySendShowAndAwaitAcknowledgementAsync(stream, cancellationToken)
            : Task.FromResult(false);
    }

    public static Task<bool> TrySendShowAndAwaitAcknowledgementAsync(
        Stream stream,
        CancellationToken cancellationToken)
        => TrySendShowAndAwaitAcknowledgementAsync(
            stream,
            new EndOfStreamActivationMessageReader(),
            cancellationToken);

    internal static async Task<bool> TrySendShowAndAwaitAcknowledgementAsync(
        Stream stream,
        IActivationMessageReader messageReader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(messageReader);
        await WriteFrameAsync(stream, Show, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        var response = await messageReader.ReadMessageAsync(
            stream,
            FramedAcknowledgement.Length,
            cancellationToken).ConfigureAwait(false);
        return response is not null && response.AsSpan().SequenceEqual(FramedAcknowledgement);
    }

    public static async Task<bool> TryHandleShowMessageAsync(
        ReadOnlyMemory<byte> message,
        ActivationCommandHandler handler,
        Stream response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(response);
        if (!message.Span.SequenceEqual(FramedShow) ||
            !await handler.HandleAsync(Show, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        await WriteFrameAsync(response, Acknowledgement, cancellationToken).ConfigureAwait(false);
        await response.FlushAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    public static Task<byte[]?> ReadShowAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return ReadFrameAsync(stream, Show.Length, cancellationToken);
    }

    public static async Task WriteAcknowledgementAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        await WriteFrameAsync(stream, Acknowledgement, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadFrameAsync(
        Stream stream,
        int maximumPayloadBytes,
        CancellationToken cancellationToken)
    {
        var lengthBuffer = new byte[1];
        if (!await ReadExactlyOrEndAsync(stream, lengthBuffer, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var length = lengthBuffer[0];
        if (length == 0 || length > maximumPayloadBytes)
        {
            return null;
        }

        var payload = new byte[length];
        return await ReadExactlyOrEndAsync(stream, payload, cancellationToken).ConfigureAwait(false)
            ? payload
            : null;
    }

    private static async Task<bool> ReadExactlyOrEndAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    private static async Task WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (payload.Length is <= 0 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(payload));
        }

        var frame = new byte[payload.Length + 1];
        frame[0] = (byte)payload.Length;
        payload.CopyTo(frame.AsMemory(1));
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
    }
}

internal interface IActivationMessageReader
{
    Task<byte[]?> ReadMessageAsync(
        Stream stream,
        int maximumMessageBytes,
        CancellationToken cancellationToken);
}

internal sealed class EndOfStreamActivationMessageReader : IActivationMessageReader
{
    public async Task<byte[]?> ReadMessageAsync(
        Stream stream,
        int maximumMessageBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumMessageBytes);
        var buffer = new byte[maximumMessageBytes + 1];
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return offset <= maximumMessageBytes ? buffer[..offset] : null;
            }

            offset += read;
        }

        return null;
    }
}

internal sealed class NamedPipeActivationMessageReader : IActivationMessageReader
{
    [SupportedOSPlatform("windows")]
    public async Task<byte[]?> ReadMessageAsync(
        Stream stream,
        int maximumMessageBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumMessageBytes);
        if (stream is not PipeStream pipe)
        {
            throw new ArgumentException("activation_message_pipe_required", nameof(stream));
        }

        var buffer = new byte[maximumMessageBytes + 1];
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await pipe.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            offset += read;
            if (pipe.IsMessageComplete)
            {
                return offset <= maximumMessageBytes ? buffer[..offset] : null;
            }
        }

        return null;
    }
}

public sealed class SingleInstanceActivator : ISingleInstanceActivator
{
    public const int MaximumActivationRetries = 4;
    public static readonly TimeSpan ConnectionTimeout = TimeSpan.FromMilliseconds(750);
    public static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(125);

    private readonly IActivationTransport _transport;
    private readonly IActivationRetryDelay _delay;

    public SingleInstanceActivator()
        : this(new WindowsActivationTransport(), new SystemActivationRetryDelay())
    {
    }

    public SingleInstanceActivator(IActivationTransport transport, IActivationRetryDelay delay)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _delay = delay ?? throw new ArgumentNullException(nameof(delay));
    }

    public async Task<int> RunSingleAsync(
        string signingUserSid,
        Func<IActivationServer, CancellationToken, Task<int>> startOwnedInstance,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(startOwnedInstance);
        var names = ActivationNames.ForSigningUser(signingUserSid);
        if (await _transport.TrySendShowAsync(
                names,
                signingUserSid,
                ConnectionTimeout,
                cancellationToken).ConfigureAwait(false))
        {
            return 0;
        }

        if (_transport.AgentInstanceExists(names))
        {
            await ActivateAfterRaceAsync(names, signingUserSid, cancellationToken).ConfigureAwait(false);
            return 0;
        }

        var server = await _transport.TryCreateServerAsync(names, signingUserSid, cancellationToken)
            .ConfigureAwait(false);
        if (server is null)
        {
            await ActivateAfterRaceAsync(names, signingUserSid, cancellationToken).ConfigureAwait(false);
            return 0;
        }

        await using (server.ConfigureAwait(false))
        {
            return await startOwnedInstance(server, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ActivateAfterRaceAsync(
        ActivationNames names,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaximumActivationRetries; attempt++)
        {
            await _delay.DelayAsync(RetryDelay, cancellationToken).ConfigureAwait(false);
            if (await _transport.TrySendShowAsync(
                    names,
                    signingUserSid,
                    ConnectionTimeout,
                    cancellationToken).ConfigureAwait(false))
            {
                return;
            }
        }

        throw new ActivationException("activation_unavailable");
    }
}

public sealed class WindowsActivationTransport : IActivationTransport
{
    private readonly IActivationServerIdentityReader _identityReader;
    private readonly IActivationServerIdentityVerifier _identityVerifier;

    public WindowsActivationTransport()
        : this(
            new WindowsActivationServerIdentityReader(),
            new ActivationServerIdentityVerifier())
    {
    }

    internal WindowsActivationTransport(
        IActivationServerIdentityReader identityReader,
        IActivationServerIdentityVerifier identityVerifier)
    {
        _identityReader = identityReader ?? throw new ArgumentNullException(nameof(identityReader));
        _identityVerifier = identityVerifier ?? throw new ArgumentNullException(nameof(identityVerifier));
    }

    public async Task<bool> TrySendShowAsync(
        ActivationNames names,
        string signingUserSid,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(names);
        if (!CanonicalWindowsSid.IsValid(signingUserSid))
        {
            throw new ActivationException("activation_identity_invalid");
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new ActivationException("activation_windows_required");
        }

        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCancellation.CancelAfter(timeout);
        try
        {
            await using var client = new NamedPipeClientStream(
                ".",
                names.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification);
            await client.ConnectAsync(timeoutCancellation.Token).ConfigureAwait(false);
            client.ReadMode = PipeTransmissionMode.Message;
            var serverIdentity = _identityReader.ReadServer(client.SafePipeHandle);
            var currentIdentity = _identityReader.ReadCurrent();
            if (!_identityVerifier.IsTrusted(
                    serverIdentity,
                    signingUserSid,
                    currentIdentity.SessionId,
                    currentIdentity.ExecutablePath ?? string.Empty))
            {
                return false;
            }

            return await ActivationWireProtocol.TrySendShowAndAwaitAcknowledgementAsync(
                client,
                new NamedPipeActivationMessageReader(),
                timeoutCancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            !cancellationToken.IsCancellationRequested && timeoutCancellation.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public bool AgentInstanceExists(ActivationNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        if (!OperatingSystem.IsWindows())
        {
            throw new ActivationException("activation_windows_required");
        }

        try
        {
            if (!Mutex.TryOpenExisting(names.AgentMutexName, out var mutex))
            {
                return false;
            }

            mutex.Dispose();
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }

    public ValueTask<IActivationServer?> TryCreateServerAsync(
        ActivationNames names,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(names);
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            throw new ActivationException("activation_windows_required");
        }

        try
        {
            return ValueTask.FromResult<IActivationServer?>(CreateWindowsServer(names, signingUserSid));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return ValueTask.FromResult<IActivationServer?>(null);
        }
    }

    [SupportedOSPlatform("windows")]
    private static IActivationServer CreateWindowsServer(ActivationNames names, string signingUserSid)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddRule(security, new SecurityIdentifier(signingUserSid));
        AddRule(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        var pipe = NamedPipeServerStreamAcl.Create(
            names.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Message,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
            inBufferSize: NamedPipeActivationServer.MaximumMessageBytes + 1,
            outBufferSize: NamedPipeActivationServer.MaximumAcknowledgementBytes + 1,
            security,
            HandleInheritability.None);
        return new NamedPipeActivationServer(pipe);
    }

    [SupportedOSPlatform("windows")]
    private static void AddRule(PipeSecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new PipeAccessRule(
            identity,
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
}

internal interface IActivationServerIdentityReader
{
    ActivationServerIdentityEvidence ReadServer(SafePipeHandle pipeHandle);

    ActivationServerIdentityEvidence ReadCurrent();
}

internal sealed class WindowsActivationServerIdentityReader : IActivationServerIdentityReader
{
    public ActivationServerIdentityEvidence ReadServer(SafePipeHandle pipeHandle)
    {
        ArgumentNullException.ThrowIfNull(pipeHandle);
        if (!OperatingSystem.IsWindows())
        {
            return ActivationServerIdentityEvidence.Unavailable;
        }

        return ReadServerOnWindows(pipeHandle);
    }

    public ActivationServerIdentityEvidence ReadCurrent()
    {
        if (!OperatingSystem.IsWindows())
        {
            return ActivationServerIdentityEvidence.Unavailable;
        }

        return ReadProcessOnWindows((uint)Environment.ProcessId);
    }

    [SupportedOSPlatform("windows")]
    private static ActivationServerIdentityEvidence ReadServerOnWindows(SafePipeHandle pipeHandle)
    {
        try
        {
            return GetNamedPipeServerProcessId(pipeHandle, out var processId) && processId != 0
                ? ReadProcessOnWindows(processId)
                : ActivationServerIdentityEvidence.Unavailable;
        }
        catch (Exception error) when (
            error is UnauthorizedAccessException
                or IOException
                or InvalidOperationException
                or System.Security.SecurityException)
        {
            return ActivationServerIdentityEvidence.Unavailable;
        }
    }

    [SupportedOSPlatform("windows")]
    private static ActivationServerIdentityEvidence ReadProcessOnWindows(uint processId)
    {
        try
        {
            if (!ProcessIdToSessionId(processId, out var sessionId))
            {
                return ActivationServerIdentityEvidence.Unavailable;
            }

            using var process = OpenProcess(ProcessQueryLimitedInformation, inheritHandle: false, processId);
            if (process.IsInvalid)
            {
                return ActivationServerIdentityEvidence.Unavailable;
            }

            var executablePath = ReadExecutablePath(process);
            var userSid = ReadUserSid(process);
            return string.IsNullOrWhiteSpace(executablePath) || !CanonicalWindowsSid.IsValid(userSid)
                ? ActivationServerIdentityEvidence.Unavailable
                : new ActivationServerIdentityEvidence(true, userSid, sessionId, executablePath);
        }
        catch (Exception error) when (
            error is UnauthorizedAccessException
                or IOException
                or InvalidOperationException
                or ArgumentException
                or System.Security.SecurityException)
        {
            return ActivationServerIdentityEvidence.Unavailable;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadExecutablePath(SafeProcessHandle process)
    {
        var capacity = 32768u;
        var buffer = new StringBuilder((int)capacity);
        return QueryFullProcessImageName(process, flags: 0, buffer, ref capacity) && capacity > 0
            ? buffer.ToString(0, checked((int)capacity))
            : null;
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadUserSid(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process, TokenQuery, out var token) || token.IsInvalid)
        {
            token?.Dispose();
            return null;
        }

        using (token)
        {
            _ = GetTokenInformation(token, TokenInformationClass.TokenUser, IntPtr.Zero, 0, out var length);
            if (length == 0 || length > int.MaxValue)
            {
                return null;
            }

            var buffer = Marshal.AllocHGlobal(checked((int)length));
            try
            {
                if (!GetTokenInformation(
                        token,
                        TokenInformationClass.TokenUser,
                        buffer,
                        length,
                        out _))
                {
                    return null;
                }

                var tokenUser = Marshal.PtrToStructure<TokenUser>(buffer);
                return tokenUser.User.Sid == IntPtr.Zero
                    ? null
                    : new SecurityIdentifier(tokenUser.User.Sid).Value;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct SidAndAttributes
    {
        public readonly IntPtr Sid;
        public readonly uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct TokenUser
    {
        public readonly SidAndAttributes User;
    }

    private enum TokenInformationClass
    {
        TokenUser = 1,
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe,
        out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        StringBuilder executablePath,
        ref uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle process,
        uint desiredAccess,
        out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle token,
        TokenInformationClass informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnLength);
}

public sealed class NamedPipeActivationServer : IActivationServer
{
    public const int MaximumMessageBytes = 4;
    public const int MaximumAcknowledgementBytes = 5;
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(2);
    private readonly CancellationTokenSource _disposeCancellation = new();
    private readonly IActivationMessageReader _messageReader;
    private NamedPipeServerStream? _pipe;

    public NamedPipeActivationServer(NamedPipeServerStream pipe)
        : this(pipe, new NamedPipeActivationMessageReader())
    {
    }

    internal NamedPipeActivationServer(
        NamedPipeServerStream pipe,
        IActivationMessageReader messageReader)
    {
        _pipe = pipe ?? throw new ArgumentNullException(nameof(pipe));
        _messageReader = messageReader ?? throw new ArgumentNullException(nameof(messageReader));
    }

    public async Task RunAsync(
        ActivationCommandHandler handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _disposeCancellation.Token);
        while (!lifetime.IsCancellationRequested)
        {
            var pipe = _pipe ?? throw new ObjectDisposedException(nameof(NamedPipeActivationServer));
            try
            {
                await pipe.WaitForConnectionAsync(lifetime.Token).ConfigureAwait(false);
                using var readCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                readCancellation.CancelAfter(ReadTimeout);
                var message = await _messageReader.ReadMessageAsync(
                    pipe,
                    MaximumMessageBytes + 1,
                    readCancellation.Token).ConfigureAwait(false);
                if (message is not null)
                {
                    await ActivationWireProtocol.TryHandleShowMessageAsync(
                        message,
                        handler,
                        pipe,
                        lifetime.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error) when (error is IOException or OperationCanceledException)
            {
            }
            finally
            {
                if (pipe.IsConnected)
                {
                    pipe.Disconnect();
                }
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _disposeCancellation.Cancel();
        Interlocked.Exchange(ref _pipe, null)?.Dispose();
        _disposeCancellation.Dispose();
        return ValueTask.CompletedTask;
    }

}
