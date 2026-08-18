using System.Diagnostics;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class ProcessRunnerTests
{
    [Fact]
    public async Task Starts_without_a_shell_and_preserves_each_argument_as_one_entry()
    {
        var starter = new FakeProcessStarter(FakeProcessHandle.Exited());
        var runner = new ProcessRunner(starter);

        var result = await runner.RunAsync(
            "/controlled/tools/SimplySignDesktop.exe",
            ["/autologin", "123456", "value with spaces"],
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        var startInfo = Assert.IsType<ProcessStartInfo>(starter.StartInfo);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.CreateNoWindow);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.Equal(["/autologin", "123456", "value with spaces"], startInfo.ArgumentList);
        Assert.Empty(startInfo.Arguments);
        Assert.Equal("SimplySignDesktop.exe", result.ExecutableName);
        Assert.DoesNotContain("controlled", result.ExecutableName, StringComparison.Ordinal);
        Assert.Equal(ProcessTermination.Exited, result.Termination);
    }

    [Fact]
    public async Task Drains_both_outputs_concurrently_caps_them_and_redacts_only_totp_secrets()
    {
        const string fakeBase32Secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var pair = CoordinatedTextReader.CreatePair(
            new string('x', ProcessRunner.MaximumCapturedOutputBytes + 1_024) + " 123456",
            $"otpauth://totp/Certum:user?secret={fakeBase32Secret}&algorithm=SHA256&digits=6&period=30 "
            + $"123456 TOKEN-SERIAL-01 c0ffee01 EE527809 /controlled/SimplySignDesktop.exe raw={fakeBase32Secret}");
        var starter = new FakeProcessStarter(FakeProcessHandle.Exited(pair.First, pair.Second));
        var runner = new ProcessRunner(starter);

        var run = runner.RunAsync(
            "/controlled/SimplySignDesktop.exe",
            ["/autologin", "123456", fakeBase32Secret, "TOKEN-SERIAL-01", "c0ffee01"],
            TimeSpan.FromSeconds(1),
            CancellationToken.None);
        var result = await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.True(System.Text.Encoding.UTF8.GetByteCount(result.StandardOutput) <= ProcessRunner.MaximumCapturedOutputBytes);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(result.StandardError) <= ProcessRunner.MaximumCapturedOutputBytes);
        Assert.True(result.StandardOutputTruncated);
        Assert.False(result.StandardErrorTruncated);
        Assert.Contains($"secret=[REDACTED_TOTP_SECRET]&algorithm=SHA256", result.StandardError, StringComparison.Ordinal);
        Assert.DoesNotContain($"secret={fakeBase32Secret}", result.StandardError, StringComparison.Ordinal);
        Assert.Contains("otpauth://totp/Certum:user?secret=[REDACTED_TOTP_SECRET]&algorithm=SHA256&digits=6&period=30", result.StandardError, StringComparison.Ordinal);
        Assert.Contains("123456 TOKEN-SERIAL-01 c0ffee01 EE527809 /controlled/SimplySignDesktop.exe", result.StandardError, StringComparison.Ordinal);
        Assert.Contains(fakeBase32Secret, result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Timeout_kills_the_entire_process_tree_and_is_distinct_from_caller_cancellation()
    {
        var handle = FakeProcessHandle.Running();
        var runner = new ProcessRunner(new FakeProcessStarter(handle));

        var result = await runner.RunAsync(
            "/controlled/child.exe",
            ["safe"],
            TimeSpan.FromMilliseconds(20),
            CancellationToken.None);

        Assert.Equal(ProcessTermination.TimedOut, result.Termination);
        Assert.Equal("process_timeout", result.FailureCode);
        Assert.True(handle.KillEntireProcessTree);
    }

    [Fact]
    public async Task Caller_cancellation_kills_the_entire_process_tree_and_returns_its_own_state()
    {
        var handle = FakeProcessHandle.Running();
        var starter = new FakeProcessStarter(handle);
        var runner = new ProcessRunner(starter);
        using var cancellation = new CancellationTokenSource();

        var run = runner.RunAsync(
            "/controlled/child.exe",
            ["safe"],
            TimeSpan.FromSeconds(30),
            cancellation.Token);
        await starter.Started;
        cancellation.Cancel();
        var result = await run;

        Assert.Equal(ProcessTermination.Cancelled, result.Termination);
        Assert.Equal("process_cancelled", result.FailureCode);
        Assert.True(handle.KillEntireProcessTree);
    }

    [Theory]
    [InlineData(false, ProcessTermination.TimedOut, "process_timeout")]
    [InlineData(true, ProcessTermination.Cancelled, "process_cancelled")]
    public async Task Drain_fault_does_not_overwrite_timeout_or_caller_cancellation(
        bool cancelByCaller,
        ProcessTermination expectedTermination,
        string expectedCode)
    {
        var handle = FakeProcessHandle.Running(
            new ThrowingTextReader("sensitive-output"),
            new StringReader(string.Empty));
        var starter = new FakeProcessStarter(handle);
        var runner = new ProcessRunner(starter);
        using var cancellation = new CancellationTokenSource();

        var run = runner.RunAsync(
            "/controlled/child.exe",
            ["sensitive-output"],
            cancelByCaller ? TimeSpan.FromSeconds(30) : TimeSpan.FromMilliseconds(20),
            cancellation.Token);
        await starter.Started;
        if (cancelByCaller)
        {
            cancellation.Cancel();
        }

        var result = await run;

        Assert.Equal(expectedTermination, result.Termination);
        Assert.Equal(expectedCode, result.FailureCode);
        Assert.Equal(1, handle.CloseOutputCalls);
    }

    [Fact]
    public async Task Closes_output_then_reawaits_faulting_drains_without_hanging()
    {
        var output = new DisposeFaultTextReader();
        var handle = FakeProcessHandle.Exited(output, new StringReader(string.Empty));
        var runner = new ProcessRunner(
            new FakeProcessStarter(handle),
            TimeSpan.FromMilliseconds(20));

        var result = await runner.RunAsync(
            "/controlled/child.exe",
            ["safe"],
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(ProcessTermination.IoFailed, result.Termination);
        Assert.Equal("process_io_failed", result.FailureCode);
        Assert.Equal(1, handle.CloseOutputCalls);
        Assert.True(output.Disposed);
    }

    [Fact]
    public async Task Detached_start_releases_only_the_local_handle_without_waiting_or_killing_the_child()
    {
        var handle = FakeProcessHandle.Running();
        var starter = new FakeProcessStarter(handle);
        var runner = new ProcessRunner(starter);

        var result = await runner.StartDetachedAsync(
            "/controlled/SimplySignDesktop.exe",
            ["/autologin", "123456"],
            CancellationToken.None);

        Assert.True(result.Started);
        Assert.Equal("SimplySignDesktop.exe", result.ExecutableName);
        Assert.True(handle.Disposed);
        Assert.False(handle.KillEntireProcessTree);
        Assert.False(handle.HasExited);
        Assert.False(starter.StartInfo!.RedirectStandardOutput);
        Assert.False(starter.StartInfo.RedirectStandardError);
        Assert.Equal(["/autologin", "123456"], starter.StartInfo.ArgumentList);
    }

    [Fact]
    public async Task Launch_and_io_failures_return_only_stable_sanitized_codes()
    {
        const string sensitive = "123456 /very/secret/path";
        var launchRunner = new ProcessRunner(new ThrowingProcessStarter(sensitive));

        var launch = await launchRunner.RunAsync(
            "/very/secret/path/tool.exe",
            ["123456"],
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(ProcessTermination.LaunchFailed, launch.Termination);
        Assert.Equal("process_launch_failed", launch.FailureCode);
        Assert.Equal("tool.exe", launch.ExecutableName);
        Assert.DoesNotContain(sensitive, launch.StandardError, StringComparison.Ordinal);

        var ioRunner = new ProcessRunner(new FakeProcessStarter(
            FakeProcessHandle.Exited(new ThrowingTextReader(sensitive), new StringReader(string.Empty))));
        var io = await ioRunner.RunAsync(
            "/very/secret/path/tool.exe",
            ["123456"],
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(ProcessTermination.IoFailed, io.Termination);
        Assert.Equal("process_io_failed", io.FailureCode);
        Assert.NotNull(io.FailureException);
        Assert.DoesNotContain(sensitive, io.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Preserves_non_secret_arguments_and_diagnostic_output()
    {
        string[] secrets = ["SER-1", "ab", "abcd", "T1", "x", "E", "X", "e"];
        var echoed = string.Join('|', secrets) + "|aXb";
        var runner = new ProcessRunner(new FakeProcessStarter(
            FakeProcessHandle.Exited(new StringReader(echoed), new StringReader(echoed))));

        var result = await runner.RunAsync(
            "/controlled/child.exe",
            secrets,
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(echoed, result.StandardOutput);
        Assert.Equal(echoed, result.StandardError);
    }

    [Fact]
    public async Task Launch_failure_preserves_the_original_exception_for_diagnostics()
    {
        var expected = new System.ComponentModel.Win32Exception(5, "access path=C:\\controlled\\helper.exe");
        var runner = new ProcessRunner(new ThrowingProcessStarter(expected));

        var result = await runner.RunAsync(
            "/controlled/helper.exe",
            ["safe"],
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(ProcessTermination.LaunchFailed, result.Termination);
        Assert.Same(expected, result.FailureException);

        var detached = await runner.StartDetachedAsync(
            "/controlled/helper.exe",
            ["safe"],
            CancellationToken.None);
        Assert.False(detached.Started);
        Assert.Same(expected, detached.FailureException);
    }

    [Fact]
    public async Task Catalog_capture_truncates_at_its_byte_hard_limit_without_expanding_generic_stderr()
    {
        const string secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new string('x', SimplySignProbe.MaximumCatalogOutputBytes + 1);
        var error = $"otpauth://totp/test?secret={secret}&digits=6";
        var runner = new ProcessRunner(new FakeProcessStarter(
            FakeProcessHandle.Exited(new StringReader(output), new StringReader(error))));

        var result = await runner.RunAsync(
            "/controlled/catalog-helper.exe",
            [secret],
            TimeSpan.FromSeconds(1),
            SimplySignProbe.MaximumCatalogOutputBytes,
            ProcessRunner.MaximumCapturedOutputBytes,
            CancellationToken.None);

        Assert.Equal(SimplySignProbe.MaximumCatalogOutputBytes, System.Text.Encoding.UTF8.GetByteCount(result.StandardOutput));
        Assert.True(result.StandardOutputTruncated);
        Assert.False(result.StandardErrorTruncated);
        Assert.DoesNotContain(secret, result.StandardError, StringComparison.Ordinal);
        Assert.Contains("secret=[REDACTED_TOTP_SECRET]", result.StandardError, StringComparison.Ordinal);
    }

    private sealed class FakeProcessStarter(FakeProcessHandle handle) : IProcessStarter
    {
        private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ProcessStartInfo? StartInfo { get; private set; }

        public Task Started => _started.Task;

        public IProcessHandle Start(ProcessStartInfo startInfo)
        {
            StartInfo = startInfo;
            _started.TrySetResult();
            return handle;
        }
    }

    private sealed class ThrowingProcessStarter
        : IProcessStarter
    {
        private readonly Exception _error;

        public ThrowingProcessStarter(string message)
            : this(new InvalidOperationException(message))
        {
        }

        public ThrowingProcessStarter(Exception error) => _error = error;

        public IProcessHandle Start(ProcessStartInfo startInfo) => throw _error;
    }

    private sealed class FakeProcessHandle : IProcessHandle
    {
        private readonly TaskCompletionSource _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly int _exitCode;

        private FakeProcessHandle(TextReader standardOutput, TextReader standardError, bool exited, int exitCode)
        {
            StandardOutput = standardOutput;
            StandardError = standardError;
            _exitCode = exitCode;
            if (exited)
            {
                _exit.TrySetResult();
            }
        }

        public TextReader StandardOutput { get; }

        public TextReader StandardError { get; }

        public bool HasExited => _exit.Task.IsCompleted;

        public int ExitCode => _exitCode;

        public bool KillEntireProcessTree { get; private set; }

        public bool Disposed { get; private set; }

        public int CloseOutputCalls { get; private set; }

        public static FakeProcessHandle Exited(
            TextReader? standardOutput = null,
            TextReader? standardError = null,
            int exitCode = 0) =>
            new(standardOutput ?? new StringReader(string.Empty), standardError ?? new StringReader(string.Empty), true, exitCode);

        public static FakeProcessHandle Running(
            TextReader? standardOutput = null,
            TextReader? standardError = null) =>
            new(
                standardOutput ?? new StringReader(string.Empty),
                standardError ?? new StringReader(string.Empty),
                false,
                0);

        public Task WaitForExitAsync(CancellationToken cancellationToken) => _exit.Task.WaitAsync(cancellationToken);

        public void Kill(bool entireProcessTree)
        {
            KillEntireProcessTree = entireProcessTree;
            _exit.TrySetResult();
        }

        public void CloseOutput()
        {
            CloseOutputCalls++;
            StandardOutput.Dispose();
            StandardError.Dispose();
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingTextReader(string message) : TextReader
    {
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException(message));
    }

    private sealed class DisposeFaultTextReader : TextReader
    {
        private readonly TaskCompletionSource<int> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool Disposed { get; private set; }

        public override ValueTask<int> ReadAsync(
            Memory<char> buffer,
            CancellationToken cancellationToken = default) =>
            new(_completion.Task);

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            _completion.TrySetException(new ObjectDisposedException(nameof(DisposeFaultTextReader)));
            base.Dispose(disposing);
        }
    }

    private sealed class CoordinatedTextReader
    {
        public static (TextReader First, TextReader Second) CreatePair(string first, string second)
        {
            var barrier = new ReadBarrier();
            return (new BarrierReader(first, barrier), new BarrierReader(second, barrier));
        }

        private sealed class ReadBarrier
        {
            private readonly TaskCompletionSource _bothStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
            private int _started;

            public Task Arrive()
            {
                if (Interlocked.Increment(ref _started) == 2)
                {
                    _bothStarted.TrySetResult();
                }

                return _bothStarted.Task;
            }
        }

        private sealed class BarrierReader(string text, ReadBarrier barrier) : TextReader
        {
            private int _position;
            private bool _arrived;

            public override async ValueTask<int> ReadAsync(
                Memory<char> buffer,
                CancellationToken cancellationToken = default)
            {
                if (!_arrived)
                {
                    _arrived = true;
                    await barrier.Arrive().WaitAsync(cancellationToken);
                }

                if (_position >= text.Length)
                {
                    return 0;
                }

                var length = Math.Min(buffer.Length, text.Length - _position);
                text.AsMemory(_position, length).CopyTo(buffer);
                _position += length;
                return length;
            }
        }
    }
}
