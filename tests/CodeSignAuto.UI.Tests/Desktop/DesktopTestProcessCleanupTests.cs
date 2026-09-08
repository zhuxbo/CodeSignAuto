using System.Diagnostics;
using CodeSignAuto.App.UI.Testing;

namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class DesktopTestProcessCleanupTests
{
    [Fact]
    public async Task Output_validation_failure_is_rethrown_only_after_process_and_host_cleanup()
    {
        using var process = StartLongRunningProcess();
        var processId = process.Id;
        var host = CreateHost();

        var error = await Assert.ThrowsAsync<InvalidDataException>(() =>
            DesktopTestProcessCleanup.ExecuteAsync(
                process,
                host,
                requestExit: null,
                Task.FromResult(new[] { "unsafe" }),
                Task.FromResult(Array.Empty<string>()),
                _ => throw new InvalidDataException("unsafe_output")));

        Assert.Equal("unsafe_output", error.Message);
        Assert.True(host.IsDisposed);
        Assert.Throws<ArgumentException>(() => Process.GetProcessById(processId));
        Assert.Throws<InvalidOperationException>(() => _ = process.HasExited);
    }

    [Fact]
    public async Task Faulted_output_drain_still_kills_and_joins_before_disposal()
    {
        using var process = StartLongRunningProcess();
        var processId = process.Id;
        var host = CreateHost();

        var error = await Assert.ThrowsAsync<IOException>(() =>
            DesktopTestProcessCleanup.ExecuteAsync(
                process,
                host,
                requestExit: null,
                Task.FromException<string[]>(new IOException("drain_failed")),
                Task.FromResult(Array.Empty<string>()),
                _ => { }));

        Assert.Equal("drain_failed", error.Message);
        Assert.True(host.IsDisposed);
        Assert.Throws<ArgumentException>(() => Process.GetProcessById(processId));
        Assert.Throws<InvalidOperationException>(() => _ = process.HasExited);
    }

    private static FakeManagementHost CreateHost()
    {
        Assert.True(UiTestState.TryParse("ready", out var state));
        return new FakeManagementHost(new UiTestLaunchOptions(
            state!,
            $"SSA.UI.{Guid.NewGuid():N}",
            new string('A', 64),
            Environment.ProcessId));
    }

    private static Process StartLongRunningProcess()
    {
        var start = OperatingSystem.IsWindows()
            ? new ProcessStartInfo("cmd.exe", "/d /c ping -n 30 127.0.0.1 >nul")
            : new ProcessStartInfo("/bin/sleep", "30");
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        return Process.Start(start) ?? throw new InvalidOperationException("cleanup_test_process_start_failed");
    }
}
