using CodeSignAuto.App.UI.Testing;

namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class FakeManagementHostTests
{
    [Fact]
    public async Task Private_host_requires_nonce_state_and_pid_then_tracks_heartbeat_and_exit()
    {
        var options = CreateOptions(Environment.ProcessId);
        await using var host = new FakeManagementHost(options);
        await using var connection = await UiTestHostConnection.ConnectAsync(options, CancellationToken.None);

        await host.Connected.WaitAsync(TimeSpan.FromSeconds(5));
        await host.HeartbeatReceived.WaitAsync(TimeSpan.FromSeconds(5));
        var exitRequest = connection.WaitForExitRequestAsync(CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));
        await host.RequestExitAsync();

        Assert.True(await exitRequest);
    }

    [Fact]
    public async Task Wrong_child_pid_is_rejected_without_exposing_binding_material()
    {
        var expected = CreateOptions(Environment.ProcessId + 1);
        var actual = expected with { ProcessId = Environment.ProcessId };
        await using var host = new FakeManagementHost(expected);

        var failure = await Assert.ThrowsAsync<UiTestHostException>(
            () => UiTestHostConnection.ConnectAsync(actual, CancellationToken.None));

        Assert.Equal("ui_test_handshake_rejected", failure.Code);
        Assert.DoesNotContain(expected.Nonce, failure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(expected.PipeName, failure.ToString(), StringComparison.Ordinal);
    }

    private static UiTestLaunchOptions CreateOptions(int processId) => new(
        UiTestState.TryParse("ready", out var state) ? state! : throw new InvalidOperationException(),
        $"SSA.UI.{Guid.NewGuid():N}",
        Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
        processId);
}
