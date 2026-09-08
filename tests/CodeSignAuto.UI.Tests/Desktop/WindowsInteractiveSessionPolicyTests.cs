namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class WindowsInteractiveSessionPolicyTests
{
    [Theory]
    [InlineData(0, (int)WtsConnectState.Active, false)]
    [InlineData(1, (int)WtsConnectState.Disconnected, false)]
    [InlineData(1, (int)WtsConnectState.Connected, false)]
    [InlineData(1, (int)WtsConnectState.Active, true)]
    public void Only_nonzero_WTS_active_session_is_desktop_eligible(
        int sessionId,
        int rawState,
        bool expected)
    {
        Assert.Equal(expected, WindowsInteractiveSessionPolicy.IsEligible(sessionId, (WtsConnectState)rawState));
    }
}
