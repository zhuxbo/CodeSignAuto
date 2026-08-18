namespace SimplySignAuto.UI.Tests.Desktop;

internal sealed class WindowsDesktopFactAttribute : FactAttribute
{
    public WindowsDesktopFactAttribute()
    {
        if (string.Equals(
                Environment.GetEnvironmentVariable("GITHUB_ACTIONS"),
                "true",
                StringComparison.OrdinalIgnoreCase))
        {
            Skip = "Requires an interactive desktop; GitHub-hosted runners do not provide a supported UI Automation session.";
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows, SessionId > 0, and a WTS Active interactive desktop.";
            return;
        }

        if (!WindowsInteractiveSessionPolicy.TryGetCurrent(out int sessionId, out WtsConnectState state))
        {
            Skip = "Requires a queryable WTS session state; UI Automation cannot verify this desktop.";
            return;
        }

        if (sessionId <= 0)
        {
            Skip = "Requires SessionId > 0; Session 0 cannot run desktop UI Automation.";
            return;
        }

        if (!WindowsInteractiveSessionPolicy.IsEligible(sessionId, state))
        {
            Skip = $"Requires WTS Active session; session {sessionId} is {state}. Disconnected sessions are not accepted.";
        }
    }
}
