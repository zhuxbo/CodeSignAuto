namespace SimplySignAuto.UI.Tests.Desktop;

internal sealed class ProductionAcceptanceFactAttribute : FactAttribute
{
    public ProductionAcceptanceFactAttribute()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable("SIMPLYSIGN_RUN_PRODUCTION_UI_ACCEPTANCE"),
                "1",
                StringComparison.Ordinal))
        {
            Skip = "Requires the explicit production UI acceptance gate.";
            return;
        }

        if (!OperatingSystem.IsWindows() ||
            !WindowsInteractiveSessionPolicy.TryGetCurrent(out var sessionId, out var state) ||
            sessionId <= 0 ||
            !WindowsInteractiveSessionPolicy.IsEligible(sessionId, state))
        {
            Skip = "Requires a WTS Active non-zero Windows session.";
        }
    }
}
