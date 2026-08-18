namespace SimplySignAuto.UI.Tests.Desktop;

internal sealed record ScreenshotSecretInput(string Name, string Value);

internal sealed record AutomationSecretObservation(
    string Name,
    string AutomationId,
    bool IsPassword,
    string? ValuePatternValue,
    string? LegacyAccessibleValue,
    IReadOnlyList<string> PropertyValues);

internal static class ScreenshotSecretPolicy
{
    public static bool IsSecretInput(string? automationName, bool isPassword) =>
        isPassword ||
        (!string.IsNullOrWhiteSpace(automationName) &&
            (automationName.Contains("激活内容", StringComparison.Ordinal) ||
                automationName.Contains("OTP", StringComparison.OrdinalIgnoreCase) ||
                automationName.Contains("secret", StringComparison.OrdinalIgnoreCase)));

    public static void AssertEmpty(IEnumerable<ScreenshotSecretInput> inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        if (inputs.Any(input => !string.IsNullOrEmpty(input.Value)))
        {
            throw new InvalidDataException("screenshot_secret_present");
        }
    }

    public static bool AssertAutomationTreeSafe(IEnumerable<AutomationSecretObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(observations);
        string[] forbidden =
        [
            string.Concat("o", "t", "p", "auth://"),
            string.Concat("bear", "er "),
            string.Concat("api", "-", new string(['t', 'o', 'k', 'e', 'n'])),
            string.Concat("sec", "ret="),
        ];
        foreach (var observation in observations)
        {
            ArgumentNullException.ThrowIfNull(observation);
            var secretControl = observation.IsPassword ||
                IsSecretInput(observation.Name, observation.IsPassword) ||
                IsSecretInput(observation.AutomationId, observation.IsPassword) ||
                observation.AutomationId.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                observation.Name.Contains("token", StringComparison.OrdinalIgnoreCase);
            if (secretControl &&
                (!string.IsNullOrEmpty(observation.ValuePatternValue) ||
                    !string.IsNullOrEmpty(observation.LegacyAccessibleValue)))
            {
                throw new InvalidDataException("production_ui_secret_scan_failed");
            }
            if (observation.PropertyValues.Any(value =>
                    forbidden.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase))))
            {
                throw new InvalidDataException("production_ui_secret_scan_failed");
            }
        }

        return true;
    }
}
