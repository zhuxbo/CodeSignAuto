namespace SimplySignAuto.UI.Tests.Desktop;

internal sealed record ExpectedScreenshotArtifact(
    string PngFileName,
    string TestName,
    string CurrentPageAnchor);

internal static class ScreenshotArtifactContract
{
    internal static IReadOnlyList<ExpectedScreenshotArtifact> All { get; } =
    [
        new(
            "activation-saved.png",
            "Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret",
            "current_page_title:激活凭证"),
        new(
            "jobs-loaded.png",
            "Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy",
            "current_page_title:签名任务"),
        new(
            "overview-busy.png",
            "Overview_exposes_busy_state_and_opens_the_real_jobs_page",
            "current_page_title:概览"),
        new(
            "quick-finalizing.png",
            "Quick_sign_exposes_finalizing_before_opening_jobs",
            "current_page_title:快速签名"),
        new(
            "window-geometry.png",
            "Real_process_window_is_1024_by_768_landscape_four_by_three",
            "current_page_title:概览"),
    ];

    private static readonly IReadOnlyDictionary<string, ExpectedScreenshotArtifact> Expected =
        All.ToDictionary(artifact => artifact.PngFileName, StringComparer.Ordinal);

    public static ExpectedScreenshotArtifact Validate(
        string pngFileName,
        string testName,
        IReadOnlyList<string> validatedAnchors)
    {
        ArgumentNullException.ThrowIfNull(validatedAnchors);
        if (!Expected.TryGetValue(pngFileName, out var expected) ||
            !string.Equals(testName, expected.TestName, StringComparison.Ordinal) ||
            validatedAnchors.Count != 3 ||
            !string.Equals(validatedAnchors[0], "main_navigation", StringComparison.Ordinal) ||
            !string.Equals(validatedAnchors[1], "fixed_header", StringComparison.Ordinal) ||
            !string.Equals(validatedAnchors[2], expected.CurrentPageAnchor, StringComparison.Ordinal) ||
            validatedAnchors.Distinct(StringComparer.Ordinal).Count() != validatedAnchors.Count)
        {
            throw new InvalidDataException("screenshot_artifact_contract_invalid");
        }

        return expected;
    }
}
