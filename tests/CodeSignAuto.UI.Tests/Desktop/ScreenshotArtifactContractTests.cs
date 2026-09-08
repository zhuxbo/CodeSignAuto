namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class ScreenshotArtifactContractTests
{
    public static TheoryData<string, string, string> ExpectedArtifacts => new()
    {
        {
            "activation-saved.png",
            "Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret",
            "current_page_title:激活凭证"
        },
        {
            "jobs-loaded.png",
            "Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy",
            "current_page_title:签名任务"
        },
        {
            "overview-busy.png",
            "Overview_exposes_busy_state_and_opens_the_real_jobs_page",
            "current_page_title:概览"
        },
        {
            "quick-finalizing.png",
            "Quick_sign_exposes_finalizing_before_opening_jobs",
            "current_page_title:快速签名"
        },
        {
            "window-geometry.png",
            "Real_process_window_is_1024_by_768_landscape_four_by_three",
            "current_page_title:概览"
        },
    };

    [Theory]
    [MemberData(nameof(ExpectedArtifacts))]
    public void Exact_png_test_and_current_page_mapping_is_accepted(
        string pngFileName,
        string testName,
        string currentPageAnchor)
    {
        var result = ScreenshotArtifactContract.Validate(
            pngFileName,
            testName,
            ["main_navigation", "fixed_header", currentPageAnchor]);

        Assert.Equal(pngFileName, result.PngFileName);
        Assert.Equal(testName, result.TestName);
        Assert.Equal(currentPageAnchor, result.CurrentPageAnchor);
    }

    [Theory]
    [InlineData(
        "activation-saved.png",
        "Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy",
        "current_page_title:激活凭证")]
    [InlineData(
        "jobs-loaded.png",
        "Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy",
        "current_page_title:概览")]
    [InlineData(
        "overview-busy.png",
        "Quick_sign_exposes_finalizing_before_opening_jobs",
        "current_page_title:快速签名")]
    [InlineData(
        "window-geometry.png",
        "Real_process_window_is_1024_by_768_landscape_four_by_three",
        "current_page_title:服务设置")]
    public void Swapped_test_or_page_mapping_is_rejected(
        string pngFileName,
        string testName,
        string currentPageAnchor)
    {
        AssertInvalid(pngFileName, testName, ["main_navigation", "fixed_header", currentPageAnchor]);
    }

    [Theory]
    [InlineData(
        "unknown.png",
        "Real_process_window_is_1024_by_768_landscape_four_by_three",
        "current_page_title:概览")]
    [InlineData(
        "WINDOW-GEOMETRY.PNG",
        "Real_process_window_is_1024_by_768_landscape_four_by_three",
        "current_page_title:概览")]
    [InlineData(
        "window-geometry.png",
        "real_process_window_is_1024_by_768_landscape_four_by_three",
        "current_page_title:概览")]
    [InlineData(
        "window-geometry.png",
        "Real_process_window_is_1024_by_768_landscape_four_by_three",
        "current_page_title:概览 ")]
    public void Unknown_or_case_variant_contract_values_are_rejected(
        string pngFileName,
        string testName,
        string currentPageAnchor)
    {
        AssertInvalid(pngFileName, testName, ["main_navigation", "fixed_header", currentPageAnchor]);
    }

    [Fact]
    public void Duplicate_anchor_is_rejected_even_when_expected_page_is_present()
    {
        AssertInvalid(
            "window-geometry.png",
            "Real_process_window_is_1024_by_768_landscape_four_by_three",
            ["main_navigation", "fixed_header", "current_page_title:概览", "current_page_title:概览"]);
    }

    private static void AssertInvalid(
        string pngFileName,
        string testName,
        IReadOnlyList<string> anchors)
    {
        var error = Assert.Throws<InvalidDataException>(() => ScreenshotArtifactContract.Validate(
            pngFileName,
            testName,
            anchors));

        Assert.Equal("screenshot_artifact_contract_invalid", error.Message);
    }
}
