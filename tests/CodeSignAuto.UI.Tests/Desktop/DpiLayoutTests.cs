#if CODESIGNAUTO_WPF
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CodeSignAuto.App.UI;
using CodeSignAuto.App.UI.Testing;

namespace CodeSignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class DpiLayoutTests
{
    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Four_dpi_levels_render_all_six_real_pages_inside_minimum_and_default_clients()
    {
        foreach (var dpi in new[] { 96, 120, 144, 192 })
        {
            foreach (var state in new[] { "ready", "partial", "token-missing", "job-failed" })
            {
                foreach (var size in new[] { UiWindowGeometry.Minimum, UiWindowGeometry.Default })
                {
                    var result = await WpfLayoutProbe.RenderAsync(dpi, size, state);
                    Assert.Equal(6, result.Pages.Count);
                    Assert.All(result.Pages, page =>
                    {
                        Assert.True(page.NavigationVisible);
                        Assert.True(page.TitleVisible);
                        Assert.True(page.PrimaryActionReachable);
                        Assert.True(page.StatusAreaReachable);
                        Assert.True(page.RectanglesFiniteAndNonNegative);
                        Assert.False(page.FixedChromeOverlapsContent);
                        Assert.True(page.NamedControlsInsideClient);
                        Assert.True(page.NamedControlsDoNotOverlap);
                        Assert.True(page.PrimaryActionContainmentValid);
                        Assert.True(page.NoHorizontalClipping);
                        Assert.True(page.VerticalScrollReachable);
                        Assert.True(page.RenderHasNonEmptyPixels);
                        Assert.True(page.NamedRegionsHaveNonEmptyPixels);
                    });
                    Assert.Equal(1, result.ContentScrollViewerCount);
                }
            }
        }
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Activation_primary_action_is_validly_nested_and_reachable_at_all_four_dpi_levels()
    {
        foreach (var dpi in new[] { 96, 120, 144, 192 })
        {
            var result = await WpfLayoutProbe.RenderAsync(dpi, UiWindowGeometry.Minimum, "ready");
            var activation = Assert.Single(result.Pages, page => page.Page == "激活凭证");

            Assert.True(activation.PrimaryActionNestedInStatus);
            Assert.True(activation.PrimaryActionContainmentValid);
            Assert.True(activation.PrimaryActionReachable);
            Assert.True(activation.StatusAreaReachable);
            Assert.True(activation.NamedControlsDoNotOverlap);
        }
    }
}
#else
namespace CodeSignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class DpiLayoutTests
{
    [Fact(Skip = "Requires isolated STA WPF rendering on Windows.")]
    public void Four_dpi_levels_render_all_six_real_pages_inside_minimum_and_default_clients() { }

    [Fact(Skip = "Requires isolated STA WPF rendering on Windows.")]
    public void Activation_primary_action_is_validly_nested_and_reachable_at_all_four_dpi_levels() { }
}
#endif
