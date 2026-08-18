using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Testing;

namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class WindowGeometryTests
{
#if SIMPLYSIGN_WPF
    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Real_process_window_is_1024_by_768_landscape_four_by_three()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        var uiaBounds = app.MainWindow.Current.BoundingRectangle;
        var geometry = app.ReadWindowGeometry();

        Assert.InRange(geometry.Dpi, 96, 768);
        Assert.InRange(geometry.LogicalOuter.Width, 1023, 1025);
        Assert.InRange(geometry.LogicalOuter.Height, 767, 769);
        Assert.True(UiWindowGeometry.IsLandscapeFourByThree(geometry.LogicalOuter.Size, 0.002));
        Assert.InRange(Math.Abs(uiaBounds.Left - geometry.PhysicalOuter.Left), 0, 1);
        Assert.InRange(Math.Abs(uiaBounds.Top - geometry.PhysicalOuter.Top), 0, 1);
        Assert.InRange(Math.Abs(uiaBounds.Width - geometry.PhysicalOuter.Width), 0, 1);
        Assert.InRange(Math.Abs(uiaBounds.Height - geometry.PhysicalOuter.Height), 0, 1);
        Assert.InRange(geometry.PhysicalClient.Width, 1, geometry.PhysicalOuter.Width);
        Assert.InRange(geometry.PhysicalClient.Height, 1, geometry.PhysicalOuter.Height);
        Assert.InRange(geometry.LogicalClient.Width, 1, geometry.LogicalOuter.Width);
        Assert.InRange(geometry.LogicalClient.Height, 1, geometry.LogicalOuter.Height);
        Assert.True(app.Process.SessionId > 0);
        var transformPattern = (System.Windows.Automation.TransformPattern)app.MainWindow.GetCurrentPattern(
            System.Windows.Automation.TransformPattern.Pattern);
        Assert.False(transformPattern.Current.CanResize);
        await app.CaptureWindowPngAsync(
            "window-geometry.png",
            nameof(Real_process_window_is_1024_by_768_landscape_four_by_three));
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Target_window_capture_is_not_replaced_by_a_covering_window()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        var before = app.CaptureTargetWindowPixelHash();

        using var overlay = OpaqueWindowCover.Show(app.ReadWindowGeometry().PhysicalOuter);
        var covered = app.CaptureTargetWindowPixelHash();

        Assert.Equal(before, covered);
    }
#else
    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Real_process_window_is_1024_by_768_landscape_four_by_three()
    {
    }


    [Fact(Skip = "Requires real WPF target-HWND capture in a WTS Active non-zero Windows session.")]
    public void Target_window_capture_is_not_replaced_by_a_covering_window()
    {
    }
#endif

    [Fact]
    public void Default_and_minimum_geometry_are_landscape_four_by_three()
    {
        Assert.Equal(new UiClientSize(1024, 768), UiWindowGeometry.Default);
        Assert.Equal(new UiClientSize(960, 720), UiWindowGeometry.Minimum);
        Assert.True(UiWindowGeometry.IsLandscapeFourByThree(UiWindowGeometry.Default, 0.001));
        Assert.True(UiWindowGeometry.IsLandscapeFourByThree(UiWindowGeometry.Minimum, 0.001));
        Assert.Equal(1024, WindowPlacementStore.DefaultWidth);
        Assert.Equal(768, WindowPlacementStore.DefaultHeight);
    }

    [Fact]
    public void Reversed_portrait_dimensions_are_rejected()
    {
        Assert.False(UiWindowGeometry.IsLandscapeFourByThree(new UiClientSize(768, 1024), 0.001));
    }

    [Theory]
    [InlineData(96, 1024, 768)]
    [InlineData(120, 1280, 960)]
    [InlineData(144, 1536, 1152)]
    [InlineData(192, 2048, 1536)]
    public void Physical_bounds_preserve_ratio_at_supported_dpi(int dpi, int width, int height)
    {
        var physical = UiWindowGeometry.ToPhysical(UiWindowGeometry.Default, dpi);

        Assert.Equal(new UiClientSize(width, height), physical);
        Assert.True(UiWindowGeometry.IsLandscapeFourByThree(physical, 0.001));
    }

    [Theory]
    [InlineData(96, 1024, 768)]
    [InlineData(120, 1280, 960)]
    [InlineData(144, 1536, 1152)]
    [InlineData(192, 2048, 1536)]
    public void Physical_outer_bounds_convert_back_to_1024_by_768_DIPs(int dpi, double width, double height)
    {
        var logical = UiWindowGeometry.ToLogical(new UiClientSize(width, height), dpi);

        Assert.Equal(UiWindowGeometry.Default.Width, logical.Width, 6);
        Assert.Equal(UiWindowGeometry.Default.Height, logical.Height, 6);
    }
}
