using SimplySignAuto.App.UI;

namespace SimplySignAuto.UI.Tests;

public sealed class WindowPlacementStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"SimplySignAuto-UI-{Guid.NewGuid():N}");

    [Fact]
    public void Invalid_or_disconnected_placement_falls_back_to_centered_landscape_four_by_three()
    {
        var source = new FixedWorkAreas([new ScreenWorkArea(0, 0, 1920, 1040)]);
        var store = new WindowPlacementStore(Path.Combine(_directory, "window.json"), source);

        var restored = store.Normalize(new WindowPlacement(2200, 20, 800, 600));

        Assert.True(restored.CenterOnScreen);
        Assert.Equal(1024, restored.Placement.Width);
        Assert.Equal(768, restored.Placement.Height);
        Assert.Equal(4d / 3d, restored.Placement.Width / restored.Placement.Height, 6);
        Assert.True(restored.Placement.Width > restored.Placement.Height);
    }

    [Fact]
    public void Placement_requires_the_exact_minimum_size_and_a_positive_screen_intersection()
    {
        var source = new FixedWorkAreas([
            new ScreenWorkArea(0, 0, 1920, 1040),
            new ScreenWorkArea(-1600, -200, 1600, 900),
        ]);
        var store = new WindowPlacementStore(Path.Combine(_directory, "window.json"), source);

        var secondary = store.Normalize(new WindowPlacement(-1500, -100, 960, 720));
        var tooSmall = store.Normalize(new WindowPlacement(10, 10, 959, 720));
        var touchingOnly = store.Normalize(new WindowPlacement(1920, 20, 1024, 768));

        Assert.False(secondary.CenterOnScreen);
        Assert.Equal(-1500, secondary.Placement.Left);
        Assert.True(tooSmall.CenterOnScreen);
        Assert.True(touchingOnly.CenterOnScreen);
    }

    [Theory]
    [InlineData(960, 1280)]
    [InlineData(1024, 769)]
    [InlineData(1100, 760)]
    public void Portrait_or_non_four_by_three_placement_never_reaches_WPF(double width, double height)
    {
        var store = new WindowPlacementStore(
            Path.Combine(_directory, "window.json"),
            new FixedWorkAreas([new ScreenWorkArea(0, 0, 1920, 1440)]));

        var restored = store.Normalize(new WindowPlacement(20, 20, width, height));

        Assert.True(restored.CenterOnScreen);
        Assert.Equal(WindowPlacementStore.Default, restored.Placement);
    }

    [Theory]
    [InlineData(double.NaN, 10, 1024, 768)]
    [InlineData(10, double.PositiveInfinity, 1024, 768)]
    [InlineData(10, 10, double.NegativeInfinity, 768)]
    public void Non_finite_placement_never_restores(double left, double top, double width, double height)
    {
        var store = new WindowPlacementStore(
            Path.Combine(_directory, "window.json"),
            new FixedWorkAreas([new ScreenWorkArea(0, 0, 1920, 1040)]));

        Assert.True(store.Normalize(new WindowPlacement(left, top, width, height)).CenterOnScreen);
    }

    [Fact]
    public void Huge_or_overflowing_finite_placement_never_reaches_WPF()
    {
        var store = new WindowPlacementStore(
            Path.Combine(_directory, "window.json"),
            new FixedWorkAreas([
                new ScreenWorkArea(0, 0, 1920, 1040),
                new ScreenWorkArea(1920, 0, 1920, 1040),
            ]));
        WindowPlacement[] invalid =
        [
            new(0, 0, double.MaxValue, 768),
            new(0, 0, 1024, double.MaxValue),
            new(double.MaxValue - 512, 0, 1024, 768),
            new(0, double.MaxValue - 512, 1024, 768),
            new(-1e300, 0, 1e300, 768),
        ];

        foreach (var placement in invalid)
        {
            var restored = store.Normalize(placement);
            Assert.True(restored.CenterOnScreen);
            Assert.Equal(WindowPlacementStore.Default, restored.Placement);
        }

        var spanning = store.Normalize(new WindowPlacement(1200, 40, 1280, 960));
        Assert.False(spanning.CenterOnScreen);
    }

    [Fact]
    public async Task Huge_finite_json_placement_falls_back_to_the_centered_default()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "window.json");
        await File.WriteAllTextAsync(
            path,
            "{\"left\":0,\"top\":0,\"width\":1e308,\"height\":768}");
        var store = new WindowPlacementStore(
            path,
            new FixedWorkAreas([new ScreenWorkArea(0, 0, 1920, 1040)]));

        var restored = await store.LoadAsync(CancellationToken.None);

        Assert.True(restored.CenterOnScreen);
        Assert.Equal(WindowPlacementStore.Default, restored.Placement);
    }

    [Theory]
    [InlineData("{\"left\":1,\"top\":2,\"width\":1024,\"height\":768,\"extra\":true}")]
    [InlineData("{\"left\":1,\"top\":2,\"width\":1024,\"width\":1024,\"height\":768}")]
    [InlineData("{\"left\":1,\"top\":2,\"width\":\"1024\",\"height\":768}")]
    public async Task Corrupt_or_non_strict_json_returns_the_safe_default_without_blocking_startup(string json)
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "window.json");
        await File.WriteAllTextAsync(path, json);
        var store = new WindowPlacementStore(
            path,
            new FixedWorkAreas([new ScreenWorkArea(0, 0, 1920, 1040)]));

        var restored = await store.LoadAsync(CancellationToken.None);

        Assert.True(restored.CenterOnScreen);
        Assert.Equal(new WindowPlacement(0, 0, 1024, 768), restored.Placement);
    }

    [Fact]
    public async Task Save_and_load_round_trip_preserves_a_valid_secondary_monitor_placement()
    {
        var workAreas = new FixedWorkAreas([new ScreenWorkArea(-1920, 0, 1920, 1040)]);
        var store = new WindowPlacementStore(Path.Combine(_directory, "window.json"), workAreas);
        var expected = new WindowPlacement(-1800, 50, 1080, 810);

        await store.SaveAsync(expected, CancellationToken.None);
        var restored = await store.LoadAsync(CancellationToken.None);

        Assert.False(restored.CenterOnScreen);
        Assert.Equal(expected, restored.Placement);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class FixedWorkAreas(IReadOnlyList<ScreenWorkArea> workAreas) : IScreenWorkAreaSource
    {
        public IReadOnlyList<ScreenWorkArea> GetWorkAreas() => workAreas;
    }
}
