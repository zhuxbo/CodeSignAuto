namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class ScreenshotContentPolicyTests
{
    [Fact]
    public void Opaque_client_and_three_independent_semantic_anchors_are_accepted()
    {
        var fixture = CreateValidFixture();

        var result = ScreenshotContentPolicy.Validate(
            fixture.Width,
            fixture.Height,
            fixture.Pixels,
            fixture.Client,
            fixture.Anchors);

        Assert.Equal(3, result.AnchorCount);
        Assert.Equal(fixture.Anchors.Select(anchor => anchor.Name), result.AnchorNames);
    }

    [Fact]
    public void Transparent_colored_pixels_are_not_visible_content()
    {
        var fixture = CreateValidFixture();
        var transparent = fixture.Pixels
            .Select(pixel => pixel with { Alpha = 0 })
            .ToArray();

        var error = Assert.Throws<InvalidDataException>(() => ScreenshotContentPolicy.Validate(
            fixture.Width,
            fixture.Height,
            transparent,
            fixture.Client,
            fixture.Anchors));

        Assert.Equal("screenshot_alpha_invalid", error.Message);
    }

    [Fact]
    public void Colorful_outer_chrome_does_not_rescue_a_black_client()
    {
        var fixture = CreateValidFixture();
        var pixels = Enumerable.Repeat(new ScreenshotPixel(0, 0, 0, 255), fixture.Pixels.Count).ToArray();
        for (var x = 0; x < fixture.Width; x++)
        {
            pixels[x] = new ScreenshotPixel((byte)(x * 7), 180, 70, 255);
        }

        var error = Assert.Throws<InvalidDataException>(() => ScreenshotContentPolicy.Validate(
            fixture.Width,
            fixture.Height,
            pixels,
            fixture.Client,
            fixture.Anchors));

        Assert.Equal("screenshot_client_content_invalid", error.Message);
    }

    [Fact]
    public void A_single_changed_client_pixel_is_not_rendered_content()
    {
        var fixture = CreateValidFixture();
        var pixels = Enumerable.Repeat(new ScreenshotPixel(245, 245, 245, 255), fixture.Pixels.Count).ToArray();
        pixels[(fixture.Client.Top * fixture.Width) + fixture.Client.Left] = new ScreenshotPixel(0, 0, 0, 255);

        var error = Assert.Throws<InvalidDataException>(() => ScreenshotContentPolicy.Validate(
            fixture.Width,
            fixture.Height,
            pixels,
            fixture.Client,
            fixture.Anchors));

        Assert.Equal("screenshot_client_content_invalid", error.Message);
    }

    [Fact]
    public void Blank_semantic_anchor_fails_even_when_the_rest_of_the_client_is_drawn()
    {
        var fixture = CreateValidFixture();
        var pixels = fixture.Pixels.ToArray();
        var blank = fixture.Anchors[1];
        Fill(pixels, fixture.Width, blank.Region, new ScreenshotPixel(245, 245, 245, 255));

        var error = Assert.Throws<InvalidDataException>(() => ScreenshotContentPolicy.Validate(
            fixture.Width,
            fixture.Height,
            pixels,
            fixture.Client,
            fixture.Anchors));

        Assert.Equal("screenshot_anchor_content_invalid:fixed_header", error.Message);
    }

    [Theory]
    [InlineData("fewer")]
    [InlineData("overlap")]
    [InlineData("outside")]
    public void Anchor_contract_requires_three_distinct_non_overlapping_client_regions(string mutation)
    {
        var fixture = CreateValidFixture();
        IReadOnlyList<ScreenshotAnchor> anchors = mutation switch
        {
            "fewer" => fixture.Anchors.Take(2).ToArray(),
            "overlap" =>
            [
                fixture.Anchors[0],
                fixture.Anchors[1] with { Region = fixture.Anchors[0].Region },
                fixture.Anchors[2],
            ],
            "outside" =>
            [
                fixture.Anchors[0],
                fixture.Anchors[1],
                fixture.Anchors[2] with { Region = new ScreenshotRegion(0, 0, 5, 4) },
            ],
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        var error = Assert.Throws<InvalidDataException>(() => ScreenshotContentPolicy.Validate(
            fixture.Width,
            fixture.Height,
            fixture.Pixels,
            fixture.Client,
            anchors));

        Assert.Equal("screenshot_anchor_contract_invalid", error.Message);
    }

    private static ScreenshotFixture CreateValidFixture()
    {
        const int width = 24;
        const int height = 20;
        var client = new ScreenshotRegion(1, 1, 22, 18);
        ScreenshotAnchor[] anchors =
        [
            new("main_navigation", new ScreenshotRegion(2, 3, 5, 4)),
            new("fixed_header", new ScreenshotRegion(9, 3, 5, 4)),
            new("current_page_title", new ScreenshotRegion(16, 3, 5, 4)),
        ];
        var pixels = Enumerable.Repeat(new ScreenshotPixel(30, 30, 30, 255), width * height).ToArray();
        for (var y = client.Top; y < client.Bottom; y++)
        {
            for (var x = client.Left; x < client.Right; x++)
            {
                var shade = (byte)(210 + ((x + y) % 4 * 8));
                pixels[(y * width) + x] = new ScreenshotPixel(shade, shade, shade, 255);
            }
        }

        foreach (var anchor in anchors)
        {
            for (var y = anchor.Region.Top; y < anchor.Region.Bottom; y++)
            {
                for (var x = anchor.Region.Left; x < anchor.Region.Right; x++)
                {
                    pixels[(y * width) + x] = (x + y) % 2 == 0
                        ? new ScreenshotPixel(25, 45, 85, 255)
                        : new ScreenshotPixel(240, 245, 250, 255);
                }
            }
        }

        return new ScreenshotFixture(width, height, pixels, client, anchors);
    }

    private static void Fill(
        ScreenshotPixel[] pixels,
        int width,
        ScreenshotRegion region,
        ScreenshotPixel pixel)
    {
        for (var y = region.Top; y < region.Bottom; y++)
        {
            for (var x = region.Left; x < region.Right; x++)
            {
                pixels[(y * width) + x] = pixel;
            }
        }
    }

    private sealed record ScreenshotFixture(
        int Width,
        int Height,
        IReadOnlyList<ScreenshotPixel> Pixels,
        ScreenshotRegion Client,
        IReadOnlyList<ScreenshotAnchor> Anchors);
}
