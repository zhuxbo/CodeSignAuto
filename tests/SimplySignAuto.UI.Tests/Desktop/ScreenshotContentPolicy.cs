namespace SimplySignAuto.UI.Tests.Desktop;

internal readonly record struct ScreenshotPixel(byte Red, byte Green, byte Blue, byte Alpha);

internal readonly record struct ScreenshotRegion(int Left, int Top, int Width, int Height)
{
    public int Right => checked(Left + Width);

    public int Bottom => checked(Top + Height);
}

internal sealed record ScreenshotAnchor(string Name, ScreenshotRegion Region);

internal sealed record ScreenshotContentValidationResult(
    IReadOnlyList<string> AnchorNames,
    int AnchorCount);

internal static class ScreenshotContentPolicy
{
    private const int MinimumRegionPixels = 16;
    private const int MinimumBrightnessRange = 8;
    private const double MinimumBrightnessVariance = 3;
    private const double MinimumDifferentColorFraction = 0.005;

    public static ScreenshotContentValidationResult Validate(
        int width,
        int height,
        IReadOnlyList<ScreenshotPixel> pixels,
        ScreenshotRegion client,
        IReadOnlyList<ScreenshotAnchor> anchors)
    {
        ArgumentNullException.ThrowIfNull(pixels);
        ArgumentNullException.ThrowIfNull(anchors);
        if (width <= 0 || height <= 0 ||
            pixels.Count != checked(width * height) ||
            !IsInside(client, new ScreenshotRegion(0, 0, width, height)) ||
            checked(client.Width * client.Height) < MinimumRegionPixels)
        {
            throw new InvalidDataException("screenshot_client_contract_invalid");
        }

        if (anchors.Count < 3 ||
            anchors.Any(anchor =>
                string.IsNullOrWhiteSpace(anchor.Name) ||
                anchor.Name.Length > 80 ||
                anchor.Name.Any(char.IsControl) ||
                !IsInside(anchor.Region, client) ||
                checked(anchor.Region.Width * anchor.Region.Height) < MinimumRegionPixels) ||
            anchors.Select(anchor => anchor.Name).Distinct(StringComparer.Ordinal).Count() != anchors.Count ||
            anchors.SelectMany((left, index) => anchors.Skip(index + 1).Select(right => (left, right)))
                .Any(pair => Intersects(pair.left.Region, pair.right.Region)))
        {
            throw new InvalidDataException("screenshot_anchor_contract_invalid");
        }

        foreach (var pixel in PixelsIn(pixels, width, client))
        {
            if (pixel.Alpha != byte.MaxValue)
            {
                throw new InvalidDataException("screenshot_alpha_invalid");
            }
        }

        if (!HasRenderedContent(pixels, width, client))
        {
            throw new InvalidDataException("screenshot_client_content_invalid");
        }

        foreach (var anchor in anchors)
        {
            if (!HasRenderedContent(pixels, width, anchor.Region))
            {
                throw new InvalidDataException($"screenshot_anchor_content_invalid:{anchor.Name}");
            }
        }

        var names = anchors.Select(anchor => anchor.Name).ToArray();
        return new ScreenshotContentValidationResult(names, names.Length);
    }

    private static bool HasRenderedContent(
        IReadOnlyList<ScreenshotPixel> pixels,
        int width,
        ScreenshotRegion region)
    {
        var colorCounts = new Dictionary<int, int>();
        var minimumBrightness = byte.MaxValue;
        var maximumBrightness = byte.MinValue;
        long brightnessSum = 0;
        long brightnessSquaredSum = 0;
        var count = 0;
        foreach (var pixel in PixelsIn(pixels, width, region))
        {
            var brightness = ((pixel.Red * 54) + (pixel.Green * 183) + (pixel.Blue * 19)) >> 8;
            minimumBrightness = Math.Min(minimumBrightness, (byte)brightness);
            maximumBrightness = Math.Max(maximumBrightness, (byte)brightness);
            brightnessSum += brightness;
            brightnessSquaredSum += brightness * brightness;
            var quantizedColor = ((pixel.Red >> 4) << 8) | ((pixel.Green >> 4) << 4) | (pixel.Blue >> 4);
            colorCounts.TryGetValue(quantizedColor, out var occurrences);
            colorCounts[quantizedColor] = occurrences + 1;
            count++;
        }

        if (count < MinimumRegionPixels || colorCounts.Count < 2 ||
            maximumBrightness - minimumBrightness < MinimumBrightnessRange)
        {
            return false;
        }

        var mean = brightnessSum / (double)count;
        var variance = (brightnessSquaredSum / (double)count) - (mean * mean);
        var requiredDifferentPixels = Math.Max(
            2,
            checked((int)Math.Ceiling(count * MinimumDifferentColorFraction)));
        var differentFromDominant = count - colorCounts.Values.Max();
        return variance >= MinimumBrightnessVariance &&
            differentFromDominant >= requiredDifferentPixels;
    }

    private static IEnumerable<ScreenshotPixel> PixelsIn(
        IReadOnlyList<ScreenshotPixel> pixels,
        int width,
        ScreenshotRegion region)
    {
        for (var y = region.Top; y < region.Bottom; y++)
        {
            for (var x = region.Left; x < region.Right; x++)
            {
                yield return pixels[(y * width) + x];
            }
        }
    }

    private static bool IsInside(ScreenshotRegion inner, ScreenshotRegion outer) =>
        inner.Width > 0 && inner.Height > 0 &&
        inner.Left >= outer.Left && inner.Top >= outer.Top &&
        inner.Right <= outer.Right && inner.Bottom <= outer.Bottom;

    private static bool Intersects(ScreenshotRegion left, ScreenshotRegion right) =>
        left.Left < right.Right && left.Right > right.Left &&
        left.Top < right.Bottom && left.Bottom > right.Top;
}
