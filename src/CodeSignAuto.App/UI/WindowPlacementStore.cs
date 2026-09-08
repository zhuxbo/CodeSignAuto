using System.Text.Json;

namespace CodeSignAuto.App.UI;

public sealed record WindowPlacement(double Left, double Top, double Width, double Height);

public sealed record ScreenWorkArea(double Left, double Top, double Width, double Height);

public sealed record RestoredWindowPlacement(WindowPlacement Placement, bool CenterOnScreen);

public interface IScreenWorkAreaSource
{
    IReadOnlyList<ScreenWorkArea> GetWorkAreas();
}

public sealed class EmptyScreenWorkAreaSource : IScreenWorkAreaSource
{
    public IReadOnlyList<ScreenWorkArea> GetWorkAreas() => [];
}

public sealed class WindowPlacementStore
{
    private const double AspectRatio = 4d / 3d;
    private const double AspectRatioTolerance = 0.001d;

    public const double DefaultWidth = 1024;
    public const double DefaultHeight = 768;
    public const double MinimumWidth = 960;
    public const double MinimumHeight = 720;

    private static readonly HashSet<string> ExpectedProperties = new(StringComparer.Ordinal)
    {
        "left", "top", "width", "height",
    };

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = true,
    };

    private readonly string _path;
    private readonly IScreenWorkAreaSource _workAreas;

    public WindowPlacementStore()
        : this(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CodeSignAuto",
                "window.json"),
            new EmptyScreenWorkAreaSource())
    {
    }

    public WindowPlacementStore(string path, IScreenWorkAreaSource workAreas)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        _workAreas = workAreas ?? throw new ArgumentNullException(nameof(workAreas));
    }

    public static WindowPlacement Default => new(0, 0, DefaultWidth, DefaultHeight);

    public RestoredWindowPlacement Normalize(WindowPlacement placement)
    {
        ArgumentNullException.ThrowIfNull(placement);
        if (!TryGetBounds(
                placement.Left,
                placement.Top,
                placement.Width,
                placement.Height,
                out var placementRight,
                out var placementBottom) ||
            placement.Width < MinimumWidth ||
            placement.Height < MinimumHeight ||
            placement.Width <= placement.Height ||
            Math.Abs((placement.Width / placement.Height) - AspectRatio) > AspectRatioTolerance)
        {
            return SafeDefault();
        }

        var validAreas = _workAreas.GetWorkAreas()
            .Select(area => TryGetAreaBounds(area, out var right, out var bottom)
                ? new WorkAreaBounds(area, right, bottom)
                : null)
            .Where(area => area is not null)
            .Select(area => area!)
            .ToArray();
        if (validAreas.Length == 0)
        {
            return SafeDefault();
        }

        var virtualLeft = validAreas.Min(area => area.Area.Left);
        var virtualTop = validAreas.Min(area => area.Area.Top);
        var virtualRight = validAreas.Max(area => area.Right);
        var virtualBottom = validAreas.Max(area => area.Bottom);
        var virtualWidth = virtualRight - virtualLeft;
        var virtualHeight = virtualBottom - virtualTop;
        var minimumAllowedLeft = virtualLeft - virtualWidth;
        var minimumAllowedTop = virtualTop - virtualHeight;
        var maximumAllowedRight = virtualRight + virtualWidth;
        var maximumAllowedBottom = virtualBottom + virtualHeight;
        if (!IsFinite(virtualWidth) || virtualWidth <= 0 ||
            !IsFinite(virtualHeight) || virtualHeight <= 0 ||
            !IsFinite(minimumAllowedLeft) ||
            !IsFinite(minimumAllowedTop) ||
            !IsFinite(maximumAllowedRight) ||
            !IsFinite(maximumAllowedBottom) ||
            placement.Width > virtualWidth ||
            placement.Height > virtualHeight ||
            placement.Left < minimumAllowedLeft ||
            placement.Top < minimumAllowedTop ||
            placementRight > maximumAllowedRight ||
            placementBottom > maximumAllowedBottom ||
            !validAreas.Any(area => HasPositiveIntersection(
                placement,
                placementRight,
                placementBottom,
                area)))
        {
            return SafeDefault();
        }

        return new RestoredWindowPlacement(placement, CenterOnScreen: false);
    }

    public async Task<RestoredWindowPlacement> LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return Normalize(ParseStrict(document.RootElement));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException
                or UnauthorizedAccessException
                or JsonException
                or InvalidDataException
                or ArgumentException
                or NotSupportedException)
        {
            return new RestoredWindowPlacement(Default, CenterOnScreen: true);
        }
    }

    public async Task SaveAsync(WindowPlacement placement, CancellationToken cancellationToken)
    {
        var normalized = Normalize(placement);
        if (normalized.CenterOnScreen)
        {
            return;
        }

        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("window_placement_path_invalid");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await using var writer = new Utf8JsonWriter(stream, WriterOptions);
                writer.WriteStartObject();
                writer.WriteNumber("left", placement.Left);
                writer.WriteNumber("top", placement.Top);
                writer.WriteNumber("width", placement.Width);
                writer.WriteNumber("height", placement.Height);
                writer.WriteEndObject();
                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, _path, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (IOException)
            {
            }
        }
    }

    private static WindowPlacement ParseStrict(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("window_placement_invalid");
        }

        var values = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!ExpectedProperties.Contains(property.Name) ||
                !values.TryAdd(property.Name, ReadNumber(property.Value)))
            {
                throw new InvalidDataException("window_placement_invalid");
            }
        }

        if (values.Count != ExpectedProperties.Count)
        {
            throw new InvalidDataException("window_placement_invalid");
        }

        return new WindowPlacement(values["left"], values["top"], values["width"], values["height"]);
    }

    private static double ReadNumber(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out var number))
        {
            throw new InvalidDataException("window_placement_invalid");
        }

        return number;
    }

    private static RestoredWindowPlacement SafeDefault() =>
        new(Default, CenterOnScreen: true);

    private static bool HasPositiveIntersection(
        WindowPlacement placement,
        double placementRight,
        double placementBottom,
        WorkAreaBounds area)
    {
        var width = Math.Min(placementRight, area.Right) - Math.Max(placement.Left, area.Area.Left);
        var height = Math.Min(placementBottom, area.Bottom) - Math.Max(placement.Top, area.Area.Top);
        return width > 0 && height > 0;
    }

    private static bool TryGetAreaBounds(
        ScreenWorkArea area,
        out double right,
        out double bottom) =>
        TryGetBounds(area.Left, area.Top, area.Width, area.Height, out right, out bottom) &&
        area.Width > 0 &&
        area.Height > 0;

    private static bool TryGetBounds(
        double left,
        double top,
        double width,
        double height,
        out double right,
        out double bottom)
    {
        right = left + width;
        bottom = top + height;
        return IsFinite(left) &&
            IsFinite(top) &&
            IsFinite(width) &&
            IsFinite(height) &&
            IsFinite(right) &&
            IsFinite(bottom);
    }

    private static bool IsFinite(double value) => !double.IsNaN(value) && !double.IsInfinity(value);

    private sealed record WorkAreaBounds(ScreenWorkArea Area, double Right, double Bottom);
}
