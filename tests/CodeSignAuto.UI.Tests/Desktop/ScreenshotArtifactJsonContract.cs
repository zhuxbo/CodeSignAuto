using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.RegularExpressions;
using CodeSignAuto.UiAcceptance.StrictJson;

namespace CodeSignAuto.UI.Tests.Desktop;

internal static partial class ScreenshotArtifactJsonContract
{
    private static readonly string[] SidecarFields =
    [
        "schemaVersion", "runId", "sessionId", "testName", "windowPid", "targetHwnd",
        "title", "dpi", "logicalOuter", "physicalOuter", "logicalClient", "physicalClient",
        "pngFileName", "pngWidth", "pngHeight", "pngSha256", "captureMethod",
        "validatedAnchorCount", "validatedAnchors", "currentPageAnchor", "secretInputsEmpty",
        "secretVerificationMethod",
    ];

    private static readonly string[] ManifestFields =
    [
        "schemaVersion", "runId", "sessionId", "dpi", "exitCode", "trxSha256", "appSha256",
        "strictJsonSourceSha256", "expectedScreenshots", "pngs",
    ];

    private static readonly string[] ManifestPngFields =
    [
        "fileName", "testName", "sessionId", "windowPid", "targetHwnd", "title", "dpi",
        "logicalOuter", "physicalOuter", "logicalClient", "physicalClient", "sha256",
        "captureMethod", "validatedAnchorCount", "validatedAnchors", "currentPageAnchor",
        "secretInputsEmpty", "secretVerificationMethod",
    ];

    private static readonly string[] RectangleFields = ["Left", "Top", "Width", "Height"];

    private static readonly string[] ChildResultFields = ["schemaVersion", "result", "runId"];

    public static void ValidateSidecar(string json)
    {
        try
        {
            Preflight.ValidateObject(json, maxDepth: 16, maxLength: 1_048_576);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            RequireExactObject(root, SidecarFields);
            RequireInteger(root, "schemaVersion", 3, 3);
            RequireString(root, "runId", LowerRunIdPattern());
            RequireInteger(root, "sessionId", 1, int.MaxValue);
            var testName = RequireString(root, "testName", TestNamePattern());
            RequireInteger(root, "windowPid", 1, int.MaxValue);
            RequireString(root, "targetHwnd", HwndPattern());
            RequireExactString(root, "title", "CodeSignAuto");
            RequireInteger(root, "dpi", 96, 768);
            RequireRectangle(root.GetProperty("logicalOuter"));
            RequireRectangle(root.GetProperty("physicalOuter"));
            RequireRectangle(root.GetProperty("logicalClient"));
            RequireRectangle(root.GetProperty("physicalClient"));
            var pngFileName = RequireString(root, "pngFileName", PngNamePattern());
            RequireInteger(root, "pngWidth", 1, int.MaxValue);
            RequireInteger(root, "pngHeight", 1, int.MaxValue);
            RequireString(root, "pngSha256", UpperSha256Pattern());
            RequireExactString(root, "captureMethod", "PrintWindow.PW_RENDERFULLCONTENT.24bppRgb");
            RequireInteger(root, "validatedAnchorCount", 3, 3);
            var anchors = RequireStringArray(root.GetProperty("validatedAnchors"), 3);
            var currentPageAnchor = RequireString(root, "currentPageAnchor", PageAnchorPattern());
            RequireBoolean(root, "secretInputsEmpty", expected: true);
            RequireExactString(root, "secretVerificationMethod", "UIAutomationValuePattern");
            if (!string.Equals(currentPageAnchor, anchors[2], StringComparison.Ordinal))
            {
                Reject();
            }

            ScreenshotArtifactContract.Validate(pngFileName, testName, anchors);
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or OverflowException or FormatException)
        {
            throw new InvalidDataException("screenshot_json_contract_invalid", error);
        }
    }

    public static void ValidateManifest(string json)
    {
        try
        {
            Preflight.ValidateObject(json, maxDepth: 16, maxLength: 1_048_576);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            RequireExactObject(root, ManifestFields);
            RequireInteger(root, "schemaVersion", 3, 3);
            RequireString(root, "runId", LowerRunIdPattern());
            RequireInteger(root, "sessionId", 1, int.MaxValue);
            RequireInteger(root, "dpi", 96, 768);
            RequireInteger(root, "exitCode", 0, 0);
            RequireString(root, "trxSha256", UpperSha256Pattern());
            RequireString(root, "appSha256", UpperSha256Pattern());
            RequireString(root, "strictJsonSourceSha256", UpperSha256Pattern());

            var expected = root.GetProperty("expectedScreenshots");
            RequireArrayLength(expected, ScreenshotArtifactContract.All.Count);
            var expectedIndex = 0;
            foreach (var item in expected.EnumerateArray())
            {
                var contract = ScreenshotArtifactContract.All[expectedIndex++];
                RequireExactObject(item, ["pngFileName", "testName", "currentPageAnchor"]);
                RequireExactString(item, "pngFileName", contract.PngFileName);
                RequireExactString(item, "testName", contract.TestName);
                RequireExactString(item, "currentPageAnchor", contract.CurrentPageAnchor);
            }

            var pngs = root.GetProperty("pngs");
            RequireArrayLength(pngs, ScreenshotArtifactContract.All.Count);
            var pngIndex = 0;
            foreach (var item in pngs.EnumerateArray())
            {
                ValidateManifestPng(item, ScreenshotArtifactContract.All[pngIndex++]);
            }
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or OverflowException or FormatException)
        {
            throw new InvalidDataException("screenshot_json_contract_invalid", error);
        }
    }

    public static void ValidateChildResult(string json, string expectedRunId)
    {
        try
        {
            Preflight.ValidateObject(json, maxDepth: 4, maxLength: 4096);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            RequireExactObject(root, ChildResultFields);
            RequireInteger(root, "schemaVersion", 1, 1);
            RequireExactString(root, "result", "ui_session_unavailable");
            var runId = RequireString(root, "runId", LowerRunIdPattern());
            if (!string.Equals(runId, expectedRunId, StringComparison.Ordinal))
            {
                Reject();
            }
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or OverflowException or FormatException)
        {
            throw new InvalidDataException("screenshot_json_contract_invalid", error);
        }
    }

    private static void ValidateManifestPng(JsonElement item, ExpectedScreenshotArtifact contract)
    {
        RequireExactObject(item, ManifestPngFields);
        RequireExactString(item, "fileName", contract.PngFileName);
        RequireExactString(item, "testName", contract.TestName);
        RequireInteger(item, "sessionId", 1, int.MaxValue);
        RequireInteger(item, "windowPid", 1, int.MaxValue);
        RequireString(item, "targetHwnd", HwndPattern());
        RequireExactString(item, "title", "CodeSignAuto");
        RequireInteger(item, "dpi", 96, 768);
        RequireRectangle(item.GetProperty("logicalOuter"));
        RequireRectangle(item.GetProperty("physicalOuter"));
        RequireRectangle(item.GetProperty("logicalClient"));
        RequireRectangle(item.GetProperty("physicalClient"));
        RequireString(item, "sha256", UpperSha256Pattern());
        RequireExactString(item, "captureMethod", "PrintWindow.PW_RENDERFULLCONTENT.24bppRgb");
        RequireInteger(item, "validatedAnchorCount", 3, 3);
        var anchors = RequireStringArray(item.GetProperty("validatedAnchors"), 3);
        RequireExactString(item, "currentPageAnchor", contract.CurrentPageAnchor);
        RequireBoolean(item, "secretInputsEmpty", expected: true);
        RequireExactString(item, "secretVerificationMethod", "UIAutomationValuePattern");
        ScreenshotArtifactContract.Validate(contract.PngFileName, contract.TestName, anchors);
    }

    private static void RequireExactObject(JsonElement element, IReadOnlyCollection<string> expectedFields)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            Reject();
        }

        var properties = element.EnumerateObject().ToArray();
        if (properties.Length != expectedFields.Count ||
            properties.Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() != properties.Length ||
            expectedFields.Any(expected => !properties.Any(property =>
                string.Equals(property.Name, expected, StringComparison.Ordinal))))
        {
            Reject();
        }
    }

    private static string RequireString(JsonElement root, string propertyName, Regex pattern)
    {
        var value = root.GetProperty(propertyName);
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { Length: > 0 } text ||
            !pattern.IsMatch(text))
        {
            Reject();
            return string.Empty;
        }

        return text;
    }

    private static void RequireExactString(JsonElement root, string propertyName, string expected)
    {
        var value = root.GetProperty(propertyName);
        if (value.ValueKind != JsonValueKind.String ||
            !string.Equals(value.GetString(), expected, StringComparison.Ordinal))
        {
            Reject();
        }
    }

    private static void RequireInteger(JsonElement root, string propertyName, int minimum, int maximum)
    {
        var value = root.GetProperty(propertyName);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number) ||
            number < minimum || number > maximum)
        {
            Reject();
        }
    }

    private static void RequireBoolean(JsonElement root, string propertyName, bool expected)
    {
        var value = root.GetProperty(propertyName);
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False) || value.GetBoolean() != expected)
        {
            Reject();
        }
    }

    private static void RequireRectangle(JsonElement rectangle)
    {
        RequireExactObject(rectangle, RectangleFields);
        var left = RequireFiniteNumber(rectangle, "Left");
        var top = RequireFiniteNumber(rectangle, "Top");
        var width = RequireFiniteNumber(rectangle, "Width");
        var height = RequireFiniteNumber(rectangle, "Height");
        if (Math.Abs(left) > 1_000_000 || Math.Abs(top) > 1_000_000 ||
            width <= 0 || width > 100_000 || height <= 0 || height > 100_000)
        {
            Reject();
        }
    }

    private static double RequireFiniteNumber(JsonElement root, string propertyName)
    {
        var value = root.GetProperty(propertyName);
        var number = double.NaN;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out number) || !double.IsFinite(number))
        {
            Reject();
        }

        return number;
    }

    private static IReadOnlyList<string> RequireStringArray(JsonElement array, int expectedCount)
    {
        RequireArrayLength(array, expectedCount);
        var result = new List<string>(expectedCount);
        foreach (var item in array.EnumerateArray())
        {
            var text = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
            if (text is not { Length: > 0 } ||
                text.Length > 160 || text.Any(char.IsControl))
            {
                Reject();
            }

            result.Add(text);
        }

        if (result.Distinct(StringComparer.Ordinal).Count() != result.Count)
        {
            Reject();
        }

        return result;
    }

    private static void RequireArrayLength(JsonElement array, int expectedCount)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != expectedCount)
        {
            Reject();
        }
    }

    [DoesNotReturn]
    private static void Reject() => throw new InvalidDataException("screenshot_json_contract_invalid");

    [GeneratedRegex("^[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex LowerRunIdPattern();

    [GeneratedRegex("^[A-Za-z0-9._]{1,160}$", RegexOptions.CultureInvariant)]
    private static partial Regex TestNamePattern();

    [GeneratedRegex("^[a-z0-9-]+\\.png$", RegexOptions.CultureInvariant)]
    private static partial Regex PngNamePattern();

    [GeneratedRegex("^[0-9A-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex UpperSha256Pattern();

    [GeneratedRegex("^0x[1-9A-F][0-9A-F]*$", RegexOptions.CultureInvariant)]
    private static partial Regex HwndPattern();

    [GeneratedRegex("^current_page_title:.{1,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex PageAnchorPattern();
}
