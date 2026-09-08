using System.Text.Json.Nodes;

namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class ScreenshotArtifactJsonContractTests
{
    private static readonly (string File, string Test, string Page)[] Expected =
    [
        (
            "activation-saved.png",
            "Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret",
            "current_page_title:激活凭证"),
        (
            "jobs-loaded.png",
            "Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy",
            "current_page_title:签名任务"),
        (
            "overview-busy.png",
            "Overview_exposes_busy_state_and_opens_the_real_jobs_page",
            "current_page_title:概览"),
        (
            "quick-finalizing.png",
            "Quick_sign_exposes_finalizing_before_opening_jobs",
            "current_page_title:快速签名"),
        (
            "window-geometry.png",
            "Real_process_window_is_1024_by_768_landscape_four_by_three",
            "current_page_title:概览"),
    ];

    public static TheoryData<string, string> StringTypeMutations
    {
        get
        {
            var result = new TheoryData<string, string>();
            foreach (var fieldName in new[]
            {
                "testName", "pngSha256", "runId", "pngFileName", "title", "captureMethod",
                "targetHwnd", "currentPageAnchor", "secretVerificationMethod",
            })
            {
                foreach (var mutation in new[] { "[]", "{}", "null", "123", "true" })
                {
                    result.Add(fieldName, mutation);
                }
            }

            return result;
        }
    }

    public static TheoryData<string, string> ExpectedScreenshotStringTypeMutations
    {
        get
        {
            var result = new TheoryData<string, string>();
            foreach (var fieldName in new[] { "pngFileName", "testName", "currentPageAnchor" })
            {
                foreach (var mutation in new[] { "[]", "{}", "null", "123", "true" })
                {
                    result.Add(fieldName, mutation);
                }
            }

            return result;
        }
    }

    [Fact]
    public void Exact_sidecar_and_manifest_json_shapes_are_accepted()
    {
        ScreenshotArtifactJsonContract.ValidateSidecar(CreateSidecar());
        ScreenshotArtifactJsonContract.ValidateManifest(CreateManifest());
        ScreenshotArtifactJsonContract.ValidateChildResult(CreateChildResult(), new string('a', 32));
    }

    [Theory]
    [InlineData("sidecar")]
    [InlineData("manifest")]
    [InlineData("child-result")]
    public void Artifact_json_rejects_singleton_root_array_exact_and_nested_duplicate_case_variant_escaped_duplicate_trailing_and_multiple_roots(
        string documentKind)
    {
        var json = documentKind switch
        {
            "sidecar" => CreateSidecar(),
            "manifest" => CreateManifest(),
            "child-result" => CreateChildResult(),
            _ => throw new ArgumentOutOfRangeException(nameof(documentKind)),
        };
        var mutations = new[]
        {
            $"[{json}]",
            InjectAfterOpeningBrace(json, "\"schemaVersion\":1,"),
            InjectAfterOpeningBrace(json, "\"nested\":{\"value\":1,\"value\":2},"),
            json.Replace("\"schemaVersion\"", "\"SchemaVersion\"", StringComparison.Ordinal),
            InjectAfterOpeningBrace(json, "\"schema\\u0056ersion\":1,"),
            json + " trailing",
            json + "{}",
        };

        foreach (var mutation in mutations)
        {
            AssertInvalid(() => Validate(documentKind, mutation));
        }
    }

    [Theory]
    [MemberData(nameof(StringTypeMutations))]
    public void Sidecar_string_fields_reject_array_object_null_number_and_boolean(
        string field,
        string mutationJson)
    {
        var sidecar = JsonNode.Parse(CreateSidecar())!.AsObject();
        sidecar[field] = JsonNode.Parse(mutationJson);

        AssertInvalid(() => ScreenshotArtifactJsonContract.ValidateSidecar(sidecar.ToJsonString()));
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("single")]
    [InlineData("object")]
    [InlineData("null")]
    [InlineData("numeric")]
    [InlineData("boolean")]
    [InlineData("duplicate")]
    public void Sidecar_validated_anchors_require_a_real_exact_three_element_array(string mutation)
    {
        var sidecar = JsonNode.Parse(CreateSidecar())!.AsObject();
        sidecar["validatedAnchors"] = mutation switch
        {
            "empty" => new JsonArray(),
            "single" => new JsonArray("main_navigation"),
            "object" => new JsonObject(),
            "null" => null,
            "numeric" => 3,
            "boolean" => true,
            "duplicate" => new JsonArray(
                "main_navigation",
                "main_navigation",
                "current_page_title:概览"),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        AssertInvalid(() => ScreenshotArtifactJsonContract.ValidateSidecar(sidecar.ToJsonString()));
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("single")]
    [InlineData("object")]
    [InlineData("null")]
    [InlineData("numeric")]
    [InlineData("boolean")]
    [InlineData("duplicate")]
    public void Manifest_expected_screenshots_require_a_real_exact_five_object_array(string mutation)
    {
        var manifest = JsonNode.Parse(CreateManifest())!.AsObject();
        var original = manifest["expectedScreenshots"]!.AsArray();
        manifest["expectedScreenshots"] = mutation switch
        {
            "empty" => new JsonArray(),
            "single" => new JsonArray(original[0]!.DeepClone()),
            "object" => new JsonObject(),
            "null" => null,
            "numeric" => 5,
            "boolean" => true,
            "duplicate" => new JsonArray(
                original[0]!.DeepClone(),
                original[1]!.DeepClone(),
                original[2]!.DeepClone(),
                original[3]!.DeepClone(),
                original[3]!.DeepClone()),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        AssertInvalid(() => ScreenshotArtifactJsonContract.ValidateManifest(manifest.ToJsonString()));
    }

    [Theory]
    [MemberData(nameof(ExpectedScreenshotStringTypeMutations))]
    public void Manifest_expected_screenshot_strings_reject_non_string_json_types(
        string field,
        string mutationJson)
    {
        var manifest = JsonNode.Parse(CreateManifest())!.AsObject();
        manifest["expectedScreenshots"]!.AsArray()[0]![field] = JsonNode.Parse(mutationJson);

        AssertInvalid(() => ScreenshotArtifactJsonContract.ValidateManifest(manifest.ToJsonString()));
    }

    [Fact]
    public void Manifest_expected_mapping_rejects_geometry_settings_mutation()
    {
        var manifest = JsonNode.Parse(CreateManifest())!.AsObject();
        manifest["expectedScreenshots"]!.AsArray()[4]!["currentPageAnchor"] =
            "current_page_title:服务设置";

        AssertInvalid(() => ScreenshotArtifactJsonContract.ValidateManifest(manifest.ToJsonString()));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("123")]
    [InlineData("true")]
    public void Manifest_parser_source_hash_rejects_non_string_json_types(string mutationJson)
    {
        var manifest = JsonNode.Parse(CreateManifest())!.AsObject();
        manifest["strictJsonSourceSha256"] = JsonNode.Parse(mutationJson);

        AssertInvalid(() => ScreenshotArtifactJsonContract.ValidateManifest(manifest.ToJsonString()));
    }

    private static string CreateSidecar()
    {
        var expected = Expected[^1];
        return new JsonObject
        {
            ["schemaVersion"] = 3,
            ["runId"] = new string('a', 32),
            ["sessionId"] = 1,
            ["testName"] = expected.Test,
            ["windowPid"] = 4123,
            ["targetHwnd"] = "0x1A2B",
            ["title"] = "CodeSignAuto",
            ["dpi"] = 96,
            ["logicalOuter"] = Rect(0, 0, 1024, 768),
            ["physicalOuter"] = Rect(0, 0, 1024, 768),
            ["logicalClient"] = Rect(8, 31, 1008, 729),
            ["physicalClient"] = Rect(8, 31, 1008, 729),
            ["pngFileName"] = expected.File,
            ["pngWidth"] = 1024,
            ["pngHeight"] = 768,
            ["pngSha256"] = new string('A', 64),
            ["captureMethod"] = "PrintWindow.PW_RENDERFULLCONTENT.24bppRgb",
            ["validatedAnchorCount"] = 3,
            ["validatedAnchors"] = new JsonArray("main_navigation", "fixed_header", expected.Page),
            ["currentPageAnchor"] = expected.Page,
            ["secretInputsEmpty"] = true,
            ["secretVerificationMethod"] = "UIAutomationValuePattern",
        }.ToJsonString();
    }

    private static string CreateManifest()
    {
        var expectedScreenshots = new JsonArray();
        var pngs = new JsonArray();
        foreach (var expected in Expected)
        {
            expectedScreenshots.Add(new JsonObject
            {
                ["pngFileName"] = expected.File,
                ["testName"] = expected.Test,
                ["currentPageAnchor"] = expected.Page,
            });
            pngs.Add(new JsonObject
            {
                ["fileName"] = expected.File,
                ["testName"] = expected.Test,
                ["sessionId"] = 1,
                ["windowPid"] = 4123,
                ["targetHwnd"] = "0x1A2B",
                ["title"] = "CodeSignAuto",
                ["dpi"] = 96,
                ["logicalOuter"] = Rect(0, 0, 1024, 768),
                ["physicalOuter"] = Rect(0, 0, 1024, 768),
                ["logicalClient"] = Rect(8, 31, 1008, 729),
                ["physicalClient"] = Rect(8, 31, 1008, 729),
                ["sha256"] = new string('A', 64),
                ["captureMethod"] = "PrintWindow.PW_RENDERFULLCONTENT.24bppRgb",
                ["validatedAnchorCount"] = 3,
                ["validatedAnchors"] = new JsonArray("main_navigation", "fixed_header", expected.Page),
                ["currentPageAnchor"] = expected.Page,
                ["secretInputsEmpty"] = true,
                ["secretVerificationMethod"] = "UIAutomationValuePattern",
            });
        }

        return new JsonObject
        {
            ["schemaVersion"] = 3,
            ["runId"] = new string('a', 32),
            ["sessionId"] = 1,
            ["dpi"] = 96,
            ["exitCode"] = 0,
            ["trxSha256"] = new string('B', 64),
            ["appSha256"] = new string('C', 64),
            ["strictJsonSourceSha256"] = new string('D', 64),
            ["expectedScreenshots"] = expectedScreenshots,
            ["pngs"] = pngs,
        }.ToJsonString();
    }

    private static string CreateChildResult() => new JsonObject
    {
        ["schemaVersion"] = 1,
        ["result"] = "ui_session_unavailable",
        ["runId"] = new string('a', 32),
    }.ToJsonString();

    private static string InjectAfterOpeningBrace(string json, string fragment) =>
        "{" + fragment + json[1..];

    private static void Validate(string documentKind, string json)
    {
        switch (documentKind)
        {
            case "sidecar":
                ScreenshotArtifactJsonContract.ValidateSidecar(json);
                break;
            case "manifest":
                ScreenshotArtifactJsonContract.ValidateManifest(json);
                break;
            case "child-result":
                ScreenshotArtifactJsonContract.ValidateChildResult(json, new string('a', 32));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(documentKind));
        }
    }

    private static JsonObject Rect(double left, double top, double width, double height) => new()
    {
        ["Left"] = left,
        ["Top"] = top,
        ["Width"] = width,
        ["Height"] = height,
    };

    private static void AssertInvalid(Action action)
    {
        var error = Assert.Throws<InvalidDataException>(action);
        Assert.Equal("screenshot_json_contract_invalid", error.Message);
    }
}
