using SimplySignAuto.UiAcceptance.StrictJson;

namespace SimplySignAuto.UI.Tests.Desktop;

public sealed class StrictJsonPreflightTests
{
    public static TheoryData<string> InvalidTokenDocuments => new()
    {
        "[]",
        "[{\"value\":1}]",
        "{\"value\":1,\"value\":2}",
        "{\"nested\":{\"value\":1,\"value\":2}}",
        "{\"runId\":1,\"run\\u0049d\":2}",
        "{\"value\":01}",
        "{\"value\":1.}",
        "{\"value\":1e}",
        "{\"value\":\"bad\\x\"}",
        "{\"value\":\"bad\\u12xz\"}",
        "{\"value\":\"bad\ncontrol\"}",
        "{\"value\":1} trailing",
        "{\"value\":1} {\"other\":2}",
    };

    [Fact]
    public void Complete_json_token_grammar_accepts_one_object_with_unique_ordinal_keys()
    {
        const string json =
            "{\"text\":\"A\\u0041\\/\\b\\f\\n\\r\\t\",\"Case\":1,\"case\":2,\"values\":[null,true,false,-1,0,1.25e+3,{\"nested\":\"ok\"}]}";

        Preflight.ValidateObject(json, maxDepth: 16, maxLength: 4096);
    }

    [Theory]
    [MemberData(nameof(InvalidTokenDocuments))]
    public void Invalid_root_duplicate_escape_number_control_trailing_and_multi_root_are_rejected(string json)
    {
        AssertInvalid(() => Preflight.ValidateObject(json, maxDepth: 16, maxLength: 4096));
    }

    [Fact]
    public void Depth_and_length_limits_fail_closed()
    {
        AssertInvalid(() => Preflight.ValidateObject(
            "{\"a\":{\"b\":{\"c\":1}}}",
            maxDepth: 2,
            maxLength: 4096));
        AssertInvalid(() => Preflight.ValidateObject(
            "{\"value\":1}",
            maxDepth: 16,
            maxLength: 4));
    }

    private static void AssertInvalid(Action action)
    {
        var error = Assert.Throws<FormatException>(action);
        Assert.Equal("ui_acceptance_json_invalid", error.Message);
    }
}
