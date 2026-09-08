using CodeSignAuto.App.UI.Testing;

namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class UiTestModePolicyTests
{
    private static readonly IReadOnlyDictionary<string, string?> ValidEnvironment =
        new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [UiTestLaunchOptions.ModeEnvironmentVariable] = "1",
            [UiTestLaunchOptions.PipeEnvironmentVariable] = "SSA.UI.0123456789abcdef0123456789abcdef",
            [UiTestLaunchOptions.NonceEnvironmentVariable] = new string('A', 64),
            [UiTestLaunchOptions.CultureEnvironmentVariable] = "zh-CN",
        };

    [Theory]
    [InlineData("ready")]
    [InlineData("partial")]
    [InlineData("session0")]
    [InlineData("token-missing")]
    [InlineData("active-job")]
    [InlineData("job-failed")]
    public void Exact_state_and_private_launch_contract_are_accepted(string state)
    {
        var result = UiTestLaunchOptions.Parse(["--ui-test-state", state], ValidEnvironment, 4123);

        Assert.True(result.IsAccepted);
        Assert.Equal(state, result.Options!.State.Code);
        Assert.Equal(4123, result.Options.ProcessId);
        Assert.Equal("zh-CN", result.Options.CultureName);
        Assert.DoesNotContain("CodeSignAuto.Agent.v1", result.Options.PipeName, StringComparison.Ordinal);
        Assert.DoesNotContain("CodeSignAuto.Activation", result.Options.PipeName, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_permission_or_non_exact_arguments_fail_closed()
    {
        (string[] Arguments, IReadOnlyDictionary<string, string?> Environment)[] rejectedLaunches =
        [
            (["--ui-test-state", "Ready"], ValidEnvironment),
            (["--ui-test-state", "ready", "extra"], ValidEnvironment),
            (["--ui-test-state", "ready", "--ui-test-state", "partial"], ValidEnvironment),
            (["--UI-TEST-STATE", "ready"], ValidEnvironment),
            (["--ui-test-state", "ready"], Without(UiTestLaunchOptions.ModeEnvironmentVariable)),
            (["--ui-test-state", "ready"], With(UiTestLaunchOptions.ModeEnvironmentVariable, "true")),
            (["--ui-test-state", "ready"], With(UiTestLaunchOptions.PipeEnvironmentVariable, "CodeSignAuto.Agent.v1")),
            (["--ui-test-state", "ready"], With(UiTestLaunchOptions.PipeEnvironmentVariable, "C:\\secret\\pipe")),
            (["--ui-test-state", "ready"], With(UiTestLaunchOptions.NonceEnvironmentVariable, new string('A', 63))),
            (["--ui-test-state", "ready"], Without(UiTestLaunchOptions.CultureEnvironmentVariable)),
            (["--ui-test-state", "ready"], With(UiTestLaunchOptions.CultureEnvironmentVariable, "en-us")),
            (["--ui-test-state", "ready"], With(UiTestLaunchOptions.CultureEnvironmentVariable, "fr-FR")),
        ];
        foreach (var (arguments, environment) in rejectedLaunches)
        {
            var result = UiTestLaunchOptions.Parse(arguments, environment, 4123);

            Assert.False(result.IsAccepted);
            Assert.Null(result.Options);
            Assert.Equal("invalid_arguments", result.ErrorCode);
        }
    }

    [Fact]
    public void Handshake_is_bound_to_exact_nonce_state_and_positive_child_pid()
    {
        var options = UiTestLaunchOptions.Parse(["--ui-test-state", "partial"], ValidEnvironment, 4123).Options!;

        var handshake = UiTestHandshake.Create(options);

        Assert.Equal(1, handshake.SchemaVersion);
        Assert.Equal("partial", handshake.State);
        Assert.Equal(4123, handshake.ProcessId);
        Assert.Equal(new string('A', 64), handshake.Nonce);
        Assert.True(handshake.IsValidFor(options));
        Assert.False(handshake with { ProcessId = 4124 } is { } wrongPid && wrongPid.IsValidFor(options));
        Assert.False(handshake with { Nonce = new string('B', 64) } is { } wrongNonce && wrongNonce.IsValidFor(options));
    }

    [Fact]
    public void Tray_identity_is_exact_per_process_and_random_private_run()
    {
        var first = UiTestTrayIdentity.Create(4123, "SSA.UI.0123456789abcdef0123456789abcdef");
        var second = UiTestTrayIdentity.Create(4123, "SSA.UI.fedcba9876543210fedcba9876543210");

        Assert.Equal("SSA-UI-TEST:4123:0123456789abcdef0123456789abcdef", first);
        Assert.NotEqual(first, second);
        Assert.False(first.StartsWith("CodeSignAuto -", StringComparison.Ordinal));
        Assert.InRange(first.Length, 1, 63);
    }

    [Theory]
    [InlineData(0, "SSA.UI.0123456789abcdef0123456789abcdef")]
    [InlineData(4123, "CodeSignAuto - ready")]
    [InlineData(4123, "SSA.UI.0123456789abcdef0123456789abcdeg")]
    public void Tray_identity_rejects_non_private_inputs(int processId, string pipeName)
    {
        Assert.ThrowsAny<ArgumentException>(() => UiTestTrayIdentity.Create(processId, pipeName));
    }

    private static IReadOnlyDictionary<string, string?> Without(string key) =>
        ValidEnvironment.Where(item => item.Key != key)
            .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);

    private static IReadOnlyDictionary<string, string?> With(string key, string? value)
    {
        var result = ValidEnvironment.ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
        result[key] = value;
        return result;
    }
}
