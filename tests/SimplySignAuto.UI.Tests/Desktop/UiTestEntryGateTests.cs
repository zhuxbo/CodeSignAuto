using SimplySignAuto.App;
using SimplySignAuto.App.UI.Testing;

namespace SimplySignAuto.UI.Tests.Desktop;

public sealed class UiTestEntryGateTests
{
    [Fact]
    public void Only_the_exact_two_argument_form_reaches_the_ui_test_route()
    {
        var accepted = ApplicationEntryRoute.Parse(["--ui-test-state", "ready"]);
        var caseVariant = ApplicationEntryRoute.Parse(["--ui-test-state", "Ready"]);
        var repeated = ApplicationEntryRoute.Parse([
            "--ui-test-state", "ready", "--ui-test-state", "partial",
        ]);

        Assert.Equal(ApplicationEntryKind.UiTest, accepted.Kind);
        Assert.Equal(["ready"], accepted.Arguments);
        Assert.Equal(ApplicationEntryKind.Invalid, caseVariant.Kind);
        Assert.Equal(ApplicationEntryKind.Invalid, repeated.Kind);
    }

    [Fact]
    public async Task Ordinary_release_arguments_are_rejected_before_test_composition_runs()
    {
        var executions = 0;
        var error = new StringWriter();

        var exitCode = await UiTestProgramGate.DispatchAsync(
            ["ready"],
            new Dictionary<string, string?>(StringComparer.Ordinal),
            8123,
            (_, _) =>
            {
                executions++;
                return Task.FromResult(0);
            },
            error,
            CancellationToken.None);

        Assert.Equal(2, exitCode);
        Assert.Equal(0, executions);
        Assert.Equal("invalid_arguments", error.ToString().Trim());
    }

    [Fact]
    public async Task Fully_bound_test_launch_runs_once_without_forwarding_permission_material()
    {
        var executions = 0;
        UiTestLaunchOptions? received = null;
        var environment = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [UiTestLaunchOptions.ModeEnvironmentVariable] = "1",
            [UiTestLaunchOptions.PipeEnvironmentVariable] = "SSA.UI.abcdefabcdefabcdefabcdefabcdefab",
            [UiTestLaunchOptions.NonceEnvironmentVariable] = new string('C', 64),
            [UiTestLaunchOptions.CultureEnvironmentVariable] = "en-US",
        };

        var exitCode = await UiTestProgramGate.DispatchAsync(
            ["ready"],
            environment,
            8123,
            (options, token) =>
            {
                token.ThrowIfCancellationRequested();
                executions++;
                received = options;
                return Task.FromResult(0);
            },
            TextWriter.Null,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(1, executions);
        Assert.NotNull(received);
        Assert.Equal("ready", received.State.Code);
        Assert.Equal("en-US", received.CultureName);
        Assert.DoesNotContain(received.Nonce, received.PipeName, StringComparison.Ordinal);
    }
}
