using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.Manual;
using SimplySignAuto.Service.Ipc;
using Xunit;

namespace SimplySignAuto.UI.Tests;

public sealed class ManualAgentRunnerTests
{
    [Fact]
    public void Default_manual_paths_keep_database_spool_and_current_user_otp_under_one_user_root()
    {
        var expectedRoot = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SimplySignAuto",
            "manual"));

        var paths = ManualRuntimePaths.Default;

        Assert.Equal(expectedRoot, paths.DataRoot);
        Assert.Equal(Path.Combine(expectedRoot, "jobs.db"), paths.DatabasePath);
        Assert.Equal(Path.Combine(expectedRoot, "spool"), paths.SpoolPath);
        Assert.Equal(Path.Combine(expectedRoot, "otp.dat"), paths.OtpPath);
    }

    [Fact]
    public void Manual_runner_exposes_existing_desktop_contracts_without_becoming_a_pipe_runtime()
    {
        var runner = new ManualAgentRunner();

        Assert.IsAssignableFrom<IAgentRunner>(runner);
        Assert.IsAssignableFrom<IDesktopAgentRunner>(runner);
        Assert.IsAssignableFrom<IDesktopManagementSource>(runner);
        Assert.IsAssignableFrom<IDesktopLocalJobSource>(runner);
        Assert.IsAssignableFrom<IAgentAdministrationClient>(runner.Management);
        Assert.Same(runner.Management, runner.LocalJobs);
        Assert.DoesNotContain(
            typeof(IAgentPipeRuntime),
            typeof(InProcessSigningTransport).GetInterfaces());
    }
}
