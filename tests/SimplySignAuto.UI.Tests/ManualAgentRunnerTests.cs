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

    [Fact]
    public async Task Manual_configuration_uses_only_the_validated_receipt_identity_and_shared_prerequisites()
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), $"manual-config-{Guid.NewGuid():N}"));
        var paths = ManualRuntimePaths.ForDataRoot(root);
        var receipt = new InstallationReceipt(
            InstallationReceipt.CurrentSchemaVersion,
            InstallationMode.Manual,
            "0123456789abcdef0123456789abcdef",
            "S-1-5-21-1000-2000-3000-4000",
            Path.GetFullPath(Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe")),
            root);
        var prerequisites = new SetupPreflightResult(
            Path.GetFullPath(Path.Combine(root, "SimplySignDesktop.exe")),
            Path.GetFullPath(Path.Combine(root, "SimplySignPKCS.dll")),
            Path.GetFullPath(Path.Combine(root, "signtool.exe")));

        var configuration = await new ManualAgentConfigurationLoader(
                receipt,
                paths,
                () => prerequisites)
            .LoadAsync(default);

        Assert.Equal(receipt.SigningUserSid, configuration.SigningUserSid);
        Assert.Equal(paths.SpoolPath, configuration.SpoolPath);
        Assert.Equal(prerequisites.SimplySignDesktopPath, configuration.SimplySignDesktopPath);
        Assert.Equal(prerequisites.Pkcs11ModulePath, configuration.Pkcs11ModulePath);
        Assert.Equal(prerequisites.SignToolPath, configuration.Authenticode!.SignToolPath);
        Assert.NotNull(configuration.Pdf);
    }
}
