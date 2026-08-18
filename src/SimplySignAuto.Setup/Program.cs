namespace SimplySignAuto.Setup;

internal static class SetupCommandLine
{
    public static void Validate(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count != 0)
        {
            throw new SetupBootstrapperException("setup_arguments_invalid");
        }
    }
}

internal static class Program
{
    [STAThread]
    private static int Main(string[] arguments)
    {
        try
        {
            SetupCommandLine.Validate(arguments);
        }
        catch (SetupBootstrapperException error)
        {
            MessageBox.Show(error.Code, "SimplySignAuto 安装", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 2;
        }

        ApplicationConfiguration.Initialize();
        try
        {
            var powerShell = SetupPowerShell.ResolveSystemPath();
            var payloadSource = new EmbeddedSetupPayloadSource();
            var productKind = SetupPayloadMetadataCodec.Decode(
                payloadSource.ReadMetadata()).ProductKind;
            var operations = new SetupBootstrapperOperations(
                payloadSource,
                new WindowsSetupPublisherVerifier(powerShell),
                new WindowsSetupWorkspace(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
                new WindowsSetupProcessRunner(
                    powerShell,
                    new PowerShellSetupProcessInvoker(),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
            using var form = new SetupForm(new SetupBootstrapper(operations), productKind);
            Application.Run(form);
            return form.ExitCode;
        }
        catch (SetupBootstrapperException error)
        {
            MessageBox.Show(error.Code, "SimplySignAuto 安装", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        catch
        {
            MessageBox.Show("setup_failed", "SimplySignAuto 安装", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
