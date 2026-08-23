using System.Globalization;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Localization;

namespace SimplySignAuto.UI.Tests;

public sealed class UninstallPresentationTests
{
    [Theory]
    [InlineData(
        "zh-CN",
        InstallationMode.Manual,
        "将安全移除 SimplySignAuto 主程序及其拥有的系统配置。任务历史和已签名结果将保留。")]
    [InlineData(
        "en-US",
        InstallationMode.Manual,
        "Safely removes SimplySignAuto and its owned system configuration. Job history and signed results will be preserved.")]
    [InlineData(
        "zh-CN",
        InstallationMode.Service,
        "将安全移除 SimplySignAuto 主程序、其拥有的系统配置及受控数据，包括任务历史和已签名结果。")]
    [InlineData(
        "en-US",
        InstallationMode.Service,
        "Safely removes SimplySignAuto, its owned system configuration, and controlled data, including job history and signed results.")]
    public void Main_uninstall_description_matches_the_installed_data_policy(
        string cultureName,
        InstallationMode mode,
        string expected)
    {
        var culture = UiCulture.ResolveSelection(cultureName);

        Assert.Equal(
            expected,
            UninstallPresentation.DescribeProduct(
                GraphicalUninstallProduct.Main,
                mode,
                culture));
    }

    [Fact]
    public void Unknown_main_installation_mode_uses_the_conservative_service_description()
    {
        var culture = UiCulture.ResolveSelection("zh-CN");

        Assert.Contains(
            "受控数据",
            UninstallPresentation.DescribeProduct(
                GraphicalUninstallProduct.Main,
                mode: null,
                culture),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Main_uninstall_requires_restart_but_the_PDF_extension_does_not()
    {
        Assert.True(UninstallPresentation.RequiresRestart(GraphicalUninstallProduct.Main));
        Assert.False(UninstallPresentation.RequiresRestart(GraphicalUninstallProduct.PdfExtension));
    }

    [Fact]
    public void Closing_the_uninstall_form_before_starting_returns_a_nonzero_exit_code()
    {
        RunInSta(() =>
        {
            using var form = new UninstallForm(
                GraphicalUninstallProduct.Main,
                UiCulture.ResolveSelection("zh-CN"),
                InstallationMode.Manual,
                static (_, _, _) => Task.FromResult(0),
                CancellationToken.None);

            Assert.NotEqual(0, form.ExitCode);
        });
    }

    [Theory]
    [InlineData("zh-CN", "uninstall_busy", "另一个安装或卸载操作正在进行，请稍后重试。\n\n错误代码：uninstall_busy")]
    [InlineData("en-US", "uninstall_busy", "Another install or uninstall operation is in progress. Try again later.\n\nError code: uninstall_busy")]
    [InlineData("zh-CN", "owned_resource_mismatch", "安装状态已发生变化，无法安全卸载。请重新安装当前版本后再试。\n\n错误代码：owned_resource_mismatch")]
    [InlineData("en-US", "owned_resource_mismatch", "The installation state changed and cannot be removed safely. Reinstall the current version, then try again.\n\nError code: owned_resource_mismatch")]
    public void Known_uninstall_failures_are_localized_and_keep_the_stable_code(
        string cultureName,
        string code,
        string expected)
    {
        var culture = UiCulture.ResolveSelection(cultureName);

        Assert.Equal(
            expected.Replace("\n", Environment.NewLine, StringComparison.Ordinal),
            UninstallPresentation.DescribeFailure(code, culture));
    }

    [Theory]
    [InlineData("")]
    [InlineData("uninstall_failed\nexception details")]
    [InlineData("not allowed!")]
    public void Untrusted_failure_output_is_replaced_with_the_generic_stable_code(string output)
    {
        Assert.Equal("uninstall_failed", UninstallPresentation.NormalizeFailureCode(output));
    }

    private static void RunInSta(Action action)
    {
        Exception? failure = null;
        using var finished = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception error)
            {
                failure = error;
            }
            finally
            {
                finished.Set();
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(finished.Wait(TimeSpan.FromSeconds(10)));
        thread.Join();
        if (failure is not null)
        {
            throw failure;
        }
    }
}
