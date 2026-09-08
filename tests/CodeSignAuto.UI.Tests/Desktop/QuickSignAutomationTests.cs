#if CODESIGNAUTO_WPF
using System.Windows.Automation;

namespace CodeSignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class QuickSignAutomationTests
{
    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Exe_and_pdf_selection_switch_controls_and_submit_without_changing_input()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.SelectNavigation("快速签名");
        var executable = app.CreateSyntheticExecutable();
        var original = await File.ReadAllBytesAsync(executable);

        app.ChooseFile(executable);
        Assert.NotNull(app.WaitForElement("代码签名", ControlType.Text, TimeSpan.FromSeconds(5)));
        Assert.Null(app.FindElement("PDF 签名页码", ControlType.Edit));
        app.Invoke("提交本机签名任务");
        Assert.NotNull(app.WaitForElement("签名任务", ControlType.Text, TimeSpan.FromSeconds(5)));
        Assert.Equal(original, await File.ReadAllBytesAsync(executable));

        app.SelectNavigation("快速签名");
        var pdf = app.CreateSyntheticPdf();
        app.ChooseFile(pdf);
        Assert.NotNull(app.WaitForElement("PDF 签名页码", ControlType.Edit, TimeSpan.FromSeconds(5)));
    }

}
#else
namespace CodeSignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class QuickSignAutomationTests
{
    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Exe_and_pdf_selection_switch_controls_and_submit_without_changing_input() { }

}
#endif
