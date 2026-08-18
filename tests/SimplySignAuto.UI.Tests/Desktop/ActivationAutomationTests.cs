#if SIMPLYSIGN_WPF
using System.Windows.Automation;

namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class ActivationAutomationTests
{
    private const string SyntheticUri =
        "otpauth://totp/Synthetic:ui?secret=JBSWY3DPEHPK3PXP&issuer=Synthetic&algorithm=SHA1&digits=6&period=30";

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Import_is_modal_focus_trapped_escape_clears_and_restores_launcher_focus()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.SelectNavigation("激活凭证");
        app.Invoke("导入 Certum 激活内容");
        var secret = app.WaitForElement("Certum 激活内容", ControlType.Edit, TimeSpan.FromSeconds(5));
        Assert.True(secret.Current.HasKeyboardFocus);
        ((ValuePattern)secret.GetCurrentPattern(ValuePattern.Pattern)).SetValue(SyntheticUri);

        app.SendEscape();

        Assert.Null(app.FindElement("Certum 激活内容", ControlType.Edit));
        Assert.True(app.FindElement("导入 Certum 激活内容", ControlType.Button)!.Current.HasKeyboardFocus);
        app.AssertAutomationTreeDoesNotContain(SyntheticUri);
        app.AssertAutomationTreeDoesNotContain("JBSWY3DPEHPK3PXP");
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.SelectNavigation("激活凭证");
        app.Invoke("导入 Certum 激活内容");
        app.SetValue("Certum 激活内容", SyntheticUri);
        app.Invoke("验证并保存 Certum 激活内容");
        Assert.NotNull(app.WaitForElement(
            "正在保存激活内容，完成前不能关闭此窗口。",
            ControlType.Text,
            TimeSpan.FromSeconds(2)));

        app.SendEscape();
        Assert.NotNull(app.FindElement("Certum 激活内容", ControlType.Edit));
        app.CloseVisibleWindow("导入 Certum 激活内容");
        Assert.NotNull(app.FindElement("Certum 激活内容", ControlType.Edit));
        app.Invoke("取消导入激活内容");
        Assert.NotNull(app.FindElement("Certum 激活内容", ControlType.Edit));

        app.WaitForElementToDisappear("Certum 激活内容", ControlType.Edit, TimeSpan.FromSeconds(5));

        app.AssertAutomationTreeDoesNotContain(SyntheticUri);
        app.AssertAutomationTreeDoesNotContain("JBSWY3DPEHPK3PXP");
        await app.CaptureWindowPngAsync(
            "activation-saved.png",
            nameof(Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret));
    }
}
#else
namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class ActivationAutomationTests
{
    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Import_is_modal_focus_trapped_escape_clears_and_restores_launcher_focus() { }

    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret() { }
}
#endif
