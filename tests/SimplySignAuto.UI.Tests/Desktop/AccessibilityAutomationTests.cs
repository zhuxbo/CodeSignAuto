#if SIMPLYSIGN_WPF
using System.Globalization;
using System.Windows.Automation;
using SimplySignAuto.App.UI.Localization;

namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class AccessibilityAutomationTests
{
    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Every_interactive_element_has_a_stable_non_secret_name()
    {
        await using var app = await DesktopTestApp.StartAsync("token-missing");
        var settingsTitle = UiCulture.GetString(
            "ApplicationSettingsTitle",
            UiCulture.ResolveDefault(CultureInfo.CurrentUICulture));
        foreach (var page in new[] { "概览", "快速签名", "签名任务", "激活凭证", "服务设置", settingsTitle })
        {
            app.SelectNavigation(page);
            var controls = app.MainWindow.FindAll(
                TreeScope.Descendants,
                new OrCondition(
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem)));
            Assert.All(controls.Cast<AutomationElement>(), control =>
            {
                Assert.False(string.IsNullOrWhiteSpace(control.Current.Name));
                Assert.DoesNotContain("otpauth", control.Current.Name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("secret", control.Current.HelpText, StringComparison.OrdinalIgnoreCase);
            });
        }
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Keyboard_arrows_enter_space_tab_and_escape_drive_the_real_window()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.FocusNavigation();
        app.SendKeys("{DOWN}{DOWN}{ENTER}");
        Assert.NotNull(app.WaitForElement("签名任务", ControlType.Text, TimeSpan.FromSeconds(5)));
        app.SendKeys("+{TAB}{TAB}");
        app.SelectNavigation("激活凭证");
        app.FocusAndSend("导入 Certum 激活内容", " ");
        Assert.NotNull(app.WaitForElement("Certum 激活内容", ControlType.Edit, TimeSpan.FromSeconds(5)));
        app.SendEscape();
    }
}
#else
namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class AccessibilityAutomationTests
{
    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Every_interactive_element_has_a_stable_non_secret_name() { }

    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Keyboard_arrows_enter_space_tab_and_escape_drive_the_real_window() { }
}
#endif
