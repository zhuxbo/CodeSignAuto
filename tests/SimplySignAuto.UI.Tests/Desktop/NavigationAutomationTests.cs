#if SIMPLYSIGN_WPF
using System.Windows.Automation;

namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class NavigationAutomationTests
{
    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Five_pages_have_fixed_unique_names_and_real_selection_navigation()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        string[] expected = ["概览", "快速签名", "签名任务", "激活凭证", "服务设置"];

        Assert.Equal(expected, app.NavigationNames());
        foreach (var name in expected)
        {
            app.SelectNavigation(name);
            Assert.NotNull(app.WaitForElement(name, ControlType.Text, TimeSpan.FromSeconds(5)));
        }
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Overview_logout_and_close_hide_keep_fake_heartbeat_alive()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.Invoke("退出");
        app.CloseWindow();

        await app.Host.HeartbeatReceived.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(app.Process.HasExited);
        Assert.True(app.MainWindow.Current.IsOffscreen);
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Active_state_disables_relogin_and_settings_open_the_owned_editor()
    {
        await using var active = await DesktopTestApp.StartAsync("active-job");
        var login = active.FindElement("退出", ControlType.Button);
        Assert.NotNull(login);
        Assert.False(login.Current.IsEnabled);

        await using var ready = await DesktopTestApp.StartAsync("ready");
        ready.SelectNavigation("服务设置");
        ready.Invoke("修改");
        Assert.NotNull(ready.WaitForElement("服务监听端口", ControlType.Edit, TimeSpan.FromSeconds(5)));
        ready.Invoke("关闭服务设置修改");
        Assert.Null(ready.FindElement("服务监听端口", ControlType.Edit));
        Assert.False(ready.Process.HasExited);
    }
}
#else
namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class NavigationAutomationTests
{
    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Five_pages_have_fixed_unique_names_and_real_selection_navigation() { }

    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Overview_logout_and_close_hide_keep_fake_heartbeat_alive() { }

    [Fact(Skip = "Requires real WPF UI Automation in a non-zero Windows session.")]
    public void Active_state_disables_relogin_and_settings_open_the_owned_editor() { }
}
#endif
