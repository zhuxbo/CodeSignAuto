#if SIMPLYSIGN_WPF
using System.Windows.Automation;

namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class ExternalScenarioAutomationTests
{
    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Overview_exposes_busy_state_and_opens_the_real_jobs_page()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.WaitForElementEnabled("退出", enabled: true, TimeSpan.FromSeconds(5));

        app.Invoke("退出");

        app.WaitForElementEnabled("退出", enabled: false, TimeSpan.FromSeconds(2));
        await app.CaptureWindowPngAsync(
            "overview-busy.png",
            nameof(Overview_exposes_busy_state_and_opens_the_real_jobs_page));
        app.Invoke("打开签名任务页面");
        Assert.NotNull(app.WaitForElement("签名任务", ControlType.Text, TimeSpan.FromSeconds(5)));
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.SelectNavigation("签名任务");
        var firstPage = app.WaitForJobFileNames(100, TimeSpan.FromSeconds(10));

        Assert.Equal("active.exe", firstPage[0]);
        Assert.False(app.RowButtonIsEnabled("active.exe", "保存签名结果副本"));
        Assert.False(app.RowButtonIsEnabled("failed.exe", "保存签名结果副本"));
        Assert.False(app.RowButtonIsEnabled("expired.exe", "保存签名结果副本"));
        Assert.True(app.RowButtonIsEnabled("document-003.pdf", "保存签名结果副本"));

        app.Invoke("加载更多签名任务");
        var all = app.WaitForJobFileNames(101, TimeSpan.FromSeconds(10));
        Assert.Equal("active.exe", all[0]);
        Assert.Contains("software-100.exe", all);
        await app.CaptureWindowPngAsync(
            "jobs-loaded.png",
            nameof(Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy));
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Quick_sign_exposes_finalizing_before_opening_jobs()
    {
        await using var app = await DesktopTestApp.StartAsync("ready");
        app.SelectNavigation("快速签名");
        app.ChooseFile(app.CreateSyntheticExecutable());

        app.Invoke("提交本机签名任务");

        Assert.NotNull(app.WaitForElement("正在完成本机提交", ControlType.Text, TimeSpan.FromSeconds(3)));
        await app.CaptureWindowPngAsync(
            "quick-finalizing.png",
            nameof(Quick_sign_exposes_finalizing_before_opening_jobs));
        Assert.NotNull(app.WaitForElement("签名任务", ControlType.Text, TimeSpan.FromSeconds(5)));
    }

    [WindowsDesktopFact]
    [Trait("Category", "Desktop")]
    public async Task Actual_tray_exit_exits_safe_state_and_refuses_active_and_unknown()
    {
        using var squatter = ProductionLikeTraySquatter.Start();
        await using (var ready = await DesktopTestApp.StartAsync("ready"))
        {
            Assert.NotEqual(ready.TrayIdentity, squatter.Tooltip);
            Assert.NotNull(ready.WaitForElement("正在运行（会话 1）", ControlType.Text, TimeSpan.FromSeconds(5)));
            ready.InvokeTrayExit();
            ready.WaitForProcessExit(TimeSpan.FromSeconds(8));
            Assert.Equal(0, squatter.ExitClicks);
            Assert.True(squatter.IsVisible);
        }

        await using (var active = await DesktopTestApp.StartAsync("active-job"))
        {
            Assert.NotNull(active.WaitForElement(
                "代码签名 · 正在签名 · 已运行 10 秒",
                ControlType.Text,
                TimeSpan.FromSeconds(5)));
            active.InvokeTrayExit();
            active.DismissNotice("有签名任务正在执行，管理程序将继续运行。");
            Assert.False(active.Process.HasExited);
        }

        await using (var unknown = await DesktopTestApp.StartAsync("unknown"))
        {
            unknown.InvokeTrayExit();
            unknown.DismissNotice("暂时无法确认是否有签名任务，管理程序将继续运行。");
            Assert.False(unknown.Process.HasExited);
        }
    }

    private sealed class ProductionLikeTraySquatter : IDisposable
    {
        private readonly ManualResetEventSlim _ready = new(initialState: false);
        private readonly Thread _thread;
        private System.Windows.Forms.Control? _dispatcher;
        private System.Windows.Forms.ApplicationContext? _context;
        private Exception? _failure;
        private int _exitClicks;
        private int _visible;
        private int _disposed;

        private ProductionLikeTraySquatter()
        {
            _thread = new Thread(Run)
            {
                IsBackground = true,
                Name = "SimplySignAuto production-like tray squatter",
            };
            _thread.SetApartmentState(ApartmentState.STA);
        }

        public string Tooltip { get; } = "SimplySignAuto - production-like squatter";

        public int ExitClicks => Volatile.Read(ref _exitClicks);

        public bool IsVisible => Volatile.Read(ref _visible) != 0;

        public static ProductionLikeTraySquatter Start()
        {
            var squatter = new ProductionLikeTraySquatter();
            squatter._thread.Start();
            if (!squatter._ready.Wait(TimeSpan.FromSeconds(5)))
            {
                squatter.Dispose();
                throw new Xunit.Sdk.XunitException("ui_tray_squatter_start_timeout");
            }

            if (squatter._failure is not null)
            {
                squatter.Dispose();
                throw new Xunit.Sdk.XunitException($"ui_tray_squatter_start_failed:{squatter._failure.GetType().Name}");
            }

            return squatter;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                _dispatcher?.BeginInvoke(() => _context?.ExitThread());
            }
            catch (InvalidOperationException)
            {
            }

            Assert.True(_thread.Join(TimeSpan.FromSeconds(5)), "ui_tray_squatter_stop_timeout");
        }

        private void Run()
        {
            try
            {
                _dispatcher = new System.Windows.Forms.Control();
                _ = _dispatcher.Handle;
                _context = new System.Windows.Forms.ApplicationContext();
                using var menu = new System.Windows.Forms.ContextMenuStrip();
                var exit = new System.Windows.Forms.ToolStripMenuItem("退出程序");
                exit.Click += (_, _) => Interlocked.Increment(ref _exitClicks);
                menu.Items.Add(exit);
                using var icon = new System.Windows.Forms.NotifyIcon
                {
                    ContextMenuStrip = menu,
                    Icon = System.Drawing.SystemIcons.Application,
                    Text = Tooltip,
                    Visible = true,
                };
                Volatile.Write(ref _visible, 1);
                _ready.Set();
                System.Windows.Forms.Application.Run(_context);
                icon.Visible = false;
                Volatile.Write(ref _visible, 0);
            }
            catch (Exception error)
            {
                _failure = error;
                _ready.Set();
            }
            finally
            {
                _dispatcher?.Dispose();
            }
        }
    }
}
#else
namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class ExternalScenarioAutomationTests
{
    [Fact(Skip = "Requires real WPF UI Automation in a WTS Active non-zero Windows session.")]
    public void Overview_exposes_busy_state_and_opens_the_real_jobs_page() { }

    [Fact(Skip = "Requires real WPF UI Automation in a WTS Active non-zero Windows session.")]
    public void Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy() { }

    [Fact(Skip = "Requires real WPF UI Automation in a WTS Active non-zero Windows session.")]
    public void Quick_sign_exposes_finalizing_before_opening_jobs() { }

    [Fact(Skip = "Requires real WPF UI Automation in a WTS Active non-zero Windows session.")]
    public void Actual_tray_exit_exits_safe_state_and_refuses_active_and_unknown() { }
}
#endif
