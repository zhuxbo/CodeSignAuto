#if SIMPLYSIGN_WPF
namespace SimplySignAuto.UI.Tests.Desktop;

internal sealed class OpaqueWindowCover : IDisposable
{
    private readonly ManualResetEventSlim _ready = new(initialState: false);
    private readonly Thread _thread;
    private System.Windows.Forms.Form? _window;
    private Exception? _failure;
    private int _disposed;

    private OpaqueWindowCover(DesktopBounds bounds)
    {
        Bounds = bounds;
        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "SimplySignAuto screenshot covering window",
        };
        _thread.SetApartmentState(ApartmentState.STA);
    }

    private DesktopBounds Bounds { get; }

    public static OpaqueWindowCover Show(DesktopBounds bounds)
    {
        var cover = new OpaqueWindowCover(bounds);
        cover._thread.Start();
        if (!cover._ready.Wait(TimeSpan.FromSeconds(5)))
        {
            cover.Dispose();
            throw new Xunit.Sdk.XunitException("screenshot_overlay_start_timeout");
        }

        if (cover._failure is not null)
        {
            cover.Dispose();
            throw new Xunit.Sdk.XunitException($"screenshot_overlay_start_failed:{cover._failure.GetType().Name}");
        }

        return cover;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _window?.BeginInvoke(_window.Close);
        }
        catch (InvalidOperationException)
        {
        }

        Assert.True(_thread.Join(TimeSpan.FromSeconds(5)), "screenshot_overlay_stop_timeout");
    }

    private void Run()
    {
        try
        {
            using var window = new NoActivateCoverWindow
            {
                BackColor = System.Drawing.Color.Fuchsia,
                Bounds = new System.Drawing.Rectangle(
                    checked((int)Bounds.Left),
                    checked((int)Bounds.Top),
                    checked((int)Bounds.Width),
                    checked((int)Bounds.Height)),
                FormBorderStyle = System.Windows.Forms.FormBorderStyle.None,
                ShowInTaskbar = false,
                StartPosition = System.Windows.Forms.FormStartPosition.Manual,
                TopMost = true,
            };
            _window = window;
            window.Shown += (_, _) => _ready.Set();
            System.Windows.Forms.Application.Run(window);
        }
        catch (Exception error)
        {
            _failure = error;
            _ready.Set();
        }
        finally
        {
            _window = null;
        }
    }

    private sealed class NoActivateCoverWindow : System.Windows.Forms.Form
    {
        protected override bool ShowWithoutActivation => true;

        protected override System.Windows.Forms.CreateParams CreateParams
        {
            get
            {
                const int noActivate = 0x08000000;
                var parameters = base.CreateParams;
                parameters.ExStyle |= noActivate;
                return parameters;
            }
        }
    }
}
#endif
