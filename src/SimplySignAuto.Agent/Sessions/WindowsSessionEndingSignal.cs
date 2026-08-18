using System.Runtime.InteropServices;

namespace SimplySignAuto.Agent.Sessions;

public sealed class WindowsSessionEndingSignal : IAgentSessionEndingSignal
{
    private const uint WmClose = 0x0010;
    private const uint WmQueryEndSession = 0x0011;
    private const uint WmEndSession = 0x0016;
    private const uint WmDestroy = 0x0002;

    private readonly Thread _messageThread;
    private readonly TaskCompletionSource<nint> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly WindowProcedure _windowProcedure;
    private nint _window;
    private bool _disposed;

    public WindowsSessionEndingSignal()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new AgentStartupException("agent_not_interactive");
        }

        _windowProcedure = HandleWindowMessage;
        _messageThread = new Thread(RunMessageLoop)
        {
            IsBackground = true,
            Name = "SimplySignAuto session-ending monitor",
        };
        _messageThread.Start();

        try
        {
            _window = _started.Task.GetAwaiter().GetResult();
        }
        catch
        {
            _messageThread.Join(TimeSpan.FromSeconds(5));
            throw new AgentStartupException("agent_shutdown_handler_failed");
        }
    }

    public event EventHandler? SessionEnding;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        var window = Interlocked.Exchange(ref _window, nint.Zero);
        if (window != nint.Zero)
        {
            _ = PostMessage(window, WmClose, nint.Zero, nint.Zero);
        }

        _messageThread.Join(TimeSpan.FromSeconds(5));
    }

    private void RunMessageLoop()
    {
        var instance = GetModuleHandle(null);
        var className = $"SimplySignAuto.SessionEnding.{Environment.ProcessId}.{Guid.NewGuid():N}";
        var windowClass = new WindowClass
        {
            WindowProcedure = Marshal.GetFunctionPointerForDelegate(_windowProcedure),
            Instance = instance,
            ClassName = className,
        };

        if (RegisterClass(ref windowClass) == 0)
        {
            _started.TrySetException(new InvalidOperationException());
            return;
        }

        try
        {
            var window = CreateWindowEx(
                0,
                className,
                string.Empty,
                0,
                0,
                0,
                0,
                0,
                nint.Zero,
                nint.Zero,
                instance,
                nint.Zero);
            if (window == nint.Zero)
            {
                _started.TrySetException(new InvalidOperationException());
                return;
            }

            _started.TrySetResult(window);
            while (GetMessage(out var message, nint.Zero, 0, 0) > 0)
            {
                _ = TranslateMessage(ref message);
                _ = DispatchMessage(ref message);
            }
        }
        finally
        {
            _ = UnregisterClass(className, instance);
        }
    }

    private nint HandleWindowMessage(nint window, uint message, nint wParam, nint lParam)
    {
        switch (message)
        {
            case WmQueryEndSession:
                SessionEnding?.Invoke(this, EventArgs.Empty);
                return new nint(1);
            case WmEndSession when wParam != nint.Zero:
                SessionEnding?.Invoke(this, EventArgs.Empty);
                return nint.Zero;
            case WmClose:
                _ = DestroyWindow(window);
                return nint.Zero;
            case WmDestroy:
                PostQuitMessage(0);
                return nint.Zero;
            default:
                return DefWindowProc(window, message, wParam, lParam);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate nint WindowProcedure(nint window, uint message, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WindowClass
    {
        public uint Style;
        public nint WindowProcedure;
        public int ClassExtraBytes;
        public int WindowExtraBytes;
        public nint Instance;
        public nint Icon;
        public nint Cursor;
        public nint BackgroundBrush;
        public string? MenuName;
        public string ClassName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Message
    {
        public nint Window;
        public uint Value;
        public nuint WParam;
        public nint LParam;
        public uint Time;
        public Point Point;
        public uint Private;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

#pragma warning disable SYSLIB1054
    [DllImport("user32.dll", EntryPoint = "RegisterClassW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClass(ref WindowClass windowClass);

    [DllImport("user32.dll", EntryPoint = "CreateWindowExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint CreateWindowEx(
        uint extendedStyle,
        string className,
        string windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        nint parent,
        nint menu,
        nint instance,
        nint parameter);

    [DllImport("user32.dll", EntryPoint = "GetMessageW", SetLastError = true)]
    private static extern int GetMessage(out Message message, nint window, uint minimum, uint maximum);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(ref Message message);

    [DllImport("user32.dll", EntryPoint = "DispatchMessageW")]
    private static extern nint DispatchMessage(ref Message message);

    [DllImport("user32.dll", EntryPoint = "DefWindowProcW")]
    private static extern nint DefWindowProc(nint window, uint message, nint wParam, nint lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(nint window);

    [DllImport("user32.dll", EntryPoint = "PostMessageW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(nint window, uint message, nint wParam, nint lParam);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int exitCode);

    [DllImport("user32.dll", EntryPoint = "UnregisterClassW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnregisterClass(string className, nint instance);

    [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint GetModuleHandle(string? moduleName);
#pragma warning restore SYSLIB1054
}
