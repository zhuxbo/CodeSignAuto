using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SimplySignAuto.UI.Tests.Desktop;

internal enum WtsConnectState
{
    Active = 0,
    Connected = 1,
    ConnectQuery = 2,
    Shadow = 3,
    Disconnected = 4,
    Idle = 5,
    Listen = 6,
    Reset = 7,
    Down = 8,
    Init = 9,
}

internal static class WindowsInteractiveSessionPolicy
{
    private const int WtsConnectStateInformationClass = 8;

    public static bool IsEligible(int sessionId, WtsConnectState state) =>
        sessionId > 0 && state == WtsConnectState.Active;

    public static bool TryGetCurrent(out int sessionId, out WtsConnectState state)
    {
        sessionId = 0;
        state = default;

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using Process process = Process.GetCurrentProcess();
        sessionId = process.SessionId;
        return TryGetState(sessionId, out state);
    }

    private static bool TryGetState(int sessionId, out WtsConnectState state)
    {
        state = default;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSQuerySessionInformationW(
                    IntPtr.Zero,
                    sessionId,
                    WtsConnectStateInformationClass,
                    out buffer,
                    out int bytesReturned)
                || buffer == IntPtr.Zero
                || bytesReturned < sizeof(int))
            {
                return false;
            }

            int rawState = Marshal.ReadInt32(buffer);
            if (!Enum.IsDefined(typeof(WtsConnectState), rawState))
            {
                return false;
            }

            state = (WtsConnectState)rawState;
            return true;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                WTSFreeMemory(buffer);
            }
        }
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(
        IntPtr serverHandle,
        int sessionId,
        int wtsInfoClass,
        out IntPtr buffer,
        out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
