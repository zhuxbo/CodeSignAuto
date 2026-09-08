using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace CodeSignAuto.App.Commands;

internal enum WindowsServiceRecoveryActionType : uint
{
    None = 0,
    Restart = 1,
    Reboot = 2,
    RunCommand = 3,
}

internal sealed record WindowsServiceRecoveryAction(
    WindowsServiceRecoveryActionType Type,
    uint DelayMilliseconds);

internal sealed record WindowsServiceRecoverySettings(
    uint ResetPeriodSeconds,
    IReadOnlyList<WindowsServiceRecoveryAction> Actions,
    bool ApplyToNonCrashFailures);

internal static class WindowsServiceRecoveryContract
{
    public static bool IsExact(
        WindowsServiceRecoverySettings actual,
        IReadOnlyList<int> expectedRestartDelaysSeconds)
    {
        ArgumentNullException.ThrowIfNull(actual);
        ArgumentNullException.ThrowIfNull(expectedRestartDelaysSeconds);
        if (actual.ResetPeriodSeconds != 86400 ||
            !actual.ApplyToNonCrashFailures ||
            actual.Actions.Count != expectedRestartDelaysSeconds.Count)
        {
            return false;
        }

        for (var index = 0; index < actual.Actions.Count; index++)
        {
            var expectedSeconds = expectedRestartDelaysSeconds[index];
            if (expectedSeconds < 0 || expectedSeconds > uint.MaxValue / 1000 ||
                actual.Actions[index] is not
                {
                    Type: WindowsServiceRecoveryActionType.Restart,
                    DelayMilliseconds: var actualDelay,
                } ||
                actualDelay != (uint)expectedSeconds * 1000)
            {
                return false;
            }
        }

        return true;
    }
}

internal interface IWindowsServiceRecoveryInspector
{
    WindowsServiceRecoverySettings Read(string serviceName);
}

internal sealed class WindowsServiceRecoveryInspector : IWindowsServiceRecoveryInspector
{
    public WindowsServiceRecoverySettings Read(string serviceName)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        return ReadWindows(serviceName);
    }

    [SupportedOSPlatform("windows")]
    private static WindowsServiceRecoverySettings ReadWindows(string serviceName)
    {
        nint manager = nint.Zero;
        nint service = nint.Zero;
        try
        {
            manager = OpenSCManager(null, null, ServiceManagerConnect);
            if (manager == nint.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            service = OpenService(manager, serviceName, ServiceQueryConfig);
            if (service == nint.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var actions = ReadFailureActions(service);
            var nonCrash = ReadNonCrashFailureFlag(service);
            return new WindowsServiceRecoverySettings(
                actions.ResetPeriodSeconds,
                actions.Actions,
                nonCrash);
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (
            error is Win32Exception or ArgumentException or OverflowException or SystemException)
        {
            throw new InstallException("service_registration_failed");
        }
        finally
        {
            if (service != nint.Zero)
            {
                _ = CloseServiceHandle(service);
            }

            if (manager != nint.Zero)
            {
                _ = CloseServiceHandle(manager);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static WindowsServiceRecoverySettings ReadFailureActions(nint service)
    {
        var buffer = QueryBuffer(service, ServiceConfigFailureActions);
        try
        {
            var native = Marshal.PtrToStructure<ServiceFailureActions>(buffer);
            if (native.ActionCount > MaximumActions ||
                (native.ActionCount > 0 && native.Actions == nint.Zero))
            {
                throw new InstallException("service_registration_failed");
            }

            var actionSize = Marshal.SizeOf<ServiceAction>();
            var actions = new WindowsServiceRecoveryAction[native.ActionCount];
            for (var index = 0; index < actions.Length; index++)
            {
                var action = Marshal.PtrToStructure<ServiceAction>(
                    native.Actions + checked(index * actionSize));
                actions[index] = new WindowsServiceRecoveryAction(action.Type, action.DelayMilliseconds);
            }

            return new WindowsServiceRecoverySettings(
                native.ResetPeriodSeconds,
                actions,
                ApplyToNonCrashFailures: false);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool ReadNonCrashFailureFlag(nint service)
    {
        var buffer = QueryBuffer(service, ServiceConfigFailureActionsFlag);
        try
        {
            return Marshal.ReadInt32(buffer) != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static nint QueryBuffer(nint service, uint informationLevel)
    {
        _ = QueryServiceConfig2(service, informationLevel, nint.Zero, 0, out var required);
        if (required == 0 || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var buffer = Marshal.AllocHGlobal(checked((int)required));
        if (!QueryServiceConfig2(service, informationLevel, buffer, required, out _))
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            Marshal.FreeHGlobal(buffer);
            throw error;
        }

        return buffer;
    }

    private const uint ServiceManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceConfigFailureActions = 2;
    private const uint ServiceConfigFailureActionsFlag = 4;
    private const int ErrorInsufficientBuffer = 122;
    private const uint MaximumActions = 32;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceFailureActions
    {
        public uint ResetPeriodSeconds;
        public nint RebootMessage;
        public nint Command;
        public uint ActionCount;
        public nint Actions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceAction
    {
        public WindowsServiceRecoveryActionType Type;
        public uint DelayMilliseconds;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint OpenService(nint manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2(
        nint service,
        uint informationLevel,
        nint buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint service);
}
