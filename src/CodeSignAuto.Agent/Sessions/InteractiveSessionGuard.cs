using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.Agent.Sessions;

public sealed class AgentStartupException : Exception
{
    public AgentStartupException(string code)
        : base(code)
    {
        Code = code;
    }

    public string Code { get; }
}

public sealed record InteractiveSessionState(
    int SessionId,
    string UserSid,
    bool HasInteractiveWindowStation);

public sealed record InteractiveSessionInfo(
    int SessionId,
    string UserSid,
    string UserSidSuffix);

public interface IInteractiveSessionSource
{
    InteractiveSessionState ReadCurrent();
}

public sealed class InteractiveSessionGuard
{
    private readonly IInteractiveSessionSource _source;

    public InteractiveSessionGuard()
        : this(new WindowsInteractiveSessionSource())
    {
    }

    public InteractiveSessionGuard(IInteractiveSessionSource source)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
    }

    public InteractiveSessionInfo ValidateCurrentProcess(string expectedUserSid)
    {
        if (!CanonicalWindowsSid.IsValid(expectedUserSid))
        {
            throw new AgentStartupException("agent_configuration_invalid");
        }

        var state = _source.ReadCurrent();
        if (state.SessionId <= 0)
        {
            throw new AgentStartupException("agent_session_zero");
        }

        if (!string.Equals(state.UserSid, expectedUserSid, StringComparison.Ordinal))
        {
            throw new AgentStartupException("agent_wrong_user");
        }

        if (!state.HasInteractiveWindowStation)
        {
            throw new AgentStartupException("agent_not_interactive");
        }

        return new InteractiveSessionInfo(
            state.SessionId,
            state.UserSid,
            state.UserSid[^Math.Min(4, state.UserSid.Length)..]);
    }

}

public sealed partial class WindowsInteractiveSessionSource : IInteractiveSessionSource
{
    public InteractiveSessionState ReadCurrent()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new AgentStartupException("agent_not_interactive");
        }

        return ReadWindows();
    }

    [SupportedOSPlatform("windows")]
    private static InteractiveSessionState ReadWindows()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            using var identity = WindowsIdentity.GetCurrent();
            var userSid = identity.User?.Value;
            if (string.IsNullOrEmpty(userSid))
            {
                throw new AgentStartupException("agent_not_interactive");
            }

            return new InteractiveSessionState(
                process.SessionId,
                userSid,
                HasInteractiveWindowStationAndDesktop());
        }
        catch (AgentStartupException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException
                or System.ComponentModel.Win32Exception
                or UnauthorizedAccessException)
        {
            throw new AgentStartupException("agent_not_interactive");
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool HasInteractiveWindowStationAndDesktop()
    {
        const int uoiFlags = 1;
        const uint wsfVisible = 0x0001;
        const uint desktopReadObjects = 0x0001;
        const uint desktopSwitchDesktop = 0x0100;

        var windowStation = GetProcessWindowStation();
        if (windowStation == nint.Zero)
        {
            return false;
        }

        var flagsSize = Marshal.SizeOf<UserObjectFlags>();
        var flagsBuffer = Marshal.AllocHGlobal(flagsSize);
        try
        {
            if (!GetUserObjectInformation(windowStation, uoiFlags, flagsBuffer, (uint)flagsSize, out _))
            {
                return false;
            }

            var flags = Marshal.PtrToStructure<UserObjectFlags>(flagsBuffer);
            if ((flags.Flags & wsfVisible) == 0)
            {
                return false;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(flagsBuffer);
        }

        var desktop = OpenInputDesktop(0, false, desktopReadObjects | desktopSwitchDesktop);
        if (desktop == nint.Zero)
        {
            return false;
        }

        return CloseDesktop(desktop);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserObjectFlags
    {
        public bool Inherit;
        public bool Reserved;
        public uint Flags;
    }

    [LibraryImport("user32.dll")]
    private static partial nint GetProcessWindowStation();

    [LibraryImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetUserObjectInformation(
        nint objectHandle,
        int index,
        nint information,
        uint length,
        out uint needed);

    [LibraryImport("user32.dll", SetLastError = true)]
    private static partial nint OpenInputDesktop(
        uint flags,
        [MarshalAs(UnmanagedType.Bool)] bool inherit,
        uint desiredAccess);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseDesktop(nint desktop);
}
