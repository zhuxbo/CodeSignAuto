using System.ComponentModel;
using System.Security.AccessControl;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;

namespace CodeSignAuto.App.Commands;

internal interface IWindowsInstallStartupRuntime
{
    Task StartAndVerifyServiceAsync(string name, CancellationToken cancellationToken);

    Task StopServiceAsync(string name, CancellationToken cancellationToken);

    bool HasInteractiveSession(string signingUserSid);

    bool IsOtpConfiguredForSigningUser(string path, string signingUserSid);

    Task StartAndVerifyTaskAsync(
        string name,
        bool requireRunning,
        CancellationToken cancellationToken);

    Task StopTaskAsync(string name, CancellationToken cancellationToken);
}

internal sealed class WindowsInstallStartupRuntime : IWindowsInstallStartupRuntime
{
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(30);
    private readonly IWindowsTaskLaunchOperations _taskOperations;
    private readonly WindowsActiveSessionLookup _sessions = new();

    public WindowsInstallStartupRuntime()
        : this(new WindowsTaskLaunchOperations(new DefaultWindowsCommandRunner()))
    {
    }

    internal WindowsInstallStartupRuntime(IWindowsTaskLaunchOperations taskOperations)
    {
        _taskOperations = taskOperations ?? throw new ArgumentNullException(nameof(taskOperations));
    }

    public Task StartAndVerifyServiceAsync(string name, CancellationToken cancellationToken) =>
        ChangeServiceStateAsync(name, ServiceControllerStatus.Running, cancellationToken);

    public Task StopServiceAsync(string name, CancellationToken cancellationToken) =>
        ChangeServiceStateAsync(name, ServiceControllerStatus.Stopped, cancellationToken);

    public bool HasInteractiveSession(string signingUserSid) =>
        _sessions.HasActiveSession(signingUserSid);

    public bool IsOtpConfiguredForSigningUser(string path, string signingUserSid) =>
        WindowsOtpMetadata.IsConfiguredForSigningUser(path, signingUserSid);

    public async Task StartAndVerifyTaskAsync(
        string name,
        bool requireRunning,
        CancellationToken cancellationToken)
    {
        var before = _taskOperations.ReadState(name);
        var runAttempted = false;
        try
        {
            runAttempted = true;
            await _taskOperations.RunAsync(name, cancellationToken).ConfigureAwait(false);
            await _taskOperations.WaitForTriggeredAsync(
                name,
                before,
                requireRunning,
                StartupTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception original) when (runAttempted)
        {
            try
            {
                await _taskOperations.StopAndWaitAsync(
                    name,
                    StartupTimeout,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                throw new InstallException("install_state_uncertain");
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            throw;
        }
    }

    public Task StopTaskAsync(string name, CancellationToken cancellationToken) =>
        _taskOperations.StopAndWaitAsync(name, StartupTimeout, cancellationToken);

    private static async Task ChangeServiceStateAsync(
        string name,
        ServiceControllerStatus expected,
        CancellationToken cancellationToken)
    {
        try
        {
            using var service = new ServiceController(name);
            service.Refresh();
            if (service.Status != expected)
            {
                if (expected == ServiceControllerStatus.Running)
                {
                    service.Start();
                }
                else
                {
                    service.Stop();
                }
            }

            var deadline = DateTimeOffset.UtcNow + StartupTimeout;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                service.Refresh();
                if (service.Status == expected)
                {
                    return;
                }

                if (DateTimeOffset.UtcNow >= deadline)
                {
                    throw new InstallException(expected == ServiceControllerStatus.Running
                        ? "service_start_failed"
                        : "service_stop_failed");
                }

                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is InvalidOperationException or Win32Exception or SystemException)
        {
            throw new InstallException(expected == ServiceControllerStatus.Running
                ? "service_start_failed"
                : "service_stop_failed");
        }
    }
}

internal interface IWindowsTaskLaunchOperations
{
    WindowsTaskRunState ReadState(string name);

    Task RunAsync(string name, CancellationToken cancellationToken);

    Task WaitForTriggeredAsync(
        string name,
        WindowsTaskRunState before,
        bool requireRunning,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task StopAndWaitAsync(
        string name,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

internal sealed class WindowsTaskLaunchOperations(
    IWindowsCommandRunner runner) : IWindowsTaskLaunchOperations
{
    public WindowsTaskRunState ReadState(string name) =>
        WindowsTaskStartupControl.ReadState(name);

    public async Task RunAsync(string name, CancellationToken cancellationToken)
    {
        _ = await runner.RunCheckedAsync(
            "schtasks.exe",
            ["/Run", "/TN", name],
            "agent_start_failed",
            cancellationToken).ConfigureAwait(false);
    }

    public Task WaitForTriggeredAsync(
        string name,
        WindowsTaskRunState before,
        bool requireRunning,
        TimeSpan timeout,
        CancellationToken cancellationToken) =>
        WindowsTaskStartupControl.WaitForTriggeredAsync(
            name,
            before,
            requireRunning,
            timeout,
            cancellationToken);

    public Task StopAndWaitAsync(
        string name,
        TimeSpan timeout,
        CancellationToken cancellationToken) =>
        WindowsScheduledTaskControl.StopAndWaitAsync(name, timeout, cancellationToken);
}

internal static class WindowsTaskStartupControl
{
    private const int RunningState = 4;

    public static WindowsTaskRunState ReadState(string name)
    {
        dynamic? service = null;
        dynamic? folder = null;
        dynamic? task = null;
        try
        {
            service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
            service.Connect();
            folder = service.GetFolder("\\");
            task = folder.GetTask(name);
            return new WindowsTaskRunState(
                (int)task.State == RunningState,
                (DateTime)task.LastRunTime);
        }
        catch
        {
            throw new InstallException("agent_start_failed");
        }
        finally
        {
            Release(task);
            Release(folder);
            Release(service);
        }
    }

    public static async Task WaitForTriggeredAsync(
        string name,
        WindowsTaskRunState before,
        bool requireRunning,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = ReadState(name);
            var triggered = before.Running || current.Running || current.LastRunTime > before.LastRunTime;
            if (triggered && (!requireRunning || current.Running))
            {
                return;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new InstallException("agent_start_failed");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void Release(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }
}

internal sealed record WindowsTaskRunState(bool Running, DateTime LastRunTime);

internal static class WindowsOtpMetadata
{
    public static bool IsConfiguredForSigningUser(string path, string signingUserSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        if (!WindowsPathSafety.EntryExists(path))
        {
            return false;
        }

        if (!File.Exists(path) || WindowsPathSafety.IsReparse(path))
        {
            return false;
        }

        try
        {
            var expectedUser = new SecurityIdentifier(signingUserSid);
            var expectedSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var security = new FileInfo(path).GetAccessControl();
            if (!security.AreAccessRulesProtected ||
                !string.Equals(
                    security.GetOwner(typeof(SecurityIdentifier))?.Value,
                    expectedUser.Value,
                    StringComparison.Ordinal))
            {
                return false;
            }

            var rules = security.GetAccessRules(
                    includeExplicit: true,
                    includeInherited: false,
                    typeof(SecurityIdentifier))
                .OfType<FileSystemAccessRule>()
                .ToArray();
            return rules.Length == 2 &&
                HasExactFullControl(rules, expectedUser) &&
                HasExactFullControl(rules, expectedSystem);
        }
        catch (Exception error) when (
            error is UnauthorizedAccessException or IOException or SystemException)
        {
            return false;
        }
    }

    private static bool HasExactFullControl(
        IReadOnlyList<FileSystemAccessRule> rules,
        SecurityIdentifier identity) => rules.Any(rule =>
            rule.IdentityReference.Equals(identity) &&
            rule.AccessControlType == AccessControlType.Allow &&
            rule.FileSystemRights == FileSystemRights.FullControl &&
            !rule.IsInherited);
}

internal sealed class WindowsActiveSessionLookup
{
    public bool HasActiveSession(string signingUserSid)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        return HasActiveWindowsSession(signingUserSid);
    }

    [SupportedOSPlatform("windows")]
    private static bool HasActiveWindowsSession(string signingUserSid)
    {
        if (!WTSEnumerateSessions(
                nint.Zero,
                0,
                1,
                out var sessions,
                out var count))
        {
            throw new InstallException("interactive_session_query_failed");
        }

        try
        {
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<WtsSessionInfo>(sessions + index * size);
                if (session.State != WtsConnectState.Active)
                {
                    continue;
                }

                var user = QuerySessionString(session.SessionId, WtsInfoClass.UserName);
                var domain = QuerySessionString(session.SessionId, WtsInfoClass.DomainName);
                if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(domain))
                {
                    continue;
                }

                try
                {
                    var sid = ((SecurityIdentifier)new NTAccount(domain, user)
                        .Translate(typeof(SecurityIdentifier))).Value;
                    if (string.Equals(sid, signingUserSid, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
                catch (IdentityNotMappedException)
                {
                }
            }

            return false;
        }
        finally
        {
            WTSFreeMemory(sessions);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string QuerySessionString(uint sessionId, WtsInfoClass informationClass)
    {
        if (!WTSQuerySessionInformation(
                nint.Zero,
                sessionId,
                informationClass,
                out var buffer,
                out _))
        {
            throw new InstallException("interactive_session_query_failed");
        }

        try
        {
            return Marshal.PtrToStringUni(buffer) ?? string.Empty;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private enum WtsConnectState
    {
        Active,
        Connected,
        ConnectQuery,
        Shadow,
        Disconnected,
        Idle,
        Listen,
        Reset,
        Down,
        Init,
    }

    private enum WtsInfoClass
    {
        InitialProgram,
        ApplicationName,
        WorkingDirectory,
        OemId,
        SessionId,
        UserName,
        WinStationName,
        DomainName,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public uint SessionId;
        public nint WinStationName;
        public WtsConnectState State;
    }

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessions(
        nint server,
        int reserved,
        int version,
        out nint sessions,
        out int count);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformation(
        nint server,
        uint sessionId,
        WtsInfoClass informationClass,
        out nint buffer,
        out uint bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(nint memory);
}
