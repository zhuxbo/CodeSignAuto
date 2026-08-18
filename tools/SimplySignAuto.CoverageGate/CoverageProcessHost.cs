using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SimplySignAuto.Coverage;

internal sealed record CoverageProcessHostRequest(
    string Executable,
    string WorkingDirectory,
    string[] Arguments,
    int DrainTimeoutMilliseconds);

internal sealed record CoverageProcessHostResult(
    int ExitCode,
    bool DrainTimedOut,
    bool StartFailed);

internal static partial class CoverageProcessHost
{
    public static async Task<int> RunAsync(
        string requestPath,
        string startPath,
        string resultPath)
    {
        try
        {
            EstablishUnixProcessGroup();
            var request = JsonSerializer.Deserialize<CoverageProcessHostRequest>(
                await File.ReadAllTextAsync(requestPath).ConfigureAwait(false)) ??
                throw new InvalidOperationException("coverage_host_request_invalid");
            if (string.IsNullOrWhiteSpace(request.Executable) ||
                string.IsNullOrWhiteSpace(request.WorkingDirectory) ||
                request.Arguments is null || request.DrainTimeoutMilliseconds <= 0)
            {
                throw new InvalidOperationException("coverage_host_request_invalid");
            }

            using var startDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (!File.Exists(startPath))
            {
                await Task.Delay(10, startDeadline.Token).ConfigureAwait(false);
            }

            var start = new ProcessStartInfo
            {
                FileName = request.Executable,
                WorkingDirectory = request.WorkingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            start.Environment["DOTNET_NOLOGO"] = "1";
            foreach (var argument in request.Arguments)
            {
                start.ArgumentList.Add(argument);
            }

            using var process = new Process { StartInfo = start };
            if (!process.Start())
            {
                WriteResult(resultPath, new CoverageProcessHostResult(-1, false, true));
                await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
                return 2;
            }

            var stdout = process.StandardOutput.BaseStream.CopyToAsync(Console.OpenStandardOutput());
            var stderr = process.StandardError.BaseStream.CopyToAsync(Console.OpenStandardError());
            await process.WaitForExitAsync().ConfigureAwait(false);
            var drain = Task.WhenAll(stdout, stderr);
            var drainTimeout = Task.Delay(request.DrainTimeoutMilliseconds);
            var drainTimedOut = await Task.WhenAny(drain, drainTimeout).ConfigureAwait(false) != drain;
            if (!drainTimedOut)
            {
                await drain.ConfigureAwait(false);
                await Console.OpenStandardOutput().FlushAsync().ConfigureAwait(false);
                await Console.OpenStandardError().FlushAsync().ConfigureAwait(false);
            }

            WriteResult(
                resultPath,
                new CoverageProcessHostResult(process.ExitCode, drainTimedOut, false));
            await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
            return 0;
        }
        catch
        {
            try
            {
                WriteResult(resultPath, new CoverageProcessHostResult(-1, false, true));
                await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
            }
            catch
            {
            }

            return 2;
        }
    }

    private static void WriteResult(string path, CoverageProcessHostResult result)
    {
        var candidate = path + ".part";
        try
        {
            using (var stream = new FileStream(candidate, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            {
                JsonSerializer.Serialize(stream, result);
                stream.Flush(flushToDisk: true);
            }

            File.Move(candidate, path);
        }
        finally
        {
            try
            {
                File.Delete(candidate);
            }
            catch
            {
                // The process owner will remove the controlled run root after a failed publication.
            }
        }
    }

    private static void EstablishUnixProcessGroup()
    {
        if (!OperatingSystem.IsWindows() && setpgid(0, 0) != 0)
        {
            throw new InvalidOperationException("coverage_host_group_failed");
        }
    }

    internal static void KillUnixProcessGroup(int processId)
    {
        if (!OperatingSystem.IsWindows() && kill(-processId, 9) != 0)
        {
            var error = Marshal.GetLastPInvokeError();
            if (error != 3)
            {
                throw new InvalidOperationException("coverage_host_group_kill_failed");
            }
        }
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int setpgid(int processId, int processGroupId);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int kill(int processId, int signal);
}

internal sealed partial class CoverageProcessContainment : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private readonly Process _process;
    private SafeFileHandle? _job;

    public CoverageProcessContainment(Process process)
    {
        _process = process;
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        _job = CreateJobObject(IntPtr.Zero, null);
        if (_job.IsInvalid)
        {
            _job.Dispose();
            _job = null;
            throw new CoverageGateException("coverage_test_start_failed");
        }

        var limits = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose,
            },
        };
        if (!SetInformationJobObject(
                _job,
                9,
                ref limits,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()) ||
            !AssignProcessToJobObject(_job, process.Handle))
        {
            _job.Dispose();
            _job = null;
            throw new CoverageGateException("coverage_test_start_failed");
        }
    }

    public void Terminate()
    {
        Exception? first = null;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                if (_job is not null && !_job.IsInvalid && !TerminateJobObject(_job, 1))
                {
                    throw new InvalidOperationException("coverage_job_terminate_failed");
                }
            }
            else
            {
                CoverageProcessHost.KillUnixProcessGroup(_process.Id);
            }
        }
        catch (Exception error)
        {
            first = error;
        }

        if (first is null)
        {
            return;
        }

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }

        throw first;
    }

    public void Dispose()
    {
        _job?.Dispose();
        _job = null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateJobObject(IntPtr jobAttributes, string? name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateJobObject(SafeFileHandle job, uint exitCode);
}
