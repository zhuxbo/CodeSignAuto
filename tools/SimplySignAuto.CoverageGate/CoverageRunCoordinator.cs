using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SimplySignAuto.Coverage;

internal sealed record CoverageProjectDescriptor(string Name, string ProjectFile, string TestAssembly);

internal static class CoverageRunContract
{
    public const string ManifestName = "coverage-manifest.json";
    public const string StartedMarkerName = "run.started";
    public const string CompletedMarkerName = "run.completed";

    public static readonly CoverageProjectDescriptor[] Projects =
    [
        new("SimplySignAuto.Agent.Tests", "tests/SimplySignAuto.Agent.Tests/SimplySignAuto.Agent.Tests.csproj", "SimplySignAuto.Agent.Tests.dll"),
        new("SimplySignAuto.Core.Tests", "tests/SimplySignAuto.Core.Tests/SimplySignAuto.Core.Tests.csproj", "SimplySignAuto.Core.Tests.dll"),
        new("SimplySignAuto.EndToEnd.Tests", "tests/SimplySignAuto.EndToEnd.Tests/SimplySignAuto.EndToEnd.Tests.csproj", "SimplySignAuto.EndToEnd.Tests.dll"),
        new("SimplySignAuto.Protocol.Tests", "tests/SimplySignAuto.Protocol.Tests/SimplySignAuto.Protocol.Tests.csproj", "SimplySignAuto.Protocol.Tests.dll"),
        new("SimplySignAuto.Service.Tests", "tests/SimplySignAuto.Service.Tests/SimplySignAuto.Service.Tests.csproj", "SimplySignAuto.Service.Tests.dll"),
        new("SimplySignAuto.UI.Tests", "tests/SimplySignAuto.UI.Tests/SimplySignAuto.UI.Tests.csproj", "SimplySignAuto.UI.Tests.dll"),
    ];
}

internal sealed record CoverageProjectRun(
    string DotNetPath,
    string RepositoryRoot,
    string ProjectName,
    string ProjectFile,
    string ResultsDirectory,
    string TrxFileName);

internal sealed record CoverageRunLimits(
    TimeSpan WholeRunTimeout,
    TimeSpan ProjectTimeout,
    TimeSpan CleanupTimeout)
{
    public static CoverageRunLimits Default { get; } = new(
        TimeSpan.FromMinutes(10),
        TimeSpan.FromMinutes(2),
        TimeSpan.FromSeconds(10));

    public void Validate()
    {
        if (WholeRunTimeout <= TimeSpan.Zero || ProjectTimeout <= TimeSpan.Zero ||
            CleanupTimeout <= TimeSpan.Zero)
        {
            throw new CoverageGateException("coverage_limits_invalid");
        }
    }
}

internal sealed record CoverageProcessOutput(int ExitCode, string StandardOutput, string StandardError);

internal interface ICoverageProjectRunner
{
    Task<CoverageProcessOutput> RunAsync(CoverageProjectRun run, CancellationToken cancellationToken);
}

internal sealed record CoverageRunResult(
    string Root,
    string ManifestPath,
    IReadOnlyDictionary<string, CoverageResult> Coverage);

internal static class CoverageRunCoordinator
{
    public static async Task<CoverageRunResult> RunAsync(
        string repositoryRoot,
        string outputParent,
        string dotNetPath,
        ICoverageProjectRunner? runner = null,
        CancellationToken cancellationToken = default,
        CoverageRunLimits? limits = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(repositoryRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputParent);
        ArgumentException.ThrowIfNullOrWhiteSpace(dotNetPath);
        limits ??= CoverageRunLimits.Default;
        limits.Validate();
        timeProvider ??= TimeProvider.System;
        var repository = Path.GetFullPath(repositoryRoot);
        var parent = Path.GetFullPath(outputParent);
        if (!IsOrdinaryDirectory(repository))
        {
            throw Error("coverage_repository_invalid");
        }

        Directory.CreateDirectory(parent);
        if (!IsOrdinaryDirectory(parent))
        {
            throw Error("coverage_output_invalid");
        }

        foreach (var project in CoverageRunContract.Projects)
        {
            var projectPath = Path.GetFullPath(Path.Combine(
                repository,
                project.ProjectFile.Replace('/', Path.DirectorySeparatorChar)));
            if (!IsWithinRoot(repository, projectPath) || !IsOrdinaryFile(projectPath, allowEmpty: false))
            {
                throw Error("coverage_project_missing");
            }
        }

        var nonce = Guid.NewGuid().ToString("N");
        var root = Path.Combine(parent, "ssa-coverage-" + nonce);
        if (Directory.Exists(root) || File.Exists(root))
        {
            throw Error("coverage_run_collision");
        }

        Directory.CreateDirectory(root);
        if (!IsOrdinaryDirectory(root))
        {
            throw Error("coverage_output_invalid");
        }

        WriteNewFlushed(Path.Combine(root, CoverageRunContract.StartedMarkerName), nonce);
        runner ??= new DotNetCoverageProjectRunner(limits.CleanupTimeout, timeProvider);
        using var wholeTimeoutCancellation = new CancellationTokenSource();
        var wholeTimeout = Task.Delay(
            limits.WholeRunTimeout,
            timeProvider,
            wholeTimeoutCancellation.Token);
        try
        {
            foreach (var project in CoverageRunContract.Projects)
            {
                ThrowIfRunExpired(wholeTimeout, cancellationToken);
                var projectDirectory = Path.Combine(root, "projects", project.Name);
                Directory.CreateDirectory(projectDirectory);
                WriteNewFlushed(
                    Path.Combine(projectDirectory, "project.started"),
                    nonce + "\n" + project.Name);
                var invocation = new CoverageProjectRun(
                    dotNetPath,
                    repository,
                    project.Name,
                    project.ProjectFile,
                    projectDirectory,
                    project.Name + ".trx");
                var output = await RunProjectAsync(
                    runner,
                    invocation,
                    wholeTimeout,
                    limits,
                    timeProvider,
                    cancellationToken).ConfigureAwait(false);
                await RunWithinWholeRunAsync(
                    token =>
                    {
                        token.ThrowIfCancellationRequested();
                        WriteNewFlushed(Path.Combine(projectDirectory, "stdout.txt"), output.StandardOutput);
                        token.ThrowIfCancellationRequested();
                        WriteNewFlushed(Path.Combine(projectDirectory, "stderr.txt"), output.StandardError);
                        token.ThrowIfCancellationRequested();
                        if (output.ExitCode != 0)
                        {
                            throw Error("coverage_test_failed");
                        }

                        NormalizeCollectorReports(projectDirectory);
                        token.ThrowIfCancellationRequested();
                        CoverageGate.ValidateProjectArtifacts(root, repository, project);
                        token.ThrowIfCancellationRequested();
                        WriteNewFlushed(
                            Path.Combine(projectDirectory, "project.completed"),
                            nonce + "\n" + project.Name);
                        return true;
                    },
                    wholeTimeout,
                    limits.CleanupTimeout,
                    cancellationToken).ConfigureAwait(false);
            }

            await RunWithinWholeRunAsync(
                token =>
                {
                    token.ThrowIfCancellationRequested();
                    WriteNewFlushed(Path.Combine(root, CoverageRunContract.CompletedMarkerName), nonce);
                    return true;
                },
                wholeTimeout,
                limits.CleanupTimeout,
                cancellationToken).ConfigureAwait(false);

            var manifestJson = await RunWithinWholeRunAsync(
                token =>
                {
                    token.ThrowIfCancellationRequested();
                    var json = CoverageGate.CreateCoordinatorManifestJson(root, repository, nonce);
                    token.ThrowIfCancellationRequested();
                    return json;
                },
                wholeTimeout,
                limits.CleanupTimeout,
                cancellationToken).ConfigureAwait(false);
            var candidateManifest = Path.Combine(root, ".coverage-manifest.part");
            var manifestPath = Path.Combine(root, CoverageRunContract.ManifestName);
            try
            {
                await RunWithinWholeRunAsync(
                    token =>
                    {
                        token.ThrowIfCancellationRequested();
                        WriteNewFlushed(candidateManifest, manifestJson);
                        token.ThrowIfCancellationRequested();
                        return true;
                    },
                    wholeTimeout,
                    limits.CleanupTimeout,
                    cancellationToken).ConfigureAwait(false);
                var coverage = await RunWithinWholeRunAsync(
                    token =>
                    {
                        token.ThrowIfCancellationRequested();
                        var result = CoverageGate.EvaluateManifest(candidateManifest);
                        token.ThrowIfCancellationRequested();
                        return result;
                    },
                    wholeTimeout,
                    limits.CleanupTimeout,
                    cancellationToken).ConfigureAwait(false);
                ThrowIfRunExpired(wholeTimeout, cancellationToken);
                File.Move(candidateManifest, manifestPath);
                try
                {
                    ThrowIfRunExpired(wholeTimeout, cancellationToken);
                }
                catch
                {
                    TryDelete(manifestPath);
                    throw;
                }

                return new CoverageRunResult(root, manifestPath, coverage);
            }
            finally
            {
                TryDelete(candidateManifest);
            }
        }
        finally
        {
            wholeTimeoutCancellation.Cancel();
        }
    }

    private static async Task<CoverageProcessOutput> RunProjectAsync(
        ICoverageProjectRunner runner,
        CoverageProjectRun invocation,
        Task wholeTimeout,
        CoverageRunLimits limits,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        using var runnerCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var projectTimeoutCancellation = new CancellationTokenSource();
        var projectTimeout = Task.Delay(
            limits.ProjectTimeout,
            timeProvider,
            projectTimeoutCancellation.Token);
        var callerCancellation = Task.Delay(
            Timeout.InfiniteTimeSpan,
            timeProvider,
            cancellationToken);
        var runnerTask = Task.Factory.StartNew(
                () => runner.RunAsync(invocation, runnerCancellation.Token),
                CancellationToken.None,
                TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
                TaskScheduler.Default)
            .Unwrap();
        await Task.WhenAny(runnerTask, wholeTimeout, projectTimeout, callerCancellation).ConfigureAwait(false);
        if (!cancellationToken.IsCancellationRequested && !wholeTimeout.IsCompleted &&
            !projectTimeout.IsCompleted && runnerTask.IsCompleted)
        {
            projectTimeoutCancellation.Cancel();
            return await runnerTask.ConfigureAwait(false);
        }

        runnerCancellation.Cancel();
        await ObserveCleanupAsync(runnerTask, limits.CleanupTimeout, timeProvider).ConfigureAwait(false);
        if (cancellationToken.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
        }

        throw Error("coverage_test_timeout");
    }

    private static async Task<T> RunWithinWholeRunAsync<T>(
        Func<CancellationToken, T> operation,
        Task wholeTimeout,
        TimeSpan cleanupTimeout,
        CancellationToken cancellationToken)
    {
        using var operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var operationTask = Task.Run(
            () => operation(operationCancellation.Token),
            CancellationToken.None);
        var callerCancellation = Task.Delay(
            Timeout.InfiniteTimeSpan,
            TimeProvider.System,
            cancellationToken);
        await Task.WhenAny(operationTask, wholeTimeout, callerCancellation).ConfigureAwait(false);
        if (cancellationToken.IsCancellationRequested || wholeTimeout.IsCompleted)
        {
            operationCancellation.Cancel();
            await ObserveCleanupAsync(
                operationTask,
                cleanupTimeout,
                TimeProvider.System).ConfigureAwait(false);
            ThrowIfRunExpired(wholeTimeout, cancellationToken);
        }

        return await operationTask.ConfigureAwait(false);
    }

    private static void ThrowIfRunExpired(Task wholeTimeout, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (wholeTimeout.IsCompleted)
        {
            throw Error("coverage_test_timeout");
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // Cleanup is best effort and cannot replace the primary result.
        }
    }

    private static async Task ObserveCleanupAsync(
        Task runnerTask,
        TimeSpan cleanupTimeout,
        TimeProvider timeProvider)
    {
        using var cleanupTimeoutCancellation = new CancellationTokenSource();
        var cleanupTimeoutTask = Task.Delay(
            cleanupTimeout,
            timeProvider,
            cleanupTimeoutCancellation.Token);
        if (await Task.WhenAny(runnerTask, cleanupTimeoutTask).ConfigureAwait(false) == runnerTask)
        {
            cleanupTimeoutCancellation.Cancel();
            try
            {
                await runnerTask.ConfigureAwait(false);
            }
            catch
            {
                // The deadline or caller cancellation remains the primary failure.
            }

            return;
        }

        _ = runnerTask.ContinueWith(
            static task => _ = task.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static bool IsOrdinaryDirectory(string path)
    {
        var info = new DirectoryInfo(path);
        return info.Exists && info.LinkTarget is null &&
            (info.Attributes & FileAttributes.ReparsePoint) == 0;
    }

    private static bool IsOrdinaryFile(string path, bool allowEmpty)
    {
        var info = new FileInfo(path);
        return info.Exists && info.LinkTarget is null &&
            (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0 &&
            (allowEmpty || info.Length > 0);
    }

    private static bool IsWithinRoot(string root, string path)
    {
        var relative = Path.GetRelativePath(root, path);
        return relative.Length > 0 && relative != "." && !Path.IsPathRooted(relative) &&
            relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private static void WriteNewFlushed(string path, string content)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        var bytes = Encoding.UTF8.GetBytes(content);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private static void NormalizeCollectorReports(string projectDirectory)
    {
        var projectRoot = Path.GetFullPath(projectDirectory);
        var reports = Directory.EnumerateFiles(projectRoot, "coverage.cobertura.xml", SearchOption.AllDirectories)
            .Select(Path.GetFullPath)
            .ToArray();
        if (reports.Length is < 1 or > 2 || reports.Any(report => !IsOrdinaryFile(report, allowEmpty: false)))
        {
            throw Error("coverage_report_invalid");
        }

        var hashes = reports.Select(report => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(report))))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (hashes.Length != 1)
        {
            throw Error("coverage_report_invalid");
        }

        var canonical = Path.Combine(projectRoot, "coverage.cobertura.xml");
        if (File.Exists(canonical) || Directory.Exists(canonical))
        {
            throw Error("coverage_report_invalid");
        }

        File.Move(reports[0], canonical);
        for (var index = 1; index < reports.Length; index++)
        {
            File.Delete(reports[index]);
        }
    }

    private static CoverageGateException Error(string code) => new(code);
}

internal sealed class DotNetCoverageProjectRunner : ICoverageProjectRunner
{
    private readonly TimeSpan _cleanupTimeout;
    private readonly TimeProvider _timeProvider;
    private readonly string? _processHostDotNetPath;
    private readonly Func<Process, CoverageProcessContainment> _containmentFactory;
    private readonly Action<string, string> _startMarkerWriter;

    public DotNetCoverageProjectRunner(
        TimeSpan? cleanupTimeout = null,
        TimeProvider? timeProvider = null,
        string? processHostDotNetPath = null,
        Func<Process, CoverageProcessContainment>? containmentFactory = null,
        Action<string, string>? startMarkerWriter = null)
    {
        _cleanupTimeout = cleanupTimeout ?? CoverageRunLimits.Default.CleanupTimeout;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _processHostDotNetPath = processHostDotNetPath;
        _containmentFactory = containmentFactory ?? (static process => new CoverageProcessContainment(process));
        _startMarkerWriter = startMarkerWriter ?? WriteTextNewFlushed;
    }

    public async Task<CoverageProcessOutput> RunAsync(
        CoverageProjectRun run,
        CancellationToken cancellationToken)
    {
        var nonce = Guid.NewGuid().ToString("N");
        var requestPath = Path.Combine(run.ResultsDirectory, ".coverage-host-request-" + nonce + ".json");
        var startPath = Path.Combine(run.ResultsDirectory, ".coverage-host-start-" + nonce);
        var resultPath = Path.Combine(run.ResultsDirectory, ".coverage-host-result-" + nonce + ".json");
        var childArguments = BuildChildArguments(run);
        WriteJsonNewFlushed(
            requestPath,
            new CoverageProcessHostRequest(
                run.DotNetPath,
                run.RepositoryRoot,
                childArguments,
                checked((int)Math.Ceiling(_cleanupTimeout.TotalMilliseconds))));
        var start = new ProcessStartInfo
        {
            FileName = _processHostDotNetPath ?? run.DotNetPath,
            WorkingDirectory = run.RepositoryRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.Environment["DOTNET_NOLOGO"] = "1";
        start.ArgumentList.Add(typeof(DotNetCoverageProjectRunner).Assembly.Location);
        start.ArgumentList.Add("--coverage-process-host");
        start.ArgumentList.Add(requestPath);
        start.ArgumentList.Add(startPath);
        start.ArgumentList.Add(resultPath);

        using var process = new Process { StartInfo = start };
        try
        {
            if (!process.Start())
            {
                throw new CoverageGateException("coverage_test_start_failed");
            }

            var stdout = Task.FromResult(string.Empty);
            var stderr = Task.FromResult(string.Empty);
            CoverageProcessContainment? containment = null;
            try
            {
                stdout = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
                stderr = process.StandardError.ReadToEndAsync(CancellationToken.None);
                containment = _containmentFactory(process);
                _startMarkerWriter(startPath, nonce);
                var result = await WaitForHostResultAsync(
                    resultPath,
                    process,
                    cancellationToken).ConfigureAwait(false);

                CoverageGateException? cleanupError = result.DrainTimedOut
                    ? new CoverageGateException("coverage_test_cleanup_timeout")
                    : null;
                try
                {
                    containment.Terminate();
                }
                catch when (cleanupError is not null)
                {
                }

                try
                {
                    await AwaitProcessCleanupAsync(
                        process.WaitForExitAsync(CancellationToken.None),
                        stdout,
                        stderr).ConfigureAwait(false);
                }
                catch (CoverageGateException error) when (cleanupError is null)
                {
                    cleanupError = error;
                }

                if (cleanupError is not null)
                {
                    throw cleanupError;
                }

                if (result.StartFailed)
                {
                    throw new CoverageGateException("coverage_test_start_failed");
                }

                return new CoverageProcessOutput(
                    result.ExitCode,
                    stdout.Result,
                    stderr.Result);
            }
            catch (Exception firstError)
            {
                TerminateOwnedBestEffort(containment, process);
                await ObserveProcessCleanupAsync(process, stdout, stderr).ConfigureAwait(false);
                ExceptionDispatchInfo.Capture(firstError).Throw();
                throw new InvalidOperationException("unreachable");
            }
            finally
            {
                try
                {
                    containment?.Dispose();
                }
                catch
                {
                    // Owned cleanup cannot replace the primary process result.
                }
            }
        }
        catch (CoverageGateException)
        {
            throw;
        }
        catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception or IOException)
        {
            throw new CoverageGateException("coverage_test_start_failed");
        }
        finally
        {
            TryDelete(requestPath);
            TryDelete(startPath);
            TryDelete(resultPath);
        }
    }

    private static string[] BuildChildArguments(CoverageProjectRun run) =>
    [
        "test",
        run.ProjectFile,
        "-c",
        "Release",
        "--no-restore",
        "--no-build",
        "--collect:XPlat Code Coverage",
        "--results-directory",
        run.ResultsDirectory,
        "--logger",
        "trx;LogFileName=" + run.TrxFileName,
        "--logger",
        "console;verbosity=minimal",
        "--",
        "DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=cobertura",
        "DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.IncludeTestAssembly=true",
        "DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.DeterministicReport=true",
    ];

    private async Task<CoverageProcessHostResult> WaitForHostResultAsync(
        string resultPath,
        Process process,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(resultPath);
            if (info.Exists)
            {
                if (info.LinkTarget is not null || info.Length is <= 0 or > 4096)
                {
                    throw new CoverageGateException("coverage_test_start_failed");
                }

                try
                {
                    return JsonSerializer.Deserialize<CoverageProcessHostResult>(
                        await File.ReadAllTextAsync(resultPath, cancellationToken).ConfigureAwait(false)) ??
                        throw new CoverageGateException("coverage_test_start_failed");
                }
                catch (JsonException)
                {
                    throw new CoverageGateException("coverage_test_start_failed");
                }
            }

            if (process.HasExited)
            {
                throw new CoverageGateException("coverage_test_start_failed");
            }

            await Task.Delay(
                TimeSpan.FromMilliseconds(10),
                _timeProvider,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ObserveProcessCleanupAsync(
        Process process,
        Task<string> stdout,
        Task<string> stderr)
    {
        try
        {
            await AwaitProcessCleanupAsync(
                process.WaitForExitAsync(CancellationToken.None),
                stdout,
                stderr).ConfigureAwait(false);
        }
        catch
        {
            // Process termination and stream draining cannot replace the first failure.
        }
    }

    private static void WriteJsonNewFlushed<T>(string path, T value)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(stream, value);
        stream.Flush(flushToDisk: true);
    }

    private static void WriteTextNewFlushed(string path, string value)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        using var writer = new StreamWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(value);
        writer.Flush();
        stream.Flush(flushToDisk: true);
    }

    private static void TerminateBestEffort(CoverageProcessContainment containment, Process process)
    {
        try
        {
            containment.Terminate();
            return;
        }
        catch
        {
        }

        TryKillProcessTree(process);
    }

    private static void TerminateOwnedBestEffort(
        CoverageProcessContainment? containment,
        Process process)
    {
        if (containment is null)
        {
            TryKillProcessTree(process);
            return;
        }

        TerminateBestEffort(containment, process);
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
        }
    }

    private Task AwaitProcessCleanupAsync(params Task[] tasks) =>
        AwaitProcessCleanupCoreAsync(tasks);

    private async Task AwaitProcessCleanupCoreAsync(Task[] tasks)
    {
        var cleanup = Task.WhenAll(tasks);
        using var cleanupTimeoutCancellation = new CancellationTokenSource();
        var timeout = Task.Delay(
            _cleanupTimeout,
            _timeProvider,
            cleanupTimeoutCancellation.Token);
        if (await Task.WhenAny(cleanup, timeout).ConfigureAwait(false) != cleanup)
        {
            throw new CoverageGateException("coverage_test_cleanup_timeout");
        }

        cleanupTimeoutCancellation.Cancel();
        await cleanup.ConfigureAwait(false);
    }

    private static void TryKillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best effort only; the original wait failure is authoritative.
        }
    }
}
