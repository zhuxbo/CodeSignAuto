using SimplySignAuto.Coverage;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class CoverageGateTests
{
    [Fact]
    public void Coverage_process_host_is_bound_to_the_current_loaded_runtime()
    {
        var configuredHost = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        Assert.False(string.IsNullOrWhiteSpace(configuredHost));
        Assert.True(Path.IsPathFullyQualified(configuredHost!));
        var runtimeDirectory = RuntimeEnvironment.GetRuntimeDirectory();

        var resolvedHost = ResolveCurrentDotnetHost(configuredHost, runtimeDirectory);
        Assert.Equal(
            Path.GetFullPath(configuredHost),
            resolvedHost,
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

        Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(null, runtimeDirectory));
        Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(" ", runtimeDirectory));

        var relativeHost = Path.Combine(
            "relative",
            OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet");
        Assert.False(Path.IsPathFullyQualified(relativeHost));
        Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(relativeHost, runtimeDirectory));

        var unrelatedHost = Path.GetTempFileName();
        try
        {
            Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(unrelatedHost, runtimeDirectory));
        }
        finally
        {
            File.Delete(unrelatedHost);
        }

        if (OperatingSystem.IsWindows())
        {
            var caseVariant = configuredHost.ToUpperInvariant();
            Assert.Equal(
                Path.GetFullPath(configuredHost),
                ResolveCurrentDotnetHost(caseVariant, runtimeDirectory),
                StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Exact_thresholds_pass_with_independently_counted_source_lines()
    {
        var summary = CoverageGate.EvaluateXmlReports([ValidReport()]);

        Assert.Equal(8500, summary["SimplySignAuto.Core"].BasisPoints);
        Assert.Equal(8500, summary["SimplySignAuto.Service"].BasisPoints);
        Assert.Equal(8500, summary["SimplySignAuto.Protocol"].BasisPoints);
        Assert.Equal(7500, summary["SimplySignAuto.Agent"].BasisPoints);
        Assert.Equal(8000, summary["SimplySignAuto.UI.ViewModels"].BasisPoints);
    }

    [Fact]
    public void Collector_specific_paths_are_unified_and_generated_obj_lines_are_not_product_source()
    {
        var collectorVariant = Report(
            Package("SimplySignAuto.Core", "SimplySignAuto.Core.Sample", 0, 20, "SimplySignAuto.Core/Sample.cs"),
            Package("SimplySignAuto.Service", "SimplySignAuto.Service.Sample", 0, 20, "Sample.cs"),
            Package("SimplySignAuto.Protocol", "SimplySignAuto.Protocol.Sample", 0, 20, "/agent/src/SimplySignAuto.Protocol/Sample.cs"),
            Package("SimplySignAuto.Agent", "SimplySignAuto.Agent.Sample", 0, 20, "SimplySignAuto.Agent/Sample.cs"),
            Package("SimplySignAuto", "SimplySignAuto.App.UI.ViewModels.SampleViewModel", 0, 20, "SimplySignAuto.App/UI/ViewModels/SampleViewModel.cs"));
        var generatedVariant = Report(
            Package(
                "SimplySignAuto.Core",
                "SimplySignAuto.Core.GeneratedRegex",
                0,
                1_000,
                "src/SimplySignAuto.Core/obj/Release/net10.0/Generator/RegexGenerator.g.cs"));

        var summary = CoverageGate.EvaluateXmlReports([ValidReport(), collectorVariant, generatedVariant]);

        Assert.Equal((17, 20, 8500), Result(summary, "SimplySignAuto.Core"));
        Assert.Equal((17, 20, 8500), Result(summary, "SimplySignAuto.Service"));
        Assert.Equal((17, 20, 8500), Result(summary, "SimplySignAuto.Protocol"));
        Assert.Equal((15, 20, 7500), Result(summary, "SimplySignAuto.Agent"));
        Assert.Equal((16, 20, 8000), Result(summary, "SimplySignAuto.UI.ViewModels"));
    }

    [Fact]
    public void Missing_report_fails_closed()
    {
        var error = Assert.Throws<CoverageGateException>(() => CoverageGate.EvaluateXmlReports([]));

        Assert.Equal("coverage_report_missing", error.Code);
    }

    [Fact]
    public void Nan_hits_and_unknown_target_fail_closed()
    {
        var nan = ValidReport().Replace("hits=\"1\"", "hits=\"NaN\"", StringComparison.Ordinal);
        Assert.Equal(
            "coverage_report_invalid",
            Assert.Throws<CoverageGateException>(() => CoverageGate.EvaluateXmlReports([nan])).Code);

        var unknown = ValidReport().Replace(
            "name=\"SimplySignAuto.Core\"",
            "name=\"SimplySignAuto.Future\"",
            StringComparison.Ordinal);
        Assert.Equal(
            "coverage_target_missing",
            Assert.Throws<CoverageGateException>(() => CoverageGate.EvaluateXmlReports([unknown])).Code);
    }

    [Fact]
    public void Duplicate_module_in_one_report_fails_closed()
    {
        var core = Package("SimplySignAuto.Core", "SimplySignAuto.Core.Sample", 17, 20);
        var duplicate = ValidReport().Replace(core, core + core, StringComparison.Ordinal);

        var error = Assert.Throws<CoverageGateException>(() => CoverageGate.EvaluateXmlReports([duplicate]));

        Assert.Equal("coverage_module_duplicate", error.Code);
    }

    [Fact]
    public void One_basis_point_below_threshold_fails_closed()
    {
        var lowCore = Package("SimplySignAuto.Core", "SimplySignAuto.Core.Sample", 8_499, 10_000);
        var report = Report(
            lowCore,
            Package("SimplySignAuto.Service", "SimplySignAuto.Service.Sample", 17, 20),
            Package("SimplySignAuto.Protocol", "SimplySignAuto.Protocol.Sample", 17, 20),
            Package("SimplySignAuto.Agent", "SimplySignAuto.Agent.Sample", 15, 20),
            Package(
                "SimplySignAuto",
                "SimplySignAuto.App.UI.ViewModels.Sample",
                16,
                20,
                "src/SimplySignAuto.App/UI/ViewModels/SampleViewModel.cs"));

        var error = Assert.Throws<CoverageGateException>(() => CoverageGate.EvaluateXmlReports([report]));

        Assert.Equal("coverage_below_threshold", error.Code);
    }

    [Fact]
    public void Ui_view_model_denominator_is_selected_by_controlled_source_path_including_shell()
    {
        var report = ValidReport()
            .Replace("SimplySignAuto.App.UI.ViewModels.SampleViewModel", "SimplySignAuto.App.UI.ShellViewModel", StringComparison.Ordinal)
            .Replace("src/SimplySignAuto.App/UI/ViewModels/SampleViewModel.cs", "src/SimplySignAuto.App/UI/ShellViewModel.cs", StringComparison.Ordinal);

        var summary = CoverageGate.EvaluateXmlReports([report]);

        Assert.Equal((16, 20, 8000), Result(summary, "SimplySignAuto.UI.ViewModels"));
    }

    [Fact]
    public async Task One_shot_coordinator_creates_a_new_nonce_root_and_runs_only_the_six_hardcoded_projects()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-ONE-SHOT-").FullName;
        try
        {
            var runner = new RecordingCoverageProjectRunner();

            var run = await CoverageRunCoordinator.RunAsync(
                repository,
                outputParent,
                "dotnet-under-test",
                runner,
                CancellationToken.None);

            Assert.StartsWith(Path.Combine(outputParent, "ssa-coverage-"), run.Root, StringComparison.Ordinal);
            Assert.Equal(ExpectedProjectFiles, runner.ProjectFiles);
            Assert.Equal(5, CoverageGate.EvaluateManifest(run.ManifestPath).Count);
            Assert.True(File.Exists(Path.Combine(run.Root, "run.started")));
            Assert.True(File.Exists(Path.Combine(run.Root, "run.completed")));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_project_timeout_is_bounded_preserves_the_timeout_and_never_publishes_a_manifest()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-PROJECT-TIMEOUT-").FullName;
        try
        {
            var runner = new CancellingCoverageProjectRunner();
            var stopwatch = Stopwatch.StartNew();

            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    "dotnet-under-test",
                    runner,
                    CancellationToken.None,
                    new CoverageRunLimits(
                        TimeSpan.FromSeconds(2),
                        TimeSpan.FromMilliseconds(50),
                        TimeSpan.FromMilliseconds(250))));

            stopwatch.Stop();
            Assert.Equal("coverage_test_timeout", error.Code);
            Assert.True(runner.CancellationObserved);
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
            Assert.Empty(Directory.GetFiles(outputParent, "coverage-manifest.json", SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_runner_that_blocks_before_returning_its_task_is_still_bounded()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-SYNC-RUNNER-TIMEOUT-").FullName;
        var runner = new SynchronouslyBlockingCoverageProjectRunner();
        try
        {
            var runTask = CoverageRunCoordinator.RunAsync(
                repository,
                outputParent,
                "dotnet-under-test",
                runner,
                CancellationToken.None,
                new CoverageRunLimits(
                    TimeSpan.FromSeconds(2),
                    TimeSpan.FromMilliseconds(50),
                    TimeSpan.FromMilliseconds(100)));
            Assert.True(runner.Entered.Wait(TimeSpan.FromSeconds(1)));

            var completed = await Task.WhenAny(runTask, Task.Delay(TimeSpan.FromMilliseconds(500)));
            runner.Release();
            var error = await Assert.ThrowsAsync<CoverageGateException>(() => runTask);

            Assert.Same(runTask, completed);
            Assert.Equal("coverage_test_timeout", error.Code);
            Assert.Empty(Directory.GetFiles(outputParent, "coverage-manifest.json", SearchOption.AllDirectories));
        }
        finally
        {
            runner.Release();
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_whole_run_timeout_cannot_be_evaded_by_individually_fast_projects()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-WHOLE-TIMEOUT-").FullName;
        try
        {
            var clock = new ControllableCoverageTimeProvider(
                new DateTimeOffset(2026, 8, 15, 0, 0, 0, TimeSpan.Zero));
            var runner = new AdvancingCoverageProjectRunner(
                clock,
                TimeSpan.FromMilliseconds(45));

            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    "dotnet-under-test",
                    runner,
                    CancellationToken.None,
                    new CoverageRunLimits(
                        TimeSpan.FromMilliseconds(70),
                        TimeSpan.FromSeconds(1),
                        TimeSpan.FromMilliseconds(250)),
                    clock));

            Assert.Equal("coverage_test_timeout", error.Code);
            Assert.Equal(2, runner.CompletedProjects);
            Assert.Empty(Directory.GetFiles(outputParent, "coverage-manifest.json", SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_whole_deadline_wins_when_the_sixth_runner_completes_at_the_deadline()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-FINAL-PUBLISH-TIMEOUT-").FullName;
        try
        {
            var clock = new ControllableCoverageTimeProvider(
                new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero));
            var runner = new AdvanceOnFinalProjectRunner(clock, TimeSpan.FromMinutes(1));

            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    "dotnet-under-test",
                    runner,
                    CancellationToken.None,
                    new CoverageRunLimits(
                        TimeSpan.FromMinutes(1),
                        TimeSpan.FromMinutes(5),
                        TimeSpan.FromSeconds(1)),
                    clock));

            Assert.Equal("coverage_test_timeout", error.Code);
            Assert.Equal(CoverageRunContract.Projects.Length, runner.CompletedProjects);
            await runner.Advanced.WaitAsync(TimeSpan.FromSeconds(1));
            Assert.Empty(Directory.GetFiles(outputParent, CoverageRunContract.CompletedMarkerName, SearchOption.AllDirectories));
            Assert.Empty(Directory.GetFiles(outputParent, CoverageRunContract.ManifestName, SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_real_hanging_process_kills_its_process_tree_and_bounds_stream_cleanup()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-PROCESS-TIMEOUT-").FullName;
        try
        {
            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    CoverageHangFixturePath(),
                    new DotNetCoverageProjectRunner(
                        TimeSpan.FromSeconds(1),
                        processHostDotNetPath: DotNetExecutablePath()),
                    CancellationToken.None,
                    new CoverageRunLimits(
                        TimeSpan.FromSeconds(6),
                        TimeSpan.FromSeconds(2),
                        TimeSpan.FromSeconds(1))));

            Assert.Equal("coverage_test_timeout", error.Code);
            var parentPid = int.Parse(File.ReadAllText(Directory.GetFiles(
                outputParent,
                "coverage-hang-parent.pid",
                SearchOption.AllDirectories).Single()));
            var childPid = int.Parse(File.ReadAllText(Directory.GetFiles(
                outputParent,
                "coverage-hang-child.pid",
                SearchOption.AllDirectories).Single()));
            await AssertProcessExited(parentPid);
            await AssertProcessExited(childPid);
            Assert.Empty(Directory.GetFiles(outputParent, "coverage-manifest.json", SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_drain_timeout_kills_a_descendant_after_its_parent_exits_normally()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-ORPHAN-DRAIN-").FullName;
        var childPid = 0;
        try
        {
            File.WriteAllText(Path.Combine(repository, "coverage-parent-exits.mode"), "enabled");
            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    CoverageHangFixturePath(),
                    new DotNetCoverageProjectRunner(
                        TimeSpan.FromMilliseconds(250),
                        processHostDotNetPath: DotNetExecutablePath()),
                    CancellationToken.None,
                    new CoverageRunLimits(
                        TimeSpan.FromSeconds(5),
                        TimeSpan.FromSeconds(3),
                        TimeSpan.FromMilliseconds(250))));

            Assert.Equal("coverage_test_cleanup_timeout", error.Code);
            childPid = int.Parse(File.ReadAllText(Directory.GetFiles(
                outputParent,
                "coverage-hang-child.pid",
                SearchOption.AllDirectories).Single()));
            Assert.True(
                await WaitForProcessExit(childPid, TimeSpan.FromSeconds(2)),
                "coverage descendant remained alive after its parent exited and drain timed out");
            Assert.Empty(Directory.GetFiles(outputParent, CoverageRunContract.ManifestName, SearchOption.AllDirectories));
        }
        finally
        {
            TryKillProcess(childPid);
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_containment_creation_failure_kills_the_started_host_and_never_publishes_manifest()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-CONTAINMENT-FAILURE-").FullName;
        var hostPid = 0;
        try
        {
            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    CoverageHangFixturePath(),
                    new DotNetCoverageProjectRunner(
                        TimeSpan.FromMilliseconds(250),
                        processHostDotNetPath: DotNetExecutablePath(),
                        containmentFactory: process =>
                        {
                            hostPid = process.Id;
                            throw new InvalidOperationException("containment_fixture_failure");
                        }),
                    CancellationToken.None,
                    new CoverageRunLimits(
                        TimeSpan.FromSeconds(5),
                        TimeSpan.FromSeconds(3),
                        TimeSpan.FromMilliseconds(250))));

            Assert.Equal("coverage_test_start_failed", error.Code);
            Assert.True(hostPid > 0);
            await AssertProcessExited(hostPid);
            Assert.Empty(Directory.GetFiles(outputParent, "coverage-hang-child.pid", SearchOption.AllDirectories));
            Assert.Empty(Directory.GetFiles(outputParent, CoverageRunContract.ManifestName, SearchOption.AllDirectories));
        }
        finally
        {
            TryKillProcess(hostPid);
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_start_marker_failure_kills_the_owned_host_and_child_and_preserves_the_first_error()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-START-MARKER-FAILURE-").FullName;
        var hostPid = 0;
        var childPid = 0;
        try
        {
            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    CoverageHangFixturePath(),
                    new DotNetCoverageProjectRunner(
                        TimeSpan.FromMilliseconds(250),
                        processHostDotNetPath: DotNetExecutablePath(),
                        containmentFactory: process =>
                        {
                            hostPid = process.Id;
                            return new CoverageProcessContainment(process);
                        },
                        startMarkerWriter: (path, value) =>
                        {
                            WriteFlushed(path, value);
                            if (!SpinWait.SpinUntil(
                                    () =>
                                    {
                                        try
                                        {
                                            var paths = Directory.GetFiles(
                                                outputParent,
                                                "coverage-hang-child.pid",
                                                SearchOption.AllDirectories);
                                            return paths.Length == 1 &&
                                                int.TryParse(
                                                    File.ReadAllText(paths[0]),
                                                    out childPid) &&
                                                childPid > 0;
                                        }
                                        catch (IOException)
                                        {
                                            return false;
                                        }
                                    },
                                    TimeSpan.FromSeconds(2)))
                            {
                                throw new IOException("coverage_child_not_started");
                            }

                            throw new IOException("start_marker_fixture_failure");
                        }),
                    CancellationToken.None,
                    new CoverageRunLimits(
                        TimeSpan.FromSeconds(5),
                        TimeSpan.FromSeconds(3),
                        TimeSpan.FromMilliseconds(250))));

            Assert.Equal("coverage_test_start_failed", error.Code);
            Assert.True(hostPid > 0);
            Assert.True(childPid > 0);
            await AssertProcessExited(hostPid);
            await AssertProcessExited(childPid);
            Assert.Empty(Directory.GetFiles(outputParent, CoverageRunContract.ManifestName, SearchOption.AllDirectories));
        }
        finally
        {
            TryKillProcess(childPid);
            TryKillProcess(hostPid);
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Theory]
    [InlineData("copied-report")]
    [InlineData("relabelled-project")]
    [InlineData("missing-report")]
    [InlineData("duplicate-report")]
    [InlineData("extra-report")]
    [InlineData("stale-before-marker")]
    public async Task One_shot_manifest_rejects_reused_or_ambiguous_run_artifacts(string mutation)
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-MUTATION-").FullName;
        try
        {
            var run = await CoverageRunCoordinator.RunAsync(
                repository,
                outputParent,
                "dotnet-under-test",
                new RecordingCoverageProjectRunner(),
                CancellationToken.None);
            var first = ProjectDirectory(run.Root, ExpectedProjects[0]);
            var second = ProjectDirectory(run.Root, ExpectedProjects[1]);
            switch (mutation)
            {
                case "copied-report":
                    File.Copy(
                        Directory.GetFiles(first, "coverage.cobertura.xml", SearchOption.AllDirectories).Single(),
                        Directory.GetFiles(second, "coverage.cobertura.xml", SearchOption.AllDirectories).Single(),
                        overwrite: true);
                    break;
                case "relabelled-project":
                    Directory.Move(second, second + ".relabelled");
                    break;
                case "missing-report":
                    File.Delete(Directory.GetFiles(first, "coverage.cobertura.xml", SearchOption.AllDirectories).Single());
                    break;
                case "duplicate-report":
                case "extra-report":
                    var extra = Directory.CreateDirectory(Path.Combine(
                        mutation == "duplicate-report" ? first : run.Root,
                        mutation));
                    File.Copy(
                        Directory.GetFiles(first, "coverage.cobertura.xml", SearchOption.AllDirectories).Single(),
                        Path.Combine(extra.FullName, "coverage.cobertura.xml"));
                    break;
                case "stale-before-marker":
                    File.SetLastWriteTimeUtc(
                        Directory.GetFiles(first, "coverage.cobertura.xml", SearchOption.AllDirectories).Single(),
                        File.GetLastWriteTimeUtc(Path.Combine(run.Root, "run.started")).AddSeconds(-1));
                    break;
                default:
                    throw new InvalidOperationException("unknown_test_mutation");
            }

            Assert.Throws<CoverageGateException>(() => CoverageGate.EvaluateManifest(run.ManifestPath));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Theory]
    [InlineData("stdout")]
    [InlineData("stderr")]
    [InlineData("trx")]
    [InlineData("trx-test-name")]
    [InlineData("trx-definition-name")]
    [InlineData("trx-root-name")]
    [InlineData("trx-root-run-user")]
    [InlineData("coverage")]
    public async Task One_shot_runner_fails_when_a_real_captured_artifact_contains_a_sensitive_marker(string artifact)
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-SCAN-").FullName;
        try
        {
            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    "dotnet-under-test",
                    new RecordingCoverageProjectRunner(artifact),
                    CancellationToken.None));

            Assert.Equal("coverage_sensitive_output", error.Code);
            Assert.Empty(Directory.GetFiles(outputParent, "coverage-manifest.json", SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    [Fact]
    public async Task One_shot_runner_rejects_coverage_from_a_different_test_project()
    {
        var repository = CreateRepositorySkeleton();
        var outputParent = Directory.CreateTempSubdirectory("SSA-COVERAGE-IDENTITY-").FullName;
        try
        {
            var error = await Assert.ThrowsAsync<CoverageGateException>(() =>
                CoverageRunCoordinator.RunAsync(
                    repository,
                    outputParent,
                    "dotnet-under-test",
                    new RecordingCoverageProjectRunner("wrong-coverage-project"),
                    CancellationToken.None));

            Assert.Equal("coverage_project_identity_mismatch", error.Code);
            Assert.Empty(Directory.GetFiles(outputParent, "coverage-manifest.json", SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(repository, recursive: true);
            Directory.Delete(outputParent, recursive: true);
        }
    }

    private static string ValidReport() => Report(
        Package("SimplySignAuto.Core", "SimplySignAuto.Core.Sample", 17, 20),
        Package("SimplySignAuto.Service", "SimplySignAuto.Service.Sample", 17, 20),
        Package("SimplySignAuto.Protocol", "SimplySignAuto.Protocol.Sample", 17, 20),
        Package("SimplySignAuto.Agent", "SimplySignAuto.Agent.Sample", 15, 20),
        Package(
            "SimplySignAuto",
            "SimplySignAuto.App.UI.ViewModels.Sample",
            16,
            20,
            "src/SimplySignAuto.App/UI/ViewModels/SampleViewModel.cs"));

    private static readonly string[] ExpectedProjects =
    [
        "SimplySignAuto.Agent.Tests",
        "SimplySignAuto.Core.Tests",
        "SimplySignAuto.EndToEnd.Tests",
        "SimplySignAuto.Protocol.Tests",
        "SimplySignAuto.Service.Tests",
        "SimplySignAuto.UI.Tests",
    ];

    private static readonly string[] ExpectedProjectFiles =
    [
        "tests/SimplySignAuto.Agent.Tests/SimplySignAuto.Agent.Tests.csproj",
        "tests/SimplySignAuto.Core.Tests/SimplySignAuto.Core.Tests.csproj",
        "tests/SimplySignAuto.EndToEnd.Tests/SimplySignAuto.EndToEnd.Tests.csproj",
        "tests/SimplySignAuto.Protocol.Tests/SimplySignAuto.Protocol.Tests.csproj",
        "tests/SimplySignAuto.Service.Tests/SimplySignAuto.Service.Tests.csproj",
        "tests/SimplySignAuto.UI.Tests/SimplySignAuto.UI.Tests.csproj",
    ];

    private static string CreateRepositorySkeleton()
    {
        var root = Directory.CreateTempSubdirectory("SSA-COVERAGE-REPOSITORY-").FullName;
        foreach (var project in ExpectedProjectFiles)
        {
            var path = Path.Combine(root, project.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "<Project />");
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, "CoverageIdentity.cs"), "internal sealed class CoverageIdentity;");
        }

        return root;
    }

    private static string ProjectDirectory(string root, string project) =>
        Path.Combine(root, "projects", project);

    private static string CoverageHangFixturePath()
    {
        var repository = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(repository, "SimplySignAuto.sln")))
        {
            repository = Directory.GetParent(repository)?.FullName ??
                throw new InvalidOperationException("repository_root_not_found");
        }

        var executable = Path.Combine(
            repository,
            "tests",
            "SimplySignAuto.EndToEnd.Tests",
            "Fixtures",
            "CoverageHang",
            "bin",
            "Release",
            "net10.0-windows",
            "CoverageHang" + (OperatingSystem.IsWindows() ? ".exe" : string.Empty));
        Assert.True(File.Exists(executable), "coverage hang fixture was not built");
        return executable;
    }

    private static string DotNetExecutablePath()
    {
        return ResolveCurrentDotnetHost(
            Environment.GetEnvironmentVariable("DOTNET_HOST_PATH"),
            RuntimeEnvironment.GetRuntimeDirectory());
    }

    private static string ResolveCurrentDotnetHost(string? configuredHost, string runtimeDirectory)
    {
        if (string.IsNullOrWhiteSpace(configuredHost) || !Path.IsPathFullyQualified(configuredHost))
        {
            throw new InvalidOperationException("DOTNET_HOST_PATH must be a fully-qualified path.");
        }

        var runtimeVersionDirectory = new DirectoryInfo(runtimeDirectory);
        var dotnetRoot = runtimeVersionDirectory.Parent?.Parent?.Parent
            ?? throw new InvalidOperationException("The current dotnet root could not be derived from the runtime directory.");
        var expectedHost = Path.GetFullPath(Path.Combine(
            dotnetRoot.FullName,
            OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet"));
        var actualHost = Path.GetFullPath(configuredHost);
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        if (!string.Equals(actualHost, expectedHost, comparison) || !IsOrdinaryFile(actualHost))
        {
            throw new InvalidOperationException(
                "DOTNET_HOST_PATH must identify the host for the current loaded runtime.");
        }

        return actualHost;
    }

    private static bool IsOrdinaryFile(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        var attributes = File.GetAttributes(path);
        return (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0;
    }

    private static async Task AssertProcessExited(int processId)
    {
        Assert.True(
            await WaitForProcessExit(processId, TimeSpan.FromSeconds(2)),
            "coverage process remained alive after timeout cleanup");
    }

    private static async Task<bool> WaitForProcessExit(int processId, TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < timeout)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited)
                {
                    return true;
                }
            }
            catch (ArgumentException)
            {
                return true;
            }

            await Task.Delay(20);
        }

        return false;
    }

    private static void TryKillProcess(int processId)
    {
        if (processId <= 0)
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (ArgumentException)
        {
        }
    }

    private static void WriteFlushed(string path, string value)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        using var writer = new StreamWriter(stream, leaveOpen: true);
        writer.Write(value);
        writer.Flush();
        stream.Flush(flushToDisk: true);
    }

    private sealed class CancellingCoverageProjectRunner : ICoverageProjectRunner
    {
        public bool CancellationObserved { get; private set; }

        public async Task<CoverageProcessOutput> RunAsync(
            CoverageProjectRun run,
            CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("unreachable");
            }
            catch (OperationCanceledException)
            {
                CancellationObserved = true;
                throw new InvalidOperationException("cleanup_failure_must_not_replace_timeout");
            }
        }
    }

    private sealed class SynchronouslyBlockingCoverageProjectRunner : ICoverageProjectRunner
    {
        private readonly ManualResetEventSlim _release = new(initialState: false);

        public ManualResetEventSlim Entered { get; } = new(initialState: false);

        public Task<CoverageProcessOutput> RunAsync(
            CoverageProjectRun run,
            CancellationToken cancellationToken)
        {
            Entered.Set();
            _release.Wait();
            return WaitForCancellation(cancellationToken);
        }

        public void Release() => _release.Set();

        private static async Task<CoverageProcessOutput> WaitForCancellation(CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class AdvancingCoverageProjectRunner(
        ControllableCoverageTimeProvider clock,
        TimeSpan elapsedPerProject) : ICoverageProjectRunner
    {
        private readonly RecordingCoverageProjectRunner _inner = new();

        public int CompletedProjects { get; private set; }

        public async Task<CoverageProcessOutput> RunAsync(
            CoverageProjectRun run,
            CancellationToken cancellationToken)
        {
            var result = await _inner.RunAsync(run, cancellationToken);
            CompletedProjects++;
            clock.Advance(elapsedPerProject);
            return result;
        }
    }

    private sealed class AdvanceOnFinalProjectRunner(
        ControllableCoverageTimeProvider clock,
        TimeSpan advance) : ICoverageProjectRunner
    {
        private readonly RecordingCoverageProjectRunner _inner = new();
        private readonly TaskCompletionSource _advanced = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CompletedProjects { get; private set; }
        public Task Advanced => _advanced.Task;

        public async Task<CoverageProcessOutput> RunAsync(
            CoverageProjectRun run,
            CancellationToken cancellationToken)
        {
            var result = await _inner.RunAsync(run, cancellationToken);
            CompletedProjects++;
            if (CompletedProjects == CoverageRunContract.Projects.Length)
            {
                _ = Task.Run(() =>
                {
                    var stdout = Path.Combine(run.ResultsDirectory, "stdout.txt");
                    if (!SpinWait.SpinUntil(() => File.Exists(stdout), TimeSpan.FromSeconds(1)))
                    {
                        _advanced.TrySetException(new TimeoutException("stdout_not_created"));
                        return;
                    }

                    clock.Advance(advance);
                    _advanced.TrySetResult();
                });
                result = result with { StandardOutput = new string('x', 8 * 1024 * 1024) };
            }

            return result;
        }
    }

    private sealed class ControllableCoverageTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private readonly Lock _lock = new();
        private readonly List<ControlledTimer> _timers = [];
        private DateTimeOffset _now = now;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow()
        {
            lock (_lock)
            {
                return _now;
            }
        }

        public override long GetTimestamp() => GetUtcNow().UtcTicks;

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            ArgumentNullException.ThrowIfNull(callback);
            var timer = new ControlledTimer(this, callback, state, dueTime, period);
            lock (_lock)
            {
                _timers.Add(timer);
            }

            return timer;
        }

        public void Advance(TimeSpan elapsed)
        {
            if (elapsed < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(elapsed));
            }

            List<(TimerCallback Callback, object? State)> callbacks = [];
            lock (_lock)
            {
                _now += elapsed;
                foreach (var timer in _timers.ToArray())
                {
                    timer.CollectDueCallbacks(_now, callbacks);
                }
            }

            foreach (var (callback, state) in callbacks)
            {
                callback(state);
            }
        }

        private sealed class ControlledTimer : ITimer
        {
            private readonly ControllableCoverageTimeProvider _owner;
            private readonly TimerCallback _callback;
            private readonly object? _state;
            private DateTimeOffset? _dueAt;
            private TimeSpan _period;
            private bool _disposed;

            public ControlledTimer(
                ControllableCoverageTimeProvider owner,
                TimerCallback callback,
                object? state,
                TimeSpan dueTime,
                TimeSpan period)
            {
                _owner = owner;
                _callback = callback;
                _state = state;
                _period = period;
                _dueAt = DueAt(owner._now, dueTime);
            }

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (_owner._lock)
                {
                    if (_disposed)
                    {
                        return false;
                    }

                    _period = period;
                    _dueAt = DueAt(_owner._now, dueTime);
                    return true;
                }
            }

            public void Dispose()
            {
                lock (_owner._lock)
                {
                    _disposed = true;
                    _owner._timers.Remove(this);
                }
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }

            public void CollectDueCallbacks(
                DateTimeOffset current,
                List<(TimerCallback Callback, object? State)> callbacks)
            {
                if (_disposed || _dueAt is null || current < _dueAt)
                {
                    return;
                }

                callbacks.Add((_callback, _state));
                _dueAt = _period is { Ticks: > 0 } && _period != Timeout.InfiniteTimeSpan
                    ? current + _period
                    : null;
            }

            private static DateTimeOffset? DueAt(DateTimeOffset current, TimeSpan dueTime) =>
                dueTime == Timeout.InfiniteTimeSpan ? null : current + dueTime;
        }
    }

    private sealed class RecordingCoverageProjectRunner(string? sensitiveArtifact = null) : ICoverageProjectRunner
    {
        public List<string> ProjectFiles { get; } = [];

        public Task<CoverageProcessOutput> RunAsync(CoverageProjectRun run, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProjectFiles.Add(run.ProjectFile.Replace(Path.DirectorySeparatorChar, '/'));
            Directory.CreateDirectory(run.ResultsDirectory);
            var trx = Trx(run.ProjectName, sensitiveArtifact);
            File.WriteAllText(Path.Combine(run.ResultsDirectory, run.TrxFileName), trx);
            var collector = Directory.CreateDirectory(Path.Combine(run.ResultsDirectory, "collector"));
            File.WriteAllText(
                Path.Combine(collector.FullName, "coverage.cobertura.xml"),
                ReportForProject(
                    sensitiveArtifact == "wrong-coverage-project" && run.ProjectName == ExpectedProjects[1]
                        ? ExpectedProjects[0]
                        : run.ProjectName,
                    sensitiveArtifact == "coverage"));
            return Task.FromResult(new CoverageProcessOutput(
                0,
                sensitiveArtifact == "stdout" ? "SSA_SYNTHETIC_TOKEN_MARKER" : "clean test output",
                sensitiveArtifact == "stderr" ? "SSA_SYNTHETIC_TOKEN_MARKER" : string.Empty));
        }

        private static string Trx(string project, string? sensitiveArtifact) =>
            "<TestRun xmlns=\"http://microsoft.com/schemas/VisualStudio/TeamTest/2010\" name=\"" +
            (sensitiveArtifact == "trx-root-name" ? "SSA_SYNTHETIC_TOKEN_MARKER" : "clean run") +
            "\" runUser=\"" +
            (sensitiveArtifact == "trx-root-run-user" ? "SSA_SYNTHETIC_TOKEN_MARKER" : "clean user") +
            "\">" +
            "<TestDefinitions><UnitTest name=\"" +
            (sensitiveArtifact == "trx-definition-name" ? "SSA_SYNTHETIC_TOKEN_MARKER" : "clean definition") +
            "\" storage=\"/controlled/" + project + ".dll\" /></TestDefinitions>" +
            "<Results><UnitTestResult testName=\"" +
            (sensitiveArtifact == "trx-test-name" ? "SSA_SYNTHETIC_TOKEN_MARKER" : "clean result") +
            "\" outcome=\"Passed\"><Output><StdOut>" +
            (sensitiveArtifact == "trx" ? "SSA_SYNTHETIC_TOKEN_MARKER" : "clean") +
            "</StdOut></Output></UnitTestResult></Results>" +
            "<ResultSummary outcome=\"Completed\"><Counters total=\"1\" executed=\"1\" passed=\"1\" failed=\"0\" error=\"0\" timeout=\"0\" aborted=\"0\" notExecuted=\"0\" /></ResultSummary>" +
            "</TestRun>";

        private static string ReportForProject(string project, bool sensitive)
        {
            var identity = Package(
                project,
                project + ".CoverageIdentity",
                1,
                1,
                "tests/" + project + "/CoverageIdentity.cs");
            var report = ValidReport().Replace("</packages>", identity + "</packages>", StringComparison.Ordinal);
            return sensitive
                ? report.Replace("<coverage>", "<coverage><!-- SSA_SYNTHETIC_TOKEN_MARKER -->", StringComparison.Ordinal)
                : report;
        }
    }

    private static string Report(params string[] packages) =>
        "<coverage><packages>" + string.Concat(packages) + "</packages></coverage>";

    private static (int Covered, int Total, int BasisPoints) Result(
        IReadOnlyDictionary<string, CoverageResult> summary,
        string target)
    {
        var result = summary[target];
        return (result.CoveredLines, result.TotalLines, result.BasisPoints);
    }

    private static string Package(
        string name,
        string className,
        int covered,
        int total,
        string? fileName = null)
    {
        var lines = string.Concat(Enumerable.Range(1, total).Select(line =>
            $"<line number=\"{line}\" hits=\"{(line <= covered ? 1 : 0)}\"/>"));
        return $"<package name=\"{name}\"><classes><class name=\"{className}\" filename=\"{fileName ?? $"src/{name}/Sample.cs"}\"><lines>{lines}</lines></class></classes></package>";
    }
}
