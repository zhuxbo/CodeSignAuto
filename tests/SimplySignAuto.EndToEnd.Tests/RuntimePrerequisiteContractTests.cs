using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SimplySignAuto.App.Commands;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class RuntimePrerequisiteContractTests
{
    public static TheoryData<
        string,
        byte,
        uint,
        int,
        string,
        bool,
        bool,
        string?> WindowsSupportCases => new()
    {
        { "windows-10-enterprise-2016-ltsb", 1, 125u, 14393, "Client", true, true, null },
        { "windows-10-enterprise-2019-ltsc", 1, 125u, 17763, "Client", true, true, null },
        { "windows-10-enterprise-ltsc-2021", 1, 125u, 19044, "Client", true, true, null },
        { "windows-10-iot-enterprise-ltsc-2021", 1, 191u, 19044, "Client", true, true, null },
        { "windows-10-home-22h2", 1, 101u, 19045, "Client", true, true, null },
        { "windows-10-pro-22h2", 1, 48u, 19045, "Client", true, true, null },
        { "windows-11-enterprise-23h2", 1, 4u, 22631, "Client", true, true, null },
        { "windows-11-enterprise-24h2", 1, 4u, 26100, "Client", true, true, null },
        { "windows-11-pro-25h2", 1, 48u, 26200, "Client", true, true, null },
        { "windows-11-home-supported-build", 1, 101u, 28000, "Client", true, true, null },
        { "windows-server-2019-datacenter", 3, 8u, 17763, "Server", true, true, null },
        { "windows-server-2022-standard", 3, 7u, 20348, "Server", true, true, null },
        { "windows-server-2025-datacenter", 3, 8u, 26100, "Server", true, true, null },
        { "windows-10-pro-21h2", 1, 48u, 19044, "Client", true, false, "os_unsupported" },
        { "windows-11-pro-21h2", 1, 48u, 22000, "Client", true, false, "os_unsupported" },
        { "windows-11-pro-22h2", 1, 48u, 22621, "Client", true, false, "os_unsupported" },
        { "server-with-client-sku", 3, 48u, 26100, "Server", true, false, "os_unsupported" },
        { "client-with-server-sku", 1, 8u, 26100, "Client", true, false, "os_unsupported" },
        { "client-product-with-server-installation", 1, 48u, 26100, "Server", true, false, "os_unsupported" },
        { "server-core", 3, 8u, 26100, "Server Core", true, false, "desktop_experience_required" },
        { "domain-controller-product-type", 2, 8u, 26100, "Server", true, false, "os_unsupported" },
        { "unknown-client-sku", 1, 0u, 26100, "Client", true, false, "os_unsupported" },
        { "unknown-server-build", 3, 8u, 26000, "Server", true, false, "os_unsupported" },
        { "x86-operating-system", 1, 48u, 19045, "Client", false, false, "architecture_unsupported" },
    };

    [Theory]
    [MemberData(nameof(WindowsSupportCases))]
    public void Inner_windows_policy_matches_the_published_support_matrix(
        string _,
        byte productType,
        uint operatingSystemSku,
        int buildNumber,
        string installationType,
        bool is64BitOperatingSystem,
        bool expectedSupported,
        string? expectedFailureCode)
    {
        Assert.Equal(expectedSupported, expectedFailureCode is null);
        var snapshot = new WindowsSupportSnapshot(
            productType,
            operatingSystemSku,
            buildNumber,
            installationType,
            is64BitOperatingSystem);

        Assert.Equal(expectedSupported, WindowsSupportPolicy.IsSupported(snapshot));
    }

    [Fact]
    public void Native_windows_snapshot_reader_recognizes_the_supported_build_host()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var snapshot = WindowsSupportSnapshotReader.Read();

        Assert.Equal(Environment.Is64BitOperatingSystem, snapshot.Is64BitOperatingSystem);
        Assert.True(
            WindowsSupportPolicy.IsSupported(snapshot),
            $"Unsupported build host: ProductType={snapshot.ProductType}, " +
            $"SKU={snapshot.OperatingSystemSku}, Build={snapshot.BuildNumber}, " +
            $"InstallationType={snapshot.InstallationType}");
    }

    [Fact]
    public void Runtime_manifest_is_an_exact_unpinned_major_roll_forward_policy()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(ManifestPath()));
        var root = document.RootElement;

        Assert.Equal(
            [
                "architecture",
                "minimumMajor",
                "rollForward",
                "runtimes",
                "schemaVersion",
            ],
            root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("x64", root.GetProperty("architecture").GetString());
        Assert.Equal(10, root.GetProperty("minimumMajor").GetInt32());
        Assert.Equal("Major", root.GetProperty("rollForward").GetString());

        var runtimes = root.GetProperty("runtimes").EnumerateArray().ToArray();
        Assert.Equal(2, runtimes.Length);
        Assert.Equal(
            ["Microsoft.AspNetCore.App", "Microsoft.WindowsDesktop.App"],
            runtimes.Select(item => item.GetProperty("name").GetString()).Order(StringComparer.Ordinal));
        foreach (var runtime in runtimes)
        {
            Assert.Equal(
                ["name"],
                runtime.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
        }

    }

    [Fact]
    public void Default_invocation_resolves_the_manifest_beside_the_script_after_parameter_binding()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create(["10.0.10"], ["10.0.10"]);

        var result = fixture.Run(useDefaultManifestPath: true);

        AssertSuccess(result);
    }

    [Fact]
    public void Published_checker_contains_no_contract_test_bypass()
    {
        var script = File.ReadAllText(ScriptPath());

        Assert.DoesNotContain("TestScenarioPath", script, StringComparison.Ordinal);
        Assert.DoesNotContain("TestScenario", script, StringComparison.Ordinal);
        Assert.DoesNotContain("tracePath", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Add-TestTrace", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Invoke-TestDownload", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-TestDownloadPlan", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Published_checker_never_downloads_or_installs_runtimes()
    {
        var script = File.ReadAllText(ScriptPath());

        Assert.DoesNotContain("Invoke-HttpDownload", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Invoke-InstallerProcess", script, StringComparison.Ordinal);
        Assert.DoesNotContain("releaseMetadataUrl", script, StringComparison.Ordinal);
        Assert.DoesNotContain("installerName", script, StringComparison.Ordinal);
        Assert.DoesNotContain("SecureDownloadDirectory", script, StringComparison.Ordinal);
        Assert.Contains(
            "operatingSystemSku = [uint32]$operatingSystem.OperatingSystemSKU",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Install_mode_is_forwarded_through_elevation_and_the_exact_internal_setup_route()
    {
        var script = File.ReadAllText(ScriptPath());

        Assert.Contains("[ValidateSet('manual', 'service')]", script, StringComparison.Ordinal);
        Assert.Contains("'-InstallMode', $Mode", script, StringComparison.Ordinal);
        Assert.Contains("-Mode $InstallMode", script, StringComparison.Ordinal);
        Assert.Contains(
            "& $applicationPath setup --mode $InstallMode",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Contract_fixture_loads_overrides_only_in_its_temporary_script_copy()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create(["10.0.10"], ["10.0.10"]);

        var result = fixture.Run();

        AssertSuccess(result);
        Assert.Contains("harness_loaded", result.Trace, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("duplicate", "\"schemaVersion\": 1,")]
    [InlineData("unknown", "\"unexpected\": true,")]
    [InlineData("pinned-minor", "\"minimumMinor\": 1,")]
    [InlineData("pinned-patch", "\"minimumPatch\": 2,")]
    [InlineData("pinned-installer", "\"installerUrl\": \"https://builds.dotnet.microsoft.com/fixed.exe\",")]
    public void Strict_manifest_rejects_duplicate_unknown_and_pinned_fields(string _, string insertion)
    {
        RequireWindows();
        var manifest = File.ReadAllText(ManifestPath());
        manifest = "{" + insertion + manifest[1..];
        using var fixture = ScriptFixture.Create(installedDesktop: ["10.0.10"], installedAspNet: ["10.0.10"]);

        var result = fixture.Run(manifest);

        AssertFailure(result, "manifest", "manifest_invalid");
    }

    [Theory]
    [InlineData("10.0.0", "10.0.10")]
    [InlineData("12.1.4", "11.0.2")]
    public void Installed_stable_major_ten_or_newer_is_ready(string desktop, string aspNet)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([desktop], [aspNet]);

        var result = fixture.Run();

        AssertSuccess(result);
        Assert.Contains("probe", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("download", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("install", result.Trace, StringComparison.Ordinal);
    }

    [Fact]
    public void Domain_member_server_2025_desktop_experience_is_supported()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create(["10.0.10"], ["10.0.10"]);
        fixture.Machine["domainRole"] = 2;

        AssertSuccess(fixture.Run());
    }

    [Theory]
    [MemberData(nameof(WindowsSupportCases))]
    public void Published_prerequisite_checker_matches_the_shared_windows_support_matrix(
        string _,
        byte productType,
        uint operatingSystemSku,
        int buildNumber,
        string installationType,
        bool is64BitOperatingSystem,
        bool expectedSupported,
        string? expectedFailureCode)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create(["10.0.10"], ["10.0.10"]);
        fixture.Machine["productType"] = productType;
        fixture.Machine["operatingSystemSku"] = operatingSystemSku;
        fixture.Machine["buildNumber"] = buildNumber.ToString(System.Globalization.CultureInfo.InvariantCulture);
        fixture.Machine["installationType"] = installationType;
        fixture.Machine["is64BitOperatingSystem"] = is64BitOperatingSystem;

        var result = fixture.Run();
        if (expectedSupported)
        {
            AssertSuccess(result);
        }
        else
        {
            AssertFailure(result, "preflight", Assert.IsType<string>(expectedFailureCode));
        }
    }

    [Theory]
    [InlineData("domain-controller", "domainRole", 4, "domain_controller_unsupported")]
    [InlineData("backup-domain-controller", "domainRole", 5, "domain_controller_unsupported")]
    [InlineData("not-elevated", "elevated", false, "elevation_required")]
    [InlineData("wrong-process-architecture", "is64BitProcess", false, "architecture_unsupported")]
    [InlineData("invalid-os-sku", "operatingSystemSku", "invalid", "machine_lookup_failed")]
    [InlineData("server-core", "installationType", "Server Core", "desktop_experience_required")]
    [InlineData("simplysign-missing", "simplySignDesktopExists", false, "simplysign_desktop_missing")]
    [InlineData("pkcs11-missing", "pkcs11Exists", false, "simplysign_pkcs11_missing")]
    [InlineData("lookup-failed", "lookupFailure", true, "machine_lookup_failed")]
    public void Machine_preflight_fails_closed_before_network(
        string _,
        string property,
        object value,
        string expectedCode)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);
        fixture.Machine[property] = value;

        var result = fixture.Run();

        AssertFailure(result, "preflight", expectedCode);
        Assert.DoesNotContain("download", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("install", result.Trace, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_one_runtime_is_rejected_before_probe_or_product_setup()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);

        var result = fixture.Run();

        AssertFailure(result, "detection", "required_runtime_missing");
        Assert.DoesNotContain("download", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("install", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("probe", result.Trace, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_both_runtimes_is_rejected_before_probe_or_product_setup()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);

        var result = fixture.Run();

        AssertFailure(result, "detection", "required_runtime_missing");
        Assert.DoesNotContain("download", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("install", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("probe", result.Trace, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(23, "1.0.0\n", false, "probe_failed")]
    [InlineData(0, "not-a-version\n", false, "probe_output_invalid")]
    [InlineData(0, "1.0.0\n", true, "probe_timeout")]
    public void Framework_graph_probe_is_strict_and_failure_safe(
        int exitCode,
        string output,
        bool timedOut,
        string expectedCode)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create(["10.0.10"], ["10.0.10"]);
        fixture.Probe["exitCode"] = exitCode;
        fixture.Probe["stdout"] = output;
        fixture.Probe["timedOut"] = timedOut;

        AssertFailure(fixture.Run(), "probe", expectedCode);
    }

    private static void AssertSuccess(ScriptResult result)
    {
        Assert.True(
            result.ExitCode == 0,
            $"Expected exit 0, got {result.ExitCode}. Output={result.AllOutput} Trace={result.Trace}");
        Assert.Contains("phase=complete code=ready", result.OutputLines);
        AssertStableOutput(result);
    }

    private static void AssertFailure(ScriptResult result, string phase, string code)
    {
        Assert.True(
            result.ExitCode == 1,
            $"Expected exit 1, got {result.ExitCode}. Output={result.AllOutput} Trace={result.Trace}");
        Assert.Contains($"phase={phase} code={code}", result.OutputLines);
        AssertStableOutput(result);
        AssertNoProductSetup(result);
    }

    private static void AssertStableOutput(ScriptResult result)
    {
        Assert.All(
            result.OutputLines,
            line => Assert.Matches("^phase=[a-z_]+ code=[a-z0-9_]+$", line));
        Assert.DoesNotContain("test-secret-marker", result.AllOutput, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", result.AllOutput, StringComparison.OrdinalIgnoreCase);
    }

    private static void AssertNoProductSetup(ScriptResult result) =>
        Assert.DoesNotContain("product_setup", result.Trace, StringComparison.Ordinal);

    private static int Count(string value, string needle)
    {
        var count = 0;
        var offset = 0;
        while ((offset = value.IndexOf(needle, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += needle.Length;
        }

        return count;
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
    }

    private static string RepositoryRoot() => Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    private static string ManifestPath() =>
        Path.Combine(RepositoryRoot(), "packaging", "runtime-prerequisites.json");

    private static string ScriptPath() =>
        Path.Combine(RepositoryRoot(), "packaging", "install-prerequisites.ps1");

    private sealed class ScriptFixture : IDisposable
    {
        private readonly string _root;
        private readonly string _tracePath;
        private readonly Dictionary<string, object?> _scenario;

        private ScriptFixture(
            string root,
            string tracePath,
            Dictionary<string, object?> scenario,
            Dictionary<string, object?> machine,
            Dictionary<string, object?> probe)
        {
            _root = root;
            _tracePath = tracePath;
            _scenario = scenario;
            Machine = machine;
            Probe = probe;
        }

        public Dictionary<string, object?> Machine { get; }
        public Dictionary<string, object?> Probe { get; }

        public static ScriptFixture Create(string[] installedDesktop, string[] installedAspNet)
        {
            var root = Path.Combine(Path.GetTempPath(), $"ssa-prerequisite-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var tracePath = Path.Combine(root, "trace.txt");
            var machine = new Dictionary<string, object?>
            {
                ["is64BitOperatingSystem"] = true,
                ["is64BitProcess"] = true,
                ["caption"] = "Microsoft Windows Server 2025 Datacenter",
                ["productType"] = 3,
                ["operatingSystemSku"] = 8u,
                ["buildNumber"] = "26100",
                ["installationType"] = "Server",
                ["domainRole"] = 2,
                ["elevated"] = true,
                ["simplySignDesktopExists"] = true,
                ["pkcs11Exists"] = true,
                ["lookupFailure"] = false,
            };
            var installed = RuntimeMap(installedDesktop, installedAspNet);
            var probe = new Dictionary<string, object?>
            {
                ["exitCode"] = 0,
                ["stdout"] = "1.0.0\n",
                ["timedOut"] = false,
                ["processTreeTerminated"] = true,
            };

            var scenario = new Dictionary<string, object?>
            {
                ["machine"] = machine,
                ["installed"] = installed,
                ["probe"] = probe,
            };
            return new ScriptFixture(
                root,
                tracePath,
                scenario,
                machine,
                probe);
        }

        public ScriptResult Run(string? manifestOverride = null, bool useDefaultManifestPath = false)
        {
            var scenarioPath = Path.Combine(_root, "scenario.json");
            var harnessPath = Path.Combine(_root, "install-prerequisites.contract.ps1");
            var adjacentManifestPath = Path.Combine(_root, "runtime-prerequisites.json");
            File.Copy(ManifestPath(), adjacentManifestPath, overwrite: true);
            var manifestPath = ManifestPath();
            if (manifestOverride is not null)
            {
                manifestPath = Path.Combine(_root, "manifest.json");
                File.WriteAllText(manifestPath, manifestOverride, new UTF8Encoding(false));
            }

            File.WriteAllText(
                scenarioPath,
                JsonSerializer.Serialize(_scenario),
                new UTF8Encoding(false));
            File.WriteAllText(
                harnessPath,
                BuildHarnessScript(scenarioPath, _tracePath),
                new UTF8Encoding(false));

            var start = new ProcessStartInfo
            {
                FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add("-NoLogo");
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-ExecutionPolicy");
            start.ArgumentList.Add("Bypass");
            start.ArgumentList.Add("-File");
            start.ArgumentList.Add(harnessPath);
            if (!useDefaultManifestPath)
            {
                start.ArgumentList.Add("-ManifestPath");
                start.ArgumentList.Add(manifestPath);
            }
            start.Environment["SSA_TEST_SECRET"] = "test-secret-marker";

            using var process = Process.Start(start) ?? throw new InvalidOperationException("PowerShell did not start.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            Assert.True(process.WaitForExit(30_000), "Prerequisite script timed out.");
            var allOutput = stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult();
            var outputLines = allOutput
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var trace = File.Exists(_tracePath) ? File.ReadAllText(_tracePath) : string.Empty;
            return new ScriptResult(process.ExitCode, outputLines, allOutput, trace);
        }

        private static string BuildHarnessScript(string scenarioPath, string tracePath)
        {
            var publishedScript = File.ReadAllText(ScriptPath());
            var newLine = publishedScript.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var entryMarker = string.Join(
                newLine,
                "$result = 1",
                "try {",
                "    if ($VerifyMediaOnly -and [string]::IsNullOrWhiteSpace($ReleaseMediaRoot)) {");
            Assert.Equal(1, Count(publishedScript, entryMarker));
            var entryOffset = publishedScript.IndexOf(entryMarker, StringComparison.Ordinal);
            Assert.True(entryOffset >= 0, "The published checker entry point was not found.");

            var scenarioLiteral = PowerShellLiteral(scenarioPath);
            var traceLiteral = PowerShellLiteral(tracePath);
            var overrides = $$"""
                $script:ContractScenario = ConvertFrom-Json -InputObject (Get-Content -LiteralPath '{{scenarioLiteral}}' -Raw)
                $script:ContractTracePath = '{{traceLiteral}}'

                function Write-ContractTrace {
                    param([Parameter(Mandatory = $true)][string]$Value)
                    Add-Content -LiteralPath $script:ContractTracePath -Value $Value -Encoding UTF8
                }

                function Get-MachineSnapshot {
                    return $script:ContractScenario.machine
                }

                function Get-InstalledRuntimeVersions {
                    param([Parameter(Mandatory = $true)][string]$RuntimeName)
                    $property = $script:ContractScenario.installed.PSObject.Properties[$RuntimeName]
                    if ($null -eq $property) { return @() }
                    return @($property.Value)
                }

                function Invoke-PrerequisiteProbe {
                    Write-ContractTrace 'probe'
                    $probe = $script:ContractScenario.probe
                    if ([bool]$probe.timedOut) {
                        if (-not [bool]$probe.processTreeTerminated) {
                            Stop-PrerequisiteCheck 'probe' 'process_cleanup_failed'
                        }
                        Write-ContractTrace 'kill_tree'
                        Stop-PrerequisiteCheck 'probe' 'probe_timeout'
                    }
                    if ([int]$probe.exitCode -ne 0) {
                        Stop-PrerequisiteCheck 'probe' 'probe_failed'
                    }
                    if (-not (Test-StrictVersionOutput ([string]$probe.stdout))) {
                        Stop-PrerequisiteCheck 'probe' 'probe_output_invalid'
                    }
                }

                Write-ContractTrace 'harness_loaded'

                """ + Environment.NewLine;

            var harness = publishedScript.Insert(entryOffset, overrides);
            Assert.True(
                harness.IndexOf("Write-ContractTrace 'harness_loaded'", StringComparison.Ordinal) <
                harness.IndexOf(entryMarker, StringComparison.Ordinal),
                "The fixture overrides must load before the published checker entry point.");
            const string exitMarker = "exit $result";
            Assert.Equal(1, Count(harness, exitMarker));
            harness = harness.Replace(
                exitMarker,
                "$resultType = if ($null -eq $result) { 'null' } else { $result.GetType().FullName }" + newLine +
                "Write-ContractTrace (\"result:{0}:{1}\" -f $resultType, ($result -join ','))" + newLine +
                exitMarker,
                StringComparison.Ordinal);
            return harness;
        }

        private static string PowerShellLiteral(string value) => value.Replace("'", "''", StringComparison.Ordinal);

        public void Dispose()
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static Dictionary<string, object?> RuntimeMap(string[] desktop, string[] aspNet) => new()
        {
            ["Microsoft.WindowsDesktop.App"] = desktop,
            ["Microsoft.AspNetCore.App"] = aspNet,
        };

    }

    private sealed record ScriptResult(
        int ExitCode,
        string[] OutputLines,
        string AllOutput,
        string Trace);
}
