using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class RuntimePrerequisiteContractTests
{
    private const string MetadataUrl =
        "https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json";
    private const string MicrosoftSubject =
        "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    [Fact]
    public void Runtime_manifest_is_an_exact_unpinned_major_roll_forward_policy()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(ManifestPath()));
        var root = document.RootElement;

        Assert.Equal(
            [
                "allowedSignerSubjects",
                "approvedHosts",
                "architecture",
                "maximumInstallerBytes",
                "maximumMetadataBytes",
                "minimumMajor",
                "releaseMetadataUrl",
                "rollForward",
                "runtimes",
                "schemaVersion",
            ],
            root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("x64", root.GetProperty("architecture").GetString());
        Assert.Equal(10, root.GetProperty("minimumMajor").GetInt32());
        Assert.Equal("Major", root.GetProperty("rollForward").GetString());
        Assert.Equal(MetadataUrl, root.GetProperty("releaseMetadataUrl").GetString());
        Assert.Equal(2 * 1024 * 1024, root.GetProperty("maximumMetadataBytes").GetInt32());
        Assert.Equal(128 * 1024 * 1024, root.GetProperty("maximumInstallerBytes").GetInt32());
        Assert.Equal(
            ["builds.dotnet.microsoft.com"],
            root.GetProperty("approvedHosts").EnumerateArray().Select(item => item.GetString()));
        Assert.Equal(
            [MicrosoftSubject],
            root.GetProperty("allowedSignerSubjects").EnumerateArray().Select(item => item.GetString()));

        var runtimes = root.GetProperty("runtimes").EnumerateArray().ToArray();
        Assert.Equal(2, runtimes.Length);
        Assert.Equal(
            ["Microsoft.AspNetCore.App", "Microsoft.WindowsDesktop.App"],
            runtimes.Select(item => item.GetProperty("name").GetString()).Order(StringComparer.Ordinal));
        Assert.Equal(
            ["aspnetcore-runtime", "windowsdesktop"],
            runtimes.Select(item => item.GetProperty("metadataProperty").GetString()).Order(StringComparer.Ordinal));
        Assert.Equal(
            ["aspnetcore-runtime-win-x64.exe", "windowsdesktop-runtime-win-x64.exe"],
            runtimes.Select(item => item.GetProperty("installerName").GetString()).Order(StringComparer.Ordinal));
        foreach (var runtime in runtimes)
        {
            Assert.Equal(
                ["installerName", "metadataProperty", "name"],
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
    public void Published_checker_fixes_installer_and_http_security_arguments()
    {
        var script = File.ReadAllText(ScriptPath());

        Assert.Contains("-ArgumentList @('/install', '/passive', '/norestart')", script, StringComparison.Ordinal);
        Assert.Contains("$request.AllowAutoRedirect = $false", script, StringComparison.Ordinal);
        Assert.Contains("$request.UseDefaultCredentials = $false", script, StringComparison.Ordinal);
        Assert.Contains("$request.Credentials = $null", script, StringComparison.Ordinal);
        Assert.Contains("$request.PreAuthenticate = $false", script, StringComparison.Ordinal);
        Assert.Contains("$request.Proxy = $null", script, StringComparison.Ordinal);
        Assert.Contains("Test-ApprovedHttpsUri $next $ApprovedHosts", script, StringComparison.Ordinal);
        Assert.Contains(
            "operatingSystemSku = [uint32]$operatingSystem.OperatingSystemSKU",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Published_http_download_has_a_total_deadline_for_slow_drip_responses()
    {
        var script = File.ReadAllText(ScriptPath());

        Assert.Contains("$downloadWatch = [Diagnostics.Stopwatch]::StartNew()", script, StringComparison.Ordinal);
        Assert.Contains("$totalTimeoutMilliseconds = 120000", script, StringComparison.Ordinal);
        Assert.Contains("$inputStream.ReadTimeout = $remainingMilliseconds", script, StringComparison.Ordinal);
        Assert.Contains("Stop-PrerequisiteCheck 'download' 'download_timeout'", script, StringComparison.Ordinal);
        Assert.True(
            Count(script, "$downloadWatch.ElapsedMilliseconds") >= 3,
            "The total deadline must guard requests, redirects, and the response read loop.");
    }

    [Fact]
    public void Published_http_download_forces_process_local_tls12_before_request_creation()
    {
        var script = File.ReadAllText(ScriptPath());
        const string tls12 =
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12";
        const string requestCreation = "$request = [System.Net.HttpWebRequest]::CreateHttp($current)";

        Assert.Equal(1, Count(script, tls12));
        Assert.Equal(1, Count(script, requestCreation));
        Assert.True(
            script.IndexOf(tls12, StringComparison.Ordinal) <
            script.IndexOf(requestCreation, StringComparison.Ordinal),
            "TLS 1.2 must be fixed process-locally before the first real HTTP request.");
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
    [InlineData("Microsoft Windows 10 Enterprise 2016 LTSB", 1, 125u, "14393", "Client", 1)]
    [InlineData("Microsoft Windows 10 Enterprise 2019 LTSC", 1, 125u, "17763", "Client", 1)]
    [InlineData("Microsoft Windows 10 Enterprise LTSC 2021", 1, 125u, "19044", "Client", 1)]
    [InlineData("Microsoft Windows 10 IoT Enterprise LTSC 2021", 1, 191u, "19044", "Client", 1)]
    [InlineData("Microsoft Windows 11 Enterprise", 1, 4u, "22631", "Client", 1)]
    [InlineData("Microsoft Windows 11 Enterprise", 1, 4u, "26100", "Client", 1)]
    [InlineData("Microsoft Windows 11 Pro", 1, 48u, "26200", "Client", 1)]
    [InlineData("Microsoft Windows 11 Home", 1, 101u, "28000", "Client", 1)]
    [InlineData("Microsoft Windows Server 2019 数据中心版", 3, 8u, "17763", "Server", 3)]
    [InlineData("Microsoft Windows Server 2022 标准版", 3, 7u, "20348", "Server", 3)]
    public void Supported_windows_client_and_server_matrix_is_ready(
        string caption,
        int productType,
        uint operatingSystemSku,
        string buildNumber,
        string installationType,
        int domainRole)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create(["10.0.10"], ["10.0.10"]);
        fixture.Machine["caption"] = caption;
        fixture.Machine["productType"] = productType;
        fixture.Machine["operatingSystemSku"] = operatingSystemSku;
        fixture.Machine["buildNumber"] = buildNumber;
        fixture.Machine["installationType"] = installationType;
        fixture.Machine["domainRole"] = domainRole;

        AssertSuccess(fixture.Run());
    }

    [Theory]
    [InlineData("Microsoft Windows 10 Pro", 48u, "19045")]
    [InlineData("Microsoft Windows 10 Pro", 48u, "19044")]
    [InlineData("Microsoft Windows 11 Pro", 48u, "22000")]
    [InlineData("Microsoft Windows 11 Pro", 48u, "22621")]
    public void Unsupported_windows_client_builds_and_editions_are_rejected(
        string caption,
        uint operatingSystemSku,
        string buildNumber)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);
        fixture.Machine["caption"] = caption;
        fixture.Machine["productType"] = 1;
        fixture.Machine["operatingSystemSku"] = operatingSystemSku;
        fixture.Machine["buildNumber"] = buildNumber;
        fixture.Machine["installationType"] = "Client";

        AssertFailure(fixture.Run(), "preflight", "os_unsupported");
    }

    [Theory]
    [InlineData("Microsoft Windows Server 2025 Datacenter", 3, 48u, "26100", "Server")]
    [InlineData("Microsoft Windows 11 Enterprise", 1, 8u, "26100", "Client")]
    public void Mismatched_client_and_server_skus_are_rejected(
        string caption,
        int productType,
        uint operatingSystemSku,
        string buildNumber,
        string installationType)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);
        fixture.Machine["caption"] = caption;
        fixture.Machine["productType"] = productType;
        fixture.Machine["operatingSystemSku"] = operatingSystemSku;
        fixture.Machine["buildNumber"] = buildNumber;
        fixture.Machine["installationType"] = installationType;

        AssertFailure(fixture.Run(), "preflight", "os_unsupported");
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
    public void Missing_one_runtime_installs_only_that_runtime_and_uses_newest_stable_servicing_release()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);

        var result = fixture.Run();

        AssertSuccess(result);
        Assert.Contains("download:windowsdesktop-runtime-win-x64.exe:10.0.11", result.Trace, StringComparison.Ordinal);
        Assert.Contains("install:Microsoft.WindowsDesktop.App:/install /passive /norestart", result.Trace, StringComparison.Ordinal);
        Assert.DoesNotContain("install:Microsoft.AspNetCore.App", result.Trace, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_both_runtimes_installs_both_and_reprobes_the_framework_graph()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);

        var result = fixture.Run();

        AssertSuccess(result);
        Assert.Equal(2, Count(result.Trace, "install:"));
        Assert.Contains("probe", result.Trace, StringComparison.Ordinal);
    }

    [Fact]
    public void Preview_only_metadata_is_rejected()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);
        fixture.UsePreviewOnlyMetadata();

        AssertFailure(fixture.Run(), "metadata", "stable_release_missing");
    }

    [Fact]
    public void Installer_restart_code_is_preserved_as_3010_and_stops_before_product_setup()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);
        fixture.DesktopDownload["installerExitCode"] = 3010;

        var result = fixture.Run();

        Assert.True(
            result.ExitCode == 3010,
            $"Expected exit 3010, got {result.ExitCode}. Output={result.AllOutput} Trace={result.Trace}");
        Assert.Contains("phase=install code=restart_required", result.OutputLines);
        Assert.Contains("result:System.Int32:3010", result.Trace, StringComparison.Ordinal);
        AssertNoProductSetup(result);
    }

    [Theory]
    [InlineData(1602, "install_cancelled")]
    [InlineData(1603, "install_failed")]
    public void Installer_failure_and_cancellation_never_call_product_setup(int exitCode, string expectedCode)
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);
        fixture.DesktopDownload["installerExitCode"] = exitCode;

        var result = fixture.Run();

        AssertFailure(result, "install", expectedCode);
    }

    [Fact]
    public void Metadata_with_wrong_channel_is_rejected()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);
        fixture.Metadata["channel-version"] = "11.0";

        AssertFailure(fixture.Run(), "metadata", "metadata_invalid");
    }

    [Fact]
    public void Published_sha512_mismatch_is_rejected()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);
        fixture.SetDesktopHash(new string('0', 128));

        AssertFailure(fixture.Run(), "download", "hash_mismatch");
    }

    [Fact]
    public void Non_microsoft_or_invalid_authenticode_is_rejected()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);
        fixture.DesktopDownload["signerSubject"] = "CN=Contoso";

        AssertFailure(fixture.Run(), "signature", "signature_invalid");
    }

    [Fact]
    public void Redirect_outside_the_approved_https_hosts_is_rejected_without_forwarding_credentials()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);
        fixture.MetadataDownload["redirectUrl"] = "https://example.invalid/releases.json";

        var result = fixture.Run();

        AssertFailure(result, "download", "redirect_rejected");
        Assert.DoesNotContain("credential", result.AllOutput, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Oversized_response_is_rejected_before_install()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], []);
        fixture.MetadataDownload["reportedLength"] = 2 * 1024 * 1024 + 1;

        AssertFailure(fixture.Run(), "download", "download_too_large");
    }

    [Fact]
    public void Runtime_still_missing_after_install_is_rejected()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);
        fixture.PostInstall["Microsoft.WindowsDesktop.App"] = Array.Empty<string>();

        AssertFailure(fixture.Run(), "detection", "runtime_missing_after_install");
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

    [Fact]
    public void Installer_timeout_terminates_the_process_tree_and_never_calls_product_setup()
    {
        RequireWindows();
        using var fixture = ScriptFixture.Create([], ["10.0.10"]);
        fixture.DesktopDownload["timedOut"] = true;
        fixture.DesktopDownload["processTreeTerminated"] = true;

        var result = fixture.Run();

        AssertFailure(result, "install", "install_timeout");
        Assert.Contains("kill_tree", result.Trace, StringComparison.Ordinal);
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
            Dictionary<string, object?> metadata,
            Dictionary<string, object?> metadataDownload,
            Dictionary<string, object?> desktopDownload,
            Dictionary<string, object?> aspNetDownload,
            Dictionary<string, object?> postInstall,
            Dictionary<string, object?> probe)
        {
            _root = root;
            _tracePath = tracePath;
            _scenario = scenario;
            Machine = machine;
            Metadata = metadata;
            MetadataDownload = metadataDownload;
            DesktopDownload = desktopDownload;
            AspNetDownload = aspNetDownload;
            PostInstall = postInstall;
            Probe = probe;
        }

        public Dictionary<string, object?> Machine { get; }
        public Dictionary<string, object?> Metadata { get; }
        public Dictionary<string, object?> MetadataDownload { get; }
        public Dictionary<string, object?> DesktopDownload { get; }
        public Dictionary<string, object?> AspNetDownload { get; }
        public Dictionary<string, object?> PostInstall { get; }
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
            var postInstall = RuntimeMap(["10.0.11"], ["10.0.11"]);
            var probe = new Dictionary<string, object?>
            {
                ["exitCode"] = 0,
                ["stdout"] = "1.0.0\n",
                ["timedOut"] = false,
                ["processTreeTerminated"] = true,
            };

            var desktopBytes = Encoding.UTF8.GetBytes("desktop-runtime-10.0.11");
            var aspNetBytes = Encoding.UTF8.GetBytes("aspnet-runtime-10.0.11");
            var desktopUrl = InstallerUrl("windowsdesktop", "10.0.11");
            var aspNetUrl = InstallerUrl("aspnetcore-runtime", "10.0.11");
            var metadata = MetadataDocument(
                ("10.0.10", "unused", "unused"),
                ("10.0.11", Sha512(desktopBytes), Sha512(aspNetBytes)));
            var metadataBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(metadata));
            var metadataDownload = DownloadPlan(MetadataUrl, metadataBytes);
            var desktopDownload = DownloadPlan(desktopUrl, desktopBytes, installer: true);
            var aspNetDownload = DownloadPlan(aspNetUrl, aspNetBytes, installer: true);
            var scenario = new Dictionary<string, object?>
            {
                ["machine"] = machine,
                ["installed"] = installed,
                ["postInstall"] = postInstall,
                ["probe"] = probe,
                ["downloads"] = new object[] { metadataDownload, desktopDownload, aspNetDownload },
            };
            return new ScriptFixture(
                root,
                tracePath,
                scenario,
                machine,
                metadata,
                metadataDownload,
                desktopDownload,
                aspNetDownload,
                postInstall,
                probe);
        }

        public void UsePreviewOnlyMetadata()
        {
            Metadata.Clear();
            Metadata["channel-version"] = "10.0";
            Metadata["releases"] = new object[]
            {
                new Dictionary<string, object?> { ["release-version"] = "10.0.12-preview.1" },
            };
        }

        public void SetDesktopHash(string hash)
        {
            var releases = (object[])Metadata["releases"]!;
            var latest = (Dictionary<string, object?>)releases[1];
            var component = (Dictionary<string, object?>)latest["windowsdesktop"]!;
            var files = (object[])component["files"]!;
            ((Dictionary<string, object?>)files[0])["hash"] = hash;
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

            var metadataBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Metadata));
            MetadataDownload["bytesBase64"] = Convert.ToBase64String(metadataBytes);
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
                $script:ContractInstallAttempted = $false
                $script:ContractLastDownload = $null

                function Write-ContractTrace {
                    param([Parameter(Mandatory = $true)][string]$Value)
                    Add-Content -LiteralPath $script:ContractTracePath -Value $Value -Encoding UTF8
                }

                function Get-MachineSnapshot {
                    return $script:ContractScenario.machine
                }

                function Get-InstalledRuntimeVersions {
                    param([Parameter(Mandatory = $true)][string]$RuntimeName)
                    $state = if ($script:ContractInstallAttempted) {
                        $script:ContractScenario.postInstall
                    }
                    else {
                        $script:ContractScenario.installed
                    }
                    $property = $state.PSObject.Properties[$RuntimeName]
                    if ($null -eq $property) { return @() }
                    return @($property.Value)
                }

                function Invoke-HttpDownload {
                    param(
                        [Parameter(Mandatory = $true)][Uri]$Uri,
                        [Parameter(Mandatory = $true)][long]$MaximumBytes,
                        [string]$DestinationPath,
                        [Parameter(Mandatory = $true)][string[]]$ApprovedHosts
                    )

                    $plans = @($script:ContractScenario.downloads | Where-Object {
                        [string]$_.url -ceq $Uri.AbsoluteUri
                    })
                    if ($plans.Count -ne 1) {
                        Stop-PrerequisiteCheck 'download' 'download_failed'
                    }
                    $plan = $plans[0]
                    if (-not [string]::IsNullOrWhiteSpace([string]$plan.redirectUrl)) {
                        try { $next = [Uri]([string]$plan.redirectUrl) }
                        catch { Stop-PrerequisiteCheck 'download' 'redirect_rejected' }
                        if (-not (Test-ApprovedHttpsUri $next $ApprovedHosts)) {
                            Stop-PrerequisiteCheck 'download' 'redirect_rejected'
                        }
                        Stop-PrerequisiteCheck 'download' 'download_failed'
                    }
                    if ([long]$plan.reportedLength -gt $MaximumBytes) {
                        Stop-PrerequisiteCheck 'download' 'download_too_large'
                    }

                    try { $bytes = [Convert]::FromBase64String([string]$plan.bytesBase64) }
                    catch { Stop-PrerequisiteCheck 'download' 'download_failed' }
                    if ($bytes.LongLength -gt $MaximumBytes) {
                        Stop-PrerequisiteCheck 'download' 'download_too_large'
                    }

                    $leafName = if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
                        'releases.json'
                    }
                    else {
                        [IO.Path]::GetFileName($DestinationPath)
                    }
                    $releaseVersion = if ($Uri.AbsolutePath -cmatch '/(?<version>10\.0\.[0-9]+)/') {
                        [string]$Matches.version
                    }
                    else {
                        'metadata'
                    }
                    Write-ContractTrace ("download:{0}:{1}" -f $leafName, $releaseVersion)

                    if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) {
                        [IO.File]::WriteAllBytes($DestinationPath, $bytes)
                        $script:ContractLastDownload = $plan
                        return
                    }
                    Write-Output -NoEnumerate $bytes
                }

                function New-SecureDownloadDirectory {
                    $path = Join-Path (Split-Path -Parent $script:ContractTracePath) 'download'
                    [void][IO.Directory]::CreateDirectory($path)
                    return $path
                }

                function Get-AuthenticodeSignature {
                    [CmdletBinding()]
                    param(
                        [Parameter(Mandatory = $true)][string]$LiteralPath
                    )
                    [void]$LiteralPath
                    $status = [Enum]::Parse(
                        [System.Management.Automation.SignatureStatus],
                        [string]$script:ContractLastDownload.signatureStatus)
                    return [pscustomobject]@{
                        Status = $status
                        SignerCertificate = [pscustomobject]@{
                            Subject = [string]$script:ContractLastDownload.signerSubject
                        }
                    }
                }

                function Start-Process {
                    [CmdletBinding()]
                    param(
                        [Parameter(Mandatory = $true)][string]$FilePath,
                        [object[]]$ArgumentList,
                        [switch]$Wait,
                        [switch]$PassThru
                    )
                    [void]$Wait
                    [void]$PassThru
                    $runtimeName = if ([IO.Path]::GetFileName($FilePath) -ceq 'windowsdesktop-runtime-win-x64.exe') {
                        'Microsoft.WindowsDesktop.App'
                    }
                    else {
                        'Microsoft.AspNetCore.App'
                    }
                    Write-ContractTrace ("install:{0}:{1}" -f $runtimeName, ($ArgumentList -join ' '))
                    $script:ContractInstallAttempted = $true
                    $process = [pscustomobject]@{
                        Id = 4242
                        ExitCode = [int]$script:ContractLastDownload.installerExitCode
                        TimedOut = [bool]$script:ContractLastDownload.timedOut
                        WaitCount = 0
                    }
                    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
                        param($Milliseconds)
                        [void]$Milliseconds
                        $this.WaitCount++
                        if ($this.TimedOut -and $this.WaitCount -eq 1) { return $false }
                        return $true
                    }
                    return $process
                }

                function Stop-ProcessTree {
                    param([Parameter(Mandatory = $true)][int]$ProcessId)
                    [void]$ProcessId
                    Write-ContractTrace 'kill_tree'
                    return [bool]$script:ContractLastDownload.processTreeTerminated
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

        private static Dictionary<string, object?> MetadataDocument(
            params (string Version, string DesktopHash, string AspNetHash)[] releases) => new()
        {
            ["channel-version"] = "10.0",
            ["releases"] = releases.Select(release => new Dictionary<string, object?>
            {
                ["release-version"] = release.Version,
                ["windowsdesktop"] = Component(
                    release.Version,
                    "windowsdesktop-runtime-win-x64.exe",
                    InstallerUrl("windowsdesktop", release.Version),
                    release.DesktopHash),
                ["aspnetcore-runtime"] = Component(
                    release.Version,
                    "aspnetcore-runtime-win-x64.exe",
                    InstallerUrl("aspnetcore-runtime", release.Version),
                    release.AspNetHash),
            }).ToArray(),
        };

        private static Dictionary<string, object?> Component(
            string version,
            string name,
            string url,
            string hash) => new()
        {
            ["version"] = version,
            ["files"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["name"] = name,
                    ["rid"] = "win-x64",
                    ["url"] = url,
                    ["hash"] = hash,
                },
            },
        };

        private static Dictionary<string, object?> DownloadPlan(
            string url,
            byte[] bytes,
            bool installer = false) => new()
        {
            ["url"] = url,
            ["bytesBase64"] = Convert.ToBase64String(bytes),
            ["reportedLength"] = bytes.Length,
            ["redirectUrl"] = null,
            ["signatureStatus"] = installer ? "Valid" : null,
            ["signerSubject"] = installer ? MicrosoftSubject : null,
            ["installerExitCode"] = installer ? 0 : null,
            ["timedOut"] = false,
            ["processTreeTerminated"] = true,
        };

        private static string InstallerUrl(string component, string version) => component switch
        {
            "windowsdesktop" =>
                $"https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/{version}/windowsdesktop-runtime-{version}-win-x64.exe",
            "aspnetcore-runtime" =>
                $"https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/{version}/aspnetcore-runtime-{version}-win-x64.exe",
            _ => throw new ArgumentOutOfRangeException(nameof(component)),
        };

        private static string Sha512(byte[] value) =>
            Convert.ToHexString(SHA512.HashData(value)).ToLowerInvariant();
    }

    private sealed record ScriptResult(
        int ExitCode,
        string[] OutputLines,
        string AllOutput,
        string Trace);
}
