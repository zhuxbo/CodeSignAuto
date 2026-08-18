using System.Text.Json;
using System.Security.Cryptography;
using System.Reflection;
using Microsoft.AspNetCore.Builder;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class ServiceConfigurationTests
{
    [Fact]
    public async Task Strict_service_configuration_round_trips_complete_runtime_contract()
    {
        using var fixture = new ConfigurationFixture();
        var expected = fixture.ValidConfiguration();
        await File.WriteAllTextAsync(
            fixture.Path,
            JsonSerializer.Serialize(expected, JsonSerializerOptions.Web));

        var loaded = await new ServiceConfigurationLoader(fixture.Path)
            .LoadAsync(CancellationToken.None);

        Assert.Equivalent(expected, loaded, strict: true);
        Assert.Equal("0123456789abcdef0123456789abcdef", loaded.InstallInstanceId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("01234567-89ab-cdef-0123-456789abcdef")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF")]
    public void Install_instance_id_must_be_canonical_lower_guid_n(string installInstanceId)
    {
        using var fixture = new ConfigurationFixture();

        var failure = Assert.Throws<ServiceConfigurationException>(() =>
            ServiceConfigurationLoader.Validate(
                fixture.ValidConfiguration() with { InstallInstanceId = installInstanceId }));

        Assert.Equal("service_configuration_invalid", failure.Code);
    }

    [Theory]
    [InlineData("data")]
    [InlineData("agent")]
    public void Executable_below_a_controlled_data_root_is_rejected(string controlledRoot)
    {
        using var fixture = new ConfigurationFixture();
        var configuration = fixture.ValidConfiguration();
        var root = controlledRoot == "data"
            ? configuration.DataRoot
            : Path.GetDirectoryName(configuration.AgentConfigurationPath)!;

        var failure = Assert.Throws<ServiceConfigurationException>(() =>
            ServiceConfigurationLoader.Validate(configuration with
            {
                ExecutablePath = Path.Combine(root, "bin", "SimplySignAuto.exe"),
            }));

        Assert.Equal("service_configuration_invalid", failure.Code);
    }

    [Fact]
    public void Executable_below_a_same_prefix_sibling_is_accepted()
    {
        using var fixture = new ConfigurationFixture();
        var configuration = fixture.ValidConfiguration();
        var sibling = configuration.DataRoot + "-tools";

        var validated = ServiceConfigurationLoader.Validate(configuration with
        {
            ExecutablePath = Path.Combine(sibling, "SimplySignAuto.exe"),
        });

        Assert.Equal(
            Path.Combine(sibling, "SimplySignAuto.exe"),
            validated.ExecutablePath);
    }

    [Fact]
    public void Controlled_path_boundary_is_windows_case_insensitive_and_separator_aware()
    {
        (string Root, string Candidate, bool Expected)[] cases =
        [
            ("C:\\ProgramData\\SimplySignAuto", "c:\\PROGRAMDATA\\SIMPLYSIGNAUTO", true),
            ("C:\\ProgramData\\SimplySignAuto", "c:\\PROGRAMDATA\\SIMPLYSIGNAUTO\\bin\\SimplySignAuto.exe", true),
            ("C:\\ProgramData\\SimplySignAuto", "c:\\PROGRAMDATA\\SIMPLYSIGNAUTO-tools\\SimplySignAuto.exe", false),
        ];
        foreach (var (root, candidate, expected) in cases)
        {
            Assert.Equal(expected, InstallControlledPath.IsSameOrDescendant(root, candidate));
        }
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"unexpected\":true}")]
    public async Task Missing_or_unknown_service_configuration_fields_fail_closed(string json)
    {
        using var fixture = new ConfigurationFixture();
        await File.WriteAllTextAsync(fixture.Path, json);

        var failure = await Assert.ThrowsAsync<ServiceConfigurationException>(() =>
            new ServiceConfigurationLoader(fixture.Path).LoadAsync(CancellationToken.None));

        Assert.Equal("service_configuration_invalid", failure.Code);
    }

    [Fact]
    public async Task Uppercase_token_hash_is_rejected_instead_of_silently_normalized()
    {
        using var fixture = new ConfigurationFixture();
        var invalid = fixture.ValidConfiguration() with { TokenHash = new string('A', 64) };
        await File.WriteAllTextAsync(
            fixture.Path,
            JsonSerializer.Serialize(invalid, JsonSerializerOptions.Web));

        var failure = await Assert.ThrowsAsync<ServiceConfigurationException>(() =>
            new ServiceConfigurationLoader(fixture.Path).LoadAsync(CancellationToken.None));

        Assert.Equal("service_configuration_invalid", failure.Code);
    }

    [Fact]
    public async Task Duplicate_known_service_configuration_property_is_rejected()
    {
        using var fixture = new ConfigurationFixture();
        var expected = fixture.ValidConfiguration();
        var json = JsonSerializer.Serialize(expected, JsonSerializerOptions.Web);
        json = json.Insert(1, $"\"tokenHash\":\"{expected.TokenHash}\",");
        await File.WriteAllTextAsync(fixture.Path, json);

        var failure = await Assert.ThrowsAsync<ServiceConfigurationException>(() =>
            new ServiceConfigurationLoader(fixture.Path).LoadAsync(CancellationToken.None));

        Assert.Equal("service_configuration_invalid", failure.Code);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pascal_case_service_property_is_rejected_whether_single_or_case_variant_duplicate(
        bool keepCanonicalProperty)
    {
        using var fixture = new ConfigurationFixture();
        var expected = fixture.ValidConfiguration();
        var json = JsonSerializer.Serialize(expected, JsonSerializerOptions.Web);
        json = keepCanonicalProperty
            ? json.Insert(1, $"\"TokenHash\":\"{expected.TokenHash}\",")
            : json.Replace("\"tokenHash\"", "\"TokenHash\"", StringComparison.Ordinal);
        await File.WriteAllTextAsync(fixture.Path, json);

        var failure = await Assert.ThrowsAsync<ServiceConfigurationException>(() =>
            new ServiceConfigurationLoader(fixture.Path).LoadAsync(CancellationToken.None));

        Assert.Equal("service_configuration_invalid", failure.Code);
    }

    [Fact]
    public async Task Service_runtime_uses_loaded_configuration_and_never_environment_fallbacks()
    {
        using var fixture = new ConfigurationFixture();
        var expected = fixture.ValidConfiguration();
        var loader = new RecordingServiceConfigurationLoader(expected);
        Environment.SetEnvironmentVariable("SIMPLYSIGN_API_TOKEN_HASH", new string('f', 64));
        try
        {
            var runtime = await ServiceHost.PrepareRuntimeAsync(
                [],
                loader,
                CancellationToken.None);

            Assert.Same(expected, runtime.Configuration);
            Assert.Equal(Convert.FromHexString(expected.TokenHash), runtime.TokenHash);
            Assert.False(runtime.Console);
            Assert.False(runtime.AllowHttpLoopback);
            Assert.Equal(1, loader.Calls);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIMPLYSIGN_API_TOKEN_HASH", null);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(168)]
    public async Task Service_restart_maps_loaded_retention_into_job_runtime(int retentionHours)
    {
        using var fixture = new ConfigurationFixture();
        var expected = fixture.ValidConfiguration() with { RetentionHours = retentionHours };
        var runtime = await ServiceHost.PrepareRuntimeAsync(
            [],
            new RecordingServiceConfigurationLoader(expected),
            default);

        var options = ServiceHost.CreateOptions(
            runtime,
            CurrentComponentVersions(),
            _ => NoopSpoolAclPolicy.Instance);

        Assert.Equal(retentionHours, options.RetentionHours);
        Assert.Equal(retentionHours, options.ManagementSettings!.RetentionHours);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(168)]
    public void Service_configuration_accepts_the_complete_retention_range(int retentionHours)
    {
        using var fixture = new ConfigurationFixture();

        var actual = ServiceConfigurationLoader.Validate(
            fixture.ValidConfiguration() with { RetentionHours = retentionHours });

        Assert.Equal(retentionHours, actual.RetentionHours);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(169)]
    public void Invalid_retention_is_rejected_before_service_storage_mutation(int retentionHours)
    {
        using var fixture = new ConfigurationFixture();
        var builder = WebApplication.CreateBuilder();

        Assert.Throws<ArgumentOutOfRangeException>(() => ServiceHost.Configure(
            builder,
            new ServiceHostOptions(
                SHA256.HashData("token"u8),
                fixture.DatabasePath,
                fixture.SpoolPath)
            {
                ProductVersionIdentity = "1.0.0",
                RetentionHours = retentionHours,
            }));

        Assert.False(File.Exists(fixture.DatabasePath));
        Assert.False(Directory.Exists(fixture.SpoolPath));
    }

    [Fact]
    public async Task Http_loopback_test_mode_still_requires_valid_service_configuration()
    {
        using var fixture = new ConfigurationFixture();
        var expected = fixture.ValidConfiguration();
        var loader = new RecordingServiceConfigurationLoader(expected);
        var runtime = await ServiceHost.PrepareRuntimeAsync(
            ["--console", "--allow-http-loopback"],
            loader,
            CancellationToken.None);

        Assert.True(runtime.Console);
        Assert.True(runtime.AllowHttpLoopback);
        Assert.Equal(1, loader.Calls);
    }

    [Fact]
    public async Task Service_management_summary_exposes_the_fixed_http_listener_contract()
    {
        using var fixture = new ConfigurationFixture();
        var expected = fixture.ValidConfiguration();

        var runtime = await ServiceHost.PrepareRuntimeAsync(
            [],
            new RecordingServiceConfigurationLoader(expected),
            default);
        var settings = ServiceHost.CreateOptions(
            runtime,
            CurrentComponentVersions(),
            _ => NoopSpoolAclPolicy.Instance).ManagementSettings;

        Assert.NotNull(settings);
        Assert.Equal(expected.ListenPort, settings.ListenPort);
        Assert.Equal(expected.RetentionHours, settings.RetentionHours);
        Assert.Equal(ServiceSettingsSummary.FixedMaximumUploadBytes, settings.MaximumUploadBytes);
    }

    private static ProductComponentVersions CurrentComponentVersions()
    {
        var identity = typeof(ServiceHost).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            ?? throw new InvalidOperationException("service_version_missing");
        return new ProductComponentVersions(identity, identity);
    }

    private sealed class RecordingServiceConfigurationLoader(ServiceConfiguration configuration) : IServiceConfigurationLoader
    {
        public int Calls { get; private set; }

        public Task<ServiceConfiguration> LoadAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(configuration);
        }
    }

    private sealed class NoopSpoolAclPolicy : SimplySignAuto.Service.Jobs.ISpoolAclPolicy
    {
        public static NoopSpoolAclPolicy Instance { get; } = new();
        public void ProtectRoot(string path) { }
        public void ProtectJobDirectory(string path) { }
        public void ProtectInput(string path) { }
        public void ProtectFinalResult(string path) { }
    }

    private sealed class ConfigurationFixture : IDisposable
    {
        private readonly string _root = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "SimplySignAuto.Tests",
            Guid.NewGuid().ToString("N"));

        public ConfigurationFixture() => Directory.CreateDirectory(_root);

        public string Path => System.IO.Path.Combine(_root, "service.json");

        public string DatabasePath => System.IO.Path.Combine(_root, "jobs.db");

        public string SpoolPath => System.IO.Path.Combine(_root, "spool");

        public ServiceConfiguration ValidConfiguration()
        {
            var dataRoot = System.IO.Path.Combine(_root, "SimplySignAuto");
            return new ServiceConfiguration(
                new string('a', 64),
                "S-1-5-21-1000-2000-3000-4000",
                dataRoot,
                System.IO.Path.Combine(dataRoot, "spool"),
                7080,
                "SimplySignAuto/v1",
                "0123456789abcdef0123456789abcdef",
                System.IO.Path.Combine(_root, "install", "SimplySignAuto.exe"),
                System.IO.Path.Combine(_root, "profile", "AppData", "Local", "SimplySignAuto", "agent.json"),
                24);
        }

        public void Dispose() => Directory.Delete(_root, recursive: true);
    }
}
