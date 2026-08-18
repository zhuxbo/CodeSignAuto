using System.Text.Json;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.App.Commands;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class AgentCommandTests
{
    private const string ExpectedSid = "S-1-5-21-1000-2000-3000-4000";

    [Theory]
    [InlineData("--console")]
    [InlineData("--background")]
    public async Task Accepted_modes_load_the_trusted_sid_and_run_the_agent(string mode)
    {
        var configuration = CompleteConfiguration(SyntheticRoot());
        var loader = new RecordingConfigurationLoader(configuration);
        var runner = new RecordingAgentRunner();
        using var error = new StringWriter();

        var exitCode = await AgentCommand.ExecuteAsync([mode], error, loader, runner);

        Assert.Equal(0, exitCode);
        Assert.Equal(1, loader.LoadCalls);
        Assert.Same(configuration, runner.Configuration);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task Unknown_or_bypass_arguments_fail_before_configuration_is_read()
    {
        string[][] cases = [[], ["--skip-session-check"], ["--user-sid", ExpectedSid], ["--console", "--background"]];
        foreach (var args in cases)
        {
            var loader = new RecordingConfigurationLoader(CompleteConfiguration(SyntheticRoot()));
            var runner = new RecordingAgentRunner();
            using var error = new StringWriter();

            var exitCode = await AgentCommand.ExecuteAsync(args, error, loader, runner);

            Assert.Equal(2, exitCode);
            Assert.Equal(0, loader.LoadCalls);
            Assert.Null(runner.Configuration);
            Assert.Equal($"agent_arguments_invalid{Environment.NewLine}", error.ToString());
        }
    }

    [Fact]
    public async Task Missing_configuration_keeps_stable_code_and_original_path_diagnostic()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "agent.json");
        using var error = new StringWriter();

        var exitCode = await AgentCommand.ExecuteAsync(
            ["--console"],
            error,
            new AgentConfigurationLoader(path),
            new RecordingAgentRunner());

        Assert.Equal(1, exitCode);
        Assert.Contains("stable_code=agent_configuration_missing", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("exception_type=SimplySignAuto.App.Commands.AgentConfigurationException", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("System.IO.DirectoryNotFoundException", error.ToString(), StringComparison.Ordinal);
        Assert.Contains(path, error.ToString(), StringComparison.Ordinal);
        Assert.EndsWith($"agent_configuration_missing{Environment.NewLine}", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Complete_signing_configuration_round_trips_without_otp_secret()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"simplysign-agent-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        Directory.CreateDirectory(Path.Combine(directory, "spool"));
        var path = Path.Combine(directory, "agent.json");
        var expected = CompleteConfiguration(directory);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(expected, JsonSerializerOptions.Web));
        try
        {
            var loaded = await new AgentConfigurationLoader(path).LoadAsync(CancellationToken.None);

            Assert.Equal(expected.SigningUserSid, loaded.SigningUserSid);
            Assert.Equal(expected.SpoolPath, loaded.SpoolPath);
            Assert.Equal(expected.SimplySignDesktopPath, loaded.SimplySignDesktopPath);
            Assert.Equal(expected.Pkcs11ModulePath, loaded.Pkcs11ModulePath);
            Assert.Equivalent(expected.Authenticode, loaded.Authenticode, strict: true);
            Assert.Equivalent(expected.Pdf, loaded.Pdf, strict: true);
            Assert.DoesNotContain("otp", await File.ReadAllTextAsync(path), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("secret", await File.ReadAllTextAsync(path), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Incomplete_configuration_fails_closed()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"simplysign-agent-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "agent.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new { signingUserSid = ExpectedSid }));
        try
        {
            var failure = await Assert.ThrowsAsync<AgentConfigurationException>(() =>
                new AgentConfigurationLoader(path).LoadAsync(CancellationToken.None));

            Assert.Equal("agent_configuration_invalid", failure.Code);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Signing_user_sid_must_be_canonical()
    {
        string[] invalidSids =
        {
            "S-1-05-21-1000-2000-3000-4000",
            "S-1-5-021-1000-2000-3000-4000",
            "S-1-5-21-+1000-2000-3000-4000",
        };
        foreach (var signingUserSid in invalidSids)
        {
            var directory = Path.Combine(Path.GetTempPath(), $"simplysign-agent-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "agent.json");
            var configuration = CompleteConfiguration(directory) with { SigningUserSid = signingUserSid };
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(configuration, JsonSerializerOptions.Web));
            try
            {
                var failure = await Assert.ThrowsAsync<AgentConfigurationException>(() =>
                    new AgentConfigurationLoader(path).LoadAsync(CancellationToken.None));

                Assert.Equal("agent_configuration_invalid", failure.Code);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Corrupt_configuration_keeps_stable_code_and_original_parser_diagnostic()
    {
        string[] invalidConfigurations =
        {
            "not-json",
            "{}",
            "{\"signingUserSid\":\"S-1-5-21-1000\",\"unexpected\":true}",
        };
        foreach (var json in invalidConfigurations)
        {
            var directory = Path.Combine(Path.GetTempPath(), $"simplysign-agent-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "agent.json");
            await File.WriteAllTextAsync(path, json);
            try
            {
                using var error = new StringWriter();

                var exitCode = await AgentCommand.ExecuteAsync(
                    ["--background"],
                    error,
                    new AgentConfigurationLoader(path),
                    new RecordingAgentRunner());

                Assert.Equal(1, exitCode);
                Assert.Contains("stable_code=agent_configuration_invalid", error.ToString(), StringComparison.Ordinal);
                Assert.Contains("exception_type=SimplySignAuto.App.Commands.AgentConfigurationException", error.ToString(), StringComparison.Ordinal);
                Assert.Contains("exception_begin", error.ToString(), StringComparison.Ordinal);
                Assert.EndsWith($"agent_configuration_invalid{Environment.NewLine}", error.ToString(), StringComparison.Ordinal);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Duplicate_known_agent_configuration_property_fails_closed()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"simplysign-agent-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "agent.json");
        var configuration = CompleteConfiguration(directory);
        var json = JsonSerializer.Serialize(configuration, JsonSerializerOptions.Web);
        json = json.Insert(1, $"\"signingUserSid\":\"{ExpectedSid}\",");
        await File.WriteAllTextAsync(path, json);
        try
        {
            var failure = await Assert.ThrowsAsync<AgentConfigurationException>(() =>
                new AgentConfigurationLoader(path).LoadAsync(CancellationToken.None));

            Assert.Equal("agent_configuration_invalid", failure.Code);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pascal_case_nested_agent_property_is_rejected_whether_single_or_case_variant_duplicate(
        bool keepCanonicalProperty)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"simplysign-agent-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "agent.json");
        var configuration = CompleteConfiguration(directory);
        var json = JsonSerializer.Serialize(configuration, JsonSerializerOptions.Web);
        const string canonical = "\"timestampUrl\":\"http://time.certum.pl/\"";
        json = keepCanonicalProperty
            ? json.Replace(canonical, $"\"TimestampUrl\":\"http://time.certum.pl/\",{canonical}", StringComparison.Ordinal)
            : json.Replace("\"timestampUrl\"", "\"TimestampUrl\"", StringComparison.Ordinal);
        await File.WriteAllTextAsync(path, json);
        try
        {
            var failure = await Assert.ThrowsAsync<AgentConfigurationException>(() =>
                new AgentConfigurationLoader(path).LoadAsync(CancellationToken.None));

            Assert.Equal("agent_configuration_invalid", failure.Code);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData("https://timestamp.invalid/")]
    [InlineData("http://evil.example/time.certum.pl/")]
    [InlineData("file:///controlled/tsa")]
    public void Non_certum_or_invalid_timestamp_endpoint_is_rejected(string timestampUrl)
    {
        var configuration = CompleteConfiguration(SyntheticRoot()) with
        {
            Authenticode = new AgentAuthenticodeConfiguration(
                Path.Combine(SyntheticRoot(), "signtool.exe"),
                timestampUrl),
        };

        var failure = Assert.Throws<AgentConfigurationException>(() =>
            AgentConfigurationLoader.Validate(configuration));

        Assert.Equal("agent_configuration_invalid", failure.Code);
    }

    [Fact]
    public async Task Omitted_capability_timestamp_uses_the_fixed_certum_endpoint()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"simplysign-agent-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "agent.json");
        var json = JsonSerializer.Serialize(CompleteConfiguration(directory), JsonSerializerOptions.Web)
            .Replace(",\"timestampUrl\":\"http://time.certum.pl/\"", string.Empty, StringComparison.Ordinal)
            .Replace("\"timestampUrl\":\"http://time.certum.pl/\"", string.Empty, StringComparison.Ordinal);
        await File.WriteAllTextAsync(path, json);
        try
        {
            var loaded = await new AgentConfigurationLoader(path).LoadAsync(default);

            Assert.Equal("http://time.certum.pl/", loaded.Authenticode!.TimestampUrl);
            Assert.Equal("http://time.certum.pl/", loaded.Pdf!.TimestampUrl);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Startup_failure_prints_the_stable_code_and_full_diagnostic()
    {
        using var error = new StringWriter();
        var runner = new ThrowingAgentRunner(new AgentStartupException("agent_session_zero"));

        var exitCode = await AgentCommand.ExecuteAsync(
            ["--console"],
            error,
            new RecordingConfigurationLoader(CompleteConfiguration(SyntheticRoot())),
            runner);

        Assert.Equal(1, exitCode);
        Assert.Contains("stable_code=agent_session_zero", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("stage=agent_startup", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("exception_type=SimplySignAuto.Agent.Sessions.AgentStartupException", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("message=agent_session_zero", error.ToString(), StringComparison.Ordinal);
        Assert.EndsWith($"agent_session_zero{Environment.NewLine}", error.ToString(), StringComparison.Ordinal);
    }

    private static AgentConfiguration CompleteConfiguration(string root) => new(
        ExpectedSid,
        Path.Combine(root, "spool"),
        Path.Combine(root, "SimplySignDesktop.exe"),
        Path.Combine(root, "synthetic-pkcs11.dll"),
        new AgentAuthenticodeConfiguration(
            Path.Combine(root, "signtool.exe"),
            "http://time.certum.pl/"),
        new AgentPdfConfiguration("http://time.certum.pl/"));

    private static string SyntheticRoot() => Path.Combine(
        Path.GetTempPath(),
        "SimplySignAuto.Tests",
        "synthetic-agent-configuration");

    private sealed class RecordingConfigurationLoader(AgentConfiguration configuration) : IAgentConfigurationLoader
    {
        public int LoadCalls { get; private set; }

        public Task<AgentConfiguration> LoadAsync(CancellationToken cancellationToken)
        {
            LoadCalls++;
            return Task.FromResult(configuration);
        }
    }

    private sealed class RecordingAgentRunner : IAgentRunner
    {
        public AgentConfiguration? Configuration { get; private set; }

        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken)
        {
            Configuration = configuration;
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingAgentRunner(Exception error) : IAgentRunner
    {
        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromException(error);
    }
}
