using System.Text.Json;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using CodeSignAuto.Agent.Diagnostics;
using CodeSignAuto.Agent.Sessions;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.SimplySign;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class SimplySignProbeTests : IDisposable
{
    private const int AgentSessionId = 7;
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Catalog_source_runs_authoritative_catalog_command_with_one_trusted_module_path()
    {
        var runner = new ProbeRunner("{\"ok\":true,\"failureCode\":null,\"certificates\":[]}");
        var probe = CreateProbe(runner, new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var output = await probe.ReadCatalogAsync(TestPaths.Controlled("pkcs11.dll"), default);

        Assert.Equal("{\"ok\":true,\"failureCode\":null,\"certificates\":[]}", output);
        Assert.Equal(["--internal-pkcs11-helper", "catalog", "--request"], runner.Arguments.Take(3));
        Assert.EndsWith("CodeSignAuto.exe", runner.Executable, StringComparison.Ordinal);
        Assert.Equal(TimeSpan.FromSeconds(15), runner.Timeout);
        using var request = JsonDocument.Parse(Assert.IsType<string>(runner.RequestJson));
        Assert.Equal(["modulePath"], request.RootElement.EnumerateObject().Select(property => property.Name));
        Assert.Equal(TestPaths.Controlled("pkcs11.dll"), request.RootElement.GetProperty("modulePath").GetString());
        Assert.False(File.Exists(runner.Arguments[3]));
    }

    [Fact]
    public void Process_only_check_never_starts_catalog_helper()
    {
        var runner = new ProbeRunner("unused");
        var state = new SimplySignProcessState(true, AgentSessionId);
        var probe = CreateProbe(runner, new ProbeProcessSource(state));

        var actual = probe.CheckProcessOnly();

        Assert.Equal(state, actual);
        Assert.Equal(0, runner.Calls);
    }

    [Theory]
    [InlineData("{}\n{}", 0)]
    [InlineData("{}", 2)]
    [InlineData("{}", 10)]
    [InlineData("{}", 20)]
    public async Task Catalog_source_rejects_non_single_line_or_nonzero_helper_results(string output, int exitCode)
    {
        var probe = CreateProbe(
            new ProbeRunner(output, exitCode),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var error = await Assert.ThrowsAsync<SigningException>(() =>
            probe.ReadCatalogAsync(TestPaths.Controlled("pkcs11.dll"), default));

        Assert.Equal("certificate_catalog_unavailable", error.Code);
    }

    [Fact]
    public async Task Catalog_source_preserves_a_valid_ascii_catalog_larger_than_the_generic_capture()
    {
        var records = Enumerable.Range(1, 64).Select(index => new
        {
            slotId = index,
            tokenSerial = $"TOKEN-{index:D3}",
            certificateIdHex = index.ToString("x8"),
            privateKeyMatch = "unique",
            privateKeyIdHex = index.ToString("x8"),
            certificateDerBase64 = Convert.ToBase64String(new byte[384]),
        });
        var output = JsonSerializer.Serialize(new
        {
            ok = true,
            failureCode = (string?)null,
            certificates = records,
        }) + "\n";
        Assert.True(output.Length > 16_384);
        var probe = CreateProbe(
            new ProcessRunner(new FixedOutputProcessStarter(output)),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var actual = await probe.ReadCatalogAsync(TestPaths.Controlled("pkcs11.dll"), default);

        Assert.Equal(output[..^1], actual);
    }

    [WindowsFact]
    public async Task Request_store_creates_a_deletable_protected_file_under_write_only_parent_acl()
    {
        var root = Path.Combine(_directory, "restricted-probe");
        Directory.CreateDirectory(root);
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = Assert.IsType<SecurityIdentifier>(identity.User);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.Write |
            FileSystemRights.ReadAndExecute |
            FileSystemRights.Synchronize |
            FileSystemRights.ChangePermissions,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(root).SetAccessControl(security);

        try
        {
            var store = new ControlledProbeRequestStore(root);
            var path = store.AllocatePath();

            await store.WriteAsync(path, "{\"modulePath\":\"C:\\\\probe.dll\"}", CancellationToken.None);
            var requestSecurity = new FileInfo(path).GetAccessControl();
            Assert.True(requestSecurity.AreAccessRulesProtected);
            Assert.Equal(
                currentUser,
                Assert.IsType<SecurityIdentifier>(
                    requestSecurity.GetOwner(typeof(SecurityIdentifier))));
            var allowedRules = requestSecurity
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Where(rule => rule.AccessControlType == AccessControlType.Allow)
                .ToArray();
            Assert.Equal(2, allowedRules.Length);
            Assert.All(allowedRules, rule => Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights));
            Assert.Contains(allowedRules, rule => rule.IdentityReference.Equals(currentUser));
            Assert.Contains(allowedRules, rule => rule.IdentityReference.Equals(system));
            await store.DeleteAsync(path);

            Assert.False(File.Exists(path));
        }
        finally
        {
            var cleanup = new DirectorySecurity();
            cleanup.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            cleanup.AddAccessRule(new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(root).SetAccessControl(cleanup);
        }
    }

    [Fact]
    public async Task Ready_probe_exposes_metadata_parsed_from_the_selected_certificate()
    {
        var alias = CreateAlias();
        var probe = CreateProbe(
            new ProbeRunner(ResultJson(alias)),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(alias, default);

        Assert.Equal(DateTimeOffset.Parse("2027-08-09T00:00:00Z"), result.CertificateNotAfterUtc);
        Assert.Equal("89ABCDEF", result.CertificateThumbprintSuffix);
    }

    [Fact]
    public async Task Ready_requires_same_positive_session_and_helper_confirmation_for_the_configured_alias()
    {
        var alias = CreateAlias();
        var runner = new ProbeRunner(ResultJson(alias));
        var probe = CreateProbe(runner, new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(alias, CancellationToken.None);

        Assert.True(result.Ready);
        Assert.Equal(AgentSessionId, result.ProcessSessionId);
        Assert.Equal(alias.TokenSerial, result.TokenSerial);
        Assert.Equal(alias.CertificateIdHex, result.CertificateId);
        Assert.Equal(alias.PrivateKeyIdHex, result.PrivateKeyId);
        Assert.Equal(["--internal-pkcs11-helper", "probe", "--request"], runner.Arguments.Take(3));
        Assert.StartsWith(
            Path.GetFullPath(_directory) + Path.DirectorySeparatorChar,
            Path.GetFullPath(runner.Arguments[3]),
            StringComparison.Ordinal);
        using var request = JsonDocument.Parse(Assert.IsType<string>(runner.RequestJson));
        Assert.Equal(
            TestPaths.Controlled("pkcs11.dll"),
            request.RootElement.GetProperty("modulePath").GetString());
        Assert.Equal(2UL, request.RootElement.GetProperty("slotId").GetUInt64());
        Assert.Equal("TOKEN-SERIAL-01", request.RootElement.GetProperty("tokenSerial").GetString());
        Assert.Equal("c0ffee01", request.RootElement.GetProperty("certificateIdHex").GetString());
        Assert.Equal("decafbad", request.RootElement.GetProperty("privateKeyIdHex").GetString());
        Assert.NotNull(runner.RequestBytes);
        Assert.False(runner.RequestBytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }));
        Assert.False(File.Exists(runner.Arguments[3]));
    }

    [Theory]
    [InlineData(false, null, "process_missing")]
    [InlineData(true, 0, "process_session_mismatch")]
    [InlineData(true, 11, "process_session_mismatch")]
    public async Task Missing_or_mismatched_desktop_process_is_diagnostic_and_never_skips_the_crypto_helper(
        bool running,
        int? sessionId,
        string expectedCode)
    {
        var alias = CreateAlias();
        var runner = new ProbeRunner(ResultJson(alias));
        var probe = CreateProbe(runner, new ProbeProcessSource(new SimplySignProcessState(running, sessionId)));

        var result = await probe.ProbeAsync(alias, CancellationToken.None);

        Assert.True(result.Ready);
        Assert.Equal(expectedCode, result.ProcessFailureCode);
        Assert.Equal(1, runner.Calls);
    }

    [Theory]
    [InlineData(false, true, true, "token_missing")]
    [InlineData(true, false, true, "certificate_missing")]
    [InlineData(true, true, false, "private_key_missing")]
    [InlineData(false, false, false, "token_identifier_mismatch")]
    [InlineData(true, false, false, "certificate_identifier_mismatch")]
    public async Task Missing_material_or_identifier_mismatch_is_never_ready(
        bool tokenPresent,
        bool certificatePresent,
        bool privateKeyPresent,
        string expectedCode)
    {
        var alias = CreateAlias();
        var json = JsonSerializer.Serialize(new
        {
            ok = false,
            tokenPresent,
            certificatePresent,
            privateKeyPresent,
            failureCode = expectedCode,
            certificateNotAfterUtc = certificatePresent ? "2027-08-09T00:00:00Z" : null,
            certificateThumbprintSuffix = certificatePresent ? "89ABCDEF" : null,
        });
        var probe = CreateProbe(
            new ProbeRunner(json),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(alias, CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal(expectedCode, result.FailureCode);
    }

    [Theory]
    [InlineData("not-json", 0, "probe_output_invalid")]
    [InlineData("{}\n{}", 0, "probe_output_invalid")]
    [InlineData("{\"ok\":true,\"tokenPresent\":true,\"certificatePresent\":true,\"privateKeyPresent\":true,\"failureCode\":null,\"unknown\":1}", 0, "probe_output_invalid")]
    [InlineData("{}", 10, "probe_token_unavailable")]
    [InlineData("{}", 2, "probe_request_invalid")]
    [InlineData("{}", 20, "probe_failed")]
    public async Task Malformed_multiple_unknown_or_unexpected_helper_results_use_stable_codes(
        string output,
        int exitCode,
        string expectedCode)
    {
        var probe = CreateProbe(
            new ProbeRunner(output, exitCode),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(CreateAlias(), CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal(expectedCode, result.FailureCode);
        Assert.DoesNotContain("/controlled", result.FailureCode, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("case_variant")]
    public async Task Helper_metadata_rejects_duplicate_and_case_variant_fields(string mutation)
    {
        var output = ResultJson(CreateAlias());
        output = mutation == "duplicate"
            ? output.Replace("\"ok\":true", "\"ok\":true,\"ok\":true", StringComparison.Ordinal)
            : output.Replace(
                "\"certificateThumbprintSuffix\"",
                "\"CertificateThumbprintSuffix\"",
                StringComparison.Ordinal);
        var probe = CreateProbe(
            new ProbeRunner(output),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(CreateAlias(), CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal("probe_output_invalid", result.FailureCode);
    }

    [Fact]
    public async Task Runner_failure_does_not_leak_path_or_identifiers()
    {
        var probe = CreateProbe(
            new ProbeRunner(ProcessResult.Failed(
                "CodeSignAutoPdfSigner.exe",
                ProcessTermination.LaunchFailed,
                "process_launch_failed",
                TimeSpan.Zero)),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(CreateAlias(), CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal("probe_process_failed", result.FailureCode);
        Assert.DoesNotContain("TOKEN-SERIAL-01", result.FailureCode, StringComparison.Ordinal);
        Assert.DoesNotContain(_directory, result.FailureCode, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Helper_failure_is_not_ready_even_when_all_presence_flags_are_true()
    {
        var output = JsonSerializer.Serialize(new
        {
            ok = false,
            tokenPresent = true,
            certificatePresent = true,
            privateKeyPresent = true,
            failureCode = "pkcs11_error",
            certificateNotAfterUtc = "2027-08-09T00:00:00Z",
            certificateThumbprintSuffix = "89ABCDEF",
        });
        var probe = CreateProbe(
            new ProbeRunner(output),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(CreateAlias(), CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal("probe_failed", result.FailureCode);
    }

    [Fact]
    public async Task Request_write_failure_attempts_cleanup_and_returns_a_stable_code()
    {
        var store = new FaultingProbeRequestStore
        {
            WriteException = new IOException("TOKEN-SERIAL-01 /controlled/request.json"),
        };
        var runner = new ProbeRunner(ResultJson(CreateAlias()));
        var probe = CreateProbe(
            runner,
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)),
            store);

        var result = await probe.ProbeAsync(CreateAlias(), CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal("probe_request_invalid", result.FailureCode);
        Assert.Equal(1, store.DeleteCalls);
        Assert.Equal(0, runner.Calls);
        Assert.DoesNotContain("TOKEN-SERIAL-01", result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("/controlled", result.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Request_write_cancellation_still_attempts_cleanup_then_propagates_cancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var store = new FaultingProbeRequestStore
        {
            BeforeWriteFailure = cancellation.Cancel,
            WriteExceptionFactory = token => new OperationCanceledException(token),
        };
        var probe = CreateProbe(
            new ProbeRunner(ResultJson(CreateAlias())),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)),
            store);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            probe.ProbeAsync(CreateAlias(), cancellation.Token));

        Assert.Equal(1, store.DeleteCalls);
    }

    [Fact]
    public async Task Request_cleanup_failure_overrides_a_ready_helper_result()
    {
        var store = new FaultingProbeRequestStore
        {
            DeleteException = new IOException("TOKEN-SERIAL-01 /controlled/request.json"),
        };
        var probe = CreateProbe(
            new ProbeRunner(ResultJson(CreateAlias())),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)),
            store);

        var result = await probe.ProbeAsync(CreateAlias(), CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal("probe_request_cleanup_failed", result.FailureCode);
        Assert.DoesNotContain("TOKEN-SERIAL-01", result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("/controlled", result.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Truncated_real_runner_stdout_rejects_a_valid_json_prefix_instead_of_returning_ready()
    {
        var alias = CreateAlias();
        var output = ResultJson(alias)
            + new string(' ', ProcessRunner.MaximumCapturedOutputBytes)
            + "\n{\"second\":true}";
        var runner = new ProcessRunner(new FixedOutputProcessStarter(output));
        var probe = CreateProbe(
            runner,
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)));

        var result = await probe.ProbeAsync(alias, CancellationToken.None);

        Assert.False(result.Ready);
        Assert.Equal("probe_output_invalid", result.FailureCode);
    }

    [Fact]
    public async Task Catalog_process_failure_reports_exit_stdout_and_stderr_before_returning_the_stable_code()
    {
        var process = ProcessResult.Exited(
            "CodeSignAutoPdfSigner.exe",
            17,
            TimeSpan.FromMilliseconds(50),
            "catalog stdout path=C:\\ProgramData\\CodeSignAuto",
            "catalog stderr line=144");
        var diagnostics = new RecordingAgentDiagnosticSink();
        var probe = CreateProbe(
            new ProbeRunner(process),
            new ProbeProcessSource(new SimplySignProcessState(true, AgentSessionId)),
            diagnostics: diagnostics);

        var error = await Assert.ThrowsAsync<SigningException>(() =>
            probe.ReadCatalogAsync(TestPaths.Controlled("pkcs11.dll"), CancellationToken.None));

        Assert.Equal("certificate_catalog_unavailable", error.Code);
        var diagnostic = Assert.Single(diagnostics.Diagnostics);
        Assert.Equal("certificate_catalog_process", diagnostic.Stage);
        Assert.Equal("certificate_catalog_unavailable", diagnostic.StableCode);
        Assert.Same(process, diagnostic.Process);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    private SimplySignProbe CreateProbe(
        IProcessRunner runner,
        ISimplySignProcessSource processSource,
        IProbeRequestStore? requestStore = null,
        IAgentDiagnosticSink? diagnostics = null) =>
        requestStore is null
            ? new SimplySignProbe(
                runner,
                processSource,
                TestPaths.Controlled("CodeSignAuto.exe"),
                _directory,
                new InteractiveSessionInfo(AgentSessionId, "S-1-5-21-1000", "1000"),
                diagnostics)
            : new SimplySignProbe(
                runner,
                processSource,
                TestPaths.Controlled("CodeSignAuto.exe"),
                requestStore,
                new InteractiveSessionInfo(AgentSessionId, "S-1-5-21-1000", "1000"),
                diagnostics);

    private static CertificateAlias CreateAlias() =>
        new(
            "document",
            TestPaths.Controlled("pkcs11.dll"),
            2,
            "TOKEN-SERIAL-01",
            "c0ffee01",
            "decafbad");

    private static string ResultJson(CertificateAlias alias) => JsonSerializer.Serialize(new
    {
        ok = true,
        tokenPresent = true,
        certificatePresent = true,
        privateKeyPresent = true,
        failureCode = (string?)null,
        certificateNotAfterUtc = "2027-08-09T00:00:00Z",
        certificateThumbprintSuffix = "89ABCDEF",
    });

    private sealed class ProbeProcessSource(SimplySignProcessState state) : ISimplySignProcessSource
    {
        public SimplySignProcessState Read(int verifiedSessionId) => state;

        public bool IsRunningInSession(int sessionId) => state.ProcessRunning && state.SessionId == sessionId;
    }

    private sealed class ProbeRunner : IProcessRunner
    {
        private readonly ProcessResult _result;

        public ProbeRunner(string output, int exitCode = 0)
            : this(ProcessResult.Exited(
                "CodeSignAutoPdfSigner.exe",
                exitCode,
                TimeSpan.Zero,
                output,
                string.Empty))
        {
        }

        public ProbeRunner(ProcessResult result)
        {
            _result = result;
        }

        public int Calls { get; private set; }

        public IReadOnlyList<string> Arguments { get; private set; } = [];

        public string Executable { get; private set; } = string.Empty;

        public TimeSpan Timeout { get; private set; }

        public string? RequestJson { get; private set; }

        public byte[]? RequestBytes { get; private set; }

        public async Task<ProcessResult> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls++;
            Executable = executable;
            Timeout = timeout;
            Arguments = arguments.ToArray();
            if (arguments.Count == 4 && File.Exists(arguments[3]))
            {
                RequestBytes = await File.ReadAllBytesAsync(arguments[3], cancellationToken);
                RequestJson = await File.ReadAllTextAsync(arguments[3], cancellationToken);
            }

            return _result;
        }

        public Task<ProcessLaunchResult> StartDetachedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FaultingProbeRequestStore : IProbeRequestStore
    {
        public Exception? WriteException { get; init; }

        public Func<CancellationToken, Exception>? WriteExceptionFactory { get; init; }

        public Action? BeforeWriteFailure { get; init; }

        public Exception? DeleteException { get; init; }

        public int DeleteCalls { get; private set; }

        public string AllocatePath() => "/controlled/probe-request.json";

        public Task WriteAsync(string path, string content, CancellationToken cancellationToken)
        {
            if (WriteException is not null || WriteExceptionFactory is not null)
            {
                BeforeWriteFailure?.Invoke();
                return Task.FromException(WriteException ?? WriteExceptionFactory!(cancellationToken));
            }

            return Task.CompletedTask;
        }

        public Task DeleteAsync(string path)
        {
            DeleteCalls++;
            return DeleteException is null ? Task.CompletedTask : Task.FromException(DeleteException);
        }
    }

    private sealed class FixedOutputProcessStarter(string output) : IProcessStarter
    {
        public IProcessHandle Start(ProcessStartInfo startInfo) => new FixedOutputProcessHandle(output);
    }

    private sealed class FixedOutputProcessHandle(string output) : IProcessHandle
    {
        public TextReader StandardOutput { get; } = new StringReader(output);

        public TextReader StandardError { get; } = new StringReader(string.Empty);

        public bool HasExited => true;

        public int ExitCode => 0;

        public Task WaitForExitAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public void Kill(bool entireProcessTree) => throw new InvalidOperationException();

        public void CloseOutput()
        {
            StandardOutput.Close();
            StandardError.Close();
        }

        public ValueTask DisposeAsync()
        {
            StandardOutput.Dispose();
            StandardError.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
