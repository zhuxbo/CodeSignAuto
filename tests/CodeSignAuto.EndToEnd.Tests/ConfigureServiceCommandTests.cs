using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using CodeSignAuto.App;
using CodeSignAuto.App.Commands;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class ConfigureServiceCommandTests
{
    [Fact]
    public async Task Custom_token_is_hashed_without_invoking_random_factory()
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        var factory = new RecordingConfigurationTokenFactory();
        var platform = new PlatformFake { Configuration = Configuration() };
        var request = new ServiceConfigurationEditRequest(8080, 24, true, token);
        var result = await new ServiceConfigurationEditor(platform, factory).ApplyAsync(request, default);
        Assert.True(result.OneTimeApiToken == token);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token))), platform.Applied!.TokenHash);
        Assert.Equal(0, factory.CreateCalls);
        Assert.DoesNotContain(token, request.ToString());
    }

    [Theory]
    [InlineData("too-short")]
    [InlineData("has whitespace in token")]
    [InlineData("invalid,comma,in,token")]
    public async Task Invalid_custom_token_is_rejected_before_platform_access(string token)
    {
        var platform = new PlatformFake();
        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            new ServiceConfigurationEditor(platform).ApplyAsync(new(8080, 24, true, token), default));
        Assert.Equal("configure_service_input_invalid", error.Code);
        Assert.Equal(0, platform.LoadCalls);
        Assert.Equal(0, platform.ApplyCalls);
    }

    [Fact]
    public void Windows_rename_information_buffer_includes_the_native_filename_member_and_zero_tail()
    {
        var target = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "service.json"));
        var fileName = Encoding.Unicode.GetBytes(target);
        var fileNameOffset = Marshal.OffsetOf<ExpectedFileRenameInformation>(
            nameof(ExpectedFileRenameInformation.FileName)).ToInt32();
        var structureSize = Marshal.SizeOf<ExpectedFileRenameInformation>();

        var information = WindowsHandleBoundFile.CreateRenameInformation(target);

        Assert.Equal(checked(structureSize + fileName.Length), information.Length);
        Assert.Equal(
            0x00000043u,
            BinaryPrimitives.ReadUInt32LittleEndian(
                information.AsSpan(
                    Marshal.OffsetOf<ExpectedFileRenameInformation>(
                        nameof(ExpectedFileRenameInformation.Flags)).ToInt32(),
                    sizeof(uint))));
        Assert.All(
            information.AsSpan(
                Marshal.OffsetOf<ExpectedFileRenameInformation>(
                    nameof(ExpectedFileRenameInformation.RootDirectory)).ToInt32(),
                IntPtr.Size).ToArray(),
            value => Assert.Equal(0, value));
        Assert.Equal(
            fileName.Length,
            BinaryPrimitives.ReadInt32LittleEndian(
                information.AsSpan(
                    Marshal.OffsetOf<ExpectedFileRenameInformation>(
                        nameof(ExpectedFileRenameInformation.FileNameLength)).ToInt32(),
                    sizeof(int))));
        Assert.Equal(fileName, information.AsSpan(fileNameOffset, fileName.Length).ToArray());
        Assert.All(information[(fileNameOffset + fileName.Length)..], value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task Non_administrator_performs_zero_configuration_reads_or_writes()
    {
        var platform = new PlatformFake { IsAdministrator = false };
        var error = new StringWriter();

        var exit = await ConfigureServiceCommand.ExecuteAsync(
            [], new StringReader(string.Empty), new StringWriter(), error, platform, default);

        Assert.Equal(1, exit);
        Assert.Equal("administrator_required", error.ToString().Trim());
        Assert.Equal(0, platform.LoadCalls);
        Assert.Equal(0, platform.ApplyCalls);
    }

    [Fact]
    public async Task Editor_accepts_zero_retention_and_returns_a_strict_summary_without_token()
    {
        var platform = new PlatformFake { Configuration = Configuration() };
        var editor = new ServiceConfigurationEditor(platform);

        var result = await editor.ApplyAsync(
            new ServiceConfigurationEditRequest(
                8080,
                0,
                RotateToken: false),
            CancellationToken.None);

        Assert.NotNull(platform.Applied);
        Assert.Equal(0, platform.Applied.RetentionHours);
        Assert.Equal(8080, result.Summary.ListenPort);
        Assert.Equal(0, result.Summary.RetentionHours);
        Assert.Equal("0.2.0", result.Summary.ProductVersion);
        Assert.Null(result.OneTimeApiToken);
        Assert.Equal(1, platform.ApplyCalls);
    }

    [Fact]
    public async Task Editor_builds_the_strict_summary_before_committing_configuration()
    {
        var platform = new PlatformFake
        {
            Configuration = Configuration(),
            SummaryError = new ArgumentException("summary_invalid"),
        };

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            new ServiceConfigurationEditor(platform).ApplyAsync(
                new ServiceConfigurationEditRequest(
                    8080,
                    0,
                    RotateToken: false),
                CancellationToken.None));

        Assert.Equal("summary_invalid", error.Message);
        Assert.Equal(0, platform.ApplyCalls);
    }

    [Theory]
    [InlineData("service_restart_failed")]
    [InlineData("configure_service_state_uncertain")]
    public async Task Rotated_token_is_not_materialized_and_its_buffer_is_zeroed_when_apply_or_rollback_fails(
        string errorCode)
    {
        var tokenFactory = new RecordingConfigurationTokenFactory();
        var platform = new PlatformFake
        {
            Configuration = Configuration(),
            ApplyError = new ConfigureServiceException(errorCode),
        };

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            new ServiceConfigurationEditor(platform, tokenFactory).ApplyAsync(
                new ServiceConfigurationEditRequest(
                    8080,
                    24,
                    RotateToken: true),
                CancellationToken.None));

        Assert.Equal(errorCode, error.Code);
        Assert.Equal(1, tokenFactory.CreateCalls);
        Assert.False(tokenFactory.Token!.WasMaterialized);
        Assert.All(tokenFactory.Buffer, value => Assert.Equal('\0', value));
    }

    [Fact]
    public async Task Rotated_token_is_not_materialized_and_its_buffer_is_zeroed_when_apply_is_cancelled()
    {
        var tokenFactory = new RecordingConfigurationTokenFactory();
        using var cancellation = new CancellationTokenSource();
        var platform = new PlatformFake
        {
            Configuration = Configuration(),
            CancelOnApply = cancellation,
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new ServiceConfigurationEditor(platform, tokenFactory).ApplyAsync(
                new ServiceConfigurationEditRequest(
                    8080,
                    24,
                    RotateToken: true),
                cancellation.Token));

        Assert.Equal(1, tokenFactory.CreateCalls);
        Assert.False(tokenFactory.Token!.WasMaterialized);
        Assert.All(tokenFactory.Buffer, value => Assert.Equal('\0', value));
    }

    [Fact]
    public async Task Rotated_token_is_materialized_once_only_after_success_and_keeps_hash_compatibility()
    {
        var tokenFactory = new RecordingConfigurationTokenFactory();
        var platform = new PlatformFake { Configuration = Configuration() };

        var result = await new ServiceConfigurationEditor(platform, tokenFactory).ApplyAsync(
            new ServiceConfigurationEditRequest(
                8080,
                24,
                RotateToken: true),
            CancellationToken.None);

        var oneTimeToken = Assert.IsType<string>(result.OneTimeApiToken);
        Assert.Equal(RecordingConfigurationTokenFactory.ExpectedToken, oneTimeToken);
        Assert.True(tokenFactory.Token!.WasMaterialized);
        Assert.Equal(1, tokenFactory.Token.MaterializationCount);
        Assert.All(tokenFactory.Buffer, value => Assert.Equal('\0', value));
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(oneTimeToken))).ToLowerInvariant(),
            platform.Applied!.TokenHash);
    }

    [Fact]
    public async Task Editor_validates_before_first_platform_operation_and_releases_preacquired_lease_on_cancellation()
    {
        var invalidPlatform = new PlatformFake();
        var invalid = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            new ServiceConfigurationEditor(invalidPlatform).ApplyAsync(
                new ServiceConfigurationEditRequest(8080, 169, RotateToken: false),
                CancellationToken.None));

        Assert.Equal("configure_service_input_invalid", invalid.Code);
        Assert.Equal(0, invalidPlatform.LoadCalls);
        Assert.Equal(0, invalidPlatform.ApplyCalls);

        var cancelledPlatform = new PlatformFake();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new ServiceConfigurationEditor(cancelledPlatform).ApplyAsync(
                new ServiceConfigurationEditRequest(8080, 24, RotateToken: false),
                cancellation.Token));

        Assert.Equal(0, cancelledPlatform.LoadCalls);
        Assert.Equal(0, cancelledPlatform.ApplyCalls);

        var preacquiredLease = new TrackingLease();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new ServiceConfigurationEditor(
                cancelledPlatform,
                new ConfigureServiceLoadResult(
                    cancelledPlatform.Configuration,
                    new ConfigureServiceRevision("preloaded", new string('a', 64))),
                preacquiredLease)
                .ApplyAsync(
                    new ServiceConfigurationEditRequest(8080, 0, RotateToken: false),
                    cancellation.Token));
        Assert.True(preacquiredLease.Disposed);
    }

    [Fact]
    public async Task Planner_changes_only_allowlisted_fields_and_rotates_token_transactionally()
    {
        var platform = new PlatformFake { Configuration = Configuration() };
        var input = new StringReader("8443\n48\ny\ny\n");
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await ConfigureServiceCommand.ExecuteAsync(
            [], input, output, error, platform, default);

        Assert.Equal(0, exit);
        var updated = Assert.IsType<ServiceConfiguration>(platform.Applied);
        Assert.Equal(8443, updated.ListenPort);
        Assert.Equal(48, updated.RetentionHours);
        Assert.Equal(platform.Configuration.SigningUserSid, updated.SigningUserSid);
        Assert.Equal(platform.Configuration.DataRoot, updated.DataRoot);
        Assert.Equal(platform.Configuration.InstallInstanceId, updated.InstallInstanceId);
        Assert.NotEqual(platform.Configuration.TokenHash, updated.TokenHash);
        var visibleOutput = output.ToString();
        Assert.Contains("监听端口", visibleOutput, StringComparison.Ordinal);
        Assert.Contains("结果保留小时", visibleOutput, StringComparison.Ordinal);
        Assert.Contains("轮换 API token", visibleOutput, StringComparison.Ordinal);
        var tokenLine = Assert.Single(
            visibleOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries),
            line => line.StartsWith("API token (copy once): ", StringComparison.Ordinal));
        Assert.DoesNotContain(updated.TokenHash, tokenLine, StringComparison.Ordinal);
        Assert.Contains("确认已安全保存", visibleOutput, StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task Rotated_token_is_shown_once_and_process_waits_for_explicit_confirmation()
    {
        var platform = new PlatformFake { Configuration = Configuration() };
        var input = new GatedConfirmationReader(["", "", "y"]);
        var output = new StringWriter();

        var execution = ConfigureServiceCommand.ExecuteAsync(
            [], input, output, new StringWriter(), platform, default);
        await input.ConfirmationRequested.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(execution.IsCompleted);
        Assert.Single(
            output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries),
            line => line.StartsWith("API token (copy once): ", StringComparison.Ordinal));
        input.Confirm();

        Assert.Equal(0, await execution.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Single(
            output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries),
            line => line.StartsWith("API token (copy once): ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cancellation_after_token_display_cannot_close_the_process_before_confirmation()
    {
        var platform = new PlatformFake { Configuration = Configuration() };
        var input = new GatedConfirmationReader(["", "", "y"]);
        using var cancellation = new CancellationTokenSource();
        var execution = ConfigureServiceCommand.ExecuteAsync(
            [], input, new StringWriter(), new StringWriter(), platform, cancellation.Token);
        await input.ConfirmationRequested.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();
        await Assert.ThrowsAsync<TimeoutException>(() =>
            execution.WaitAsync(TimeSpan.FromMilliseconds(50)));

        input.Confirm();
        Assert.Equal(0, await execution.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task Competing_configuration_instance_is_rejected_before_any_read_and_leaks_no_plaintext()
    {
        var platform = new PlatformFake { LeaseAvailable = false };
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await ConfigureServiceCommand.ExecuteAsync(
            [], new StringReader(string.Empty), output, error, platform, default);

        Assert.Equal(1, exit);
        Assert.Equal("configure_service_busy", error.ToString().Trim());
        Assert.Equal(0, platform.LoadCalls);
        Assert.DoesNotContain("API token", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Named_configuration_lease_rejects_a_second_live_instance()
    {
        var factory = new ServiceConfigurationWriterLeaseFactory($"CodeSignAuto.Tests.{Guid.NewGuid():N}");

        using var first = Assert.IsAssignableFrom<IDisposable>(factory.TryAcquire());
        var second = factory.TryAcquire();

        Assert.Null(second);
    }

    [Fact]
    public async Task Failed_restart_rolls_back_and_never_displays_rotated_plaintext()
    {
        var platform = new PlatformFake
        {
            Configuration = Configuration(),
            ApplyError = new ConfigureServiceException("service_restart_failed"),
        };
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await ConfigureServiceCommand.ExecuteAsync(
            [], new StringReader("\n\ny\n"), output, error, platform, default);

        Assert.Equal(1, exit);
        Assert.DoesNotContain("API token (copy once): ", output.ToString(), StringComparison.Ordinal);
        Assert.Equal("service_restart_failed", error.ToString().Trim());
        Assert.Equal(1, platform.ApplyCalls);
    }

    [Fact]
    public void Token_hashing_zeroes_the_mutable_plaintext_buffer()
    {
        var plaintext = Encoding.UTF8.GetBytes("test-secret-token");
        var expected = Convert.ToHexString(SHA256.HashData(plaintext)).ToLowerInvariant();

        var actual = ConfigureServiceTokenSecret.HashAndZero(plaintext);

        Assert.Equal(expected, actual);
        Assert.All(plaintext, value => Assert.Equal(0, value));
    }

    [Fact]
    public void Route_accepts_only_argument_free_configure_service()
    {
        Assert.Equal(ApplicationEntryKind.ConfigureService, ApplicationEntryRoute.Parse(["configure-service"]).Kind);
        Assert.Equal(ApplicationEntryKind.Invalid, ApplicationEntryRoute.Parse(["configure-service", "--config", "evil"]).Kind);
    }

    [Fact]
    public async Task Unexpected_native_failure_is_reduced_to_a_stable_path_free_error()
    {
        var platform = new PlatformFake { LoadError = new InvalidOperationException("C:\\secret\\service.json") };
        var error = new StringWriter();

        var exit = await ConfigureServiceCommand.ExecuteAsync(
            [], new StringReader(string.Empty), new StringWriter(), error, platform, default);

        Assert.Equal(1, exit);
        Assert.Equal("configure_service_failed", error.ToString().Trim());
        Assert.DoesNotContain("secret", error.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Transactional_executor_rolls_back_configuration_and_running_service_after_restart_failure()
    {
        var original = Configuration();
        var updated = original with { ListenPort = 8443 };
        var runtime = new MutationRuntimeFake { FailFirstStart = true };
        var executor = new TransactionalConfigureServiceExecutor(runtime);

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            executor.ExecuteAsync(Loaded(original, runtime), updated, CancellationToken.None));

        Assert.Equal("service_restart_failed", error.Code);
        Assert.Equal(
            [
                "state", "verify:7080", "replace:8443", "stop", "start", "stop", "replace:7080", "start", "read",
                "verify:7080", "ready:7080",
            ],
            runtime.Events);
        Assert.True(ServiceConfigurationLoader.MatchesExpected(original, runtime.Persisted!));
    }

    [Fact]
    public async Task Transactional_executor_commits_only_after_restart_readback_and_ownership_verification()
    {
        var original = Configuration();
        var updated = original with { ListenPort = 8443 };
        var runtime = new MutationRuntimeFake();

        await new TransactionalConfigureServiceExecutor(runtime)
            .ExecuteAsync(Loaded(original, runtime), updated, CancellationToken.None);

        Assert.Equal(
            ["state", "verify:7080", "replace:8443", "stop", "start", "read", "verify:8443", "ready:8443"],
            runtime.Events);
        Assert.True(ServiceConfigurationLoader.MatchesExpected(updated, runtime.Persisted!));
    }

    [Fact]
    public async Task Transactional_executor_reports_uncertain_when_rollback_cannot_be_verified()
    {
        var original = Configuration();
        var runtime = new MutationRuntimeFake { FailFirstStart = true, FailRollbackReplace = true };
        var executor = new TransactionalConfigureServiceExecutor(runtime);

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            executor.ExecuteAsync(Loaded(original, runtime), original with { ListenPort = 8443 }, CancellationToken.None));

        Assert.Equal("configure_service_state_uncertain", error.Code);
        Assert.DoesNotContain("read", runtime.Events);
    }

    [Fact]
    public async Task Transactional_executor_restarts_again_with_original_configuration_after_post_start_verification_failure()
    {
        var original = Configuration();
        var updated = original with { ListenPort = 8443 };
        var runtime = new MutationRuntimeFake { FailUpdatedOwnershipVerification = true };

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            new TransactionalConfigureServiceExecutor(runtime)
                .ExecuteAsync(Loaded(original, runtime), updated, CancellationToken.None));

        Assert.Equal("service_restart_failed", error.Code);
        Assert.Equal(
            [
                "state", "verify:7080", "replace:8443", "stop", "start", "read", "verify:8443",
                "stop", "replace:7080", "start", "read", "verify:7080", "ready:7080",
            ],
            runtime.Events);
        Assert.True(ServiceConfigurationLoader.MatchesExpected(original, runtime.Persisted!));
    }

    [Fact]
    public async Task Transactional_executor_preserves_an_originally_stopped_service()
    {
        var original = Configuration();
        var updated = original with { ListenPort = 8443 };
        var runtime = new MutationRuntimeFake { OriginalState = ConfigureServiceState.Stopped };

        await new TransactionalConfigureServiceExecutor(runtime)
            .ExecuteAsync(Loaded(original, runtime), updated, CancellationToken.None);

        Assert.Equal(
            ["state", "verify:7080", "replace:8443", "start", "read", "verify:8443", "ready:8443", "stop", "state"],
            runtime.Events);
        Assert.Equal(ConfigureServiceState.Stopped, runtime.CurrentState);
    }

    [Fact]
    public async Task Originally_stopped_readiness_failure_rolls_back_without_token_eligible_commit()
    {
        var original = Configuration();
        var runtime = new MutationRuntimeFake
        {
            OriginalState = ConfigureServiceState.Stopped,
            FailUpdatedReadiness = true,
        };

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            new TransactionalConfigureServiceExecutor(runtime)
                .ExecuteAsync(Loaded(original, runtime), original with { ListenPort = 8443 }, CancellationToken.None));

        Assert.Equal("service_restart_failed", error.Code);
        Assert.Equal(ConfigureServiceState.Stopped, runtime.CurrentState);
        Assert.True(ServiceConfigurationLoader.MatchesExpected(original, runtime.Persisted!));
        Assert.Equal(
            [
                "state", "verify:7080", "replace:8443", "start", "read", "verify:8443", "ready:8443",
                "stop", "replace:7080", "read", "verify:7080", "state",
            ],
            runtime.Events);
    }

    [Fact]
    public async Task Rollback_refuses_to_overwrite_an_external_configuration_change()
    {
        var original = Configuration();
        var runtime = new MutationRuntimeFake
        {
            FailUpdatedReadiness = true,
            ChangeRevisionBeforeRollback = true,
        };

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            new TransactionalConfigureServiceExecutor(runtime)
                .ExecuteAsync(Loaded(original, runtime), original with { ListenPort = 8443 }, CancellationToken.None));

        Assert.Equal("configure_service_state_uncertain", error.Code);
        Assert.Equal(9443, runtime.Persisted!.ListenPort);
    }

    [Fact]
    public async Task Readiness_failure_rolls_back_configuration_and_restores_running_state()
    {
        var original = Configuration();
        var updated = original with { ListenPort = 8443 };
        var runtime = new MutationRuntimeFake { FailUpdatedReadiness = true };

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            new TransactionalConfigureServiceExecutor(runtime)
                .ExecuteAsync(Loaded(original, runtime), updated, CancellationToken.None));

        Assert.Equal("service_restart_failed", error.Code);
        Assert.Equal(
            [
                "state", "verify:7080", "replace:8443", "stop", "start", "read", "verify:8443", "ready:8443",
                "stop", "replace:7080", "start", "read", "verify:7080", "ready:7080",
            ],
            runtime.Events);
        Assert.Equal(ConfigureServiceState.Running, runtime.CurrentState);
        Assert.True(ServiceConfigurationLoader.MatchesExpected(original, runtime.Persisted!));
    }

    [Fact]
    public async Task Protected_configuration_load_reads_and_verifies_the_same_no_follow_handle()
    {
        var expected = Configuration();
        var content = JsonSerializer.SerializeToUtf8Bytes(expected, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var operations = new ProtectedConfigurationOperationsFake(content);
        var storage = new ProtectedConfigurationStorage(operations);

        var snapshot = await storage.ReadSnapshotAsync(ProtectedConfigurationTestPath(), default);
        var actual = ServiceConfigurationLoader.Deserialize(Encoding.UTF8.GetString(snapshot.Content));

        Assert.True(ServiceConfigurationLoader.MatchesExpected(expected, actual));
        Assert.Equal("target-A", snapshot.Revision.Identity);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(),
            snapshot.Revision.ContentSha256);
        Assert.Equal(["parent", "target", "read:target-A"], operations.Events);
        Assert.True(operations.ParentVerifiedBeforeTargetOpen);
    }

    [Fact]
    public async Task Protected_configuration_replace_rejects_a_target_identity_swap_before_publish()
    {
        var operations = new ProtectedConfigurationOperationsFake([1, 2, 3])
        {
            SwapTargetBeforeReplace = true,
        };
        var storage = new ProtectedConfigurationStorage(operations);

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            storage.ReplaceAsync(
                ProtectedConfigurationTestPath(),
                new ConfigureServiceRevision("target-A", Convert.ToHexString(SHA256.HashData([1, 2, 3])).ToLowerInvariant()),
                new byte[] { 4, 5, 6 },
                default));

        Assert.Equal("configure_service_state_uncertain", error.Code);
        Assert.Equal(["parent", "replace:target-A"], operations.Events);
        Assert.False(operations.Published);
    }

    [Fact]
    public async Task Protected_configuration_replace_rejects_in_place_content_change_since_load()
    {
        var operations = new ProtectedConfigurationOperationsFake([1, 2, 3])
        {
            ChangeContentBeforeReplace = true,
        };
        var storage = new ProtectedConfigurationStorage(operations);
        var snapshot = await storage.ReadSnapshotAsync(ProtectedConfigurationTestPath(), default);

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            storage.ReplaceAsync(ProtectedConfigurationTestPath(), snapshot.Revision, new byte[] { 4, 5, 6 }, default));

        Assert.Equal("configure_service_state_uncertain", error.Code);
        Assert.False(operations.Published);
    }

    [Theory]
    [InlineData("temp")]
    [InlineData("target")]
    public async Task Protected_configuration_replace_detects_verified_entry_swap(string entry)
    {
        var operations = new ProtectedConfigurationOperationsFake([1, 2, 3])
        {
            SwapVerifiedEntry = entry,
        };
        var storage = new ProtectedConfigurationStorage(operations);
        var snapshot = await storage.ReadSnapshotAsync(ProtectedConfigurationTestPath(), default);

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            storage.ReplaceAsync(ProtectedConfigurationTestPath(), snapshot.Revision, new byte[] { 4, 5, 6 }, default));

        Assert.Equal("configure_service_state_uncertain", error.Code);
        Assert.False(operations.Published);
    }

    [Fact]
    public async Task Protected_configuration_publish_seam_preserves_an_external_change_after_verification()
    {
        var operations = new ProtectedConfigurationOperationsFake([1, 2, 3])
        {
            ChangeTargetAfterVerification = true,
        };
        var storage = new ProtectedConfigurationStorage(operations);
        var snapshot = await storage.ReadSnapshotAsync(ProtectedConfigurationTestPath(), default);

        var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
            storage.ReplaceAsync(ProtectedConfigurationTestPath(), snapshot.Revision, new byte[] { 4, 5, 6 }, default));

        Assert.Equal("configure_service_state_uncertain", error.Code);
        Assert.Equal(new byte[] { 9, 9, 9 }, operations.CurrentContent);
        Assert.False(operations.Published);
    }

    [WindowsFact]
    public async Task Windows_native_protected_configuration_rejects_a_reparse_target_without_touching_its_victim()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-protected-{Guid.NewGuid():N}");
        var victim = Path.Combine(Path.GetTempPath(), $"simplysign-victim-{Guid.NewGuid():N}.json");
        var target = Path.Combine(root, "service.json");
        Directory.CreateDirectory(root);
        await File.WriteAllTextAsync(victim, "victim-content");
        try
        {
            WindowsInstallAcl.ApplyDirectory(
                root,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            File.CreateSymbolicLink(target, victim);
            var storage = new ProtectedConfigurationStorage(new WindowsProtectedConfigurationOperations());

            var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
                storage.ReplaceAsync(
                    target,
                    new ConfigureServiceRevision("untrusted", new string('0', 64)),
                    new byte[] { 1, 2, 3 },
                    default));

            Assert.Equal("configure_service_state_uncertain", error.Code);
            Assert.Equal("victim-content", await File.ReadAllTextAsync(victim));
        }
        finally
        {
            if (File.Exists(target) || WindowsPathSafety.IsReparse(target))
            {
                File.Delete(target);
            }
            Directory.Delete(root, recursive: false);
            File.Delete(victim);
        }
    }

    [WindowsFact]
    public async Task Windows_native_protected_configuration_cas_rejects_in_place_content_change()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-protected-{Guid.NewGuid():N}");
        var target = Path.Combine(root, "service.json");
        Directory.CreateDirectory(root);
        try
        {
            WindowsInstallAcl.ApplyDirectory(
                root,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            await WindowsAtomicProtectedFile.WriteNewAsync(target, new byte[] { 1, 2, 3 }, default);
            var storage = new ProtectedConfigurationStorage(new WindowsProtectedConfigurationOperations());
            var snapshot = await storage.ReadSnapshotAsync(target, default);
            await File.WriteAllBytesAsync(target, new byte[] { 9, 9, 9 });

            var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
                storage.ReplaceAsync(target, snapshot.Revision, new byte[] { 4, 5, 6 }, default));

            Assert.Equal("configure_service_state_uncertain", error.Code);
            Assert.Equal(new byte[] { 9, 9, 9 }, await File.ReadAllBytesAsync(target));
        }
        finally
        {
            File.Delete(target);
            Directory.Delete(root, recursive: false);
        }
    }

    [WindowsFact]
    public async Task Windows_native_protected_configuration_cas_rejects_reinstalled_target()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-protected-{Guid.NewGuid():N}");
        var target = Path.Combine(root, "service.json");
        Directory.CreateDirectory(root);
        try
        {
            WindowsInstallAcl.ApplyDirectory(
                root,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            await WindowsAtomicProtectedFile.WriteNewAsync(target, new byte[] { 1, 2, 3 }, default);
            var storage = new ProtectedConfigurationStorage(new WindowsProtectedConfigurationOperations());
            var snapshot = await storage.ReadSnapshotAsync(target, default);
            File.Delete(target);
            await WindowsAtomicProtectedFile.WriteNewAsync(target, new byte[] { 1, 2, 3 }, default);

            var error = await Assert.ThrowsAsync<ConfigureServiceException>(() =>
                storage.ReplaceAsync(target, snapshot.Revision, new byte[] { 4, 5, 6 }, default));

            Assert.Equal("configure_service_state_uncertain", error.Code);
            Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(target));
        }
        finally
        {
            File.Delete(target);
            Directory.Delete(root, recursive: false);
        }
    }

    [WindowsFact]
    public async Task Windows_native_protected_publish_guard_blocks_in_place_write_after_verification()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-protected-{Guid.NewGuid():N}");
        var target = Path.Combine(root, "service.json");
        Directory.CreateDirectory(root);
        var blocked = false;
        try
        {
            WindowsInstallAcl.ApplyDirectory(
                root,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            await WindowsAtomicProtectedFile.WriteNewAsync(target, new byte[] { 1, 2, 3 }, default);
            var operations = new WindowsProtectedConfigurationOperations(() =>
            {
                try
                {
                    File.WriteAllBytes(target, new byte[] { 9, 9, 9 });
                }
                catch (IOException)
                {
                    blocked = true;
                }
            });
            var storage = new ProtectedConfigurationStorage(operations);
            var snapshot = await storage.ReadSnapshotAsync(target, default);

            await storage.ReplaceAsync(target, snapshot.Revision, new byte[] { 4, 5, 6 }, default);

            Assert.True(blocked);
            Assert.Equal(new byte[] { 4, 5, 6 }, await File.ReadAllBytesAsync(target));
        }
        finally
        {
            File.Delete(target);
            Directory.Delete(root, recursive: false);
        }
    }

    [WindowsFact]
    public async Task Windows_native_protected_publish_guard_blocks_reinstall_after_verification()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-protected-{Guid.NewGuid():N}");
        var target = Path.Combine(root, "service.json");
        Directory.CreateDirectory(root);
        var blocked = false;
        try
        {
            WindowsInstallAcl.ApplyDirectory(
                root,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            await WindowsAtomicProtectedFile.WriteNewAsync(target, new byte[] { 1, 2, 3 }, default);
            var operations = new WindowsProtectedConfigurationOperations(() =>
            {
                try
                {
                    File.Delete(target);
                    File.WriteAllBytes(target, new byte[] { 9, 9, 9 });
                }
                catch (IOException)
                {
                    blocked = true;
                }
            });
            var storage = new ProtectedConfigurationStorage(operations);
            var snapshot = await storage.ReadSnapshotAsync(target, default);

            await storage.ReplaceAsync(target, snapshot.Revision, new byte[] { 4, 5, 6 }, default);

            Assert.True(blocked);
            Assert.Equal(new byte[] { 4, 5, 6 }, await File.ReadAllBytesAsync(target));
        }
        finally
        {
            File.Delete(target);
            Directory.Delete(root, recursive: false);
        }
    }

    private static ServiceConfiguration Configuration()
    {
        var root = Path.Combine(Path.GetTempPath(), "CodeSignAuto-configure-service");
        var dataRoot = Path.Combine(root, "data");
        return new ServiceConfiguration(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("old-token"))).ToLowerInvariant(),
            "S-1-5-21-1000", dataRoot, Path.Combine(dataRoot, "spool"),
            7080, "CodeSignAuto/v1", new string('a', 32),
            Path.Combine(root, "install", "CodeSignAuto.exe"),
            Path.Combine(root, "profile", "agent.json"), 24);
    }

    private static ConfigureServiceLoadResult Loaded(
        ServiceConfiguration configuration,
        MutationRuntimeFake runtime) =>
        new(configuration, runtime.InitialRevision);

    private static string ProtectedConfigurationTestPath() =>
        Path.Combine(Path.GetTempPath(), "CodeSignAuto-protected-config", "service.json");

    [StructLayout(LayoutKind.Sequential)]
    private struct ExpectedFileRenameInformation
    {
        public uint Flags;
        public nint RootDirectory;
        public uint FileNameLength;
        public ushort FileName;
    }

    private sealed class PlatformFake : IConfigureServicePlatform
    {
        public bool IsAdministrator { get; set; } = true;
        public ServiceConfiguration Configuration { get; set; } = ConfigureServiceCommandTests.Configuration();
        public ServiceConfiguration? Applied { get; private set; }
        public Exception? ApplyError { get; set; }
        public Exception? LoadError { get; set; }
        public int LoadCalls { get; private set; }
        public int ApplyCalls { get; private set; }
        public bool LeaseAvailable { get; set; } = true;
        public Exception? SummaryError { get; set; }
        public CancellationTokenSource? CancelOnApply { get; set; }

        public IDisposable? TryAcquireInstanceLease() =>
            LeaseAvailable ? NoopLease.Instance : null;

        public bool IsAdministratorElevated() => IsAdministrator;

        public Task<ConfigureServiceLoadResult> LoadProtectedAsync(CancellationToken cancellationToken)
        {
            LoadCalls++;
            return LoadError is null
                ? Task.FromResult(new ConfigureServiceLoadResult(
                    Configuration,
                    new ConfigureServiceRevision("platform-A", new string('a', 64))))
                : Task.FromException<ConfigureServiceLoadResult>(LoadError);
        }

        public Task ApplyAndRestartAsync(
            ConfigureServiceLoadResult original,
            ServiceConfiguration updated,
            CancellationToken cancellationToken)
        {
            ApplyCalls++;
            Applied = updated;
            if (CancelOnApply is not null)
            {
                CancelOnApply.Cancel();
                return Task.FromCanceled(CancelOnApply.Token);
            }

            return ApplyError is null ? Task.CompletedTask : Task.FromException(ApplyError);
        }

        public ServiceSettingsSummary CreateSettingsSummary(ServiceConfiguration configuration)
        {
            if (SummaryError is not null)
            {
                throw SummaryError;
            }

            return new ServiceSettingsSummary(
                configuration.ListenPort,
                ServiceSettingsSummary.FixedMaximumUploadBytes,
                configuration.RetentionHours,
                "0.2.0");
        }

        private sealed class NoopLease : IDisposable
        {
            public static NoopLease Instance { get; } = new();
            public void Dispose() { }
        }
    }

    private sealed class TrackingLease : IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
    }

    private sealed class RecordingConfigurationTokenFactory : IServiceConfigurationTokenFactory
    {
        public const string ExpectedToken = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";

        public char[] Buffer { get; } = ExpectedToken.ToCharArray();
        public int CreateCalls { get; private set; }
        public SensitiveOneTimeApiToken? Token { get; private set; }

        public SensitiveOneTimeApiToken Create()
        {
            CreateCalls++;
            Token = new SensitiveOneTimeApiToken(Buffer);
            return Token;
        }
    }

    private sealed class GatedConfirmationReader(IEnumerable<string> initialLines) : TextReader
    {
        private readonly Queue<string> _lines = new(initialLines);
        private readonly TaskCompletionSource<string?> _confirmation =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ConfirmationRequested { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override ValueTask<string?> ReadLineAsync(CancellationToken cancellationToken)
        {
            if (_lines.TryDequeue(out var line))
            {
                return ValueTask.FromResult<string?>(line);
            }

            ConfirmationRequested.TrySetResult();
            return new ValueTask<string?>(_confirmation.Task.WaitAsync(cancellationToken));
        }

        public void Confirm() => _confirmation.TrySetResult("y");
    }

    private sealed class MutationRuntimeFake : IConfigureServiceMutationRuntime
    {
        private int _startCalls;
        private int _replaceCalls;

        public List<string> Events { get; } = [];
        public ServiceConfiguration? Persisted { get; private set; }
        public bool FailFirstStart { get; set; }
        public bool FailRollbackReplace { get; set; }
        public bool FailUpdatedOwnershipVerification { get; set; }
        public bool FailUpdatedReadiness { get; set; }
        public bool ChangeRevisionBeforeRollback { get; set; }
        public ConfigureServiceState OriginalState { get; set; } = ConfigureServiceState.Running;
        public ConfigureServiceState CurrentState { get; private set; } = ConfigureServiceState.Running;
        public ConfigureServiceRevision InitialRevision { get; } =
            new("revision-A", new string('a', 64));
        public ConfigureServiceRevision CurrentRevision { get; private set; } =
            new("revision-A", new string('a', 64));

        public Task<ConfigureServiceState> GetServiceStateAsync(CancellationToken cancellationToken)
        {
            Events.Add("state");
            if (Events.Count == 1)
            {
                CurrentState = OriginalState;
            }

            return Task.FromResult(CurrentState);
        }

        public Task VerifyOwnershipAsync(ServiceConfiguration configuration, CancellationToken cancellationToken)
        {
            Events.Add($"verify:{configuration.ListenPort}");
            if (configuration.ListenPort == 8443 && FailUpdatedOwnershipVerification)
            {
                throw new IOException("updated ownership failed");
            }

            return Task.CompletedTask;
        }

        public Task<ConfigureServiceRevision> ReplaceProtectedAsync(
            ServiceConfiguration configuration,
            ConfigureServiceRevision expected,
            CancellationToken cancellationToken)
        {
            Events.Add($"replace:{configuration.ListenPort}");
            if (Interlocked.Increment(ref _replaceCalls) == 2 && FailRollbackReplace)
            {
                throw new IOException("rollback failed");
            }

            if (ChangeRevisionBeforeRollback && _replaceCalls == 2)
            {
                Persisted = configuration with { ListenPort = 9443 };
                CurrentRevision = new ConfigureServiceRevision("external", new string('e', 64));
            }

            if (CurrentRevision != expected)
            {
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }

            Persisted = configuration;
            CurrentRevision = new ConfigureServiceRevision(
                $"revision-{_replaceCalls + 1}",
                new string((char)('a' + _replaceCalls), 64));
            return Task.FromResult(CurrentRevision);
        }

        public Task StopServiceAsync(CancellationToken cancellationToken)
        {
            Events.Add("stop");
            CurrentState = ConfigureServiceState.Stopped;
            return Task.CompletedTask;
        }

        public Task StartServiceAsync(CancellationToken cancellationToken)
        {
            Events.Add("start");
            if (Interlocked.Increment(ref _startCalls) == 1 && FailFirstStart)
            {
                throw new IOException("restart failed");
            }

            CurrentState = ConfigureServiceState.Running;
            return Task.CompletedTask;
        }

        public Task<ConfigureServiceLoadResult> ReadBackAsync(CancellationToken cancellationToken)
        {
            Events.Add("read");
            return Task.FromResult(new ConfigureServiceLoadResult(Persisted!, CurrentRevision));
        }

        public Task WaitUntilReadyAsync(ServiceConfiguration configuration, CancellationToken cancellationToken)
        {
            Events.Add($"ready:{configuration.ListenPort}");
            if (configuration.ListenPort == 8443 && FailUpdatedReadiness)
            {
                throw new IOException("readiness failed");
            }

            return Task.CompletedTask;
        }
    }

    private sealed class ProtectedConfigurationOperationsFake(byte[] content) :
        IProtectedConfigurationOperations
    {
        private readonly byte[] _content = content;
        private readonly FakeDirectory _directory = new();
        private readonly FakeFile _file = new("target-A");

        public List<string> Events { get; } = [];
        public bool ParentVerifiedBeforeTargetOpen { get; private set; }
        public bool SwapTargetBeforeReplace { get; init; }
        public bool ChangeContentBeforeReplace { get; init; }
        public bool ChangeTargetAfterVerification { get; init; }
        public string? SwapVerifiedEntry { get; init; }
        public bool Published { get; private set; }
        public byte[] CurrentContent => _content.ToArray();

        public IProtectedConfigurationDirectory OpenProtectedParent(string path)
        {
            Events.Add("parent");
            _directory.Verified = true;
            return _directory;
        }

        public IProtectedConfigurationFile OpenNoFollowConfiguration(
            IProtectedConfigurationDirectory parent,
            string fileName)
        {
            ParentVerifiedBeforeTargetOpen = _directory.Verified;
            Events.Add("target");
            return _file;
        }

        public Task<byte[]> ReadAllAsync(
            IProtectedConfigurationFile file,
            CancellationToken cancellationToken)
        {
            Events.Add($"read:{file.Identity.Value}");
            return Task.FromResult(_content.ToArray());
        }

        public Task<ConfigureServiceRevision> ReplaceVerifiedAsync(
            IProtectedConfigurationDirectory parent,
            string fileName,
            ConfigureServiceRevision expected,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            Events.Add($"replace:{expected.Identity}");
            var current = SwapTargetBeforeReplace
                ? new ProtectedConfigurationIdentity("target-B")
                : _file.Identity;
            var currentContent = ChangeContentBeforeReplace ? new byte[] { 9, 9, 9 } : _content;
            var currentHash = Convert.ToHexString(SHA256.HashData(currentContent)).ToLowerInvariant();
            if (current.Value != expected.Identity || currentHash != expected.ContentSha256 ||
                SwapVerifiedEntry is not null)
            {
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }

            if (ChangeTargetAfterVerification)
            {
                Array.Fill(_content, (byte)9);
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }

            Published = true;
            return Task.FromResult(new ConfigureServiceRevision(
                "target-C",
                Convert.ToHexString(SHA256.HashData(content.Span)).ToLowerInvariant()));
        }

        private sealed class FakeDirectory : IProtectedConfigurationDirectory
        {
            public bool Verified { get; set; }
            public ProtectedConfigurationIdentity Identity { get; } = new("parent-A");
            public void Dispose() { }
        }

        private sealed class FakeFile(string identity) : IProtectedConfigurationFile
        {
            public ProtectedConfigurationIdentity Identity { get; } = new(identity);
            public void Dispose() { }
        }
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Windows-only protected file semantics.";
            }
        }
    }

}
