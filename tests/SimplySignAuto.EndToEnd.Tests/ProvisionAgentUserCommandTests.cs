using SimplySignAuto.App.Commands;
using SimplySignAuto.App;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class ProvisionAgentUserCommandTests
{
    [Fact]
    public void Fresh_user_rights_request_can_create_the_LSA_account_object()
    {
        Assert.Equal(0x00000810u, WindowsLsaAccountRights.AddPolicyAccess);
    }

    [Fact]
    public void Provision_command_route_and_arguments_never_accept_a_password_or_secret_value()
    {
        Assert.Equal(
            ApplicationEntryKind.ProvisionAgentUser,
            ApplicationEntryRoute.Parse([
                "provision-agent-user", "--mode", "provision-user", "--user", "signer",
            ]).Kind);
        Assert.True(ProvisionAgentUserCommand.TryParse(
            ["--mode", "existing-user", "--user", "signer"],
            out var existing));
        Assert.Equal(AgentUserProvisionMode.ExistingUser, existing!.Mode);
        Assert.True(ProvisionAgentUserCommand.TryParse(
            ["--mode", "repair-user", "--user", "signer"],
            out var repair));
        Assert.Equal("RepairUser", repair!.Mode.ToString());
        Assert.False(ProvisionAgentUserCommand.TryParse(
            ["--mode", "provision-user", "--user", "signer", "--password", "forbidden"],
            out _));
    }

    [Fact]
    public async Task Existing_user_mode_performs_readback_without_any_mutation()
    {
        var platform = RecordingPlatform.ExistingReady();
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var result = await orchestrator.ExecuteAsync(
            new ProvisionAgentUserOptions(AgentUserProvisionMode.ExistingUser, "signer"),
            CancellationToken.None);

        Assert.Equal("TEST\\signer", result.AccountName);
        Assert.Empty(platform.Mutations);
        Assert.Equal(["inspect", "readback"], platform.Reads);
    }

    [Fact]
    public async Task Existing_user_mode_rejects_dangerous_rights_without_any_mutation()
    {
        var platform = RecordingPlatform.ExistingReady(dangerousRightsPresent: true);
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.ExistingUser, "signer"),
                CancellationToken.None));

        Assert.Equal("agent_user_rights_invalid", failure.Code);
        Assert.Empty(platform.Mutations);
        Assert.Equal(["inspect"], platform.Reads);
    }

    [Fact]
    public async Task Repair_user_mode_resets_the_existing_password_and_recreates_owned_autologon()
    {
        var platform = RecordingPlatform.Repairable();
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var result = await orchestrator.ExecuteAsync(
            new ProvisionAgentUserOptions(AgentUserProvisionMode.RepairUser, "signer"),
            CancellationToken.None);

        Assert.Equal("TEST\\signer", result.AccountName);
        Assert.Equal(
            ["configure-rights", "store-lsa", "write-winlogon", "create-task", "reset-password"],
            platform.Mutations);
        Assert.DoesNotContain("create-user", platform.Mutations);
        Assert.Equal(["inspect", "readback"], platform.Reads);
        Assert.True(platform.SecretReceivedWithoutStringConversion);
        Assert.Equal(["readback", "reset-password"], platform.Events[^2..]);
    }

    [Fact]
    public async Task Repair_user_failure_rolls_back_only_new_autologon_state_and_keeps_the_account()
    {
        var platform = RecordingPlatform.Repairable();
        platform.FailingOperation = "create-task";
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.RepairUser, "signer"),
                CancellationToken.None));

        Assert.Equal("task_registration_failed", failure.Code);
        Assert.DoesNotContain("reset-password", platform.Mutations);
        Assert.Equal(["rollback:write-winlogon", "rollback:store-lsa"], platform.Rollbacks);
        Assert.DoesNotContain("rollback:create-user", platform.Rollbacks);
        Assert.DoesNotContain("rollback:configure-rights", platform.Rollbacks);
    }

    [Fact]
    public async Task Repair_user_rejects_a_non_product_local_account_without_mutation()
    {
        var platform = RecordingPlatform.Fresh(ProvisionConflict.ExistingUser);
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.RepairUser, "signer"),
                CancellationToken.None));

        Assert.Equal("agent_user_not_managed", failure.Code);
        Assert.Empty(platform.Mutations);
    }

    [Fact]
    public async Task Fresh_provision_uses_protected_secret_and_exact_readback_without_exposing_password()
    {
        var platform = RecordingPlatform.Fresh();
        var password = StrongPassword();
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(password),
            new FixedProvisionOwnerGenerator());
        using var output = new StringWriter();

        var result = await orchestrator.ExecuteAsync(
            new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, "signer"),
            output,
            CancellationToken.None);

        Assert.Equal("TEST\\signer", result.AccountName);
        Assert.Equal(
            ["create-user", "create-profile", "configure-rights", "store-lsa", "write-winlogon", "create-task"],
            platform.Mutations);
        Assert.Equal(["inspect", "readback"], platform.Reads);
        Assert.Equal("agent_user_ready" + Environment.NewLine, output.ToString());
        Assert.False(platform.RegistryDefaultPasswordWritten);
        Assert.True(platform.SecretReceivedWithoutStringConversion);
    }

    [Fact]
    public async Task Fresh_provision_setup_hook_runs_after_user_creation_and_before_profile_or_autologon()
    {
        var platform = RecordingPlatform.Fresh();
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var result = await orchestrator.ExecuteAsync(
            new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, "signer"),
            (createdUser, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                platform.Events.Add($"authorize-media:{createdUser.Sid}");
                return Task.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal("S-1-5-21-1000-2000-3000-4000", result.Sid);
        Assert.True(
            platform.Events.IndexOf("create-user") <
            platform.Events.IndexOf("authorize-media:S-1-5-21-1000-2000-3000-4000"));
        Assert.True(
            platform.Events.IndexOf("authorize-media:S-1-5-21-1000-2000-3000-4000") <
            platform.Events.IndexOf("create-profile"));
        Assert.DoesNotContain("authorize-media:TEST\\signer", platform.Events);
    }

    [Fact]
    public async Task Fresh_provision_setup_hook_failure_rolls_back_only_the_new_user_before_profile()
    {
        var platform = RecordingPlatform.Fresh();
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, "signer"),
                (createdUser, cancellationToken) =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    platform.Events.Add($"authorize-media:{createdUser.Sid}");
                    throw new ProvisionAgentUserException("install_media_authorization_failed");
                },
                CancellationToken.None));

        Assert.Equal("install_media_authorization_failed", failure.Code);
        Assert.Equal(["create-user"], platform.Mutations);
        Assert.Equal(["rollback:create-user"], platform.Rollbacks);
        Assert.DoesNotContain("create-profile", platform.Events);
        Assert.DoesNotContain("configure-rights", platform.Events);
        Assert.DoesNotContain("write-winlogon", platform.Events);
        Assert.DoesNotContain("create-task", platform.Events);
    }

    [Fact]
    public async Task Empty_password_generator_result_is_rejected_before_any_mutation()
    {
        var platform = RecordingPlatform.Fresh();
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator([]),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, "signer"),
                CancellationToken.None));

        Assert.Equal("password_generation_failed", failure.Code);
        Assert.Empty(platform.Mutations);
    }

    [Theory]
    [InlineData(ProvisionConflict.ExistingUser, "agent_user_exists")]
    [InlineData(ProvisionConflict.OtherAutoLogon, "autologon_conflict")]
    [InlineData(ProvisionConflict.DomainController, "domain_controller_unsupported")]
    [InlineData(ProvisionConflict.NotAdministrator, "administrator_required")]
    [InlineData(ProvisionConflict.DangerousRights, "agent_user_rights_invalid")]
    public async Task Provision_preflight_rejects_conflicts_without_mutation(
        ProvisionConflict conflict,
        string expectedCode)
    {
        var platform = RecordingPlatform.Fresh(conflict);
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, "signer"),
                CancellationToken.None));

        Assert.Equal(expectedCode, failure.Code);
        Assert.Empty(platform.Mutations);
    }

    [Theory]
    [InlineData("create-profile", "profile_create_failed")]
    [InlineData("store-lsa", "lsa_secret_write_failed")]
    [InlineData("write-winlogon", "autologon_registry_failed")]
    [InlineData("create-task", "task_registration_failed")]
    [InlineData("readback", "autologon_readback_failed")]
    public async Task Provision_failure_rolls_back_only_this_runs_owned_changes_in_reverse_order(
        string failingOperation,
        string expectedCode)
    {
        var platform = RecordingPlatform.Fresh();
        platform.FailingOperation = failingOperation;
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, "signer"),
                CancellationToken.None));

        Assert.Equal(expectedCode, failure.Code);
        Assert.Equal(
            platform.Mutations
                .Where(operation => operation != failingOperation)
                .Reverse()
                .Select(operation => "rollback:" + operation),
            platform.Rollbacks);
    }

    [Fact]
    public async Task Rollback_failure_preserves_the_first_error_and_marks_state_uncertain()
    {
        var platform = RecordingPlatform.Fresh();
        platform.FailingOperation = "create-task";
        platform.FailingRollback = "store-lsa";
        var orchestrator = new ProvisionAgentUserOrchestrator(
            platform,
            new FixedPasswordGenerator(StrongPassword()),
            new FixedProvisionOwnerGenerator());

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            orchestrator.ExecuteAsync(
                new ProvisionAgentUserOptions(AgentUserProvisionMode.ProvisionUser, "signer"),
                CancellationToken.None));

        Assert.Equal("task_registration_failed", failure.Code);
        Assert.True(failure.RollbackStateUncertain);
    }

    [Fact]
    public void Lsa_store_readback_failure_removes_the_just_written_secret_and_exact_receipt()
    {
        var secret = new RecordingLsaSecretStore { FailReadbackAfterWrite = true };
        var receipt = new RecordingLsaOwnerReceiptStore();
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);
        using var password = new FixedPasswordGenerator(StrongPassword()).Generate();

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            transaction.Store(password, FixedProvisionOwnerGenerator.Owner));

        Assert.Equal("lsa_secret_readback_failed", failure.Code);
        Assert.False(failure.RollbackStateUncertain);
        Assert.False(secret.Present);
        Assert.Null(receipt.Owner);
        Assert.Equal([
            "read-secret", "store-secret", "read-secret", "read-secret", "remove-secret", "read-secret",
        ],
            secret.Events.Select(item => item.Name));
        Assert.Equal(["write-receipt", "remove-receipt"], receipt.Events.Select(item => item.Name));
    }

    [Fact]
    public void Lsa_receipt_native_failure_after_write_self_compensates_the_exact_receipt()
    {
        var secret = new RecordingLsaSecretStore();
        var receipt = new RecordingLsaOwnerReceiptStore { FailAfterWrite = true };
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);
        using var password = new FixedPasswordGenerator(StrongPassword()).Generate();

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            transaction.Store(password, FixedProvisionOwnerGenerator.Owner));

        Assert.Equal("lsa_secret_receipt_failed", failure.Code);
        Assert.False(failure.RollbackStateUncertain);
        Assert.False(secret.Present);
        Assert.Null(receipt.Owner);
        Assert.Equal(["write-receipt", "remove-receipt"], receipt.Events.Select(item => item.Name));
    }

    [Fact]
    public void Lsa_secret_native_failure_after_write_rechecks_fingerprint_and_self_compensates()
    {
        var secret = new RecordingLsaSecretStore { FailAfterWrite = true };
        var receipt = new RecordingLsaOwnerReceiptStore();
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);
        using var password = new FixedPasswordGenerator(StrongPassword()).Generate();

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            transaction.Store(password, FixedProvisionOwnerGenerator.Owner));

        Assert.Equal("lsa_secret_write_failed", failure.Code);
        Assert.False(failure.RollbackStateUncertain);
        Assert.False(secret.Present);
        Assert.Null(receipt.Owner);
        Assert.Contains(secret.Events, item => item.Name == "remove-secret");
    }

    [Fact]
    public void Lsa_store_owner_swap_fails_uncertain_without_deleting_the_replacement_secret()
    {
        var receipt = new RecordingLsaOwnerReceiptStore();
        var secret = new RecordingLsaSecretStore
        {
            FailReadbackAfterWrite = true,
            BeforeReadbackFailure = () => receipt.Owner = "SimplySignAuto/v1/fedcba9876543210fedcba9876543210",
        };
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);
        using var password = new FixedPasswordGenerator(StrongPassword()).Generate();

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            transaction.Store(password, FixedProvisionOwnerGenerator.Owner));

        Assert.Equal("lsa_secret_readback_failed", failure.Code);
        Assert.True(failure.RollbackStateUncertain);
        Assert.True(secret.Present);
        Assert.Equal("SimplySignAuto/v1/fedcba9876543210fedcba9876543210", receipt.Owner);
        Assert.DoesNotContain(secret.Events, item => item.Name == "remove-secret");
    }

    [Fact]
    public void Global_lsa_rollback_rechecks_exact_owner_before_deleting_anything()
    {
        var secret = new RecordingLsaSecretStore { Present = true };
        var receipt = new RecordingLsaOwnerReceiptStore
        {
            Owner = "SimplySignAuto/v1/fedcba9876543210fedcba9876543210",
        };
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            transaction.Remove(FixedProvisionOwnerGenerator.Owner));

        Assert.Equal("provision_state_uncertain", failure.Code);
        Assert.True(failure.RollbackStateUncertain);
        Assert.True(secret.Present);
        Assert.DoesNotContain(secret.Events, item => item.Name == "remove-secret");
    }

    [Fact]
    public void Lsa_receipt_binds_the_exact_owner_to_the_stored_secret_fingerprint()
    {
        var secret = new RecordingLsaSecretStore();
        var receipt = new RecordingLsaOwnerReceiptStore();
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);
        using var password = new FixedPasswordGenerator(StrongPassword()).Generate();

        transaction.Store(password, FixedProvisionOwnerGenerator.Owner);

        Assert.Equal(FixedProvisionOwnerGenerator.Owner, receipt.Owner);
        Assert.NotNull(secret.Fingerprint);
        Assert.Equal(secret.Fingerprint, receipt.Fingerprint);
        Assert.Matches("^[0-9A-F]{64}$", receipt.Fingerprint);
    }

    [Fact]
    public void Lsa_secret_only_replacement_is_preserved_and_reports_uncertain_state()
    {
        var secret = new RecordingLsaSecretStore();
        var receipt = new RecordingLsaOwnerReceiptStore();
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);
        using var password = new FixedPasswordGenerator(StrongPassword()).Generate();
        transaction.Store(password, FixedProvisionOwnerGenerator.Owner);
        secret.ReplaceWithExternalSecret();

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            transaction.Remove(FixedProvisionOwnerGenerator.Owner));

        Assert.Equal("provision_state_uncertain", failure.Code);
        Assert.True(failure.RollbackStateUncertain);
        Assert.True(secret.Present);
        Assert.DoesNotContain(secret.Events, item => item.Name == "remove-secret");
        Assert.Equal(FixedProvisionOwnerGenerator.Owner, receipt.Owner);
    }

    [Fact]
    public void Lsa_final_cleanup_resumes_after_the_owned_secret_was_removed_before_its_receipt()
    {
        var secret = new RecordingLsaSecretStore();
        var receipt = new RecordingLsaOwnerReceiptStore();
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);
        using var password = new FixedPasswordGenerator(StrongPassword()).Generate();
        transaction.Store(password, FixedProvisionOwnerGenerator.Owner);
        secret.Present = false;

        transaction.FinalizeRemoval(FixedProvisionOwnerGenerator.Owner);

        Assert.False(secret.Present);
        Assert.Null(receipt.Owner);
        Assert.Contains(receipt.Events, item => item.Name == "remove-receipt");
    }

    [Fact]
    public void Lsa_final_cleanup_never_removes_an_unowned_remaining_receipt()
    {
        var secret = new RecordingLsaSecretStore();
        var receipt = new RecordingLsaOwnerReceiptStore
        {
            Owner = "SimplySignAuto/v1/fedcba9876543210fedcba9876543210",
        };
        var transaction = new OwnedLsaSecretTransaction(secret, receipt);

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            transaction.FinalizeRemoval(FixedProvisionOwnerGenerator.Owner));

        Assert.True(failure.RollbackStateUncertain);
        Assert.Equal("SimplySignAuto/v1/fedcba9876543210fedcba9876543210", receipt.Owner);
        Assert.DoesNotContain(receipt.Events, item => item.Name == "remove-receipt");
    }

    [Fact]
    public void Cli_failure_format_preserves_the_business_code_and_marks_uncertain_rollback()
    {
        var failure = new ProvisionAgentUserException(
            "task_registration_failed",
            rollbackStateUncertain: true);

        Assert.Equal(
            "task_registration_failed rollback_state_uncertain",
            ProvisionAgentUserCommand.FormatFailure(failure));
    }

    [Fact]
    public void Winlogon_transaction_restores_the_in_memory_snapshot_at_every_write_boundary()
    {
        for (var boundary = 1; boundary <= 11; boundary++)
        {
            var registry = RecordingWinlogonValueStore.WithPriorValues();
            var before = registry.Snapshot();
            registry.FailAtMutation = boundary;
            var transaction = new WinlogonMutationTransaction(registry);

            var failure = Assert.Throws<ProvisionAgentUserException>(() =>
                transaction.Apply("signer", "TEST", FixedProvisionOwnerGenerator.Owner));

            Assert.Equal("autologon_registry_failed", failure.Code);
            Assert.False(failure.RollbackStateUncertain);
            Assert.Equal(before, registry.Snapshot());
            Assert.DoesNotContain(registry.Values.Keys, name =>
                name != WinlogonMutationTransaction.LsaOwnerReceiptValueName &&
                name.StartsWith("SimplySignAuto", StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData(64, 64, true)]
    [InlineData(64, 66, true)]
    [InlineData(0, 0, false)]
    [InlineData(63, 64, false)]
    [InlineData(66, 64, false)]
    [InlineData(1026, 1026, false)]
    public void Lsa_retrieved_secret_length_is_strictly_bounded_before_zeroing(
        int length,
        int maximumLength,
        bool expected)
    {
        Assert.Equal(
            expected,
            WindowsLsaPrivateData.IsValidRetrievedSecretBuffer(
                new IntPtr(1),
                checked((ushort)length),
                checked((ushort)maximumLength)));
    }

    [Fact]
    public void Lsa_native_fingerprint_seam_matches_and_clears_the_retrieved_plaintext_buffer()
    {
        var characters = StrongPassword();
        var plaintext = System.Runtime.InteropServices.MemoryMarshal.AsBytes(characters.AsSpan()).ToArray();
        var expected = System.Security.Cryptography.SHA256.HashData(plaintext);
        var native = System.Runtime.InteropServices.Marshal.AllocHGlobal(plaintext.Length);
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(plaintext, 0, native, plaintext.Length);

            Assert.True(WindowsLsaPrivateData.MatchesAndZeroRetrievedSecretBuffer(
                native,
                checked((ushort)plaintext.Length),
                checked((ushort)plaintext.Length),
                expected));

            var readback = new byte[plaintext.Length];
            System.Runtime.InteropServices.Marshal.Copy(native, readback, 0, readback.Length);
            Assert.All(readback, value => Assert.Equal(0, value));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(expected);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(characters.AsSpan()));
            System.Runtime.InteropServices.Marshal.FreeHGlobal(native);
        }
    }

    [Fact]
    public void Csprng_password_has_required_structure_and_never_stringifies()
    {
        using var password = new CryptographicAgentUserPasswordGenerator().Generate();

        Assert.True(password.Length >= 32);
        Assert.True(password.ContainsCategory(AgentUserPasswordCategory.Uppercase));
        Assert.True(password.ContainsCategory(AgentUserPasswordCategory.Lowercase));
        Assert.True(password.ContainsCategory(AgentUserPasswordCategory.Digit));
        Assert.True(password.ContainsCategory(AgentUserPasswordCategory.Symbol));
        Assert.Equal(string.Empty, password.ToString());
    }

    private static char[] StrongPassword() =>
        "Ab3!".Concat(Enumerable.Repeat('x', 28)).ToArray();

    public enum ProvisionConflict
    {
        None,
        ExistingUser,
        OtherAutoLogon,
        DomainController,
        NotAdministrator,
        DangerousRights,
    }

    private sealed class FixedPasswordGenerator(char[] value) : IAgentUserPasswordGenerator
    {
        public SensitiveAgentUserPassword Generate() => new((char[])value.Clone());
    }

    private sealed class FixedProvisionOwnerGenerator : IProvisionOwnerGenerator
    {
        public const string Owner = "SimplySignAuto/v1/0123456789abcdef0123456789abcdef";

        public string Generate() => Owner;
    }

    private sealed class RecordingLsaSecretStore : IWindowsLsaSecretStore
    {
        private static int _sequence;
        private byte[]? _fingerprint;

        public bool Present { get; set; }

        public string? Fingerprint => _fingerprint is null ? null : Convert.ToHexString(_fingerprint);

        public bool FailReadbackAfterWrite { get; set; }

        public bool FailAfterWrite { get; init; }

        public Action? BeforeReadbackFailure { get; init; }

        public List<(int Sequence, string Name)> Events { get; } = [];

        public bool Exists()
        {
            Events.Add((Interlocked.Increment(ref _sequence), "read-secret"));
            return Present;
        }

        public bool MatchesFingerprint(ReadOnlySpan<byte> expectedFingerprint)
        {
            Events.Add((Interlocked.Increment(ref _sequence), "read-secret"));
            if (FailReadbackAfterWrite && Present)
            {
                FailReadbackAfterWrite = false;
                BeforeReadbackFailure?.Invoke();
                throw new ProvisionAgentUserException("lsa_secret_readback_failed");
            }

            return Present && _fingerprint is not null &&
                System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    _fingerprint,
                    expectedFingerprint);
        }

        public void Store(SensitiveAgentUserPassword password)
        {
            Events.Add((Interlocked.Increment(ref _sequence), "store-secret"));
            _fingerprint = System.Security.Cryptography.SHA256.HashData(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(password.AsSpan()));
            Present = true;
            if (FailAfterWrite)
            {
                throw new ProvisionAgentUserException("lsa_secret_write_failed");
            }
        }

        public void Remove()
        {
            Events.Add((Interlocked.Increment(ref _sequence), "remove-secret"));
            if (_fingerprint is not null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(_fingerprint);
                _fingerprint = null;
            }

            Present = false;
        }

        public void ReplaceWithExternalSecret()
        {
            if (_fingerprint is not null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(_fingerprint);
            }

            _fingerprint = Enumerable.Repeat((byte)0xA5, 32).ToArray();
            Present = true;
        }
    }

    private sealed class RecordingLsaOwnerReceiptStore : IWindowsLsaOwnerReceiptStore
    {
        private static int _sequence;
        private const string Separator = "/sha256/";
        private string? _receipt;

        public string? Owner
        {
            get
            {
                var separator = _receipt?.IndexOf(Separator, StringComparison.Ordinal) ?? -1;
                return separator > 0 ? _receipt![..separator] : _receipt;
            }
            set
            {
                if (value is null)
                {
                    _receipt = null;
                    return;
                }

                _receipt = Fingerprint is { } fingerprint
                    ? value + Separator + fingerprint
                    : value;
            }
        }

        public string? Fingerprint
        {
            get
            {
                var separator = _receipt?.IndexOf(Separator, StringComparison.Ordinal) ?? -1;
                return separator > 0 ? _receipt![(separator + Separator.Length)..] : null;
            }
        }

        public bool FailAfterWrite { get; init; }

        public List<(int Sequence, string Name)> Events { get; } = [];

        public string? ReadReceipt() => _receipt;

        public void WriteReceipt(string receipt)
        {
            Events.Add((Interlocked.Increment(ref _sequence), "write-receipt"));
            _receipt = receipt;
            if (FailAfterWrite)
            {
                throw new ProvisionAgentUserException("lsa_secret_receipt_failed");
            }
        }

        public void RemoveReceipt()
        {
            Events.Add((Interlocked.Increment(ref _sequence), "remove-receipt"));
            _receipt = null;
        }
    }

    private sealed class RecordingWinlogonValueStore : IWinlogonValueStore
    {
        private int _mutations;

        public Dictionary<string, WinlogonStoredValue> Values { get; } = new(StringComparer.Ordinal);

        public int FailAtMutation { get; set; }

        public static RecordingWinlogonValueStore WithPriorValues()
        {
            var store = new RecordingWinlogonValueStore();
            store.Values["DefaultUserName"] = WinlogonStoredValue.String("prior-user");
            store.Values["DefaultDomainName"] = WinlogonStoredValue.String("PRIOR");
            store.Values["AutoAdminLogon"] = WinlogonStoredValue.String("0");
            store.Values[WinlogonMutationTransaction.LsaOwnerReceiptValueName] =
                WinlogonStoredValue.String(LsaSecretReceipt.Create(
                    FixedProvisionOwnerGenerator.Owner,
                    Enumerable.Repeat((byte)0x5A, 32).ToArray()));
            return store;
        }

        public string Snapshot() => string.Join(
            "|",
            Values.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{pair.Key}:{pair.Value.Kind}:{pair.Value.Value}"));

        public WinlogonStoredValue Read(string name) =>
            Values.TryGetValue(name, out var value) ? value : WinlogonStoredValue.Missing;

        public void Write(string name, WinlogonStoredValue value)
        {
            Mutate();
            Values[name] = value;
        }

        public void Delete(string name)
        {
            Mutate();
            Values.Remove(name);
        }

        public void Flush() => Mutate();

        private void Mutate()
        {
            _mutations++;
            if (_mutations == FailAtMutation)
            {
                FailAtMutation = 0;
                throw new InvalidOperationException("injected registry boundary failure");
            }
        }
    }

    private sealed class RecordingPlatform : IWindowsAutoLogonPlatform
    {
        private readonly AgentUserProvisionInspection _inspection;
        private readonly ProvisionedAgentUser _user = new(
            "TEST\\signer",
            "S-1-5-21-1000-2000-3000-4000",
            "TEST");

        private RecordingPlatform(AgentUserProvisionInspection inspection) =>
            _inspection = inspection;

        public List<string> Reads { get; } = [];
        public List<string> Mutations { get; } = [];
        public List<string> Rollbacks { get; } = [];
        public List<string> Events { get; } = [];
        public string? FailingOperation { get; set; }
        public string? FailingRollback { get; set; }
        public bool RegistryDefaultPasswordWritten { get; private set; }
        public bool SecretReceivedWithoutStringConversion { get; private set; }

        public static RecordingPlatform ExistingReady(bool dangerousRightsPresent = false) => new(new AgentUserProvisionInspection(
            IsWindowsServer2025: true,
            IsAdministrator: true,
            IsDomainController: false,
            UserExists: true,
            AutoLogonConfigured: true,
            AutoLogonAccountName: "TEST\\signer",
            RegistryDefaultPasswordPresent: false,
            ProvisionOwnerPresent: false,
            DangerousRightsPresent: dangerousRightsPresent));

        public static RecordingPlatform Repairable() => new(new AgentUserProvisionInspection(
            IsWindowsServer2025: true,
            IsAdministrator: true,
            IsDomainController: false,
            UserExists: true,
            AutoLogonConfigured: false,
            AutoLogonAccountName: null,
            RegistryDefaultPasswordPresent: false,
            ProvisionOwnerPresent: false,
            DangerousRightsPresent: false,
            LsaDefaultPasswordPresent: false,
            ManagedLocalUser: true));

        public static RecordingPlatform Fresh(ProvisionConflict conflict = ProvisionConflict.None) => new(
            new AgentUserProvisionInspection(
                IsWindowsServer2025: true,
                IsAdministrator: conflict != ProvisionConflict.NotAdministrator,
                IsDomainController: conflict == ProvisionConflict.DomainController,
                UserExists: conflict == ProvisionConflict.ExistingUser,
                AutoLogonConfigured: conflict == ProvisionConflict.OtherAutoLogon,
                AutoLogonAccountName: conflict == ProvisionConflict.OtherAutoLogon ? "TEST\\other" : null,
                RegistryDefaultPasswordPresent: false,
                ProvisionOwnerPresent: false,
                DangerousRightsPresent: conflict == ProvisionConflict.DangerousRights));

        public Task<AgentUserProvisionInspection> InspectAsync(
            string userName,
            CancellationToken cancellationToken)
        {
            Reads.Add("inspect");
            Events.Add("inspect");
            return Task.FromResult(_inspection);
        }

        public Task<ProvisionedAgentUser> ResolveExistingUserAsync(
            string userName,
            CancellationToken cancellationToken) => Task.FromResult(_user);

        public Task<ProvisionedAgentUser> CreateLocalUserAsync(
            string userName,
            SensitiveAgentUserPassword password,
            CancellationToken cancellationToken)
        {
            Mutate("create-user");
            return Task.FromResult(_user);
        }

        public Task ResetLocalUserPasswordAsync(
            ProvisionedAgentUser user,
            SensitiveAgentUserPassword password,
            CancellationToken cancellationToken)
        {
            SecretReceivedWithoutStringConversion = password.ToString().Length == 0;
            Mutate("reset-password");
            return Task.CompletedTask;
        }

        public Task<ProvisionedAgentUser> CreateUserProfileAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken)
        {
            Mutate("create-profile");
            return Task.FromResult(user with
            {
                ProfilePath = @"C:\Users\signer",
                OwnerMarker = ownerMarker,
            });
        }

        public Task ConfigureRightsAsync(
            ProvisionedAgentUser user,
            CancellationToken cancellationToken)
        {
            Mutate("configure-rights");
            return Task.CompletedTask;
        }

        public Task StoreLsaSecretAsync(
            ProvisionedAgentUser user,
            SensitiveAgentUserPassword password,
            string ownerMarker,
            CancellationToken cancellationToken)
        {
            SecretReceivedWithoutStringConversion = password.ToString().Length == 0;
            Mutate("store-lsa");
            return Task.CompletedTask;
        }

        public Task WriteWinlogonAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken)
        {
            RegistryDefaultPasswordWritten = false;
            Mutate("write-winlogon");
            return Task.CompletedTask;
        }

        public Task CreateAgentTaskAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken)
        {
            Mutate("create-task");
            return Task.CompletedTask;
        }

        public Task<AgentUserProvisionReadback> ReadbackAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken)
        {
            Reads.Add("readback");
            Events.Add("readback");
            if (FailingOperation == "readback")
            {
                throw new ProvisionAgentUserException("autologon_readback_failed");
            }

            return Task.FromResult(new AgentUserProvisionReadback(
                UserExists: true,
                OnlyUsersGroup: true,
                InteractiveLogonAllowed: true,
                NetworkLogonDenied: true,
                RemoteInteractiveLogonDenied: true,
                AutoLogonAccountName: user.AccountName,
                AutoAdminLogonEnabled: true,
                LsaSecretPresent: true,
                RegistryDefaultPasswordPresent: false,
                AgentTaskExact: true,
                OwnerMarker: string.IsNullOrEmpty(ownerMarker)
                    ? "SimplySignAuto/v1/0123456789abcdef0123456789abcdef"
                    : ownerMarker,
                ProfileExact: !string.IsNullOrEmpty(ownerMarker),
                ProfilePath: !string.IsNullOrEmpty(ownerMarker) ? user.ProfilePath : null));
        }

        public Task RollbackAgentTaskAsync(ProvisionedAgentUser user, string ownerMarker) =>
            RollbackAsync("create-task");

        public Task RollbackWinlogonAsync(ProvisionedAgentUser user, string ownerMarker) =>
            RollbackAsync("write-winlogon");

        public Task RollbackLsaSecretAsync(ProvisionedAgentUser user, string ownerMarker) =>
            RollbackAsync("store-lsa");

        public Task RollbackRightsAsync(ProvisionedAgentUser user) =>
            RollbackAsync("configure-rights");

        public Task RollbackUserProfileAsync(ProvisionedAgentUser user, string ownerMarker) =>
            RollbackAsync("create-profile");

        public Task RollbackLocalUserAsync(ProvisionedAgentUser user) =>
            RollbackAsync("create-user");

        private void Mutate(string operation)
        {
            Mutations.Add(operation);
            Events.Add(operation);
            if (FailingOperation == operation)
            {
                throw new ProvisionAgentUserException(operation switch
                {
                    "store-lsa" => "lsa_secret_write_failed",
                    "write-winlogon" => "autologon_registry_failed",
                    "create-task" => "task_registration_failed",
                    "create-profile" => "profile_create_failed",
                    "reset-password" => "agent_user_password_reset_failed",
                    _ => "provision_agent_user_failed",
                });
            }
        }

        private Task RollbackAsync(string operation)
        {
            Rollbacks.Add("rollback:" + operation);
            return operation == FailingRollback
                ? Task.FromException(new ProvisionAgentUserException("provision_state_uncertain"))
                : Task.CompletedTask;
        }
    }
}
