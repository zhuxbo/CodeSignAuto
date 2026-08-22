using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text.Json;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.App;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.Tools;
using SimplySignAuto.Service;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class UninstallSafetyTests
{
    [Fact]
    public void Trusted_anchor_rejects_every_effective_dangerous_allow_for_an_untrusted_concrete_sid()
    {
        var first = "S-1-5-21-111111111-222222222-333333333-1001";
        var second = "S-1-5-21-444444444-555555555-666666666-2001";
        FileSystemRights[] dangerousRights =
        [
            FileSystemRights.FullControl,
            FileSystemRights.Delete,
            FileSystemRights.DeleteSubdirectoriesAndFiles,
            FileSystemRights.ChangePermissions,
            FileSystemRights.TakeOwnership,
        ];
        foreach (var identity in new[] { first, second })
        {
            foreach (var rights in dangerousRights)
            {
                var failure = Assert.Throws<InstallException>(() =>
                    WindowsTrustedAnchorAcl.Verify(
                        "S-1-5-18",
                        [new WindowsTrustedAnchorRuleSnapshot(
                            identity,
                            (int)rights,
                            IsAllow: true,
                            AppliesToAnchor: true)]));

                Assert.Equal("uninstall_path_invalid", failure.Code);
            }
        }
    }

    [Fact]
    public void Trusted_anchor_allows_only_the_explicit_trusted_identities_as_owner_and_dangerous_allow()
    {
        string[] trustedIdentities =
        [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        ];
        foreach (var identity in trustedIdentities)
        {
            WindowsTrustedAnchorAcl.Verify(
                identity,
                [new WindowsTrustedAnchorRuleSnapshot(
                    identity,
                    (int)FileSystemRights.FullControl,
                    IsAllow: true,
                    AppliesToAnchor: true)]);
        }
    }

    [Fact]
    public void Trusted_anchor_rejects_an_untrusted_owner_even_without_access_rules()
    {
        var failure = Assert.Throws<InstallException>(() =>
            WindowsTrustedAnchorAcl.Verify(
                "S-1-5-21-111111111-222222222-333333333-1001",
                []));

        Assert.Equal("uninstall_path_invalid", failure.Code);
    }

    [Fact]
    public void Trusted_anchor_ignores_inherit_only_and_deny_rules_that_do_not_grant_anchor_access()
    {
        const string untrusted = "S-1-5-21-111111111-222222222-333333333-1001";

        WindowsTrustedAnchorAcl.Verify(
            "S-1-5-18",
            [
                new WindowsTrustedAnchorRuleSnapshot(
                    untrusted,
                    (int)FileSystemRights.FullControl,
                    IsAllow: true,
                    AppliesToAnchor: false),
                new WindowsTrustedAnchorRuleSnapshot(
                    untrusted,
                    (int)FileSystemRights.FullControl,
                    IsAllow: false,
                    AppliesToAnchor: true),
            ]);
    }

    [Fact]
    public void Trusted_anchor_allows_an_untrusted_effective_rule_without_dangerous_rights()
    {
        WindowsTrustedAnchorAcl.Verify(
            "S-1-5-18",
            [new WindowsTrustedAnchorRuleSnapshot(
                "S-1-5-21-111111111-222222222-333333333-1001",
                (int)FileSystemRights.ReadAndExecute,
                IsAllow: true,
                AppliesToAnchor: true)]);
    }

    [Theory]
    [InlineData("direction")]
    [InlineData("action")]
    [InlineData("enabled")]
    [InlineData("profiles")]
    public void Firewall_ownership_requires_every_created_field_to_match(string changedField)
    {
        var expected = new WindowsFirewallRuleSnapshot(
            "SimplySignAuto API",
            "SimplySignAuto/v1",
            "SimplySignAuto/v1",
            6,
            "7080",
            1,
            1,
            true,
            int.MaxValue);
        var changed = changedField switch
        {
            "direction" => expected with { Direction = 2 },
            "action" => expected with { Action = 0 },
            "enabled" => expected with { Enabled = false },
            "profiles" => expected with { Profiles = 1 },
            _ => throw new InvalidOperationException(),
        };

        Assert.True(WindowsFirewallRuleContract.IsExact(
            expected,
            expected.Name,
            expected.Description,
            7080));
        Assert.False(WindowsFirewallRuleContract.IsExact(
            changed,
            expected.Name,
            expected.Description,
            7080));
    }

    [Fact]
    public void Firewall_add_then_external_replacement_is_never_removed_by_name()
    {
        var policy = new ReplacingFirewallPolicy();

        var failure = Assert.Throws<InstallException>(() =>
            new WindowsFirewallCreationCoordinator(policy).Create(
                "SimplySignAuto API",
                "SimplySignAuto/v1/0123456789abcdef0123456789abcdef",
                7080));

        Assert.Equal("install_state_uncertain", failure.Code);
        Assert.Equal(1, policy.AddCalls);
        Assert.Equal(0, policy.RemoveCalls);
        Assert.NotNull(policy.Current);
    }

    [Fact]
    public void Firewall_add_failure_removes_only_the_still_exact_instance_and_verifies_missing()
    {
        var policy = new ExactThenFailFirewallPolicy();

        var failure = Assert.Throws<InstallException>(() =>
            new WindowsFirewallCreationCoordinator(policy).Create(
                "SimplySignAuto API",
                "SimplySignAuto/v1/0123456789abcdef0123456789abcdef",
                7080));

        Assert.Equal("synthetic_add_failure", failure.Code);
        Assert.Equal(1, policy.RemoveCalls);
        Assert.Null(policy.Current);
        Assert.True(policy.MissingVerified);
    }

    [Theory]
    [InlineData("identity", "owned_resource_mismatch")]
    [InlineData("task", "owned_resource_mismatch")]
    [InlineData("task", "resource_preflight_failed")]
    [InlineData("service", "owned_resource_mismatch")]
    [InlineData("autologon", "owned_resource_mismatch")]
    [InlineData("firewall", "owned_resource_mismatch")]
    [InlineData("session", "resource_preflight_failed")]
    [InlineData("rights", "owned_resource_mismatch")]
    [InlineData("profile", "owned_resource_mismatch")]
    [InlineData("user", "owned_resource_mismatch")]
    [InlineData("data", "uninstall_path_invalid")]
    [InlineData("product-registration", "owned_resource_mismatch")]
    public async Task Any_late_owner_preflight_failure_causes_zero_uninstall_mutation(
        string failingResource,
        string failureCode)
    {
        var native = new RecordingWindowsUninstallNative(failingResource, failureCode);
        var purge = new RecordingPurgeIsolationFileSystem();
        var executor = new WindowsUninstallActionExecutor(
            native,
            purge,
            AllowOptionalToolUninstallPreflight.Instance,
            AllowInstalledMediaUninstallPreflight.Instance);
        var plan = Plan(includePurge: true);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new UninstallOrchestrator(executor).ExecuteAsync(plan, TextWriter.Null, CancellationToken.None));

        Assert.Equal(failureCode, failure.Code);
        Assert.Empty(native.Mutations);
        Assert.Empty(purge.Calls);
    }

    [Fact]
    public async Task Installed_media_mismatch_stops_uninstall_before_every_native_mutation()
    {
        var native = new RecordingWindowsUninstallNative("identity", "native_preflight_should_not_run");
        var purge = new RecordingPurgeIsolationFileSystem();
        var media = new RecordingInstalledMediaUninstallPreflight
        {
            Failure = new InstallException("owned_resource_mismatch"),
        };
        var executor = new WindowsUninstallActionExecutor(
            native,
            purge,
            AllowOptionalToolUninstallPreflight.Instance,
            media);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new UninstallOrchestrator(executor).ExecuteAsync(
                Plan(includePurge: true),
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("owned_resource_mismatch", failure.Code);
        Assert.Equal(1, media.Calls);
        Assert.Empty(native.Mutations);
        Assert.Empty(purge.Calls);
    }

    [Fact]
    public async Task Legacy_receipt_removal_requires_exact_preflight_readback_then_deletes_once()
    {
        var basePlan = Plan(includePurge: false);
        var receipt = InstallationReceipt.ForService(basePlan.Configuration);
        var receiptStore = new RecordingInstallationReceiptStore(receipt);
        var plan = basePlan with
        {
            Actions = [.. basePlan.Actions, new RemoveOwnedInstallationReceipt(receipt)],
            Receipt = receipt,
        };
        var executor = new WindowsUninstallActionExecutor(
            new RecordingWindowsUninstallNative(null, null),
            new RecordingPurgeIsolationFileSystem(),
            AllowOptionalToolUninstallPreflight.Instance,
            AllowInstalledMediaUninstallPreflight.Instance,
            receiptStore);

        await new UninstallOrchestrator(executor)
            .ExecuteAsync(plan, TextWriter.Null, CancellationToken.None);

        Assert.Equal(["load", "delete"], receiptStore.Events);
        Assert.Null(receiptStore.Current);
    }

    [Fact]
    public async Task Default_uninstall_fully_cleans_the_exact_product_managed_user()
    {
        var configuration = Configuration();
        var identity = ManagedIdentity(configuration);
        var planner = new UninstallPlanner(new RecordingUninstallEnvironment(configuration, identity));

        var plan = await planner.PlanAsync(
            new UninstallOptions(PurgeData: false, Confirmation: null),
            CancellationToken.None);

        var removal = Assert.Single(plan.Actions.OfType<RemoveOwnedAutoLogon>());
        Assert.Equal(configuration.SigningUserSid, removal.SigningUserSid);
        Assert.Equal(
            "SimplySignAuto/v1/0123456789abcdef0123456789abcdef",
            removal.OwnerMarker);
        Assert.Collection(
            plan.Actions,
            action => Assert.IsType<RemoveOwnedInteractiveLogonTask>(action),
            action => Assert.IsType<RemoveOwnedWindowsService>(action),
            action => Assert.IsType<RemoveOwnedFirewallRule>(action),
            action => Assert.IsType<RemoveOwnedPdfExtension>(action),
            action => Assert.IsType<EndOwnedSigningUserSession>(action),
            action => Assert.IsType<RemoveOwnedAutoLogon>(action),
            action => Assert.IsType<RemoveOwnedAccountRights>(action),
            action => Assert.IsType<DeleteOwnedLocalUser>(action),
            action => Assert.IsType<DeleteOwnedWindowsProfile>(action),
            action => Assert.IsType<PurgeControlledData>(action),
            action => Assert.IsType<RemoveOwnedDesktopShortcut>(action),
            action => Assert.IsType<RemoveOwnedProductUninstall>(action));
        var productRegistration = Assert.IsType<RemoveOwnedProductUninstall>(plan.Actions[^1]).Registration;
        Assert.Equal(configuration.ExecutablePath, productRegistration.ExecutablePath);
        Assert.Equal(
            InstallOwnershipMarker.Create(configuration.InstallInstanceId),
            productRegistration.OwnerMarker);
    }

    [Fact]
    public async Task Service_receipt_is_cross_checked_and_covered_by_the_owned_data_isolation()
    {
        var configuration = Configuration();
        var identity = ManagedIdentity(configuration);
        var receipt = InstallationReceipt.ForService(configuration);
        var planner = new UninstallPlanner(
            new RecordingUninstallEnvironment(configuration, identity, receipt));

        var plan = await planner.PlanAsync(
            new UninstallOptions(PurgeData: false, Confirmation: null),
            CancellationToken.None);

        Assert.Equal(receipt, plan.Receipt);
        Assert.Contains(plan.Actions, action =>
            action is PurgeControlledData purge && purge.DataRoot == configuration.DataRoot);
        Assert.DoesNotContain(plan.Actions, action => action is RemoveOwnedInstallationReceipt);
    }

    [Fact]
    public async Task Upgraded_legacy_service_without_data_isolation_removes_the_exact_receipt()
    {
        var configuration = Configuration();
        var receipt = InstallationReceipt.ForService(configuration);

        var plan = await new UninstallPlanner(
                new RecordingUninstallEnvironment(configuration, identity: null, receipt: receipt))
            .PlanAsync(
                new UninstallOptions(PurgeData: false, Confirmation: null),
                CancellationToken.None);

        Assert.Equal(
            receipt,
            Assert.IsType<RemoveOwnedInstallationReceipt>(plan.Actions[^1]).Receipt);
    }

    [Fact]
    public async Task Receipt_and_service_configuration_identity_conflicts_fail_closed()
    {
        var configuration = Configuration();
        var exact = InstallationReceipt.ForService(configuration);
        var identity = ManagedIdentity(configuration);
        foreach (var conflicting in new[]
        {
            exact with
            {
                Mode = InstallationMode.Manual,
                UserDataRoot = Path.GetFullPath(Path.Combine(
                    Path.GetTempPath(),
                    "SimplySignAuto.Tests",
                    "manual")),
            },
            exact with { InstallInstanceId = "fedcba9876543210fedcba9876543210" },
            exact with { SigningUserSid = "S-1-5-21-1000-2000-3000-5000" },
            exact with
            {
                ExecutablePath = Path.GetFullPath(Path.Combine(
                    Path.GetDirectoryName(configuration.ExecutablePath)!,
                    "other",
                    "SimplySignAuto.exe")),
            },
        })
        {
            var failure = await Assert.ThrowsAsync<InstallException>(() =>
                new UninstallPlanner(
                        new RecordingUninstallEnvironment(configuration, identity, conflicting))
                    .PlanAsync(
                        new UninstallOptions(PurgeData: false, Confirmation: null),
                        CancellationToken.None));

            Assert.Equal("owned_resource_mismatch", failure.Code);
        }
    }

    [Fact]
    public async Task Manual_default_uninstall_removes_activation_and_preserves_task_data()
    {
        var receipt = ManualReceipt();
        var plan = await new ManualUninstallPlanner(new RecordingManualUninstallEnvironment(receipt))
            .PlanAsync(new UninstallOptions(PurgeData: false, Confirmation: null), CancellationToken.None);

        Assert.Equal(UninstallSigningUserOwnership.ExistingUser, plan.Identity.Ownership);
        Assert.Collection(
            plan.Actions,
            action => Assert.IsType<RemoveOwnedPdfExtension>(action),
            action =>
            {
                var activation = Assert.IsType<RemoveOwnedManualActivation>(action);
                Assert.Equal(Path.Combine(receipt.UserDataRoot!, "otp.dat"), activation.Path);
                Assert.Equal(receipt.UserDataRoot, activation.UserDataRoot);
                Assert.Equal(receipt.SigningUserSid, activation.SigningUserSid);
            },
            action =>
            {
                var purge = Assert.IsType<PurgeControlledData>(action);
                Assert.False(purge.IncludeAgentDirectory);
                Assert.Equal(receipt.UserDataRoot, purge.AgentDirectory);
            },
            action => Assert.IsType<RemoveOwnedDesktopShortcut>(action),
            action => Assert.IsType<RemoveOwnedProductUninstall>(action));
        Assert.DoesNotContain(plan.Actions, action => action is RemoveOwnedWindowsService);
        Assert.DoesNotContain(plan.Actions, action => action is RemoveOwnedInteractiveLogonTask);
        Assert.DoesNotContain(plan.Actions, action => action is RemoveOwnedAutoLogon);
        Assert.DoesNotContain(plan.Actions, action => action is RemoveOwnedAccountRights);
        Assert.DoesNotContain(plan.Actions, action => action is DeleteOwnedLocalUser);
        Assert.DoesNotContain(plan.Actions, action => action is DeleteOwnedWindowsProfile);
    }

    [Fact]
    public async Task Manual_user_data_is_purged_only_with_the_existing_exact_confirmation()
    {
        var receipt = ManualReceipt();
        var planner = new ManualUninstallPlanner(new RecordingManualUninstallEnvironment(receipt));

        var plan = await planner.PlanAsync(
            new UninstallOptions(PurgeData: true, Confirmation: "PURGE"),
            CancellationToken.None);

        var purge = Assert.Single(plan.Actions.OfType<PurgeControlledData>());
        Assert.True(purge.IncludeAgentDirectory);
        Assert.Equal(receipt.UserDataRoot, purge.AgentDirectory);
    }

    [Fact]
    public void Windows_manual_activation_removal_preserves_other_manual_data()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.ActivationUninstall", Guid.NewGuid().ToString("N"));
        var otpPath = Path.Combine(root, "otp.dat");
        var historyPath = Path.Combine(root, "jobs.db");
        Directory.CreateDirectory(root);
        try
        {
            using (var stream = WindowsCurrentUserProtectedFile.CreateNew(otpPath))
            {
                stream.WriteByte(0x01);
            }
            File.WriteAllText(historyPath, "history");
            using var identity = WindowsIdentity.GetCurrent();
            var action = new RemoveOwnedManualActivation(
                otpPath,
                root,
                Assert.IsType<SecurityIdentifier>(identity.User).Value);
            var native = new WindowsUninstallNative();

            native.VerifyManualActivationOwnership(action);
            native.RemoveManualActivation(action);
            native.RemoveManualActivation(action);

            Assert.False(File.Exists(otpPath));
            Assert.Equal("history", File.ReadAllText(historyPath));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [WindowsAdministratorFact]
    public void Windows_manual_activation_removal_refuses_unsafe_targets_without_deleting_them()
    {
        foreach (var mismatch in new[] { "reparse", "hardlink", "owner-acl" })
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                "SimplySignAuto.ActivationUninstall",
                Guid.NewGuid().ToString("N"));
            var otpPath = Path.Combine(root, "otp.dat");
            var externalPath = Path.Combine(
                Path.GetTempPath(),
                $"ssa-activation-external-{Guid.NewGuid():N}.dat");
            Directory.CreateDirectory(root);
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var signingUser = Assert.IsType<SecurityIdentifier>(identity.User);
                if (mismatch == "reparse")
                {
                    File.WriteAllText(externalPath, "credential");
                    File.CreateSymbolicLink(otpPath, externalPath);
                }
                else
                {
                    using (var stream = WindowsCurrentUserProtectedFile.CreateNew(otpPath))
                    {
                        stream.Write("credential"u8);
                    }

                    if (mismatch == "hardlink")
                    {
                        Assert.True(CreateHardLinkW(externalPath, otpPath, nint.Zero));
                    }
                    else
                    {
                        WindowsInstallAcl.ApplyFile(
                            otpPath,
                            InstallAclProfile.SigningUserRead,
                            signingUser);
                    }
                }

                var action = new RemoveOwnedManualActivation(otpPath, root, signingUser.Value);
                var verify = Assert.Throws<InstallException>(
                    () => WindowsManualActivationCredential.VerifyExact(action));
                var remove = Assert.Throws<InstallException>(
                    () => WindowsManualActivationCredential.RemoveExact(action));

                Assert.Equal("owned_resource_mismatch", verify.Code);
                Assert.Equal("uninstall_state_uncertain", remove.Code);
                Assert.Equal("credential", File.ReadAllText(otpPath));
                if (mismatch == "hardlink")
                {
                    Assert.Equal("credential", File.ReadAllText(externalPath));
                }
            }
            finally
            {
                if (File.Exists(otpPath) || WindowsPathSafety.IsReparse(otpPath))
                {
                    File.Delete(otpPath);
                }

                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: false);
                }

                if (File.Exists(externalPath))
                {
                    File.Delete(externalPath);
                }
            }
        }
    }

    [Theory]
    [InlineData("S-1-5-21-1000-2000-3000-4000", FileAttributes.Directory, true)]
    [InlineData("S-1-5-32-544", FileAttributes.Directory, true)]
    [InlineData("S-1-5-18", FileAttributes.Directory, false)]
    [InlineData("S-1-5-21-1000-2000-3000-4999", FileAttributes.Directory, false)]
    [InlineData(
        "S-1-5-32-544",
        FileAttributes.Directory | FileAttributes.ReparsePoint,
        false)]
    public void Manual_user_data_accepts_only_the_signing_user_or_administrators_owner(
        string ownerSid,
        FileAttributes attributes,
        bool accepted)
    {
        const string signingUserSid = "S-1-5-21-1000-2000-3000-4000";
        var snapshot = new WindowsNoFollowSecuritySnapshot(
            attributes,
            new RawSecurityDescriptor(
                ControlFlags.None,
                new SecurityIdentifier(ownerSid),
                group: null,
                systemAcl: null,
                discretionaryAcl: null));

        var error = Record.Exception(() =>
            WindowsManualUninstallOwnership.VerifyUserDataSnapshot(snapshot, signingUserSid));

        if (accepted)
        {
            Assert.Null(error);
        }
        else
        {
            Assert.Equal("owned_resource_mismatch", Assert.IsType<InstallException>(error).Code);
        }
    }

    [Fact]
    public async Task Default_uninstall_preserves_an_existing_user_and_profile()
    {
        var configuration = Configuration();
        var identity = ManagedIdentity(configuration) with
        {
            Ownership = UninstallSigningUserOwnership.ExistingUser,
        };
        var planner = new UninstallPlanner(new RecordingUninstallEnvironment(configuration, identity));

        var plan = await planner.PlanAsync(
            new UninstallOptions(PurgeData: false, Confirmation: null),
            CancellationToken.None);

        Assert.Contains(plan.Actions, action => action is RemoveOwnedAutoLogon);
        Assert.Contains(plan.Actions, action => action is PurgeControlledData);
        Assert.DoesNotContain(plan.Actions, action => action is EndOwnedSigningUserSession);
        Assert.DoesNotContain(plan.Actions, action => action is RemoveOwnedAccountRights);
        Assert.DoesNotContain(plan.Actions, action => action is DeleteOwnedWindowsProfile);
        Assert.DoesNotContain(plan.Actions, action => action is DeleteOwnedLocalUser);
    }

    [Fact]
    public async Task Managed_uninstall_uses_the_fixed_destructive_order()
    {
        var events = new List<string>();
        var native = new RecordingWindowsUninstallNative(null, null, events);
        var purge = new RecordingPurgeIsolationFileSystem(events);
        var executor = new WindowsUninstallActionExecutor(
            native,
            purge,
            AllowOptionalToolUninstallPreflight.Instance,
            AllowInstalledMediaUninstallPreflight.Instance);

        await new UninstallOrchestrator(executor)
            .ExecuteAsync(Plan(includePurge: true), TextWriter.Null, CancellationToken.None);

        Assert.Equal(
            [
                "end-task", "delete-task", "stop-service", "delete-service", "remove-firewall",
                "remove-pdf-extension",
                "logoff-session", "remove-autologon", "remove-rights", "delete-user", "delete-profile",
                "purge-move", "remove-product-registration",
            ],
            events);
    }

    [Fact]
    public async Task Directory_only_profile_and_program_data_share_one_deferred_cleanup_plan()
    {
        var configuration = Configuration();
        var identity = ManagedIdentity(configuration);
        var native = new RecordingWindowsUninstallNative(
            null,
            null,
            profileRemovalState: ManagedProfileRemovalState.DirectoryOnly);
        var purge = new RecordingPurgeIsolationFileSystem();
        var executor = new WindowsUninstallActionExecutor(
            native,
            purge,
            AllowOptionalToolUninstallPreflight.Instance,
            AllowInstalledMediaUninstallPreflight.Instance);

        await new UninstallOrchestrator(executor)
            .ExecuteAsync(Plan(includePurge: true), TextWriter.Null, CancellationToken.None);

        Assert.Contains(
            $"plan:{configuration.DataRoot}|{identity.ProfilePath}",
            purge.Calls);
        Assert.Single(purge.Calls, call => call.StartsWith("schedule:", StringComparison.Ordinal));
    }

    [Fact]
    public void Deleted_managed_profile_uses_the_exact_disabled_autologon_receipt_for_retry()
    {
        var configuration = Configuration();
        var identity = ManagedIdentity(configuration);
        var disabled = new DisabledOwnedAutoLogon(
            identity.Sid,
            identity.AccountName,
            identity.ProfilePath,
            identity.OwnerMarker);

        var expected = WindowsUninstallEnvironment.ResolveExpectedAgentPath(
            configuration,
            profileListPath: null,
            disabled);

        Assert.Equal(configuration.AgentConfigurationPath, expected);
    }

    [Fact]
    public void Deleted_profile_retry_rejects_a_disabled_receipt_for_another_sid()
    {
        var configuration = Configuration();
        var identity = ManagedIdentity(configuration);
        var disabled = new DisabledOwnedAutoLogon(
            "S-1-5-21-1000-2000-3000-4999",
            identity.AccountName,
            identity.ProfilePath,
            identity.OwnerMarker);

        var failure = Assert.Throws<InstallException>(() =>
            WindowsUninstallEnvironment.ResolveExpectedAgentPath(
                configuration,
                profileListPath: null,
                disabled));

        Assert.Equal("uninstall_configuration_invalid", failure.Code);
    }

    [Fact]
    public void Managed_profile_retry_accepts_each_exact_half_deleted_state()
    {
        var identity = ManagedIdentity(Configuration());
        var disabled = new DisabledOwnedAutoLogon(
            identity.Sid,
            identity.AccountName,
            identity.ProfilePath,
            identity.OwnerMarker);
        var receipt = ExactProfileReceipt(identity);

        Assert.Equal(
            ManagedProfileRemovalState.RegistryOnly,
            ManagedProfileRemovalPolicy.Validate(
                identity,
                receipt,
                disabled,
                directoryExists: false,
                directoryIsReparse: false,
                pathUnderTrustedProfilesRoot: true));
        Assert.Equal(
            ManagedProfileRemovalState.DirectoryOnly,
            ManagedProfileRemovalPolicy.Validate(
                identity,
                receipt with
                {
                    ProfileExists = false,
                    HasOwnershipValues = false,
                    RegisteredPath = null,
                    OwnerMarker = null,
                    InstallInstanceId = null,
                    Sid = null,
                    AccountName = null,
                    RecordedPath = null,
                },
                disabled,
                directoryExists: true,
                directoryIsReparse: false,
                pathUnderTrustedProfilesRoot: true));
    }

    [Fact]
    public void Directory_only_profile_removal_is_deferred_into_the_final_combined_purge()
    {
        Assert.True(ManagedProfileRemovalPolicy.RequiresCombinedPurge(
            ManagedProfileRemovalState.DirectoryOnly));
        Assert.False(ManagedProfileRemovalPolicy.RequiresCombinedPurge(
            ManagedProfileRemovalState.RegisteredAndPresent));
        Assert.False(ManagedProfileRemovalPolicy.RequiresCombinedPurge(
            ManagedProfileRemovalState.RegistryOnly));
        Assert.False(ManagedProfileRemovalPolicy.RequiresCombinedPurge(
            ManagedProfileRemovalState.Complete));
    }

    [Fact]
    public void Managed_profile_retry_rejects_mismatched_receipts_and_unsafe_remaining_directories()
    {
        var identity = ManagedIdentity(Configuration());
        var disabled = new DisabledOwnedAutoLogon(
            identity.Sid,
            identity.AccountName,
            identity.ProfilePath,
            identity.OwnerMarker);
        var receipt = ExactProfileReceipt(identity);

        var wrongReceipt = Assert.Throws<InstallException>(() =>
            ManagedProfileRemovalPolicy.Validate(
                identity,
                receipt with { Sid = "S-1-5-21-1000-2000-3000-4999" },
                disabled,
                directoryExists: false,
                directoryIsReparse: false,
                pathUnderTrustedProfilesRoot: true));
        var reparse = Assert.Throws<InstallException>(() =>
            ManagedProfileRemovalPolicy.Validate(
                identity,
                receipt with
                {
                    ProfileExists = false,
                    HasOwnershipValues = false,
                    RegisteredPath = null,
                    OwnerMarker = null,
                    InstallInstanceId = null,
                    Sid = null,
                    AccountName = null,
                    RecordedPath = null,
                },
                disabled,
                directoryExists: true,
                directoryIsReparse: true,
                pathUnderTrustedProfilesRoot: true));

        Assert.Equal("owned_resource_mismatch", wrongReceipt.Code);
        Assert.Equal("owned_resource_mismatch", reparse.Code);
    }

    [Fact]
    public async Task Purge_planning_failure_occurs_before_any_uninstall_mutation()
    {
        var native = new RecordingWindowsUninstallNative(null, null);
        var purge = new RecordingPurgeIsolationFileSystem
        {
            FailPlanning = true,
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new UninstallOrchestrator(new WindowsUninstallActionExecutor(
                native,
                purge,
                AllowOptionalToolUninstallPreflight.Instance,
                AllowInstalledMediaUninstallPreflight.Instance))
                .ExecuteAsync(Plan(includePurge: true), TextWriter.Null, CancellationToken.None));

        Assert.Equal("uninstall_path_invalid", failure.Code);
        Assert.Empty(native.Mutations);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Optional_pdf_tool_preflight_accepts_only_absence_or_the_exact_ready_tree(
        bool ready)
    {
        var configuration = Configuration();
        var helperPath = OptionalHelperPath(configuration);
        var security = new RecordingOptionalToolUninstallSecurity(
            ready ? OptionalManifestJson() : null);
        var tree = new RecordingOptionalToolTreeInspector(
            ready ? ExactOptionalToolTree() : new OptionalToolUninstallTreeSnapshot([]));
        var preflight = new WindowsOptionalToolUninstallPreflight(
            security,
            tree);
        var identity = ManagedIdentity(configuration);

        await preflight.VerifyAsync(
            new InstalledProductIdentity(configuration.ExecutablePath, identity.Sid),
            CancellationToken.None);

        Assert.Equal(
            OptionalExtensionRoot(configuration),
            security.Paths?.Root);
        Assert.Equal(identity.Sid, security.ManifestSigningUserSid);
        Assert.Equal(ready ? 1 : 0, security.VerifyCalls);
        if (ready)
        {
            Assert.Equal(helperPath, security.HelperPath);
            Assert.Equal(identity.Sid, security.HelperSigningUserSid);
        }
        else
        {
            Assert.Null(security.HelperPath);
        }
    }

    [Fact]
    public void Controlled_data_preflight_consumes_the_same_read_only_tools_acl_that_setup_produces()
    {
        Assert.Equal(
            InstallAclProfile.SigningUserRead,
            WindowsUninstallNative.ExpectedOptionalToolsAclProfile);
    }

    [Theory]
    [InlineData("manifest")]
    [InlineData("unknown-child")]
    [InlineData("part")]
    [InlineData("reparse")]
    [InlineData("hardlink")]
    [InlineData("acl")]
    [InlineData("owner")]
    [InlineData("hash")]
    [InlineData("publisher")]
    public async Task Any_optional_pdf_tool_mismatch_stops_uninstall_before_every_mutation(
        string mismatch)
    {
        var configuration = Configuration();
        var security = new RecordingOptionalToolUninstallSecurity(
            mismatch == "manifest" ? "{}" : OptionalManifestJson())
        {
            VerifyFailure = mismatch is "hash" or "publisher"
                ? new IOException($"synthetic-{mismatch}")
                : null,
        };
        var entries = ExactOptionalToolTree().Entries.ToList();
        if (mismatch == "unknown-child")
        {
            entries.Add(new OptionalToolUninstallTreeEntry("unknown.bin", IsDirectory: false));
        }
        else if (mismatch == "part")
        {
            entries.Add(new OptionalToolUninstallTreeEntry(".0.1.0.part-deadbeef", IsDirectory: true));
        }

        var tree = new RecordingOptionalToolTreeInspector(
            new OptionalToolUninstallTreeSnapshot(entries))
        {
            Failure = mismatch is "reparse" or "hardlink" or "acl" or "owner"
                ? new InstallException("owned_resource_mismatch")
                : null,
        };
        var optional = new WindowsOptionalToolUninstallPreflight(
            security,
            tree);
        var native = new RecordingWindowsUninstallNative(null, null);
        var purge = new RecordingPurgeIsolationFileSystem();
        var executor = new WindowsUninstallActionExecutor(
            native,
            purge,
            optional,
            AllowInstalledMediaUninstallPreflight.Instance);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new UninstallOrchestrator(executor).ExecuteAsync(
                Plan(includePurge: true),
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("owned_resource_mismatch", failure.Code);
        Assert.Empty(native.Mutations);
        Assert.Empty(purge.Calls);
    }

    [WindowsAdministratorFact]
    public async Task Windows_optional_tool_tree_accepts_real_empty_and_exact_protected_layouts()
    {
        using var fixture = new WindowsOptionalToolTreeFixture();
        var emptySecurity = new RecordingOptionalToolUninstallSecurity(
            manifestJson: null);
        await new WindowsOptionalToolUninstallPreflight(
                emptySecurity,
                new WindowsOptionalToolUninstallTreeInspector())
            .VerifyAsync(
                new InstalledProductIdentity(
                    fixture.Configuration.ExecutablePath,
                    fixture.Identity.Sid),
                CancellationToken.None);

        fixture.CreateExactReadyTree();
        var readySecurity = new RecordingOptionalToolUninstallSecurity(
            OptionalManifestJson());
        await new WindowsOptionalToolUninstallPreflight(
                readySecurity,
                new WindowsOptionalToolUninstallTreeInspector())
            .VerifyAsync(
                new InstalledProductIdentity(
                    fixture.Configuration.ExecutablePath,
                    fixture.Identity.Sid),
                CancellationToken.None);

        Assert.Equal(1, readySecurity.VerifyCalls);
        Assert.Equal(fixture.HelperPath, readySecurity.HelperPath);
    }

    [WindowsAdministratorFact]
    public async Task Windows_optional_tool_tree_rejects_real_unknown_part_hardlink_and_dangerous_acl()
    {
        foreach (var mismatch in new[] { "unknown", "part", "hardlink", "acl" })
        {
            using var fixture = new WindowsOptionalToolTreeFixture();
            fixture.CreateExactReadyTree();
            fixture.IntroduceMismatch(mismatch);
            var security = new RecordingOptionalToolUninstallSecurity(
                OptionalManifestJson());
            var preflight = new WindowsOptionalToolUninstallPreflight(
                security,
                new WindowsOptionalToolUninstallTreeInspector());

            var failure = await Record.ExceptionAsync(() => preflight.VerifyAsync(
                new InstalledProductIdentity(
                    fixture.Configuration.ExecutablePath,
                    fixture.Identity.Sid),
                CancellationToken.None));

            var installFailure = Assert.IsAssignableFrom<InstallException>(failure);
            Assert.True(
                string.Equals(
                    installFailure.Code,
                    "owned_resource_mismatch",
                    StringComparison.Ordinal),
                $"Mismatch '{mismatch}' returned '{installFailure.Code}'.");
        }
    }

    [Fact]
    public void Uninstall_actions_never_target_simplysign_desktop_or_pkcs11()
    {
        var actionText = string.Join(
            Environment.NewLine,
            Plan(includePurge: true).Actions.Select(action => action.ToString()));

        Assert.DoesNotContain("SimplySignDesktop.exe", actionText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SimplySignPKCS.dll", actionText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Certum", actionText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Failed_deletion_readback_has_the_stable_uncertain_state_code()
    {
        var failure = Assert.Throws<InstallException>(() => UninstallStateReadback.Require(false));

        Assert.Equal("uninstall_state_uncertain", failure.Code);
    }

    [Fact]
    public async Task Purge_quarantines_each_volume_and_schedules_cleanup_without_touching_staged_content()
    {
        var fileSystem = new RecordingPurgeIsolationFileSystem();
        var action = new PurgeControlledData("controlled-data", "controlled-agent", true);

        await new PurgeIsolationCoordinator(fileSystem)
            .ExecuteAsync(action, PurgeIdentity(), CancellationToken.None);

        Assert.Equal(
            [
                "plan:controlled-data|controlled-agent",
                "create-operation:operation-root",
                "manifest:synthetic-operation",
                "create:volume-a-staging",
                "move:controlled-data->volume-a-staging/program-data",
                "create:volume-b-staging",
                "move:controlled-agent->volume-b-staging/agent-data",
                "schedule:synthetic-operation",
            ],
            fileSystem.Calls);
        Assert.True(fileSystem.ExternalSentinelExists);
        Assert.False(fileSystem.RecursiveTouchObserved);
    }

    [Fact]
    public void Purge_planning_groups_targets_by_volume_with_one_protected_staging_per_volume()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var groups = PurgeIsolationGrouping.Create(
            operationId,
            [
                new PurgeIsolationSource("program-data", "/volume-a/data", "/volume-a/"),
                new PurgeIsolationSource("agent-data", "/volume-b/agent", "/volume-b/"),
                new PurgeIsolationSource("other", "/volume-a/other", "/volume-a/"),
            ]);

        Assert.Equal(2, groups.Count);
        Assert.Equal(2, groups[0].Targets.Count);
        Assert.Single(groups[1].Targets);
        Assert.All(groups, group => Assert.All(
            group.Targets,
            target => Assert.StartsWith(group.StagingRoot, target.StagedPath, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Second_root_move_failure_rolls_back_the_first_without_deleting_any_tree()
    {
        var fileSystem = new RecordingPurgeIsolationFileSystem
        {
            FailingMoveSource = "controlled-agent",
        };
        var action = new PurgeControlledData("controlled-data", "controlled-agent", true);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new PurgeIsolationCoordinator(fileSystem)
                .ExecuteAsync(action, PurgeIdentity(), CancellationToken.None));

        Assert.Equal("uninstall_isolation_failed", failure.Code);
        Assert.Equal(
            [
                "plan:controlled-data|controlled-agent",
                "create-operation:operation-root",
                "manifest:synthetic-operation",
                "create:volume-a-staging",
                "move:controlled-data->volume-a-staging/program-data",
                "create:volume-b-staging",
                "move:controlled-agent->volume-b-staging/agent-data",
                "unschedule:synthetic-operation",
                "rollback:volume-a-staging/program-data->controlled-data",
                "remove:volume-b-staging",
                "remove:volume-a-staging",
                "remove-manifest:synthetic-operation",
                "remove-operation:operation-root",
            ],
            fileSystem.Calls);
        Assert.DoesNotContain(fileSystem.Calls, call => call.StartsWith("schedule:", StringComparison.Ordinal));
        Assert.False(fileSystem.RecursiveTouchObserved);
        Assert.True(fileSystem.ExternalSentinelExists);
    }

    [Fact]
    public async Task Incomplete_move_rollback_preserves_the_durable_manifest_and_operation_root()
    {
        var fileSystem = new RecordingPurgeIsolationFileSystem
        {
            FailingMoveSource = "controlled-agent",
            FailingRollbackSource = "controlled-data",
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new PurgeIsolationCoordinator(fileSystem).ExecuteAsync(
                new PurgeControlledData("controlled-data", "controlled-agent", true),
                PurgeIdentity(),
                CancellationToken.None));

        Assert.Equal("uninstall_state_uncertain", failure.Code);
        Assert.Contains("unschedule:synthetic-operation", fileSystem.Calls);
        Assert.Contains(
            "rollback:volume-a-staging/program-data->controlled-data",
            fileSystem.Calls);
        Assert.True(fileSystem.DurableManifestPresent);
        Assert.DoesNotContain("remove-manifest:synthetic-operation", fileSystem.Calls);
        Assert.DoesNotContain("remove-operation:operation-root", fileSystem.Calls);
    }

    [Fact]
    public async Task Cleanup_task_rollback_failure_with_complete_data_restore_removes_manifest_for_retry()
    {
        var fileSystem = new RecordingPurgeIsolationFileSystem
        {
            FailingMoveSource = "controlled-agent",
            FailCleanupTaskRollback = true,
        };

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var failure = await Assert.ThrowsAsync<InstallException>(() =>
                new PurgeIsolationCoordinator(fileSystem).ExecuteAsync(
                    new PurgeControlledData("controlled-data", "controlled-agent", true),
                    PurgeIdentity(),
                    CancellationToken.None));

            Assert.Equal("uninstall_state_uncertain", failure.Code);
            Assert.False(fileSystem.DurableManifestPresent);
        }

        Assert.Equal(
            2,
            fileSystem.Calls.Count(call => call == "manifest:synthetic-operation"));
        Assert.Equal(
            2,
            fileSystem.Calls.Count(call => call == "remove-manifest:synthetic-operation"));
        Assert.Equal(
            2,
            fileSystem.Calls.Count(call => call == "remove-operation:operation-root"));
        var rollbackIndexes = fileSystem.Calls
            .Select((call, index) => (call, index))
            .Where(item => item.call == "rollback:volume-a-staging/program-data->controlled-data")
            .Select(item => item.index)
            .ToArray();
        var manifestRemovalIndexes = fileSystem.Calls
            .Select((call, index) => (call, index))
            .Where(item => item.call == "remove-manifest:synthetic-operation")
            .Select(item => item.index)
            .ToArray();
        Assert.Equal(2, rollbackIndexes.Length);
        Assert.Equal(2, manifestRemovalIndexes.Length);
        Assert.True(rollbackIndexes[0] < manifestRemovalIndexes[0]);
        Assert.True(rollbackIndexes[1] < manifestRemovalIndexes[1]);
    }

    [Fact]
    public async Task Preexisting_operation_root_fails_before_any_move_or_cleanup_task()
    {
        var fileSystem = new RecordingPurgeIsolationFileSystem
        {
            FailOperationRootCreation = true,
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new PurgeIsolationCoordinator(fileSystem).ExecuteAsync(
                new PurgeControlledData("controlled-data", "controlled-agent", true),
                PurgeIdentity(),
                CancellationToken.None));

        Assert.Equal("uninstall_isolation_failed", failure.Code);
        Assert.Equal(
            ["plan:controlled-data|controlled-agent", "create-operation:operation-root"],
            fileSystem.Calls);
        Assert.DoesNotContain(fileSystem.Calls, call => call.StartsWith("move:", StringComparison.Ordinal));
        Assert.DoesNotContain(fileSystem.Calls, call => call.StartsWith("schedule:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Staging_root_created_by_a_plan_create_race_is_never_removed_or_acl_mutated()
    {
        var fileSystem = new RecordingPurgeIsolationFileSystem
        {
            FailingStagingCreation = "volume-a-staging",
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new PurgeIsolationCoordinator(fileSystem).ExecuteAsync(
                new PurgeControlledData("controlled-data", "controlled-agent", true),
                PurgeIdentity(),
                CancellationToken.None));

        Assert.Equal("uninstall_isolation_failed", failure.Code);
        Assert.Equal(
            [
                "plan:controlled-data|controlled-agent",
                "create-operation:operation-root",
                "manifest:synthetic-operation",
                "create:volume-a-staging",
                "unschedule:synthetic-operation",
                "remove-manifest:synthetic-operation",
                "remove-operation:operation-root",
            ],
            fileSystem.Calls);
        Assert.DoesNotContain("remove:volume-a-staging", fileSystem.Calls);
        Assert.DoesNotContain(fileSystem.Calls, call => call.StartsWith("move:", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Atomic_protected_root_never_mutates_a_preexisting_or_racing_entry(bool existsBeforeCreate)
    {
        var operations = new RecordingAtomicProtectedDirectoryOperations
        {
            ExistsBeforeCreate = existsBeforeCreate,
            RaceOnCreate = !existsBeforeCreate,
        };

        var failure = Assert.Throws<InstallException>(() =>
            new AtomicProtectedDirectoryCreator(operations).Create(
                "trusted-anchor",
                "trusted-anchor/unique-root"));

        Assert.Equal("uninstall_path_invalid", failure.Code);
        Assert.Equal(0, operations.AclMutationCalls);
        Assert.Equal(existsBeforeCreate ? 0 : 1, operations.CreateCalls);
        Assert.Equal(0, operations.VerifyCreatedCalls);
    }

    [Fact]
    public async Task Successful_purge_reports_quarantine_and_deferred_system_cleanup()
    {
        var native = new RecordingWindowsUninstallNative(null, null);
        var purge = new RecordingPurgeIsolationFileSystem();
        var executor = new WindowsUninstallActionExecutor(
            native,
            purge,
            AllowOptionalToolUninstallPreflight.Instance,
            AllowInstalledMediaUninstallPreflight.Instance);
        using var output = new StringWriter();

        await new UninstallOrchestrator(executor)
            .ExecuteAsync(Plan(includePurge: true), output, CancellationToken.None);

        Assert.Contains("isolated", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("after restart", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("permanently deleted", output.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Purge_manifest_round_trip_uses_value_equality_and_rejects_changed_quarantine_identity()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var exact = new PurgeQuarantineManifest(
            1,
            PurgeQuarantineManifestCodec.OwnerMarker,
            operationId,
            $"SimplySignAuto.Purge.{operationId}",
            $"SimplySignAuto/v1/{operationId}",
            "S-1-5-21-1000-2000-3000-4000",
            operationId,
            UninstallSigningUserOwnership.ProductManaged,
            Path.GetFullPath(Path.Combine(Path.DirectorySeparatorChar.ToString(), "opt", "SimplySignAuto.exe")),
            new string('a', 64),
            [Path.GetFullPath(Path.Combine(
                Path.DirectorySeparatorChar.ToString(),
                $".SimplySignAuto.quarantine.{operationId}.0"))],
            [new PurgeQuarantineTarget(
                Path.GetFullPath(Path.Combine(Path.DirectorySeparatorChar.ToString(), "opt", "data")),
                Path.GetFullPath(Path.Combine(
                    Path.DirectorySeparatorChar.ToString(),
                    $".SimplySignAuto.quarantine.{operationId}.0",
                    "program-data")))]);

        var json = System.Text.Encoding.UTF8.GetString(PurgeQuarantineManifestCodec.Serialize(exact));
        var roundTrip = PurgeQuarantineManifestCodec.Deserialize(json);

        Assert.True(PurgeQuarantineManifestCodec.MatchesExpected(roundTrip, exact));
        Assert.Contains("\"installOwnerMarker\"", json, StringComparison.Ordinal);
        Assert.Contains("\"signingUserSid\"", json, StringComparison.Ordinal);
        Assert.Contains("\"signingUserOwnership\"", json, StringComparison.Ordinal);
        Assert.Contains("\"installInstanceId\"", json, StringComparison.Ordinal);
        Assert.Contains("\"sourcePath\"", json, StringComparison.Ordinal);
        Assert.Contains("\"stagedPath\"", json, StringComparison.Ordinal);
        Assert.False(PurgeQuarantineManifestCodec.MatchesExpected(
            roundTrip with { StagingRoots = [roundTrip.StagingRoots[0] + "-external"] },
            exact));
        Assert.All(
            new[]
            {
                roundTrip with { InstallOwnerMarker = $"SimplySignAuto/v1/{new string('f', 32)}" },
                roundTrip with { SigningUserSid = "S-1-5-21-1000-2000-3000-4999" },
                roundTrip with { InstallInstanceId = new string('f', 32) },
                roundTrip with { SigningUserOwnership = UninstallSigningUserOwnership.ExistingUser },
                roundTrip with { ExecutablePath = roundTrip.ExecutablePath + ".other" },
                roundTrip with { ExecutableSha256 = new string('b', 64) },
                roundTrip with
                {
                    Targets =
                    [
                        roundTrip.Targets[0] with
                        {
                            SourcePath = roundTrip.Targets[0].SourcePath + ".other",
                        },
                    ],
                },
            },
            changed => Assert.False(PurgeQuarantineManifestCodec.MatchesExpected(changed, exact)));

        var unknownField = Assert.Throws<InstallException>(() =>
            PurgeQuarantineManifestCodec.Deserialize(json[..^1] + ",\"unexpected\":true}"));
        var missingOwnership = Assert.Throws<InstallException>(() =>
            PurgeQuarantineManifestCodec.Deserialize(
                json.Replace("\"signingUserOwnership\":1,", string.Empty, StringComparison.Ordinal)));
        var nonCanonicalPair = Assert.Throws<InstallException>(() =>
            PurgeQuarantineManifestCodec.Serialize(exact with
            {
                Targets =
                [
                    exact.Targets[0] with
                    {
                        SourcePath = Path.Combine(exact.Targets[0].SourcePath, "..", "data"),
                    },
                ],
            }));
        Assert.Equal("purge_manifest_invalid", unknownField.Code);
        Assert.Equal("purge_manifest_invalid", missingOwnership.Code);
        Assert.Equal("purge_manifest_invalid", nonCanonicalPair.Code);
    }

    [Fact]
    public void Purge_manifest_binds_cleanup_to_the_installed_main_program_without_staging_its_directory()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var volumeRoot = Path.GetPathRoot(Path.GetFullPath(Path.GetTempPath()))!;
        var stagingRoot = Path.Combine(
            volumeRoot,
            $".SimplySignAuto.quarantine.{operationId}.0");
        var sourceRoot = Path.Combine(volumeRoot, "controlled");
        var installedRoot = Path.Combine(sourceRoot, "SimplySignAuto");
        var installedExecutable = Path.Combine(installedRoot, "SimplySignAuto.exe");
        var plan = new PurgeIsolationPlan(
            operationId,
            PurgeQuarantineManifestCodec.ExpectedManifestPath(operationId),
            $"SimplySignAuto.Purge.{operationId}",
            installedExecutable,
            [new PurgeIsolationGroup(
                volumeRoot,
                stagingRoot,
                [
                    new PurgeIsolationTarget(
                        Path.Combine(sourceRoot, "program-data"),
                        Path.Combine(stagingRoot, "program-data")),
                    new PurgeIsolationTarget(
                        Path.Combine(sourceRoot, "agent-data"),
                        Path.Combine(stagingRoot, "agent-data")),
                ])],
            PurgeIdentity(installedExecutable),
            ExecutableSha256: new string('a', 64));

        var manifest = PurgeQuarantineManifestCodec.Create(plan);

        Assert.Equal(installedExecutable, manifest.ExecutablePath);
        Assert.Equal(new string('a', 64), manifest.ExecutableSha256);
        Assert.Collection(
            manifest.Targets,
            target => Assert.Equal("program-data", Path.GetFileName(target.StagedPath)),
            target => Assert.Equal("agent-data", Path.GetFileName(target.StagedPath)));
    }

    [Fact]
    public void Purge_sources_always_include_the_installed_program_directory()
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "purge-sources"));
        var dataRoot = Path.Combine(root, "program-data");
        var agentRoot = Path.Combine(root, "agent-data");
        var programRoot = Path.Combine(root, "program-files", "SimplySignAuto");
        var executable = Path.Combine(programRoot, "SimplySignAuto.exe");

        var sources = PurgeIsolationSourcePolicy.Create(dataRoot, agentRoot, executable);

        Assert.Collection(
            sources,
            source =>
            {
                Assert.Equal("program-data", source.Label);
                Assert.Equal(dataRoot, source.SourcePath);
            },
            source =>
            {
                Assert.Equal("agent-data", source.Label);
                Assert.Equal(agentRoot, source.SourcePath);
            },
            source =>
            {
                Assert.Equal("program-files", source.Label);
                Assert.Equal(programRoot, source.SourcePath);
            });
    }

    [WindowsAdministratorFact]
    public void Windows_purge_plan_keeps_the_running_program_directory_in_place_until_deferred_cleanup()
    {
        var dataRoot = Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.PurgePlan",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var executable = Path.GetFullPath(Environment.ProcessPath!);
            var programDirectory = Path.GetDirectoryName(executable)!;

            var plan = new WindowsPurgeIsolationFileSystem().Plan(
                dataRoot,
                agentDirectory: null,
                PurgeIdentity(executable));

            Assert.Equal(executable, plan.ExecutablePath);
            Assert.DoesNotContain(
                plan.Groups.SelectMany(group => group.Targets),
                target => string.Equals(
                    target.SourcePath,
                    programDirectory,
                    StringComparison.OrdinalIgnoreCase));
            Assert.Contains(
                plan.Groups.SelectMany(group => group.Targets),
                target => string.Equals(
                    target.SourcePath,
                    dataRoot,
                    StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(dataRoot);
        }
    }

    [Fact]
    public void Purge_manifest_rejects_a_manifest_location_inside_any_source_tree()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var manifestPath = PurgeQuarantineManifestCodec.ExpectedManifestPath(operationId);
        var operationRoot = Path.GetDirectoryName(manifestPath)!;
        var sourceRoot = Path.GetDirectoryName(operationRoot)!;
        var volumeRoot = Path.GetPathRoot(sourceRoot)!;
        var stagingRoot = Path.Combine(
            volumeRoot,
            $".SimplySignAuto.quarantine.{operationId}.0");
        var plan = new PurgeIsolationPlan(
            operationId,
            manifestPath,
            $"SimplySignAuto.Purge.{operationId}",
            Path.Combine(sourceRoot, "SimplySignAuto.exe"),
            [new PurgeIsolationGroup(
                volumeRoot,
                stagingRoot,
                [new PurgeIsolationTarget(sourceRoot, Path.Combine(stagingRoot, "program-data"))])],
            PurgeIdentity());

        var failure = Assert.Throws<InstallException>(() =>
            PurgeQuarantineManifestCodec.Create(plan));

        Assert.Equal("purge_manifest_invalid", failure.Code);
    }

    [Fact]
    public void Purge_manifest_uses_a_unique_operation_root_instead_of_a_fixed_shared_directory()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";

        var path = PurgeQuarantineManifestCodec.ExpectedManifestPath(operationId);

        Assert.Equal("manifest.json", Path.GetFileName(path));
        Assert.Equal(
            $"SimplySignAuto.Purge.{operationId}",
            Path.GetFileName(Path.GetDirectoryName(path)));
    }

    [Fact]
    public void Purge_cleanup_task_is_local_system_at_startup_and_hidden_command_is_exact()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var plan = new PurgeIsolationPlan(
            operationId,
            Path.GetFullPath(Path.Combine(Path.GetTempPath(), $"{operationId}.json")),
            $"SimplySignAuto.Purge.{operationId}",
            Path.GetFullPath(Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe")),
            []);
        var xml = WindowsPurgeCleanupTaskXml.Create(plan);

        Assert.True(WindowsPurgeCleanupTaskXml.IsOwned(xml, plan));
        Assert.DoesNotContain("<LogonType>", xml, StringComparison.Ordinal);
        Assert.Contains("S-1-5-18", xml, StringComparison.Ordinal);
        Assert.Contains("BootTrigger", xml, StringComparison.Ordinal);
        Assert.Contains("purge-quarantine --manifest", xml, StringComparison.Ordinal);
        var schedulerReadback = xml.Replace(
            "<Enabled>true</Enabled>",
            string.Empty,
            StringComparison.Ordinal);
        Assert.True(WindowsPurgeCleanupTaskXml.IsOwned(schedulerReadback, plan));
        Assert.False(WindowsPurgeCleanupTaskXml.IsOwned(
            schedulerReadback.Replace(
                "<BootTrigger>",
                "<BootTrigger><Enabled>false</Enabled>",
                StringComparison.Ordinal),
            plan));
        Assert.False(WindowsPurgeCleanupTaskXml.IsOwned(
            schedulerReadback.Replace(
                "<Settings>",
                "<Settings><Enabled>false</Enabled>",
                StringComparison.Ordinal),
            plan));
        Assert.False(WindowsPurgeCleanupTaskXml.IsOwned(
            xml.Replace("purge-quarantine", "uninstall", StringComparison.Ordinal),
            plan));
        Assert.False(WindowsPurgeCleanupTaskXml.IsOwned(
            xml.Replace(
                "</Actions>",
                "<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler></Actions>",
                StringComparison.Ordinal),
            plan));
        Assert.False(WindowsPurgeCleanupTaskXml.IsOwned(
            xml.Replace(
                "</Triggers>",
                "<TimeTrigger><StartBoundary>2026-08-14T00:00:00</StartBoundary></TimeTrigger></Triggers>",
                StringComparison.Ordinal),
            plan));
        Assert.False(WindowsPurgeCleanupTaskXml.IsOwned(
            xml.Replace(
                "</Principals>",
                "<Principal id=\"Other\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>",
                StringComparison.Ordinal),
            plan));
    }

    [Fact]
    public void Purge_cleanup_task_runs_the_installed_main_program_then_removes_its_empty_install_tree()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var volumeRoot = Path.GetPathRoot(Path.GetFullPath(Path.GetTempPath()))!;
        var stagingRoot = Path.Combine(
            volumeRoot,
            $".SimplySignAuto.quarantine.{operationId}.0");
        var installedRoot = Path.Combine(volumeRoot, "Program Files", "SimplySignAuto");
        var installedExecutable = Path.Combine(installedRoot, "SimplySignAuto.exe");
        var manifestPath = PurgeQuarantineManifestCodec.ExpectedManifestPath(operationId);
        var plan = new PurgeIsolationPlan(
            operationId,
            manifestPath,
            $"SimplySignAuto.Purge.{operationId}",
            installedExecutable,
            [new PurgeIsolationGroup(
                volumeRoot,
                stagingRoot,
                [new PurgeIsolationTarget(
                    Path.Combine(volumeRoot, "ProgramData", "SimplySignAuto"),
                    Path.Combine(stagingRoot, "program-data"))])]);

        var xml = WindowsPurgeCleanupTaskXml.Create(plan);
        var document = System.Xml.Linq.XDocument.Parse(xml);
        var ns = (System.Xml.Linq.XNamespace)"http://schemas.microsoft.com/windows/2004/02/mit/task";
        var command = document.Descendants(ns + "Command").Single().Value;
        var arguments = document.Descendants(ns + "Arguments").Single().Value;

        Assert.Equal(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            command);
        Assert.Contains(
            $"\"{installedExecutable}\" purge-quarantine --manifest \"{manifestPath}\"",
            arguments,
            StringComparison.Ordinal);
        Assert.Contains($"&& del /f /q \"{installedExecutable}\"", arguments, StringComparison.Ordinal);
        Assert.Contains($"&& rmdir \"{installedRoot}\"", arguments, StringComparison.Ordinal);
        Assert.DoesNotContain($"&& rmdir \"{stagingRoot}\"", arguments, StringComparison.Ordinal);
        Assert.True(WindowsPurgeCleanupTaskXml.IsOwned(xml, plan));
    }

    [Fact]
    public void Purge_cleanup_task_remains_identifiable_after_the_manifest_has_been_removed()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var volumeRoot = Path.GetPathRoot(Path.GetFullPath(Path.GetTempPath()))!;
        var stagingRoot = Path.Combine(
            volumeRoot,
            $".SimplySignAuto.quarantine.{operationId}.0");
        var installedRoot = Path.Combine(volumeRoot, "Program Files", "SimplySignAuto");
        var installedExecutable = Path.Combine(installedRoot, "SimplySignAuto.exe");
        var originalPlan = new PurgeIsolationPlan(
            operationId,
            PurgeQuarantineManifestCodec.ExpectedManifestPath(operationId),
            $"SimplySignAuto.Purge.{operationId}",
            installedExecutable,
            [new PurgeIsolationGroup(
                volumeRoot,
                stagingRoot,
                [new PurgeIsolationTarget(
                    Path.Combine(volumeRoot, "ProgramData", "SimplySignAuto"),
                    Path.Combine(stagingRoot, "program-data"))])]);
        var resumeWithoutManifest = originalPlan with { Groups = [] };

        var taskXml = WindowsPurgeCleanupTaskXml.Create(originalPlan);

        Assert.True(WindowsPurgeCleanupTaskXml.IsOwned(taskXml, resumeWithoutManifest));
        Assert.Equal(taskXml, WindowsPurgeCleanupTaskXml.Create(resumeWithoutManifest));
    }

    [WindowsAdministratorFact]
    public async Task Windows_accepts_and_round_trips_the_exact_purge_cleanup_task_xml()
    {
        var operationId = Guid.NewGuid().ToString("N");
        var taskName = $"SimplySignAuto.Purge.{operationId}";
        var xmlPath = Path.Combine(Path.GetTempPath(), $"{operationId}.task.xml");
        var plan = new PurgeIsolationPlan(
            operationId,
            Path.Combine(Path.GetTempPath(), $"{operationId}.manifest.json"),
            taskName,
            Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "cmd.exe")),
            []);
        var runner = new DefaultWindowsCommandRunner();
        await File.WriteAllTextAsync(xmlPath, WindowsPurgeCleanupTaskXml.Create(plan));
        try
        {
            await runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Create", "/TN", taskName, "/XML", xmlPath],
                "purge_cleanup_registration_failed",
                CancellationToken.None);
            var query = await runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Query", "/TN", taskName, "/XML"],
                "uninstall_state_uncertain",
                CancellationToken.None);

            Assert.True(WindowsPurgeCleanupTaskXml.IsOwned(query.StandardOutput, plan));
        }
        finally
        {
            if (WindowsPurgeCleanupTask.Exists(taskName))
            {
                await runner.RunCheckedAsync(
                    "schtasks.exe",
                    ["/Delete", "/TN", taskName, "/F"],
                    "uninstall_state_uncertain",
                    CancellationToken.None);
            }

            File.Delete(xmlPath);
        }
    }

    [WindowsAdministratorFact]
    public async Task Windows_schedules_and_rolls_back_the_exact_protected_purge_cleanup_state()
    {
        var operationId = Guid.NewGuid().ToString("N");
        var operationRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            $"SimplySignAuto.Purge.{operationId}");
        var executableDirectory = Path.Combine(Path.GetTempPath(), operationId);
        var executablePath = Path.Combine(executableDirectory, "SimplySignAuto.exe");
        Directory.CreateDirectory(executableDirectory);
        File.Copy(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            executablePath);
        var volumeRoot = Path.GetPathRoot(operationRoot)!;
        var plan = new PurgeIsolationPlan(
            operationId,
            Path.Combine(operationRoot, "manifest.json"),
            $"SimplySignAuto.Purge.{operationId}",
            executablePath,
            [new PurgeIsolationGroup(
                volumeRoot,
                Path.Combine(volumeRoot, $".SimplySignAuto.quarantine.{operationId}.0"),
                [new PurgeIsolationTarget(
                    executableDirectory,
                    Path.Combine(
                        volumeRoot,
                        $".SimplySignAuto.quarantine.{operationId}.0",
                        "program-data"))])],
            PurgeIdentity(executablePath, operationId));
        var cleanup = new WindowsPurgeDeferredCleanup();
        var runner = new DefaultWindowsCommandRunner();
        new AtomicProtectedDirectoryCreator(new WindowsAtomicProtectedDirectoryOperations())
            .Create(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                operationRoot);
        try
        {
            await cleanup.WriteManifestAsync(plan, CancellationToken.None);
            await cleanup.ScheduleAsync(plan, CancellationToken.None);

            Assert.True(File.Exists(plan.ManifestPath));
            Assert.True(WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName));

            await cleanup.RollbackTaskAsync(plan);
            cleanup.RemoveManifest(plan);
            new WindowsPurgeIsolationFileSystem().RemoveEmptyOperationRoot(operationRoot);

            Assert.False(File.Exists(plan.ManifestPath));
            Assert.False(Directory.Exists(operationRoot));
            Assert.False(WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName));
        }
        finally
        {
            if (WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName))
            {
                await runner.RunCheckedAsync(
                    "schtasks.exe",
                    ["/Delete", "/TN", plan.CleanupTaskName, "/F"],
                    "uninstall_state_uncertain",
                    CancellationToken.None);
            }

            if (File.Exists(plan.ManifestPath))
            {
                File.Delete(plan.ManifestPath);
            }

            if (Directory.Exists(operationRoot))
            {
                Directory.Delete(operationRoot, recursive: false);
            }

            Directory.Delete(executableDirectory, recursive: true);
        }
    }

    [Fact]
    public void Completed_autologon_finalization_is_recognized_only_when_every_product_secret_and_receipt_is_absent()
    {
        Assert.True(WindowsAutoLogonPlatform.IsFullyFinalizedEvidence(
            ownerMarker: null,
            uninstallState: null,
            uninstallSid: null,
            uninstallAccount: null,
            uninstallProfile: null,
            hasPriorState: false,
            defaultPasswordPresent: false,
            lsaReceiptPresent: false,
            lsaSecretPresent: false));

        Assert.False(WindowsAutoLogonPlatform.IsFullyFinalizedEvidence(
            ownerMarker: null,
            uninstallState: null,
            uninstallSid: null,
            uninstallAccount: null,
            uninstallProfile: null,
            hasPriorState: false,
            defaultPasswordPresent: false,
            lsaReceiptPresent: true,
            lsaSecretPresent: false));
        Assert.False(WindowsAutoLogonPlatform.IsFullyFinalizedEvidence(
            ownerMarker: "SimplySignAuto/v1/0123456789abcdef0123456789abcdef",
            uninstallState: null,
            uninstallSid: null,
            uninstallAccount: null,
            uninstallProfile: null,
            hasPriorState: false,
            defaultPasswordPresent: false,
            lsaReceiptPresent: false,
            lsaSecretPresent: false));
    }

    [Fact]
    public void Purge_autologon_finalization_accepts_only_manifest_exact_owner_sid_and_install()
    {
        const string installInstanceId = "0123456789abcdef0123456789abcdef";
        const string ownerMarker = "SimplySignAuto/v1/0123456789abcdef0123456789abcdef";
        const string signingUserSid = "S-1-5-21-1000-2000-3000-4000";
        var exact = new DisabledAutoLogonFinalizationEvidence(
            ownerMarker,
            "disabled",
            signingUserSid,
            "MACHINE\\SimplySignAgent",
            Path.GetFullPath(Path.Combine(Path.GetTempPath(), "SimplySignAgent")),
            HasPriorState: true,
            DefaultPasswordPresent: false,
            LsaReceiptPresent: true,
            LsaSecretPresent: true);

        Assert.True(WindowsAutoLogonPlatform.RequiresExactDisabledAutoLogonFinalization(
            ownerMarker,
            signingUserSid,
            installInstanceId,
            exact));
        var wrongOwner = Assert.Throws<InstallException>(() =>
            WindowsAutoLogonPlatform.RequiresExactDisabledAutoLogonFinalization(
                ownerMarker,
                signingUserSid,
                installInstanceId,
                exact with
                {
                    OwnerMarker = "SimplySignAuto/v1/fedcba9876543210fedcba9876543210",
                }));
        var wrongSid = Assert.Throws<InstallException>(() =>
            WindowsAutoLogonPlatform.RequiresExactDisabledAutoLogonFinalization(
                ownerMarker,
                signingUserSid,
                installInstanceId,
                exact with { SigningUserSid = "S-1-5-21-1000-2000-3000-4999" }));

        Assert.Equal("uninstall_state_uncertain", wrongOwner.Code);
        Assert.Equal("uninstall_state_uncertain", wrongSid.Code);
    }

    [Fact]
    public void Purge_autologon_finalization_is_reentrant_only_for_fully_absent_exact_state()
    {
        const string installInstanceId = "0123456789abcdef0123456789abcdef";
        const string ownerMarker = "SimplySignAuto/v1/0123456789abcdef0123456789abcdef";
        const string signingUserSid = "S-1-5-21-1000-2000-3000-4000";
        var finalized = new DisabledAutoLogonFinalizationEvidence(
            OwnerMarker: null,
            UninstallState: null,
            SigningUserSid: null,
            AccountName: null,
            ProfilePath: null,
            HasPriorState: false,
            DefaultPasswordPresent: false,
            LsaReceiptPresent: false,
            LsaSecretPresent: false);

        Assert.False(WindowsAutoLogonPlatform.RequiresExactDisabledAutoLogonFinalization(
            ownerMarker,
            signingUserSid,
            installInstanceId,
            finalized));
        var partial = Assert.Throws<InstallException>(() =>
            WindowsAutoLogonPlatform.RequiresExactDisabledAutoLogonFinalization(
                ownerMarker,
                signingUserSid,
                installInstanceId,
                finalized with { LsaReceiptPresent = true }));
        var mismatchedInstall = Assert.Throws<InstallException>(() =>
            WindowsAutoLogonPlatform.RequiresExactDisabledAutoLogonFinalization(
                ownerMarker,
                signingUserSid,
                "fedcba9876543210fedcba9876543210",
                finalized));

        Assert.Equal("uninstall_state_uncertain", partial.Code);
        Assert.Equal("uninstall_state_uncertain", mismatchedInstall.Code);
    }

    [Fact]
    public void Purge_cleaner_passes_the_service_manifest_exact_autologon_identity_to_the_finalizer()
    {
        var fixture = ResumeManifestFixture();
        var manifest = fixture.Manifest with
        {
            SigningUserOwnership = UninstallSigningUserOwnership.ProductManaged,
        };
        (string Owner, string Sid, string Install)? captured = null;

        WindowsPurgeQuarantineCleaner.FinalizeAutoLogon(
            manifest,
            (owner, sid, install) => captured = (owner, sid, install));

        Assert.Equal(manifest.InstallOwnerMarker, captured?.Owner);
        Assert.Equal(manifest.SigningUserSid, captured?.Sid);
        Assert.Equal(manifest.InstallInstanceId, captured?.Install);
    }

    [Fact]
    public void Purge_cleaner_skips_autologon_finalization_for_manual_install()
    {
        var fixture = ResumeManifestFixture();
        var calls = 0;

        WindowsPurgeQuarantineCleaner.FinalizeAutoLogon(
            fixture.Manifest,
            (_, _, _) => calls++);

        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task Interrupted_purge_after_first_move_resumes_only_the_pending_target()
    {
        var plan = ResumePlan();
        var runtime = new RecordingPurgeResumeRuntime(
            new Dictionary<string, PurgeResumeTargetPresence>(StringComparer.Ordinal)
            {
                [plan.Groups[0].Targets[0].SourcePath] = PurgeResumeTargetPresence.StagedOnly,
                [plan.Groups[1].Targets[0].SourcePath] = PurgeResumeTargetPresence.SourceOnly,
            });

        await new PurgeResumeCoordinator(runtime).ResumeAsync(plan, CancellationToken.None);

        Assert.Equal(
            [
                $"verify-staging:{plan.Groups[0].StagingRoot}",
                $"create-staging:{plan.Groups[1].StagingRoot}",
                $"move:{plan.Groups[1].Targets[0].SourcePath}->{plan.Groups[1].Targets[0].StagedPath}",
                $"schedule:{plan.OperationId}",
            ],
            runtime.Calls);
    }

    [Fact]
    public async Task Interrupted_purge_with_all_moves_complete_registers_the_missing_cleanup_task()
    {
        var plan = ResumePlan();
        var runtime = new RecordingPurgeResumeRuntime(
            plan.Groups
                .SelectMany(group => group.Targets)
                .ToDictionary(
                    target => target.SourcePath,
                    _ => PurgeResumeTargetPresence.StagedOnly,
                    StringComparer.Ordinal));

        await new PurgeResumeCoordinator(runtime).ResumeAsync(plan, CancellationToken.None);

        Assert.Equal(2, runtime.Calls.Count(call => call.StartsWith("verify-staging:", StringComparison.Ordinal)));
        Assert.Equal(1, runtime.Calls.Count(call => call == $"schedule:{plan.OperationId}"));
        Assert.DoesNotContain(runtime.Calls, call => call.StartsWith("move:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Interrupted_purge_with_an_existing_cleanup_task_verifies_instead_of_recreating_it()
    {
        var plan = ResumePlan();
        var runtime = new RecordingPurgeResumeRuntime(
            plan.Groups
                .SelectMany(group => group.Targets)
                .ToDictionary(
                    target => target.SourcePath,
                    _ => PurgeResumeTargetPresence.StagedOnly,
                    StringComparer.Ordinal),
            cleanupTaskExists: true);

        await new PurgeResumeCoordinator(runtime).ResumeAsync(plan, CancellationToken.None);

        Assert.Contains($"verify-task:{plan.OperationId}", runtime.Calls);
        Assert.DoesNotContain($"schedule:{plan.OperationId}", runtime.Calls);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Interrupted_purge_rejects_ambiguous_target_presence_without_cleanup_evidence(
        int presenceValue)
    {
        var presence = (PurgeResumeTargetPresence)presenceValue;
        var plan = ResumePlan();
        var runtime = new RecordingPurgeResumeRuntime(
            plan.Groups
                .SelectMany(group => group.Targets)
                .ToDictionary(target => target.SourcePath, _ => presence, StringComparer.Ordinal));

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new PurgeResumeCoordinator(runtime).ResumeAsync(plan, CancellationToken.None));

        Assert.Equal("uninstall_state_uncertain", failure.Code);
        Assert.DoesNotContain(runtime.Calls, call => call.StartsWith("move:", StringComparison.Ordinal));
        Assert.DoesNotContain(runtime.Calls, call => call.StartsWith("schedule:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Interrupted_purge_accepts_missing_source_and_staged_only_with_an_exact_cleanup_task()
    {
        var plan = ResumePlan();
        var runtime = new RecordingPurgeResumeRuntime(
            plan.Groups
                .SelectMany(group => group.Targets)
                .ToDictionary(
                    target => target.SourcePath,
                    _ => PurgeResumeTargetPresence.Neither,
                    StringComparer.Ordinal),
            cleanupTaskExists: true);

        await new PurgeResumeCoordinator(runtime).ResumeAsync(plan, CancellationToken.None);

        Assert.Equal([$"verify-task:{plan.OperationId}"], runtime.Calls);
    }

    [Fact]
    public void Interrupted_purge_discovery_accepts_only_one_exact_direct_non_reparse_operation_root()
    {
        var programData = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "resume-program-data"));
        var first = Path.Combine(programData, "SimplySignAuto.Purge.0123456789abcdef0123456789abcdef");
        var second = Path.Combine(programData, "SimplySignAuto.Purge.fedcba9876543210fedcba9876543210");
        var entries = new[]
        {
            new PurgeResumeCandidate(Path.Combine(programData, "SimplySignAuto.Purge.not-an-operation"), false),
            new PurgeResumeCandidate(Path.Combine(programData, "nested", Path.GetFileName(second)), false),
            new PurgeResumeCandidate(first, false),
        };

        Assert.Null(PurgeResumeDiscovery.SelectUnique(programData, entries[..2]));
        Assert.Equal(first, PurgeResumeDiscovery.SelectUnique(programData, entries));

        var multiple = Assert.Throws<InstallException>(() =>
            PurgeResumeDiscovery.SelectUnique(
                programData,
                [.. entries, new PurgeResumeCandidate(second, false)]));
        var reparse = Assert.Throws<InstallException>(() =>
            PurgeResumeDiscovery.SelectUnique(
                programData,
                [new PurgeResumeCandidate(first, true)]));
        Assert.Equal("uninstall_state_uncertain", multiple.Code);
        Assert.Equal("uninstall_state_uncertain", reparse.Code);
    }

    [Fact]
    public void Interrupted_purge_manifest_requires_exact_owner_sid_install_executable_hash_and_source_paths()
    {
        var fixture = ResumeManifestFixture();
        var changed = new PurgeQuarantineManifest[]
        {
            fixture.Manifest with
            {
                InstallOwnerMarker = "SimplySignAuto/v1/fedcba9876543210fedcba9876543210",
                InstallInstanceId = "fedcba9876543210fedcba9876543210",
            },
            fixture.Manifest with { SigningUserSid = "S-1-5-21-1000-2000-3000-4999" },
            fixture.Manifest with { InstallInstanceId = "fedcba9876543210fedcba9876543210" },
            fixture.Manifest with { SigningUserOwnership = UninstallSigningUserOwnership.ProductManaged },
            fixture.Manifest with
            {
                ExecutablePath = Path.Combine(Path.GetDirectoryName(fixture.ExecutablePath)!, "other", "SimplySignAuto.exe"),
            },
            fixture.Manifest with { ExecutableSha256 = new string('b', 64) },
            fixture.Manifest with
            {
                Targets =
                [
                    fixture.Manifest.Targets[0] with
                    {
                        SourcePath = Path.Combine(fixture.ProgramDataRoot, "ExternalProduct"),
                    },
                ],
            },
        };

        Assert.NotNull(PurgeResumeManifestValidator.Validate(
            fixture.OperationRoot,
            fixture.ProgramDataRoot,
            fixture.ExecutablePath,
            fixture.ExecutableSha256,
            fixture.DisabledAutoLogon,
            fixture.VerifiedOwnership,
            fixture.Manifest));
        Assert.All(changed, manifest =>
        {
            var failure = Assert.Throws<InstallException>(() =>
                PurgeResumeManifestValidator.Validate(
                    fixture.OperationRoot,
                    fixture.ProgramDataRoot,
                    fixture.ExecutablePath,
                    fixture.ExecutableSha256,
                    fixture.DisabledAutoLogon,
                    fixture.VerifiedOwnership,
                    manifest));
            Assert.Equal("uninstall_state_uncertain", failure.Code);
        });
    }

    [Fact]
    public void Existing_user_resume_rejects_an_exact_profile_root_target()
    {
        var fixture = ResumeManifestFixture();
        var profileTarget = new PurgeQuarantineTarget(
            fixture.DisabledAutoLogon.ProfilePath,
            Path.Combine(fixture.Manifest.StagingRoots[0], "agent-data"));
        var manifest = fixture.Manifest with
        {
            Targets = [.. fixture.Manifest.Targets, profileTarget],
        };

        var failure = Assert.Throws<InstallException>(() =>
            PurgeResumeManifestValidator.Validate(
                fixture.OperationRoot,
                fixture.ProgramDataRoot,
                fixture.ExecutablePath,
                fixture.ExecutableSha256,
                fixture.DisabledAutoLogon,
                UninstallSigningUserOwnership.ExistingUser,
                manifest));

        Assert.Equal("uninstall_state_uncertain", failure.Code);
    }

    [Fact]
    public void Product_managed_resume_accepts_its_exact_profile_root_target()
    {
        var fixture = ResumeManifestFixture();
        var profileTarget = new PurgeQuarantineTarget(
            fixture.DisabledAutoLogon.ProfilePath,
            Path.Combine(fixture.Manifest.StagingRoots[0], "agent-data"));
        var manifest = fixture.Manifest with
        {
            SigningUserOwnership = UninstallSigningUserOwnership.ProductManaged,
            Targets = [.. fixture.Manifest.Targets, profileTarget],
        };

        var plan = PurgeResumeManifestValidator.Validate(
            fixture.OperationRoot,
            fixture.ProgramDataRoot,
            fixture.ExecutablePath,
            fixture.ExecutableSha256,
            fixture.DisabledAutoLogon,
            UninstallSigningUserOwnership.ProductManaged,
            manifest);

        Assert.Contains(
            plan.Groups.SelectMany(group => group.Targets),
            target => string.Equals(
                target.SourcePath,
                fixture.DisabledAutoLogon.ProfilePath,
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal));
    }

    [Fact]
    public void Manual_resume_accepts_only_program_data_and_the_exact_manual_user_data_root()
    {
        var fixture = ResumeManifestFixture();
        var manualRoot = Path.Combine(
            fixture.DisabledAutoLogon.ProfilePath,
            "AppData",
            "Local",
            "SimplySignAuto",
            "manual");
        var manualTarget = new PurgeQuarantineTarget(
            manualRoot,
            Path.Combine(fixture.Manifest.StagingRoots[0], "agent-data"));
        var manifest = fixture.Manifest with
        {
            Targets = [.. fixture.Manifest.Targets, manualTarget],
        };

        var plan = PurgeResumeManifestValidator.ValidateManual(
            fixture.OperationRoot,
            fixture.ProgramDataRoot,
            fixture.ExecutablePath,
            fixture.ExecutableSha256,
            fixture.DisabledAutoLogon.ProfilePath,
            manifest);

        Assert.Contains(
            plan.Groups.SelectMany(group => group.Targets),
            target => string.Equals(target.SourcePath, manualRoot, StringComparison.Ordinal));
        var serviceRoot = Path.GetDirectoryName(manualRoot)!;
        var failure = Assert.Throws<InstallException>(() =>
            PurgeResumeManifestValidator.ValidateManual(
                fixture.OperationRoot,
                fixture.ProgramDataRoot,
                fixture.ExecutablePath,
                fixture.ExecutableSha256,
                fixture.DisabledAutoLogon.ProfilePath,
                manifest with
                {
                    Targets =
                    [
                        fixture.Manifest.Targets[0],
                        manualTarget with { SourcePath = serviceRoot },
                    ],
                }));
        Assert.Equal("uninstall_state_uncertain", failure.Code);
    }

    [Fact]
    public async Task Existing_user_resume_only_moves_recorded_product_data_and_never_requests_user_or_profile_deletion()
    {
        var plan = ResumePlan();
        var runtime = new RecordingPurgeResumeRuntime(
            plan.Groups
                .SelectMany(group => group.Targets)
                .ToDictionary(
                    target => target.SourcePath,
                    _ => PurgeResumeTargetPresence.SourceOnly,
                    StringComparer.Ordinal));

        await new PurgeResumeCoordinator(runtime).ResumeAsync(plan, CancellationToken.None);

        Assert.Equal(2, runtime.Calls.Count(call => call.StartsWith("move:", StringComparison.Ordinal)));
        Assert.All(runtime.Calls, call =>
        {
            Assert.DoesNotContain("delete-user", call, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("delete-profile", call, StringComparison.OrdinalIgnoreCase);
        });
    }

    [WindowsAdministratorFact]
    public async Task Windows_atomic_isolation_never_follows_a_root_replaced_with_a_directory_link()
    {
        var root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Uninstall.Purge", Guid.NewGuid().ToString("N"));
        var dataRoot = Path.Combine(root, "ProgramData", "SimplySignAuto");
        var agentRoot = Path.Combine(root, "Users", "signer", "SimplySignAuto");
        var externalRoot = Path.Combine(root, "external");
        Directory.CreateDirectory(dataRoot);
        Directory.CreateDirectory(agentRoot);
        Directory.CreateDirectory(externalRoot);
        var sentinel = Path.Combine(externalRoot, "sentinel.txt");
        File.WriteAllText(sentinel, "do-not-delete");
        var externalAcl = new DirectoryInfo(externalRoot)
            .GetAccessControl()
            .GetSecurityDescriptorBinaryForm();
        var fileSystem = new RootSwapPurgeIsolationFileSystem(
            new WindowsPurgeIsolationFileSystem(),
            agentRoot,
            externalRoot);
        try
        {
            await new PurgeIsolationCoordinator(fileSystem).ExecuteAsync(
                new PurgeControlledData(dataRoot, agentRoot, true),
                PurgeIdentity(Environment.ProcessPath!),
                CancellationToken.None);

            Assert.True(File.Exists(sentinel));
            Assert.Equal("do-not-delete", File.ReadAllText(sentinel));
            Assert.Equal(
                externalAcl,
                new DirectoryInfo(externalRoot).GetAccessControl().GetSecurityDescriptorBinaryForm());
        }
        finally
        {
            fileSystem.RollbackQuarantineForCleanup();
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class RecordingPurgeResumeRuntime(
        IReadOnlyDictionary<string, PurgeResumeTargetPresence> targetPresence,
        bool cleanupTaskExists = false) : IPurgeResumeRuntime
    {
        private readonly HashSet<string> _existingStagingRoots = targetPresence
            .Where(pair => pair.Value is PurgeResumeTargetPresence.StagedOnly or PurgeResumeTargetPresence.Both)
            .Select(pair => Path.GetDirectoryName(
                ResumePlan().Groups.SelectMany(group => group.Targets)
                    .Single(target => target.SourcePath == pair.Key).StagedPath)!)
            .ToHashSet(StringComparer.Ordinal);

        public List<string> Calls { get; } = [];

        public PurgeResumeTargetPresence Inspect(PurgeIsolationTarget target) =>
            targetPresence[target.SourcePath];

        public bool StagingRootExists(string path) => _existingStagingRoots.Contains(path);

        public void VerifyProtectedStaging(string path) => Calls.Add($"verify-staging:{path}");

        public void CreateProtectedStaging(string path)
        {
            Calls.Add($"create-staging:{path}");
            _existingStagingRoots.Add(path);
        }

        public void MoveToStaging(PurgeIsolationTarget target) =>
            Calls.Add($"move:{target.SourcePath}->{target.StagedPath}");

        public bool CleanupTaskExists(PurgeIsolationPlan plan) => cleanupTaskExists;

        public Task VerifyCleanupTaskAsync(
            PurgeIsolationPlan plan,
            CancellationToken cancellationToken)
        {
            Calls.Add($"verify-task:{plan.OperationId}");
            return Task.CompletedTask;
        }

        public Task ScheduleCleanupTaskAsync(
            PurgeIsolationPlan plan,
            CancellationToken cancellationToken)
        {
            Calls.Add($"schedule:{plan.OperationId}");
            return Task.CompletedTask;
        }
    }

    private static PurgeIsolationPlan ResumePlan()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "resume-plan"));
        var volumeA = Path.Combine(root, "volume-a");
        var volumeB = Path.Combine(root, "volume-b");
        var stagingA = Path.Combine(
            volumeA,
            $".SimplySignAuto.quarantine.{operationId}.0");
        var stagingB = Path.Combine(
            volumeB,
            $".SimplySignAuto.quarantine.{operationId}.1");
        return new PurgeIsolationPlan(
            operationId,
            Path.GetFullPath(Path.Combine(Path.GetTempPath(), "resume", operationId, "manifest.json")),
            $"SimplySignAuto.Purge.{operationId}",
            Path.GetFullPath(Path.Combine(Path.GetTempPath(), "resume", "SimplySignAuto.exe")),
            [
                new PurgeIsolationGroup(
                    volumeA,
                    stagingA,
                    [new PurgeIsolationTarget(
                        Path.Combine(volumeA, "SimplySignAuto"),
                        Path.Combine(stagingA, "program-data"))]),
                new PurgeIsolationGroup(
                    volumeB,
                    stagingB,
                    [new PurgeIsolationTarget(
                        Path.Combine(volumeB, "Users", "signer", "AppData", "Local", "SimplySignAuto"),
                        Path.Combine(stagingB, "agent-data"))]),
            ],
            PurgeIdentity(ownership: UninstallSigningUserOwnership.ExistingUser));
    }

    private static ResumeManifestTestFixture ResumeManifestFixture()
    {
        const string operationId = "0123456789abcdef0123456789abcdef";
        var programDataRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "resume-manifest-program-data"));
        var operationRoot = Path.Combine(programDataRoot, $"SimplySignAuto.Purge.{operationId}");
        var executablePath = Path.Combine(programDataRoot, "install", "SimplySignAuto.exe");
        var executableSha256 = new string('a', 64);
        var stagingRoot = Path.Combine(
            Path.GetPathRoot(programDataRoot)!,
            $".SimplySignAuto.quarantine.{operationId}.0");
        var manifest = new PurgeQuarantineManifest(
            1,
            PurgeQuarantineManifestCodec.OwnerMarker,
            operationId,
            $"SimplySignAuto.Purge.{operationId}",
            $"SimplySignAuto/v1/{operationId}",
            "S-1-5-21-1000-2000-3000-4000",
            operationId,
            UninstallSigningUserOwnership.ExistingUser,
            executablePath,
            executableSha256,
            [stagingRoot],
            [new PurgeQuarantineTarget(
                Path.Combine(programDataRoot, "SimplySignAuto"),
                Path.Combine(stagingRoot, "program-data"))]);
        return new ResumeManifestTestFixture(
            programDataRoot,
            operationRoot,
            executablePath,
            executableSha256,
            new DisabledOwnedAutoLogon(
                manifest.SigningUserSid,
                "MACHINE\\existing-signer",
                Path.Combine(programDataRoot, "Users", "existing-signer"),
                manifest.InstallOwnerMarker),
            UninstallSigningUserOwnership.ExistingUser,
            manifest);
    }

    private sealed record ResumeManifestTestFixture(
        string ProgramDataRoot,
        string OperationRoot,
        string ExecutablePath,
        string ExecutableSha256,
        DisabledOwnedAutoLogon DisabledAutoLogon,
        UninstallSigningUserOwnership VerifiedOwnership,
        PurgeQuarantineManifest Manifest);

    private sealed class RecordingPurgeIsolationFileSystem(List<string>? mutationEvents = null)
        : IPurgeIsolationFileSystem
    {
        public List<string> Calls { get; } = [];

        public string? FailingMoveSource { get; init; }

        public string? FailingRollbackSource { get; init; }

        public bool FailOperationRootCreation { get; init; }

        public bool FailCleanupTaskRollback { get; init; }

        public string? FailingStagingCreation { get; init; }

        public bool FailPlanning { get; init; }

        public bool ExternalSentinelExists { get; private set; } = true;

        public bool RecursiveTouchObserved { get; private set; }

        public bool DurableManifestPresent { get; private set; }

        public PurgeIsolationPlan Plan(
            string dataRoot,
            string? agentDirectory,
            PurgeInstallIdentity installIdentity)
        {
            Calls.Add($"plan:{dataRoot}|{agentDirectory}");
            if (DurableManifestPresent)
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            if (FailPlanning)
            {
                throw new InstallException("uninstall_path_invalid");
            }

            var groups = new List<PurgeIsolationGroup>
            {
                new(
                    "volume-a",
                    "volume-a-staging",
                    [new PurgeIsolationTarget(dataRoot, "volume-a-staging/program-data")]),
            };
            if (agentDirectory is not null)
            {
                groups.Add(new PurgeIsolationGroup(
                    "volume-b",
                    "volume-b-staging",
                    [new PurgeIsolationTarget(agentDirectory, "volume-b-staging/agent-data")]));
            }

            return new PurgeIsolationPlan(
                "synthetic-operation",
                Path.Combine("operation-root", "manifest.json"),
                "synthetic-task",
                "synthetic-executable",
                groups,
                installIdentity);
        }

        public void CreateProtectedOperationRoot(string path)
        {
            Calls.Add($"create-operation:{path}");
            if (FailOperationRootCreation)
            {
                throw new InstallException("uninstall_path_invalid");
            }
        }

        public Task WriteDurableManifestAsync(
            PurgeIsolationPlan plan,
            CancellationToken cancellationToken)
        {
            Calls.Add($"manifest:{plan.OperationId}");
            DurableManifestPresent = true;
            return Task.CompletedTask;
        }

        public void CreateProtectedStaging(string path)
        {
            Calls.Add($"create:{path}");
            if (path == FailingStagingCreation)
            {
                throw new InstallException("uninstall_path_invalid");
            }
        }

        public void MoveToStaging(PurgeIsolationTarget target)
        {
            Calls.Add($"move:{target.SourcePath}->{target.StagedPath}");
            mutationEvents?.Add("purge-move");
            if (target.SourcePath == FailingMoveSource)
            {
                throw new IOException("synthetic move failure");
            }
        }

        public void RollbackMove(PurgeIsolationTarget target)
        {
            Calls.Add($"rollback:{target.StagedPath}->{target.SourcePath}");
            if (target.SourcePath == FailingRollbackSource)
            {
                throw new IOException("synthetic rollback failure");
            }
        }

        public Task ScheduleDeferredCleanupAsync(
            PurgeIsolationPlan plan,
            CancellationToken cancellationToken)
        {
            Calls.Add($"schedule:{plan.OperationId}");
            return Task.CompletedTask;
        }

        public Task RollbackDeferredCleanupAsync(PurgeIsolationPlan plan)
        {
            Calls.Add($"unschedule:{plan.OperationId}");
            if (FailCleanupTaskRollback)
            {
                throw new IOException("synthetic cleanup task rollback failure");
            }

            return Task.CompletedTask;
        }

        public void RemoveDurableManifest(PurgeIsolationPlan plan)
        {
            Calls.Add($"remove-manifest:{plan.OperationId}");
            DurableManifestPresent = false;
        }

        public void RemoveEmptyStaging(string path) => Calls.Add($"remove:{path}");

        public void RemoveEmptyOperationRoot(string path) => Calls.Add($"remove-operation:{path}");
    }

    private sealed class RecordingAtomicProtectedDirectoryOperations : IAtomicProtectedDirectoryOperations
    {
        public bool ExistsBeforeCreate { get; init; }

        public bool RaceOnCreate { get; init; }

        public int CreateCalls { get; private set; }

        public int VerifyCreatedCalls { get; private set; }

        public int AclMutationCalls { get; private set; }

        public void VerifyTrustedAnchor(string path) { }

        public bool EntryExistsNoFollow(string path) => ExistsBeforeCreate;

        public void CreateNewWithSecurity(string path)
        {
            CreateCalls++;
            if (RaceOnCreate)
            {
                throw new IOException("already exists");
            }
        }

        public void VerifyCreated(string path) => VerifyCreatedCalls++;
    }

    private sealed class RecordingWindowsUninstallNative(
        string? failingResource,
        string? failureCode,
        List<string>? mutationEvents = null,
        ManagedProfileRemovalState profileRemovalState = ManagedProfileRemovalState.RegisteredAndPresent)
        : IWindowsUninstallNative
    {
        public List<string> Mutations { get; } = [];

        public void VerifySigningIdentityOwnership(
            UninstallSigningIdentity identity,
            SimplySignAuto.Service.ServiceConfiguration configuration) => FailIf("identity");

        public void VerifyFirewallOwnership(RemoveOwnedFirewallRule action) => FailIf("firewall");

        public Task VerifyTaskOwnershipAsync(
            RemoveOwnedInteractiveLogonTask action,
            CancellationToken cancellationToken)
        {
            FailIf("task");
            return Task.CompletedTask;
        }

        public void VerifyServiceOwnership(RemoveOwnedWindowsService action) => FailIf("service");

        public void VerifyAutoLogonOwnership(RemoveOwnedAutoLogon action) => FailIf("autologon");

        public void VerifySigningSessionOwnership(EndOwnedSigningUserSession action) => FailIf("session");

        public void VerifyAccountRightsOwnership(RemoveOwnedAccountRights action) => FailIf("rights");

        public void VerifyControlledDataOwnership(
            PurgeControlledData action,
            UninstallSigningIdentity identity) => FailIf("data");

        public ManagedProfileRemovalState VerifyProfileOwnership(DeleteOwnedWindowsProfile action)
        {
            FailIf("profile");
            return profileRemovalState;
        }

        public void VerifyLocalUserOwnership(DeleteOwnedLocalUser action) => FailIf("user");

        public void VerifyProductRegistrationOwnership(RemoveOwnedProductUninstall action) =>
            FailIf("product-registration");

        public void VerifyDesktopShortcutOwnership(RemoveOwnedDesktopShortcut action) =>
            FailIf("desktop-shortcut");

        public void VerifyManualActivationOwnership(RemoveOwnedManualActivation action) =>
            FailIf("manual-activation");

        public void RemoveFirewall(RemoveOwnedFirewallRule action) => Record("remove-firewall");

        public Task EndAndRemoveTaskAsync(
            RemoveOwnedInteractiveLogonTask action,
            CancellationToken cancellationToken)
        {
            Record("end-task");
            Record("delete-task");
            return Task.CompletedTask;
        }

        public Task StopAndRemoveServiceAsync(
            RemoveOwnedWindowsService action,
            CancellationToken cancellationToken)
        {
            Record("stop-service");
            Record("delete-service");
            return Task.CompletedTask;
        }

        public void RemoveAutoLogon(RemoveOwnedAutoLogon action) => Record("remove-autologon");

        public void RemoveAccountRights(RemoveOwnedAccountRights action) => Record("remove-rights");

        public Task EndSigningUserSessionsAsync(
            EndOwnedSigningUserSession action,
            CancellationToken cancellationToken)
        {
            Record("logoff-session");
            return Task.CompletedTask;
        }

        public Task DeleteProfileAsync(
            DeleteOwnedWindowsProfile action,
            CancellationToken cancellationToken)
        {
            Record("delete-profile");
            return Task.CompletedTask;
        }

        public void DeleteLocalUser(DeleteOwnedLocalUser action) => Record("delete-user");

        public void RemoveProductRegistration(RemoveOwnedProductUninstall action) =>
            Record("remove-product-registration");

        public void RemoveDesktopShortcut(RemoveOwnedDesktopShortcut action) =>
            Record("remove-desktop-shortcut");

        public void RemoveManualActivation(RemoveOwnedManualActivation action) =>
            Record("remove-manual-activation");

        public Task RemovePdfExtensionAsync(CancellationToken cancellationToken)
        {
            Record("remove-pdf-extension");
            return Task.CompletedTask;
        }

        private void Record(string mutation)
        {
            Mutations.Add(mutation);
            mutationEvents?.Add(mutation);
        }

        private void FailIf(string resource)
        {
            if (resource == failingResource)
            {
                throw new InstallException(failureCode!);
            }
        }
    }

    private sealed class RecordingOptionalToolUninstallSecurity(string? manifestJson)
        : IInstalledPdfToolSecurity
    {
        public PdfExtensionPaths? Paths { get; private set; }

        public string? HelperPath { get; private set; }

        public string? ManifestSigningUserSid { get; private set; }

        public string? HelperSigningUserSid { get; private set; }

        public int VerifyCalls { get; private set; }

        public Exception? VerifyFailure { get; init; }

        public Task<string?> ReadManifestAsync(
            PdfExtensionPaths paths,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Paths = paths;
            return Task.FromResult(manifestJson);
        }

        public Task VerifyHelperAsync(
            string path,
            PdfExtensionManifest manifest,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            VerifyCalls++;
            HelperPath = path;
            return VerifyFailure is null
                ? Task.CompletedTask
                : Task.FromException(VerifyFailure);
        }

        public Task<string?> ReadManifestAsync(
            PdfExtensionPaths paths,
            string signingUserSid,
            CancellationToken cancellationToken)
        {
            ManifestSigningUserSid = signingUserSid;
            return ReadManifestAsync(paths, cancellationToken);
        }

        public Task VerifyHelperAsync(
            string path,
            PdfExtensionManifest manifest,
            string signingUserSid,
            CancellationToken cancellationToken)
        {
            HelperSigningUserSid = signingUserSid;
            return VerifyHelperAsync(path, manifest, cancellationToken);
        }
    }

    private sealed class RecordingOptionalToolTreeInspector(
        OptionalToolUninstallTreeSnapshot snapshot) : IOptionalToolUninstallTreeInspector
    {
        public Exception? Failure { get; init; }

        public OptionalToolUninstallTreeSnapshot Inspect(
            string toolsRoot,
            string signingUserSid)
        {
            if (Failure is not null)
            {
                throw Failure;
            }

            return snapshot;
        }
    }

    private sealed class AllowOptionalToolUninstallPreflight : IOptionalToolUninstallPreflight
    {
        public static AllowOptionalToolUninstallPreflight Instance { get; } = new();

        public Task VerifyAsync(
            InstalledProductIdentity identity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingInstalledMediaUninstallPreflight : IInstalledMediaUninstallPreflight
    {
        public int Calls { get; private set; }

        public Exception? Failure { get; init; }

        public Task VerifyAsync(UninstallPlan plan, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Failure is null ? Task.CompletedTask : Task.FromException(Failure);
        }
    }

    private sealed class AllowInstalledMediaUninstallPreflight : IInstalledMediaUninstallPreflight
    {
        public static AllowInstalledMediaUninstallPreflight Instance { get; } = new();

        public Task VerifyAsync(UninstallPlan plan, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    private sealed class WindowsOptionalToolTreeFixture : IDisposable
    {
        private readonly SecurityIdentifier _signingUser = new(
            WellKnownSidType.BuiltinUsersSid,
            domainSid: null);
        private readonly string _externalHardlink;

        public WindowsOptionalToolTreeFixture()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "SimplySignAuto.OptionalUninstall",
                Guid.NewGuid().ToString("N"));
            var dataRoot = Path.Combine(Root, "ProgramData", "SimplySignAuto");
            var productRoot = Path.Combine(Root, "Program Files", "SimplySignAuto");
            ToolsRoot = Path.Combine(Root, "Program Files", "SimplySignAuto PDF Support");
            HelperPath = Path.Combine(ToolsRoot, "SimplySignPdfSigner.exe");
            _externalHardlink = Path.Combine(Root, "helper-hardlink.exe");
            Directory.CreateDirectory(ToolsRoot);
            WindowsInstallAcl.ApplyDirectory(
                ToolsRoot,
                InstallAclProfile.SigningUserRead,
                _signingUser);
            Configuration = Configuration() with
            {
                SigningUserSid = _signingUser.Value,
                DataRoot = dataRoot,
                SpoolRoot = Path.Combine(dataRoot, "spool"),
                ExecutablePath = Path.Combine(productRoot, "SimplySignAuto.exe"),
            };
            Identity = ManagedIdentity(Configuration) with { Sid = _signingUser.Value };
        }

        public string Root { get; }

        public string ToolsRoot { get; }

        public string HelperPath { get; }

        public SimplySignAuto.Service.ServiceConfiguration Configuration { get; }

        public UninstallSigningIdentity Identity { get; }

        public void CreateExactReadyTree()
        {
            File.WriteAllText(HelperPath, "signed-helper-fixture");
            WindowsInstallAcl.ApplyFile(
                HelperPath,
                InstallAclProfile.SigningUserRead,
                _signingUser);
            var manifestPath = Path.Combine(ToolsRoot, "extension.json");
            File.WriteAllText(manifestPath, OptionalManifestJson());
            WindowsInstallAcl.ApplyFile(
                manifestPath,
                InstallAclProfile.SigningUserRead,
                _signingUser);
            foreach (var name in new[] { "LICENSE.txt", "THIRD-PARTY-NOTICES.txt" })
            {
                var path = Path.Combine(ToolsRoot, name);
                File.WriteAllText(path, name);
                WindowsInstallAcl.ApplyFile(
                    path,
                    InstallAclProfile.SigningUserRead,
                    _signingUser);
            }
        }

        public void IntroduceMismatch(string mismatch)
        {
            switch (mismatch)
            {
                case "unknown":
                    var unknown = Path.Combine(ToolsRoot, "unknown.bin");
                    File.WriteAllText(unknown, "unknown");
                    WindowsInstallAcl.ApplyFile(
                        unknown,
                        InstallAclProfile.SigningUserRead,
                        _signingUser);
                    break;
                case "part":
                    var part = Path.Combine(ToolsRoot, ".0.1.0.part-deadbeef");
                    Directory.CreateDirectory(part);
                    WindowsInstallAcl.ApplyDirectory(
                        part,
                        InstallAclProfile.SigningUserRead,
                        _signingUser);
                    break;
                case "hardlink":
                    if (!CreateHardLinkW(_externalHardlink, HelperPath, nint.Zero))
                    {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    }

                    break;
                case "acl":
                    WindowsInstallAcl.ApplyFile(
                        HelperPath,
                        InstallAclProfile.SigningUserModify,
                        _signingUser);
                    break;
                default:
                    throw new InvalidOperationException("unknown_optional_tool_mismatch");
            }
        }

        public void Dispose()
        {
            if (File.Exists(_externalHardlink))
            {
                File.Delete(_externalHardlink);
            }

            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        nint securityAttributes);

    private sealed class ReplacingFirewallPolicy : IWindowsFirewallPolicy
    {
        public WindowsFirewallRuleSnapshot? Current { get; private set; }

        public int AddCalls { get; private set; }

        public int RemoveCalls { get; private set; }

        public WindowsFirewallRuleSnapshot? FindUnique(string name) => Current;

        public void Add(WindowsFirewallRuleSnapshot rule)
        {
            AddCalls++;
            Current = rule with { Description = "external-owner", Grouping = "external-owner" };
        }

        public void RemoveExact(WindowsFirewallRuleSnapshot expected)
        {
            RemoveCalls++;
            Current = null;
        }
    }

    private sealed class ExactThenFailFirewallPolicy : IWindowsFirewallPolicy
    {
        public WindowsFirewallRuleSnapshot? Current { get; private set; }

        public int RemoveCalls { get; private set; }

        public bool MissingVerified { get; private set; }

        public WindowsFirewallRuleSnapshot? FindUnique(string name)
        {
            if (Current is null && RemoveCalls > 0)
            {
                MissingVerified = true;
            }

            return Current;
        }

        public void Add(WindowsFirewallRuleSnapshot rule)
        {
            Current = rule;
            throw new InstallException("synthetic_add_failure");
        }

        public void RemoveExact(WindowsFirewallRuleSnapshot expected)
        {
            Assert.True(WindowsFirewallRuleContract.IsExact(Current!, expected));
            RemoveCalls++;
            Current = null;
        }
    }

    private static UninstallPlan Plan(bool includePurge)
    {
        var configuration = Configuration();
        var identity = ManagedIdentity(configuration);
        var actions = new List<UninstallAction>
        {
            new RemoveOwnedInteractiveLogonTask(
                "SimplySignAuto.Agent",
                configuration.SigningUserSid,
                configuration.ExecutablePath,
                "SimplySignAuto/v1/0123456789abcdef0123456789abcdef"),
            new RemoveOwnedWindowsService(
                "SimplySignAuto.Service",
                configuration.ExecutablePath,
                "SimplySignAuto/v1/0123456789abcdef0123456789abcdef"),
            new RemoveOwnedFirewallRule(
                "SimplySignAuto/v1/0123456789abcdef0123456789abcdef",
                7080),
            new RemoveOwnedPdfExtension(),
        };
        if (includePurge)
        {
            actions.Add(new EndOwnedSigningUserSession(identity));
            actions.Add(new RemoveOwnedAutoLogon(
                configuration.SigningUserSid,
                "SimplySignAuto/v1/0123456789abcdef0123456789abcdef",
                identity.AccountName,
                identity.ProfilePath));
            actions.Add(new RemoveOwnedAccountRights(identity));
            actions.Add(new DeleteOwnedLocalUser(identity));
            actions.Add(new DeleteOwnedWindowsProfile(identity));
            actions.Add(new PurgeControlledData(
                configuration.DataRoot,
                Path.GetDirectoryName(configuration.AgentConfigurationPath)!,
                false));
        }

        actions.Add(new RemoveOwnedProductUninstall(
            ProductUninstallRegistration.Create(
                configuration.ExecutablePath,
                ApplicationVersion.ReadIdentity(typeof(UninstallCommand).Assembly),
                InstallOwnershipMarker.Create(configuration.InstallInstanceId))));

        return new UninstallPlan(configuration, identity, actions);
    }

    private const string OptionalProductVersion = "0.14.0";
    private const string OptionalHelperVersion = "0.1.0";

    private static string OptionalExtensionRoot(
        SimplySignAuto.Service.ServiceConfiguration configuration)
    {
        var productRoot = Path.GetDirectoryName(configuration.ExecutablePath)!;
        var programFilesRoot = Directory.GetParent(productRoot)!.FullName;
        return Path.Combine(programFilesRoot, "SimplySignAuto PDF Support");
    }

    private static string OptionalHelperPath(SimplySignAuto.Service.ServiceConfiguration configuration) =>
        Path.Combine(
            OptionalExtensionRoot(configuration),
            "SimplySignPdfSigner.exe");

    private static OptionalToolUninstallTreeSnapshot ExactOptionalToolTree() => new(
        [
            new OptionalToolUninstallTreeEntry("extension.json", IsDirectory: false),
            new OptionalToolUninstallTreeEntry("LICENSE.txt", IsDirectory: false),
            new OptionalToolUninstallTreeEntry("SimplySignPdfSigner.exe", IsDirectory: false),
            new OptionalToolUninstallTreeEntry("THIRD-PARTY-NOTICES.txt", IsDirectory: false),
        ]);

    private static string OptionalManifestJson() => JsonSerializer.Serialize(new
    {
        schemaVersion = 1,
        productVersion = OptionalProductVersion,
        helperVersion = OptionalHelperVersion,
        helperLength = 20_597_280,
        helperSha256 = new string('a', 64),
        publisherCertificateSha256 = new string('c', 64),
    });

    private static PurgeInstallIdentity PurgeIdentity(
        string? executablePath = null,
        string installInstanceId = "0123456789abcdef0123456789abcdef",
        UninstallSigningUserOwnership ownership = UninstallSigningUserOwnership.ProductManaged) =>
        new(
            $"SimplySignAuto/v1/{installInstanceId}",
            "S-1-5-21-1000-2000-3000-4000",
            installInstanceId,
            ownership,
            executablePath ?? Path.GetFullPath(Path.Combine(
                Path.DirectorySeparatorChar.ToString(),
                "opt",
                "SimplySignAuto.exe")));

    private static UninstallSigningIdentity ManagedIdentity(
        SimplySignAuto.Service.ServiceConfiguration configuration)
    {
        var agentDirectory = Path.GetDirectoryName(configuration.AgentConfigurationPath)!;
        var profilePath = Directory.GetParent(Directory.GetParent(Directory.GetParent(agentDirectory)!.FullName)!.FullName)!.FullName;
        return new UninstallSigningIdentity(
            "MACHINE\\SimplySignAgent",
            "SimplySignAgent",
            configuration.SigningUserSid,
            profilePath,
            "SimplySignAuto/v1/0123456789abcdef0123456789abcdef",
            UninstallSigningUserOwnership.ProductManaged);
    }

    private static OwnedUserProfileReceipt ExactProfileReceipt(UninstallSigningIdentity identity) =>
        new(
            ProfileExists: true,
            HasOwnershipValues: true,
            RegisteredPath: identity.ProfilePath,
            OwnerMarker: identity.OwnerMarker,
            InstallInstanceId: identity.OwnerMarker["SimplySignAuto/v1/".Length..],
            Sid: identity.Sid,
            AccountName: identity.AccountName,
            RecordedPath: identity.ProfilePath);

    private static SimplySignAuto.Service.ServiceConfiguration Configuration()
    {
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", "controlled"));
        return new SimplySignAuto.Service.ServiceConfiguration(
            new string('a', 64),
            "S-1-5-21-1000-2000-3000-4000",
            Path.Combine(root, "SimplySignAuto"),
            Path.Combine(root, "SimplySignAuto", "spool"),
            7080,
            "SimplySignAuto/v1",
            "0123456789abcdef0123456789abcdef",
            Path.Combine(root, "SimplySignAuto.exe"),
            Path.Combine(root, "user", "AppData", "Local", "SimplySignAuto", "agent.json"));
    }

    private static InstallationReceipt ManualReceipt()
    {
        var root = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.Tests",
            "manual-owned"));
        return new InstallationReceipt(
            InstallationReceipt.CurrentSchemaVersion,
            InstallationMode.Manual,
            "0123456789abcdef0123456789abcdef",
            "S-1-5-21-1000-2000-3000-4000",
            Path.Combine(root, "Program Files", "SimplySignAuto", "SimplySignAuto.exe"),
            Path.Combine(root, "Users", "admin", "AppData", "Local", "SimplySignAuto", "manual"));
    }

    private sealed class RecordingManualUninstallEnvironment(InstallationReceipt receipt)
        : IManualUninstallEnvironment
    {
        public bool IsWindows => true;

        public string CommonDesktopDirectory => Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.Tests",
            "PublicDesktop");

        public string ProgramDataRoot => Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.Tests",
            "ProgramData"));

        public Task<InstallationReceipt> LoadReceiptAsync(CancellationToken cancellationToken) =>
            Task.FromResult(receipt);
    }

    private sealed class RecordingUninstallEnvironment(
        SimplySignAuto.Service.ServiceConfiguration configuration,
        UninstallSigningIdentity? identity,
        InstallationReceipt? receipt = null) : IUninstallEnvironment
    {
        public bool IsWindows => true;

        public string CommonDesktopDirectory => Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.Tests",
            "PublicDesktop");

        public Task<SimplySignAuto.Service.ServiceConfiguration> LoadConfigurationAsync(
            CancellationToken cancellationToken) => Task.FromResult(configuration);

        public Task<InstallationReceipt?> LoadInstallationReceiptAsync(
            CancellationToken cancellationToken) => Task.FromResult(receipt);

        public void ValidateControlledPaths(
            SimplySignAuto.Service.ServiceConfiguration configured)
        {
        }

        public UninstallSigningIdentity? InspectSigningIdentity(
            SimplySignAuto.Service.ServiceConfiguration configured,
            string ownerMarker) => identity;
    }

    private sealed class RecordingInstallationReceiptStore(InstallationReceipt current)
        : IInstallationReceiptStore
    {
        public InstallationReceipt? Current { get; private set; } = current;

        public List<string> Events { get; } = [];

        public Task<InstallationReceipt?> LoadOptionalAsync(CancellationToken cancellationToken)
        {
            Events.Add("load");
            return Task.FromResult(Current);
        }

        public Task CreateAsync(
            InstallationReceipt receipt,
            CancellationToken cancellationToken) => throw new InvalidOperationException();

        public Task DeleteExactAsync(
            InstallationReceipt receipt,
            CancellationToken cancellationToken)
        {
            Events.Add("delete");
            Assert.Equal(receipt, Current);
            Current = null;
            return Task.CompletedTask;
        }
    }

    private sealed class RootSwapPurgeIsolationFileSystem(
        IPurgeIsolationFileSystem inner,
        string swappedRoot,
        string externalRoot) : IPurgeIsolationFileSystem
    {
        private PurgeIsolationPlan? _plan;

        public PurgeIsolationPlan Plan(
            string dataRoot,
            string? agentDirectory,
            PurgeInstallIdentity installIdentity)
        {
            var planned = inner.Plan(dataRoot, agentDirectory, installIdentity);
            var runningDirectory = Path.GetDirectoryName(Environment.ProcessPath!)!;
            _plan = planned with
            {
                Groups = planned.Groups
                    .Select(group => group with
                    {
                        Targets = group.Targets
                            .Where(target => !string.Equals(
                                target.SourcePath,
                                runningDirectory,
                                StringComparison.OrdinalIgnoreCase))
                            .ToArray(),
                    })
                    .Where(group => group.Targets.Count > 0)
                    .ToArray(),
            };
            return _plan;
        }

        public void CreateProtectedOperationRoot(string path) => inner.CreateProtectedOperationRoot(path);

        public Task WriteDurableManifestAsync(
            PurgeIsolationPlan plan,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public void CreateProtectedStaging(string path) => inner.CreateProtectedStaging(path);

        public void MoveToStaging(PurgeIsolationTarget target)
        {
            if (string.Equals(target.SourcePath, swappedRoot, StringComparison.OrdinalIgnoreCase))
            {
                Directory.Delete(swappedRoot, recursive: false);
                Directory.CreateSymbolicLink(swappedRoot, externalRoot);
            }

            inner.MoveToStaging(target);
        }

        public void RollbackMove(PurgeIsolationTarget target) => inner.RollbackMove(target);

        public Task ScheduleDeferredCleanupAsync(
            PurgeIsolationPlan plan,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RollbackDeferredCleanupAsync(PurgeIsolationPlan plan) =>
            inner.RollbackDeferredCleanupAsync(plan);

        public void RemoveDurableManifest(PurgeIsolationPlan plan) =>
            inner.RemoveDurableManifest(plan);

        public void RemoveEmptyStaging(string path) => inner.RemoveEmptyStaging(path);

        public void RemoveEmptyOperationRoot(string path) => inner.RemoveEmptyOperationRoot(path);

        public void RollbackQuarantineForCleanup()
        {
            if (_plan is null)
            {
                return;
            }

            foreach (var target in _plan.Groups.SelectMany(group => group.Targets).Reverse())
            {
                if (string.Equals(target.SourcePath, swappedRoot, StringComparison.OrdinalIgnoreCase))
                {
                    if (Directory.Exists(target.StagedPath))
                    {
                        Directory.Delete(target.StagedPath, recursive: false);
                    }

                    continue;
                }

                if (Directory.Exists(target.StagedPath) && !Directory.Exists(target.SourcePath))
                {
                    inner.RollbackMove(target);
                }
            }

            foreach (var group in _plan.Groups.Reverse())
            {
                inner.RemoveEmptyStaging(group.StagingRoot);
            }

            inner.RemoveEmptyOperationRoot(Path.GetDirectoryName(_plan.ManifestPath)!);
        }
    }
}
