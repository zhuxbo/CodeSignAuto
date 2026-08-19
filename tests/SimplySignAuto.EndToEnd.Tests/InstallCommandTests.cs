using System.Security.Cryptography;
using System.Security.Principal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Win32;
using SimplySignAuto.App;
using SimplySignAuto.App.Commands;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Service;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class InstallCommandTests
{
    private const string TestInstallOwnerMarker =
        "SimplySignAuto/v1/0123456789abcdef0123456789abcdef";

    [Fact]
    public void Setup_route_accepts_only_the_parameterless_command()
    {
        Assert.Equal(ApplicationEntryKind.Setup, ApplicationEntryRoute.Parse(["setup"]).Kind);
        Assert.True(SetupCommand.TryParse([]));
        Assert.False(SetupCommand.TryParse(["--user", "other"]));
        Assert.Equal(ApplicationEntryKind.Invalid, ApplicationEntryRoute.Parse(["setup", "--user", "other"]).Kind);
    }

    [Theory]
    [InlineData(SetupPreflightFailure.NotWindowsServer2025, "windows_server_2025_required")]
    [InlineData(SetupPreflightFailure.NotAdministrator, "administrator_required")]
    [InlineData(SetupPreflightFailure.DomainController, "domain_controller_unsupported")]
    [InlineData(SetupPreflightFailure.DesktopMissing, "simplysign_desktop_missing")]
    [InlineData(SetupPreflightFailure.Pkcs11Missing, "simplysign_pkcs11_missing")]
    [InlineData(SetupPreflightFailure.InstallResourceConflict, "setup_resource_conflict")]
    public async Task Setup_preflight_failure_performs_zero_mutation(
        SetupPreflightFailure failure,
        string expectedCode)
    {
        var events = new List<string>();
        var preflight = new RecordingSetupPreflight(events) { Failure = failure };
        var media = new RecordingInstallMediaStager(events);
        var reservation = new RecordingSetupResourceReservation(events);
        var provisioner = new RecordingSetupProvisioner(events);
        var writer = new RecordingSetupConfigurationWriter(events);
        var installer = new RecordingSetupInstaller(events);
        using var output = new StringWriter();

        var error = await Assert.ThrowsAsync<SetupException>(() => new SetupOrchestrator(
                media,
                preflight,
                reservation,
                provisioner,
                writer,
                installer)
            .ExecuteAsync(output, CancellationToken.None));

        Assert.Equal(expectedCode, error.Code);
        Assert.Equal(["media-plan", "preflight", "media-rollback"], events);
        Assert.Empty(media.Mutations);
        Assert.Empty(provisioner.Mutations);
        Assert.Empty(reservation.Mutations);
        Assert.Empty(writer.Mutations);
        Assert.Empty(installer.Mutations);
    }

    [Fact]
    public async Task Setup_composes_preflight_managed_user_profile_configuration_and_existing_install()
    {
        var events = new List<string>();
        var preflight = new RecordingSetupPreflight(events);
        var media = new RecordingInstallMediaStager(events);
        var reservation = new RecordingSetupResourceReservation(events);
        var provisioner = new RecordingSetupProvisioner(events);
        var writer = new RecordingSetupConfigurationWriter(events);
        var installer = new RecordingSetupInstaller(events);
        using var output = new StringWriter();

        await new SetupOrchestrator(media, preflight, reservation, provisioner, writer, installer)
            .ExecuteAsync(output, CancellationToken.None);

        Assert.Equal(
            [
                "media-plan", "preflight", "media-stage", "reserve", "create-user",
                "media-authorize:S-1-5-21-1000-2000-3000-4000", "create-profile",
                "write-config", "install", "delete-config"
            ],
            events);
        Assert.Equal("S-1-5-21-1000-2000-3000-4000", media.AuthorizedSid);
        Assert.Equal("SimplySignAgent", provisioner.RequestedUserName);
        Assert.Equal("TEST\\SimplySignAgent", installer.SigningUser);
        Assert.Equal(writer.GeneratedPath, installer.AgentConfigurationPath);
        Assert.Contains("restart_required", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("authenticode_disabled_signtool_missing", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Setup_install_resource_preflight_rejects_every_conflict_and_untrusted_dependency()
    {
        var clean = new SetupInstallResourceInspection(
            ServiceExists: false,
            AgentTaskExists: false,
            DataRootEntryExists: false,
            ProfileRootEntryExists: false,
            ProgramDataRootSecure: true,
            ProfilesRootSecure: true,
            ServiceControlAvailable: true,
            TaskSchedulerAvailable: true);

        SetupInstallResourcePreflight.Validate(clean);

        foreach (var conflict in new[]
        {
            clean with { ServiceExists = true },
            clean with { AgentTaskExists = true },
            clean with { DataRootEntryExists = true },
            clean with { ProfileRootEntryExists = true },
        })
        {
            var error = Assert.Throws<SetupException>(() =>
                SetupInstallResourcePreflight.Validate(conflict));
            Assert.Equal("setup_resource_conflict", error.Code);
        }

        foreach (var unavailable in new[]
        {
            clean with { ProgramDataRootSecure = false },
            clean with { ProfilesRootSecure = false },
            clean with { ServiceControlAvailable = false },
            clean with { TaskSchedulerAvailable = false },
        })
        {
            var error = Assert.Throws<SetupException>(() =>
                SetupInstallResourcePreflight.Validate(unavailable));
            Assert.Equal("resource_preflight_failed", error.Code);
        }
    }

    [Fact]
    public async Task Setup_install_failure_removes_generated_configuration_then_rolls_back_owned_user_resources()
    {
        var events = new List<string>();
        var preflight = new RecordingSetupPreflight(events);
        var media = new RecordingInstallMediaStager(events);
        var reservation = new RecordingSetupResourceReservation(events);
        var provisioner = new RecordingSetupProvisioner(events);
        var writer = new RecordingSetupConfigurationWriter(events);
        var installer = new RecordingSetupInstaller(events) { Failure = new InstallException("service_create_failed") };
        using var output = new StringWriter();

        var failure = await Assert.ThrowsAsync<InstallException>(() => new SetupOrchestrator(
                media,
                preflight,
                reservation,
                provisioner,
                writer,
                installer)
            .ExecuteAsync(output, CancellationToken.None));

        Assert.Equal("service_create_failed", failure.Code);
        Assert.Equal(
            [
                "media-plan", "preflight", "media-stage", "reserve", "create-user",
                "media-authorize:S-1-5-21-1000-2000-3000-4000", "create-profile",
                "write-config", "install", "delete-config", "rollback-provision",
                "rollback-reserve", "media-rollback"
            ],
            events);
    }

    [Fact]
    public async Task Setup_resource_reservation_failure_still_performs_zero_user_mutation()
    {
        var events = new List<string>();
        var preflight = new RecordingSetupPreflight(events);
        var media = new RecordingInstallMediaStager(events);
        var reservation = new RecordingSetupResourceReservation(events)
        {
            Failure = new SetupException("setup_resource_conflict"),
        };
        var provisioner = new RecordingSetupProvisioner(events);

        var error = await Assert.ThrowsAsync<SetupException>(() => new SetupOrchestrator(
                media,
                preflight,
                reservation,
                provisioner,
                new RecordingSetupConfigurationWriter(events),
                new RecordingSetupInstaller(events))
            .ExecuteAsync(TextWriter.Null, CancellationToken.None));

        Assert.Equal("setup_resource_conflict", error.Code);
        Assert.Equal(["media-plan", "preflight", "media-stage", "reserve", "media-rollback"], events);
        Assert.Empty(provisioner.Mutations);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Setup_media_plan_or_stage_failure_performs_zero_user_profile_and_autologon_mutation(
        bool failDuringPlan)
    {
        var events = new List<string>();
        var media = new RecordingInstallMediaStager(events)
        {
            PlanFailure = failDuringPlan ? new SetupException("install_media_preflight_failed") : null,
            StageFailure = failDuringPlan ? null : new SetupException("install_media_copy_failed"),
        };
        var reservation = new RecordingSetupResourceReservation(events);
        var provisioner = new RecordingSetupProvisioner(events);

        var error = await Assert.ThrowsAsync<SetupException>(() => new SetupOrchestrator(
                media,
                new RecordingSetupPreflight(events),
                reservation,
                provisioner,
                new RecordingSetupConfigurationWriter(events),
                new RecordingSetupInstaller(events))
            .ExecuteAsync(TextWriter.Null, CancellationToken.None));

        Assert.Equal(
            failDuringPlan ? "install_media_preflight_failed" : "install_media_copy_failed",
            error.Code);
        Assert.Equal(
            failDuringPlan
                ? ["media-plan"]
                : ["media-plan", "preflight", "media-stage", "media-rollback"],
            events);
        Assert.Empty(provisioner.Mutations);
        Assert.Empty(reservation.Mutations);
    }

    [Fact]
    public async Task Setup_media_rollback_failure_overrides_later_failure_with_state_uncertain()
    {
        var events = new List<string>();
        var media = new RecordingInstallMediaStager(events)
        {
            RollbackFailure = new SetupException("setup_state_uncertain"),
        };
        var installer = new RecordingSetupInstaller(events)
        {
            Failure = new InstallException("service_create_failed"),
        };

        var error = await Assert.ThrowsAsync<SetupException>(() => new SetupOrchestrator(
                media,
                new RecordingSetupPreflight(events),
                new RecordingSetupResourceReservation(events),
                new RecordingSetupProvisioner(events),
                new RecordingSetupConfigurationWriter(events),
                installer)
            .ExecuteAsync(TextWriter.Null, CancellationToken.None));

        Assert.Equal("setup_state_uncertain", error.Code);
        Assert.Equal("media-rollback", events[^1]);
    }

    [Fact]
    public async Task Setup_uncertain_prior_rollback_preserves_promoted_media()
    {
        var events = new List<string>();
        var media = new RecordingInstallMediaStager(events);
        var provisioner = new RecordingSetupProvisioner(events)
        {
            RollbackFailure = new ProvisionAgentUserException(
                "provision_state_uncertain",
                rollbackStateUncertain: true),
        };
        var installer = new RecordingSetupInstaller(events)
        {
            Failure = new InstallException("service_create_failed"),
        };

        var error = await Assert.ThrowsAsync<SetupException>(() => new SetupOrchestrator(
                media,
                new RecordingSetupPreflight(events),
                new RecordingSetupResourceReservation(events),
                provisioner,
                new RecordingSetupConfigurationWriter(events),
                installer)
            .ExecuteAsync(TextWriter.Null, CancellationToken.None));

        Assert.Equal("setup_state_uncertain", error.Code);
        Assert.DoesNotContain("media-rollback", events);
        Assert.DoesNotContain("media-rollback", media.Mutations);
    }

    [Fact]
    public async Task Setup_installer_uncertain_failure_preserves_media_and_returns_state_uncertain()
    {
        var events = new List<string>();
        var media = new RecordingInstallMediaStager(events);
        var installer = new RecordingSetupInstaller(events)
        {
            Failure = new InstallException("install_state_uncertain"),
        };

        var error = await Assert.ThrowsAsync<SetupException>(() => new SetupOrchestrator(
                media,
                new RecordingSetupPreflight(events),
                new RecordingSetupResourceReservation(events),
                new RecordingSetupProvisioner(events),
                new RecordingSetupConfigurationWriter(events),
                installer)
            .ExecuteAsync(TextWriter.Null, CancellationToken.None));

        Assert.Equal("setup_state_uncertain", error.Code);
        Assert.Contains("rollback-provision", events);
        Assert.Contains("rollback-reserve", events);
        Assert.DoesNotContain("media-rollback", events);
    }

    [Fact]
    public async Task Setup_provision_failure_with_uncertain_internal_rollback_preserves_media()
    {
        var events = new List<string>();
        var media = new RecordingInstallMediaStager(events);
        var provisioner = new RecordingSetupProvisioner(events)
        {
            ProvisionFailure = new ProvisionAgentUserException(
                "provision_agent_user_failed",
                rollbackStateUncertain: true),
        };

        var error = await Assert.ThrowsAsync<SetupException>(() => new SetupOrchestrator(
                media,
                new RecordingSetupPreflight(events),
                new RecordingSetupResourceReservation(events),
                provisioner,
                new RecordingSetupConfigurationWriter(events),
                new RecordingSetupInstaller(events))
            .ExecuteAsync(TextWriter.Null, CancellationToken.None));

        Assert.Equal("setup_state_uncertain", error.Code);
        Assert.Contains("rollback-reserve", events);
        Assert.DoesNotContain("rollback-provision", events);
        Assert.DoesNotContain("media-rollback", events);
    }

    [Fact]
    public void Installed_runtime_paths_are_fixed_under_program_files()
    {
        const string programFiles = @"C:\Program Files";
        var platform = new WindowsAutoLogonPlatform();

        var environment = new WindowsInstallEnvironment(platform, programFiles);
        var task = WindowsAutoLogonPlatform.CreateAgentTask(
            new ProvisionedAgentUser(
                "TEST\\SimplySignAgent",
                InstallFixture.SigningSid,
                "TEST"),
            TestInstallOwnerMarker,
            programFiles);

        Assert.Equal(
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            environment.ExecutablePath);
        Assert.Equal(environment.ExecutablePath, task.ExecutablePath);
        Assert.Equal(["agent", "--background"], task.Arguments);
    }

    [Fact]
    public void Install_media_space_preflight_is_exact_and_fail_closed()
    {
        InstallMediaPreflight.ValidateAvailableSpace(4096, 4096);

        var error = Assert.Throws<SetupException>(() =>
            InstallMediaPreflight.ValidateAvailableSpace(4095, 4096));

        Assert.Equal("install_media_space_insufficient", error.Code);
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_stager_holds_source_snapshot_copies_flushes_promotes_and_authorizes_exact_sid()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var verifier = new RecordingInstallMediaVerifier();
        var stager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            verifier,
            () => "testnonce");

        var plan = await stager.PlanAsync(CancellationToken.None);

        Assert.Equal(
            ["SimplySignAuto.exe", "docs/readme.txt", "install-prerequisites.ps1", "release-files.cat"],
            plan.Files.Select(file => file.RelativePath));
        Assert.ThrowsAny<IOException>(() => File.Open(
            Path.Combine(fixture.SourceRoot, "docs", "readme.txt"),
            FileMode.Open,
            FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete));
        Assert.False(Directory.Exists(plan.StagingRoot));
        Assert.False(Directory.Exists(plan.TargetRoot));

        await stager.StageAsync(plan, CancellationToken.None);

        Assert.False(Directory.Exists(plan.StagingRoot));
        Assert.True(Directory.Exists(plan.TargetRoot));
        Assert.Equal([fixture.SourceRoot, plan.StagingRoot], verifier.VerifiedRoots);
        Assert.All(plan.Files, file => Assert.Equal(
            file.Sha256,
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                File.ReadAllBytes(file.FinalPath))).ToLowerInvariant()));
        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.ReadDirectory(plan.TargetRoot),
            directory: true);

        const string exactSid = "S-1-5-21-1000-2000-3000-4000";
        await stager.AuthorizeAsync(plan, exactSid, CancellationToken.None);

        WindowsInstallAcl.VerifyDirectory(
            plan.TargetRoot,
            InstallAclProfile.SigningUserRead,
            new SecurityIdentifier(exactSid));
        Assert.All(
            Directory.EnumerateDirectories(plan.TargetRoot, "*", SearchOption.AllDirectories),
            directory => WindowsInstallAcl.VerifyDirectory(
                directory,
                InstallAclProfile.SigningUserRead,
                new SecurityIdentifier(exactSid)));
        Assert.All(plan.Files, file => WindowsInstallAcl.VerifyFile(
            file.FinalPath,
            InstallAclProfile.SigningUserRead,
            new SecurityIdentifier(exactSid)));
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_plan_releases_source_handles_during_catalog_verification()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var verifier = new ExclusiveCatalogInstallMediaVerifier();
        var stager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            verifier,
            () => "catalog");

        var plan = await stager.PlanAsync(CancellationToken.None);

        Assert.Equal(1, verifier.VerifyMediaCalls);
        Assert.ThrowsAny<IOException>(() => File.Open(
            Path.Combine(fixture.SourceRoot, "docs", "readme.txt"),
            FileMode.Open,
            FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete));
        await stager.RollbackAsync(plan);
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_plan_rejects_source_change_during_catalog_verification()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var changedPath = Path.Combine(fixture.SourceRoot, "docs", "readme.txt");
        var stager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            new MutatingCatalogInstallMediaVerifier(changedPath),
            () => "changedincatalog");

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            stager.PlanAsync(CancellationToken.None));

        Assert.Equal("install_media_source_changed", error.Code);
        Assert.False(Directory.Exists(InstallMediaPaths.GetTargetRoot(fixture.ProgramFilesRoot)));
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_stager_rejects_existing_target_before_mutation()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var target = InstallMediaPaths.GetTargetRoot(fixture.ProgramFilesRoot);
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "unknown.txt"), "preserve");
        var stager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            new RecordingInstallMediaVerifier(),
            () => "testnonce");

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            stager.PlanAsync(CancellationToken.None));

        Assert.Equal("install_media_target_exists", error.Code);
        Assert.Equal("preserve", File.ReadAllText(Path.Combine(target, "unknown.txt")));
        Assert.False(Directory.Exists(Path.Combine(fixture.ProgramFilesRoot, "SimplySignAuto.part-testnonce")));
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_rollback_deletes_only_the_exact_owned_tree_and_preserves_drift()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var exactStager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            new RecordingInstallMediaVerifier(),
            () => "exact");
        var exactPlan = await exactStager.PlanAsync(CancellationToken.None);
        await exactStager.StageAsync(exactPlan, CancellationToken.None);

        await exactStager.RollbackAsync(exactPlan);

        Assert.False(Directory.Exists(exactPlan.TargetRoot));

        var driftStager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            new RecordingInstallMediaVerifier(),
            () => "drift");
        var driftPlan = await driftStager.PlanAsync(CancellationToken.None);
        await driftStager.StageAsync(driftPlan, CancellationToken.None);
        File.WriteAllText(Path.Combine(driftPlan.TargetRoot, "unknown.txt"), "preserve");

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            driftStager.RollbackAsync(driftPlan));

        Assert.Equal("setup_state_uncertain", error.Code);
        Assert.True(File.Exists(Path.Combine(driftPlan.TargetRoot, "unknown.txt")));
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_stager_preserves_part_when_create_readback_cannot_establish_ownership()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var directoryOperations = new FailingCreatedDirectoryReadbackOperations();
        var stager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            new RecordingInstallMediaVerifier(),
            () => "uncertain",
            directoryOperations);
        var plan = await stager.PlanAsync(CancellationToken.None);

        var stageError = await Assert.ThrowsAsync<SetupException>(() =>
            stager.StageAsync(plan, CancellationToken.None));
        var rollbackError = await Assert.ThrowsAsync<SetupException>(() =>
            stager.RollbackAsync(plan));

        Assert.Equal("setup_state_uncertain", stageError.Code);
        Assert.Equal("setup_state_uncertain", rollbackError.Code);
        Assert.True(Directory.Exists(plan.StagingRoot));
        Assert.False(Directory.Exists(plan.TargetRoot));
    }

    [Fact]
    public void Install_media_publisher_identity_normalizes_thumbprint_case_but_rejects_multiple_signers()
    {
        var reader = new RecordingAuthenticodeSignatureReader(
            [new string('A', 40)],
            [new string('a', 40)]);

        var mediaRoot = Path.Combine("media", "release");
        var executablePath = Path.Combine(mediaRoot, "SimplySignAuto.exe");
        var scriptPath = Path.Combine(mediaRoot, "install-prerequisites.ps1");

        var publisher = new WindowsInstallMediaVerifier(reader)
            .VerifyInitialPublisher(executablePath, scriptPath);

        Assert.Equal(new string('A', 40), publisher);
        Assert.Equal(
            [Path.GetFullPath(executablePath), Path.GetFullPath(Path.Combine(mediaRoot, "release-files.cat"))],
            reader.ReadPaths);

        reader.ExecutableSigners = [new string('A', 40), new string('B', 40)];
        var error = Assert.Throws<SetupException>(() =>
            new WindowsInstallMediaVerifier(reader)
                .VerifyInitialPublisher(executablePath, scriptPath));
        Assert.Equal("install_media_signature_invalid", error.Code);
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_stager_rejects_source_hardlinks_before_mutation()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var original = Path.Combine(fixture.SourceRoot, "docs", "readme.txt");
        var hardlink = Path.Combine(fixture.SourceRoot, "docs", "readme-hardlink.txt");
        Assert.True(CreateHardLinkW(hardlink, original, nint.Zero));
        var stager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            new RecordingInstallMediaVerifier(),
            () => "hardlink");

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            stager.PlanAsync(CancellationToken.None));

        Assert.Equal("install_media_link_invalid", error.Code);
        Assert.False(Directory.Exists(InstallMediaPaths.GetTargetRoot(fixture.ProgramFilesRoot)));
        Assert.False(Directory.Exists(Path.Combine(
            fixture.ProgramFilesRoot,
            "SimplySignAuto.part-hardlink")));
    }

    [WindowsAdministratorFact]
    public async Task Windows_media_stager_detects_source_closure_change_and_releases_then_rolls_back_part()
    {
        using var fixture = WindowsInstallMediaFixture.Create();
        var stager = new WindowsInstallMediaStager(
            fixture.SourceRoot,
            fixture.ProgramFilesRoot,
            new RecordingInstallMediaVerifier(),
            () => "changed");
        var plan = await stager.PlanAsync(CancellationToken.None);
        var unexpected = Path.Combine(fixture.SourceRoot, "unexpected.txt");
        File.WriteAllText(unexpected, "unexpected");

        var error = await Assert.ThrowsAsync<SetupException>(() =>
            stager.StageAsync(plan, CancellationToken.None));
        await stager.RollbackAsync(plan);

        Assert.Equal("install_media_source_changed", error.Code);
        Assert.True(File.Exists(unexpected));
        Assert.False(Directory.Exists(plan.StagingRoot));
        Assert.False(Directory.Exists(plan.TargetRoot));
    }

    [SignedReleaseMediaFact]
    public async Task Production_media_verifier_accepts_real_signed_catalog_closed_media_without_mutation()
    {
        var root = Path.GetFullPath(
            Environment.GetEnvironmentVariable("SIMPLYSIGN_SIGNED_MEDIA_ROOT")!);
        var before = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .ToDictionary(
                path => Path.GetRelativePath(root, path),
                path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                StringComparer.Ordinal);
        var verifier = new WindowsInstallMediaVerifier();
        var publisher = verifier.VerifyInitialPublisher(
            Path.Combine(root, "SimplySignAuto.exe"),
            Path.Combine(root, "install-prerequisites.ps1"));

        await verifier.VerifyMediaAsync(root, publisher, CancellationToken.None);

        var after = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .ToDictionary(
                path => Path.GetRelativePath(root, path),
                path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                StringComparer.Ordinal);
        Assert.Equal(
            before.OrderBy(pair => pair.Key, StringComparer.Ordinal),
            after.OrderBy(pair => pair.Key, StringComparer.Ordinal));
    }

    [SignedReleaseMediaFact]
    public async Task Production_media_verifier_accepts_only_the_locked_signed_application_exception()
    {
        var root = Path.GetFullPath(
            Environment.GetEnvironmentVariable("SIMPLYSIGN_SIGNED_MEDIA_ROOT")!);
        var verifier = new WindowsInstallMediaVerifier();
        var publisher = verifier.VerifyInitialPublisher(
            Path.Combine(root, "SimplySignAuto.exe"),
            Path.Combine(root, "install-prerequisites.ps1"));

        using (File.Open(
                   Path.Combine(root, "SimplySignAuto.exe"),
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read))
        {
            await verifier.VerifyMediaAsync(root, publisher, CancellationToken.None);
        }

        using (File.Open(
                   Path.Combine(root, "agent.example.json"),
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read))
        {
            var error = await Assert.ThrowsAsync<SetupException>(() =>
                verifier.VerifyMediaAsync(root, publisher, CancellationToken.None));
            Assert.Equal("install_media_verification_failed", error.Code);
        }
    }

    [SignedReleaseMediaAdministratorFact]
    public async Task Production_media_stager_accepts_real_signed_media_through_every_verification_phase()
    {
        var root = Path.GetFullPath(
            Environment.GetEnvironmentVariable("SIMPLYSIGN_SIGNED_MEDIA_ROOT")!);
        var stager = new WindowsInstallMediaStager(
            root,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            new WindowsInstallMediaVerifier(),
            () => "signedmediadiagnostic");
        InstallMediaPlan? plan = null;
        try
        {
            try
            {
                plan = await stager.PlanAsync(CancellationToken.None);
            }
            catch (SetupException error)
            {
                throw new InvalidOperationException($"plan:{error.Code}", error);
            }

            try
            {
                await stager.StageAsync(plan, CancellationToken.None);
            }
            catch (SetupException error)
            {
                throw new InvalidOperationException($"stage:{error.Code}", error);
            }

            try
            {
                await stager.AuthorizeAsync(
                    plan,
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value,
                    CancellationToken.None);
            }
            catch (SetupException error)
            {
                throw new InvalidOperationException($"authorize:{error.Code}", error);
            }
        }
        finally
        {
            if (plan is not null)
            {
                await stager.RollbackAsync(plan);
            }
        }
    }

    [Fact]
    public void Generated_setup_configuration_enables_only_capabilities_present_at_preflight()
    {
        var user = new ProvisionedAgentUser(
            "TEST\\SimplySignAgent",
            InstallFixture.SigningSid,
            "TEST",
            @"C:\Users\SimplySignAgent",
            TestInstallOwnerMarker);
        var withoutSignTool = new SetupPreflightResult(
            @"C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe",
            @"C:\Windows\System32\SimplySignPKCS.dll",
            null);

        var pdfOnly = SetupAgentConfigurationFactory.Create(
            user,
            withoutSignTool,
            @"C:\ProgramData");
        var withAuthenticode = SetupAgentConfigurationFactory.Create(
            user,
            withoutSignTool with { SignToolPath = @"C:\Windows Kits\10\bin\x64\signtool.exe" },
            @"C:\ProgramData");

        Assert.NotNull(pdfOnly.Pdf);
        Assert.Null(pdfOnly.Authenticode);
        Assert.Equal(@"C:\Windows\System32\SimplySignPKCS.dll", pdfOnly.Pkcs11ModulePath);
        Assert.Equal(@"C:\Windows Kits\10\bin\x64\signtool.exe", withAuthenticode.Authenticode!.SignToolPath);
    }

    [Fact]
    public void Task_lookup_accepts_only_the_two_native_not_found_HRESULTs_across_exception_projections()
    {
        Assert.True(WindowsInstallResourceLookup.IsTaskNotFound(new FileNotFoundException()));
        Assert.True(WindowsInstallResourceLookup.IsTaskNotFound(
            new System.Runtime.InteropServices.COMException(
                "missing",
                unchecked((int)0x8004130F))));
        Assert.False(WindowsInstallResourceLookup.IsTaskNotFound(
            new System.Runtime.InteropServices.COMException(
                "denied",
                unchecked((int)0x80070005))));
    }

    [Fact]
    public void App_assembly_name_matches_the_windows_service_executable_contract()
    {
        var assembly = typeof(InstallCommand).Assembly;
        using var fixture = new InstallFixture();

        Assert.Equal("SimplySignAuto", assembly.GetName().Name);
        Assert.Equal("SimplySignAuto.dll", Path.GetFileName(assembly.Location));
        Assert.Equal(
            Path.Combine(Path.GetDirectoryName(assembly.Location)!, "SimplySignAuto.exe"),
            ServiceConfigurationLoader.Validate(fixture.ServiceConfiguration() with
            {
                ExecutablePath = Path.Combine(Path.GetDirectoryName(assembly.Location)!, "SimplySignAuto.exe"),
            }).ExecutablePath);
    }

    [Fact]
    public async Task Install_command_maps_service_configuration_failure_to_a_stable_error()
    {
        using var fixture = new InstallFixture();
        await fixture.WriteAgentConfigurationAsync(fixture.Configuration);
        using var output = new StringWriter();
        using var error = new StringWriter();
        var environment = new RecordingInstallEnvironment(
            fixture,
            Path.Combine(fixture.Root, "SimplySignAuto.App.exe"));

        var exitCode = await InstallCommand.ExecuteAsync(
            fixture.Arguments,
            output,
            error,
            environment,
            _ => new RecordingInstallActionExecutor(),
            new FixedTokenGenerator(new byte[32]),
            CancellationToken.None);

        Assert.Equal(1, exitCode);
        Assert.Equal($"service_configuration_invalid{Environment.NewLine}", error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public void Install_arguments_require_complete_unique_strict_options()
    {
        Assert.True(InstallCommand.TryParse(
            [
                "--signing-user", "TEST\\signer",
                "--agent-config", Path.Combine(Path.GetTempPath(), "agent.json"),
            ],
            out var valid));
        Assert.Equal(7080, valid!.ListenPort);
        Assert.False(valid.OpenFirewall);

        Assert.False(InstallCommand.TryParse(
            [
                "--signing-user", "TEST\\signer",
                "--signing-user", "TEST\\other",
                "--agent-config", Path.Combine(Path.GetTempPath(), "agent.json"),
            ],
            out _));
        Assert.False(InstallCommand.TryParse(["--open-firewall"], out _));
    }

    [Fact]
    public void Uninstall_arguments_accept_only_default_or_exact_purge_shape()
    {
        Assert.True(UninstallCommand.TryParse([], out var conservative));
        Assert.False(conservative!.PurgeData);
        Assert.True(UninstallCommand.TryParse(
            ["--purge-data", "--confirm", "PURGE"],
            out var purge));
        Assert.True(purge!.PurgeData);
        Assert.False(UninstallCommand.TryParse(["--purge-data"], out _));
        Assert.False(UninstallCommand.TryParse(["--confirm", "PURGE", "--purge-data"], out _));
    }

    [Fact]
    public void Unelevated_uninstall_relaunches_only_the_fixed_current_executable_and_forwards_exit_code()
    {
        var launcher = new RecordingUninstallElevationLauncher(23);
        var executable = Path.GetFullPath(Path.Combine(
            Path.GetTempPath(),
            "Program Files",
            "SimplySignAuto",
            "SimplySignAuto.exe"));

        var exitCode = UninstallElevation.RelaunchElevatedAndWait(
            executable,
            ["--purge-data", "--confirm", "PURGE"],
            TextWriter.Null,
            launcher);

        Assert.Equal(23, exitCode);
        Assert.Equal(executable, launcher.ExecutablePath);
        Assert.Equal(["uninstall", "--purge-data", "--confirm", "PURGE"], launcher.Arguments);
        Assert.Equal("runas", launcher.Verb);
        Assert.True(launcher.WaitForExit);
    }

    [Fact]
    public async Task Install_plan_creates_local_system_service_and_exact_interactive_sid_task()
    {
        using var fixture = new InstallFixture();
        var planner = fixture.CreatePlanner();

        var plan = await planner.PlanAsync(
            fixture.Options with { OpenFirewall = true },
            CancellationToken.None);

        Assert.Equal(32, plan.InstallInstanceId.Length);
        var exactOwner = InstallOwnershipMarker.Create(plan.InstallInstanceId);

        var service = Assert.Single(plan.Actions.OfType<CreateWindowsService>());
        Assert.Equal("LocalSystem", service.Account);
        Assert.False(service.AutomaticDelayedStart);
        Assert.Equal([5, 15, 60], service.RestartDelaysSeconds);
        Assert.Equal(["service"], service.Arguments);
        Assert.Equal(exactOwner, service.OwnerMarker);
        var task = Assert.Single(plan.Actions.OfType<CreateInteractiveLogonTask>());
        Assert.Equal(InstallFixture.SigningSid, task.SigningUserSid);
        Assert.Equal("InteractiveToken", task.LogonType);
        Assert.True(task.Highest);
        Assert.True(task.RunOnlyIfNetworkAvailable);
        Assert.Equal(["agent", "--background"], task.Arguments);
        Assert.Equal(exactOwner, task.OwnerMarker);
        Assert.Equal(exactOwner, Assert.Single(plan.Actions.OfType<CreateOwnedFirewallRule>()).OwnerMarker);
        var productRegistration = Assert.Single(plan.Actions.OfType<RegisterProductUninstall>()).Registration;
        Assert.Equal("SimplySignAuto", productRegistration.DisplayName);
        Assert.Equal(ApplicationVersion.ReadIdentity(typeof(InstallCommand).Assembly), productRegistration.DisplayVersion);
        Assert.Equal("SimplySignAuto", productRegistration.Publisher);
        Assert.Equal(Path.GetDirectoryName(plan.Paths.ExecutablePath), productRegistration.InstallLocation);
        Assert.Equal($"\"{plan.Paths.ExecutablePath}\",0", productRegistration.DisplayIcon);
        Assert.Equal($"\"{plan.Paths.ExecutablePath}\" uninstall", productRegistration.UninstallString);
        Assert.Equal(exactOwner, productRegistration.OwnerMarker);
        var shortcut = Assert.Single(plan.Actions.OfType<CreateDesktopShortcut>());
        Assert.Equal(
            Path.Combine(fixture.CommonDesktopDirectory, "SimplySignAuto.lnk"),
            shortcut.Path);
        Assert.Equal(plan.Paths.ExecutablePath, shortcut.TargetPath);
        Assert.Equal(exactOwner, shortcut.OwnerMarker);
        var actionArray = plan.Actions.ToArray();
        var productRegistrationIndex = Array.FindIndex(actionArray, action => action is RegisterProductUninstall);
        var verifyIndex = Array.FindIndex(actionArray, action => action is VerifyInstallSecurity);
        var serviceStartIndex = Array.FindIndex(actionArray, action => action is StartAndVerifyWindowsService);
        var agentStartIndex = Array.FindIndex(actionArray, action => action is StartInteractiveAgentTask);
        Assert.True(productRegistrationIndex >= 0 && productRegistrationIndex < verifyIndex);
        Assert.True(verifyIndex < serviceStartIndex);
        Assert.True(serviceStartIndex < agentStartIndex);
        Assert.DoesNotContain("otpauth", JsonSerializer.Serialize(plan), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Install_plan_grants_the_signing_user_read_execute_only_on_the_optional_tools_root()
    {
        using var fixture = new InstallFixture();

        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);

        var toolsRoot = Assert.Single(plan.Actions.OfType<CreateProtectedDirectory>(), action =>
            string.Equals(action.Path, plan.Paths.ToolsRoot, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(InstallAclProfile.SigningUserRead, toolsRoot.Acl);
    }

    [Theory]
    [InlineData(@"C:\Program Files\SimplySignAuto\SimplySignAuto.exe", true)]
    [InlineData(@"C:\Program Files\SimplySignAuto\other.exe", false)]
    [InlineData(@"C:\Program Files\SimplySignAuto\nested\SimplySignAuto.exe", false)]
    [InlineData(@"C:\Users\Administrator\Desktop\SimplySignAuto\SimplySignAuto.exe", false)]
    public void Standard_setup_accepts_only_the_fixed_program_files_executable_location(
        string executablePath,
        bool expected)
    {
        Assert.Equal(
            expected,
            WindowsExecutableSecurity.IsRequiredLocation(
                executablePath,
                @"C:\Program Files"));
    }

    [Fact]
    public async Task Install_plan_reuses_the_exact_preprovision_owner_for_later_task_adoption()
    {
        using var fixture = new InstallFixture();
        const string instanceId = "fedcba9876543210fedcba9876543210";
        var environment = new RecordingInstallEnvironment(fixture)
        {
            ProvisionedInstanceId = instanceId,
        };

        var plan = await new InstallPlanner(environment)
            .PlanAsync(fixture.Options, CancellationToken.None);

        Assert.Equal(instanceId, plan.InstallInstanceId);
        Assert.Equal(
            InstallOwnershipMarker.Create(instanceId),
            Assert.Single(plan.Actions.OfType<CreateInteractiveLogonTask>()).OwnerMarker);
    }

    [Fact]
    public async Task Exact_preprovisioned_agent_task_is_adopted_without_rewriting_it()
    {
        using var fixture = new InstallFixture();
        var lookup = new ReconciledWindowsResourceLookup
        {
            TaskPresent = true,
            ExactOwned = true,
        };
        var runner = new RecordingWindowsCommandRunner();
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            lookup);
        var task = new CreateInteractiveLogonTask(
            "SimplySignAuto.Agent",
            "TEST\\signer",
            InstallFixture.SigningSid,
            fixture.ExecutablePath,
            ["agent", "--background"],
            "InteractiveToken",
            Highest: true,
            RunOnlyIfNetworkAvailable: true,
            TestInstallOwnerMarker);

        var applied = await executor.CreateTaskRegistrationAsync(task, CancellationToken.None);

        Assert.False(applied.Created);
        Assert.Empty(runner.Calls);
    }

    [Theory]
    [InlineData("data")]
    [InlineData("agent")]
    public async Task Install_plan_rejects_an_executable_below_a_controlled_data_root(string controlledRoot)
    {
        using var fixture = new InstallFixture();
        var root = controlledRoot == "data"
            ? fixture.DataRoot
            : Path.Combine(fixture.LocalApplicationData, "SimplySignAuto");
        var planner = new InstallPlanner(new RecordingInstallEnvironment(
            fixture,
            Path.Combine(root, "bin", "SimplySignAuto.exe")));

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            planner.PlanAsync(fixture.Options, CancellationToken.None));

        Assert.Equal("install_arguments_invalid", failure.Code);
    }

    [Fact]
    public async Task Install_plan_fails_closed_when_automatic_interactive_logon_is_not_verified()
    {
        using var fixture = new InstallFixture();
        var environment = new RecordingInstallEnvironment(fixture)
        {
            AutomaticLogonFailure = new InstallException("autologon_not_ready"),
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new InstallPlanner(environment).PlanAsync(fixture.Options, CancellationToken.None));

        Assert.Equal("autologon_not_ready", failure.Code);
    }

    [Fact]
    public async Task Production_install_environment_reuses_the_complete_read_only_provision_contract()
    {
        var platform = ReadOnlyAutoLogonPlatform.Ready();
        var environment = new WindowsInstallEnvironment(platform);
        var account = new ResolvedSigningAccount(
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.GetTempPath());

        await environment.ValidateAutomaticLogonAsync(account, CancellationToken.None);
        var instanceId = await environment.GetProvisionedInstallInstanceIdAsync(
            account,
            CancellationToken.None);

        Assert.Equal("0123456789abcdef0123456789abcdef", instanceId);
        Assert.Equal(["inspect", "resolve", "readback"], platform.Reads);
        Assert.Empty(platform.Mutations);
    }

    [Theory]
    [InlineData(AutoLogonContractFailure.WrongSid)]
    [InlineData(AutoLogonContractFailure.ExtraGroup)]
    [InlineData(AutoLogonContractFailure.InteractiveLogonMissing)]
    [InlineData(AutoLogonContractFailure.NetworkLogonAllowed)]
    [InlineData(AutoLogonContractFailure.RemoteInteractiveLogonAllowed)]
    [InlineData(AutoLogonContractFailure.OwnerMissing)]
    [InlineData(AutoLogonContractFailure.OwnerInvalid)]
    [InlineData(AutoLogonContractFailure.TaskNotExact)]
    public async Task Production_install_environment_rejects_any_incomplete_low_privilege_or_owner_readback(
        AutoLogonContractFailure failureKind)
    {
        var platform = ReadOnlyAutoLogonPlatform.Ready(failureKind);
        var environment = new WindowsInstallEnvironment(platform);
        var account = new ResolvedSigningAccount(
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.GetTempPath());

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            environment.ValidateAutomaticLogonAsync(account, CancellationToken.None));

        Assert.Equal("autologon_not_ready", failure.Code);
        Assert.Empty(platform.Mutations);
    }

    [Fact]
    public async Task Install_plan_rejects_a_missing_provision_owner_instead_of_generating_one()
    {
        using var fixture = new InstallFixture();
        await fixture.WriteAgentConfigurationAsync(fixture.Configuration);
        var environment = new RecordingInstallEnvironment(fixture)
        {
            ProvisionedInstanceId = null,
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new InstallPlanner(environment).PlanAsync(fixture.Options, CancellationToken.None));

        Assert.Equal("autologon_not_ready", failure.Code);
    }

    [Fact]
    public async Task Install_without_an_interactive_signing_session_succeeds_with_an_explicit_readiness_warning()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);
        var executor = new RecordingInstallActionExecutor { InteractiveSessionAvailable = false };
        using var output = new StringWriter();

        _ = await new InstallOrchestrator(executor, new FixedTokenGenerator(new byte[32]))
            .ExecuteAsync(plan, output, CancellationToken.None);

        Assert.Contains("readiness is unavailable until that user logs on", output.ToString(), StringComparison.Ordinal);
        Assert.Contains(executor.Applied, action => action is StartAndVerifyWindowsService);
        Assert.Contains(executor.Applied, action => action is StartInteractiveAgentTask);
    }

    [Fact]
    public async Task Install_with_an_active_session_but_missing_otp_succeeds_with_activation_warning()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);
        var executor = new RecordingInstallActionExecutor
        {
            InteractiveSessionAvailable = true,
            OtpConfigured = false,
        };
        using var output = new StringWriter();

        _ = await new InstallOrchestrator(executor, new FixedTokenGenerator(new byte[32]))
            .ExecuteAsync(plan, output, CancellationToken.None);

        Assert.Contains("activation is required; readiness is unavailable", output.ToString(), StringComparison.Ordinal);
        var started = Assert.Single(executor.Applied, action => action is StartInteractiveAgentTask);
        var status = Assert.IsType<AgentTaskStartStatus>(executor.Results[started].RollbackState);
        Assert.True(status.StartedForActiveSession);
        Assert.True(status.ActivationRequired);
    }

    [Fact]
    public async Task Agent_start_failure_rolls_back_the_started_service_and_all_created_resources()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);
        var executor = new RecordingInstallActionExecutor
        {
            InteractiveSessionAvailable = true,
            FailAgentStart = true,
        };

        await Assert.ThrowsAsync<InstallException>(() =>
            new InstallOrchestrator(executor, new FixedTokenGenerator(new byte[32]))
                .ExecuteAsync(plan, TextWriter.Null, CancellationToken.None));

        Assert.Contains(executor.RolledBack, action => action is StartAndVerifyWindowsService);
        Assert.Contains(executor.RolledBack, action => action is RegisterProductUninstall);
        Assert.Equal(
            executor.Applied.Take(executor.Applied.Count - 1).Reverse().Select(action => action.GetType()),
            executor.RolledBack.Select(action => action.GetType()));
        Assert.All(
            executor.RolledBackResults,
            rolledBack => Assert.Equal(
                plan.InstallInstanceId,
                Assert.IsType<ServiceConfiguration>(rolledBack.OwnershipConfiguration).InstallInstanceId));
    }

    [Fact]
    public async Task Rollback_owner_mismatch_overrides_the_triggering_failure_with_state_uncertain()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);
        var executor = new RecordingInstallActionExecutor
        {
            InteractiveSessionAvailable = true,
            FailAgentStart = true,
            FailRollbackOwnership = true,
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new InstallOrchestrator(executor, new FixedTokenGenerator(new byte[32]))
                .ExecuteAsync(plan, TextWriter.Null, CancellationToken.None));

        Assert.Equal("install_state_uncertain", failure.Code);
        Assert.NotEmpty(executor.RolledBackResults);
    }

    [Fact]
    public async Task Any_rollback_exception_marks_the_install_state_uncertain_and_continues_cleanup()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);
        var executor = new RecordingInstallActionExecutor
        {
            InteractiveSessionAvailable = true,
            FailAgentStart = true,
            FailFirstRollbackWithIoException = true,
        };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new InstallOrchestrator(executor, new FixedTokenGenerator(new byte[32]))
                .ExecuteAsync(plan, TextWriter.Null, CancellationToken.None));

        Assert.Equal("install_state_uncertain", failure.Code);
        Assert.Equal(executor.Applied.Count - 1, executor.RolledBack.Count);
    }

    [Fact]
    public async Task Windows_rollback_guard_rejects_owner_mismatch_before_any_mutation()
    {
        using var fixture = new InstallFixture();
        var runner = new RecordingWindowsCommandRunner();
        var runtime = new RecordingWindowsInstallStartupRuntime(interactiveSessionAvailable: true);
        var verifier = new RejectingRollbackOwnershipVerifier();
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            new MissingWindowsResourceLookup(),
            runtime,
            verifier);
        var action = new CreateWindowsService(
            "SimplySignAuto.Service",
            "LocalSystem",
            fixture.ExecutablePath,
            ["service"],
            true,
            [5, 15, 60],
            TestInstallOwnerMarker);
        var applied = new AppliedInstallAction(
            action,
            Created: true,
            RollbackState: null,
            fixture.ServiceConfiguration());

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            executor.RollbackAsync(applied, CancellationToken.None));

        Assert.Equal("install_state_uncertain", failure.Code);
        Assert.Single(verifier.Actions);
        Assert.Empty(runner.Calls);
        Assert.Empty(runtime.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Windows_startup_actions_use_exact_session_state_and_are_rollback_capable(
        bool interactiveSessionAvailable)
    {
        var runtime = new RecordingWindowsInstallStartupRuntime(interactiveSessionAvailable);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            new RecordingWindowsCommandRunner(),
            new MissingWindowsResourceLookup(),
            runtime,
            new AllowingRollbackOwnershipVerifier());
        var serviceAction = new StartAndVerifyWindowsService(
            "SimplySignAuto.Service",
            TestInstallOwnerMarker);
        var agentAction = new StartInteractiveAgentTask(
            "SimplySignAuto.Agent",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "otp.dat"),
            TestInstallOwnerMarker);

        var service = await executor.ApplyAsync(
            serviceAction,
            EmptyMaterial(),
            CancellationToken.None);
        var agent = await executor.ApplyAsync(
            agentAction,
            EmptyMaterial(),
            CancellationToken.None);
        await executor.RollbackAsync(agent, CancellationToken.None);
        await executor.RollbackAsync(service, CancellationToken.None);

        Assert.Equal(interactiveSessionAvailable, Assert.IsType<AgentTaskStartStatus>(agent.RollbackState).StartedForActiveSession);
        Assert.Equal(
            interactiveSessionAvailable
                ? [
                    "start-service",
                    $"session:{InstallFixture.SigningSid}",
                    "otp-metadata",
                    "start-task:running",
                    "stop-task",
                    "stop-service",
                ]
                : ["start-service", $"session:{InstallFixture.SigningSid}", "stop-service"],
            runtime.Calls);
    }

    [Fact]
    public async Task Active_session_without_otp_requires_trigger_proof_but_not_a_running_agent()
    {
        var runtime = new RecordingWindowsInstallStartupRuntime(
            interactiveSessionAvailable: true,
            otpConfigured: false);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            new RecordingWindowsCommandRunner(),
            new MissingWindowsResourceLookup(),
            runtime);
        var action = new StartInteractiveAgentTask(
            "SimplySignAuto.Agent",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "otp.dat"),
            TestInstallOwnerMarker);

        var applied = await executor.ApplyAsync(action, EmptyMaterial(), CancellationToken.None);

        var status = Assert.IsType<AgentTaskStartStatus>(applied.RollbackState);
        Assert.True(status.StartedForActiveSession);
        Assert.True(status.ActivationRequired);
        Assert.Equal(
            [$"session:{InstallFixture.SigningSid}", "otp-metadata", "start-task:trigger-only"],
            runtime.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Task_run_success_then_wait_or_cancellation_failure_stops_before_propagating(
        bool cancellationFailure)
    {
        var operations = new RecordingTaskLaunchOperations
        {
            WaitFailure = cancellationFailure
                ? new OperationCanceledException()
                : new InstallException("agent_start_failed"),
        };
        var runtime = new WindowsInstallStartupRuntime(operations);

        _ = await Assert.ThrowsAnyAsync<Exception>(() =>
            runtime.StartAndVerifyTaskAsync(
                "SimplySignAuto.Agent",
                requireRunning: true,
                CancellationToken.None));

        Assert.Equal(["read", "run", "wait", "stop"], operations.Calls);
    }

    [Theory]
    [InlineData("timeout")]
    [InlineData("cancel")]
    [InlineData("io")]
    public async Task Task_run_call_failure_always_stops_before_propagating(string failureKind)
    {
        var operations = new RecordingTaskLaunchOperations
        {
            RunFailure = failureKind switch
            {
                "timeout" => new InstallException("windows_process_timeout"),
                "cancel" => new OperationCanceledException(),
                "io" => new IOException("synthetic"),
                _ => throw new InvalidOperationException(),
            },
        };
        var runtime = new WindowsInstallStartupRuntime(operations);

        _ = await Assert.ThrowsAnyAsync<Exception>(() =>
            runtime.StartAndVerifyTaskAsync(
                "SimplySignAuto.Agent",
                requireRunning: true,
                CancellationToken.None));

        Assert.Equal(["read", "run", "stop"], operations.Calls);
    }

    [Fact]
    public async Task Task_run_compensation_failure_is_state_uncertain()
    {
        var operations = new RecordingTaskLaunchOperations
        {
            WaitFailure = new InstallException("agent_start_failed"),
            StopFailure = new InstallException("agent_stop_failed"),
        };
        var runtime = new WindowsInstallStartupRuntime(operations);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            runtime.StartAndVerifyTaskAsync(
                "SimplySignAuto.Agent",
                requireRunning: true,
                CancellationToken.None));

        Assert.Equal("install_state_uncertain", failure.Code);
        Assert.Equal(["read", "run", "wait", "stop"], operations.Calls);
    }

    [Fact]
    public async Task Registered_task_rollback_stops_and_confirms_before_delete()
    {
        var events = new List<string>();
        var lookup = new ReconciledWindowsResourceLookup
        {
            TaskPresent = true,
            ExactOwned = true,
            Events = events,
        };
        var runner = new OrderedTaskDeleteRunner(lookup, events);
        var runtime = new OrderedTaskStopRuntime(events);
        await new WindowsOwnedTaskRollback(runner, lookup, runtime)
            .ExecuteAsync("SimplySignAuto.Agent", CancellationToken.None);

        Assert.Equal(["stop-task", "delete-task", "query-missing"], events);
    }

    [Fact]
    public async Task Registered_service_rollback_stops_and_confirms_before_delete()
    {
        var events = new List<string>();
        var lookup = new ReconciledWindowsResourceLookup
        {
            ServicePresent = true,
            ExactOwned = true,
            Events = events,
        };
        var runner = new OrderedServiceDeleteRunner(lookup, events);
        var runtime = new OrderedServiceStopRuntime(events);

        await new WindowsOwnedServiceRollback(runner, lookup, runtime)
            .ExecuteAsync("SimplySignAuto.Service", CancellationToken.None);

        Assert.Equal(["stop-service", "delete-service", "query-service-missing"], events);
    }

    [Fact]
    public async Task Task_registration_verification_failure_stops_before_compensation_delete()
    {
        var events = new List<string>();
        var lookup = new ReconciledWindowsResourceLookup
        {
            TaskPresent = false,
            ExactOwned = true,
            Events = events,
        };
        var runner = new OrderedTaskDeleteRunner(lookup, events);
        var runtime = new OrderedTaskStopRuntime(events);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            lookup,
            runtime);
        var action = new CreateInteractiveLogonTask(
            "SimplySignAuto.Agent",
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["agent", "--background"],
            "InteractiveToken",
            true,
            true,
            TestInstallOwnerMarker);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateTaskRegistrationAsync(action, CancellationToken.None));

        Assert.Equal("task_registration_failed", failure.Code);
        Assert.Equal(
            ["query-missing", "create-task", "verify-task", "stop-task", "delete-task", "query-missing"],
            events);
    }

    [Fact]
    public async Task Task_registration_compensation_stop_failure_is_uncertain_and_never_deletes()
    {
        var events = new List<string>();
        var lookup = new ReconciledWindowsResourceLookup
        {
            TaskPresent = false,
            ExactOwned = true,
            Events = events,
        };
        var runner = new OrderedTaskDeleteRunner(lookup, events);
        var runtime = new OrderedTaskStopRuntime(events, failStop: true);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            lookup,
            runtime);
        var action = new CreateInteractiveLogonTask(
            "SimplySignAuto.Agent",
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["agent", "--background"],
            "InteractiveToken",
            true,
            true,
            TestInstallOwnerMarker);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateTaskRegistrationAsync(action, CancellationToken.None));

        Assert.Equal("install_state_uncertain", failure.Code);
        Assert.Contains("stop-task", events);
        Assert.DoesNotContain("delete-task", events);
    }

    [Fact]
    public void Service_recovery_contract_requires_exact_restart_sequence_count_reset_and_non_crash_flag()
    {
        var exact = new WindowsServiceRecoverySettings(
            ResetPeriodSeconds: 86400,
            [
                new WindowsServiceRecoveryAction(WindowsServiceRecoveryActionType.Restart, 5000),
                new WindowsServiceRecoveryAction(WindowsServiceRecoveryActionType.Restart, 15000),
                new WindowsServiceRecoveryAction(WindowsServiceRecoveryActionType.Restart, 60000),
            ],
            ApplyToNonCrashFailures: true);

        Assert.True(WindowsServiceRecoveryContract.IsExact(exact, [5, 15, 60]));
        Assert.False(WindowsServiceRecoveryContract.IsExact(exact with { ResetPeriodSeconds = 0 }, [5, 15, 60]));
        Assert.False(WindowsServiceRecoveryContract.IsExact(exact with { ApplyToNonCrashFailures = false }, [5, 15, 60]));
        Assert.False(WindowsServiceRecoveryContract.IsExact(exact with
        {
            Actions = [.. exact.Actions, new WindowsServiceRecoveryAction(WindowsServiceRecoveryActionType.Restart, 60000)],
        }, [5, 15, 60]));
        Assert.False(WindowsServiceRecoveryContract.IsExact(exact with
        {
            Actions =
            [
                exact.Actions[1],
                exact.Actions[0],
                exact.Actions[2],
            ],
        }, [5, 15, 60]));
        Assert.False(WindowsServiceRecoveryContract.IsExact(exact with
        {
            Actions =
            [
                new WindowsServiceRecoveryAction(WindowsServiceRecoveryActionType.None, 5000),
                exact.Actions[1],
                exact.Actions[2],
            ],
        }, [5, 15, 60]));
    }

    [Fact]
    public async Task Successful_install_writes_only_token_hash_to_service_config_and_displays_token_once()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);
        var executor = new RecordingInstallActionExecutor();
        using var output = new StringWriter();

        var result = await new InstallOrchestrator(
            executor,
            new FixedTokenGenerator(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray()))
            .ExecuteAsync(plan, output, CancellationToken.None);

        Assert.Equal(1, Count(output.ToString(), result.ApiToken));
        Assert.Equal(result.ApiToken + Environment.NewLine, Encoding.UTF8.GetString(
            executor.Files[plan.Paths.InstallTokenPath]));
        var service = JsonSerializer.Deserialize<ServiceConfiguration>(
            executor.Files[plan.Paths.ServiceConfigurationPath],
            JsonSerializerOptions.Web)!;
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(result.ApiToken))).ToLowerInvariant(),
            service.TokenHash);
        Assert.DoesNotContain(result.ApiToken, Encoding.UTF8.GetString(executor.Files[plan.Paths.ServiceConfigurationPath]), StringComparison.Ordinal);
        Assert.Contains(executor.Applied, action =>
            action is WriteProtectedFile { Path: var path, Acl: InstallAclProfile.AdministratorsOnly } &&
            path == plan.Paths.InstallTokenPath);
        Assert.True(
            executor.Applied.FindIndex(action => action is VerifyInstallSecurity) <
            executor.Applied.FindIndex(action => action is StartAndVerifyWindowsService));
    }

    [Fact]
    public async Task Acl_verification_failure_rolls_back_every_created_resource_in_reverse_order()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options with { OpenFirewall = true }, CancellationToken.None);
        var executor = new RecordingInstallActionExecutor { FailVerification = true };

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            new InstallOrchestrator(executor, new FixedTokenGenerator(new byte[32]))
                .ExecuteAsync(plan, TextWriter.Null, CancellationToken.None));

        Assert.Equal("acl_verification_failed", failure.Code);
        Assert.Equal(
            executor.Applied.Take(executor.Applied.Count - 1).Reverse().Select(action => action.GetType()),
            executor.RolledBack.Select(action => action.GetType()));
    }

    [Fact]
    public async Task Agent_sid_or_spool_outside_controlled_install_paths_is_rejected()
    {
        using var fixture = new InstallFixture();
        var configuration = fixture.Configuration with { SpoolPath = Path.Combine(fixture.Root, "other-spool") };
        await fixture.WriteAgentConfigurationAsync(configuration);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None));

        Assert.Equal("agent_configuration_mismatch", failure.Code);
    }

    [Fact]
    public async Task Install_rejects_secret_shaped_agent_values_before_any_write()
    {
        string[] secretShapes =
        [
            "otpauth://totp/Certum:test?secret=SYNTHETIC",
            "Authorization: synthetic-credential",
            "Bearer synthetic-credential",
            "/autologin 123456",
        ];
        foreach (var secretShape in secretShapes)
        {
            using var fixture = new InstallFixture();
            await fixture.WriteAgentConfigurationAsync(fixture.Configuration with { Pkcs11ModulePath = secretShape });
            var executor = new RecordingInstallActionExecutor();
            using var output = new StringWriter();
            using var error = new StringWriter();

            var exitCode = await InstallCommand.ExecuteAsync(
                fixture.Arguments,
                output,
                error,
                new RecordingInstallEnvironment(fixture),
                _ => executor,
                new FixedTokenGenerator(new byte[32]),
                CancellationToken.None);

            Assert.Equal(1, exitCode);
            Assert.Equal($"agent_configuration_invalid{Environment.NewLine}", error.ToString());
            Assert.Empty(executor.Applied);
            Assert.Equal(string.Empty, output.ToString());
            Assert.DoesNotContain(secretShape, output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(secretShape, error.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Default_uninstall_removes_owned_registrations_but_has_no_data_delete_action()
    {
        using var fixture = new InstallFixture();
        var configuration = fixture.ServiceConfiguration();
        var planner = new UninstallPlanner(new RecordingUninstallEnvironment(configuration));

        var plan = await planner.PlanAsync(new UninstallOptions(false, null), CancellationToken.None);

        Assert.Collection(
            plan.Actions,
            action => Assert.Equal(
                TestInstallOwnerMarker,
                Assert.IsType<RemoveOwnedFirewallRule>(action).OwnerMarker),
            action => Assert.Equal(
                TestInstallOwnerMarker,
                Assert.IsType<RemoveOwnedInteractiveLogonTask>(action).OwnerMarker),
            action => Assert.Equal(
                TestInstallOwnerMarker,
                Assert.IsType<RemoveOwnedWindowsService>(action).OwnerMarker),
            action => Assert.IsType<RemoveOwnedPdfExtension>(action));
        Assert.DoesNotContain(plan.Actions, action => action is PurgeControlledData);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("purge")]
    [InlineData(" PURGE")]
    public async Task Purge_requires_exact_confirmation(string? confirmation)
    {
        using var fixture = new InstallFixture();
        var planner = new UninstallPlanner(new RecordingUninstallEnvironment(fixture.ServiceConfiguration()));

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            planner.PlanAsync(new UninstallOptions(true, confirmation), CancellationToken.None));

        Assert.Equal("purge_confirmation_required", failure.Code);
    }

    [Fact]
    public async Task Native_resource_preflight_failure_never_invokes_create_or_delete()
    {
        var runner = new RecordingWindowsCommandRunner();
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            new ThrowingWindowsResourceLookup());
        var service = new CreateWindowsService(
            "external-service",
            "LocalSystem",
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["service"],
            true,
            [5, 15, 60],
            "SimplySignAuto/v1");

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateServiceRegistrationAsync(service, CancellationToken.None));

        Assert.Equal("resource_preflight_failed", failure.Code);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Windows_service_registration_uses_non_delayed_automatic_start()
    {
        var runner = new RecordingWindowsCommandRunner();
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            new MissingWindowsResourceLookup());
        var service = new CreateWindowsService(
            "SimplySignAuto.Service",
            "LocalSystem",
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["service"],
            AutomaticDelayedStart: false,
            [5, 15, 60],
            TestInstallOwnerMarker);

        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateServiceRegistrationAsync(service, CancellationToken.None));

        var create = Assert.Single(runner.Calls, call =>
            call.Arguments.Contains("create", StringComparer.OrdinalIgnoreCase));
        Assert.Contains("auto", create.Arguments, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("delayed-auto", create.Arguments, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Windows_service_ownership_verification_uses_the_installed_non_delayed_start_policy()
    {
        using var fixture = new InstallFixture();
        var configuration = fixture.ServiceConfiguration();
        var marker = InstallOwnershipMarker.Create(configuration.InstallInstanceId);

        var expected = WindowsInstallRollbackOwnershipVerifier.CreateExpectedService(
            new StartAndVerifyWindowsService("SimplySignAuto.Service", marker),
            configuration,
            marker);

        Assert.False(expected.AutomaticDelayedStart);
        Assert.Equal(configuration.ExecutablePath, expected.ExecutablePath);
        Assert.Equal(marker, expected.OwnerMarker);
    }

    [Fact]
    public async Task Windows_desktop_shortcut_is_verified_and_exact_owned_rollback_removes_it()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Shortcut.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var target = Path.Combine(root, "SimplySignAuto.exe");
        var shortcutPath = Path.Combine(root, "SimplySignAuto.lnk");
        await File.WriteAllBytesAsync(target, [0x4d, 0x5a]);
        var action = new CreateDesktopShortcut(
            shortcutPath,
            target,
            TestInstallOwnerMarker);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            new RecordingWindowsCommandRunner(),
            new MissingWindowsResourceLookup());

        try
        {
            await File.WriteAllBytesAsync(shortcutPath, [0x01, 0x02, 0x03]);
            var collision = await Assert.ThrowsAsync<InstallException>(() =>
                executor.ApplyAsync(action, EmptyMaterial(), CancellationToken.None));
            Assert.Equal("install_resource_exists", collision.Code);
            Assert.Equal([0x01, 0x02, 0x03], await File.ReadAllBytesAsync(shortcutPath));
            File.Delete(shortcutPath);

            var applied = await executor.ApplyAsync(action, EmptyMaterial(), CancellationToken.None);

            Assert.True(applied.Created);
            Assert.True(WindowsDesktopShortcut.IsExact(action));

            await executor.RollbackAsync(applied, CancellationToken.None);
            Assert.False(File.Exists(shortcutPath));
        }
        finally
        {
            if (File.Exists(shortcutPath))
            {
                File.Delete(shortcutPath);
            }
            if (File.Exists(target))
            {
                File.Delete(target);
            }
            if (Directory.Exists(root))
            {
                Directory.Delete(root);
            }
        }
    }

    [Fact]
    public async Task Failed_native_create_never_compensates_by_deleting_an_unowned_name()
    {
        var runner = new RecordingWindowsCommandRunner { FailChecked = true };
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            new MissingWindowsResourceLookup());
        var service = new CreateWindowsService(
            "raced-service",
            "LocalSystem",
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["service"],
            true,
            [5, 15, 60],
            "SimplySignAuto/v1");
        var task = new CreateInteractiveLogonTask(
            "raced-task",
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["agent", "--background"],
            "InteractiveToken",
            true,
            true,
            TestInstallOwnerMarker);

        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateServiceRegistrationAsync(service, CancellationToken.None));
        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateTaskRegistrationAsync(task, CancellationToken.None));

        Assert.DoesNotContain(runner.Calls, call => call.Arguments.Contains("delete", StringComparer.OrdinalIgnoreCase));
        Assert.DoesNotContain(runner.Calls, call => call.Arguments.Contains("/Delete", StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Timed_out_create_reconciles_and_removes_an_exact_resource_registered_before_failure()
    {
        var lookup = new ReconciledWindowsResourceLookup { ExactOwned = true };
        var runner = new TimeoutAfterRegistrationRunner(lookup);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            lookup,
            new RecordingWindowsInstallStartupRuntime(interactiveSessionAvailable: true));
        var service = new CreateWindowsService(
            "timed-out-service",
            "LocalSystem",
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["service"],
            true,
            [5, 15, 60],
            "SimplySignAuto/v1");
        var task = new CreateInteractiveLogonTask(
            "timed-out-task",
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["agent", "--background"],
            "InteractiveToken",
            true,
            true,
            TestInstallOwnerMarker);

        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateServiceRegistrationAsync(service, CancellationToken.None));
        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateTaskRegistrationAsync(task, CancellationToken.None));

        Assert.False(lookup.ServicePresent);
        Assert.False(lookup.TaskPresent);
        Assert.Contains(runner.Calls, call => call.Arguments.Contains("delete", StringComparer.OrdinalIgnoreCase));
        Assert.Contains(runner.Calls, call => call.Arguments.Contains("/Delete", StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Timed_out_create_never_deletes_a_racing_external_resource()
    {
        var lookup = new ReconciledWindowsResourceLookup { ExactOwned = false };
        var runner = new TimeoutAfterRegistrationRunner(lookup);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            lookup);
        var service = new CreateWindowsService(
            "external-service",
            "LocalSystem",
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["service"],
            true,
            [5, 15, 60],
            "SimplySignAuto/v1");
        var task = new CreateInteractiveLogonTask(
            "external-task",
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["agent", "--background"],
            "InteractiveToken",
            true,
            true,
            TestInstallOwnerMarker);

        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateServiceRegistrationAsync(service, CancellationToken.None));
        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateTaskRegistrationAsync(task, CancellationToken.None));

        Assert.True(lookup.ServicePresent);
        Assert.True(lookup.TaskPresent);
        Assert.DoesNotContain(runner.Calls, call => call.Arguments.Contains("delete", StringComparer.OrdinalIgnoreCase));
        Assert.DoesNotContain(runner.Calls, call => call.Arguments.Contains("/Delete", StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Post_create_failure_never_deletes_a_resource_that_no_longer_matches_the_install_owner()
    {
        var lookup = new ReconciledWindowsResourceLookup { ExactOwned = false };
        var runner = new FailureAfterSuccessfulCreateRunner(lookup);
        var executor = new WindowsInstallActionExecutor(
            InstallFixture.SigningSid,
            runner,
            lookup);
        var service = new CreateWindowsService(
            "replaced-service",
            "LocalSystem",
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["service"],
            true,
            [5, 15, 60],
            "SimplySignAuto/v1");
        var task = new CreateInteractiveLogonTask(
            "replaced-task",
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["agent", "--background"],
            "InteractiveToken",
            true,
            true,
            TestInstallOwnerMarker);

        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateServiceRegistrationAsync(service, CancellationToken.None));
        await Assert.ThrowsAsync<InstallException>(() =>
            executor.CreateTaskRegistrationAsync(task, CancellationToken.None));

        Assert.True(lookup.ServicePresent);
        Assert.True(lookup.TaskPresent);
        Assert.DoesNotContain(runner.Calls, call => call.Arguments.Contains("delete", StringComparer.OrdinalIgnoreCase));
        Assert.DoesNotContain(runner.Calls, call => call.Arguments.Contains("/Delete", StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Process_timeout_kills_and_joins_the_process_tree_with_bounded_output_drain()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var elapsed = Stopwatch.StartNew();
        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            WindowsProcess.RunIgnoreExitCodeAsync(
                "/bin/sh",
                ["-c", "printf started; sleep 30"],
                TimeSpan.FromMilliseconds(100),
                CancellationToken.None));

        Assert.Equal("windows_process_timeout", failure.Code);
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Install_acl_owner_contract_uses_administrators_without_requiring_restore_privilege()
    {
        var security = WindowsInstallAcl.CreateFileSecurity(
            InstallAclProfile.AdministratorsOnly,
            new SecurityIdentifier(InstallFixture.SigningSid));
        var owner = Assert.IsType<SecurityIdentifier>(
            security.GetOwner(typeof(SecurityIdentifier)));

        Assert.Equal("S-1-5-32-544", owner.Value);
        Assert.True(WindowsInstallAcl.IsExpectedOwner("S-1-5-32-544"));
        Assert.True(WindowsInstallAcl.IsExpectedOwner("S-1-5-18"));
        Assert.False(WindowsInstallAcl.IsExpectedOwner(InstallFixture.SigningSid));
        Assert.False(WindowsInstallAcl.IsExpectedOwner(null));
    }

    [WindowsAdministratorFact]
    public void Windows_install_acl_rejects_a_correct_dacl_owned_by_the_signing_user()
    {
        var root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Install.Owner", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "service.json");
        File.WriteAllText(path, "{}");
        var signingUser = WindowsIdentity.GetCurrent().User!;
        try
        {
            WindowsInstallAcl.ApplyFile(path, InstallAclProfile.AdministratorsOnly, signingUser);
            var security = new FileInfo(path).GetAccessControl();
            security.SetOwner(signingUser);
            new FileInfo(path).SetAccessControl(security);

            var failure = Assert.Throws<InstallException>(() =>
                WindowsInstallAcl.VerifyFile(path, InstallAclProfile.AdministratorsOnly, signingUser));

            Assert.Equal("acl_verification_failed", failure.Code);
        }
        finally
        {
            File.Delete(path);
            Directory.Delete(root);
        }
    }

    [WindowsAdministratorFact]
    public void Installed_spool_acl_remains_valid_after_the_service_protects_its_root()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.SpoolAcl.Contract",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var signingUser = WindowsIdentity.GetCurrent().User!;
        try
        {
            WindowsInstallAcl.ApplyDirectory(
                root,
                InstallAclProfile.SigningUserRead,
                signingUser);
            new WindowsSpoolAclPolicy(signingUser.Value).ProtectRoot(root);

            WindowsInstallAcl.VerifyDirectory(
                root,
                InstallAclProfile.SigningUserRead,
                signingUser);
        }
        finally
        {
            Directory.Delete(root);
        }
    }

    [WindowsAdministratorFact]
    public async Task Setup_tools_acl_snapshot_is_accepted_by_the_optional_tool_resolver_security_contract()
    {
        using var fixture = new InstallFixture();
        var plan = await fixture.CreatePlanner().PlanAsync(fixture.Options, CancellationToken.None);
        var toolsAction = Assert.Single(plan.Actions.OfType<CreateProtectedDirectory>(), action =>
            string.Equals(action.Path, plan.Paths.ToolsRoot, StringComparison.OrdinalIgnoreCase));
        var root = Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.OptionalToolsAcl.Contract",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var signingUser = new SecurityIdentifier(InstallFixture.SigningSid);
        try
        {
            WindowsInstallAcl.ApplyDirectory(root, toolsAction.Acl, signingUser);

            WindowsExecutableSecurity.VerifyEntry(
                WindowsNoFollowSecurity.ReadDirectory(root),
                signingUser.Value,
                requireReadExecute: true);
        }
        finally
        {
            Directory.Delete(root);
        }
    }

    [Fact]
    public void Task_ownership_requires_trigger_and_principal_sid_to_match_independently()
    {
        var task = new CreateInteractiveLogonTask(
            "owned-task",
            "TEST\\signer",
            InstallFixture.SigningSid,
            Path.Combine(Path.GetTempPath(), "SimplySignAuto.exe"),
            ["agent", "--background"],
            "InteractiveToken",
            true,
            true,
            TestInstallOwnerMarker);
        var taskNamespace = (XNamespace)"http://schemas.microsoft.com/windows/2004/02/mit/task";
        var original = XDocument.Parse(WindowsTaskXml.Create(task));

        var wrongPrincipal = new XDocument(original);
        wrongPrincipal.Descendants(taskNamespace + "Principal").Single()
            .Element(taskNamespace + "UserId")!.Value = "S-1-5-21-1000-2000-3000-4001";
        Assert.False(WindowsTaskXml.IsOwned(
            wrongPrincipal.ToString(SaveOptions.DisableFormatting),
            task.SigningUserSid,
            task.ExecutablePath,
            task.OwnerMarker));

        var wrongTrigger = new XDocument(original);
        wrongTrigger.Descendants(taskNamespace + "LogonTrigger").Single()
            .Element(taskNamespace + "UserId")!.Value = "S-1-5-21-1000-2000-3000-4001";
        Assert.False(WindowsTaskXml.IsOwned(
            wrongTrigger.ToString(SaveOptions.DisableFormatting),
            task.SigningUserSid,
            task.ExecutablePath,
            task.OwnerMarker));
    }

    [WindowsAdministratorFact]
    public async Task Windows_executor_creates_verifies_and_rolls_back_temporary_native_resources()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Install.Native", suffix);
        var executable = Environment.ProcessPath!;
        var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User!.Value;
        var account = identity.Name;
        var executor = new WindowsInstallActionExecutor(
            sid,
            new DefaultWindowsCommandRunner(),
            new WindowsInstallResourceLookup(),
            new WindowsInstallStartupRuntime(),
            new AllowingRollbackOwnershipVerifier());
        var material = new InstallExecutionMaterial("{}"u8.ToArray(), "{}"u8.ToArray(), "token\n"u8.ToArray());
        var actions = new InstallAction[]
        {
            new CreateProtectedDirectory(root, InstallAclProfile.AdministratorsOnly),
            new WriteProtectedFile(Path.Combine(root, "install-token.txt"), InstallAclProfile.AdministratorsOnly, InstallContent.InstallToken),
            new CreateWindowsService($"SimplySignAuto.Install.{suffix}", "LocalSystem", executable, ["service"], true, [5, 15, 60], TestInstallOwnerMarker),
            new CreateInteractiveLogonTask($"SimplySignAuto.Install.{suffix}", account, sid, executable, ["agent", "--background"], "InteractiveToken", true, true, TestInstallOwnerMarker),
            new CreateOwnedFirewallRule($"SimplySignAuto Install {suffix}", TestInstallOwnerMarker, 47443),
        };
        var applied = new List<AppliedInstallAction>();
        try
        {
            foreach (var action in actions)
            {
                applied.Add(await executor.ApplyAsync(action, material, CancellationToken.None));
            }

            Assert.Equal(actions.Length, applied.Count);
        }
        finally
        {
            foreach (var action in applied.AsEnumerable().Reverse())
            {
                await executor.RollbackAsync(action, CancellationToken.None);
            }
        }
    }

    [WindowsAdministratorFact]
    public void Windows_product_registration_is_exact_collision_safe_and_removable()
    {
        using (var existing = Registry.LocalMachine.OpenSubKey(
                   WindowsProductUninstallRegistry.KeyPath,
                   writable: false))
        {
            Assert.Null(existing);
        }

        var registration = ProductUninstallRegistration.Create(
            Environment.ProcessPath!,
            "0.0.0-test.3",
            TestInstallOwnerMarker);
        var owned = false;
        try
        {
            WindowsProductUninstallRegistry.Create(registration);
            owned = true;
            WindowsProductUninstallRegistry.Verify(registration, "owned_resource_mismatch");

            var collision = Assert.Throws<InstallException>(() =>
                WindowsProductUninstallRegistry.Create(registration));

            Assert.Equal("resource_preflight_failed", collision.Code);
            WindowsProductUninstallRegistry.Verify(registration, "owned_resource_mismatch");

            using (var key = Registry.LocalMachine.OpenSubKey(
                       WindowsProductUninstallRegistry.KeyPath,
                       writable: true)!)
            {
                key.SetValue(
                    WindowsInstallResourceLookup.InstallOwnerValueName,
                    "SimplySignAuto/v1/ffffffffffffffffffffffffffffffff",
                    RegistryValueKind.String);
            }

            var mismatch = Assert.Throws<InstallException>(() =>
                WindowsProductUninstallRegistry.Verify(registration, "owned_resource_mismatch"));
            Assert.Equal("owned_resource_mismatch", mismatch.Code);
            var blockedRemoval = Assert.Throws<InstallException>(() =>
                WindowsProductUninstallRegistry.Remove(registration));
            Assert.Equal("uninstall_state_uncertain", blockedRemoval.Code);
            using (var key = Registry.LocalMachine.OpenSubKey(
                       WindowsProductUninstallRegistry.KeyPath,
                       writable: true)!)
            {
                key.SetValue(
                    WindowsInstallResourceLookup.InstallOwnerValueName,
                    registration.OwnerMarker,
                    RegistryValueKind.String);
            }

            WindowsProductUninstallRegistry.Remove(registration);
            owned = false;
            using var removed = Registry.LocalMachine.OpenSubKey(
                WindowsProductUninstallRegistry.KeyPath,
                writable: false);
            Assert.Null(removed);
        }
        finally
        {
            if (owned)
            {
                WindowsProductUninstallRegistry.Rollback(registration);
            }
        }
    }

    private static int Count(string value, string needle) =>
        (value.Length - value.Replace(needle, string.Empty, StringComparison.Ordinal).Length) / needle.Length;

    private static InstallExecutionMaterial EmptyMaterial() => new([], [], []);

    private sealed class FixedTokenGenerator(byte[] bytes) : IApiTokenGenerator
    {
        public byte[] Generate() => bytes.ToArray();
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null &&
            !File.Exists(Path.Combine(current.FullName, "SimplySignAuto.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new InvalidOperationException("repository_root_not_found");
    }

    public enum SetupPreflightFailure
    {
        None,
        NotWindowsServer2025,
        NotAdministrator,
        DomainController,
        DesktopMissing,
        Pkcs11Missing,
        InstallResourceConflict,
    }

    private sealed class RecordingSetupPreflight(List<string> events) : ISetupPreflight
    {
        public SetupPreflightFailure Failure { get; init; }

        public Task<SetupPreflightResult> InspectAsync(string userName, CancellationToken cancellationToken)
        {
            events.Add("preflight");
            if (Failure != SetupPreflightFailure.None)
            {
                return Task.FromException<SetupPreflightResult>(new SetupException(Failure switch
                {
                    SetupPreflightFailure.NotWindowsServer2025 => "windows_server_2025_required",
                    SetupPreflightFailure.NotAdministrator => "administrator_required",
                    SetupPreflightFailure.DomainController => "domain_controller_unsupported",
                    SetupPreflightFailure.DesktopMissing => "simplysign_desktop_missing",
                    SetupPreflightFailure.Pkcs11Missing => "simplysign_pkcs11_missing",
                    SetupPreflightFailure.InstallResourceConflict => "setup_resource_conflict",
                    _ => throw new InvalidOperationException(),
                }));
            }

            return Task.FromResult(new SetupPreflightResult(
                @"C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe",
                @"C:\Windows\System32\SimplySignPKCS.dll",
                null));
        }
    }

    private sealed class RecordingInstallMediaStager(List<string> events) : IInstallMediaStager
    {
        private bool _stageAttempted;

        public Exception? PlanFailure { get; init; }

        public Exception? StageFailure { get; init; }

        public Exception? AuthorizeFailure { get; init; }

        public Exception? RollbackFailure { get; init; }

        public List<string> Mutations { get; } = [];

        public string? AuthorizedSid { get; private set; }

        public Task<InstallMediaPlan> PlanAsync(CancellationToken cancellationToken)
        {
            events.Add("media-plan");
            if (PlanFailure is not null)
            {
                return Task.FromException<InstallMediaPlan>(PlanFailure);
            }

            return Task.FromResult(new InstallMediaPlan(
                @"D:\release",
                @"C:\Program Files\SimplySignAuto.part-test",
                @"C:\Program Files\SimplySignAuto",
                @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
                new string('A', 40),
                4096,
                [
                    new InstallMediaFilePlan(
                        "SimplySignAuto.exe",
                        @"D:\release\SimplySignAuto.exe",
                        @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
                        4096,
                        new string('b', 64)),
                ]));
        }

        public Task StageAsync(InstallMediaPlan plan, CancellationToken cancellationToken)
        {
            events.Add("media-stage");
            _stageAttempted = true;
            Mutations.Add("media-stage");
            return StageFailure is null ? Task.CompletedTask : Task.FromException(StageFailure);
        }

        public Task AuthorizeAsync(
            InstallMediaPlan plan,
            string signingUserSid,
            CancellationToken cancellationToken)
        {
            events.Add($"media-authorize:{signingUserSid}");
            Mutations.Add("media-authorize");
            AuthorizedSid = signingUserSid;
            return AuthorizeFailure is null ? Task.CompletedTask : Task.FromException(AuthorizeFailure);
        }

        public Task RollbackAsync(InstallMediaPlan plan)
        {
            events.Add("media-rollback");
            if (_stageAttempted)
            {
                Mutations.Add("media-rollback");
            }

            return RollbackFailure is null ? Task.CompletedTask : Task.FromException(RollbackFailure);
        }
    }

    private sealed class RecordingInstallMediaVerifier : IInstallMediaVerifier
    {
        public List<string> VerifiedRoots { get; } = [];

        public string VerifyInitialPublisher(string executablePath, string scriptPath)
        {
            Assert.EndsWith("SimplySignAuto.exe", executablePath, StringComparison.OrdinalIgnoreCase);
            Assert.EndsWith("install-prerequisites.ps1", scriptPath, StringComparison.OrdinalIgnoreCase);
            return new string('A', 40);
        }

        public Task VerifyMediaAsync(
            string root,
            string expectedPublisherIdentity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(new string('A', 40), expectedPublisherIdentity);
            VerifiedRoots.Add(root);
            return Task.CompletedTask;
        }
    }

    private sealed class ExclusiveCatalogInstallMediaVerifier : IInstallMediaVerifier
    {
        public int VerifyMediaCalls { get; private set; }

        public string VerifyInitialPublisher(string executablePath, string scriptPath) =>
            new('A', 40);

        public Task VerifyMediaAsync(
            string root,
            string expectedPublisherIdentity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            VerifyMediaCalls++;
            foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
                Assert.True(stream.Length >= 0);
            }

            return Task.CompletedTask;
        }
    }

    private sealed class MutatingCatalogInstallMediaVerifier(string path) : IInstallMediaVerifier
    {
        public string VerifyInitialPublisher(string executablePath, string scriptPath) =>
            new('A', 40);

        public Task VerifyMediaAsync(
            string root,
            string expectedPublisherIdentity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            File.WriteAllText(path, "changed during catalog verification");
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingAuthenticodeSignatureReader(
        IReadOnlyList<string> executableSigners,
        IReadOnlyList<string> scriptSigners) : IAuthenticodeSignatureReader
    {
        public List<string> ReadPaths { get; } = [];

        public IReadOnlyList<string> ExecutableSigners { get; set; } = executableSigners;

        public IReadOnlyList<string> ScriptSigners { get; set; } = scriptSigners;

        public IReadOnlyList<string> ReadSignerThumbprints(string signedFilePath)
        {
            ReadPaths.Add(signedFilePath);
            return signedFilePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? ExecutableSigners
                : ScriptSigners;
        }
    }

    private sealed class FailingCreatedDirectoryReadbackOperations : IAtomicProtectedDirectoryOperations
    {
        private readonly WindowsAtomicProtectedDirectoryOperations _inner = new();

        public void VerifyTrustedAnchor(string path) => _inner.VerifyTrustedAnchor(path);

        public bool EntryExistsNoFollow(string path) => _inner.EntryExistsNoFollow(path);

        public void CreateNewWithSecurity(string path) => _inner.CreateNewWithSecurity(path);

        public void VerifyCreated(string path)
        {
            _inner.VerifyCreated(path);
            throw new InstallException("injected_created_readback_failure");
        }
    }

    private sealed class WindowsInstallMediaFixture : IDisposable
    {
        private WindowsInstallMediaFixture(string sourceRoot, string programFilesRoot)
        {
            SourceRoot = sourceRoot;
            ProgramFilesRoot = programFilesRoot;
        }

        public string SourceRoot { get; }

        public string ProgramFilesRoot { get; }

        public static WindowsInstallMediaFixture Create()
        {
            var suffix = Guid.NewGuid().ToString("N");
            var source = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Media.Source", suffix);
            var programFiles = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SimplySignAuto.Media.ProgramFiles." + suffix);
            Directory.CreateDirectory(Path.Combine(source, "docs"));
            File.WriteAllBytes(Path.Combine(source, "SimplySignAuto.exe"), "signed-exe"u8.ToArray());
            File.WriteAllText(
                Path.Combine(source, "install-prerequisites.ps1"),
                "# signed prerequisite verifier");
            File.WriteAllBytes(Path.Combine(source, "release-files.cat"), "signed-catalog"u8.ToArray());
            File.WriteAllText(Path.Combine(source, "docs", "readme.txt"), "documentation");

            Directory.CreateDirectory(programFiles);
            WindowsInstallAcl.ApplyDirectory(
                programFiles,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            WindowsInstallAcl.VerifyDirectory(
                programFiles,
                InstallAclProfile.AdministratorsOnly,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            return new WindowsInstallMediaFixture(source, programFiles);
        }

        public void Dispose()
        {
            if (Directory.Exists(SourceRoot))
            {
                Directory.Delete(SourceRoot, recursive: true);
            }

            if (Directory.Exists(ProgramFilesRoot))
            {
                Directory.Delete(ProgramFilesRoot, recursive: true);
            }
        }
    }

    private sealed class RecordingSetupProvisioner(List<string> events) : ISetupProvisioner
    {
        public Exception? ProvisionFailure { get; init; }

        public Exception? RollbackFailure { get; init; }

        public List<string> Mutations { get; } = [];

        public string? RequestedUserName { get; private set; }

        public async Task<ProvisionedAgentUser> ProvisionAsync(
            string userName,
            Func<ProvisionedAgentUser, CancellationToken, Task> afterUserCreated,
            CancellationToken cancellationToken)
        {
            RequestedUserName = userName;
            events.Add("create-user");
            Mutations.Add("create-user");
            var user = new ProvisionedAgentUser(
                "TEST\\SimplySignAgent",
                InstallFixture.SigningSid,
                "TEST",
                @"C:\Users\SimplySignAgent",
                TestInstallOwnerMarker);
            await afterUserCreated(user, cancellationToken);
            if (ProvisionFailure is not null)
            {
                throw ProvisionFailure;
            }

            events.Add("create-profile");
            Mutations.Add("create-profile");
            return user;
        }

        public Task RollbackAsync(ProvisionedAgentUser user)
        {
            events.Add("rollback-provision");
            Mutations.Add("rollback-provision");
            return RollbackFailure is null
                ? Task.CompletedTask
                : Task.FromException(RollbackFailure);
        }
    }

    private sealed class RecordingSetupResourceReservation(List<string> events) : ISetupResourceReservation
    {
        public Exception? Failure { get; init; }

        public List<string> Mutations { get; } = [];

        public string Reserve()
        {
            events.Add("reserve");
            if (Failure is not null)
            {
                throw Failure;
            }

            Mutations.Add("reserve");
            return @"C:\ProgramData\SimplySignAuto";
        }

        public Task RollbackAsync(string dataRoot)
        {
            events.Add("rollback-reserve");
            Mutations.Add("rollback-reserve");
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingSetupConfigurationWriter(List<string> events) : ISetupConfigurationWriter
    {
        public string GeneratedPath { get; } = Path.Combine(Path.GetTempPath(), "setup-agent.json");

        public List<string> Mutations { get; } = [];

        public Task<SetupGeneratedConfiguration> WriteAsync(
            ProvisionedAgentUser user,
            SetupPreflightResult preflight,
            CancellationToken cancellationToken)
        {
            events.Add("write-config");
            Mutations.Add("write-config");
            return Task.FromResult(new SetupGeneratedConfiguration(
                GeneratedPath,
                SetupAgentConfigurationFactory.Create(user, preflight, @"C:\ProgramData")));
        }

        public Task DeleteAsync(SetupGeneratedConfiguration configuration)
        {
            events.Add("delete-config");
            Mutations.Add("delete-config");
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingSetupInstaller(List<string> events) : ISetupInstaller
    {
        public Exception? Failure { get; init; }

        public List<string> Mutations { get; } = [];

        public string? SigningUser { get; private set; }

        public string? AgentConfigurationPath { get; private set; }

        public Task InstallAsync(
            ProvisionedAgentUser user,
            SetupGeneratedConfiguration configuration,
            TextWriter output,
            CancellationToken cancellationToken)
        {
            events.Add("install");
            Mutations.Add("install");
            SigningUser = user.AccountName;
            AgentConfigurationPath = configuration.Path;
            return Failure is null ? Task.CompletedTask : Task.FromException(Failure);
        }
    }

    private sealed class RecordingInstallActionExecutor : IInstallActionExecutor
    {
        public List<InstallAction> Applied { get; } = [];
        public List<InstallAction> RolledBack { get; } = [];
        public List<AppliedInstallAction> RolledBackResults { get; } = [];
        public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
        public Dictionary<InstallAction, AppliedInstallAction> Results { get; } = [];
        public bool FailVerification { get; init; }
        public bool InteractiveSessionAvailable { get; init; }
        public bool OtpConfigured { get; init; } = true;
        public bool FailAgentStart { get; init; }
        public bool FailRollbackOwnership { get; init; }
        public bool FailFirstRollbackWithIoException { get; init; }

        public Task<AppliedInstallAction> ApplyAsync(
            InstallAction action,
            InstallExecutionMaterial material,
            CancellationToken cancellationToken)
        {
            Applied.Add(action);
            if (action is WriteProtectedFile file)
            {
                Files[file.Path] = material.GetFile(file.Content);
            }

            if (FailVerification && action is VerifyInstallSecurity)
            {
                throw new InstallException("acl_verification_failed");
            }

            if (FailAgentStart && action is StartInteractiveAgentTask)
            {
                throw new InstallException("agent_start_failed");
            }

            if (action is StartInteractiveAgentTask)
            {
                var applied = new AppliedInstallAction(
                    action,
                    Created: false,
                    new AgentTaskStartStatus(
                        InteractiveSessionAvailable,
                        InteractiveSessionAvailable && !OtpConfigured));
                Results[action] = applied;
                return Task.FromResult(applied);
            }

            var result = new AppliedInstallAction(action, Created: true, RollbackState: null);
            Results[action] = result;
            return Task.FromResult(result);
        }

        public Task RollbackAsync(AppliedInstallAction applied, CancellationToken cancellationToken)
        {
            RolledBack.Add(applied.Action);
            RolledBackResults.Add(applied);
            if (FailFirstRollbackWithIoException && RolledBack.Count == 1)
            {
                throw new IOException("rollback blocked");
            }

            if (FailRollbackOwnership)
            {
                throw new InstallException("install_state_uncertain");
            }

            return Task.CompletedTask;
        }
    }

    private sealed class RecordingUninstallElevationLauncher(int exitCode)
        : IUninstallElevationLauncher
    {
        public string? ExecutablePath { get; private set; }

        public IReadOnlyList<string>? Arguments { get; private set; }

        public string? Verb { get; private set; }

        public bool WaitForExit { get; private set; }

        public int LaunchAndWait(
            string executablePath,
            IReadOnlyList<string> arguments,
            string verb)
        {
            ExecutablePath = executablePath;
            Arguments = arguments;
            Verb = verb;
            WaitForExit = true;
            return exitCode;
        }
    }

    private sealed class RejectingRollbackOwnershipVerifier : IWindowsInstallRollbackOwnershipVerifier
    {
        public List<InstallAction> Actions { get; } = [];

        public Task VerifyAsync(AppliedInstallAction applied, CancellationToken cancellationToken)
        {
            Actions.Add(applied.Action);
            throw new InstallException("install_state_uncertain");
        }
    }

    private sealed class AllowingRollbackOwnershipVerifier : IWindowsInstallRollbackOwnershipVerifier
    {
        public Task VerifyAsync(AppliedInstallAction applied, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class RecordingTaskLaunchOperations : IWindowsTaskLaunchOperations
    {
        public List<string> Calls { get; } = [];
        public Exception? RunFailure { get; init; }
        public Exception? WaitFailure { get; init; }
        public Exception? StopFailure { get; init; }

        public WindowsTaskRunState ReadState(string name)
        {
            Calls.Add("read");
            return new WindowsTaskRunState(false, DateTime.MinValue);
        }

        public Task RunAsync(string name, CancellationToken cancellationToken)
        {
            Calls.Add("run");
            return RunFailure is null ? Task.CompletedTask : Task.FromException(RunFailure);
        }

        public Task WaitForTriggeredAsync(
            string name,
            WindowsTaskRunState before,
            bool requireRunning,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls.Add("wait");
            return WaitFailure is null ? Task.CompletedTask : Task.FromException(WaitFailure);
        }

        public Task StopAndWaitAsync(string name, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add("stop");
            return StopFailure is null ? Task.CompletedTask : Task.FromException(StopFailure);
        }
    }

    private sealed class OrderedTaskStopRuntime(
        List<string> events,
        bool failStop = false) : IWindowsInstallStartupRuntime
    {
        public Task StartAndVerifyServiceAsync(string name, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task StopServiceAsync(string name, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public bool HasInteractiveSession(string signingUserSid) => throw new NotSupportedException();

        public bool IsOtpConfiguredForSigningUser(string path, string signingUserSid) =>
            throw new NotSupportedException();

        public Task StartAndVerifyTaskAsync(
            string name,
            bool requireRunning,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task StopTaskAsync(string name, CancellationToken cancellationToken)
        {
            events.Add("stop-task");
            return failStop
                ? Task.FromException(new InstallException("agent_stop_failed"))
                : Task.CompletedTask;
        }
    }

    private sealed class OrderedTaskDeleteRunner(
        ReconciledWindowsResourceLookup lookup,
        List<string> events) : IWindowsCommandRunner
    {
        public Task<WindowsProcessResult> RunCheckedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            string errorCode,
            CancellationToken cancellationToken)
        {
            if (arguments.Contains("/Create", StringComparer.OrdinalIgnoreCase))
            {
                events.Add("create-task");
                lookup.TaskPresent = true;
                return Task.FromResult(new WindowsProcessResult(0, string.Empty));
            }

            if (arguments.Contains("/Query", StringComparer.OrdinalIgnoreCase))
            {
                events.Add("verify-task");
                throw new InstallException("task_registration_failed");
            }

            if (arguments.Contains("/Delete", StringComparer.OrdinalIgnoreCase))
            {
                events.Add("delete-task");
                lookup.TaskPresent = false;
            }

            return Task.FromResult(new WindowsProcessResult(0, string.Empty));
        }

        public Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class OrderedServiceStopRuntime(List<string> events) : IWindowsInstallStartupRuntime
    {
        public Task StartAndVerifyServiceAsync(string name, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task StopServiceAsync(string name, CancellationToken cancellationToken)
        {
            events.Add("stop-service");
            return Task.CompletedTask;
        }

        public bool HasInteractiveSession(string signingUserSid) => throw new NotSupportedException();

        public bool IsOtpConfiguredForSigningUser(string path, string signingUserSid) =>
            throw new NotSupportedException();

        public Task StartAndVerifyTaskAsync(
            string name,
            bool requireRunning,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task StopTaskAsync(string name, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class OrderedServiceDeleteRunner(
        ReconciledWindowsResourceLookup lookup,
        List<string> events) : IWindowsCommandRunner
    {
        public Task<WindowsProcessResult> RunCheckedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            string errorCode,
            CancellationToken cancellationToken)
        {
            if (arguments.Contains("delete", StringComparer.OrdinalIgnoreCase))
            {
                events.Add("delete-service");
                lookup.ServicePresent = false;
            }

            return Task.FromResult(new WindowsProcessResult(0, string.Empty));
        }

        public Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class RecordingWindowsCommandRunner : IWindowsCommandRunner
    {
        public List<WindowsCommandCall> Calls { get; } = [];

        public bool FailChecked { get; init; }

        public Task<WindowsProcessResult> RunCheckedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            string errorCode,
            CancellationToken cancellationToken)
        {
            Calls.Add(new WindowsCommandCall(executable, arguments.ToArray()));
            return FailChecked
                ? Task.FromException<WindowsProcessResult>(new InstallException(errorCode))
                : Task.FromResult(new WindowsProcessResult(0, string.Empty));
        }

        public Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            Calls.Add(new WindowsCommandCall(executable, arguments.ToArray()));
            return Task.FromResult(new WindowsProcessResult(0, string.Empty));
        }
    }

    private sealed class RecordingWindowsInstallStartupRuntime(
        bool interactiveSessionAvailable,
        bool otpConfigured = true) : IWindowsInstallStartupRuntime
    {
        public List<string> Calls { get; } = [];

        public Task StartAndVerifyServiceAsync(string name, CancellationToken cancellationToken)
        {
            Calls.Add("start-service");
            return Task.CompletedTask;
        }

        public Task StopServiceAsync(string name, CancellationToken cancellationToken)
        {
            Calls.Add("stop-service");
            return Task.CompletedTask;
        }

        public bool HasInteractiveSession(string signingUserSid)
        {
            Calls.Add($"session:{signingUserSid}");
            return interactiveSessionAvailable;
        }

        public bool IsOtpConfiguredForSigningUser(string path, string signingUserSid)
        {
            Calls.Add("otp-metadata");
            return otpConfigured;
        }

        public Task StartAndVerifyTaskAsync(
            string name,
            bool requireRunning,
            CancellationToken cancellationToken)
        {
            Calls.Add(requireRunning ? "start-task:running" : "start-task:trigger-only");
            return Task.CompletedTask;
        }

        public Task StopTaskAsync(string name, CancellationToken cancellationToken)
        {
            Calls.Add("stop-task");
            return Task.CompletedTask;
        }
    }

    private sealed record WindowsCommandCall(string Executable, IReadOnlyList<string> Arguments);

    private sealed class ThrowingWindowsResourceLookup : IWindowsInstallResourceLookup
    {
        public bool ServiceExists(string name) => throw new InstallException("resource_preflight_failed");

        public bool TaskExists(string name) => throw new InstallException("resource_preflight_failed");

        public void MarkServiceOwner(CreateWindowsService action) =>
            throw new InstallException("resource_preflight_failed");

        public bool ServiceMatchesOwner(CreateWindowsService action) =>
            throw new InstallException("resource_preflight_failed");

        public bool TaskMatchesOwner(CreateInteractiveLogonTask action) =>
            throw new InstallException("resource_preflight_failed");
    }

    private sealed class MissingWindowsResourceLookup : IWindowsInstallResourceLookup
    {
        public bool ServiceExists(string name) => false;

        public bool TaskExists(string name) => false;

        public void MarkServiceOwner(CreateWindowsService action)
        {
        }

        public bool ServiceMatchesOwner(CreateWindowsService action) => false;

        public bool TaskMatchesOwner(CreateInteractiveLogonTask action) => false;
    }

    private sealed class ReconciledWindowsResourceLookup : IWindowsInstallResourceLookup
    {
        public bool ServicePresent { get; set; }

        public bool TaskPresent { get; set; }

        public bool ExactOwned { get; init; }

        public List<string>? Events { get; init; }

        public bool ServiceExists(string name)
        {
            if (!ServicePresent)
            {
                Events?.Add("query-service-missing");
            }

            return ServicePresent;
        }

        public bool TaskExists(string name)
        {
            if (!TaskPresent)
            {
                Events?.Add("query-missing");
            }

            return TaskPresent;
        }

        public void MarkServiceOwner(CreateWindowsService action)
        {
        }

        public bool ServiceMatchesOwner(CreateWindowsService action) => ServicePresent && ExactOwned;

        public bool TaskMatchesOwner(CreateInteractiveLogonTask action) => TaskPresent && ExactOwned;
    }

    private sealed class TimeoutAfterRegistrationRunner(
        ReconciledWindowsResourceLookup lookup) : IWindowsCommandRunner
    {
        public List<WindowsCommandCall> Calls { get; } = [];

        public Task<WindowsProcessResult> RunCheckedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            string errorCode,
            CancellationToken cancellationToken)
        {
            Calls.Add(new WindowsCommandCall(executable, arguments.ToArray()));
            if (executable.Equals("sc.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("create", StringComparison.OrdinalIgnoreCase))
            {
                lookup.ServicePresent = true;
                throw new InstallException("windows_process_timeout");
            }

            if (executable.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("/Create", StringComparison.OrdinalIgnoreCase))
            {
                lookup.TaskPresent = true;
                throw new InstallException("windows_process_timeout");
            }

            if (executable.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("/Delete", StringComparison.OrdinalIgnoreCase))
            {
                lookup.TaskPresent = false;
            }

            if (executable.Equals("sc.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("delete", StringComparison.OrdinalIgnoreCase))
            {
                lookup.ServicePresent = false;
            }

            return Task.FromResult(new WindowsProcessResult(0, string.Empty));
        }

        public Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            Calls.Add(new WindowsCommandCall(executable, arguments.ToArray()));
            if (executable.Equals("sc.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("delete", StringComparison.OrdinalIgnoreCase))
            {
                lookup.ServicePresent = false;
            }

            if (executable.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("/Delete", StringComparison.OrdinalIgnoreCase))
            {
                lookup.TaskPresent = false;
            }

            return Task.FromResult(new WindowsProcessResult(0, string.Empty));
        }
    }

    private sealed class FailureAfterSuccessfulCreateRunner(
        ReconciledWindowsResourceLookup lookup) : IWindowsCommandRunner
    {
        public List<WindowsCommandCall> Calls { get; } = [];

        public Task<WindowsProcessResult> RunCheckedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            string errorCode,
            CancellationToken cancellationToken)
        {
            Calls.Add(new WindowsCommandCall(executable, arguments.ToArray()));
            if (executable.Equals("sc.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("create", StringComparison.OrdinalIgnoreCase))
            {
                lookup.ServicePresent = true;
                return Task.FromResult(new WindowsProcessResult(0, string.Empty));
            }

            if (executable.Equals("sc.exe", StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("windows_process_timeout");
            }

            if (executable.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase) &&
                arguments[0].Equals("/Create", StringComparison.OrdinalIgnoreCase))
            {
                lookup.TaskPresent = true;
                return Task.FromResult(new WindowsProcessResult(0, string.Empty));
            }

            throw new InstallException("windows_process_timeout");
        }

        public Task<WindowsProcessResult> RunIgnoreExitCodeAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            Calls.Add(new WindowsCommandCall(executable, arguments.ToArray()));
            return Task.FromResult(new WindowsProcessResult(0, string.Empty));
        }
    }

    private sealed class RecordingInstallEnvironment(
        InstallFixture fixture,
        string? executablePath = null) : IInstallEnvironment
    {
        public bool IsWindows => true;
        public string ExecutablePath => executablePath ?? fixture.ExecutablePath;
        public string ProgramDataRoot => fixture.ProgramDataRoot;
        public string CommonDesktopDirectory => fixture.CommonDesktopDirectory;
        public string? ProvisionedInstanceId { get; init; } =
            "0123456789abcdef0123456789abcdef";
        public InstallException? AutomaticLogonFailure { get; init; }

        public Task<ResolvedSigningAccount> ResolveSigningAccountAsync(string account, CancellationToken cancellationToken) =>
            Task.FromResult(new ResolvedSigningAccount(account, InstallFixture.SigningSid, fixture.LocalApplicationData));

        public Task ValidateAutomaticLogonAsync(
            ResolvedSigningAccount account,
            CancellationToken cancellationToken) =>
            AutomaticLogonFailure is null
                ? Task.CompletedTask
                : Task.FromException(AutomaticLogonFailure);

        public Task<string?> GetProvisionedInstallInstanceIdAsync(
            ResolvedSigningAccount account,
            CancellationToken cancellationToken) => Task.FromResult(ProvisionedInstanceId);
    }

    public enum AutoLogonContractFailure
    {
        None,
        WrongSid,
        ExtraGroup,
        InteractiveLogonMissing,
        NetworkLogonAllowed,
        RemoteInteractiveLogonAllowed,
        OwnerMissing,
        OwnerInvalid,
        TaskNotExact,
    }

    private sealed class ReadOnlyAutoLogonPlatform : IWindowsAutoLogonPlatform
    {
        private const string Owner = "SimplySignAuto/v1/0123456789abcdef0123456789abcdef";
        private readonly AutoLogonContractFailure _failure;

        private ReadOnlyAutoLogonPlatform(AutoLogonContractFailure failure) => _failure = failure;

        public List<string> Reads { get; } = [];

        public List<string> Mutations { get; } = [];

        public static ReadOnlyAutoLogonPlatform Ready(
            AutoLogonContractFailure failure = AutoLogonContractFailure.None) => new(failure);

        public Task<AgentUserProvisionInspection> InspectAsync(
            string userName,
            CancellationToken cancellationToken)
        {
            Reads.Add("inspect");
            return Task.FromResult(new AgentUserProvisionInspection(
                IsWindowsServer2025: true,
                IsAdministrator: true,
                IsDomainController: false,
                UserExists: true,
                AutoLogonConfigured: true,
                AutoLogonAccountName: "TEST\\signer",
                RegistryDefaultPasswordPresent: false,
                ProvisionOwnerPresent: true,
                DangerousRightsPresent: false,
                LsaDefaultPasswordPresent: true));
        }

        public Task<ProvisionedAgentUser> ResolveExistingUserAsync(
            string userName,
            CancellationToken cancellationToken)
        {
            Reads.Add("resolve");
            return Task.FromResult(new ProvisionedAgentUser(
                "TEST\\signer",
                _failure == AutoLogonContractFailure.WrongSid
                    ? "S-1-5-21-1000-2000-3000-9999"
                    : InstallFixture.SigningSid,
                "TEST"));
        }

        public Task<AgentUserProvisionReadback> ReadbackAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken)
        {
            Reads.Add("readback");
            return Task.FromResult(new AgentUserProvisionReadback(
                UserExists: true,
                OnlyUsersGroup: _failure != AutoLogonContractFailure.ExtraGroup,
                InteractiveLogonAllowed: _failure != AutoLogonContractFailure.InteractiveLogonMissing,
                NetworkLogonDenied: _failure != AutoLogonContractFailure.NetworkLogonAllowed,
                RemoteInteractiveLogonDenied: _failure != AutoLogonContractFailure.RemoteInteractiveLogonAllowed,
                AutoLogonAccountName: "TEST\\signer",
                AutoAdminLogonEnabled: true,
                LsaSecretPresent: true,
                RegistryDefaultPasswordPresent: false,
                AgentTaskExact: _failure != AutoLogonContractFailure.TaskNotExact,
                OwnerMarker: _failure switch
                {
                    AutoLogonContractFailure.OwnerMissing => null,
                    AutoLogonContractFailure.OwnerInvalid => "SimplySignAuto/v1/not-an-owner",
                    _ => Owner,
                }));
        }

        public Task<ProvisionedAgentUser> CreateLocalUserAsync(
            string userName,
            SensitiveAgentUserPassword password,
            CancellationToken cancellationToken) => Mutated<ProvisionedAgentUser>();

        public Task<ProvisionedAgentUser> CreateUserProfileAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken) => Mutated<ProvisionedAgentUser>();

        public Task ResetLocalUserPasswordAsync(
            ProvisionedAgentUser user,
            SensitiveAgentUserPassword password,
            CancellationToken cancellationToken) => Mutated();

        public Task ConfigureRightsAsync(ProvisionedAgentUser user, CancellationToken cancellationToken) =>
            Mutated();

        public Task StoreLsaSecretAsync(
            ProvisionedAgentUser user,
            SensitiveAgentUserPassword password,
            string ownerMarker,
            CancellationToken cancellationToken) => Mutated();

        public Task WriteWinlogonAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken) => Mutated();

        public Task CreateAgentTaskAsync(
            ProvisionedAgentUser user,
            string ownerMarker,
            CancellationToken cancellationToken) => Mutated();

        public Task RollbackAgentTaskAsync(ProvisionedAgentUser user, string ownerMarker) => Mutated();

        public Task RollbackWinlogonAsync(ProvisionedAgentUser user, string ownerMarker) => Mutated();

        public Task RollbackLsaSecretAsync(ProvisionedAgentUser user, string ownerMarker) => Mutated();

        public Task RollbackRightsAsync(ProvisionedAgentUser user) => Mutated();

        public Task RollbackUserProfileAsync(ProvisionedAgentUser user, string ownerMarker) => Mutated();

        public Task RollbackLocalUserAsync(ProvisionedAgentUser user) => Mutated();

        private Task Mutated()
        {
            Mutations.Add("unexpected");
            return Task.CompletedTask;
        }

        private Task<T> Mutated<T>()
        {
            Mutations.Add("unexpected");
            return Task.FromException<T>(new InvalidOperationException("unexpected mutation"));
        }
    }

    private sealed class RecordingUninstallEnvironment(ServiceConfiguration configuration) : IUninstallEnvironment
    {
        public bool IsWindows => true;
        public string CommonDesktopDirectory => Path.Combine(
            Path.GetTempPath(), "SimplySignAuto.Tests", "PublicDesktop");

        public Task<ServiceConfiguration> LoadConfigurationAsync(CancellationToken cancellationToken) =>
            Task.FromResult(configuration);

        public void ValidateControlledPaths(ServiceConfiguration configured) { }
    }

    private sealed class InstallFixture : IDisposable
    {
        public const string SigningSid = "S-1-5-21-1000-2000-3000-4000";
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));
        public string ProgramDataRoot => Path.Combine(Root, "ProgramData");
        public string DataRoot => Path.Combine(ProgramDataRoot, "SimplySignAuto");
        public string SpoolRoot => Path.Combine(DataRoot, "spool");
        public string LocalApplicationData => Path.Combine(Root, "Users", "signer", "AppData", "Local");
        public string CommonDesktopDirectory => Path.Combine(Root, "Users", "Public", "Desktop");
        public string AgentSourcePath => Path.Combine(Root, "agent-source.json");
        public string ExecutablePath => Path.Combine(Root, "install", "SimplySignAuto.exe");
        public AgentConfiguration Configuration => new(
            SigningSid,
            SpoolRoot,
            Path.Combine(Root, "SimplySignDesktop.exe"),
            Path.Combine(Root, "synthetic-pkcs11.dll"),
            null,
            new AgentPdfConfiguration());
        public InstallOptions Options => new(
            "TEST\\signer",
            AgentSourcePath,
            7080,
            false);
        public string[] Arguments =>
        [
            "--signing-user", Options.SigningUser,
            "--agent-config", Options.AgentConfigurationPath,
        ];

        public InstallFixture()
        {
            Directory.CreateDirectory(Root);
            WriteAgentConfigurationAsync(Configuration).GetAwaiter().GetResult();
        }

        public InstallPlanner CreatePlanner() => new(new RecordingInstallEnvironment(this));

        public Task WriteAgentConfigurationAsync(AgentConfiguration configuration) => File.WriteAllTextAsync(
            AgentSourcePath,
            JsonSerializer.Serialize(configuration, JsonSerializerOptions.Web));

        public ServiceConfiguration ServiceConfiguration() => new(
            new string('a', 64),
            SigningSid,
            DataRoot,
            SpoolRoot,
            7080,
            "SimplySignAuto/v1",
            "0123456789abcdef0123456789abcdef",
            ExecutablePath,
            Path.Combine(LocalApplicationData, "SimplySignAuto", "agent.json"));

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        nint securityAttributes);
}

public sealed class WindowsAdministratorFactAttribute : FactAttribute
{
    public WindowsAdministratorFactAttribute()
    {
        if (!OperatingSystem.IsWindows() ||
            !string.Equals(
                Environment.GetEnvironmentVariable("SIMPLYSIGN_RUN_ADMIN_INTEGRATION"),
                "1",
                StringComparison.Ordinal))
        {
            Skip = "Requires an explicitly enabled elevated Windows installation integration run.";
        }
    }
}

public sealed class SignedReleaseMediaFactAttribute : FactAttribute
{
    public SignedReleaseMediaFactAttribute()
    {
        var root = Environment.GetEnvironmentVariable("SIMPLYSIGN_SIGNED_MEDIA_ROOT");
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            Skip = "Requires an explicitly supplied real signed release media root.";
        }
    }
}

public sealed class SignedReleaseMediaAdministratorFactAttribute : FactAttribute
{
    public SignedReleaseMediaAdministratorFactAttribute()
    {
        var root = Environment.GetEnvironmentVariable("SIMPLYSIGN_SIGNED_MEDIA_ROOT");
        if (!OperatingSystem.IsWindows() ||
            !string.Equals(
                Environment.GetEnvironmentVariable("SIMPLYSIGN_RUN_ADMIN_INTEGRATION"),
                "1",
                StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(root) ||
            !Directory.Exists(root))
        {
            Skip = "Requires explicitly enabled elevated Windows integration with real signed media.";
        }
    }
}
