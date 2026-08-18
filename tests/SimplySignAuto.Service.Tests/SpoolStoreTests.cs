using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class SpoolStoreTests
{
    [Theory]
    [InlineData(".exe")]
    [InlineData(".pdf")]
    [InlineData(".cat")]
    public void Result_part_path_keeps_the_real_file_extension_last(string extension)
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);

        var path = spool.GetResultPartPath(Guid.NewGuid(), extension);

        Assert.Equal(extension, Path.GetExtension(path));
        Assert.Equal("result.part" + extension, Path.GetFileName(path));
    }

    [Fact]
    public async Task Promotion_protects_the_claimed_final_before_returning_it()
    {
        using var fixture = new SpoolFixture();
        var acl = new RecordingSpoolAclPolicy();
        var spool = new SpoolStore(fixture.Root, acl);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        await File.WriteAllTextAsync(partPath, "verified-result");

        var promoted = await spool.PromoteResultAsync(
            jobId,
            ".pdf",
            Sha256("verified-result"),
            15);

        Assert.Equal("final", acl.Events[^1]);
        Assert.Contains("root", acl.Events);
        Assert.Contains("job", acl.Events);
        Assert.Equal(promoted.Path, acl.FinalPath);
    }

    [Fact]
    public async Task Final_acl_failure_prevents_result_publication()
    {
        using var fixture = new SpoolFixture();
        var acl = new RecordingSpoolAclPolicy { FailFinal = true };
        var spool = new SpoolStore(fixture.Root, acl);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        await File.WriteAllTextAsync(partPath, "verified-result");

        var failure = await Assert.ThrowsAsync<SpoolException>(() => spool.PromoteResultAsync(
            jobId,
            ".pdf",
            Sha256("verified-result"),
            15));

        Assert.Equal("acl_verification_failed", failure.Code);
        Assert.False(File.Exists(spool.GetResultPath(jobId, ".pdf")));
    }

    [Fact]
    public async Task Idempotent_existing_final_is_reprotected_before_acceptance()
    {
        using var fixture = new SpoolFixture();
        var acl = new RecordingSpoolAclPolicy();
        var spool = new SpoolStore(fixture.Root, acl);
        var jobId = Guid.NewGuid();
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllTextAsync(finalPath, "verified-result");
        acl.Events.Clear();

        var promoted = await spool.PromoteResultAsync(
            jobId,
            ".pdf",
            Sha256("verified-result"),
            15);

        Assert.Equal(finalPath, promoted.Path);
        Assert.Equal("final", acl.Events[^1]);
    }

    [Fact]
    public async Task Existing_final_acl_revalidation_failure_preserves_both_crash_window_artifacts()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(
            fixture.Root,
            new RecordingSpoolAclPolicy { FailFinal = true });
        var jobId = Guid.NewGuid();
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        await File.WriteAllTextAsync(finalPath, "verified-result");
        await File.WriteAllTextAsync(partPath, "unclaimed-part");

        var failure = await Assert.ThrowsAsync<SpoolException>(() => spool.PromoteResultAsync(
            jobId,
            ".pdf",
            Sha256("verified-result"),
            15));

        Assert.Equal("acl_verification_failed", failure.Code);
        Assert.Equal("verified-result", await File.ReadAllTextAsync(finalPath));
        Assert.Equal("unclaimed-part", await File.ReadAllTextAsync(partPath));
    }

    [Fact]
    public async Task Original_name_never_controls_spool_path()
    {
        string[] originalNames = ["../../windows/system32/a.exe", "C:\\Windows\\a.exe"];
        foreach (var originalName in originalNames)
        {
            using var fixture = new SpoolFixture();
            var spool = new SpoolStore(fixture.Root);

            var written = await spool.WriteInputAsync(Guid.NewGuid(), ".exe", Stream.Null, 512L * 1024 * 1024);

            Assert.StartsWith(Path.GetFullPath(spool.Root) + Path.DirectorySeparatorChar, Path.GetFullPath(written.Path), StringComparison.Ordinal);
            Assert.DoesNotContain(originalName, written.Path, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("exe")]
    [InlineData(".exe.part")]
    [InlineData("../.exe")]
    public async Task Rejects_extensions_that_cannot_name_a_controlled_file(string extension)
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);

        var exception = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.WriteInputAsync(Guid.NewGuid(), extension, Stream.Null, 1024));

        Assert.Equal("invalid_extension", exception.Code);
    }

    [Fact]
    public async Task Streams_input_and_returns_its_exact_size_and_hash()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        await using var input = new MemoryStream(Encoding.UTF8.GetBytes("signed-input"));

        var written = await spool.WriteInputAsync(Guid.NewGuid(), ".pdf", input, 1024);

        Assert.Equal(12, written.Size);
        Assert.Equal(Sha256("signed-input"), written.Sha256);
        Assert.True(File.Exists(written.Path));
        Assert.False(File.Exists(written.Path + ".part"));
    }

    [Fact]
    public async Task Deletes_partial_file_immediately_when_size_limit_is_exceeded()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        await using var input = new MemoryStream(Encoding.UTF8.GetBytes("1234"));

        var exception = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.WriteInputAsync(jobId, ".exe", input, 3));

        Assert.Equal("file_too_large", exception.Code);
        Assert.False(File.Exists(Path.Combine(fixture.Root, jobId.ToString("N"), "input.exe.part")));
        Assert.False(File.Exists(Path.Combine(fixture.Root, jobId.ToString("N"), "input.exe")));
    }

    [Fact]
    public async Task Input_acl_failure_removes_the_claimed_input_and_returns_only_the_stable_code()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root, new RecordingSpoolAclPolicy { FailInput = true });
        var jobId = Guid.NewGuid();

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.WriteInputAsync(jobId, ".exe", new MemoryStream("MZ-input"u8.ToArray()), 1024));

        Assert.Equal("acl_verification_failed", failure.Code);
        Assert.False(File.Exists(Path.Combine(fixture.Root, jobId.ToString("N"), "input.exe")));
        Assert.False(File.Exists(Path.Combine(fixture.Root, jobId.ToString("N"), "input.exe.part")));
    }

    [Fact]
    public async Task Invalid_result_metadata_and_missing_artifacts_fail_closed_without_creating_a_result()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var hash = Sha256("result");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            spool.OpenVerifiedResultAsync(jobId, ".pdf", -1, hash));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", "not-a-hash", 1));
        var missingVerified = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.OpenVerifiedResultAsync(jobId, ".pdf", 6, hash));
        var missingPart = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", hash, 6));

        Assert.Equal("result_corrupt", missingVerified.Code);
        Assert.Equal("result_not_ready", missingPart.Code);
        Assert.False(File.Exists(Path.Combine(fixture.Root, jobId.ToString("N"), "result.pdf")));
    }

    [Fact]
    public async Task Verified_result_reader_rejects_size_and_hash_mismatch_and_rewinds_a_matching_file()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var resultPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllTextAsync(resultPath, "result");

        var sizeFailure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.OpenVerifiedResultAsync(jobId, ".pdf", 5, Sha256("result")));
        var hashFailure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.OpenVerifiedResultAsync(jobId, ".pdf", 6, Sha256("other!")));
        await using var verified = await spool.OpenVerifiedResultAsync(
            jobId,
            ".pdf",
            6,
            Sha256("result"));

        Assert.Equal("result_corrupt", sizeFailure.Code);
        Assert.Equal("result_corrupt", hashFailure.Code);
        Assert.Equal(0, verified.Position);
        using var reader = new StreamReader(verified);
        Assert.Equal("result", await reader.ReadToEndAsync());
    }

    [Fact]
    public async Task Never_opens_an_unpublished_result_part()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".exe");
        Directory.CreateDirectory(Path.GetDirectoryName(partPath)!);
        await File.WriteAllTextAsync(partPath, "partial");

        var exception = await Assert.ThrowsAsync<SpoolException>(() => spool.OpenResultAsync(jobId, ".exe"));

        Assert.Equal("result_not_ready", exception.Code);
    }

    [Fact]
    public async Task Promotes_only_a_result_that_matches_the_reported_size_and_hash()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        Directory.CreateDirectory(Path.GetDirectoryName(partPath)!);
        await File.WriteAllTextAsync(partPath, "verified-result");

        var promoted = await spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15);
        await using var opened = await spool.OpenResultAsync(jobId, ".pdf");
        using var reader = new StreamReader(opened);

        Assert.Equal(15, promoted.Size);
        Assert.Equal(Sha256("verified-result"), promoted.Sha256);
        Assert.Equal("verified-result", await reader.ReadToEndAsync());
        Assert.False(File.Exists(partPath));
    }

    [Fact]
    public async Task Rejects_and_removes_result_part_when_its_hash_does_not_match()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".dll");
        Directory.CreateDirectory(Path.GetDirectoryName(partPath)!);
        await File.WriteAllTextAsync(partPath, "tampered");

        var exception = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".dll", Sha256("expected"), 8));

        Assert.Equal("result_corrupt", exception.Code);
        Assert.False(File.Exists(partPath));
    }

    [Fact]
    public async Task Atomically_claims_the_part_before_hashing_so_a_replacement_cannot_be_published()
    {
        using var fixture = new SpoolFixture();
        var observer = new ReplacingPromotionObserver("attacker-result");
        var spool = new SpoolStore(fixture.Root, observer);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllTextAsync(partPath, "verified-result");

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15));

        Assert.Equal("result_corrupt", failure.Code);
        Assert.Equal(1, observer.Calls);
        Assert.False(File.Exists(finalPath));
        Assert.False(File.Exists(partPath));
    }

    [Fact]
    public async Task Promotion_is_idempotent_after_part_was_already_moved_to_matching_final()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllTextAsync(finalPath, "verified-result");

        var promoted = await spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15);

        Assert.Equal(finalPath, promoted.Path);
        Assert.Equal(15, promoted.Size);
        Assert.Equal("verified-result", await File.ReadAllTextAsync(finalPath));
    }

    [Fact]
    public async Task Differing_existing_final_fails_closed_and_is_never_overwritten()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllTextAsync(partPath, "verified-result");
        await File.WriteAllTextAsync(finalPath, "conflicting-final");

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15));

        Assert.Equal("result_corrupt", failure.Code);
        Assert.Equal("conflicting-final", await File.ReadAllTextAsync(finalPath));
    }

    [Fact]
    public async Task Dangling_result_part_is_reported_as_corrupt_instead_of_not_ready()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        File.CreateSymbolicLink(partPath, partPath + ".missing");

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15));

        Assert.Equal("result_corrupt", failure.Code);
    }

    [Fact]
    public async Task Reparse_result_part_is_never_hashed_or_promoted()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        var outsidePath = Path.Combine(fixture.OutsideRoot, "outside.part");
        await File.WriteAllTextAsync(outsidePath, "verified-result");
        File.CreateSymbolicLink(partPath, outsidePath);

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15));

        Assert.Equal("result_corrupt", failure.Code);
        Assert.Equal("verified-result", await File.ReadAllTextAsync(outsidePath));
        Assert.False(File.Exists(spool.GetResultPath(jobId, ".pdf")));
    }

    [Fact]
    public async Task Dangling_existing_final_is_never_replaced_by_result_part()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllTextAsync(partPath, "verified-result");
        File.CreateSymbolicLink(finalPath, finalPath + ".missing");

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15));

        Assert.Equal("result_corrupt", failure.Code);
        Assert.NotNull(new FileInfo(finalPath).LinkTarget);
        Assert.False(File.Exists(partPath));
    }

    [Fact]
    public async Task Reparse_existing_final_is_never_accepted_even_when_target_matches()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        var outsidePath = Path.Combine(fixture.OutsideRoot, "outside.final");
        await File.WriteAllTextAsync(partPath, "verified-result");
        await File.WriteAllTextAsync(outsidePath, "verified-result");
        File.CreateSymbolicLink(finalPath, outsidePath);

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15));

        Assert.Equal("result_corrupt", failure.Code);
        Assert.Equal("verified-result", await File.ReadAllTextAsync(outsidePath));
        Assert.False(File.Exists(partPath));
    }

    [Fact]
    public async Task Existing_final_directory_is_reported_as_corrupt_without_leaking_io_exception()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetResultPartPath(jobId, ".pdf");
        var finalPath = spool.GetResultPath(jobId, ".pdf");
        await File.WriteAllTextAsync(partPath, "verified-result");
        Directory.CreateDirectory(finalPath);

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.PromoteResultAsync(jobId, ".pdf", Sha256("verified-result"), 15));

        Assert.Equal("result_corrupt", failure.Code);
        Assert.True(Directory.Exists(finalPath));
        Assert.False(File.Exists(partPath));
    }

    [Fact]
    public async Task Deletes_only_the_requested_job_spool_files()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var removedJobId = Guid.NewGuid();
        var retainedJobId = Guid.NewGuid();
        await spool.WriteInputAsync(removedJobId, ".pdf", new MemoryStream("%PDF-remove"u8.ToArray()), 1024);
        var retained = await spool.WriteInputAsync(retainedJobId, ".pdf", new MemoryStream("%PDF-retain"u8.ToArray()), 1024);

        await spool.DeleteJobAsync(removedJobId);

        Assert.False(Directory.Exists(Path.Combine(fixture.Root, removedJobId.ToString("N"))));
        Assert.True(File.Exists(retained.Path));
    }

    [Fact]
    public async Task Invalid_job_ids_and_absent_local_upload_directories_are_safe_no_ops_or_rejections()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var absentJobId = Guid.NewGuid();

        await Assert.ThrowsAsync<ArgumentException>(() => spool.DeleteJobAsync(Guid.Empty));
        await spool.DeleteLocalUploadArtifactsAsync(absentJobId, ".pdf");
        spool.ValidateLocalUploadArtifacts(absentJobId, ".pdf");
        var missing = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.OpenLocalUploadAsync(absentJobId, ".pdf"));

        Assert.Equal("local_upload_missing", missing.Code);
        Assert.False(Directory.Exists(Path.Combine(fixture.Root, absentJobId.ToString("N"))));
    }

    [Fact]
    public void Local_upload_preparation_and_validation_reject_colliding_artifacts()
    {
        using var fixture = new SpoolFixture();
        var spool = new SpoolStore(fixture.Root);
        var jobId = Guid.NewGuid();
        var inputPath = spool.GetInputPath(jobId, ".pdf");
        File.WriteAllText(inputPath, "first");
        File.WriteAllText(inputPath + ".part", "second");

        var prepareFailure = Assert.Throws<SpoolException>(() =>
            spool.PrepareLocalUpload(jobId, ".pdf"));
        var validationFailure = Assert.Throws<SpoolException>(() =>
            spool.ValidateLocalUploadArtifacts(jobId, ".pdf"));

        Assert.Equal("local_upload_invalid_path", prepareFailure.Code);
        Assert.Equal("local_upload_invalid_path", validationFailure.Code);
    }

    [Fact]
    public void Root_and_job_acl_failures_are_mapped_to_the_stable_spool_code()
    {
        using var rootFixture = new SpoolFixture();
        var rootFailure = Assert.Throws<SpoolException>(() =>
            new SpoolStore(rootFixture.Root, new RecordingSpoolAclPolicy { FailRoot = true })
                .GetInputPath(Guid.NewGuid(), ".exe"));
        using var jobFixture = new SpoolFixture();
        var jobFailure = Assert.Throws<SpoolException>(() =>
            new SpoolStore(jobFixture.Root, new RecordingSpoolAclPolicy { FailJob = true })
                .GetInputPath(Guid.NewGuid(), ".exe"));

        Assert.Equal("acl_verification_failed", rootFailure.Code);
        Assert.Equal("acl_verification_failed", jobFailure.Code);
    }

    [Fact]
    public async Task Local_upload_link_count_above_one_is_rejected_before_hash_claim_or_acl()
    {
        using var fixture = new SpoolFixture();
        var acl = new RecordingSpoolAclPolicy();
        var identities = new FixedFileIdentityProvider(new LocalFileIdentity(42, 7, 9, 2));
        var spool = new SpoolStore(fixture.Root, acl, identities);
        var jobId = Guid.NewGuid();
        var partPath = spool.GetInputPath(jobId, ".exe") + ".part";
        await File.WriteAllTextAsync(partPath, "MZ-untrusted-hardlink");
        var external = Path.Combine(fixture.OutsideRoot, "outside.exe");
        await File.WriteAllTextAsync(external, "external-owner-and-content");
        var externalHash = SHA256.HashData(await File.ReadAllBytesAsync(external));
        acl.Events.Clear();

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.OpenLocalUploadAsync(jobId, ".exe"));

        Assert.Equal("local_upload_invalid_path", failure.Code);
        Assert.DoesNotContain("input", acl.Events);
        Assert.Equal("MZ-untrusted-hardlink", await File.ReadAllTextAsync(partPath));
        Assert.Equal(externalHash, SHA256.HashData(await File.ReadAllBytesAsync(external)));
    }

    [Fact]
    public async Task Local_upload_claim_rejects_when_final_path_readback_is_not_the_verified_handle_identity()
    {
        using var fixture = new SpoolFixture();
        var verified = new LocalFileIdentity(42, 7, 9, 1);
        var replacement = new LocalFileIdentity(42, 7, 10, 1);
        var identities = new SequenceFileIdentityProvider(
            verified,
            verified,
            verified,
            verified,
            replacement);
        var acl = new RecordingSpoolAclPolicy();
        var spool = new SpoolStore(fixture.Root, acl, identities);
        var jobId = Guid.NewGuid();
        var input = "MZ-verified-input";
        var inputPath = spool.GetInputPath(jobId, ".exe");
        var partPath = inputPath + ".part";
        await File.WriteAllTextAsync(partPath, input);
        await using var upload = await spool.OpenLocalUploadAsync(jobId, ".exe");

        var failure = await Assert.ThrowsAsync<SpoolException>(() => spool.PromoteLocalUploadAsync(
            upload,
            input.Length,
            Sha256(input)));

        Assert.Equal("local_upload_invalid_path", failure.Code);
        Assert.Contains("input", acl.Events);
        Assert.True(File.Exists(inputPath));
        Assert.Equal(input, await File.ReadAllTextAsync(inputPath));
    }

    [Fact]
    public async Task Local_upload_claim_failure_never_deletes_an_unverified_path_replacement()
    {
        using var fixture = new SpoolFixture();
        var verified = new LocalFileIdentity(42, 7, 9, 1);
        var replacementIdentity = new LocalFileIdentity(42, 7, 10, 1);
        var identities = new SequenceFileIdentityProvider(verified, verified, verified, replacementIdentity);
        var exchangeWasDenied = false;
        var displaced = string.Empty;
        var replacement = "MZ-unverified-replacement";
        var acl = new RecordingSpoolAclPolicy
        {
            OnProtectInput = path =>
            {
                displaced = path + ".displaced";
                try
                {
                    File.Move(path, displaced);
                    File.WriteAllText(path, replacement);
                }
                catch (IOException)
                {
                    exchangeWasDenied = true;
                }
            },
        };
        var spool = new SpoolStore(fixture.Root, acl, identities);
        var jobId = Guid.NewGuid();
        var original = "MZ-verified-input";
        var inputPath = spool.GetInputPath(jobId, ".exe");
        await File.WriteAllTextAsync(inputPath + ".part", original);
        await using var upload = await spool.OpenLocalUploadAsync(jobId, ".exe");

        var failure = await Assert.ThrowsAsync<SpoolException>(() => spool.PromoteLocalUploadAsync(
            upload,
            original.Length,
            Sha256(original)));

        Assert.Equal("local_upload_invalid_path", failure.Code);
        Assert.True(File.Exists(inputPath));
        if (OperatingSystem.IsWindows())
        {
            Assert.True(exchangeWasDenied);
            Assert.False(File.Exists(displaced));
            Assert.Equal(original, await File.ReadAllTextAsync(inputPath));
        }
        else
        {
            Assert.False(exchangeWasDenied);
            Assert.Equal(original, await File.ReadAllTextAsync(displaced));
            Assert.Equal(replacement, await File.ReadAllTextAsync(inputPath));
        }
    }

    [WindowsAdministratorFact]
    public async Task Windows_local_upload_hardlink_rejection_preserves_external_hash_owner_and_dacl()
    {
        using var fixture = new SpoolFixture();
        var currentSid = WindowsIdentity.GetCurrent().User?.Value;
        Assert.False(string.IsNullOrWhiteSpace(currentSid));
        var spool = new SpoolStore(fixture.Root, new WindowsSpoolAclPolicy(currentSid!));
        var jobId = Guid.NewGuid();
        var partPath = spool.GetInputPath(jobId, ".exe") + ".part";
        var externalPath = Path.Combine(fixture.OutsideRoot, "external-owner.exe");
        await File.WriteAllTextAsync(externalPath, "MZ-external-hardlink-owner");
        Assert.True(CreateHardLinkW(partPath, externalPath, IntPtr.Zero), "hardlink_fixture_failed");
        var beforeHash = SHA256.HashData(await File.ReadAllBytesAsync(externalPath));
        var beforeSecurity = new FileInfo(externalPath).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        var beforeOwner = Assert.IsType<SecurityIdentifier>(
            beforeSecurity.GetOwner(typeof(SecurityIdentifier)));
        var beforeDacl = beforeSecurity.GetSecurityDescriptorSddlForm(
            AccessControlSections.Owner | AccessControlSections.Access);

        var failure = await Assert.ThrowsAsync<SpoolException>(() =>
            spool.OpenLocalUploadAsync(jobId, ".exe"));

        Assert.Equal("local_upload_invalid_path", failure.Code);
        Assert.True(File.Exists(partPath));
        Assert.True(File.Exists(externalPath));
        Assert.Equal(beforeHash, SHA256.HashData(await File.ReadAllBytesAsync(externalPath)));
        var afterSecurity = new FileInfo(externalPath).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        Assert.Equal(
            beforeOwner,
            Assert.IsType<SecurityIdentifier>(afterSecurity.GetOwner(typeof(SecurityIdentifier))));
        Assert.Equal(
            beforeDacl,
            afterSecurity.GetSecurityDescriptorSddlForm(
                AccessControlSections.Owner | AccessControlSections.Access));
    }

    private static string Sha256(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    private sealed class SpoolFixture : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));

        public string OutsideRoot { get; } = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests.Outside", Guid.NewGuid().ToString("N"));

        public SpoolFixture()
        {
            Directory.CreateDirectory(OutsideRoot);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }

            if (Directory.Exists(OutsideRoot))
            {
                Directory.Delete(OutsideRoot, recursive: true);
            }
        }
    }

    private sealed class ReplacingPromotionObserver(string replacement) : ISpoolPromotionObserver
    {
        public int Calls { get; private set; }

        public async Task BeforeResultClaimAsync(
            string partPath,
            string resultPath,
            CancellationToken cancellationToken)
        {
            Calls++;
            var displaced = partPath + ".displaced";
            File.Move(partPath, displaced, overwrite: false);
            await File.WriteAllTextAsync(partPath, replacement, cancellationToken);
            File.Delete(displaced);
        }
    }

    private sealed class RecordingSpoolAclPolicy : ISpoolAclPolicy
    {
        public List<string> Events { get; } = [];

        public Action<string>? OnProtectInput { get; init; }

        public bool FailFinal { get; init; }

        public bool FailInput { get; init; }

        public bool FailRoot { get; init; }

        public bool FailJob { get; init; }

        public string? FinalPath { get; private set; }

        public void ProtectRoot(string path)
        {
            Events.Add("root");
            if (FailRoot)
            {
                throw new SpoolAclException();
            }
        }

        public void ProtectJobDirectory(string path)
        {
            Events.Add("job");
            if (FailJob)
            {
                throw new SpoolAclException();
            }
        }

        public void ProtectInput(string path)
        {
            Events.Add("input");
            OnProtectInput?.Invoke(path);
            if (FailInput)
            {
                throw new SpoolAclException();
            }
        }

        public void ProtectFinalResult(string path)
        {
            Events.Add("final");
            FinalPath = path;
            if (FailFinal)
            {
                throw new SpoolAclException();
            }
        }
    }

    private sealed class FixedFileIdentityProvider(LocalFileIdentity identity) : ILocalFileIdentityProvider
    {
        public bool TryGetIdentity(SafeFileHandle handle, out LocalFileIdentity result)
        {
            result = identity;
            return true;
        }
    }

    private sealed class SequenceFileIdentityProvider(params LocalFileIdentity[] identities) : ILocalFileIdentityProvider
    {
        private readonly Queue<LocalFileIdentity> _identities = new(identities);

        public bool TryGetIdentity(SafeFileHandle handle, out LocalFileIdentity result)
        {
            result = _identities.Dequeue();
            return true;
        }
    }

    private sealed class WindowsAdministratorFactAttribute : FactAttribute
    {
        public WindowsAdministratorFactAttribute()
        {
            if (!OperatingSystem.IsWindows() ||
                !string.Equals(
                    Environment.GetEnvironmentVariable("SIMPLYSIGN_RUN_ADMIN_INTEGRATION"),
                    "1",
                    StringComparison.Ordinal))
            {
                Skip = "Requires an explicitly enabled elevated Windows spool integration run.";
            }
        }
    }
}
