using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class LocalJobClientTests
{
    private const string ParametersJson =
        "{\"appendSignature\":false,\"certificateSerialNumber\":\"AA00\",\"digestAlgorithm\":\"sha256\",\"kind\":\"authenticode\"}";
    private static readonly AuthenticodeParameters Parameters =
        new("AA00", "sha256", false);

    [Fact]
    public async Task Upload_streams_to_the_service_lease_and_never_mutates_the_original()
    {
        using var fixture = new LocalFixture();
        var original = "MZ-original-payload"u8.ToArray();
        var source = fixture.WriteSource("release.exe", original);
        var beforeWrite = File.GetLastWriteTimeUtc(source);
        var progress = new List<LocalCopyProgress>();

        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            new InlineProgress(value => progress.Add(value)),
            CancellationToken.None);

        Assert.Equal(fixture.Transport.JobId, jobId);
        Assert.Equal(original, await File.ReadAllBytesAsync(source));
        Assert.Equal(beforeWrite, File.GetLastWriteTimeUtc(source));
        Assert.Equal(original, await File.ReadAllBytesAsync(fixture.Transport.InputPath));
        Assert.Equal(ParametersJson, fixture.Transport.CreateRequest!.CanonicalParametersJson);
        Assert.Equal("release.exe", fixture.Transport.CreateRequest.OriginalName);
        Assert.DoesNotContain(fixture.SourceRoot, fixture.Transport.CreateRequest.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, progress[0].Percent);
        Assert.Equal(100, progress[^1].Percent);
    }

    [Fact]
    public async Task Cancellation_during_copy_removes_only_the_controlled_part_and_creates_no_job()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", CreatePeBytes(3 * 1024 * 1024));
        var sibling = fixture.WriteSource("keep.txt", "keep"u8.ToArray());
        using var cancellation = new CancellationTokenSource();
        var progress = new InlineProgress(value =>
        {
            if (value.BytesCopied >= 1024 * 1024)
            {
                cancellation.Cancel();
            }
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress,
            cancellation.Token));

        Assert.False(File.Exists(fixture.Transport.PartPath));
        Assert.False(fixture.Transport.Completed);
        Assert.True(File.Exists(source));
        Assert.Equal("keep", await File.ReadAllTextAsync(sibling));
    }

    [Fact]
    public async Task Cancellation_while_waiting_for_complete_response_preserves_the_same_submission_for_retry()
    {
        using var fixture = new LocalFixture();
        var original = "MZ-finalizing-cancel"u8.ToArray();
        var source = fixture.WriteSource("release.exe", original);
        fixture.Transport.BlockComplete = true;
        using var cancellation = new CancellationTokenSource();
        var first = fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            cancellation.Token);
        await fixture.Transport.CompleteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        cancellation.Cancel();
        fixture.Transport.ReleaseComplete();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);

        Assert.True(File.Exists(fixture.Transport.PartPath));
        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);

        Assert.Equal(fixture.Transport.JobId, jobId);
        Assert.Equal(1, fixture.Transport.CreateCalls);
        Assert.Equal(2, fixture.Transport.CompletedRequests.Count);
        Assert.Equal(
            fixture.Transport.CompletedRequests[0],
            fixture.Transport.CompletedRequests[1]);
        Assert.Equal(original, await File.ReadAllBytesAsync(source));
    }

    [Fact]
    public async Task Source_symlink_is_rejected_without_opening_its_target_for_upload()
    {
        using var fixture = new LocalFixture();
        var target = fixture.WriteSource("target.exe", "MZ-target"u8.ToArray());
        var link = Path.Combine(fixture.SourceRoot, "link.exe");
        File.CreateSymbolicLink(link, target);

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            link,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("local_source_invalid", error.Code);
        Assert.Null(fixture.Transport.CreateRequest);
        Assert.Equal("MZ-target"u8.ToArray(), await File.ReadAllBytesAsync(target));
    }

    [Fact]
    public async Task Exact_512_mib_limit_is_checked_from_the_same_source_handle_before_a_lease()
    {
        using var fixture = new LocalFixture();
        var path = Path.Combine(fixture.SourceRoot, "large.exe");
        await using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            await file.WriteAsync("MZ"u8.ToArray());
            file.SetLength(LocalJobClient.MaximumInputBytes + 1);
        }

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            path,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("file_too_large", error.Code);
        Assert.Null(fixture.Transport.CreateRequest);
    }

    [Fact]
    public async Task Existing_or_escaping_part_path_is_never_overwritten()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", "MZ-input"u8.ToArray());
        Directory.CreateDirectory(Path.GetDirectoryName(fixture.Transport.PartPath)!);
        await File.WriteAllTextAsync(fixture.Transport.PartPath, "preserve");

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("local_upload_invalid_path", error.Code);
        Assert.Equal("preserve", await File.ReadAllTextAsync(fixture.Transport.PartPath));
        Assert.False(fixture.Transport.Completed);
    }

    [Fact]
    public async Task Save_copy_reverifies_result_and_publishes_the_default_name_without_changing_spool()
    {
        using var fixture = new LocalFixture();
        var result = "MZ-signed-result"u8.ToArray();
        Directory.CreateDirectory(Path.GetDirectoryName(fixture.Transport.ResultPath)!);
        await File.WriteAllBytesAsync(fixture.Transport.ResultPath, result);
        fixture.Transport.ResultMetadata = new LocalJobResultMetadata(
            Guid.NewGuid(),
            fixture.Transport.JobId,
            ".exe",
            result.Length,
            Convert.ToHexString(SHA256.HashData(result)).ToLowerInvariant());
        var destination = Path.Combine(
            fixture.SourceRoot,
            LocalJobClient.DefaultSignedCopyName("release.exe", ".exe"));

        await fixture.Client.SaveSignedCopyAsync(
            fixture.Transport.JobId,
            destination,
            overwrite: false,
            CancellationToken.None);

        Assert.Equal("release.signed.exe", Path.GetFileName(destination));
        Assert.Equal(result, await File.ReadAllBytesAsync(destination));
        Assert.Equal(result, await File.ReadAllBytesAsync(fixture.Transport.ResultPath));
        Assert.Empty(Directory.GetFiles(fixture.SourceRoot, ".simplysign-*.part"));
    }

    [Fact]
    public async Task Save_copy_rejects_same_input_and_existing_destination_without_explicit_overwrite()
    {
        var identity = new LocalFileIdentity(42, 7, 9, 1);
        using var fixture = new LocalFixture(new SequenceFileIdentityProvider(identity, identity, identity));
        var original = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        var jobId = await fixture.Client.CreateAndUploadAsync(
            original,
            Parameters,
            progress: null,
            CancellationToken.None);
        var result = "MZ-signed"u8.ToArray();
        Directory.CreateDirectory(Path.GetDirectoryName(fixture.Transport.ResultPath)!);
        await File.WriteAllBytesAsync(fixture.Transport.ResultPath, result);
        fixture.Transport.ResultMetadata = new LocalJobResultMetadata(
            Guid.NewGuid(),
            fixture.Transport.JobId,
            ".exe",
            result.Length,
            Convert.ToHexString(SHA256.HashData(result)).ToLowerInvariant());

        var same = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            original,
            overwrite: true,
            CancellationToken.None));
        var existing = Path.Combine(fixture.SourceRoot, "existing.exe");
        await File.WriteAllTextAsync(existing, "keep");
        var collision = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            existing,
            overwrite: false,
            CancellationToken.None));

        Assert.Equal("local_destination_is_input", same.Code);
        Assert.Equal("local_destination_exists", collision.Code);
        Assert.Equal("MZ-original"u8.ToArray(), await File.ReadAllBytesAsync(original));
        Assert.Equal("keep", await File.ReadAllTextAsync(existing));
    }

    [Fact]
    public async Task Save_copy_uses_the_uploaded_source_handle_identity_instead_of_a_caller_path()
    {
        var identity = new LocalFileIdentity(42, 7, 9, 1);
        using var fixture = new LocalFixture(new SequenceFileIdentityProvider(identity, identity, identity));
        var originalBytes = "MZ-original"u8.ToArray();
        var original = fixture.WriteSource("release.exe", originalBytes);
        var destinationAlias = fixture.WriteSource("RELEAS~1.EXE", originalBytes);
        var jobId = await fixture.Client.CreateAndUploadAsync(
            original,
            Parameters,
            progress: null,
            CancellationToken.None);
        fixture.PrepareResult("MZ-signed"u8.ToArray());
        var originalHash = SHA256.HashData(await File.ReadAllBytesAsync(original));

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            destinationAlias,
            overwrite: true,
            CancellationToken.None));

        Assert.Equal("local_destination_is_input", error.Code);
        Assert.Equal(originalHash, SHA256.HashData(await File.ReadAllBytesAsync(original)));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(destinationAlias));
    }

    [Fact]
    public async Task Missing_trusted_source_identity_allows_create_new_but_never_overwrite()
    {
        using var fixture = new LocalFixture(new SequenceFileIdentityProvider((LocalFileIdentity?)null));
        var original = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        var jobId = await fixture.Client.CreateAndUploadAsync(
            original,
            Parameters,
            progress: null,
            CancellationToken.None);
        var result = "MZ-signed"u8.ToArray();
        fixture.PrepareResult(result);
        var existing = fixture.WriteSource("existing.exe", "keep"u8.ToArray());

        var overwrite = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            existing,
            overwrite: true,
            CancellationToken.None));
        var created = Path.Combine(fixture.SourceRoot, "created.exe");
        await fixture.Client.SaveSignedCopyAsync(
            jobId,
            created,
            overwrite: true,
            CancellationToken.None);

        Assert.Equal("local_destination_identity_unavailable", overwrite.Code);
        Assert.Equal("keep", await File.ReadAllTextAsync(existing));
        Assert.Equal(result, await File.ReadAllBytesAsync(created));
    }

    [Fact]
    public async Task Overwrite_rejects_when_the_uploaded_source_path_resolves_to_a_different_identity()
    {
        var acceptedIdentity = new LocalFileIdentity(42, 7, 9, 1);
        var replacementIdentity = acceptedIdentity with { FileIdLow = 10 };
        using var fixture = new LocalFixture(new SequenceFileIdentityProvider(
            acceptedIdentity,
            replacementIdentity));
        var original = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        var jobId = await fixture.Client.CreateAndUploadAsync(
            original,
            Parameters,
            progress: null,
            CancellationToken.None);
        fixture.PrepareResult("MZ-signed"u8.ToArray());
        var destination = fixture.WriteSource("existing.exe", "keep"u8.ToArray());

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            destination,
            overwrite: true,
            CancellationToken.None));

        Assert.Equal("local_source_changed", error.Code);
        Assert.Equal("keep", await File.ReadAllTextAsync(destination));
        Assert.Equal("MZ-original"u8.ToArray(), await File.ReadAllBytesAsync(original));
    }

    [Fact]
    public async Task Publish_rechecks_an_existing_destination_replaced_with_a_source_hardlink()
    {
        var files = new FaultingLocalJobFileAccess();
        using var fixture = new LocalFixture(fileAccess: files);
        var originalBytes = "MZ-original"u8.ToArray();
        var original = fixture.WriteSource("release.exe", originalBytes);
        var jobId = await fixture.Client.CreateAndUploadAsync(
            original,
            Parameters,
            progress: null,
            CancellationToken.None);
        fixture.PrepareResult("MZ-signed"u8.ToArray());
        var destination = fixture.WriteSource("existing.exe", "keep"u8.ToArray());
        var originalIdentity = GetIdentity(original);
        var originalHash = SHA256.HashData(originalBytes);
        files.BeforePublish = (_, target, _) =>
        {
            File.Delete(target);
            CreateHardLink(target, original);
        };

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            destination,
            overwrite: true,
            CancellationToken.None));

        Assert.Equal("local_destination_is_input", error.Code);
        Assert.Equal(originalHash, SHA256.HashData(await File.ReadAllBytesAsync(original)));
        Assert.True(originalIdentity.RefersToSameFile(GetIdentity(original)));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(destination));
        Assert.Empty(Directory.GetFiles(fixture.SourceRoot, ".simplysign-*.part"));
    }

    [Fact]
    public async Task Released_accepted_source_allows_create_new_but_disables_overwrite()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);
        fixture.PrepareResult("MZ-signed"u8.ToArray());
        var release = typeof(LocalJobClient).GetMethod("ReleaseAcceptedSource")
            ?? throw new Xunit.Sdk.XunitException("LocalJobClient must expose accepted-source release ownership.");

        release.Invoke(fixture.Client, [jobId]);
        release.Invoke(fixture.Client, [jobId]);

        var existing = fixture.WriteSource("existing.exe", "keep"u8.ToArray());
        var overwrite = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            existing,
            overwrite: true,
            CancellationToken.None));
        var created = Path.Combine(fixture.SourceRoot, "created.exe");
        await fixture.Client.SaveSignedCopyAsync(
            jobId,
            created,
            overwrite: true,
            CancellationToken.None);

        Assert.Equal("local_destination_identity_unavailable", overwrite.Code);
        Assert.Equal("keep", await File.ReadAllTextAsync(existing));
        Assert.Equal("MZ-signed"u8.ToArray(), await File.ReadAllBytesAsync(created));
    }

    [WindowsFact]
    public async Task Released_accepted_source_no_longer_blocks_replacing_the_old_source_on_windows()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(() =>
            File.WriteAllBytesAsync(source, "MZ-blocked"u8.ToArray()));
        Assert.Equal("MZ-original"u8.ToArray(), await File.ReadAllBytesAsync(source));

        fixture.Client.ReleaseAcceptedSource(jobId);
        File.Delete(source);
        await File.WriteAllBytesAsync(source, "MZ-replacement"u8.ToArray());

        Assert.Equal("MZ-replacement"u8.ToArray(), await File.ReadAllBytesAsync(source));
    }

    [Theory]
    [InlineData(LocalFileFailure.CreateNew)]
    [InlineData(LocalFileFailure.Read)]
    [InlineData(LocalFileFailure.Write)]
    [InlineData(LocalFileFailure.Flush)]
    [InlineData(LocalFileFailure.Publish)]
    public async Task Save_io_failures_are_path_free_and_leave_no_temp_or_partial_destination(
        LocalFileFailure failure)
    {
        var files = new FaultingLocalJobFileAccess();
        using var fixture = new LocalFixture(fileAccess: files);
        var originalBytes = "MZ-original"u8.ToArray();
        var original = fixture.WriteSource("release.exe", originalBytes);
        var jobId = await fixture.Client.CreateAndUploadAsync(
            original,
            Parameters,
            progress: null,
            CancellationToken.None);
        var result = "MZ-signed"u8.ToArray();
        fixture.PrepareResult(result);
        var destination = Path.Combine(fixture.SourceRoot, "release.signed.exe");
        files.Failure = failure;

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.SaveSignedCopyAsync(
            jobId,
            destination,
            overwrite: false,
            CancellationToken.None));

        Assert.DoesNotContain(fixture.SourceRoot, error.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(destination));
        Assert.Empty(Directory.GetFiles(fixture.SourceRoot, ".simplysign-*.part"));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(original));
        Assert.Equal(result, await File.ReadAllBytesAsync(fixture.Transport.ResultPath));
    }

    [Fact]
    public async Task Unexpected_complete_failure_is_stable_and_removes_only_the_controlled_part()
    {
        using var fixture = new LocalFixture();
        var originalBytes = "MZ-original"u8.ToArray();
        var source = fixture.WriteSource("release.exe", originalBytes);
        fixture.Transport.CompleteException = new InvalidOperationException(fixture.SourceRoot);

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("local_job_unavailable", error.Code);
        Assert.DoesNotContain(fixture.SourceRoot, error.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(fixture.Transport.PartPath));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(source));
    }

    [Fact]
    public async Task Retry_after_a_lost_complete_response_reuses_the_same_submission_state()
    {
        using var fixture = new LocalFixture();
        var originalBytes = "MZ-original"u8.ToArray();
        var source = fixture.WriteSource("release.exe", originalBytes);
        fixture.Transport.PromoteThenFailCompleteOnce = true;

        var first = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));
        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);

        Assert.Equal("local_job_unavailable", first.Code);
        Assert.Equal(fixture.Transport.JobId, jobId);
        Assert.Equal(1, fixture.Transport.CreateCalls);
        Assert.Equal(2, fixture.Transport.CompletedRequests.Count);
        Assert.Equal(
            fixture.Transport.CompletedRequests[0],
            fixture.Transport.CompletedRequests[1]);
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(source));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(fixture.Transport.InputPath));
    }

    [Fact]
    public async Task Ambiguous_internal_error_retries_the_same_completed_submission()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", "MZ-internal-error"u8.ToArray());
        fixture.Transport.CompleteErrorCodes.Enqueue("internal_error");

        var first = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));
        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);

        Assert.Equal("internal_error", first.Code);
        Assert.Equal(fixture.Transport.JobId, jobId);
        Assert.Equal(1, fixture.Transport.CreateCalls);
        Assert.Equal(2, fixture.Transport.CompletedRequests.Count);
        Assert.Equal(
            fixture.Transport.CompletedRequests[0],
            fixture.Transport.CompletedRequests[1]);
    }

    [Fact]
    public async Task Retry_after_a_lost_create_response_reuses_the_same_request()
    {
        using var fixture = new LocalFixture();
        var originalBytes = "MZ-original"u8.ToArray();
        var source = fixture.WriteSource("release.exe", originalBytes);
        fixture.Transport.FailCreateOnce = true;

        var first = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));
        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);

        Assert.Equal("local_job_unavailable", first.Code);
        Assert.Equal(fixture.Transport.JobId, jobId);
        Assert.Equal(2, fixture.Transport.CreateRequests.Count);
        Assert.Equal(fixture.Transport.CreateRequests[0], fixture.Transport.CreateRequests[1]);
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(source));
    }

    [Fact]
    public async Task Definitive_complete_rejection_retires_pending_state_before_a_new_retry()
    {
        var identities = new RecordingFileIdentityProvider();
        using var fixture = new LocalFixture(identities);
        var originalBytes = "MZ-original"u8.ToArray();
        var source = fixture.WriteSource("release.exe", originalBytes);
        fixture.Transport.CompleteErrorCodes.Enqueue("local_job_unavailable");
        fixture.Transport.CompleteErrorCodes.Enqueue("local_upload_expired");

        var transient = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));
        var definitive = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("local_job_unavailable", transient.Code);
        Assert.Equal("local_upload_expired", definitive.Code);
        Assert.False(File.Exists(fixture.Transport.PartPath));
        Assert.All(identities.Handles, handle => Assert.True(handle.IsClosed));

        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);

        Assert.Equal(fixture.Transport.JobId, jobId);
        Assert.Equal(2, fixture.Transport.CreateRequests.Count);
        Assert.NotEqual(
            fixture.Transport.CreateRequests[0].RequestId,
            fixture.Transport.CreateRequests[1].RequestId);
    }

    [Fact]
    public async Task Definitive_create_rejection_retires_pending_request_before_a_new_retry()
    {
        var identities = new RecordingFileIdentityProvider();
        using var fixture = new LocalFixture(identities);
        var source = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        fixture.Transport.CreateErrorCodes.Enqueue("local_job_unavailable");
        fixture.Transport.CreateErrorCodes.Enqueue("local_request_conflict");

        var transient = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));
        var definitive = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("local_job_unavailable", transient.Code);
        Assert.Equal("local_request_conflict", definitive.Code);
        Assert.All(identities.Handles, handle => Assert.True(handle.IsClosed));

        var jobId = await fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None);

        Assert.Equal(fixture.Transport.JobId, jobId);
        Assert.Equal(3, fixture.Transport.CreateRequests.Count);
        Assert.Equal(
            fixture.Transport.CreateRequests[0].RequestId,
            fixture.Transport.CreateRequests[1].RequestId);
        Assert.NotEqual(
            fixture.Transport.CreateRequests[1].RequestId,
            fixture.Transport.CreateRequests[2].RequestId);
    }

    [Fact]
    public async Task Part_delete_failure_is_reported_and_retains_the_auditable_artifact()
    {
        var files = new FaultingLocalJobFileAccess { Failure = LocalFileFailure.Delete };
        using var fixture = new LocalFixture(fileAccess: files);
        var originalBytes = "MZ-original"u8.ToArray();
        var source = fixture.WriteSource("release.exe", originalBytes);
        fixture.Transport.CompleteException = new InvalidOperationException(fixture.SourceRoot);

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("local_upload_cleanup_failed", error.Code);
        Assert.DoesNotContain(fixture.SourceRoot, error.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(fixture.Transport.PartPath));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(fixture.Transport.PartPath));
        Assert.Equal(originalBytes, await File.ReadAllBytesAsync(source));
    }

    [Fact]
    public async Task Dangling_reparse_part_is_rejected_during_cleanup_without_following_its_target()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        var outside = Path.Combine(fixture.SourceRoot, "missing-target.exe");
        fixture.Transport.BeforeComplete = () =>
        {
            File.Delete(fixture.Transport.PartPath);
            Directory.CreateSymbolicLink(fixture.Transport.PartPath, outside);
        };
        fixture.Transport.CompleteException = new InvalidOperationException(fixture.SourceRoot);

        var error = await Assert.ThrowsAsync<LocalJobException>(() => fixture.Client.CreateAndUploadAsync(
            source,
            Parameters,
            progress: null,
            CancellationToken.None));

        Assert.Equal("local_upload_cleanup_failed", error.Code);
        Assert.DoesNotContain(fixture.SourceRoot, error.Message, StringComparison.Ordinal);
        Assert.NotNull(new FileInfo(fixture.Transport.PartPath).LinkTarget);
        Assert.False(File.Exists(outside));
    }

    [Fact]
    public async Task Async_dispose_cancels_and_joins_a_blocking_copy_and_gate_waiter()
    {
        var files = new FaultingLocalJobFileAccess { BlockWrites = true };
        using var fixture = new LocalFixture(fileAccess: files);
        var firstSource = fixture.WriteSource("first.exe", CreatePeBytes(2 * 1024 * 1024));
        var secondSource = fixture.WriteSource("second.exe", "MZ-second"u8.ToArray());
        var first = fixture.Client.CreateAndUploadAsync(firstSource, Parameters, null, default);
        await files.WriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var waiter = fixture.Client.CreateAndUploadAsync(secondSource, Parameters, null, default);

        var dispose = DisposeOwnerAsync(fixture.Client);
        await Task.Delay(20);
        var returnedBeforeCopyJoined = dispose.IsCompleted;
        files.ReleaseBlockedWrite();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => first.WaitAsync(TimeSpan.FromSeconds(1)));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => waiter.WaitAsync(TimeSpan.FromSeconds(1)));
        await dispose.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(returnedBeforeCopyJoined);
    }

    [Fact]
    public async Task Async_dispose_cancels_and_joins_a_blocking_complete()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        fixture.Transport.BlockComplete = true;
        var submit = fixture.Client.CreateAndUploadAsync(source, Parameters, null, default);
        await fixture.Transport.CompleteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var dispose = DisposeOwnerAsync(fixture.Client);
        await Task.Delay(20);
        var returnedBeforeCompleteJoined = dispose.IsCompleted;
        fixture.Transport.ReleaseComplete();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => submit.WaitAsync(TimeSpan.FromSeconds(1)));
        await dispose.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(returnedBeforeCompleteJoined);
    }

    [Fact]
    public async Task Async_dispose_cancels_and_joins_a_blocking_save()
    {
        using var fixture = new LocalFixture();
        var source = fixture.WriteSource("release.exe", "MZ-original"u8.ToArray());
        var jobId = await fixture.Client.CreateAndUploadAsync(source, Parameters, null, default);
        fixture.PrepareResult("MZ-signed"u8.ToArray());
        fixture.Transport.BlockResult = true;
        var destination = Path.Combine(fixture.SourceRoot, "release.signed.exe");
        var save = fixture.Client.SaveSignedCopyAsync(jobId, destination, false, default);
        await fixture.Transport.ResultStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var dispose = DisposeOwnerAsync(fixture.Client);
        await Task.Delay(20);
        var returnedBeforeSaveJoined = dispose.IsCompleted;
        fixture.Transport.ReleaseResult();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => save.WaitAsync(TimeSpan.FromSeconds(1)));
        await dispose.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(returnedBeforeSaveJoined);
        Assert.False(File.Exists(destination));
    }

    private static Task DisposeOwnerAsync(object owner) =>
        owner is IAsyncDisposable asyncOwner
            ? asyncOwner.DisposeAsync().AsTask()
            : Task.Run(((IDisposable)owner).Dispose);

    private static byte[] CreatePeBytes(int length)
    {
        var bytes = new byte[length];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        return bytes;
    }

    private static LocalFileIdentity GetIdentity(string path)
    {
        using var stream = NoFollowFile.OpenRead(path, FileShare.ReadWrite | FileShare.Delete, 4096);
        Assert.True(PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(stream.SafeFileHandle, out var identity));
        return identity;
    }

    private static void CreateHardLink(string path, string existingPath)
    {
        var succeeded = OperatingSystem.IsWindows()
            ? CreateHardLinkWindows(path, existingPath, IntPtr.Zero)
            : Link(existingPath, path) == 0;
        Assert.True(succeeded, $"hardlink creation failed: {Marshal.GetLastPInvokeError()}");
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkWindows(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int Link(string existingPath, string newPath);

    private sealed class LocalFixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "SimplySignAuto-agent-local-" + Guid.NewGuid().ToString("N"));

        public LocalFixture(
            ILocalFileIdentityProvider? identities = null,
            ILocalJobFileAccess? fileAccess = null)
        {
            SourceRoot = Path.Combine(_root, "source");
            var spool = Path.Combine(_root, "spool");
            Directory.CreateDirectory(SourceRoot);
            Directory.CreateDirectory(spool);
            Transport = new FakeTransport(spool);
            Client = new LocalJobClient(Transport, spool, identities, fileAccess);
        }

        public string SourceRoot { get; }
        public FakeTransport Transport { get; }
        public LocalJobClient Client { get; }

        public string WriteSource(string name, byte[] bytes)
        {
            var path = Path.Combine(SourceRoot, name);
            File.WriteAllBytes(path, bytes);
            return path;
        }

        public void PrepareResult(byte[] result)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Transport.ResultPath)!);
            File.WriteAllBytes(Transport.ResultPath, result);
            Transport.ResultMetadata = new LocalJobResultMetadata(
                Guid.NewGuid(),
                Transport.JobId,
                ".exe",
                result.Length,
                Convert.ToHexString(SHA256.HashData(result)).ToLowerInvariant());
        }

        public void Dispose()
        {
            Client.Dispose();
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class FakeTransport : ILocalJobTransport
    {
        private const string Lease = "00112233445566778899aabbccddeeff";
        private readonly string _spool;

        public FakeTransport(string spool)
        {
            _spool = spool;
            JobId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        }

        public Guid JobId { get; }
        public LocalJobCreateRequest? CreateRequest { get; private set; }
        public bool Completed { get; private set; }
        public string PartPath => Path.Combine(_spool, JobId.ToString("N"), "input.exe.part");
        public string InputPath => Path.Combine(_spool, JobId.ToString("N"), "input.exe");
        public string ResultPath => Path.Combine(_spool, JobId.ToString("N"), "result.exe");
        public LocalJobResultMetadata? ResultMetadata { get; set; }
        public Exception? CompleteException { get; set; }
        public int CreateCalls { get; private set; }
        public List<LocalJobCreateRequest> CreateRequests { get; } = [];
        public List<LocalJobUploadCompleted> CompletedRequests { get; } = [];
        public bool PromoteThenFailCompleteOnce { get; set; }
        public bool FailCreateOnce { get; set; }
        public Queue<string> CreateErrorCodes { get; } = new();
        public Queue<string> CompleteErrorCodes { get; } = new();
        public Action? BeforeComplete { get; set; }
        public bool BlockComplete { get; set; }
        public bool BlockResult { get; set; }
        public TaskCompletionSource CompleteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ResultStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource CompleteRelease { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource ResultRelease { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<LocalJobCreateOutcome> CreateLocalJobAsync(
            LocalJobCreateRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CreateCalls++;
            CreateRequests.Add(request);
            CreateRequest = request;
            if (CreateErrorCodes.TryDequeue(out var createError))
            {
                throw new LocalJobException(createError);
            }

            if (FailCreateOnce)
            {
                FailCreateOnce = false;
                throw new LocalJobException("local_job_unavailable");
            }

            Directory.CreateDirectory(Path.Combine(_spool, JobId.ToString("N")));
            return Task.FromResult(LocalJobCreateOutcome.FromLease(new LocalJobUploadLease(
                request.RequestId,
                JobId,
                Lease,
                $"{JobId:N}/input{request.Extension}.part",
                DateTimeOffset.UtcNow.AddMinutes(10))));
        }

        public async Task<LocalJobAccepted> CompleteLocalJobAsync(
            LocalJobUploadCompleted completed,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CompletedRequests.Add(completed);
            if (BlockComplete)
            {
                CompleteStarted.TrySetResult();
                await CompleteRelease.Task;
                cancellationToken.ThrowIfCancellationRequested();
            }

            BeforeComplete?.Invoke();

            if (CompleteErrorCodes.TryDequeue(out var completeError))
            {
                throw new LocalJobException(completeError);
            }

            if (CompleteException is { } error)
            {
                throw error;
            }

            Completed = true;
            if (File.Exists(PartPath))
            {
                File.Move(PartPath, InputPath, overwrite: false);
            }

            if (PromoteThenFailCompleteOnce)
            {
                PromoteThenFailCompleteOnce = false;
                throw new LocalJobException("local_job_unavailable");
            }

            return new LocalJobAccepted(completed.RequestId, completed.JobId);
        }

        public async Task<LocalJobResultMetadata> GetLocalResultAsync(
            LocalJobResultRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (BlockResult)
            {
                ResultStarted.TrySetResult();
                await ResultRelease.Task;
                cancellationToken.ThrowIfCancellationRequested();
            }

            var metadata = ResultMetadata ?? throw new InvalidOperationException();
            return metadata with { RequestId = request.RequestId };
        }

        public void ReleaseComplete() => CompleteRelease.TrySetResult();

        public void ReleaseResult() => ResultRelease.TrySetResult();
    }

    private sealed class InlineProgress(Action<LocalCopyProgress> report) : IProgress<LocalCopyProgress>
    {
        public void Report(LocalCopyProgress value) => report(value);
    }

    private sealed class SequenceFileIdentityProvider(params LocalFileIdentity?[] identities) : ILocalFileIdentityProvider
    {
        private readonly Queue<LocalFileIdentity?> _identities = new(identities);

        public bool TryGetIdentity(SafeFileHandle handle, out LocalFileIdentity identity)
        {
            var value = _identities.Dequeue();
            identity = value ?? default;
            return value is not null;
        }
    }

    private sealed class RecordingFileIdentityProvider : ILocalFileIdentityProvider
    {
        public List<SafeFileHandle> Handles { get; } = [];

        public bool TryGetIdentity(SafeFileHandle handle, out LocalFileIdentity identity)
        {
            Handles.Add(handle);
            return PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(handle, out identity);
        }
    }

    public enum LocalFileFailure
    {
        CreateNew,
        Read,
        Write,
        Flush,
        Publish,
        Delete,
    }

    private sealed class FaultingLocalJobFileAccess : ILocalJobFileAccess
    {
        private readonly TaskCompletionSource _writeRelease =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public LocalFileFailure? Failure { get; set; }

        public bool BlockWrites { get; set; }

        public TaskCompletionSource WriteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Action<string, string, bool>? BeforePublish { get; set; }

        public void DeleteControlledPart(string path)
        {
            if (Failure == LocalFileFailure.Delete)
            {
                throw new UnauthorizedAccessException(path);
            }

            File.Delete(path);
        }

        public Stream OpenRead(string path)
        {
            var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Failure == LocalFileFailure.Read
                ? new ThrowingStream(stream, throwOnRead: true, throwOnWrite: false)
                : stream;
        }

        public Stream CreateNew(string path)
        {
            if (Failure == LocalFileFailure.CreateNew)
            {
                throw new IOException(path);
            }

            var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            if (Failure == LocalFileFailure.Write)
            {
                return new ThrowingStream(stream, throwOnRead: false, throwOnWrite: true);
            }

            return BlockWrites
                ? new BlockingWriteStream(stream, WriteStarted, _writeRelease.Task)
                : stream;
        }

        public void FlushToDisk(Stream stream)
        {
            if (Failure == LocalFileFailure.Flush)
            {
                throw new UnauthorizedAccessException("synthetic-path");
            }

            stream.Flush();
        }

        public void Publish(string source, string destination, bool overwrite, Action finalValidation)
        {
            BeforePublish?.Invoke(source, destination, overwrite);
            finalValidation();
            if (Failure == LocalFileFailure.Publish)
            {
                throw new InvalidOperationException(source);
            }

            File.Move(source, destination, overwrite);
        }

        public void ReleaseBlockedWrite() => _writeRelease.TrySetResult();
    }

    private sealed class BlockingWriteStream(
        Stream inner,
        TaskCompletionSource started,
        Task release) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            started.TrySetResult();
            await release;
            cancellationToken.ThrowIfCancellationRequested();
            await inner.WriteAsync(buffer, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync();
            GC.SuppressFinalize(this);
        }
    }

    private sealed class ThrowingStream(Stream inner, bool throwOnRead, bool throwOnWrite) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) =>
            throwOnRead ? throw new IOException("synthetic-path") : inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (throwOnWrite)
            {
                throw new IOException("synthetic-path");
            }

            inner.Write(buffer, offset, count);
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            throwOnRead
                ? ValueTask.FromException<int>(new IOException("synthetic-path"))
                : inner.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            throwOnWrite
                ? ValueTask.FromException(new IOException("synthetic-path"))
                : inner.WriteAsync(buffer, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync();
            GC.SuppressFinalize(this);
        }
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows file-sharing semantics.";
            }
        }
    }
}
