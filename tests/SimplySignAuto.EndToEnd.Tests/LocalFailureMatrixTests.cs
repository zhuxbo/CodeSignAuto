using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class LocalFailureMatrixTests
{
    [Fact]
    public async Task Expired_lease_is_rejected_and_cleanup_removes_its_real_spool_part()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        await using var harness = await StartWithClockAsync(clock);
        var request = CreateRequest(EndToEndFixtures.UnsignedPortableExecutable.LongLength);
        var create = await harness.Agent.Client.CreateLocalJobAsync(request, CancellationToken.None);
        var lease = Assert.IsType<LocalJobUploadLease>(create.Lease);
        var partPath = Path.Combine(harness.Spool.Root, lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        var bytes = EndToEndFixtures.UnsignedPortableExecutable;
        await File.WriteAllBytesAsync(partPath, bytes);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        clock.Advance(LocalJobUploadCoordinator.LeaseDuration + TimeSpan.FromSeconds(1));

        var error = await Assert.ThrowsAsync<LocalJobException>(() =>
            harness.Agent.Client.CompleteLocalJobAsync(
                new LocalJobUploadCompleted(request.RequestId, lease.JobId, lease.LeaseId, bytes.LongLength, hash),
                CancellationToken.None));

        Assert.Equal("local_upload_expired", error.Code);
        await harness.Services.GetRequiredService<JobCleanupService>().RunCleanupCycleAsync(CancellationToken.None);
        Assert.False(File.Exists(partPath));
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Fact]
    public async Task Caller_cancel_during_real_local_copy_deletes_part_and_never_creates_a_job()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync();
        var sourceDirectory = Directory.CreateDirectory(Path.Combine(harness.Root, "cancel-copy"));
        var sourcePath = Path.Combine(sourceDirectory.FullName, "large.exe");
        var bytes = EndToEndFixtures.UnsignedPortableExecutable
            .Concat(new byte[2 * 1024 * 1024])
            .ToArray();
        await File.WriteAllBytesAsync(sourcePath, bytes);
        using var cancellation = new CancellationTokenSource();
        var progress = new InlineProgress(value =>
        {
            if (value.BytesCopied > 0)
            {
                cancellation.Cancel();
            }
        });
        await using var local = new LocalJobClient(harness.Agent.Client, harness.Spool.Root);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => local.CreateAndUploadAsync(
            sourcePath,
            new AuthenticodeParameters("AA00", "sha256", false),
            progress,
            cancellation.Token));

        Assert.Empty(await harness.Jobs.GetAllAsync());
        Assert.Empty(Directory.EnumerateFiles(harness.Spool.Root, "*.part", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Cancellation_after_the_first_real_save_chunk_removes_temp_and_publishes_nothing()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync();
        var baseline = await harness.Agent.Client.GetTerminalJobDeltaAsync(null, null, CancellationToken.None);
        var sourceDirectory = Directory.CreateDirectory(Path.Combine(harness.Root, "cancel-save-source"));
        var sourcePath = Path.Combine(sourceDirectory.FullName, "release.exe");
        var source = EndToEndFixtures.UnsignedPortableExecutable
            .Concat(new byte[2 * LocalJobClient.CopyBufferSize])
            .ToArray();
        await File.WriteAllBytesAsync(sourcePath, source);
        using var cancellation = new CancellationTokenSource();
        var files = new CancelAfterFirstSaveChunkFileAccess(cancellation);
        await using var local = new LocalJobClient(
            harness.Agent.Client,
            harness.Spool.Root,
            fileIdentities: null,
            files);
        var jobId = await local.CreateAndUploadAsync(
            sourcePath,
            new AuthenticodeParameters("AA00", "sha256", false),
            null,
            CancellationToken.None);
        _ = await harness.WaitForStateAsync(jobId, "succeeded");
        var destination = Path.Combine(harness.Root, "cancelled-save.exe");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            local.SaveSignedCopyAsync(jobId, destination, overwrite: false, cancellation.Token));

        var observed = await files.FirstChunk.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(observed.ExistedAfterWrite);
        Assert.InRange(observed.LengthAfterWrite, 1, LocalJobClient.CopyBufferSize);
        Assert.False(File.Exists(destination));
        Assert.False(File.Exists(observed.Path));
        Assert.Empty(Directory.EnumerateFiles(harness.Root, ".simplysign-*.part", SearchOption.AllDirectories));
        var delta = await harness.Agent.Client.GetTerminalJobDeltaAsync(
            baseline.Watermark,
            null,
            CancellationToken.None);
        Assert.Equal(jobId, Assert.Single(delta.Items).Item.JobId);
        var repeated = await harness.Agent.Client.GetTerminalJobDeltaAsync(
            delta.Watermark,
            null,
            CancellationToken.None);
        Assert.Empty(repeated.Items);
        Assert.Single(harness.Agent.ReceivedCommands);
    }

    [Fact]
    public async Task Restart_preserves_unexpired_lease_quarantines_orphan_then_expires_only_the_lease()
    {
        var root = Directory.CreateTempSubdirectory("SSA-E2E-LOCAL-RESTART-").FullName;
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var protector = new EndToEndHarness.TestLeaseProtector();
        var request = CreateRequest(EndToEndFixtures.UnsignedPortableExecutable.LongLength);
        Guid leasedJobId;
        string leasedDirectory;
        try
        {
            await using (var first = await EndToEndHarness.StartAsync(
                root,
                deleteRoot: false,
                timeProvider: clock,
                localLeaseProtector: protector))
            {
                await first.StartAgentAsync();
                var created = await first.Agent.Client.CreateLocalJobAsync(request, CancellationToken.None);
                leasedJobId = Assert.IsType<LocalJobUploadLease>(created.Lease).JobId;
                leasedDirectory = Path.Combine(first.Spool.Root, leasedJobId.ToString("N"));
                var orphan = Path.Combine(first.Spool.Root, Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(orphan);
                await File.WriteAllTextAsync(Path.Combine(orphan, "sentinel.txt"), "orphan-preserved");
            }

            await using (var second = await EndToEndHarness.StartAsync(
                root,
                deleteRoot: false,
                timeProvider: clock,
                localLeaseProtector: protector))
            {
                Assert.True(Directory.Exists(leasedDirectory));
                Assert.Contains(
                    Directory.EnumerateFiles(Path.Combine(root, "quarantine"), "sentinel.txt", SearchOption.AllDirectories),
                    path => File.ReadAllText(path) == "orphan-preserved");
                await second.StartAgentAsync();
                var replay = await second.Agent.Client.CreateLocalJobAsync(request, CancellationToken.None);
                Assert.Equal(leasedJobId, Assert.IsType<LocalJobUploadLease>(replay.Lease).JobId);
            }

            clock.Advance(LocalJobUploadCoordinator.LeaseDuration + TimeSpan.FromSeconds(1));
            await using (var third = await EndToEndHarness.StartAsync(
                root,
                deleteRoot: true,
                timeProvider: clock,
                localLeaseProtector: protector))
            {
                Assert.False(Directory.Exists(leasedDirectory));
                await third.StartAgentAsync();
                var renewed = await third.Agent.Client.CreateLocalJobAsync(request, CancellationToken.None);
                Assert.NotEqual(leasedJobId, Assert.IsType<LocalJobUploadLease>(renewed.Lease).JobId);
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task<EndToEndHarness> StartWithClockAsync(MutableTimeProvider clock)
    {
        var harness = await EndToEndHarness.StartAsync(
            Directory.CreateTempSubdirectory("SSA-E2E-LOCAL-CLOCK-").FullName,
            deleteRoot: true,
            timeProvider: clock);
        await harness.StartAgentAsync();
        return harness;
    }

    private static LocalJobCreateRequest CreateRequest(long size) => new(
        Guid.NewGuid(),
        "release.exe",
        ".exe",
        size,
        SigningParameters.SerializeCanonical(
            new AuthenticodeParameters("AA00", "sha256", false)));

    private sealed class InlineProgress(Action<LocalCopyProgress> report) : IProgress<LocalCopyProgress>
    {
        public void Report(LocalCopyProgress value) => report(value);
    }

    private sealed class CancelAfterFirstSaveChunkFileAccess(CancellationTokenSource cancellation)
        : ILocalJobFileAccess
    {
        private readonly TaskCompletionSource<SaveChunkObservation> _firstChunk =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<SaveChunkObservation> FirstChunk => _firstChunk.Task;

        public Stream OpenRead(string path) => PlatformLocalJobFileAccess.Instance.OpenRead(path);

        public Stream CreateNew(string path)
        {
            var stream = PlatformLocalJobFileAccess.Instance.CreateNew(path);
            return Path.GetFileName(path).StartsWith(".simplysign-", StringComparison.Ordinal)
                ? new FirstWriteObservingStream(
                    stream,
                    () =>
                    {
                        _firstChunk.TrySetResult(new SaveChunkObservation(
                            path,
                            File.Exists(path),
                            new FileInfo(path).Length));
                        cancellation.Cancel();
                    })
                : stream;
        }

        public void FlushToDisk(Stream stream) => PlatformLocalJobFileAccess.Instance.FlushToDisk(stream);

        public void Publish(string source, string destination, bool overwrite, Action finalValidation) =>
            PlatformLocalJobFileAccess.Instance.Publish(source, destination, overwrite, finalValidation);

        public void DeleteControlledPart(string path) =>
            PlatformLocalJobFileAccess.Instance.DeleteControlledPart(path);

        private sealed class FirstWriteObservingStream(Stream inner, Action afterFirstWrite) : Stream
        {
            private int _observed;

            public override bool CanRead => inner.CanRead;
            public override bool CanSeek => inner.CanSeek;
            public override bool CanWrite => inner.CanWrite;
            public override long Length => inner.Length;
            public override long Position { get => inner.Position; set => inner.Position = value; }

            public override void Flush() => inner.Flush();

            public override Task FlushAsync(CancellationToken cancellationToken) =>
                inner.FlushAsync(cancellationToken);

            public override int Read(byte[] buffer, int offset, int count) =>
                inner.Read(buffer, offset, count);

            public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);

            public override void SetLength(long value) => inner.SetLength(value);

            public override void Write(byte[] buffer, int offset, int count)
            {
                inner.Write(buffer, offset, count);
                ObserveFirstWrite();
            }

            public override async ValueTask WriteAsync(
                ReadOnlyMemory<byte> buffer,
                CancellationToken cancellationToken = default)
            {
                await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                ObserveFirstWrite();
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
                await inner.DisposeAsync().ConfigureAwait(false);
                GC.SuppressFinalize(this);
            }

            private void ObserveFirstWrite()
            {
                if (Interlocked.Exchange(ref _observed, 1) == 0)
                {
                    afterFirstWrite();
                }
            }
        }
    }

    private sealed record SaveChunkObservation(string Path, bool ExistedAfterWrite, long LengthAfterWrite);

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now.ToUniversalTime();

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan duration) => _now += duration;
    }
}
