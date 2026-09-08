using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class JobCleanupServiceTests
{
    [Fact]
    public async Task Cleanup_skips_permanent_job_and_expires_due_finite_job()
    {
        using var fixture = new CleanupFixture();
        var jobs = fixture.CreateStore();
        var spool = new SpoolStore(fixture.SpoolPath);
        var permanent = await jobs.CreateAsync(CreateJob(null));
        var finite = await jobs.CreateAsync(CreateJob(DateTimeOffset.UtcNow.AddMinutes(-1)));
        await File.WriteAllTextAsync(spool.GetInputPath(permanent.Id, permanent.Extension), "permanent");
        await File.WriteAllTextAsync(spool.GetInputPath(finite.Id, finite.Extension), "finite");
        var service = new JobCleanupService(
            jobs,
            spool,
            new JobCompletionNotifier(jobs),
            TimeProvider.System,
            NullLogger<JobCleanupService>.Instance);

        var count = await service.CleanupExpiredAsync(CancellationToken.None);

        Assert.Equal(1, count);
        Assert.Equal(JobState.Queued, (await jobs.GetAsync(permanent.Id))!.State);
        Assert.Null((await jobs.GetAsync(permanent.Id))!.ExpiresAt);
        Assert.True(Directory.Exists(Path.Combine(spool.Root, permanent.Id.ToString("N"))));
        Assert.Equal(JobState.Expired, (await jobs.GetAsync(finite.Id))!.State);
        Assert.False(Directory.Exists(Path.Combine(spool.Root, finite.Id.ToString("N"))));
    }

    private static Job CreateJob(DateTimeOffset? expiresAt) =>
        new(Guid.NewGuid(), JobState.Queued, new AuthenticodeParameters("52A1B4C9", "sha256", false))
        {
            OriginalName = "payload.exe",
            Extension = ".exe",
            InputSha256 = Sha256(Guid.NewGuid().ToString("N")),
            ExpiresAt = expiresAt,
        };

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private sealed class CleanupFixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));
        private readonly List<SqliteJobStore> _stores = [];

        public string DatabasePath => Path.Combine(_root, "jobs.db");
        public string SpoolPath => Path.Combine(_root, "spool");

        public SqliteJobStore CreateStore()
        {
            var store = new SqliteJobStore(DatabasePath);
            _stores.Add(store);
            return store;
        }

        public void Dispose()
        {
            foreach (var store in _stores)
            {
                store.Dispose();
            }

            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }
}
