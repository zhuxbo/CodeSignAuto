using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class ManualJobRecoveryTests
{
    [Fact]
    public async Task Manual_restart_fails_every_unsigned_nonterminal_job_once_and_leaves_nothing_to_sign()
    {
        using var fixture = new Fixture();
        var store = fixture.Store;
        var waiting = await CreateQueuedAsync(store, "waiting");
        Assert.True(await store.TryMarkNextWaitingForAgentAsync());
        var signing = await CreateQueuedAsync(store, "signing");
        Assert.Equal(signing.Id, (await store.ClaimNextAsync(Guid.NewGuid()))!.Id);
        var verifying = await CreateQueuedAsync(store, "verifying");
        var verifyingLease = (await store.ClaimNextAsync(Guid.NewGuid()))!;
        Assert.True(await store.TryMarkVerifyingAsync(
            verifying.Id,
            verifyingLease.DispatchId!.Value,
            verifyingLease.LeaseConnectionId!.Value));
        var queued = await CreateQueuedAsync(store, "queued");

        Assert.Equal(4, await store.RecoverManualInterruptedAsync());
        Assert.Equal(0, await store.RecoverManualInterruptedAsync());

        foreach (var id in new[] { queued.Id, waiting.Id, signing.Id, verifying.Id })
        {
            var recovered = Assert.IsType<Job>(await store.GetAsync(id));
            Assert.Equal(JobState.Failed, recovered.State);
            Assert.Equal("manual_job_interrupted", recovered.ErrorCode);
            Assert.NotNull(recovered.CompletedAt);
            Assert.Null(recovered.DispatchId);
            Assert.Null(recovered.LeaseConnectionId);
            Assert.Null(recovered.ResultSize);
            Assert.Null(recovered.ResultSha256);
        }

        var history = await store.GetJobPageAsync(
            cursor: null,
            asOfUtc: DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(4, history.Items.Count(item =>
            item.State == "failed" && item.ErrorCode == "manual_job_interrupted"));
        Assert.Null(await store.ClaimNextAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task Manual_recovery_is_atomic_when_one_transition_is_rejected()
    {
        using var fixture = new Fixture();
        var first = await CreateQueuedAsync(fixture.Store, "first");
        var second = await CreateQueuedAsync(fixture.Store, "second");
        await using (var connection = await fixture.OpenDirectAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"""
                CREATE TRIGGER reject_manual_recovery
                BEFORE UPDATE OF state ON jobs
                WHEN OLD.id = '{second.Id:D}' AND NEW.error_code = 'manual_job_interrupted'
                BEGIN
                    SELECT RAISE(ABORT, 'reject manual recovery');
                END;
                """;
            await command.ExecuteNonQueryAsync();
        }

        await Assert.ThrowsAsync<SqliteException>(() =>
            fixture.Store.RecoverManualInterruptedAsync());

        Assert.Equal(JobState.Queued, (await fixture.Store.GetAsync(first.Id))!.State);
        Assert.Equal(JobState.Queued, (await fixture.Store.GetAsync(second.Id))!.State);
    }

    [Fact]
    public async Task Manual_recovery_fails_verifying_jobs_with_only_one_result_metadata_field()
    {
        using var fixture = new Fixture();
        var sizeOnly = await CreateQueuedAsync(fixture.Store, "size-only");
        var sizeOnlyLease = (await fixture.Store.ClaimNextAsync(Guid.NewGuid()))!;
        Assert.True(await fixture.Store.TryMarkVerifyingAsync(
            sizeOnly.Id,
            sizeOnlyLease.DispatchId!.Value,
            sizeOnlyLease.LeaseConnectionId!.Value));

        var hashOnly = await CreateQueuedAsync(fixture.Store, "hash-only");
        var hashOnlyLease = (await fixture.Store.ClaimNextAsync(Guid.NewGuid()))!;
        Assert.True(await fixture.Store.TryMarkVerifyingAsync(
            hashOnly.Id,
            hashOnlyLease.DispatchId!.Value,
            hashOnlyLease.LeaseConnectionId!.Value));

        await using (var connection = await fixture.OpenDirectAsync())
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                UPDATE jobs SET result_size = 13 WHERE id = $sizeOnlyId;
                UPDATE jobs SET result_sha256 = $resultSha256 WHERE id = $hashOnlyId;
                """;
            command.Parameters.AddWithValue("$sizeOnlyId", sizeOnly.Id.ToString("D"));
            command.Parameters.AddWithValue("$hashOnlyId", hashOnly.Id.ToString("D"));
            command.Parameters.AddWithValue("$resultSha256", Sha256("signed-result"));
            await command.ExecuteNonQueryAsync();
        }

        Assert.Equal(2, await fixture.Store.RecoverManualInterruptedAsync());
        Assert.Equal(0, await fixture.Store.RecoverActiveLeasesAsync());
        Assert.Null(await fixture.Store.ClaimNextAsync(Guid.NewGuid()));

        foreach (var id in new[] { sizeOnly.Id, hashOnly.Id })
        {
            var recovered = Assert.IsType<Job>(await fixture.Store.GetAsync(id));
            Assert.Equal(JobState.Failed, recovered.State);
            Assert.Equal("manual_job_interrupted", recovered.ErrorCode);
            Assert.Null(recovered.ResultSize);
            Assert.Null(recovered.ResultSha256);
        }
    }

    [Fact]
    public async Task Manual_recovery_preserves_complete_verifying_evidence_for_existing_recovery_validation()
    {
        using var fixture = new Fixture();
        var job = await CreateQueuedAsync(fixture.Store, "complete");
        var connectionId = Guid.NewGuid();
        var lease = (await fixture.Store.ClaimNextAsync(connectionId))!;
        Assert.True(await fixture.Store.TryMarkVerifyingAsync(
            job.Id,
            lease.DispatchId!.Value,
            connectionId));
        var resultHash = Sha256("signed-result");
        Assert.True(await fixture.Store.TryRecordCompletionAsync(
            job.Id,
            lease.DispatchId.Value,
            connectionId,
            resultSize: 13,
            resultSha256: resultHash));

        Assert.Equal(0, await fixture.Store.RecoverManualInterruptedAsync());
        Assert.Equal(1, await fixture.Store.RecoverActiveLeasesAsync());

        var pending = Assert.IsType<Job>(await fixture.Store.GetNextPendingCompletionAsync());
        Assert.Equal(job.Id, pending.Id);
        Assert.Equal(JobState.Verifying, pending.State);
        Assert.Equal(13, pending.ResultSize);
        Assert.Equal(resultHash, pending.ResultSha256);
        Assert.Null(pending.DispatchId);
        Assert.Null(pending.LeaseConnectionId);
    }

    private static Task<Job> CreateQueuedAsync(SqliteJobStore store, string marker) =>
        store.CreateAsync(new Job(
            Guid.NewGuid(),
            JobState.Queued,
            new AuthenticodeParameters("52A1B4C9", "sha256", false))
        {
            OriginalName = marker + ".exe",
            Extension = ".exe",
            InputSize = marker.Length,
            InputSha256 = Sha256(marker),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(168),
        });

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(),
            "CodeSignAuto.ManualRecovery.Tests",
            Guid.NewGuid().ToString("N"));

        public Fixture() => Store = new SqliteJobStore(Path.Combine(_root, "jobs.db"));

        public SqliteJobStore Store { get; }

        public async Task<SqliteConnection> OpenDirectAsync()
        {
            var connection = new SqliteConnection($"Data Source={Path.Combine(_root, "jobs.db")}");
            await connection.OpenAsync();
            return connection;
        }

        public void Dispose()
        {
            Store.Dispose();
            using var connection = new SqliteConnection($"Data Source={Path.Combine(_root, "jobs.db")}");
            SqliteConnection.ClearPool(connection);
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }
}
