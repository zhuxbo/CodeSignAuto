using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class SqliteJobDispatchTests
{
    [Fact]
    public async Task Concurrent_claims_are_atomic_fifo_and_create_unique_nonempty_leases()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        var first = await store.CreateAsync(NewJob(inputSize: 11));
        await Task.Delay(2);
        var second = await store.CreateAsync(NewJob(inputSize: 22));
        var connections = new[] { Guid.NewGuid(), Guid.NewGuid() };

        var claims = (await Task.WhenAll(connections.Select(connection => store.ClaimNextAsync(connection))))
            .Where(job => job is not null)
            .Cast<Job>()
            .OrderBy(job => job.CreatedAt)
            .ToArray();

        Assert.Equal([first.Id, second.Id], claims.Select(job => job.Id));
        Assert.All(claims, job => Assert.NotEqual(Guid.Empty, job.DispatchId));
        Assert.Equal(2, claims.Select(job => job.DispatchId).Distinct().Count());
        Assert.All(claims, job => Assert.Equal(1, job.AttemptCount));
        Assert.Equal([11, 22], claims.Select(job => job.InputSize));
    }

    [Fact]
    public async Task Attempt_increments_only_at_claim_and_no_third_claim_is_possible_across_reopen()
    {
        using var fixture = new Fixture();
        var connection = Guid.NewGuid();
        var store = fixture.CreateStore();
        var created = await store.CreateAsync(NewJob(inputSize: 7));
        var first = (await store.ClaimNextAsync(connection))!;

        Assert.True(await store.TryRequeueLeaseAsync(first.Id, first.DispatchId!.Value, connection));
        var secondStore = fixture.CreateStore();
        var second = (await secondStore.ClaimNextAsync(connection))!;

        Assert.Equal(2, second.AttemptCount);
        Assert.NotEqual(first.DispatchId, second.DispatchId);
        Assert.False(await secondStore.TryRequeueLeaseAsync(second.Id, second.DispatchId!.Value, connection));
        Assert.True(await secondStore.TryFailLeaseAsync(
            second.Id,
            second.DispatchId.Value,
            connection,
            "recovery_exhausted",
            "Signing recovery was exhausted."));
        Assert.Null(await secondStore.ClaimNextAsync(connection));
        Assert.Equal(JobState.Failed, (await secondStore.GetAsync(created.Id))!.State);
    }

    [Fact]
    public async Task Exact_connection_dispatch_and_expected_state_guard_every_completion_step()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        await store.CreateAsync(NewJob(inputSize: 7));
        var connection = Guid.NewGuid();
        var lease = (await store.ClaimNextAsync(connection))!;
        var wrong = Guid.NewGuid();

        Assert.False(await store.TryMarkVerifyingAsync(lease.Id, lease.DispatchId!.Value, wrong));
        Assert.False(await store.TryRecordCompletionAsync(
            lease.Id,
            lease.DispatchId.Value,
            connection,
            9,
            Sha256("result")));
        Assert.True(await store.TryMarkVerifyingAsync(lease.Id, lease.DispatchId.Value, connection));
        Assert.True(await store.TryRecordCompletionAsync(
            lease.Id,
            lease.DispatchId.Value,
            connection,
            9,
            Sha256("result")));
        Assert.False(await store.TryFinishSuccessAsync(lease.Id, lease.DispatchId.Value, wrong));
        Assert.True(await store.TryFinishSuccessAsync(lease.Id, lease.DispatchId.Value, connection));

        var completed = (await store.GetAsync(lease.Id))!;
        Assert.Equal(JobState.Succeeded, completed.State);
        Assert.Equal(9, completed.ResultSize);
        Assert.Equal(Sha256("result"), completed.ResultSha256);
        Assert.Null(completed.DispatchId);
        Assert.Null(completed.LeaseConnectionId);
    }

    [Fact]
    public async Task Recovery_does_not_increment_attempt_and_preserves_pending_verification_metadata()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        await store.CreateAsync(NewJob(inputSize: 7));
        await store.CreateAsync(NewJob(inputSize: 8));
        var signing = (await store.ClaimNextAsync(Guid.NewGuid()))!;
        var verifying = (await store.ClaimNextAsync(Guid.NewGuid()))!;
        Assert.True(await store.TryMarkVerifyingAsync(
            verifying.Id,
            verifying.DispatchId!.Value,
            verifying.LeaseConnectionId!.Value));
        Assert.True(await store.TryRecordCompletionAsync(
            verifying.Id,
            verifying.DispatchId.Value,
            verifying.LeaseConnectionId.Value,
            9,
            Sha256("result")));

        Assert.Equal(2, await store.RecoverActiveLeasesAsync());

        var recoveredSigning = (await store.GetAsync(signing.Id))!;
        var recoveredVerifying = (await store.GetAsync(verifying.Id))!;
        Assert.Equal(JobState.Queued, recoveredSigning.State);
        Assert.Equal(1, recoveredSigning.AttemptCount);
        Assert.Equal(JobState.Verifying, recoveredVerifying.State);
        Assert.Equal(1, recoveredVerifying.AttemptCount);
        Assert.Null(recoveredVerifying.DispatchId);
        Assert.Null(recoveredVerifying.LeaseConnectionId);
        Assert.Equal(Sha256("result"), recoveredVerifying.ResultSha256);
    }

    [Fact]
    public async Task Waiting_queue_does_not_consume_attempts_and_is_reactivated_in_fifo_order()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        var first = await store.CreateAsync(NewJob(inputSize: 1));
        await Task.Delay(2);
        var second = await store.CreateAsync(NewJob(inputSize: 2));

        Assert.True(await store.TryMarkNextWaitingForAgentAsync());
        Assert.True(await store.TryMarkNextWaitingForAgentAsync());
        Assert.False(await store.TryMarkNextWaitingForAgentAsync());
        Assert.Equal(0, (await store.GetAsync(first.Id))!.AttemptCount);
        Assert.Equal(2, await store.RequeueWaitingForAgentAsync());

        var connection = Guid.NewGuid();
        Assert.Equal(first.Id, (await store.ClaimNextAsync(connection))!.Id);
        Assert.Equal(second.Id, (await store.ClaimNextAsync(connection))!.Id);
    }

    [Fact]
    public async Task Recovered_pending_completion_has_lease_free_query_and_metadata_guarded_success_cas()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        await store.CreateAsync(NewJob(inputSize: 7));
        var lease = (await store.ClaimNextAsync(Guid.NewGuid()))!;
        Assert.True(await store.TryMarkVerifyingAsync(
            lease.Id,
            lease.DispatchId!.Value,
            lease.LeaseConnectionId!.Value));
        Assert.True(await store.TryRecordCompletionAsync(
            lease.Id,
            lease.DispatchId.Value,
            lease.LeaseConnectionId.Value,
            9,
            Sha256("result")));
        Assert.Equal(1, await store.RecoverActiveLeasesAsync());

        var pending = await store.GetNextPendingCompletionAsync();

        Assert.Equal(lease.Id, pending!.Id);
        Assert.False(await store.TryFinishRecoveredSuccessAsync(
            pending.Id,
            10,
            Sha256("wrong")));
        Assert.True(await store.TryFinishRecoveredSuccessAsync(
            pending.Id,
            9,
            Sha256("result")));
        Assert.Null(await store.GetNextPendingCompletionAsync());
    }

    private static Job NewJob(long inputSize) =>
        new(Guid.NewGuid(), JobState.Queued, new AuthenticodeParameters("52A1B4C9", "sha256", false))
        {
            OriginalName = "payload.exe",
            Extension = ".exe",
            InputSize = inputSize,
            InputSha256 = Sha256("input" + inputSize),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        };

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private sealed class Fixture : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(),
            "CodeSignAuto.Tests",
            Guid.NewGuid().ToString("N"));
        private readonly List<SqliteJobStore> _stores = [];

        public string DatabasePath => Path.Combine(_directory, "jobs.db");

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

            using var directConnection = new SqliteConnection($"Data Source={DatabasePath}");
            SqliteConnection.ClearPool(directConnection);

            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
    }
}
