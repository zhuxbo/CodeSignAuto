using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Service.Jobs;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class JobsPageTests
{
    [Fact]
    public async Task Management_provider_returns_page_and_prebuilt_safe_settings()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        var created = await store.CreateAsync(CreateJob());
        var summary = new ServiceSettingsSummary(
            7080,
            ServiceSettingsSummary.FixedMaximumUploadBytes,
            24,
            "1.0.0");
        var provider = new ServiceManagementSnapshotProvider(
            store,
            new FixedTimeProvider(created.CreatedAt.AddTicks(1)),
            summary);

        var page = await provider.CreateJobPageAsync(null, CancellationToken.None);
        var settings = provider.GetServiceSettings();

        Assert.Single(page.Items);
        Assert.Equal(summary, settings);
    }

    [Fact]
    public async Task Correlation_id_is_immutable_and_survives_reopen()
    {
        using var fixture = new Fixture();
        var created = await fixture.CreateStore().CreateAsync(CreateJob());

        var reopened = await fixture.CreateStore().GetAsync(created.Id);

        Assert.NotEqual(Guid.Empty, created.CorrelationId);
        Assert.Equal(created.CorrelationId, reopened!.CorrelationId);
    }

    [Fact]
    public async Task Fixed_page_is_active_first_then_stable_descending_keyset()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        var jobs = new List<Job>();
        for (var index = 0; index < 102; index++)
        {
            jobs.Add(await store.CreateAsync(CreateJob(source: index % 2 == 0 ? "api" : "local")));
        }

        var asOf = DateTimeOffset.Parse("2026-08-09T12:00:00Z");
        await SetPageStateAsync(fixture.DatabasePath, jobs, asOf);

        var first = await store.GetJobPageAsync(null, asOf, CancellationToken.None);
        var second = await store.GetJobPageAsync(first.NextCursor, asOf.AddHours(1), CancellationToken.None);

        Assert.Equal(100, first.Items.Count);
        Assert.Equal(2, second.Items.Count);
        Assert.Equal(jobs.Take(3).Select(job => job.Id), first.Items.Take(3).Select(item => item.JobId));
        Assert.Empty(first.Items.Select(item => item.JobId).Intersect(second.Items.Select(item => item.JobId)));
        Assert.Equal(102, first.Items.Concat(second.Items).Select(item => item.JobId).Distinct().Count());
        Assert.All(first.Items.Take(3), item => Assert.Contains(item.State, new[] { "queued", "signing" }));
        Assert.Equal(asOf, first.NextCursor!.AsOfUtc);
        Assert.Null(second.NextCursor);
        Assert.All(first.Items.Concat(second.Items), item =>
        {
            Assert.NotEqual(Guid.Empty, item.CorrelationId);
            Assert.Contains(item.Source, new[] { "api", "local" });
        });
    }

    [Fact]
    public async Task Terminal_delta_does_not_scan_past_one_thousand_active_jobs()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        var jobs = new List<Job>();
        for (var index = 0; index < 1_002; index++)
        {
            jobs.Add(await store.CreateAsync(CreateJob(source: index == 1_001 ? "local" : "api")));
        }

        var completed = jobs.Max(job => job.CreatedAt).AddMinutes(1);
        await SetTerminalAsync(fixture.DatabasePath, jobs[1_000], completed, JobState.Failed);
        await SetTerminalAsync(fixture.DatabasePath, jobs[1_001], completed, JobState.Succeeded);

        var page = await store.GetTerminalJobDeltaAsync(
            new TerminalJobWatermark(0),
            null,
            CancellationToken.None);

        Assert.Equal([jobs[1_000].Id, jobs[1_001].Id], page.Items.Select(item => item.Item.JobId).ToArray());
        Assert.Equal([1L, 2L], page.Items.Select(item => item.Sequence).ToArray());
        Assert.Null(page.NextCursor);
        Assert.Equal(2, page.Watermark.Sequence);
    }

    [Fact]
    public async Task Terminal_commit_after_delta_snapshot_is_observed_on_the_next_sequence_poll()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        var job = await store.CreateAsync(CreateJob());
        var completedAt = DateTimeOffset.UtcNow;

        var beforeCommit = await store.GetTerminalJobDeltaAsync(
            new TerminalJobWatermark(0), null, CancellationToken.None);
        Assert.Empty(beforeCommit.Items);
        Assert.Equal(0, beforeCommit.Watermark.Sequence);

        await using var writer = new SqliteConnection($"Data Source={fixture.DatabasePath}");
        await writer.OpenAsync();
        await using var transaction = writer.BeginTransaction(deferred: false);
        await using (var update = writer.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE jobs SET state=$failed, completed_at=$completed, error_code=$error, error_message=$error WHERE id=$id;";
            update.Parameters.AddWithValue("$failed", (int)JobState.Failed);
            update.Parameters.AddWithValue("$completed", completedAt.ToString("O"));
            update.Parameters.AddWithValue("$error", "pdf_sign_failed");
            update.Parameters.AddWithValue("$id", job.Id.ToString("D"));
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }

        await transaction.CommitAsync();
        var afterCommit = await store.GetTerminalJobDeltaAsync(
            beforeCommit.Watermark, null, CancellationToken.None);

        Assert.Equal(job.Id, Assert.Single(afterCommit.Items).Item.JobId);
        Assert.Equal(1, afterCommit.Watermark.Sequence);
    }

    [Fact]
    public async Task Bulk_recovery_assigns_stable_unique_sequences_and_does_not_duplicate_events()
    {
        using var fixture = new Fixture();
        var store = fixture.CreateStore();
        var jobs = new List<Job>();
        for (var index = 0; index < 1_005; index++)
        {
            jobs.Add(await store.CreateAsync(CreateJob()));
        }

        await using (var connection = new SqliteConnection($"Data Source={fixture.DatabasePath}"))
        {
            await connection.OpenAsync();
            await using var update = connection.CreateCommand();
            update.CommandText = "UPDATE jobs SET state=$signing, attempt_count=2, dispatch_id=$dispatch, lease_connection_id=$connection;";
            update.Parameters.AddWithValue("$signing", (int)JobState.Signing);
            update.Parameters.AddWithValue("$dispatch", Guid.NewGuid().ToString("D"));
            update.Parameters.AddWithValue("$connection", Guid.NewGuid().ToString("D"));
            Assert.Equal(jobs.Count, await update.ExecuteNonQueryAsync());
        }

        Assert.Equal(jobs.Count, await store.RecoverActiveLeasesAsync());
        var events = await ReadAllTerminalEventsAsync(store, new TerminalJobWatermark(0));
        Assert.Equal(jobs.Count, events.Count);
        Assert.Equal(Enumerable.Range(1, jobs.Count).Select(static value => (long)value), events.Select(item => item.Sequence));
        Assert.Equal(
            jobs.OrderBy(job => job.CreatedAt).ThenBy(job => job.Id).Select(job => job.Id),
            events.Select(item => item.Item.JobId));
        Assert.Single(events.Select(item => item.Item.CompletedAtUtc).Distinct());

        Assert.Equal(0, await store.RecoverActiveLeasesAsync());
        var replay = await store.GetTerminalJobDeltaAsync(
            new TerminalJobWatermark(events[^1].Sequence), null, CancellationToken.None);
        Assert.Empty(replay.Items);
    }

    private static async Task<IReadOnlyList<TerminalJobEventItem>> ReadAllTerminalEventsAsync(
        SqliteJobStore store,
        TerminalJobWatermark watermark)
    {
        var events = new List<TerminalJobEventItem>();
        TerminalJobCursor? cursor = null;
        do
        {
            var page = await store.GetTerminalJobDeltaAsync(watermark, cursor, CancellationToken.None);
            events.AddRange(page.Items);
            cursor = page.NextCursor;
        }
        while (cursor is not null);

        return events;
    }

    private static Job CreateJob(string source = "api") =>
        new(Guid.NewGuid(), JobState.Queued, new AuthenticodeParameters("52A1B4C9", "sha256", false))
        {
            OriginalName = "payload.exe",
            Extension = ".exe",
            InputSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("D")))).ToLowerInvariant(),
            InputSize = 12,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
            Source = source,
        };

    private static async Task SetPageStateAsync(string databasePath, IReadOnlyList<Job> jobs, DateTimeOffset asOf)
    {
        await using var connection = new SqliteConnection($"Data Source={databasePath}");
        await connection.OpenAsync();
        for (var index = 0; index < jobs.Count; index++)
        {
            await using var command = connection.CreateCommand();
            var active = index < 3;
            var created = asOf.AddMinutes(-(index + 1));
            command.CommandText = active
                ? "UPDATE jobs SET state=$state, created_at=$created, started_at=$started WHERE id=$id;"
                : "UPDATE jobs SET state=$state, created_at=$created, completed_at=$completed, result_size=12, result_sha256=$hash WHERE id=$id;";
            command.Parameters.AddWithValue("$state", (int)(index == 1 ? JobState.Signing : active ? JobState.Queued : JobState.Succeeded));
            command.Parameters.AddWithValue("$created", created.ToString("O"));
            command.Parameters.AddWithValue("$started", created.AddSeconds(1).ToString("O"));
            command.Parameters.AddWithValue("$completed", created.AddSeconds(2).ToString("O"));
            command.Parameters.AddWithValue("$hash", new string('a', 64));
            command.Parameters.AddWithValue("$id", jobs[index].Id.ToString("D"));
            await command.ExecuteNonQueryAsync();
        }
    }

    private static async Task SetTerminalAsync(
        string databasePath,
        Job job,
        DateTimeOffset completedAt,
        JobState state)
    {
        await using var connection = new SqliteConnection($"Data Source={databasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = state == JobState.Succeeded
            ? "UPDATE jobs SET state=$state, completed_at=$completed, result_size=12, result_sha256=$hash WHERE id=$id;"
            : "UPDATE jobs SET state=$state, completed_at=$completed, error_code=$error, error_message=$error WHERE id=$id;";
        command.Parameters.AddWithValue("$state", (int)state);
        command.Parameters.AddWithValue("$completed", completedAt.ToString("O"));
        command.Parameters.AddWithValue("$hash", new string('a', 64));
        command.Parameters.AddWithValue("$error", "pdf_sign_failed");
        command.Parameters.AddWithValue("$id", job.Id.ToString("D"));
        await command.ExecuteNonQueryAsync();
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "CodeSignAuto.Tests", Guid.NewGuid().ToString("N"));
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

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
