using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class SqliteJobStoreTests
{
    [Fact]
    public async Task Dispose_releases_only_its_database_pool_and_rejects_reuse()
    {
        using var firstFixture = new JobStoreFixture();
        using var secondFixture = new JobStoreFixture();
        var first = new SqliteJobStore(firstFixture.DatabasePath);
        var second = new SqliteJobStore(secondFixture.DatabasePath);
        try
        {
            var firstJob = await first.CreateAsync(CreateJob());
            var secondJob = await second.CreateAsync(CreateJob());

            Assert.IsAssignableFrom<IDisposable>(first).Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => first.GetAsync(firstJob.Id));
            if (OperatingSystem.IsWindows())
            {
                File.Delete(firstFixture.DatabasePath);
                Assert.False(File.Exists(firstFixture.DatabasePath));
                Assert.Throws<IOException>(() => File.Delete(secondFixture.DatabasePath));
            }

            Assert.Equal(secondJob.Id, (await second.GetAsync(secondJob.Id))!.Id);
        }
        finally
        {
            first.Dispose();
            second.Dispose();
        }
    }

    [Fact]
    public async Task Only_one_expected_state_transition_wins()
    {
        using var fixture = new JobStoreFixture();
        var store = fixture.CreateStore();
        var job = await store.CreateAsync(CreateJob());

        var results = await Task.WhenAll(
            store.TryMarkNextWaitingForAgentAsync(),
            store.TryMarkNextWaitingForAgentAsync());

        Assert.Single(results, result => result);
    }

    [Fact]
    public async Task Persists_jobs_across_store_reopen()
    {
        using var fixture = new JobStoreFixture();
        var created = await fixture.CreateStore().CreateAsync(CreateJob());

        var reloaded = await fixture.CreateStore().GetAsync(created.Id);

        Assert.NotNull(reloaded);
        Assert.Equal(created.Id, reloaded.Id);
        Assert.Equal("payload.exe", reloaded.OriginalName);
        Assert.Equal(".exe", reloaded.Extension);
        Assert.Equal(created.InputSha256, reloaded.InputSha256);
    }

    [Fact]
    public async Task Reopens_pdf_job_without_optional_text_fields()
    {
        using var fixture = new JobStoreFixture();
        var job = new Job(
            Guid.NewGuid(),
            JobState.Queued,
            new PdfParameters("6F09D233", "sha256", 1, new PdfBox(10, 20, 30, 40), "Signature1", null, null))
        {
            OriginalName = "payload.pdf",
            Extension = ".pdf",
            InputSha256 = Sha256("input"),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        };
        var created = await fixture.CreateStore().CreateAsync(job);

        var reloaded = await fixture.CreateStore().GetAsync(created.Id);

        var parameters = Assert.IsType<PdfParameters>(reloaded!.Parameters);
        Assert.Null(parameters.Reason);
        Assert.Null(parameters.Location);
    }

    [Fact]
    public async Task Rejects_unknown_newer_schema_version()
    {
        using var fixture = new JobStoreFixture();
        Directory.CreateDirectory(Path.GetDirectoryName(fixture.DatabasePath)!);
        await using (var connection = new SqliteConnection($"Data Source={fixture.DatabasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version = 99;";
            await command.ExecuteNonQueryAsync();
        }

        var exception = await Assert.ThrowsAsync<SchemaVersionException>(() =>
            fixture.CreateStore().GetAsync(Guid.NewGuid()));

        Assert.Equal("unsupported_schema_version", exception.Code);
    }

    [Fact]
    public async Task Rejects_noncurrent_schema_without_mutating_existing_data()
    {
        using var fixture = new JobStoreFixture();
        Directory.CreateDirectory(Path.GetDirectoryName(fixture.DatabasePath)!);
        await using (var connection = await fixture.OpenDirectAsync())
        {
            await ExecuteAsync(connection, """
                CREATE TABLE sentinel (value TEXT NOT NULL);
                INSERT INTO sentinel(value) VALUES ('preserve-me');
                PRAGMA user_version = 6;
                """);
        }

        var failure = await Assert.ThrowsAsync<SchemaVersionException>(() =>
            fixture.CreateStore().GetAsync(Guid.NewGuid()));

        await using var readback = await fixture.OpenDirectAsync();
        Assert.Equal("unsupported_schema_version", failure.Code);
        Assert.Equal(6L, await ScalarInt64Async(readback, "PRAGMA user_version;"));
        Assert.Equal("preserve-me", await ScalarStringAsync(readback, "SELECT value FROM sentinel;"));
        Assert.Equal(0L, await ScalarInt64Async(
            readback,
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'jobs';"));
    }

    [Fact]
    public async Task Reopening_current_schema_is_idempotent_and_keeps_permanent_and_finite_expiry_values()
    {
        using var fixture = new JobStoreFixture();
        var permanent = await fixture.CreateStore().CreateAsync(CreateJob() with { ExpiresAt = null });
        var finiteExpiry = new DateTimeOffset(2026, 8, 15, 3, 4, 5, TimeSpan.FromHours(8)).AddTicks(6789);
        var finite = await fixture.CreateStore().CreateAsync(CreateJob(expiresAt: finiteExpiry));

        using var reopened = fixture.CreateStore();
        Assert.Null((await reopened.GetAsync(permanent.Id))!.ExpiresAt);
        Assert.Equal(finiteExpiry, (await reopened.GetAsync(finite.Id))!.ExpiresAt);

        await using var readback = await fixture.OpenDirectAsync();
        Assert.Equal(7L, await ScalarInt64Async(readback, "PRAGMA user_version;"));
        Assert.Equal(1L, await ScalarInt64Async(
            readback,
            "SELECT count(*) FROM jobs WHERE id = $id AND expires_at IS NULL;",
            ("$id", permanent.Id.ToString("D"))));
        Assert.Equal("2026-08-14T19:04:05.0006789+00:00", await ScalarStringAsync(
            readback,
            "SELECT expires_at FROM jobs WHERE id = $id;",
            ("$id", finite.Id.ToString("D"))));
        Assert.Equal(0L, await ScalarInt64Async(
            readback,
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'jobs_v7';"));
    }

    [Fact]
    public async Task Reuses_existing_job_for_matching_idempotency_fingerprint()
    {
        using var fixture = new JobStoreFixture();
        var store = fixture.CreateStore();
        var created = await store.CreateAsync(CreateJob(), "ci-principal", "same-key");

        var repeated = await store.CreateAsync(CreateJob(), "ci-principal", "same-key");

        Assert.Equal(created.Id, repeated.Id);
    }

    [Fact]
    public async Task Fingerprints_the_input_hash_and_canonical_parameters_json()
    {
        using var fixture = new JobStoreFixture();
        var request = CreateJob();

        var created = await fixture.CreateStore().CreateAsync(request);

        Assert.Equal(Sha256($"{request.InputSha256}\n{created.CanonicalParametersJson}"), created.RequestFingerprint);
    }

    [Fact]
    public async Task Rejects_reused_idempotency_key_with_different_request()
    {
        using var fixture = new JobStoreFixture();
        var store = fixture.CreateStore();
        await store.CreateAsync(CreateJob(), "ci-principal", "same-key");

        var exception = await Assert.ThrowsAsync<IdempotencyConflictException>(() =>
            store.CreateAsync(CreateJob(inputSha256: Sha256("different-input")), "ci-principal", "same-key"));

        Assert.Equal("idempotency_conflict", exception.Code);
    }

    [Fact]
    public async Task Recovers_waiting_jobs_without_consuming_an_attempt()
    {
        using var fixture = new JobStoreFixture();
        var store = fixture.CreateStore();
        var job = await store.CreateAsync(CreateJob());
        Assert.True(await store.TryMarkNextWaitingForAgentAsync());

        var recovered = await store.RecoverInterruptedAsync();
        var reloaded = await store.GetAsync(job.Id);

        Assert.Equal(1, recovered);
        Assert.NotNull(reloaded);
        Assert.Equal(JobState.Queued, reloaded.State);
        Assert.Equal(0, reloaded.AttemptCount);
    }

    [Fact]
    public async Task Expires_non_active_jobs_at_the_requested_cutoff()
    {
        using var fixture = new JobStoreFixture();
        var store = fixture.CreateStore();
        var job = await store.CreateAsync(CreateJob(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1)));

        var expired = await store.TryExpireNextAsync(
            DateTimeOffset.UtcNow,
            static (_, _) => Task.CompletedTask);
        var reloaded = await store.GetAsync(job.Id);

        Assert.Equal(job.Id, expired!.Id);
        Assert.NotNull(reloaded);
        Assert.Equal(JobState.Expired, reloaded.State);
    }

    private static Job CreateJob(string? inputSha256 = null, DateTimeOffset? expiresAt = null) =>
        new(Guid.NewGuid(), JobState.Queued, new AuthenticodeParameters("52A1B4C9", "sha256", false))
        {
            OriginalName = "payload.exe",
            Extension = ".exe",
            InputSha256 = inputSha256 ?? Sha256("input"),
            ExpiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddHours(1),
        };

    private static string Sha256(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static async Task ExecuteAsync(SqliteConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarInt64Async(
        SqliteConnection connection,
        string sql,
        params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
        {
            command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        }

        return (long)(await command.ExecuteScalarAsync())!;
    }

    private static async Task<string> ScalarStringAsync(
        SqliteConnection connection,
        string sql,
        params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
        {
            command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        }

        return (string)(await command.ExecuteScalarAsync())!;
    }

    private sealed class JobStoreFixture : IDisposable
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

        public async Task<SqliteConnection> OpenDirectAsync()
        {
            Directory.CreateDirectory(_directory);
            var connection = new SqliteConnection($"Data Source={DatabasePath}");
            await connection.OpenAsync();
            return connection;
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
