using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.Service.Jobs;

public interface IJobStore
{
    Task<Job> CreateAsync(Job job, string? apiPrincipal = null, string? idempotencyKey = null, CancellationToken cancellationToken = default);

    Task<Job?> GetByIdempotencyKeyAsync(
        string apiPrincipal,
        string idempotencyKey,
        CancellationToken cancellationToken = default) => Task.FromResult<Job?>(null);

    Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default);

    Task CheckHealthAsync(CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    Task<JobQueueSnapshot> GetQueueSnapshotAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<JobQueueSnapshot>(new NotSupportedException());

    Task<JobManagementState> GetManagementStateAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<JobManagementState>(new NotSupportedException());

    Task<JobPageData> GetJobPageAsync(
        JobPageCursor? cursor,
        DateTimeOffset asOfUtc,
        CancellationToken cancellationToken = default) =>
        Task.FromException<JobPageData>(new NotSupportedException());

    Task<TerminalJobDeltaData> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken = default) =>
        Task.FromException<TerminalJobDeltaData>(new NotSupportedException());

    Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<IReadOnlyList<Job>>(new NotSupportedException());

    Task<Job?> TryExpireNextAsync(
        DateTimeOffset cutoff,
        Func<Job, CancellationToken, Task> deleteJobAsync,
        CancellationToken cancellationToken = default) => Task.FromException<Job?>(new NotSupportedException());

    Task<bool> TryMarkNextWaitingForAgentAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<bool>(new NotSupportedException());

    Task<int> RequeueWaitingForAgentAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<int>(new NotSupportedException());

    Task<Job?> ClaimNextAsync(Guid connectionId, CancellationToken cancellationToken = default) =>
        Task.FromException<Job?>(new NotSupportedException());

    Task<bool> TryMarkVerifyingAsync(Guid jobId, Guid dispatchId, Guid connectionId, CancellationToken cancellationToken = default) =>
        Task.FromException<bool>(new NotSupportedException());

    Task<bool> TryRecordCompletionAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        long resultSize,
        string resultSha256,
        CancellationToken cancellationToken = default) => Task.FromException<bool>(new NotSupportedException());

    Task<bool> TryFinishSuccessAsync(Guid jobId, Guid dispatchId, Guid connectionId, CancellationToken cancellationToken = default) =>
        Task.FromException<bool>(new NotSupportedException());

    Task<bool> TryRequeueLeaseAsync(Guid jobId, Guid dispatchId, Guid connectionId, CancellationToken cancellationToken = default) =>
        Task.FromException<bool>(new NotSupportedException());

    Task<bool> TryFailLeaseAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken = default) => Task.FromException<bool>(new NotSupportedException());

    Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<int>(new NotSupportedException());

    Task<int> RecoverManualInterruptedAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<int>(new NotSupportedException());

    Task<Job?> GetNextPendingCompletionAsync(CancellationToken cancellationToken = default) =>
        Task.FromException<Job?>(new NotSupportedException());

    Task<bool> TryFinishRecoveredSuccessAsync(
        Guid jobId,
        long resultSize,
        string resultSha256,
        CancellationToken cancellationToken = default) => Task.FromException<bool>(new NotSupportedException());

    Task<bool> TryFailRecoveredCompletionAsync(
        Guid jobId,
        long resultSize,
        string resultSha256,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken = default) => Task.FromException<bool>(new NotSupportedException());

    Task<bool> TryFailSucceededResultAsync(
        Guid jobId,
        long resultSize,
        string resultSha256,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken = default) => Task.FromException<bool>(new NotSupportedException());

    Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default);
}

public sealed record LocalUploadLeaseRecord(
    Guid RequestId,
    string RequestFingerprint,
    Guid JobId,
    string LeaseHash,
    byte[] ProtectedLease,
    string SigningUserSid,
    int SessionId,
    string RelativePartPath,
    string OriginalName,
    string Extension,
    long DeclaredSize,
    string CanonicalParametersJson,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    Guid? AcceptedJobId);

public sealed record LocalLeaseCreateOutcome(LocalUploadLeaseRecord Lease, bool Created);

public sealed record LocalLeaseAcceptOutcome(Job Job, bool Created);

public interface ILocalUploadLeaseStore
{
    Task<LocalLeaseCreateOutcome> CreateOrGetLocalLeaseAsync(
        LocalUploadLeaseRecord lease,
        CancellationToken cancellationToken = default);

    Task<LocalUploadLeaseRecord?> GetLocalLeaseAsync(
        Guid requestId,
        CancellationToken cancellationToken = default);

    Task<LocalLeaseAcceptOutcome> AcceptLocalLeaseAsync(
        Guid requestId,
        Job job,
        CancellationToken cancellationToken = default);

    Task<LocalUploadLeaseRecord?> GetNextExpiredLocalLeaseAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<LocalUploadLeaseRecord>> GetUnacceptedLocalLeasesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteLocalLeaseAsync(
        Guid requestId,
        Guid jobId,
        CancellationToken cancellationToken = default);
}

public sealed record JobQueueSnapshot(int Queued, int Active);

public sealed record JobPageData(IReadOnlyList<JobPageItem> Items, JobPageCursor? NextCursor);

public sealed record TerminalJobDeltaData(
    IReadOnlyList<TerminalJobEventItem> Items,
    TerminalJobCursor? NextCursor,
    TerminalJobWatermark Watermark);

public sealed record JobManagementState
{
    public JobManagementState(
        int queuedJobCount,
        int activeJobCount,
        Job? currentJob,
        IReadOnlyList<Job> recentJobs)
    {
        ArgumentNullException.ThrowIfNull(recentJobs);
        if (queuedJobCount < 0 || activeJobCount < 0 || recentJobs.Count > 5 ||
            (activeJobCount == 0) != (currentJob is null))
        {
            throw new ArgumentException("The job management state is invalid.");
        }

        QueuedJobCount = queuedJobCount;
        ActiveJobCount = activeJobCount;
        CurrentJob = currentJob;
        RecentJobs = Array.AsReadOnly(recentJobs.ToArray());
    }

    public int QueuedJobCount { get; }
    public int ActiveJobCount { get; }
    public Job? CurrentJob { get; }
    public IReadOnlyList<Job> RecentJobs { get; }
}

public sealed class IdempotencyConflictException : Exception
{
    public IdempotencyConflictException()
        : base("idempotency_conflict")
    {
    }

    public string Code => "idempotency_conflict";
}

public sealed class SchemaVersionException : Exception
{
    public SchemaVersionException()
        : base("unsupported_schema_version")
    {
    }

    public string Code => "unsupported_schema_version";
}

public sealed class SqliteJobStore : IJobStore, ILocalUploadLeaseStore, IDisposable
{
    private const int SchemaVersion = 7;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _initializationGate = new(1, 1);
    private int _disposed;
    private int _initialized;

    public SqliteJobStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        var fullPath = Path.GetFullPath(databasePath);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new ArgumentException("Database path must have a directory.", nameof(databasePath));
        Directory.CreateDirectory(directory);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = fullPath, Pooling = true }.ToString();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        using var connection = new SqliteConnection(_connectionString);
        SqliteConnection.ClearPool(connection);
    }

    public async Task<Job> CreateAsync(Job job, string? apiPrincipal = null, string? idempotencyKey = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        ValidateNewJob(job);
        if ((apiPrincipal is null) != (idempotencyKey is null) ||
            (apiPrincipal is not null && (string.IsNullOrWhiteSpace(apiPrincipal) || string.IsNullOrWhiteSpace(idempotencyKey))))
        {
            throw new ArgumentException("Idempotency principal and key must be supplied together.");
        }

        var canonicalParameters = SigningParameters.SerializeCanonical(job.Parameters);
        var normalizedInputHash = job.InputSha256.ToLowerInvariant();
        var fingerprint = HashText($"{normalizedInputHash}\n{canonicalParameters}");
        var idempotencyHash = apiPrincipal is null ? null : HashText($"{apiPrincipal}\n{idempotencyKey}");
        var createdAt = DateTimeOffset.UtcNow;
        var stored = job with
        {
            Kind = GetKind(job.Parameters),
            CanonicalParametersJson = canonicalParameters,
            InputSha256 = normalizedInputHash,
            RequestFingerprint = fingerprint,
            CreatedAt = createdAt,
            Source = NormalizeSource(job.Source),
            CorrelationId = job.CorrelationId == Guid.Empty ? Guid.NewGuid() : job.CorrelationId,
        };

        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO jobs (
                id, state, kind, original_name, extension, parameters_json, input_sha256, input_size,
                result_sha256, result_size, dispatch_id, lease_connection_id,
                error_code, error_message, attempt_count, idempotency_key_hash,
                request_fingerprint, created_at, started_at, completed_at, expires_at, source, correlation_id)
            VALUES (
                $id, $state, $kind, $originalName, $extension, $parametersJson, $inputSha256, $inputSize,
                NULL, NULL, NULL, NULL, NULL, NULL, 0, $idempotencyHash,
                $requestFingerprint, $createdAt, NULL, NULL, $expiresAt, $source, $correlationId);
            """;
        AddJobParameters(command, stored, idempotencyHash);

        try
        {
            await command.ExecuteNonQueryAsync(cancellationToken);
            return stored;
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 19 && idempotencyHash is not null)
        {
            var existing = await GetByIdempotencyHashAsync(connection, idempotencyHash, cancellationToken);
            if (existing is null)
            {
                throw;
            }
            if (!string.Equals(existing.RequestFingerprint, fingerprint, StringComparison.Ordinal))
            {
                throw new IdempotencyConflictException();
            }

            return existing;
        }
    }

    public async Task<Job?> GetByIdempotencyKeyAsync(
        string apiPrincipal,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiPrincipal) || string.IsNullOrWhiteSpace(idempotencyKey))
        {
            throw new ArgumentException("Idempotency principal and key must be nonempty.");
        }

        var idempotencyHash = HashText($"{apiPrincipal}\n{idempotencyKey}");
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await GetByIdempotencyHashAsync(connection, idempotencyHash, cancellationToken);
    }

    public async Task<Job?> GetAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM jobs WHERE id = $id;";
        command.Parameters.AddWithValue("$id", jobId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
    }

    public async Task<LocalLeaseCreateOutcome> CreateOrGetLocalLeaseAsync(
        LocalUploadLeaseRecord lease,
        CancellationToken cancellationToken = default)
    {
        ValidateLocalLease(lease);
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO local_upload_leases (
                request_id, request_fingerprint, job_id, lease_hash, protected_lease,
                signing_user_sid, session_id, relative_part_path, original_name, extension,
                declared_size, parameters_json, created_at, expires_at, accepted_job_id)
            VALUES (
                $requestId, $fingerprint, $jobId, $leaseHash, $protectedLease,
                $sid, $sessionId, $relativePath, $originalName, $extension,
                $declaredSize, $parameters, $createdAt, $expiresAt, NULL);
            """;
        AddLocalLeaseParameters(command, lease);
        try
        {
            await command.ExecuteNonQueryAsync(cancellationToken);
            return new LocalLeaseCreateOutcome(lease with { ProtectedLease = lease.ProtectedLease.ToArray() }, true);
        }
        catch (SqliteException error) when (error.SqliteErrorCode == 19)
        {
            var existing = await GetLocalLeaseAsync(connection, lease.RequestId, cancellationToken);
            if (existing is null)
            {
                throw;
            }

            return new LocalLeaseCreateOutcome(existing, false);
        }
    }

    public async Task<LocalUploadLeaseRecord?> GetLocalLeaseAsync(
        Guid requestId,
        CancellationToken cancellationToken = default)
    {
        RequireId(requestId, nameof(requestId));
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await GetLocalLeaseAsync(connection, requestId, cancellationToken);
    }

    public async Task<LocalLeaseAcceptOutcome> AcceptLocalLeaseAsync(
        Guid requestId,
        Job job,
        CancellationToken cancellationToken = default)
    {
        RequireId(requestId, nameof(requestId));
        ArgumentNullException.ThrowIfNull(job);
        ValidateNewJob(job);
        if (job.Source != "local")
        {
            throw new ArgumentException("A local upload must create a local job.", nameof(job));
        }

        var canonicalParameters = SigningParameters.SerializeCanonical(job.Parameters);
        var normalizedInputHash = job.InputSha256.ToLowerInvariant();
        var fingerprint = HashText($"{normalizedInputHash}\n{canonicalParameters}");
        var createdAt = job.CreatedAt == default ? DateTimeOffset.UtcNow : job.CreatedAt;
        var stored = job with
        {
            Kind = GetKind(job.Parameters),
            CanonicalParametersJson = canonicalParameters,
            InputSha256 = normalizedInputHash,
            RequestFingerprint = fingerprint,
            CreatedAt = createdAt,
            Source = "local",
            CorrelationId = job.CorrelationId == Guid.Empty ? Guid.NewGuid() : job.CorrelationId,
        };

        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        var lease = await GetLocalLeaseAsync(connection, requestId, cancellationToken, transaction)
            ?? throw new InvalidOperationException("local_upload_missing");
        if (lease.AcceptedJobId is { } acceptedJobId)
        {
            var accepted = await GetJobAsync(connection, acceptedJobId, cancellationToken, transaction)
                ?? throw new InvalidOperationException("local_upload_missing");
            await transaction.CommitAsync(cancellationToken);
            return new LocalLeaseAcceptOutcome(accepted, false);
        }

        if (lease.JobId != stored.Id)
        {
            throw new InvalidOperationException("local_upload_missing");
        }

        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO jobs (
                    id, state, kind, original_name, extension, parameters_json, input_sha256, input_size,
                    result_sha256, result_size, dispatch_id, lease_connection_id,
                    error_code, error_message, attempt_count, idempotency_key_hash,
                    request_fingerprint, created_at, started_at, completed_at, expires_at, source, correlation_id)
                VALUES (
                    $id, $state, $kind, $originalName, $extension, $parametersJson, $inputSha256, $inputSize,
                    NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL,
                    $requestFingerprint, $createdAt, NULL, NULL, $expiresAt, $source, $correlationId);
                """;
            AddJobParameters(insert, stored, idempotencyHash: null);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var accept = connection.CreateCommand())
        {
            accept.Transaction = transaction;
            accept.CommandText = """
                UPDATE local_upload_leases
                SET accepted_job_id = $jobId
                WHERE request_id = $requestId AND accepted_job_id IS NULL;
                """;
            accept.Parameters.AddWithValue("$jobId", stored.Id.ToString("D"));
            accept.Parameters.AddWithValue("$requestId", requestId.ToString("D"));
            if (await accept.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("local_upload_missing");
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return new LocalLeaseAcceptOutcome(stored, true);
    }

    public async Task<LocalUploadLeaseRecord?> GetNextExpiredLocalLeaseAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT * FROM local_upload_leases
            WHERE accepted_job_id IS NULL AND expires_at <= $cutoff
            ORDER BY expires_at, request_id
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$cutoff", ToStorageTime(cutoff));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadLocalLease(reader) : null;
    }

    public async Task<IReadOnlyList<LocalUploadLeaseRecord>> GetUnacceptedLocalLeasesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT * FROM local_upload_leases
            WHERE accepted_job_id IS NULL AND expires_at > $now
            ORDER BY job_id;
            """;
        command.Parameters.AddWithValue("$now", ToStorageTime(now));
        var leases = new List<LocalUploadLeaseRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            leases.Add(ReadLocalLease(reader));
        }

        return leases;
    }

    public async Task<bool> DeleteLocalLeaseAsync(
        Guid requestId,
        Guid jobId,
        CancellationToken cancellationToken = default)
    {
        RequireId(requestId, nameof(requestId));
        RequireId(jobId, nameof(jobId));
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            DELETE FROM local_upload_leases
            WHERE request_id = $requestId AND job_id = $jobId AND accepted_job_id IS NULL;
            """;
        command.Parameters.AddWithValue("$requestId", requestId.ToString("D"));
        command.Parameters.AddWithValue("$jobId", jobId.ToString("D"));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1;";
        _ = await command.ExecuteScalarAsync(cancellationToken);
    }

    public async Task<JobQueueSnapshot> GetQueueSnapshotAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                COALESCE(SUM(CASE WHEN state = $queued THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state IN ($waitingForAgent, $signing, $verifying) THEN 1 ELSE 0 END), 0)
            FROM jobs;
            """;
        command.Parameters.AddWithValue("$queued", (int)JobState.Queued);
        command.Parameters.AddWithValue("$waitingForAgent", (int)JobState.WaitingForAgent);
        command.Parameters.AddWithValue("$signing", (int)JobState.Signing);
        command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new JobQueueSnapshot(reader.GetInt32(0), reader.GetInt32(1));
    }

    public async Task<JobManagementState> GetManagementStateAsync(
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        int queued;
        int active;
        await using (var counts = connection.CreateCommand())
        {
            counts.Transaction = (SqliteTransaction)transaction;
            counts.CommandText = """
                SELECT
                    COALESCE(SUM(CASE WHEN state = $queued THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN state IN ($waiting, $signing, $verifying) THEN 1 ELSE 0 END), 0)
                FROM jobs;
                """;
            counts.Parameters.AddWithValue("$queued", (int)JobState.Queued);
            counts.Parameters.AddWithValue("$waiting", (int)JobState.WaitingForAgent);
            counts.Parameters.AddWithValue("$signing", (int)JobState.Signing);
            counts.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
            await using var reader = await counts.ExecuteReaderAsync(cancellationToken);
            await reader.ReadAsync(cancellationToken);
            queued = reader.GetInt32(0);
            active = reader.GetInt32(1);
        }

        Job? current;
        await using (var currentCommand = connection.CreateCommand())
        {
            currentCommand.Transaction = (SqliteTransaction)transaction;
            currentCommand.CommandText = """
                SELECT * FROM jobs
                WHERE state IN ($waiting, $signing, $verifying)
                ORDER BY COALESCE(started_at, created_at), id
                LIMIT 1;
                """;
            currentCommand.Parameters.AddWithValue("$waiting", (int)JobState.WaitingForAgent);
            currentCommand.Parameters.AddWithValue("$signing", (int)JobState.Signing);
            currentCommand.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
            await using var reader = await currentCommand.ExecuteReaderAsync(cancellationToken);
            current = await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
            if (current is { State: JobState.WaitingForAgent, StartedAt: null })
            {
                current = current with { StartedAt = current.CreatedAt };
            }
        }

        var recent = new List<Job>(5);
        await using (var recentCommand = connection.CreateCommand())
        {
            recentCommand.Transaction = (SqliteTransaction)transaction;
            recentCommand.CommandText = """
                SELECT * FROM jobs
                WHERE state IN ($succeeded, $failed, $expired)
                  AND completed_at IS NOT NULL
                ORDER BY completed_at DESC, id
                LIMIT 5;
                """;
            recentCommand.Parameters.AddWithValue("$succeeded", (int)JobState.Succeeded);
            recentCommand.Parameters.AddWithValue("$failed", (int)JobState.Failed);
            recentCommand.Parameters.AddWithValue("$expired", (int)JobState.Expired);
            await using var reader = await recentCommand.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                recent.Add(ReadJob(reader));
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return new JobManagementState(queued, active, current, recent);
    }

    public async Task<JobPageData> GetJobPageAsync(
        JobPageCursor? cursor,
        DateTimeOffset asOfUtc,
        CancellationToken cancellationToken = default)
    {
        if (asOfUtc == default || asOfUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("The page time must be UTC.", nameof(asOfUtc));
        }

        var effectiveAsOf = cursor?.AsOfUtc ?? asOfUtc;
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        const string bucket = "CASE WHEN state IN ($queued, $waiting, $signing, $verifying) THEN 0 ELSE 1 END";
        command.CommandText = $"""
            SELECT * FROM jobs
            WHERE created_at <= $asOf
              AND (
                $hasCursor = 0
                OR {bucket} > $cursorBucket
                OR ({bucket} = $cursorBucket AND
                    (created_at < $cursorCreated OR (created_at = $cursorCreated AND id < $cursorId)))
              )
            ORDER BY {bucket}, created_at DESC, id DESC
            LIMIT 101;
            """;
        command.Parameters.AddWithValue("$queued", (int)JobState.Queued);
        command.Parameters.AddWithValue("$waiting", (int)JobState.WaitingForAgent);
        command.Parameters.AddWithValue("$signing", (int)JobState.Signing);
        command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
        command.Parameters.AddWithValue("$asOf", ToStorageTime(effectiveAsOf));
        command.Parameters.AddWithValue("$hasCursor", cursor is null ? 0 : 1);
        command.Parameters.AddWithValue("$cursorBucket", cursor?.Bucket == "terminal" ? 1 : 0);
        command.Parameters.AddWithValue("$cursorCreated", cursor is null ? string.Empty : ToStorageTime(cursor.CreatedAtUtc));
        command.Parameters.AddWithValue("$cursorId", cursor?.JobId.ToString("D") ?? string.Empty);

        var jobs = new List<Job>(101);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            jobs.Add(ReadJob(reader));
        }

        var hasMore = jobs.Count > 100;
        if (hasMore)
        {
            jobs.RemoveAt(100);
        }

        var items = jobs.Select(CreatePageItem).ToArray();
        JobPageCursor? next = null;
        if (hasMore)
        {
            var last = jobs[^1];
            next = new JobPageCursor(
                IsActive(last.State) ? "active" : "terminal",
                last.CreatedAt,
                last.Id,
                effectiveAsOf);
        }

        return new JobPageData(Array.AsReadOnly(items), next);
    }

    public async Task<TerminalJobDeltaData> GetTerminalJobDeltaAsync(
        TerminalJobWatermark? watermark,
        TerminalJobCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        if (cursor is not null && watermark is null)
        {
            throw new ArgumentException("The terminal delta bounds are invalid.", nameof(cursor));
        }

        if (cursor is { } positioned && positioned.LastSequence <= watermark!.Sequence)
        {
            throw new ArgumentException("The terminal delta cursor is outside its watermark.", nameof(cursor));
        }

        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        long snapshotSequence;
        if (cursor is { } existingCursor)
        {
            snapshotSequence = existingCursor.SnapshotSequence;
        }
        else
        {
            await using var maximum = connection.CreateCommand();
            maximum.Transaction = (SqliteTransaction)transaction;
            maximum.CommandText = "SELECT COALESCE(MAX(sequence), 0) FROM terminal_job_events;";
            snapshotSequence = Convert.ToInt64(
                await maximum.ExecuteScalarAsync(cancellationToken),
                CultureInfo.InvariantCulture);
        }

        if (watermark is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new TerminalJobDeltaData([], null, new TerminalJobWatermark(snapshotSequence));
        }

        await using var command = connection.CreateCommand();
        command.Transaction = (SqliteTransaction)transaction;
        command.CommandText = """
            SELECT jobs.*, terminal_job_events.sequence AS terminal_sequence,
                   terminal_job_events.terminal_state AS event_state,
                   terminal_job_events.completed_at AS event_completed_at,
                   terminal_job_events.error_code AS event_error_code
            FROM terminal_job_events
            INNER JOIN jobs ON jobs.id = terminal_job_events.job_id
            WHERE terminal_job_events.sequence > $afterSequence
              AND terminal_job_events.sequence <= $snapshotSequence
              AND terminal_job_events.sequence > $cursorSequence
            ORDER BY terminal_job_events.sequence
            LIMIT 101;
            """;
        command.Parameters.AddWithValue("$afterSequence", watermark.Sequence);
        command.Parameters.AddWithValue("$snapshotSequence", snapshotSequence);
        command.Parameters.AddWithValue("$cursorSequence", cursor?.LastSequence ?? watermark.Sequence);

        var events = new List<TerminalJobEventItem>(101);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(ReadTerminalEvent(reader));
        }

        var hasMore = events.Count > 100;
        if (hasMore)
        {
            events.RemoveAt(100);
        }

        TerminalJobCursor? next = null;
        if (hasMore)
        {
            next = new TerminalJobCursor(events[^1].Sequence, snapshotSequence);
        }

        await transaction.CommitAsync(cancellationToken);
        return new TerminalJobDeltaData(
            Array.AsReadOnly(events.ToArray()),
            next,
            new TerminalJobWatermark(snapshotSequence));
    }

    public async Task<IReadOnlyList<Job>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM jobs ORDER BY created_at, id;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var jobs = new List<Job>();
        while (await reader.ReadAsync(cancellationToken))
        {
            jobs.Add(ReadJob(reader));
        }

        return jobs;
    }

    public async Task<Job?> TryExpireNextAsync(
        DateTimeOffset cutoff,
        Func<Job, CancellationToken, Task> deleteJobAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(deleteJobAsync);
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        Job? candidate;
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT * FROM jobs
                WHERE expires_at IS NOT NULL
                  AND expires_at <= $cutoff
                  AND state NOT IN ($waitingForAgent, $signing, $verifying, $expired)
                ORDER BY expires_at, created_at, id
                LIMIT 1;
                """;
            select.Parameters.AddWithValue("$cutoff", ToStorageTime(cutoff));
            select.Parameters.AddWithValue("$waitingForAgent", (int)JobState.WaitingForAgent);
            select.Parameters.AddWithValue("$signing", (int)JobState.Signing);
            select.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
            select.Parameters.AddWithValue("$expired", (int)JobState.Expired);
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            candidate = await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
        }

        if (candidate is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        await deleteJobAsync(candidate, CancellationToken.None).ConfigureAwait(false);
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE jobs
                SET state = $expired,
                    dispatch_id = NULL,
                    lease_connection_id = NULL,
                    error_code = 'job_expired',
                    error_message = 'job_expired',
                    completed_at = $now
                WHERE id = $id
                  AND state = $expectedState
                  AND expires_at IS NOT NULL
                  AND expires_at <= $cutoff;
                """;
            update.Parameters.AddWithValue("$expired", (int)JobState.Expired);
            update.Parameters.AddWithValue("$expectedState", (int)candidate.State);
            update.Parameters.AddWithValue("$now", ToStorageTime(cutoff));
            update.Parameters.AddWithValue("$id", candidate.Id.ToString("D"));
            update.Parameters.AddWithValue("$cutoff", ToStorageTime(cutoff));
            if (await update.ExecuteNonQueryAsync(CancellationToken.None) != 1)
            {
                throw new InvalidOperationException("expiry_reservation_lost");
            }
        }

        await transaction.CommitAsync(CancellationToken.None);
        return candidate with
        {
            State = JobState.Expired,
            DispatchId = null,
            LeaseConnectionId = null,
            ErrorCode = "job_expired",
            ErrorMessage = "job_expired",
        };
    }

    public async Task<bool> TryMarkNextWaitingForAgentAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE jobs
            SET state = $waitingForAgent,
                started_at = COALESCE(started_at, $now)
            WHERE id = (
                SELECT id FROM jobs
                WHERE state = $queued
                ORDER BY created_at, id
                LIMIT 1
            )
              AND state = $queued;
            """;
        command.Parameters.AddWithValue("$queued", (int)JobState.Queued);
        command.Parameters.AddWithValue("$waitingForAgent", (int)JobState.WaitingForAgent);
        command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<int> RequeueWaitingForAgentAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE jobs SET state = $queued WHERE state = $waitingForAgent;";
        command.Parameters.AddWithValue("$queued", (int)JobState.Queued);
        command.Parameters.AddWithValue("$waitingForAgent", (int)JobState.WaitingForAgent);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<Job?> ClaimNextAsync(Guid connectionId, CancellationToken cancellationToken = default)
    {
        RequireId(connectionId, nameof(connectionId));
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var dispatchId = Guid.NewGuid();
        command.CommandText = """
            UPDATE jobs
            SET state = $signing,
                attempt_count = attempt_count + 1,
                dispatch_id = $dispatchId,
                lease_connection_id = $connectionId,
                started_at = COALESCE(started_at, $now),
                error_code = NULL,
                error_message = NULL,
                completed_at = NULL
            WHERE id = (
                SELECT id FROM jobs
                WHERE state = $queued AND attempt_count < 2
                ORDER BY created_at, id
                LIMIT 1
            )
              AND state = $queued
              AND attempt_count < 2
            RETURNING *;
            """;
        command.Parameters.AddWithValue("$signing", (int)JobState.Signing);
        command.Parameters.AddWithValue("$queued", (int)JobState.Queued);
        command.Parameters.AddWithValue("$dispatchId", dispatchId.ToString("D"));
        command.Parameters.AddWithValue("$connectionId", connectionId.ToString("D"));
        command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
    }

    public Task<bool> TryMarkVerifyingAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        CancellationToken cancellationToken = default) =>
        ExecuteLeaseUpdateAsync(
            jobId,
            dispatchId,
            connectionId,
            JobState.Signing,
            "state = $verifying",
            command => command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying),
            cancellationToken);

    public async Task<bool> TryRecordCompletionAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        long resultSize,
        string resultSha256,
        CancellationToken cancellationToken = default)
    {
        if (resultSize < 0 || !IsSha256(resultSha256) || resultSha256.Any(char.IsUpper))
        {
            throw new ArgumentException("Result metadata is invalid.");
        }

        return await ExecuteLeaseUpdateAsync(
            jobId,
            dispatchId,
            connectionId,
            JobState.Verifying,
            "result_size = $resultSize, result_sha256 = $resultSha256",
            command =>
            {
                command.Parameters.AddWithValue("$resultSize", resultSize);
                command.Parameters.AddWithValue("$resultSha256", resultSha256);
            },
            cancellationToken,
            "result_size IS NULL AND result_sha256 IS NULL");
    }

    public Task<bool> TryFinishSuccessAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        CancellationToken cancellationToken = default) =>
        ExecuteLeaseUpdateAsync(
            jobId,
            dispatchId,
            connectionId,
            JobState.Verifying,
            "state = $succeeded, dispatch_id = NULL, lease_connection_id = NULL, completed_at = $now",
            command =>
            {
                command.Parameters.AddWithValue("$succeeded", (int)JobState.Succeeded);
                command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
            },
            cancellationToken,
            "result_size IS NOT NULL AND result_sha256 IS NOT NULL");

    public Task<bool> TryRequeueLeaseAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        CancellationToken cancellationToken = default) =>
        ExecuteLeaseUpdateAsync(
            jobId,
            dispatchId,
            connectionId,
            expectedState: null,
            "state = $queued, dispatch_id = NULL, lease_connection_id = NULL, result_size = NULL, result_sha256 = NULL",
            command => command.Parameters.AddWithValue("$queued", (int)JobState.Queued),
            cancellationToken,
            "state IN ($signing, $verifying) AND attempt_count < 2 AND result_size IS NULL AND result_sha256 IS NULL",
            addStateParameters: true);

    public Task<bool> TryFailLeaseAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken = default)
    {
        ValidateFailure(errorCode, errorMessage);
        return ExecuteLeaseUpdateAsync(
            jobId,
            dispatchId,
            connectionId,
            expectedState: null,
            "state = $failed, dispatch_id = NULL, lease_connection_id = NULL, result_size = NULL, result_sha256 = NULL, error_code = $errorCode, error_message = $errorMessage, completed_at = $now",
            command =>
            {
                command.Parameters.AddWithValue("$failed", (int)JobState.Failed);
                command.Parameters.AddWithValue("$errorCode", errorCode);
                command.Parameters.AddWithValue("$errorMessage", errorMessage);
                command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
            },
            cancellationToken,
            "state IN ($signing, $verifying)",
            addStateParameters: true);
    }

    public async Task<int> RecoverActiveLeasesAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        var activeJobIds = new List<Guid>();
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT id
                FROM jobs
                WHERE state IN ($waitingForAgent, $signing, $verifying)
                ORDER BY created_at, id;
                """;
            select.Parameters.AddWithValue("$waitingForAgent", (int)JobState.WaitingForAgent);
            select.Parameters.AddWithValue("$signing", (int)JobState.Signing);
            select.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                activeJobIds.Add(Guid.Parse(reader.GetString(0)));
            }
        }

        var affected = 0;
        var completedAt = ToStorageTime(DateTimeOffset.UtcNow);
        foreach (var jobId in activeJobIds)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
            UPDATE jobs
            SET state = CASE
                    WHEN state = $verifying AND result_size IS NOT NULL AND result_sha256 IS NOT NULL THEN $verifying
                    WHEN state = $waitingForAgent THEN $queued
                    WHEN attempt_count < 2 THEN $queued
                    ELSE $failed
                END,
                dispatch_id = NULL,
                lease_connection_id = NULL,
                error_code = CASE
                    WHEN state <> $waitingForAgent
                         AND NOT (state = $verifying AND result_size IS NOT NULL AND result_sha256 IS NOT NULL)
                         AND attempt_count >= 2 THEN 'recovery_exhausted'
                    ELSE error_code
                END,
                error_message = CASE
                    WHEN state <> $waitingForAgent
                         AND NOT (state = $verifying AND result_size IS NOT NULL AND result_sha256 IS NOT NULL)
                         AND attempt_count >= 2 THEN 'Signing recovery was exhausted.'
                    ELSE error_message
                END,
                completed_at = CASE
                    WHEN state <> $waitingForAgent
                         AND NOT (state = $verifying AND result_size IS NOT NULL AND result_sha256 IS NOT NULL)
                         AND attempt_count >= 2 THEN $now
                    ELSE completed_at
                END
            WHERE id = $id
              AND state IN ($waitingForAgent, $signing, $verifying);
            """;
            command.Parameters.AddWithValue("$id", jobId.ToString("D"));
            command.Parameters.AddWithValue("$waitingForAgent", (int)JobState.WaitingForAgent);
            command.Parameters.AddWithValue("$queued", (int)JobState.Queued);
            command.Parameters.AddWithValue("$signing", (int)JobState.Signing);
            command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
            command.Parameters.AddWithValue("$failed", (int)JobState.Failed);
            command.Parameters.AddWithValue("$now", completedAt);
            affected += await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return affected;
    }

    public async Task<int> RecoverManualInterruptedAsync(
        CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE jobs
            SET state = $failed,
                dispatch_id = NULL,
                lease_connection_id = NULL,
                result_size = NULL,
                result_sha256 = NULL,
                error_code = 'manual_job_interrupted',
                error_message = 'Manual signing was interrupted before completion.',
                completed_at = $now
            WHERE state IN ($queued, $waitingForAgent, $signing, $verifying)
              AND NOT (
                  state = $verifying AND
                  result_size IS NOT NULL AND
                  result_sha256 IS NOT NULL);
            """;
        command.Parameters.AddWithValue("$failed", (int)JobState.Failed);
        command.Parameters.AddWithValue("$queued", (int)JobState.Queued);
        command.Parameters.AddWithValue("$waitingForAgent", (int)JobState.WaitingForAgent);
        command.Parameters.AddWithValue("$signing", (int)JobState.Signing);
        command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
        command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
        var affected = await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return affected;
    }

    public async Task<Job?> GetNextPendingCompletionAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT * FROM jobs
            WHERE state = $verifying
              AND dispatch_id IS NULL
              AND lease_connection_id IS NULL
              AND result_size IS NOT NULL
              AND result_sha256 IS NOT NULL
            ORDER BY created_at, id
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
    }

    public async Task<bool> TryFinishRecoveredSuccessAsync(
        Guid jobId,
        long resultSize,
        string resultSha256,
        CancellationToken cancellationToken = default)
    {
        RequireId(jobId, nameof(jobId));
        if (resultSize < 0 || !IsSha256(resultSha256) || resultSha256.Any(char.IsUpper))
        {
            throw new ArgumentException("Result metadata is invalid.");
        }

        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE jobs
            SET state = $succeeded,
                completed_at = $now
            WHERE id = $id
              AND state = $verifying
              AND dispatch_id IS NULL
              AND lease_connection_id IS NULL
              AND result_size = $resultSize
              AND result_sha256 = $resultSha256;
            """;
        command.Parameters.AddWithValue("$succeeded", (int)JobState.Succeeded);
        command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
        command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$id", jobId.ToString("D"));
        command.Parameters.AddWithValue("$resultSize", resultSize);
        command.Parameters.AddWithValue("$resultSha256", resultSha256);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<bool> TryFailRecoveredCompletionAsync(
        Guid jobId,
        long resultSize,
        string resultSha256,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken = default)
    {
        RequireId(jobId, nameof(jobId));
        if (resultSize < 0 || !IsSha256(resultSha256) || resultSha256.Any(char.IsUpper))
        {
            throw new ArgumentException("Result metadata is invalid.");
        }

        ValidateFailure(errorCode, errorMessage);
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE jobs
            SET state = $failed,
                result_size = NULL,
                result_sha256 = NULL,
                error_code = $errorCode,
                error_message = $errorMessage,
                completed_at = $now
            WHERE id = $id
              AND state = $verifying
              AND dispatch_id IS NULL
              AND lease_connection_id IS NULL
              AND result_size = $resultSize
              AND result_sha256 = $resultSha256;
            """;
        command.Parameters.AddWithValue("$failed", (int)JobState.Failed);
        command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
        command.Parameters.AddWithValue("$errorCode", errorCode);
        command.Parameters.AddWithValue("$errorMessage", errorMessage);
        command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$id", jobId.ToString("D"));
        command.Parameters.AddWithValue("$resultSize", resultSize);
        command.Parameters.AddWithValue("$resultSha256", resultSha256);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<bool> TryFailSucceededResultAsync(
        Guid jobId,
        long resultSize,
        string resultSha256,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken = default)
    {
        RequireId(jobId, nameof(jobId));
        if (resultSize < 0 || !IsSha256(resultSha256) || resultSha256.Any(char.IsUpper))
        {
            throw new ArgumentException("Result metadata is invalid.");
        }

        ValidateFailure(errorCode, errorMessage);
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE jobs
            SET state = $failed,
                result_size = NULL,
                result_sha256 = NULL,
                error_code = $errorCode,
                error_message = $errorMessage,
                completed_at = $now
            WHERE id = $id
              AND state = $succeeded
              AND result_size = $resultSize
              AND result_sha256 = $resultSha256;
            """;
        command.Parameters.AddWithValue("$failed", (int)JobState.Failed);
        command.Parameters.AddWithValue("$succeeded", (int)JobState.Succeeded);
        command.Parameters.AddWithValue("$errorCode", errorCode);
        command.Parameters.AddWithValue("$errorMessage", errorMessage);
        command.Parameters.AddWithValue("$now", ToStorageTime(DateTimeOffset.UtcNow));
        command.Parameters.AddWithValue("$id", jobId.ToString("D"));
        command.Parameters.AddWithValue("$resultSize", resultSize);
        command.Parameters.AddWithValue("$resultSha256", resultSha256);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<int> RecoverInterruptedAsync(CancellationToken cancellationToken = default)
    {
        return await RecoverActiveLeasesAsync(cancellationToken);
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _initialized) == 1)
        {
            return;
        }

        await _initializationGate.WaitAsync(cancellationToken);
        try
        {
            if (Volatile.Read(ref _initialized) == 1)
            {
                return;
            }

            await using var connection = await OpenConnectionAsync(cancellationToken);
            await using var versionCommand = connection.CreateCommand();
            versionCommand.CommandText = "PRAGMA user_version;";
            var version = Convert.ToInt32(
                await versionCommand.ExecuteScalarAsync(cancellationToken),
                CultureInfo.InvariantCulture);
            if (version is not 0 && version != SchemaVersion)
            {
                throw new SchemaVersionException();
            }

            if (version == 0)
            {
                await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
                await using var schemaCommand = connection.CreateCommand();
                schemaCommand.Transaction = (SqliteTransaction)transaction;
                schemaCommand.CommandText = $"""
                    CREATE TABLE jobs (
                      id TEXT PRIMARY KEY,
                      state INTEGER NOT NULL,
                      kind INTEGER NOT NULL,
                      original_name TEXT NOT NULL,
                      extension TEXT NOT NULL,
                      parameters_json TEXT NOT NULL,
                      input_sha256 TEXT NOT NULL,
                      input_size INTEGER NOT NULL,
                      result_sha256 TEXT NULL,
                      result_size INTEGER NULL,
                      dispatch_id TEXT NULL,
                      lease_connection_id TEXT NULL,
                      error_code TEXT NULL,
                      error_message TEXT NULL,
                      attempt_count INTEGER NOT NULL DEFAULT 0,
                      idempotency_key_hash TEXT NULL,
                      request_fingerprint TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      started_at TEXT NULL,
                      completed_at TEXT NULL,
                      expires_at TEXT NULL,
                      source TEXT NOT NULL DEFAULT 'api',
                      correlation_id TEXT NOT NULL
                    );
                    CREATE UNIQUE INDEX ux_jobs_idempotency ON jobs(idempotency_key_hash)
                      WHERE idempotency_key_hash IS NOT NULL;
                    CREATE INDEX ix_jobs_state_created ON jobs(state, created_at);
                    CREATE TABLE local_upload_leases (
                      request_id TEXT PRIMARY KEY,
                      request_fingerprint TEXT NOT NULL,
                      job_id TEXT NOT NULL UNIQUE,
                      lease_hash TEXT NOT NULL,
                      protected_lease BLOB NOT NULL,
                      signing_user_sid TEXT NOT NULL,
                      session_id INTEGER NOT NULL,
                      relative_part_path TEXT NOT NULL,
                      original_name TEXT NOT NULL,
                      extension TEXT NOT NULL,
                      declared_size INTEGER NOT NULL,
                      parameters_json TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      expires_at TEXT NOT NULL,
                      accepted_job_id TEXT NULL
                    );
                    CREATE INDEX ix_local_upload_leases_expiry
                      ON local_upload_leases(accepted_job_id, expires_at);
                    CREATE TABLE terminal_job_events (
                      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                      job_id TEXT NOT NULL,
                      terminal_state INTEGER NOT NULL,
                      completed_at TEXT NOT NULL,
                      error_code TEXT NULL,
                      UNIQUE(job_id, terminal_state, completed_at)
                    );
                    CREATE INDEX ix_terminal_job_events_job
                      ON terminal_job_events(job_id, sequence);
                    {JobsTerminalEventTriggerSql};
                    {JobsTerminalEventInsertTriggerSql};
                    PRAGMA user_version = {SchemaVersion};
                    """;
                await schemaCommand.ExecuteNonQueryAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }

            Volatile.Write(ref _initialized, 1);
        }
        finally
        {
            _initializationGate.Release();
        }
    }

    private static string JobsTerminalEventTriggerSql => $"""
        CREATE TRIGGER jobs_terminal_event
        AFTER UPDATE OF state ON jobs
        WHEN NEW.state IN ({(int)JobState.Succeeded}, {(int)JobState.Failed}, {(int)JobState.Expired})
          AND NEW.completed_at IS NOT NULL
          AND (OLD.state NOT IN ({(int)JobState.Succeeded}, {(int)JobState.Failed}, {(int)JobState.Expired})
               OR OLD.state <> NEW.state)
        BEGIN
          INSERT INTO terminal_job_events(job_id, terminal_state, completed_at, error_code)
          VALUES(
            NEW.id,
            NEW.state,
            NEW.completed_at,
            CASE WHEN NEW.state = {(int)JobState.Expired} THEN 'job_expired' ELSE NEW.error_code END);
        END
        """;

    private static string JobsTerminalEventInsertTriggerSql => $"""
        CREATE TRIGGER jobs_terminal_event_insert
        AFTER INSERT ON jobs
        WHEN NEW.state IN ({(int)JobState.Succeeded}, {(int)JobState.Failed}, {(int)JobState.Expired})
          AND NEW.completed_at IS NOT NULL
        BEGIN
          INSERT INTO terminal_job_events(job_id, terminal_state, completed_at, error_code)
          VALUES(
            NEW.id,
            NEW.state,
            NEW.completed_at,
            CASE WHEN NEW.state = {(int)JobState.Expired} THEN 'job_expired' ELSE NEW.error_code END);
        END
        """;

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var connection = new SqliteConnection(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            if (Volatile.Read(ref _disposed) != 0)
            {
                SqliteConnection.ClearPool(connection);
                throw new ObjectDisposedException(nameof(SqliteJobStore));
            }

            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
            await command.ExecuteNonQueryAsync(cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private static async Task<Job?> GetByIdempotencyHashAsync(SqliteConnection connection, string idempotencyHash, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM jobs WHERE idempotency_key_hash = $idempotencyHash;";
        command.Parameters.AddWithValue("$idempotencyHash", idempotencyHash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
    }

    private static async Task<Job?> GetJobAsync(
        SqliteConnection connection,
        Guid jobId,
        CancellationToken cancellationToken,
        SqliteTransaction transaction)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM jobs WHERE id = $id;";
        command.Parameters.AddWithValue("$id", jobId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadJob(reader) : null;
    }

    private static async Task<LocalUploadLeaseRecord?> GetLocalLeaseAsync(
        SqliteConnection connection,
        Guid requestId,
        CancellationToken cancellationToken,
        SqliteTransaction? transaction = null)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT * FROM local_upload_leases WHERE request_id = $requestId;";
        command.Parameters.AddWithValue("$requestId", requestId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadLocalLease(reader) : null;
    }

    private static void AddLocalLeaseParameters(SqliteCommand command, LocalUploadLeaseRecord lease)
    {
        command.Parameters.AddWithValue("$requestId", lease.RequestId.ToString("D"));
        command.Parameters.AddWithValue("$fingerprint", lease.RequestFingerprint);
        command.Parameters.AddWithValue("$jobId", lease.JobId.ToString("D"));
        command.Parameters.AddWithValue("$leaseHash", lease.LeaseHash);
        command.Parameters.AddWithValue("$protectedLease", lease.ProtectedLease.ToArray());
        command.Parameters.AddWithValue("$sid", lease.SigningUserSid);
        command.Parameters.AddWithValue("$sessionId", lease.SessionId);
        command.Parameters.AddWithValue("$relativePath", lease.RelativePartPath);
        command.Parameters.AddWithValue("$originalName", lease.OriginalName);
        command.Parameters.AddWithValue("$extension", lease.Extension);
        command.Parameters.AddWithValue("$declaredSize", lease.DeclaredSize);
        command.Parameters.AddWithValue("$parameters", lease.CanonicalParametersJson);
        command.Parameters.AddWithValue("$createdAt", ToStorageTime(lease.CreatedAtUtc));
        command.Parameters.AddWithValue("$expiresAt", ToStorageTime(lease.ExpiresAtUtc));
    }

    private static LocalUploadLeaseRecord ReadLocalLease(SqliteDataReader reader) => new(
        Guid.Parse(reader.GetString(reader.GetOrdinal("request_id"))),
        reader.GetString(reader.GetOrdinal("request_fingerprint")),
        Guid.Parse(reader.GetString(reader.GetOrdinal("job_id"))),
        reader.GetString(reader.GetOrdinal("lease_hash")),
        ((byte[])reader[reader.GetOrdinal("protected_lease")]).ToArray(),
        reader.GetString(reader.GetOrdinal("signing_user_sid")),
        reader.GetInt32(reader.GetOrdinal("session_id")),
        reader.GetString(reader.GetOrdinal("relative_part_path")),
        reader.GetString(reader.GetOrdinal("original_name")),
        reader.GetString(reader.GetOrdinal("extension")),
        reader.GetInt64(reader.GetOrdinal("declared_size")),
        reader.GetString(reader.GetOrdinal("parameters_json")),
        ParseStorageTime(reader.GetString(reader.GetOrdinal("created_at"))),
        ParseStorageTime(reader.GetString(reader.GetOrdinal("expires_at"))),
        ReadNullableGuid(reader, "accepted_job_id"));

    private static void AddJobParameters(SqliteCommand command, Job job, string? idempotencyHash)
    {
        command.Parameters.AddWithValue("$id", job.Id.ToString("D"));
        command.Parameters.AddWithValue("$state", (int)job.State);
        command.Parameters.AddWithValue("$kind", (int)job.Kind);
        command.Parameters.AddWithValue("$originalName", job.OriginalName);
        command.Parameters.AddWithValue("$extension", job.Extension);
        command.Parameters.AddWithValue("$parametersJson", job.CanonicalParametersJson);
        command.Parameters.AddWithValue("$inputSha256", job.InputSha256);
        command.Parameters.AddWithValue("$inputSize", job.InputSize);
        command.Parameters.AddWithValue("$idempotencyHash", (object?)idempotencyHash ?? DBNull.Value);
        command.Parameters.AddWithValue("$requestFingerprint", job.RequestFingerprint);
        command.Parameters.AddWithValue("$createdAt", ToStorageTime(job.CreatedAt));
        command.Parameters.AddWithValue(
            "$expiresAt",
            job.ExpiresAt is { } expiresAt ? ToStorageTime(expiresAt) : DBNull.Value);
        command.Parameters.AddWithValue("$source", job.Source);
        command.Parameters.AddWithValue("$correlationId", job.CorrelationId.ToString("D"));
    }

    private static Job ReadJob(SqliteDataReader reader)
    {
        var parametersJson = reader.GetString(reader.GetOrdinal("parameters_json"));
        return new Job(
            Guid.Parse(reader.GetString(reader.GetOrdinal("id"))),
            (JobState)reader.GetInt32(reader.GetOrdinal("state")),
            SigningParameters.Parse(parametersJson))
        {
            Kind = (FileKind)reader.GetInt32(reader.GetOrdinal("kind")),
            OriginalName = reader.GetString(reader.GetOrdinal("original_name")),
            Extension = reader.GetString(reader.GetOrdinal("extension")),
            CanonicalParametersJson = parametersJson,
            InputSha256 = reader.GetString(reader.GetOrdinal("input_sha256")),
            InputSize = reader.GetInt64(reader.GetOrdinal("input_size")),
            ResultSha256 = ReadNullableString(reader, "result_sha256"),
            ResultSize = ReadNullableInt64(reader, "result_size"),
            DispatchId = ReadNullableGuid(reader, "dispatch_id"),
            LeaseConnectionId = ReadNullableGuid(reader, "lease_connection_id"),
            ErrorCode = ReadNullableString(reader, "error_code"),
            ErrorMessage = ReadNullableString(reader, "error_message"),
            AttemptCount = reader.GetInt32(reader.GetOrdinal("attempt_count")),
            RequestFingerprint = reader.GetString(reader.GetOrdinal("request_fingerprint")),
            CreatedAt = ParseStorageTime(reader.GetString(reader.GetOrdinal("created_at"))),
            StartedAt = ReadNullableTime(reader, "started_at"),
            CompletedAt = ReadNullableTime(reader, "completed_at"),
            ExpiresAt = ReadNullableTime(reader, "expires_at"),
            Source = reader.GetString(reader.GetOrdinal("source")),
            CorrelationId = Guid.Parse(reader.GetString(reader.GetOrdinal("correlation_id"))),
        };
    }

    private static TerminalJobEventItem ReadTerminalEvent(SqliteDataReader reader)
    {
        var current = ReadJob(reader);
        var eventState = (JobState)reader.GetInt32(reader.GetOrdinal("event_state"));
        var eventJob = current with
        {
            State = eventState,
            CompletedAt = ParseStorageTime(reader.GetString(reader.GetOrdinal("event_completed_at"))),
            ErrorCode = ReadNullableString(reader, "event_error_code"),
            ErrorMessage = null,
            ResultSize = eventState == JobState.Succeeded ? current.ResultSize : null,
            ResultSha256 = eventState == JobState.Succeeded ? current.ResultSha256 : null,
        };
        return new TerminalJobEventItem(
            reader.GetInt64(reader.GetOrdinal("terminal_sequence")),
            CreatePageItem(eventJob));
    }

    private static string? ReadNullableString(SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static DateTimeOffset? ReadNullableTime(SqliteDataReader reader, string name)
    {
        var value = ReadNullableString(reader, name);
        return value is null ? null : ParseStorageTime(value);
    }

    private static long? ReadNullableInt64(SqliteDataReader reader, string name)
    {
        var ordinal = reader.GetOrdinal(name);
        return reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    }

    private static Guid? ReadNullableGuid(SqliteDataReader reader, string name)
    {
        var value = ReadNullableString(reader, name);
        return value is null ? null : Guid.Parse(value);
    }

    private static void ValidateNewJob(Job job)
    {
        if (job.Id == Guid.Empty || job.State != JobState.Queued || string.IsNullOrWhiteSpace(job.OriginalName) ||
            string.IsNullOrWhiteSpace(job.Extension) || job.InputSize < 0 ||
            (job.ExpiresAt is { } expiresAt && expiresAt == default) ||
            !IsSha256(job.InputSha256) || job.Source is not "api" and not "local")
        {
            throw new ArgumentException("Job metadata is incomplete.", nameof(job));
        }
    }

    private static void ValidateLocalLease(LocalUploadLeaseRecord lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (lease.RequestId == Guid.Empty || lease.JobId == Guid.Empty ||
            !IsSha256(lease.RequestFingerprint) || !IsSha256(lease.LeaseHash) ||
            lease.ProtectedLease.Length == 0 || string.IsNullOrWhiteSpace(lease.SigningUserSid) ||
            lease.SessionId <= 0 || string.IsNullOrWhiteSpace(lease.RelativePartPath) ||
            string.IsNullOrWhiteSpace(lease.OriginalName) || string.IsNullOrWhiteSpace(lease.Extension) ||
            lease.DeclaredSize <= 0 || string.IsNullOrWhiteSpace(lease.CanonicalParametersJson) ||
            lease.CreatedAtUtc == default || lease.ExpiresAtUtc <= lease.CreatedAtUtc ||
            lease.AcceptedJobId is not null)
        {
            throw new ArgumentException("Local upload lease metadata is invalid.", nameof(lease));
        }
    }

    private static FileKind GetKind(SigningParameters parameters) => parameters switch
    {
        PdfParameters => FileKind.Pdf,
        AuthenticodeParameters => FileKind.Authenticode,
        _ => throw new ArgumentException("Unsupported signing parameters.", nameof(parameters)),
    };

    private static string NormalizeSource(string? source) => source switch
    {
        "api" => "api",
        "local" => "local",
        _ => throw new ArgumentException("Job source is invalid.", nameof(source)),
    };

    private static JobPageItem CreatePageItem(Job job) => new(
        job.Id,
        job.Source,
        job.Kind == FileKind.Authenticode ? "authenticode" : "pdf",
        StateName(job.State),
        job.OriginalName,
        job.CreatedAt,
        job.StartedAt,
        job.CompletedAt,
        job.State switch
        {
            JobState.Failed => job.ErrorCode,
            JobState.Expired => "job_expired",
            _ => null,
        },
        job.CorrelationId,
        job.State == JobState.Succeeded && job.ResultSize is > 0 && job.ResultSha256 is not null);

    private static bool IsActive(JobState state) =>
        state is JobState.Queued or JobState.WaitingForAgent or JobState.Signing or JobState.Verifying;

    private static string StateName(JobState state) => state switch
    {
        JobState.Queued => "queued",
        JobState.WaitingForAgent => "waiting_for_agent",
        JobState.Signing => "signing",
        JobState.Verifying => "verifying",
        JobState.Succeeded => "succeeded",
        JobState.Failed => "failed",
        JobState.Expired => "expired",
        _ => throw new InvalidOperationException("job_state_invalid"),
    };

    private static bool IsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string HashText(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private async Task<bool> ExecuteLeaseUpdateAsync(
        Guid jobId,
        Guid dispatchId,
        Guid connectionId,
        JobState? expectedState,
        string assignments,
        Action<SqliteCommand> addParameters,
        CancellationToken cancellationToken,
        string? additionalPredicate = null,
        bool addStateParameters = false)
    {
        RequireId(jobId, nameof(jobId));
        RequireId(dispatchId, nameof(dispatchId));
        RequireId(connectionId, nameof(connectionId));
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            UPDATE jobs
            SET {assignments}
            WHERE id = $id
              AND dispatch_id = $dispatchId
              AND lease_connection_id = $connectionId
              {(expectedState is null ? string.Empty : "AND state = $expectedState")}
              {(additionalPredicate is null ? string.Empty : "AND " + additionalPredicate)};
            """;
        command.Parameters.AddWithValue("$id", jobId.ToString("D"));
        command.Parameters.AddWithValue("$dispatchId", dispatchId.ToString("D"));
        command.Parameters.AddWithValue("$connectionId", connectionId.ToString("D"));
        if (expectedState is not null)
        {
            command.Parameters.AddWithValue("$expectedState", (int)expectedState.Value);
        }

        if (addStateParameters)
        {
            command.Parameters.AddWithValue("$signing", (int)JobState.Signing);
            command.Parameters.AddWithValue("$verifying", (int)JobState.Verifying);
        }

        addParameters(command);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static void RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A nonempty identifier is required.", parameterName);
        }
    }

    private static void ValidateFailure(string errorCode, string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(errorCode) || errorCode.Length > 64 ||
            string.IsNullOrWhiteSpace(errorMessage) || errorMessage.Length > 256 ||
            errorCode.Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '_')) ||
            errorMessage.Any(char.IsControl))
        {
            throw new ArgumentException("Failure metadata is invalid.");
        }
    }

    private static string ToStorageTime(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseStorageTime(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}
