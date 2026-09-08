using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Api;
using CodeSignAuto.Service.Ipc;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class LocalJobUploadCoordinatorTests
{
    private const string Sid = "S-1-5-21-1000";
    private static readonly DateTimeOffset Now =
        new(2026, 8, 8, 1, 0, 0, TimeSpan.Zero);
    private const string ParametersJson =
        "{\"appendSignature\":false,\"certificateSerialNumber\":\"52A1B4C9\",\"digestAlgorithm\":\"sha256\",\"kind\":\"authenticode\"}";

    [Fact]
    public async Task Succeeded_api_job_exposes_result_metadata_for_create_new_save()
    {
        using var fixture = new LocalFixture();
        var job = await fixture.Store.CreateAsync(new Job(
            Guid.NewGuid(),
            JobState.Queued,
            new AuthenticodeParameters("52A1B4C9", "sha256", false))
        {
            OriginalName = "api.exe",
            Extension = ".exe",
            InputSha256 = new string('a', 64),
            InputSize = 12,
            ExpiresAt = Now.AddHours(24),
            Source = "api",
        });
        await using (var connection = new SqliteConnection($"Data Source={fixture.DatabasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE jobs SET state=$state, result_size=12, result_sha256=$hash, completed_at=$completed WHERE id=$id;";
            command.Parameters.AddWithValue("$state", (int)JobState.Succeeded);
            command.Parameters.AddWithValue("$hash", new string('b', 64));
            command.Parameters.AddWithValue("$completed", Now.ToString("O"));
            command.Parameters.AddWithValue("$id", job.Id.ToString("D"));
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        var response = Assert.IsType<LocalJobResultMetadata>(await fixture.Coordinator.GetResultAsync(
            new LocalJobResultRequest(Guid.NewGuid(), job.Id),
            Identity(),
            CancellationToken.None));

        Assert.Equal(job.Id, response.JobId);
        Assert.Equal(12, response.Size);
        Assert.Equal(new string('b', 64), response.Sha256);
    }

    [Fact]
    public async Task Create_is_durable_idempotent_and_does_not_create_a_job()
    {
        using var fixture = new LocalFixture();
        var request = CreateRequest();

        var first = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), CancellationToken.None));
        var retry = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), CancellationToken.None));

        Assert.Equal(first, retry);
        Assert.Equal(Now.AddMinutes(10), first.ExpiresAtUtc);
        Assert.Equal($"{first.JobId:N}/input.exe.part", first.RelativePartPath);
        Assert.Empty(await fixture.Store.GetAllAsync());
        Assert.True(Directory.Exists(Path.Combine(fixture.Spool.Root, first.JobId.ToString("N"))));

        await using var connection = new SqliteConnection($"Data Source={fixture.DatabasePath}");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT lease_hash, protected_lease FROM local_upload_leases WHERE request_id=$id;";
        command.Parameters.AddWithValue("$id", request.RequestId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(Convert.FromHexString(first.LeaseId))).ToLowerInvariant(),
            reader.GetString(0));
        Assert.DoesNotContain(first.LeaseId, Convert.ToHexString((byte[])reader[1]), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Reusing_request_id_with_a_different_fingerprint_is_rejected_without_a_second_lease()
    {
        using var fixture = new LocalFixture();
        var request = CreateRequest();
        await fixture.Coordinator.CreateAsync(request, Identity(), CancellationToken.None);

        var rejected = Assert.IsType<LocalJobRejected>(await fixture.Coordinator.CreateAsync(
            request with { DeclaredSize = request.DeclaredSize + 1 },
            Identity(),
            CancellationToken.None));

        Assert.Equal("local_request_conflict", rejected.ErrorCode);
        Assert.Empty(await fixture.Store.GetAllAsync());
        Assert.Single(Directory.GetDirectories(fixture.Spool.Root));
    }

    [Fact]
    public async Task Complete_reverifies_the_service_path_and_atomically_creates_one_local_job()
    {
        using var fixture = new LocalFixture();
        var input = "MZ-real-input"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), CancellationToken.None));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);
        var sha256 = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        var completed = new LocalJobUploadCompleted(
            request.RequestId,
            lease.JobId,
            lease.LeaseId,
            input.Length,
            sha256);

        var accepted = Assert.IsType<LocalJobAccepted>(
            await fixture.Coordinator.CompleteAsync(completed, Identity(), CancellationToken.None));
        var duplicate = Assert.IsType<LocalJobAccepted>(
            await fixture.Coordinator.CompleteAsync(completed, Identity(), CancellationToken.None));
        var job = Assert.Single(await fixture.Store.GetAllAsync());

        Assert.Equal(accepted, duplicate);
        Assert.Equal(lease.JobId, accepted.JobId);
        Assert.Equal(JobState.Queued, job.State);
        Assert.Equal("local", job.Source);
        Assert.Equal(input.Length, job.InputSize);
        Assert.Equal(sha256, job.InputSha256);
        Assert.True(File.Exists(fixture.Spool.GetInputPath(job.Id, job.Extension)));
        Assert.False(File.Exists(partPath));
        Assert.Equal([job.Id], fixture.Dispatcher.Enqueued);
    }

    [Fact]
    public async Task Administrator_upload_uses_the_verified_control_identity_and_never_impersonates_the_signing_user()
    {
        using var fixture = new LocalFixture();
        var administrator = new AgentConnectionIdentity(654, 9, "S-1-5-21-2000");
        var input = "MZ-admin-input"u8.ToArray();
        var request = CreateRequest(input.Length);
        var handler = Assert.IsAssignableFrom<IAdministratorLocalJobRequestHandler>(fixture.Coordinator);
        var lease = Assert.IsType<LocalJobUploadLease>(await handler.HandleAdministratorAsync(
            request,
            administrator,
            CancellationToken.None));
        await File.WriteAllBytesAsync(
            Path.Combine(
                fixture.Spool.Root,
                lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar)),
            input);
        var completed = new LocalJobUploadCompleted(
            request.RequestId,
            lease.JobId,
            lease.LeaseId,
            input.Length,
            Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant());

        var mismatched = Assert.IsType<LocalJobRejected>(await handler.HandleAdministratorAsync(
            completed,
            administrator with { SessionId = 10 },
            CancellationToken.None));
        var accepted = Assert.IsType<LocalJobAccepted>(await handler.HandleAdministratorAsync(
            completed,
            administrator,
            CancellationToken.None));

        Assert.Equal("local_upload_identity_mismatch", mismatched.ErrorCode);
        Assert.Equal(lease.JobId, accepted.JobId);
        Assert.Single(await fixture.Store.GetAllAsync());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(168)]
    public async Task Configured_retention_controls_local_job_expiry(int retentionHours)
    {
        using var fixture = new LocalFixture(retentionHours: retentionHours);
        var input = "MZ-retention-input"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);

        Assert.IsType<LocalJobAccepted>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            default));
        var job = Assert.Single(await fixture.Store.GetAllAsync());

        Assert.Equal(Now.AddHours(retentionHours), job.ExpiresAt);
    }

    [Fact]
    public async Task Zero_retention_makes_the_accepted_local_job_permanent_but_not_its_upload_lease()
    {
        var root = Path.Combine(Path.GetTempPath(), "CodeSignAuto-local-permanent-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new InMemoryRetentionJobStore();
            var spool = new SpoolStore(Path.Combine(root, "spool"));
            var dispatcher = new RecordingDispatcher();
            var coordinator = new LocalJobUploadCoordinator(
                store,
                spool,
                dispatcher,
                new MutableTimeProvider(Now),
                Sid,
                new XorLeaseProtector(),
                retentionHours: 0);
            var input = "MZ-permanent-input"u8.ToArray();
            var request = CreateRequest(input.Length);

            var lease = Assert.IsType<LocalJobUploadLease>(
                await coordinator.CreateAsync(request, Identity(), default));
            await File.WriteAllBytesAsync(
                Path.Combine(root, "spool", lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar)),
                input);
            var accepted = Assert.IsType<LocalJobAccepted>(await coordinator.CompleteAsync(
                new LocalJobUploadCompleted(
                    request.RequestId,
                    lease.JobId,
                    lease.LeaseId,
                    input.Length,
                    Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
                Identity(),
                default));
            var job = await store.GetAsync(accepted.JobId);

            Assert.Equal(Now.Add(LocalJobUploadCoordinator.LeaseDuration), lease.ExpiresAtUtc);
            Assert.NotEqual(default, lease.ExpiresAtUtc);
            Assert.Null(job!.ExpiresAt);
            Assert.Equal([accepted.JobId], dispatcher.Enqueued);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Changed_retention_applies_only_to_jobs_accepted_by_the_new_coordinator()
    {
        using var fixture = new LocalFixture(retentionHours: 168);
        var retained = await AcceptLocalJobAsync(
            fixture,
            fixture.Coordinator,
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "retained");
        var permanent = await AcceptLocalJobAsync(
            fixture,
            fixture.CreateCoordinator(retentionHours: 0),
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            "permanent");

        Assert.Equal(Now.AddHours(168), (await fixture.Store.GetAsync(retained.Id))!.ExpiresAt);
        Assert.Null((await fixture.Store.GetAsync(permanent.Id))!.ExpiresAt);
    }

    [Fact]
    public async Task Live_retention_provider_changes_only_subsequently_accepted_jobs()
    {
        using var fixture = new LocalFixture(retentionHours: 168);
        var retentionHours = 168;
        var coordinator = new LocalJobUploadCoordinator(
            fixture.Store,
            fixture.Spool,
            fixture.Dispatcher,
            fixture.Time,
            Sid,
            new XorLeaseProtector(),
            retentionHours: retentionHours,
            retentionHoursProvider: () => retentionHours);
        var retained = await AcceptLocalJobAsync(
            fixture,
            coordinator,
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            "retained-live");

        retentionHours = 0;
        var permanent = await AcceptLocalJobAsync(
            fixture,
            coordinator,
            Guid.Parse("44444444-4444-4444-4444-444444444444"),
            "permanent-live");

        Assert.Equal(Now.AddHours(168), (await fixture.Store.GetAsync(retained.Id))!.ExpiresAt);
        Assert.Null((await fixture.Store.GetAsync(permanent.Id))!.ExpiresAt);
    }

    [Fact]
    public async Task Sqlite_v7_persists_a_permanent_local_job_as_sql_null()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "CodeSignAuto-null-expiry-" + Guid.NewGuid().ToString("N"));
        var databasePath = Path.Combine(root, "jobs.db");
        try
        {
            using var store = new SqliteJobStore(databasePath);
            var job = new Job(
                Guid.NewGuid(),
                JobState.Queued,
                new AuthenticodeParameters("52A1B4C9", "sha256", false))
            {
                OriginalName = "permanent.exe",
                Extension = ".exe",
                InputSha256 = new string('a', 64),
                InputSize = 12,
                Source = "local",
            };

            var created = await store.CreateAsync(job);
            var reloaded = await store.GetAsync(created.Id);

            Assert.Null(created.ExpiresAt);
            Assert.Null(reloaded!.ExpiresAt);
            var inspectionConnectionString = new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Pooling = false,
            }.ToString();
            await using var connection = new SqliteConnection(inspectionConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM jobs WHERE id = $id AND expires_at IS NULL;";
            command.Parameters.AddWithValue("$id", created.Id.ToString("D"));
            Assert.Equal(1L, await command.ExecuteScalarAsync());
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Theory]
    [InlineData("identity")]
    [InlineData("lease")]
    [InlineData("size")]
    [InlineData("hash")]
    public async Task Accepted_completion_is_idempotent_only_when_the_entire_completion_still_matches(string mismatch)
    {
        using var fixture = new LocalFixture();
        var input = "MZ-real-input"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        await File.WriteAllBytesAsync(
            Path.Combine(fixture.Spool.Root, lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar)),
            input);
        var completed = new LocalJobUploadCompleted(
            request.RequestId,
            lease.JobId,
            lease.LeaseId,
            input.Length,
            Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant());
        Assert.IsType<LocalJobAccepted>(await fixture.Coordinator.CompleteAsync(completed, Identity(), default));

        var retry = completed with
        {
            LeaseId = mismatch == "lease" ? new string('f', 32) : completed.LeaseId,
            ActualSize = mismatch == "size" ? completed.ActualSize + 1 : completed.ActualSize,
            Sha256 = mismatch == "hash" ? new string('b', 64) : completed.Sha256,
        };
        var response = await fixture.Coordinator.CompleteAsync(
            retry,
            mismatch == "identity" ? new AgentConnectionIdentity(321, 8, Sid) : Identity(),
            default);

        Assert.IsType<LocalJobRejected>(response);
        Assert.Single(await fixture.Store.GetAllAsync());
        Assert.Single(fixture.Dispatcher.Enqueued);
    }

    [Theory]
    [InlineData("size")]
    [InlineData("hash")]
    [InlineData("magic")]
    [InlineData("identity")]
    public async Task Completion_mismatch_never_creates_or_dispatches_a_job(string mismatch)
    {
        using var fixture = new LocalFixture();
        var input = mismatch == "magic" ? "NO-real-input"u8.ToArray() : "MZ-real-input"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), CancellationToken.None));
        var partPath = Path.Combine(fixture.Spool.Root, lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);
        var actualHash = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        var completed = new LocalJobUploadCompleted(
            request.RequestId,
            lease.JobId,
            lease.LeaseId,
            mismatch == "size" ? input.Length + 1 : input.Length,
            mismatch == "hash" ? new string('b', 64) : actualHash);

        var rejected = Assert.IsType<LocalJobRejected>(await fixture.Coordinator.CompleteAsync(
            completed,
            mismatch == "identity" ? new AgentConnectionIdentity(321, 8, Sid) : Identity(),
            CancellationToken.None));

        Assert.Contains(rejected.ErrorCode, new[]
        {
            "local_upload_size_mismatch",
            "local_upload_hash_mismatch",
            "file_signature_mismatch",
            "local_upload_identity_mismatch",
        });
        Assert.Empty(await fixture.Store.GetAllAsync());
        Assert.Empty(fixture.Dispatcher.Enqueued);
    }

    [Fact]
    public async Task Lease_expires_at_the_exact_ten_minute_boundary_and_cleanup_removes_only_its_artifacts()
    {
        using var fixture = new LocalFixture();
        var request = CreateRequest();
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), CancellationToken.None));
        var partPath = Path.Combine(fixture.Spool.Root, lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, "MZ-partial"u8.ToArray());
        fixture.Time.Set(Now.AddMinutes(10));

        var rejected = Assert.IsType<LocalJobRejected>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                10,
                Convert.ToHexString(SHA256.HashData("MZ-partial"u8)).ToLowerInvariant()),
            Identity(),
            CancellationToken.None));
        var cleaned = await fixture.Coordinator.CleanupExpiredAsync(CancellationToken.None);

        Assert.Equal("local_upload_expired", rejected.ErrorCode);
        Assert.Equal(1, cleaned);
        Assert.False(Directory.Exists(Path.GetDirectoryName(partPath)));
        Assert.Empty(await fixture.Store.GetAllAsync());
    }

    [Fact]
    public async Task Startup_preserves_unaccepted_lease_part_and_promoted_input_for_same_lease_completion()
    {
        using var fixture = new LocalFixture();
        var input = "MZ-restart-input"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);
        var cleanup = new JobCleanupService(
            fixture.Store,
            fixture.Spool,
            new JobCompletionNotifier(fixture.Store),
            fixture.Time,
            NullLogger<JobCleanupService>.Instance,
            fixture.Coordinator);

        await cleanup.RecoverStartupAsync(default);
        Assert.True(File.Exists(partPath));

        var sha256 = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        await using (var upload = await fixture.Spool.OpenLocalUploadAsync(lease.JobId, ".exe"))
        {
            await fixture.Spool.PromoteLocalUploadAsync(upload, input.Length, sha256);
        }

        var inputPath = fixture.Spool.GetInputPath(lease.JobId, ".exe");
        await cleanup.RecoverStartupAsync(default);
        Assert.True(File.Exists(inputPath));
        var recoveredLease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var completed = new LocalJobUploadCompleted(
            request.RequestId,
            lease.JobId,
            lease.LeaseId,
            input.Length,
            sha256);

        var accepted = Assert.IsType<LocalJobAccepted>(
            await fixture.Coordinator.CompleteAsync(completed, Identity(), default));
        var duplicate = Assert.IsType<LocalJobAccepted>(
            await fixture.Coordinator.CompleteAsync(completed, Identity(), default));

        Assert.Equal(lease, recoveredLease);
        Assert.Equal(accepted, duplicate);
        Assert.Single(await fixture.Store.GetAllAsync());
        Assert.Single(fixture.Dispatcher.Enqueued);
    }

    [Fact]
    public async Task Local_create_rejects_append_signature_before_preparing_a_lease_or_job()
    {
        using var fixture = new LocalFixture();
        var request = CreateRequest() with
        {
            CanonicalParametersJson =
                "{\"appendSignature\":true,\"certificateSerialNumber\":\"52A1B4C9\",\"digestAlgorithm\":\"sha256\",\"kind\":\"authenticode\"}",
        };

        var rejected = Assert.IsType<LocalJobRejected>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));

        Assert.Equal("invalid_parameters", rejected.ErrorCode);
        Assert.Empty(await fixture.Store.GetAllAsync());
        Assert.False(Directory.Exists(fixture.Spool.Root));
    }

    [Theory]
    [InlineData(".msi")]
    [InlineData(".cat")]
    public async Task Fake_native_authenticode_containers_are_rejected_before_job_creation(string extension)
    {
        using var fixture = new LocalFixture();
        var input = "MZ-not-a-native-container"u8.ToArray();
        var request = CreateRequest(input.Length) with
        {
            OriginalName = "release" + extension,
            Extension = extension,
        };
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);

        var rejected = Assert.IsType<LocalJobRejected>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            default));

        Assert.Equal("file_signature_mismatch", rejected.ErrorCode);
        Assert.Empty(await fixture.Store.GetAllAsync());
        Assert.Empty(fixture.Dispatcher.Enqueued);
    }

    [Theory]
    [InlineData(2, 10, 10, 50, 50)]
    [InlineData(1, 10, 10, 201, 50)]
    [InlineData(1, -1, 10, 50, 50)]
    public async Task Pdf_page_and_box_must_fit_the_real_uploaded_page_before_job_creation(
        int page,
        double left,
        double bottom,
        double right,
        double top)
    {
        using var fixture = new LocalFixture();
        var input = CreateSinglePagePdf(width: 200, height: 300);
        var parameters = new PdfParameters(
            "6F09D233",
            "sha256",
            page,
            new PdfBox(left, bottom, right, top),
            "Signature1",
            null,
            null);
        var request = CreateRequest(input.Length) with
        {
            OriginalName = "document.pdf",
            Extension = ".pdf",
            CanonicalParametersJson = SigningParameters.SerializeCanonical(parameters),
        };
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);

        var rejected = Assert.IsType<LocalJobRejected>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            default));

        Assert.Equal("invalid_parameters", rejected.ErrorCode);
        Assert.Empty(await fixture.Store.GetAllAsync());
        Assert.Empty(fixture.Dispatcher.Enqueued);
    }

    [Fact]
    public async Task Valid_pdf_page_and_box_from_the_hashed_upload_is_accepted()
    {
        using var fixture = new LocalFixture();
        var input = CreateSinglePagePdf(width: 200, height: 300);
        var request = CreateRequest(input.Length) with
        {
            OriginalName = "document.pdf",
            Extension = ".pdf",
            CanonicalParametersJson = SigningParameters.SerializeCanonical(new PdfParameters(
                "6F09D233",
                "sha256",
                1,
                new PdfBox(10, 20, 190, 290),
                "Signature1",
                null,
                null)),
        };
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);

        var accepted = Assert.IsType<LocalJobAccepted>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            default));

        Assert.Equal(lease.JobId, accepted.JobId);
        Assert.Single(await fixture.Store.GetAllAsync());
        Assert.Equal([lease.JobId], fixture.Dispatcher.Enqueued);
    }

    [Fact]
    public async Task Existing_local_upload_can_complete_while_upgrade_drain_blocks_new_creates()
    {
        var gate = new UpgradeAdmissionGate();
        using var fixture = new LocalFixture(upgradeGate: gate);
        var input = "MZ-drain-barrier"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), CancellationToken.None));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);

        using var cancellation = new CancellationTokenSource();
        var drain = new UpgradeDrainCoordinator(gate, fixture.Store, fixture.Time)
            .DrainAsync(TimeSpan.FromSeconds(2), cancellation.Token);
        await WaitUntilAsync(() => gate.IsDraining);

        Assert.IsType<LocalJobAccepted>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            CancellationToken.None));
        Assert.False(drain.IsCompleted);

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => drain);
        Assert.False(gate.IsDraining);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(90)]
    [InlineData(270)]
    public async Task Pdf_box_uses_pyhanko_unrotated_crop_box_coordinates(int rotation)
    {
        using var fixture = new LocalFixture();
        var input = CreateSinglePagePdf(
            width: 400,
            height: 500,
            lowerLeftX: -50,
            lowerLeftY: 20,
            rotation: rotation,
            cropBox: (10, 40, 310, 480));
        var request = PdfRequest(input, new PdfBox(20, 50, 300, 470));
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);

        var accepted = Assert.IsType<LocalJobAccepted>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            default));

        Assert.Equal(lease.JobId, accepted.JobId);
        Assert.Single(await fixture.Store.GetAllAsync());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(90)]
    [InlineData(270)]
    public async Task Pdf_box_below_nonzero_crop_box_origin_is_rejected(int rotation)
    {
        using var fixture = new LocalFixture();
        var input = CreateSinglePagePdf(
            width: 400,
            height: 500,
            lowerLeftX: -50,
            lowerLeftY: 20,
            rotation: rotation,
            cropBox: (10, 40, 310, 480));
        var request = PdfRequest(input, new PdfBox(0, 30, 20, 50));
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);

        var rejected = Assert.IsType<LocalJobRejected>(await fixture.Coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            default));

        Assert.Equal("invalid_parameters", rejected.ErrorCode);
        Assert.Empty(await fixture.Store.GetAllAsync());
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("nested")]
    [InlineData("reparse")]
    public async Task Expired_lease_cleanup_preserves_all_artifacts_and_row_when_any_entry_is_not_exact(
        string unsafeEntry)
    {
        using var fixture = new LocalFixture();
        var request = CreateRequest();
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var directory = Path.Combine(fixture.Spool.Root, lease.JobId.ToString("N"));
        var partPath = Path.Combine(directory, "input.exe.part");
        await File.WriteAllBytesAsync(partPath, "MZ-partial"u8.ToArray());
        var external = Path.Combine(fixture.Spool.Root, "..", $"external-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(external, "external");
        string unsafePath;
        if (unsafeEntry == "nested")
        {
            unsafePath = Path.Combine(directory, "nested");
            Directory.CreateDirectory(unsafePath);
            await File.WriteAllTextAsync(Path.Combine(unsafePath, "keep.txt"), "keep");
        }
        else if (unsafeEntry == "reparse")
        {
            unsafePath = Path.Combine(directory, "foreign-link");
            File.CreateSymbolicLink(unsafePath, external);
        }
        else
        {
            unsafePath = Path.Combine(directory, "unknown.bin");
            await File.WriteAllTextAsync(unsafePath, "keep");
        }

        fixture.Time.Set(Now.AddMinutes(10));
        await Assert.ThrowsAsync<SpoolException>(() => fixture.Coordinator.CleanupExpiredAsync(default));

        Assert.NotNull(await fixture.Store.GetLocalLeaseAsync(request.RequestId, default));
        Assert.True(File.Exists(partPath));
        Assert.True(File.Exists(unsafePath) || Directory.Exists(unsafePath));
        Assert.Equal("external", await File.ReadAllTextAsync(external));
    }

    [Fact]
    public async Task Delayed_response_after_database_accept_allows_same_completion_retry_without_a_second_job()
    {
        var observer = new BlockingAcceptanceObserver();
        using var fixture = new LocalFixture(observer);
        var input = "MZ-response-delay"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);
        var completed = new LocalJobUploadCompleted(
            request.RequestId,
            lease.JobId,
            lease.LeaseId,
            input.Length,
            Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant());

        var delayed = fixture.Coordinator.CompleteAsync(completed, Identity(), default);
        await observer.Entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var retry = Assert.IsType<LocalJobAccepted>(
            await fixture.Coordinator.CompleteAsync(completed, Identity(), default));

        Assert.Equal(lease.JobId, retry.JobId);
        Assert.Single(await fixture.Store.GetAllAsync());
        observer.Release();
        Assert.Equal(retry, Assert.IsType<LocalJobAccepted>(await delayed));
        Assert.Single(await fixture.Store.GetAllAsync());
        Assert.Single(fixture.Dispatcher.Enqueued);
    }

    [Fact]
    public async Task Observer_failure_after_database_accept_returns_acceptance_and_wakes_dispatcher_once()
    {
        using var fixture = new LocalFixture(new ThrowingAcceptanceObserver());
        fixture.Dispatcher.ThrowAfterEnqueue = true;
        var input = "MZ-observer-failure"u8.ToArray();
        var request = CreateRequest(input.Length);
        var lease = Assert.IsType<LocalJobUploadLease>(
            await fixture.Coordinator.CreateAsync(request, Identity(), default));
        var partPath = Path.Combine(
            fixture.Spool.Root,
            lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar));
        await File.WriteAllBytesAsync(partPath, input);
        var completed = new LocalJobUploadCompleted(
            request.RequestId,
            lease.JobId,
            lease.LeaseId,
            input.Length,
            Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant());

        var accepted = Assert.IsType<LocalJobAccepted>(
            await fixture.Coordinator.CompleteAsync(completed, Identity(), default));
        var retry = Assert.IsType<LocalJobAccepted>(
            await fixture.Coordinator.CompleteAsync(completed, Identity(), default));

        Assert.Equal(accepted, retry);
        Assert.Equal(lease.JobId, accepted.JobId);
        Assert.Single(await fixture.Store.GetAllAsync());
        Assert.Equal([lease.JobId], fixture.Dispatcher.Enqueued);
    }

    private static byte[] CreateSinglePagePdf(
        int width,
        int height,
        int lowerLeftX = 0,
        int lowerLeftY = 0,
        int rotation = 0,
        (int Left, int Bottom, int Right, int Top)? cropBox = null)
    {
        var upperRightX = lowerLeftX + width;
        var upperRightY = lowerLeftY + height;
        var crop = cropBox is { } value
            ? $" /CropBox [{value.Left} {value.Bottom} {value.Right} {value.Top}]"
            : string.Empty;
        var rotate = rotation == 0 ? string.Empty : $" /Rotate {rotation}";
        var objects = new[]
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            $"<< /Type /Page /Parent 2 0 R /MediaBox [{lowerLeftX} {lowerLeftY} {upperRightX} {upperRightY}]{crop}{rotate} /Resources << >> >>",
        };
        using var stream = new MemoryStream();
        using var writer = new StreamWriter(stream, System.Text.Encoding.ASCII, leaveOpen: true)
        {
            NewLine = "\n",
        };
        writer.WriteLine("%PDF-1.4");
        writer.Flush();
        var offsets = new List<long> { 0 };
        for (var index = 0; index < objects.Length; index++)
        {
            offsets.Add(stream.Position);
            writer.WriteLine($"{index + 1} 0 obj");
            writer.WriteLine(objects[index]);
            writer.WriteLine("endobj");
            writer.Flush();
        }

        var xref = stream.Position;
        writer.WriteLine("xref");
        writer.WriteLine($"0 {objects.Length + 1}");
        writer.WriteLine("0000000000 65535 f ");
        foreach (var offset in offsets.Skip(1))
        {
            writer.WriteLine($"{offset:0000000000} 00000 n ");
        }

        writer.WriteLine("trailer");
        writer.WriteLine($"<< /Size {objects.Length + 1} /Root 1 0 R >>");
        writer.WriteLine("startxref");
        writer.WriteLine(xref);
        writer.WriteLine("%%EOF");
        writer.Flush();
        return stream.ToArray();
    }

    private static LocalJobCreateRequest PdfRequest(byte[] input, PdfBox box) =>
        CreateRequest(input.Length) with
        {
            OriginalName = "document.pdf",
            Extension = ".pdf",
            CanonicalParametersJson = SigningParameters.SerializeCanonical(new PdfParameters(
                "6F09D233",
                "sha256",
                1,
                box,
                "Signature1",
                null,
                null)),
        };

    private static LocalJobCreateRequest CreateRequest(long size = 12) => new(
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        "release.exe",
        ".exe",
        size,
        ParametersJson);

    private static async Task<Job> AcceptLocalJobAsync(
        LocalFixture fixture,
        LocalJobUploadCoordinator coordinator,
        Guid requestId,
        string marker)
    {
        var input = Encoding.UTF8.GetBytes("MZ-" + marker);
        var request = CreateRequest(input.Length) with
        {
            RequestId = requestId,
            OriginalName = marker + ".exe",
        };
        var lease = Assert.IsType<LocalJobUploadLease>(
            await coordinator.CreateAsync(request, Identity(), default));
        await File.WriteAllBytesAsync(
            Path.Combine(
                fixture.Spool.Root,
                lease.RelativePartPath.Replace('/', Path.DirectorySeparatorChar)),
            input);
        var accepted = Assert.IsType<LocalJobAccepted>(await coordinator.CompleteAsync(
            new LocalJobUploadCompleted(
                requestId,
                lease.JobId,
                lease.LeaseId,
                input.Length,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant()),
            Identity(),
            default));
        return Assert.IsType<Job>(await fixture.Store.GetAsync(accepted.JobId));
    }

    private static AgentConnectionIdentity Identity() => new(321, 7, Sid);

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(1);
        while (!condition())
        {
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException();
            }

            await Task.Delay(5);
        }
    }

    private sealed class LocalFixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "CodeSignAuto-local-" + Guid.NewGuid().ToString("N"));

        public LocalFixture(
            ILocalJobAcceptanceObserver? acceptanceObserver = null,
            int retentionHours = 24,
            IUpgradeAdmissionGate? upgradeGate = null)
        {
            Directory.CreateDirectory(_root);
            DatabasePath = Path.Combine(_root, "jobs.db");
            Store = new SqliteJobStore(DatabasePath);
            Spool = new SpoolStore(Path.Combine(_root, "spool"));
            Dispatcher = new RecordingDispatcher();
            Time = new MutableTimeProvider(Now);
            Coordinator = new LocalJobUploadCoordinator(
                Store,
                Spool,
                Dispatcher,
                Time,
                Sid,
                new XorLeaseProtector(),
                acceptanceObserver: acceptanceObserver,
                retentionHours: retentionHours,
                upgradeGate: upgradeGate);
        }

        public string DatabasePath { get; }
        public SqliteJobStore Store { get; }
        public SpoolStore Spool { get; }
        public RecordingDispatcher Dispatcher { get; }
        public MutableTimeProvider Time { get; }
        public LocalJobUploadCoordinator Coordinator { get; }

        public LocalJobUploadCoordinator CreateCoordinator(int retentionHours) => new(
            Store,
            Spool,
            Dispatcher,
            Time,
            Sid,
            new XorLeaseProtector(),
            retentionHours: retentionHours);

        public void Dispose()
        {
            Store.Dispose();
            using var directConnection = new SqliteConnection($"Data Source={DatabasePath}");
            SqliteConnection.ClearPool(directConnection);
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class XorLeaseProtector : ILocalLeaseProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> lease) => lease.ToArray().Select(value => (byte)(value ^ 0xa5)).ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedLease) => Protect(protectedLease);
    }

    private sealed class RecordingDispatcher : IJobDispatcher
    {
        public List<Guid> Enqueued { get; } = [];

        public bool ThrowAfterEnqueue { get; set; }

        public void Enqueue(Guid jobId)
        {
            Enqueued.Add(jobId);
            if (ThrowAfterEnqueue)
            {
                throw new IOException("dispatcher_wake_failed_after_commit");
            }
        }
    }

    private sealed class BlockingAcceptanceObserver : ILocalJobAcceptanceObserver
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task AfterAcceptedAsync(
            Guid requestId,
            Guid jobId,
            CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class ThrowingAcceptanceObserver : ILocalJobAcceptanceObserver
    {
        public Task AfterAcceptedAsync(
            Guid requestId,
            Guid jobId,
            CancellationToken cancellationToken) =>
            Task.FromException(new IOException("observer_failed_after_commit"));
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Set(DateTimeOffset value) => _now = value;
    }
}
