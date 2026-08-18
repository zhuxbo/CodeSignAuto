using System.Security.Cryptography;
using System.Text;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Ipc;

namespace SimplySignAuto.Service.Jobs;

public interface ILocalLeaseProtector
{
    byte[] Protect(ReadOnlySpan<byte> lease);

    byte[] Unprotect(ReadOnlySpan<byte> protectedLease);
}

public sealed class WindowsLocalLeaseProtector : ILocalLeaseProtector
{
    private static readonly byte[] Entropy = "SimplySignAuto/local-upload/v1"u8.ToArray();

    public byte[] Protect(ReadOnlySpan<byte> lease)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows DPAPI is required.");
        }

        return ProtectedData.Protect(lease.ToArray(), Entropy, DataProtectionScope.LocalMachine);
    }

    public byte[] Unprotect(ReadOnlySpan<byte> protectedLease)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows DPAPI is required.");
        }

        return ProtectedData.Unprotect(protectedLease.ToArray(), Entropy, DataProtectionScope.LocalMachine);
    }
}

public interface ILocalJobRequestHandler
{
    Task<AgentMessage> HandleAsync(
        AgentMessage request,
        AgentConnectionIdentity identity,
        CancellationToken cancellationToken);
}

public interface IAdministratorLocalJobRequestHandler
{
    Task<AgentMessage> HandleAdministratorAsync(
        AgentMessage request,
        AgentConnectionIdentity identity,
        CancellationToken cancellationToken);
}

public interface ILocalJobAcceptanceObserver
{
    Task AfterAcceptedAsync(
        Guid requestId,
        Guid jobId,
        CancellationToken cancellationToken);
}

public interface ILocalUploadCleanup
{
    Task<int> CleanupExpiredAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<LocalUploadOwnership>> GetStartupOwnershipAsync(
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<LocalUploadOwnership>>([]);
}

public sealed record LocalUploadOwnership(Guid JobId, string Extension);

public sealed class LocalJobUploadCoordinator :
    ILocalJobRequestHandler,
    IAdministratorLocalJobRequestHandler,
    ILocalUploadCleanup
{
    public static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(10);
    public const long MaximumInputBytes = 512L * 1024 * 1024;

    private readonly IJobStore _jobs;
    private readonly ILocalUploadLeaseStore _leases;
    private readonly ISpoolStore _spool;
    private readonly IJobDispatcher _dispatcher;
    private readonly TimeProvider _timeProvider;
    private readonly string _signingUserSid;
    private readonly ILocalLeaseProtector _protector;
    private readonly ILocalUploadContentValidator _contentValidator;
    private readonly ILocalJobAcceptanceObserver? _acceptanceObserver;
    private readonly JobRetentionPolicy _retention;

    public LocalJobUploadCoordinator(
        IJobStore jobs,
        ISpoolStore spool,
        IJobDispatcher dispatcher,
        TimeProvider timeProvider,
        string signingUserSid,
        ILocalLeaseProtector? protector = null,
        ILocalUploadContentValidator? contentValidator = null,
        ILocalJobAcceptanceObserver? acceptanceObserver = null,
        int retentionHours = 24)
    {
        _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
        _leases = jobs as ILocalUploadLeaseStore
            ?? throw new ArgumentException("The job store must support local upload leases.", nameof(jobs));
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _signingUserSid = string.IsNullOrWhiteSpace(signingUserSid)
            ? throw new ArgumentException("Signing user SID is required.", nameof(signingUserSid))
            : signingUserSid;
        _protector = protector ?? new WindowsLocalLeaseProtector();
        _contentValidator = contentValidator ?? new LocalUploadContentValidator();
        _acceptanceObserver = acceptanceObserver;
        _retention = new JobRetentionPolicy(retentionHours);
    }

    public Task<AgentMessage> HandleAsync(
        AgentMessage request,
        AgentConnectionIdentity identity,
        CancellationToken cancellationToken) =>
        HandleCoreAsync(request, identity, requireSigningUser: true, cancellationToken);

    public Task<AgentMessage> HandleAdministratorAsync(
        AgentMessage request,
        AgentConnectionIdentity identity,
        CancellationToken cancellationToken) =>
        HandleCoreAsync(request, identity, requireSigningUser: false, cancellationToken);

    private Task<AgentMessage> HandleCoreAsync(
        AgentMessage request,
        AgentConnectionIdentity identity,
        bool requireSigningUser,
        CancellationToken cancellationToken) => request switch
        {
            LocalJobCreateRequest create => CreateCoreAsync(
                create, identity, requireSigningUser, cancellationToken),
            LocalJobUploadCompleted completed => CompleteCoreAsync(
                completed, identity, requireSigningUser, cancellationToken),
            LocalJobResultRequest result => GetResultCoreAsync(
                result, identity, requireSigningUser, cancellationToken),
            _ => Task.FromException<AgentMessage>(new ProtocolException(
                "invalid_message_direction",
                "The message is not a local job request.")),
        };

    public async Task<AgentMessage> CreateAsync(
        LocalJobCreateRequest request,
        AgentConnectionIdentity identity,
        CancellationToken cancellationToken) =>
        await CreateCoreAsync(request, identity, requireSigningUser: true, cancellationToken)
            .ConfigureAwait(false);

    private async Task<AgentMessage> CreateCoreAsync(
        LocalJobCreateRequest request,
        AgentConnectionIdentity identity,
        bool requireSigningUser,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!IsIdentityValid(identity, requireSigningUser))
        {
            return Reject(request.RequestId, "local_upload_identity_mismatch");
        }

        Guid candidateJobId = Guid.NewGuid();
        var candidatePrepared = false;
        try
        {
            var parameters = ValidateCreate(request);
            var fingerprint = Fingerprint(request);
            var now = _timeProvider.GetUtcNow();
            var leaseBytes = RandomNumberGenerator.GetBytes(16);
            try
            {
                var leaseId = Convert.ToHexString(leaseBytes).ToLowerInvariant();
                var leaseHash = Convert.ToHexString(SHA256.HashData(leaseBytes)).ToLowerInvariant();
                var relativePartPath = _spool.PrepareLocalUpload(candidateJobId, request.Extension);
                candidatePrepared = true;
                var candidate = new LocalUploadLeaseRecord(
                    request.RequestId,
                    fingerprint,
                    candidateJobId,
                    leaseHash,
                    _protector.Protect(leaseBytes),
                    identity.UserSid,
                    identity.SessionId,
                    relativePartPath,
                    request.OriginalName,
                    request.Extension,
                    request.DeclaredSize,
                    request.CanonicalParametersJson,
                    now,
                    now.Add(LeaseDuration),
                    null);
                var outcome = await _leases
                    .CreateOrGetLocalLeaseAsync(candidate, cancellationToken)
                    .ConfigureAwait(false);
                if (!outcome.Created)
                {
                    await _spool.DeleteJobAsync(candidateJobId, CancellationToken.None).ConfigureAwait(false);
                    candidatePrepared = false;
                    if (!string.Equals(outcome.Lease.RequestFingerprint, fingerprint, StringComparison.Ordinal))
                    {
                        return Reject(request.RequestId, "local_request_conflict");
                    }

                    if (outcome.Lease.AcceptedJobId is { } acceptedJobId)
                    {
                        return new LocalJobAccepted(request.RequestId, acceptedJobId);
                    }

                    if (outcome.Lease.ExpiresAtUtc <= now)
                    {
                        return Reject(request.RequestId, "local_upload_expired");
                    }

                    var recovered = _protector.Unprotect(outcome.Lease.ProtectedLease);
                    try
                    {
                        if (recovered.Length != 16 ||
                            !FixedHashMatches(outcome.Lease.LeaseHash, recovered))
                        {
                            return Reject(request.RequestId, "local_job_unavailable");
                        }

                        return ToWireLease(outcome.Lease, recovered);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(recovered);
                    }
                }

                candidatePrepared = false;
                return new LocalJobUploadLease(
                    request.RequestId,
                    candidateJobId,
                    leaseId,
                    relativePartPath,
                    candidate.ExpiresAtUtc);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(leaseBytes);
            }
        }
        catch (ValidationException error)
        {
            return Reject(request.RequestId, error.Code);
        }
        catch (SpoolException error)
        {
            return Reject(request.RequestId, NormalizeSpoolCode(error.Code));
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return Reject(request.RequestId, "internal_error");
        }
        finally
        {
            if (candidatePrepared)
            {
                try
                {
                    await _spool.DeleteJobAsync(candidateJobId, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                }
            }
        }
    }

    public async Task<AgentMessage> CompleteAsync(
        LocalJobUploadCompleted completed,
        AgentConnectionIdentity identity,
        CancellationToken cancellationToken) =>
        await CompleteCoreAsync(completed, identity, requireSigningUser: true, cancellationToken)
            .ConfigureAwait(false);

    private async Task<AgentMessage> CompleteCoreAsync(
        LocalJobUploadCompleted completed,
        AgentConnectionIdentity identity,
        bool requireSigningUser,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(completed);
        try
        {
            var lease = await _leases.GetLocalLeaseAsync(completed.RequestId, cancellationToken).ConfigureAwait(false);
            if (lease is null || lease.JobId != completed.JobId)
            {
                return Reject(completed.RequestId, "local_upload_missing");
            }

            if (!IsIdentityValid(identity, requireSigningUser) ||
                !string.Equals(lease.SigningUserSid, identity.UserSid, StringComparison.Ordinal) ||
                lease.SessionId != identity.SessionId)
            {
                return Reject(completed.RequestId, "local_upload_identity_mismatch");
            }

            byte[] suppliedLease;
            try
            {
                suppliedLease = Convert.FromHexString(completed.LeaseId);
            }
            catch (FormatException)
            {
                return Reject(completed.RequestId, "local_upload_hash_mismatch");
            }

            try
            {
                if (!FixedHashMatches(lease.LeaseHash, suppliedLease))
                {
                    return Reject(completed.RequestId, "local_upload_hash_mismatch");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(suppliedLease);
            }

            if (lease.AcceptedJobId is { } acceptedJobId)
            {
                if (completed.ActualSize != lease.DeclaredSize)
                {
                    return Reject(completed.RequestId, "local_upload_size_mismatch");
                }

                var acceptedJob = await _jobs.GetAsync(acceptedJobId, cancellationToken).ConfigureAwait(false);
                if (acceptedJob is not { Source: "local" } ||
                    acceptedJob.Id != lease.JobId ||
                    acceptedJob.InputSize != completed.ActualSize)
                {
                    return Reject(completed.RequestId, "local_upload_size_mismatch");
                }

                if (!string.Equals(acceptedJob.InputSha256, completed.Sha256, StringComparison.Ordinal))
                {
                    return Reject(completed.RequestId, "local_upload_hash_mismatch");
                }

                return new LocalJobAccepted(completed.RequestId, acceptedJobId);
            }

            if (lease.ExpiresAtUtc <= _timeProvider.GetUtcNow())
            {
                return Reject(completed.RequestId, "local_upload_expired");
            }

            if (completed.ActualSize != lease.DeclaredSize)
            {
                return Reject(completed.RequestId, "local_upload_size_mismatch");
            }

            await using var upload = await _spool.OpenLocalUploadAsync(
                lease.JobId,
                lease.Extension,
                cancellationToken).ConfigureAwait(false);
            var verified = await VerifyUploadAsync(
                lease,
                upload,
                cancellationToken).ConfigureAwait(false);
            if (verified.Size != completed.ActualSize)
            {
                return Reject(completed.RequestId, "local_upload_size_mismatch");
            }

            if (!string.Equals(verified.Sha256, completed.Sha256, StringComparison.Ordinal))
            {
                return Reject(completed.RequestId, "local_upload_hash_mismatch");
            }

            await _spool.PromoteLocalUploadAsync(
                upload,
                verified.Size,
                verified.Sha256,
                cancellationToken).ConfigureAwait(false);
            var now = _timeProvider.GetUtcNow().ToUniversalTime();
            var job = new Job(lease.JobId, JobState.Queued, verified.Parameters)
            {
                OriginalName = lease.OriginalName,
                Extension = lease.Extension,
                InputSize = verified.Size,
                InputSha256 = verified.Sha256,
                CreatedAt = now,
                ExpiresAt = _retention.GetExpiresAt(now),
                Source = "local",
            };
            var accepted = await _leases.AcceptLocalLeaseAsync(
                lease.RequestId,
                job,
                cancellationToken).ConfigureAwait(false);
            var response = new LocalJobAccepted(completed.RequestId, accepted.Job.Id);
            if (accepted.Created)
            {
                try
                {
                    _dispatcher.Enqueue(accepted.Job.Id);
                }
                catch
                {
                    // The durable queued row is the recovery source after a best-effort wake failure.
                }
            }

            if (_acceptanceObserver is not null)
            {
                try
                {
                    await _acceptanceObserver.AfterAcceptedAsync(
                        lease.RequestId,
                        accepted.Job.Id,
                        cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    // Acceptance is irreversible once the lease transaction commits.
                }
            }

            return response;
        }
        catch (ValidationException error)
        {
            return Reject(completed.RequestId, error.Code);
        }
        catch (SpoolException error)
        {
            return Reject(completed.RequestId, NormalizeSpoolCode(error.Code));
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return Reject(completed.RequestId, "internal_error");
        }
    }

    public async Task<AgentMessage> GetResultAsync(
        LocalJobResultRequest request,
        AgentConnectionIdentity identity,
        CancellationToken cancellationToken) =>
        await GetResultCoreAsync(request, identity, requireSigningUser: true, cancellationToken)
            .ConfigureAwait(false);

    private async Task<AgentMessage> GetResultCoreAsync(
        LocalJobResultRequest request,
        AgentConnectionIdentity identity,
        bool requireSigningUser,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!IsIdentityValid(identity, requireSigningUser))
        {
            return Reject(request.RequestId, "local_upload_identity_mismatch");
        }

        var job = await _jobs.GetAsync(request.JobId, cancellationToken).ConfigureAwait(false);
        if (job is not { State: JobState.Succeeded, ResultSize: > 0 } ||
            job.Source is not ("local" or "api") ||
            string.IsNullOrWhiteSpace(job.ResultSha256))
        {
            return Reject(request.RequestId, "local_result_not_succeeded");
        }

        return new LocalJobResultMetadata(
            request.RequestId,
            job.Id,
            job.Extension,
            job.ResultSize.Value,
            job.ResultSha256);
    }

    public async Task<int> CleanupExpiredAsync(CancellationToken cancellationToken)
    {
        var count = 0;
        while (await _leases.GetNextExpiredLocalLeaseAsync(
                _timeProvider.GetUtcNow(),
                cancellationToken).ConfigureAwait(false) is { } lease)
        {
            await _spool.DeleteLocalUploadArtifactsAsync(
                lease.JobId,
                lease.Extension,
                cancellationToken).ConfigureAwait(false);
            if (!await _leases.DeleteLocalLeaseAsync(
                    lease.RequestId,
                    lease.JobId,
                    cancellationToken).ConfigureAwait(false))
            {
                throw new InvalidOperationException("local_upload_cleanup_failed");
            }

            count++;
        }

        return count;
    }

    public async Task<IReadOnlyList<LocalUploadOwnership>> GetStartupOwnershipAsync(
        CancellationToken cancellationToken)
    {
        var leases = await _leases.GetUnacceptedLocalLeasesAsync(
            _timeProvider.GetUtcNow(),
            cancellationToken).ConfigureAwait(false);
        return leases
            .Select(lease => new LocalUploadOwnership(lease.JobId, lease.Extension))
            .ToArray();
    }

    private SigningParameters ValidateCreate(LocalJobCreateRequest request)
    {
        if (request.DeclaredSize is < 1 or > MaximumInputBytes ||
            request.RequestId == Guid.Empty ||
            request.OriginalName.Length is < 1 or > 255 ||
            !string.Equals(Path.GetFileName(request.OriginalName), request.OriginalName, StringComparison.Ordinal) ||
            request.OriginalName.IndexOfAny(['/', '\\']) >= 0 ||
            request.OriginalName.Any(char.IsControl) ||
            !string.Equals(Path.GetExtension(request.OriginalName), request.Extension, StringComparison.Ordinal))
        {
            throw new ValidationException("invalid_parameters");
        }

        var parameters = SigningParameters.Parse(request.CanonicalParametersJson);
        if (!string.Equals(
                SigningParameters.SerializeCanonical(parameters),
                request.CanonicalParametersJson,
                StringComparison.Ordinal) ||
            parameters is AuthenticodeParameters && request.Extension is not (".exe" or ".dll" or ".msi" or ".sys" or ".cat") ||
            parameters is AuthenticodeParameters { AppendSignature: true } ||
            parameters is PdfParameters && request.Extension != ".pdf")
        {
            throw new ValidationException("invalid_parameters");
        }

        return parameters;
    }

    private async Task<VerifiedUpload> VerifyUploadAsync(
        LocalUploadLeaseRecord lease,
        LocalUploadFile upload,
        CancellationToken cancellationToken)
    {
        var input = upload.Stream;
        if (!input.CanSeek || input.Length != lease.DeclaredSize || input.Length is < 1 or > MaximumInputBytes)
        {
            throw new SpoolException("local_upload_size_mismatch");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        var prefix = new byte[8];
        var prefixLength = 0;
        long size = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (prefixLength < prefix.Length)
            {
                var copy = Math.Min(prefix.Length - prefixLength, read);
                buffer.AsSpan(0, copy).CopyTo(prefix.AsSpan(prefixLength));
                prefixLength += copy;
            }

            if (read > lease.DeclaredSize - size)
            {
                throw new SpoolException("local_upload_size_mismatch");
            }

            hash.AppendData(buffer, 0, read);
            size += read;
        }

        if (size != lease.DeclaredSize)
        {
            throw new SpoolException("local_upload_size_mismatch");
        }

        var parameters = SigningParameters.ParseAndValidate(
            lease.CanonicalParametersJson,
            lease.OriginalName,
            prefix.AsSpan(0, prefixLength));
        _contentValidator.Validate(upload, parameters);
        return new VerifiedUpload(
            size,
            Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(),
            parameters);
    }

    private bool IsIdentityValid(
        AgentConnectionIdentity identity,
        bool requireSigningUser) =>
        identity.ProcessId > 0 && identity.SessionId > 0 &&
        CanonicalWindowsSid.IsValid(identity.UserSid) &&
        (!requireSigningUser ||
            string.Equals(identity.UserSid, _signingUserSid, StringComparison.Ordinal));

    private static bool FixedHashMatches(string expectedHash, ReadOnlySpan<byte> lease)
    {
        byte[] expected;
        try
        {
            expected = Convert.FromHexString(expectedHash);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = SHA256.HashData(lease);
        try
        {
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static LocalJobUploadLease ToWireLease(LocalUploadLeaseRecord lease, ReadOnlySpan<byte> plaintext) => new(
        lease.RequestId,
        lease.JobId,
        Convert.ToHexString(plaintext).ToLowerInvariant(),
        lease.RelativePartPath,
        lease.ExpiresAtUtc);

    private static string Fingerprint(LocalJobCreateRequest request) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{request.RequestId:D}\n{request.OriginalName}\n{request.Extension}\n{request.DeclaredSize}\n{request.CanonicalParametersJson}")))
            .ToLowerInvariant();

    private static string NormalizeSpoolCode(string code) => code switch
    {
        "local_upload_missing" => "local_upload_missing",
        "local_upload_size_mismatch" => "local_upload_size_mismatch",
        "input_corrupt" => "local_upload_hash_mismatch",
        "local_upload_invalid_path" or "invalid_spool_path" => "local_upload_invalid_path",
        "file_too_large" => "file_too_large",
        _ => "internal_error",
    };

    private static LocalJobRejected Reject(Guid requestId, string code) =>
        new(requestId, code, Guid.NewGuid());

    private sealed record VerifiedUpload(long Size, string Sha256, SigningParameters Parameters);
}
