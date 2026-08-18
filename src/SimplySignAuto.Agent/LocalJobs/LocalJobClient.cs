using System.Security.Cryptography;
using System.Collections.Concurrent;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.Agent.LocalJobs;

public sealed class LocalJobException : Exception
{
    public LocalJobException(
        string code,
        Guid? correlationId = null,
        LocalJobRejectionDisposition? disposition = null)
        : base(code)
    {
        Code = code;
        CorrelationId = correlationId;
        Disposition = disposition ?? LocalJobRejectionPolicy.Classify(code);
    }

    public string Code { get; }

    public Guid? CorrelationId { get; }

    public LocalJobRejectionDisposition Disposition { get; }
}

public sealed record LocalCopyProgress(long BytesCopied, long TotalBytes, int Percent);

public sealed record LocalJobCreateOutcome(LocalJobUploadLease? Lease, Guid? AcceptedJobId)
{
    public Guid JobId => Lease?.JobId ?? AcceptedJobId ?? Guid.Empty;

    public static LocalJobCreateOutcome FromLease(LocalJobUploadLease lease) =>
        new(lease ?? throw new ArgumentNullException(nameof(lease)), null);

    public static LocalJobCreateOutcome FromAccepted(LocalJobAccepted accepted) =>
        new(null, (accepted ?? throw new ArgumentNullException(nameof(accepted))).JobId);
}

public interface ILocalJobTransport
{
    Task<LocalJobCreateOutcome> CreateLocalJobAsync(
        LocalJobCreateRequest request,
        CancellationToken cancellationToken);

    Task<LocalJobAccepted> CompleteLocalJobAsync(
        LocalJobUploadCompleted completed,
        CancellationToken cancellationToken);

    Task<LocalJobResultMetadata> GetLocalResultAsync(
        LocalJobResultRequest request,
        CancellationToken cancellationToken);
}

public interface ILocalJobClient
{
    Task<Guid> CreateAndUploadAsync(
        string path,
        SigningParameters parameters,
        IProgress<LocalCopyProgress>? progress,
        CancellationToken cancellationToken);

    Task SaveSignedCopyAsync(
        Guid jobId,
        string destinationPath,
        bool overwrite,
        CancellationToken cancellationToken);

    void ReleaseAcceptedSource(Guid jobId);
}

internal interface ILocalJobFileAccess
{
    Stream OpenRead(string path);

    Stream CreateNew(string path);

    void FlushToDisk(Stream stream);

    void Publish(string source, string destination, bool overwrite, Action finalValidation);

    void DeleteControlledPart(string path);
}

internal sealed class PlatformLocalJobFileAccess : ILocalJobFileAccess
{
    public static PlatformLocalJobFileAccess Instance { get; } = new();

    public Stream OpenRead(string path) => new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        LocalJobClient.CopyBufferSize,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    public Stream CreateNew(string path) => new FileStream(
        path,
        FileMode.CreateNew,
        FileAccess.Write,
        FileShare.None,
        LocalJobClient.CopyBufferSize,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    public void FlushToDisk(Stream stream)
    {
        if (stream is not FileStream file)
        {
            throw new IOException("The local file stream is invalid.");
        }

        file.Flush(flushToDisk: true);
    }

    public void Publish(string source, string destination, bool overwrite, Action finalValidation)
    {
        ArgumentNullException.ThrowIfNull(finalValidation);
        finalValidation();
        File.Move(source, destination, overwrite);
    }

    public void DeleteControlledPart(string path) => File.Delete(path);
}

public sealed class LocalJobClient : ILocalJobClient, IDisposable, IAsyncDisposable
{
    public const long MaximumInputBytes = 512L * 1024 * 1024;
    internal const int CopyBufferSize = 1024 * 1024;

    private readonly ILocalJobTransport _transport;
    private readonly string _spoolRoot;
    private readonly ILocalFileIdentityProvider _fileIdentities;
    private readonly ILocalJobFileAccess _fileAccess;
    private readonly ConcurrentDictionary<Guid, TrustedSourceIdentity> _trustedSources = new();
    private readonly SemaphoreSlim _submitGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _lifecycleSync = new();
    private readonly HashSet<Task> _operations = [];
    private PendingLocalCreation? _pendingCreation;
    private PendingLocalSubmission? _pendingSubmission;
    private Task? _disposeTask;

    public LocalJobClient(
        ILocalJobTransport transport,
        string spoolRoot,
        ILocalFileIdentityProvider? fileIdentities = null)
        : this(transport, spoolRoot, fileIdentities, null)
    {
    }

    internal LocalJobClient(
        ILocalJobTransport transport,
        string spoolRoot,
        ILocalFileIdentityProvider? fileIdentities,
        ILocalJobFileAccess? fileAccess)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        ArgumentException.ThrowIfNullOrWhiteSpace(spoolRoot);
        _spoolRoot = Path.GetFullPath(spoolRoot);
        _fileIdentities = fileIdentities ?? PlatformLocalFileIdentityProvider.Instance;
        _fileAccess = fileAccess ?? PlatformLocalJobFileAccess.Instance;
    }

    public Task<Guid> CreateAndUploadAsync(
        string path,
        SigningParameters parameters,
        IProgress<LocalCopyProgress>? progress,
        CancellationToken cancellationToken) =>
        RegisterOperationAsync(
            token => CreateAndUploadCoreAsync(path, parameters, progress, token),
            cancellationToken);

    private async Task<Guid> CreateAndUploadCoreAsync(
        string path,
        SigningParameters parameters,
        IProgress<LocalCopyProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        await _submitGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string? controlledPartPath = null;
        FileStream? source = null;
        try
        {
            var canonicalSource = ValidateCanonicalSourcePath(path);
            source = OpenSource(canonicalSource);
            LocalFileIdentity? sourceIdentity = _fileIdentities.TryGetIdentity(
                source.SafeFileHandle,
                out var capturedIdentity)
                ? capturedIdentity
                : null;
            var declaredSize = source.Length;
            if (declaredSize == 0)
            {
                throw new LocalJobException("local_source_empty");
            }

            if (declaredSize > MaximumInputBytes)
            {
                throw new LocalJobException("file_too_large");
            }

            var prefix = new byte[8];
            var prefixLength = await source.ReadAsync(prefix, cancellationToken).ConfigureAwait(false);
            source.Position = 0;
            var originalName = Path.GetFileName(canonicalSource);
            var kind = SigningRequestValidator.ValidateFile(originalName, prefix.AsSpan(0, prefixLength));
            if (parameters.DigestAlgorithm != "sha256" ||
                parameters is AuthenticodeParameters { AppendSignature: true } ||
                parameters is AuthenticodeParameters && kind != FileKind.Authenticode ||
                parameters is PdfParameters && kind != FileKind.Pdf)
            {
                throw new LocalJobException("invalid_parameters");
            }

            var extension = Path.GetExtension(originalName).ToLowerInvariant();
            var parametersJson = SigningParameters.SerializeCanonical(parameters);
            if (_pendingSubmission is { } pending)
            {
                if (pending.Matches(canonicalSource, parametersJson, declaredSize, sourceIdentity))
                {
                    try
                    {
                        var resumedHash = await HashOpenStreamAsync(source, cancellationToken).ConfigureAwait(false);
                        source.Position = 0;
                        if (!string.Equals(resumedHash, pending.Completed.Sha256, StringComparison.Ordinal))
                        {
                            throw new LocalJobException("local_source_changed");
                        }

                        var resumed = await _transport
                            .CompleteLocalJobAsync(pending.Completed, cancellationToken)
                            .ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();
                        if (resumed.RequestId != pending.Completed.RequestId ||
                            resumed.JobId != pending.Completed.JobId)
                        {
                            throw new LocalJobException("local_response_mismatch");
                        }

                        _pendingSubmission = null;
                        var guard = pending.TakeGuard();
                        var unused = RetainTrustedSource(
                            resumed.JobId,
                            canonicalSource,
                            guard,
                            pending.Identity,
                            pending.Size,
                            pending.Completed.Sha256);
                        unused?.Dispose();
                        pending.Dispose();
                        return resumed.JobId;
                    }
                    catch (LocalJobException error) when (
                        error.Disposition == LocalJobRejectionDisposition.Definitive)
                    {
                        _pendingSubmission = null;
                        pending.Dispose();
                        DeleteControlledPart(pending.PartPath);
                        throw;
                    }
                }

                _pendingSubmission = null;
                pending.Dispose();
                DeleteControlledPart(pending.PartPath);
            }

            LocalJobCreateRequest request;
            LocalJobCreateOutcome create;
            if (_pendingCreation is { } pendingCreation)
            {
                if (!pendingCreation.Matches(
                        canonicalSource,
                        parametersJson,
                        declaredSize,
                        sourceIdentity))
                {
                    _pendingCreation = null;
                    pendingCreation.Dispose();
                    request = NewCreateRequest();
                    create = await CreateNewAsync().ConfigureAwait(false);
                }
                else
                {
                    try
                    {
                        var currentHash = await HashOpenStreamAsync(source, cancellationToken).ConfigureAwait(false);
                        source.Position = 0;
                        if (!string.Equals(currentHash, pendingCreation.Sha256, StringComparison.Ordinal))
                        {
                            throw new LocalJobException("local_source_changed");
                        }

                        request = pendingCreation.Request;
                        create = await _transport
                            .CreateLocalJobAsync(request, cancellationToken)
                            .ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();
                        _pendingCreation = null;
                        pendingCreation.Dispose();
                    }
                    catch (LocalJobException error) when (
                        error.Disposition == LocalJobRejectionDisposition.Definitive)
                    {
                        _pendingCreation = null;
                        pendingCreation.Dispose();
                        throw;
                    }
                }
            }
            else
            {
                request = NewCreateRequest();
                create = await CreateNewAsync().ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();

            if (create.AcceptedJobId is { } recoveredJobId)
            {
                var recoveredHash = await HashOpenStreamAsync(source, cancellationToken).ConfigureAwait(false);
                source.Position = 0;
                if (source.Length != declaredSize)
                {
                    throw new LocalJobException("local_source_changed");
                }

                source = RetainTrustedSource(
                    recoveredJobId,
                    canonicalSource,
                    source,
                    sourceIdentity,
                    declaredSize,
                    recoveredHash);
                return recoveredJobId;
            }

            var lease = create.Lease ?? throw new LocalJobException("local_response_mismatch");
            ValidateLeaseResponse(request, lease);
            controlledPartPath = ResolvePartPath(lease, extension);
            var (copied, sha256) = await CopySourceAsync(
                source,
                declaredSize,
                controlledPartPath,
                progress,
                cancellationToken).ConfigureAwait(false);

            if (source.Length != declaredSize || copied != declaredSize)
            {
                throw new LocalJobException("local_source_changed");
            }

            var completed = new LocalJobUploadCompleted(
                request.RequestId,
                lease.JobId,
                lease.LeaseId,
                copied,
                sha256);
            var finalizing = new PendingLocalSubmission(
                canonicalSource,
                parametersJson,
                sourceIdentity,
                declaredSize,
                controlledPartPath,
                completed,
                source);
            _pendingSubmission = finalizing;
            source = null;
            controlledPartPath = null;
            try
            {
                var accepted = await _transport
                    .CompleteLocalJobAsync(completed, cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (accepted.RequestId != request.RequestId || accepted.JobId != lease.JobId)
                {
                    throw new LocalJobException("local_response_mismatch");
                }

                _pendingSubmission = null;
                var guard = finalizing.TakeGuard();
                source = RetainTrustedSource(
                    accepted.JobId,
                    canonicalSource,
                    guard,
                    sourceIdentity,
                    declaredSize,
                    sha256);
                finalizing.Dispose();
                return accepted.JobId;
            }
            catch (LocalJobException error) when (
                error.Disposition == LocalJobRejectionDisposition.Definitive)
            {
                _pendingSubmission = null;
                finalizing.Dispose();
                DeleteControlledPart(finalizing.PartPath);
                throw;
            }
            catch (LocalJobException)
            {
                throw;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                _pendingSubmission = null;
                finalizing.Dispose();
                DeleteControlledPart(finalizing.PartPath);
                throw;
            }

            LocalJobCreateRequest NewCreateRequest() => new(
                Guid.NewGuid(),
                originalName,
                extension,
                declaredSize,
                parametersJson);

            async Task<LocalJobCreateOutcome> CreateNewAsync()
            {
                try
                {
                    return await _transport
                        .CreateLocalJobAsync(request, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (LocalJobException error) when (
                    error.Disposition == LocalJobRejectionDisposition.Transient)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var sourceHash = await HashOpenStreamAsync(source, cancellationToken).ConfigureAwait(false);
                    source.Position = 0;
                    _pendingCreation = new PendingLocalCreation(
                        canonicalSource,
                        parametersJson,
                        sourceIdentity,
                        declaredSize,
                        sourceHash,
                        request,
                        source);
                    source = null;
                    throw;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            DeleteControlledPart(controlledPartPath);
            throw;
        }
        catch (LocalJobException)
        {
            DeleteControlledPart(controlledPartPath);
            throw;
        }
        catch (ValidationException error)
        {
            DeleteControlledPart(controlledPartPath);
            throw new LocalJobException(error.Code);
        }
        catch (Exception)
        {
            DeleteControlledPart(controlledPartPath);
            throw new LocalJobException("local_job_unavailable");
        }
        finally
        {
            source?.Dispose();
            _submitGate.Release();
        }
    }

    public Task SaveSignedCopyAsync(
        Guid jobId,
        string destinationPath,
        bool overwrite,
        CancellationToken cancellationToken) =>
        RegisterOperationAsync(
            token => SaveSignedCopyCoreAsync(jobId, destinationPath, overwrite, token),
            cancellationToken);

    private async Task SaveSignedCopyCoreAsync(
        Guid jobId,
        string destinationPath,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        try
        {
            if (jobId == Guid.Empty)
            {
                throw new LocalJobException("local_job_invalid");
            }

            var destination = ValidateCanonicalDestination(destinationPath);
            var destinationExists = PathEntryExists(destination);
            if (destinationExists && !overwrite)
            {
                throw new LocalJobException("local_destination_exists");
            }

            var trustedSource = GetTrustedSourceForOverwrite(jobId, destinationExists);
            if (destinationExists)
            {
                await VerifyTrustedSourceAsync(trustedSource!, cancellationToken).ConfigureAwait(false);
                VerifyOverwriteDestination(destination, trustedSource);
            }

            var request = new LocalJobResultRequest(Guid.NewGuid(), jobId);
            var metadata = await _transport.GetLocalResultAsync(request, cancellationToken).ConfigureAwait(false);
            if (metadata.RequestId != request.RequestId || metadata.JobId != jobId ||
                metadata.Size <= 0 || !IsLowerSha256(metadata.Sha256))
            {
                throw new LocalJobException("local_result_metadata_mismatch");
            }

            var resultPath = ResolveResultPath(metadata);
            await using var result = OpenControlledRead(resultPath, "local_result_metadata_mismatch");
            if (result.Length != metadata.Size ||
                !string.Equals(
                    await HashOpenStreamAsync(result, cancellationToken).ConfigureAwait(false),
                    metadata.Sha256,
                    StringComparison.Ordinal))
            {
                throw new LocalJobException("local_result_metadata_mismatch");
            }

            result.Position = 0;
            var destinationDirectory = Path.GetDirectoryName(destination)
                ?? throw new LocalJobException("local_destination_invalid");
            AssertNormalDirectory(destinationDirectory, "local_destination_invalid");
            var temp = Path.Combine(destinationDirectory, $".simplysign-{Guid.NewGuid():N}.part");
            try
            {
                await using (var output = _fileAccess.CreateNew(temp))
                {
                    await result.CopyToAsync(output, CopyBufferSize, cancellationToken).ConfigureAwait(false);
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    _fileAccess.FlushToDisk(output);
                }

                cancellationToken.ThrowIfCancellationRequested();
                _fileAccess.Publish(
                    temp,
                    destination,
                    overwrite: destinationExists,
                    finalValidation: () =>
                    {
                        if (destinationExists)
                        {
                            VerifyTrustedSourcePath(trustedSource!);
                            VerifyOverwriteDestination(destination, trustedSource);
                        }
                    });
                ReleaseTrustedSource(jobId);
            }
            catch
            {
                TryDeleteTemp(temp);
                throw;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new LocalJobException("local_save_failed");
        }
    }

    public static string DefaultSignedCopyName(string originalName, string extension)
    {
        if (string.IsNullOrWhiteSpace(originalName) ||
            string.IsNullOrWhiteSpace(extension) ||
            !string.Equals(Path.GetExtension(originalName), extension, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Original name and extension are invalid.");
        }

        return Path.GetFileNameWithoutExtension(originalName) + ".signed" + extension.ToLowerInvariant();
    }

    public void ReleaseAcceptedSource(Guid jobId) => ReleaseTrustedSource(jobId);

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync()
    {
        Task disposeTask;
        TaskCompletionSource? completion = null;
        Task[] operations = [];
        lock (_lifecycleSync)
        {
            if (_disposeTask is null)
            {
                completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _disposeTask = completion.Task;
                operations = _operations.ToArray();
            }

            disposeTask = _disposeTask;
        }

        if (completion is not null)
        {
            _ = CompleteDisposeAsync(operations, completion);
        }

        return new ValueTask(disposeTask);
    }

    private Task<T> RegisterOperationAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        cancellationToken.ThrowIfCancellationRequested();
        TaskCompletionSource tracker;
        CancellationTokenSource linked;
        lock (_lifecycleSync)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
            tracker = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _operations.Add(tracker.Task);
        }

        return RunTrackedOperationAsync(operation, linked, tracker);
    }

    private Task RegisterOperationAsync(
        Func<CancellationToken, Task> operation,
        CancellationToken cancellationToken) =>
        RegisterOperationAsync(
            async token =>
            {
                await operation(token).ConfigureAwait(false);
                return true;
            },
            cancellationToken);

    private async Task<T> RunTrackedOperationAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationTokenSource linked,
        TaskCompletionSource tracker)
    {
        try
        {
            return await operation(linked.Token).ConfigureAwait(false);
        }
        finally
        {
            linked.Dispose();
            lock (_lifecycleSync)
            {
                _operations.Remove(tracker.Task);
            }

            tracker.TrySetResult();
        }
    }

    private async Task CompleteDisposeAsync(Task[] operations, TaskCompletionSource completion)
    {
        try
        {
            _lifetime.Cancel();
            await Task.WhenAll(operations).ConfigureAwait(false);
            CleanupOwnedState();
            completion.TrySetResult();
        }
        catch (Exception error)
        {
            completion.TrySetException(error);
        }
    }

    private void CleanupOwnedState()
    {
        Exception? cleanupError = null;
        _pendingCreation?.Dispose();
        _pendingCreation = null;
        if (_pendingSubmission is { } submission)
        {
            _pendingSubmission = null;
            submission.Dispose();
            try
            {
                DeleteControlledPart(submission.PartPath);
            }
            catch (Exception error)
            {
                cleanupError = error;
            }
        }

        foreach (var source in _trustedSources.Values)
        {
            source.Dispose();
        }

        _trustedSources.Clear();
        _submitGate.Dispose();
        _lifetime.Dispose();
        if (cleanupError is not null)
        {
            throw cleanupError;
        }
    }

    private TrustedSourceIdentity? GetTrustedSourceForOverwrite(Guid jobId, bool destinationExists)
    {
        if (!destinationExists)
        {
            return null;
        }

        if (!_trustedSources.TryGetValue(jobId, out var source))
        {
            throw new LocalJobException("local_destination_identity_unavailable");
        }

        return source;
    }

    private void VerifyOverwriteDestination(string path, TrustedSourceIdentity? trustedSource)
    {
        if (trustedSource?.Identity is not { } source)
        {
            throw new LocalJobException("local_destination_identity_unavailable");
        }

        try
        {
            if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
                new FileInfo(path).LinkTarget is not null)
            {
                throw new LocalJobException("local_destination_invalid");
            }

            using var destination = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
                !_fileIdentities.TryGetIdentity(destination.SafeFileHandle, out var destinationIdentity))
            {
                throw new LocalJobException("local_destination_identity_unavailable");
            }

            if (source.RefersToSameFile(destinationIdentity))
            {
                throw new LocalJobException("local_destination_is_input");
            }
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new LocalJobException("local_destination_invalid");
        }
    }

    private static FileStream OpenSource(string path)
    {
        try
        {
            return NoFollowFile.OpenRead(path, FileShare.Read, CopyBufferSize);
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new LocalJobException("local_source_invalid");
        }
    }

    private async Task<(long Size, string Sha256)> CopySourceAsync(
        FileStream source,
        long declaredSize,
        string partPath,
        IProgress<LocalCopyProgress>? progress,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[CopyBufferSize];
        long copied = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        progress?.Report(new LocalCopyProgress(0, declaredSize, 0));
        await using (var output = _fileAccess.CreateNew(partPath))
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                if (read > declaredSize - copied)
                {
                    throw new LocalJobException("local_source_changed");
                }

                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                hash.AppendData(buffer, 0, read);
                copied += read;
                progress?.Report(new LocalCopyProgress(
                    copied,
                    declaredSize,
                    checked((int)(copied * 100 / declaredSize))));
                cancellationToken.ThrowIfCancellationRequested();
            }

            if (copied != declaredSize)
            {
                throw new LocalJobException("local_source_changed");
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            _fileAccess.FlushToDisk(output);
        }

        return (copied, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
    }

    private string ResolvePartPath(LocalJobUploadLease lease, string extension)
    {
        var expected = $"{lease.JobId:N}/input{extension}.part";
        if (!string.Equals(lease.RelativePartPath, expected, StringComparison.Ordinal))
        {
            throw new LocalJobException("local_upload_invalid_path");
        }

        AssertNormalDirectory(_spoolRoot, "local_upload_invalid_path");
        var jobDirectory = Path.GetFullPath(Path.Combine(_spoolRoot, lease.JobId.ToString("N")));
        EnsureWithinSpool(jobDirectory);
        AssertNormalDirectory(jobDirectory, "local_upload_invalid_path");
        var target = Path.GetFullPath(Path.Combine(jobDirectory, "input" + extension + ".part"));
        EnsureWithinSpool(target);
        if (PathEntryExists(target))
        {
            throw new LocalJobException("local_upload_invalid_path");
        }

        return target;
    }

    private string ResolveResultPath(LocalJobResultMetadata metadata)
    {
        AssertNormalDirectory(_spoolRoot, "local_result_metadata_mismatch");
        var jobDirectory = Path.GetFullPath(Path.Combine(_spoolRoot, metadata.JobId.ToString("N")));
        EnsureWithinSpool(jobDirectory);
        AssertNormalDirectory(jobDirectory, "local_result_metadata_mismatch");
        var result = Path.GetFullPath(Path.Combine(jobDirectory, "result" + metadata.Extension));
        EnsureWithinSpool(result);
        return result;
    }

    private static void ValidateLeaseResponse(LocalJobCreateRequest request, LocalJobUploadLease lease)
    {
        if (lease.RequestId != request.RequestId || lease.JobId == Guid.Empty ||
            lease.LeaseId.Length != 32 ||
            lease.LeaseId.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            lease.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            throw new LocalJobException("local_response_mismatch");
        }
    }

    private static string ValidateCanonicalSourcePath(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl) || !Path.IsPathFullyQualified(path))
            {
                throw new LocalJobException("local_source_invalid");
            }

            var full = Path.GetFullPath(path);
            if (!string.Equals(full, path, PathComparison()) || IsAmbiguousWindowsPath(full))
            {
                throw new LocalJobException("local_source_invalid");
            }

            return full;
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException)
        {
            throw new LocalJobException("local_source_invalid");
        }
    }

    private static string ValidateCanonicalDestination(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl) || !Path.IsPathFullyQualified(path))
            {
                throw new LocalJobException("local_destination_invalid");
            }

            var full = Path.GetFullPath(path);
            if (!string.Equals(full, path, PathComparison()) || IsAmbiguousWindowsPath(full))
            {
                throw new LocalJobException("local_destination_invalid");
            }

            return full;
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException)
        {
            throw new LocalJobException("local_destination_invalid");
        }
    }

    private static bool IsAmbiguousWindowsPath(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        if (path.StartsWith("\\\\", StringComparison.Ordinal))
        {
            return true;
        }

        var rootLength = Path.GetPathRoot(path)?.Length ?? 0;
        return path.AsSpan(rootLength).Contains(':');
    }

    private Stream OpenControlledRead(string path, string errorCode)
    {
        try
        {
            if (!File.Exists(path) ||
                (File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
                new FileInfo(path).LinkTarget is not null)
            {
                throw new LocalJobException(errorCode);
            }

            return _fileAccess.OpenRead(path);
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new LocalJobException(errorCode);
        }
    }

    private static async Task<string> HashOpenStreamAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[CopyBufferSize];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private FileStream? RetainTrustedSource(
        Guid jobId,
        string canonicalPath,
        FileStream source,
        LocalFileIdentity? identity,
        long size,
        string sha256)
    {
        if (identity is not { } trustedIdentity)
        {
            return source;
        }

        var trusted = new TrustedSourceIdentity(
            canonicalPath,
            trustedIdentity,
            size,
            sha256,
            source);
        _trustedSources.AddOrUpdate(
            jobId,
            trusted,
            (_, previous) =>
            {
                previous.Dispose();
                return trusted;
            });
        return null;
    }

    private async Task VerifyTrustedSourceAsync(
        TrustedSourceIdentity source,
        CancellationToken cancellationToken)
    {
        await using var current = OpenTrustedSourcePath(source);
        if (current.Length != source.Size ||
            !string.Equals(
                await HashOpenStreamAsync(current, cancellationToken).ConfigureAwait(false),
                source.Sha256,
                StringComparison.Ordinal))
        {
            throw new LocalJobException("local_source_changed");
        }
    }

    private void VerifyTrustedSourcePath(TrustedSourceIdentity source)
    {
        using var current = OpenTrustedSourcePath(source);
        if (current.Length != source.Size)
        {
            throw new LocalJobException("local_source_changed");
        }
    }

    private FileStream OpenTrustedSourcePath(TrustedSourceIdentity source)
    {
        try
        {
            if (source.Guard.SafeFileHandle.IsClosed || source.Guard.SafeFileHandle.IsInvalid)
            {
                throw new LocalJobException("local_source_changed");
            }

            var current = NoFollowFile.OpenRead(source.CanonicalPath, FileShare.Read, CopyBufferSize);
            try
            {
                if (!_fileIdentities.TryGetIdentity(current.SafeFileHandle, out var identity) ||
                    !source.Identity.RefersToSameFile(identity))
                {
                    throw new LocalJobException("local_source_changed");
                }

                return current;
            }
            catch
            {
                current.Dispose();
                throw;
            }
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new LocalJobException("local_source_changed");
        }
    }

    private void ReleaseTrustedSource(Guid jobId)
    {
        if (_trustedSources.TryRemove(jobId, out var source))
        {
            source.Dispose();
        }
    }

    private void EnsureWithinSpool(string path)
    {
        var root = _spoolRoot.EndsWith(Path.DirectorySeparatorChar)
            ? _spoolRoot
            : _spoolRoot + Path.DirectorySeparatorChar;
        if (!path.StartsWith(root, PathComparison()))
        {
            throw new LocalJobException("local_upload_invalid_path");
        }
    }

    private static void AssertNormalDirectory(string path, string code)
    {
        try
        {
            if (!Directory.Exists(path) ||
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 ||
                new DirectoryInfo(path).LinkTarget is not null)
            {
                throw new LocalJobException(code);
            }
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new LocalJobException(code);
        }
    }

    private void DeleteControlledPart(string? path)
    {
        if (path is null)
        {
            return;
        }

        try
        {
            switch (NoFollowFile.InspectPathEntry(path))
            {
                case NoFollowPathEntryKind.Missing:
                    return;
                case NoFollowPathEntryKind.RegularFile:
                    _fileAccess.DeleteControlledPart(path);
                    return;
                case NoFollowPathEntryKind.Directory:
                case NoFollowPathEntryKind.ReparsePoint:
                    throw new LocalJobException("local_upload_cleanup_failed");
                default:
                    throw new LocalJobException("local_upload_cleanup_failed");
            }
        }
        catch (LocalJobException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new LocalJobException("local_upload_cleanup_failed");
        }
    }

    private static void TryDeleteTemp(string path)
    {
        try
        {
            if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0)
            {
                File.Delete(path);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static bool PathEntryExists(string path) =>
        File.Exists(path) || Directory.Exists(path) || new FileInfo(path).LinkTarget is not null;

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private sealed record TrustedSourceIdentity(
        string CanonicalPath,
        LocalFileIdentity Identity,
        long Size,
        string Sha256,
        FileStream Guard) : IDisposable
    {
        public void Dispose() => Guard.Dispose();
    }

    private sealed class PendingLocalCreation : IDisposable
    {
        private readonly string _canonicalPath;
        private readonly string _parametersJson;
        private FileStream? _guard;

        public PendingLocalCreation(
            string canonicalPath,
            string parametersJson,
            LocalFileIdentity? identity,
            long size,
            string sha256,
            LocalJobCreateRequest request,
            FileStream guard)
        {
            _canonicalPath = canonicalPath;
            _parametersJson = parametersJson;
            Identity = identity;
            Size = size;
            Sha256 = sha256;
            Request = request;
            _guard = guard;
        }

        public LocalFileIdentity? Identity { get; }

        public long Size { get; }

        public string Sha256 { get; }

        public LocalJobCreateRequest Request { get; }

        public bool Matches(
            string currentPath,
            string currentParametersJson,
            long currentSize,
            LocalFileIdentity? currentIdentity) =>
            string.Equals(_canonicalPath, currentPath, PathComparison()) &&
            string.Equals(_parametersJson, currentParametersJson, StringComparison.Ordinal) &&
            Size == currentSize &&
            (Identity is null ||
                currentIdentity is { } observed && Identity.Value.RefersToSameFile(observed));

        public void Dispose() => Interlocked.Exchange(ref _guard, null)?.Dispose();
    }

    private sealed class PendingLocalSubmission : IDisposable
    {
        private readonly string _canonicalPath;
        private readonly string _parametersJson;
        private FileStream? _guard;

        public PendingLocalSubmission(
            string canonicalPath,
            string parametersJson,
            LocalFileIdentity? identity,
            long size,
            string partPath,
            LocalJobUploadCompleted completed,
            FileStream guard)
        {
            _canonicalPath = canonicalPath;
            _parametersJson = parametersJson;
            Identity = identity;
            Size = size;
            PartPath = partPath;
            Completed = completed;
            _guard = guard;
        }

        public string PartPath { get; }

        public LocalFileIdentity? Identity { get; }

        public long Size { get; }

        public LocalJobUploadCompleted Completed { get; }

        public bool Matches(
            string currentPath,
            string currentParametersJson,
            long currentSize,
            LocalFileIdentity? currentIdentity) =>
            string.Equals(_canonicalPath, currentPath, PathComparison()) &&
            string.Equals(_parametersJson, currentParametersJson, StringComparison.Ordinal) &&
            Size == currentSize &&
            (Identity is null ||
                currentIdentity is { } observed && Identity.Value.RefersToSameFile(observed));

        public FileStream TakeGuard() =>
            Interlocked.Exchange(ref _guard, null)
            ?? throw new ObjectDisposedException(nameof(PendingLocalSubmission));

        public void Dispose() => Interlocked.Exchange(ref _guard, null)?.Dispose();
    }
}
