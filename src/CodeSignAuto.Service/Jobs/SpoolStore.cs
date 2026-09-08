using System.Security.Cryptography;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.Service.Jobs;

public interface ISpoolStore
{
    Task<SpoolFile> WriteInputAsync(Guid jobId, string extension, Stream input, long maxBytes, CancellationToken cancellationToken = default);

    Task<Stream> OpenVerifiedResultAsync(
        Guid jobId,
        string extension,
        long expectedSize,
        string expectedSha256,
        CancellationToken cancellationToken = default) => Task.FromException<Stream>(new NotSupportedException());

    Task<SpoolFile> PromoteResultAsync(Guid jobId, string extension, string expectedSha256, long expectedSize, CancellationToken cancellationToken = default);

    Task DeleteJobAsync(Guid jobId, CancellationToken cancellationToken = default);

    Task DeleteLocalUploadArtifactsAsync(
        Guid jobId,
        string extension,
        CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    string PrepareLocalUpload(Guid jobId, string extension) =>
        throw new NotSupportedException();

    Task<LocalUploadFile> OpenLocalUploadAsync(
        Guid jobId,
        string extension,
        CancellationToken cancellationToken = default) =>
        Task.FromException<LocalUploadFile>(new NotSupportedException());

    Task PromoteLocalUploadAsync(
        LocalUploadFile upload,
        long expectedSize,
        string expectedSha256,
        CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    void ValidateLocalUploadArtifacts(Guid jobId, string extension) =>
        throw new NotSupportedException();

    IReadOnlyList<SpoolJobDirectory> ValidateAndListJobDirectories() =>
        throw new NotSupportedException();

    Task DeleteStalePartsAsync(Job job, DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    Task DeleteSucceededTransientFilesAsync(Job job, CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());

    Task QuarantineAsync(SpoolJobDirectory directory, CancellationToken cancellationToken = default) =>
        Task.FromException(new NotSupportedException());
}

public sealed record SpoolFile(string Path, long Size, string Sha256);

public sealed class LocalUploadFile : IAsyncDisposable
{
    internal LocalUploadFile(
        SpoolStore owner,
        Guid jobId,
        string extension,
        string path,
        bool isPart,
        FileStream stream,
        LocalFileIdentity identity)
    {
        Owner = owner;
        JobId = jobId;
        Extension = extension;
        Path = path;
        IsPart = isPart;
        Stream = stream;
        Identity = identity;
    }

    internal SpoolStore Owner { get; }
    internal Guid JobId { get; }
    internal string Extension { get; }
    internal string Path { get; set; }
    internal bool IsPart { get; set; }
    internal LocalFileIdentity Identity { get; }
    public FileStream Stream { get; }

    public ValueTask DisposeAsync() => Stream.DisposeAsync();
}

public sealed record SpoolJobDirectory(Guid? JobId, string Path, string Name);

public sealed class SpoolException : Exception
{
    public SpoolException(string code)
        : base(code)
    {
        Code = code;
    }

    public string Code { get; }
}

public sealed class SpoolAclException : Exception;

public interface ISpoolAclPolicy
{
    void ProtectRoot(string path);

    void ProtectJobDirectory(string path);

    void ProtectInput(string path);

    void ProtectFinalResult(string path);
}

internal sealed class UnrestrictedSpoolAclPolicy : ISpoolAclPolicy
{
    public static UnrestrictedSpoolAclPolicy Instance { get; } = new();

    public void ProtectRoot(string path) { }

    public void ProtectJobDirectory(string path) { }

    public void ProtectInput(string path) { }

    public void ProtectFinalResult(string path) { }
}

internal interface ISpoolPromotionObserver
{
    Task BeforeResultClaimAsync(string partPath, string resultPath, CancellationToken cancellationToken);
}

public sealed class SpoolStore : ISpoolStore
{
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".exe", ".dll", ".msi", ".sys", ".cat",
    };
    private readonly string _root;
    private readonly ISpoolPromotionObserver? _promotionObserver;
    private readonly ISpoolAclPolicy _aclPolicy;
    private readonly ILocalFileIdentityProvider _fileIdentities;

    internal SpoolStore(string root)
        : this(
            root,
            UnrestrictedSpoolAclPolicy.Instance,
            promotionObserver: null,
            PlatformLocalFileIdentityProvider.Instance)
    {
    }

    internal SpoolStore(string root, ISpoolPromotionObserver? promotionObserver)
        : this(
            root,
            UnrestrictedSpoolAclPolicy.Instance,
            promotionObserver,
            PlatformLocalFileIdentityProvider.Instance)
    {
    }

    public SpoolStore(string root, ISpoolAclPolicy aclPolicy)
        : this(root, aclPolicy, promotionObserver: null, PlatformLocalFileIdentityProvider.Instance)
    {
    }

    internal SpoolStore(
        string root,
        ISpoolAclPolicy aclPolicy,
        ISpoolPromotionObserver? promotionObserver)
        : this(root, aclPolicy, promotionObserver, PlatformLocalFileIdentityProvider.Instance)
    {
    }

    internal SpoolStore(
        string root,
        ISpoolAclPolicy aclPolicy,
        ILocalFileIdentityProvider fileIdentities)
        : this(root, aclPolicy, promotionObserver: null, fileIdentities)
    {
    }

    private SpoolStore(
        string root,
        ISpoolAclPolicy aclPolicy,
        ISpoolPromotionObserver? promotionObserver,
        ILocalFileIdentityProvider fileIdentities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        _root = Path.GetFullPath(root);
        _aclPolicy = aclPolicy ?? throw new ArgumentNullException(nameof(aclPolicy));
        _promotionObserver = promotionObserver;
        _fileIdentities = fileIdentities ?? throw new ArgumentNullException(nameof(fileIdentities));
    }

    public string Root => _root;

    public async Task<SpoolFile> WriteInputAsync(Guid jobId, string extension, Stream input, long maxBytes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (maxBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        var inputPath = GetInputPath(jobId, extension);
        var partPath = inputPath + ".part";
        var buffer = new byte[81_920];
        long size = 0;
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var output = new FileStream(partPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, buffer.Length, FileOptions.Asynchronous))
            {
                while (true)
                {
                    var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
                    if (read == 0)
                    {
                        break;
                    }

                    if (read > maxBytes - size)
                    {
                        throw new SpoolException("file_too_large");
                    }

                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    hash.AppendData(buffer, 0, read);
                    size += read;
                }

                await output.FlushAsync(cancellationToken);
                output.Flush(flushToDisk: true);
            }

            var sha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            File.Move(partPath, inputPath, overwrite: false);
            try
            {
                _aclPolicy.ProtectInput(inputPath);
            }
            catch (SpoolAclException)
            {
                DeleteIfPresent(inputPath);
                throw new SpoolException("acl_verification_failed");
            }

            return new SpoolFile(inputPath, size, sha256);
        }
        catch
        {
            DeleteIfPresent(partPath);
            throw;
        }
    }

    internal Task<Stream> OpenResultAsync(Guid jobId, string extension, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var resultPath = GetJobFilePath(jobId, "result", extension, createDirectory: false);
        if (!File.Exists(resultPath))
        {
            throw new SpoolException("result_not_ready");
        }

        AssertNotReparsePoint(resultPath);
        Stream stream = new FileStream(resultPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81_920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Task.FromResult(stream);
    }

    public async Task<Stream> OpenVerifiedResultAsync(
        Guid jobId,
        string extension,
        long expectedSize,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        if (expectedSize < 0 || !IsSha256(expectedSha256))
        {
            throw new ArgumentException("Expected result metadata is invalid.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var resultPath = GetJobFilePath(jobId, "result", extension, createDirectory: false);
        if (!File.Exists(resultPath))
        {
            throw new SpoolException("result_corrupt");
        }

        AssertNotReparsePoint(resultPath);
        var stream = new FileStream(
            resultPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            81_920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            AssertNotReparsePoint(resultPath);
            if (stream.Length != expectedSize)
            {
                throw new SpoolException("result_corrupt");
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[81_920];
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
            }

            var actualSha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            if (!string.Equals(actualSha256, expectedSha256, StringComparison.Ordinal))
            {
                throw new SpoolException("result_corrupt");
            }

            stream.Position = 0;
            return stream;
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<SpoolFile> PromoteResultAsync(Guid jobId, string extension, string expectedSha256, long expectedSize, CancellationToken cancellationToken = default)
    {
        if (expectedSize < 0 || !IsSha256(expectedSha256))
        {
            throw new ArgumentException("Expected result metadata is invalid.");
        }

        var partPath = GetResultPartPath(jobId, extension);
        var resultPath = GetResultPath(jobId, extension);
        if (PathEntryExists(resultPath))
        {
            return await AcceptExistingFinalAsync(
                resultPath,
                partPath,
                expectedSha256,
                expectedSize,
                cancellationToken);
        }

        if (!PathEntryExists(partPath))
        {
            throw new SpoolException("result_not_ready");
        }

        try
        {
            AssertNotReparsePoint(partPath);
        }
        catch (Exception exception) when (exception is SpoolException or IOException or UnauthorizedAccessException)
        {
            DeleteIfPresent(partPath);
            throw new SpoolException("result_corrupt");
        }

        try
        {
            if (_promotionObserver is not null)
            {
                await _promotionObserver
                    .BeforeResultClaimAsync(partPath, resultPath, cancellationToken)
                    .ConfigureAwait(false);
            }

            File.Move(partPath, resultPath, overwrite: false);
            try
            {
                _aclPolicy.ProtectFinalResult(resultPath);
            }
            catch (SpoolAclException)
            {
                TryDeleteIfPresent(resultPath);
                throw new SpoolException("acl_verification_failed");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            if (PathEntryExists(resultPath))
            {
                return await AcceptExistingFinalAsync(
                    resultPath,
                    partPath,
                    expectedSha256,
                    expectedSize,
                    cancellationToken);
            }

            DeleteIfPresent(partPath);
            throw new SpoolException("result_corrupt");
        }

        return await VerifyClaimedFinalAsync(
            resultPath,
            partPath,
            expectedSha256,
            expectedSize,
            cancellationToken).ConfigureAwait(false);
    }

    public Task DeleteJobAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("Job ID is required.", nameof(jobId));
        }

        var directory = Path.GetFullPath(Path.Combine(_root, jobId.ToString("N")));
        EnsureWithinRoot(directory);
        if (!Directory.Exists(directory))
        {
            return Task.CompletedTask;
        }

        AssertNotReparsePoint(directory);
        var entries = Directory
            .EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly)
            .ToArray();
        foreach (var path in entries)
        {
            AssertNotReparsePoint(path);
            if ((File.GetAttributes(path) & FileAttributes.Directory) != 0)
            {
                throw new SpoolException("invalid_spool_path");
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        foreach (var path in entries)
        {
            File.Delete(path);
        }

        if (Directory.EnumerateFileSystemEntries(directory).Any())
        {
            throw new SpoolException("invalid_spool_path");
        }

        Directory.Delete(directory);

        return Task.CompletedTask;
    }

    public Task DeleteLocalUploadArtifactsAsync(
        Guid jobId,
        string extension,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateExtension(extension);
        var directory = GetExistingJobDirectory(jobId);
        if (!Directory.Exists(directory))
        {
            return Task.CompletedTask;
        }

        AssertNotReparsePoint(directory);
        var expectedInput = "input" + extension;
        var expectedPart = expectedInput + ".part";
        var entries = Directory
            .EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly)
            .ToArray();
        foreach (var path in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AssertNotReparsePoint(path);
            var attributes = File.GetAttributes(path);
            var name = Path.GetFileName(path);
            if ((attributes & FileAttributes.Directory) != 0 ||
                name != expectedInput && name != expectedPart)
            {
                throw new SpoolException("local_upload_cleanup_unsafe");
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        foreach (var path in entries)
        {
            File.Delete(path);
        }

        if (Directory.EnumerateFileSystemEntries(directory).Any())
        {
            throw new SpoolException("local_upload_cleanup_unsafe");
        }

        Directory.Delete(directory);
        return Task.CompletedTask;
    }

    public string PrepareLocalUpload(Guid jobId, string extension)
    {
        var partPath = GetInputPath(jobId, extension) + ".part";
        if (PathEntryExists(partPath) || PathEntryExists(GetInputPath(jobId, extension)))
        {
            throw new SpoolException("local_upload_invalid_path");
        }

        return $"{jobId:N}/input{extension}.part";
    }

    public Task<LocalUploadFile> OpenLocalUploadAsync(
        Guid jobId,
        string extension,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var inputPath = GetJobFilePath(jobId, "input", extension, createDirectory: false);
        var partPath = inputPath + ".part";
        var isPart = PathEntryExists(partPath);
        var path = isPart ? partPath : inputPath;
        if (!File.Exists(path))
        {
            throw new SpoolException("local_upload_missing");
        }

        AssertNotReparsePoint(_root);
        var directory = Path.GetDirectoryName(path) ?? throw new SpoolException("local_upload_invalid_path");
        AssertNotReparsePoint(directory);
        AssertNotReparsePoint(path);
        FileStream? stream = null;
        try
        {
            stream = NoFollowFile.OpenRead(
                path,
                isPart ? FileShare.Read | FileShare.Delete : FileShare.Read,
                1024 * 1024);
            AssertNotReparsePoint(path);
            if (!_fileIdentities.TryGetIdentity(stream.SafeFileHandle, out var identity) ||
                identity.LinkCount != 1)
            {
                throw new SpoolException("local_upload_invalid_path");
            }

            return Task.FromResult(new LocalUploadFile(
                this,
                jobId,
                extension,
                path,
                isPart,
                stream,
                identity));
        }
        catch
        {
            stream?.Dispose();
            throw;
        }
    }

    public async Task PromoteLocalUploadAsync(
        LocalUploadFile upload,
        long expectedSize,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(upload);
        if (!ReferenceEquals(upload.Owner, this) ||
            expectedSize <= 0 || !IsLowerSha256(expectedSha256))
        {
            throw new ArgumentException("Expected local input metadata is invalid.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var inputPath = GetInputPath(upload.JobId, upload.Extension);
        var partPath = inputPath + ".part";
        if (!_fileIdentities.TryGetIdentity(upload.Stream.SafeFileHandle, out var beforeClaim) ||
            beforeClaim.LinkCount != 1 ||
            !beforeClaim.RefersToSameFile(upload.Identity) ||
            upload.Stream.Length != expectedSize)
        {
            throw new SpoolException("local_upload_invalid_path");
        }

        if (upload.IsPart)
        {
            if (!string.Equals(upload.Path, partPath, PathComparison()) || PathEntryExists(inputPath))
            {
                throw new SpoolException("local_upload_invalid_path");
            }

            AssertNotReparsePoint(partPath);
            File.Move(partPath, inputPath, overwrite: false);
            upload.Path = inputPath;
            upload.IsPart = false;
        }

        FileStream? guard = null;
        try
        {
            guard = NoFollowFile.OpenRead(inputPath, FileShare.Read, 1024 * 1024);
            if (!_fileIdentities.TryGetIdentity(guard.SafeFileHandle, out var claimed) ||
                claimed.LinkCount != 1 ||
                !claimed.RefersToSameFile(upload.Identity))
            {
                throw new SpoolException("local_upload_invalid_path");
            }

            _aclPolicy.ProtectInput(inputPath);
            if (!_fileIdentities.TryGetIdentity(guard.SafeFileHandle, out var readback) ||
                readback.LinkCount != 1 ||
                !readback.RefersToSameFile(upload.Identity))
            {
                throw new SpoolException("local_upload_invalid_path");
            }

            await using var pathReadback = NoFollowFile.OpenRead(
                inputPath,
                FileShare.Read,
                1024 * 1024);
            if (!_fileIdentities.TryGetIdentity(pathReadback.SafeFileHandle, out var pathIdentity) ||
                pathIdentity.LinkCount != 1 ||
                !pathIdentity.RefersToSameFile(upload.Identity))
            {
                throw new SpoolException("local_upload_invalid_path");
            }
        }
        finally
        {
            if (guard is not null)
            {
                await guard.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    public string GetInputPath(Guid jobId, string extension) => GetJobFilePath(jobId, "input", extension, createDirectory: true);

    public void ValidateLocalUploadArtifacts(Guid jobId, string extension)
    {
        var inputPath = GetJobFilePath(jobId, "input", extension, createDirectory: false);
        var directory = Path.GetDirectoryName(inputPath)
            ?? throw new SpoolException("local_upload_invalid_path");
        if (!Directory.Exists(directory))
        {
            return;
        }

        AssertNotReparsePoint(directory);
        var expectedPart = Path.GetFileName(inputPath) + ".part";
        var expectedInput = Path.GetFileName(inputPath);
        var entries = Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly).ToArray();
        if (entries.Length > 1)
        {
            throw new SpoolException("local_upload_invalid_path");
        }

        foreach (var entry in entries)
        {
            AssertNotReparsePoint(entry);
            if ((File.GetAttributes(entry) & FileAttributes.Directory) != 0 ||
                Path.GetFileName(entry) is var name && name != expectedPart && name != expectedInput)
            {
                throw new SpoolException("local_upload_invalid_path");
            }
        }
    }

    public string GetResultPartPath(Guid jobId, string extension) => GetJobFilePath(jobId, "result.part", extension, createDirectory: true);

    public string GetResultPath(Guid jobId, string extension) => GetJobFilePath(jobId, "result", extension, createDirectory: true);

    public IReadOnlyList<SpoolJobDirectory> ValidateAndListJobDirectories()
    {
        Directory.CreateDirectory(_root);
        ProtectRoot();
        AssertNotReparsePoint(_root);
        var directories = new List<SpoolJobDirectory>();
        foreach (var path in Directory.EnumerateFileSystemEntries(_root, "*", SearchOption.TopDirectoryOnly))
        {
            AssertNotReparsePoint(path);
            if ((File.GetAttributes(path) & FileAttributes.Directory) == 0)
            {
                continue;
            }

            var name = Path.GetFileName(path);
            directories.Add(new SpoolJobDirectory(
                Guid.TryParseExact(name, "N", out var jobId) ? jobId : null,
                path,
                name));
        }

        return directories;
    }

    public Task DeleteStalePartsAsync(Job job, DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        cancellationToken.ThrowIfCancellationRequested();
        var directory = GetExistingJobDirectory(job.Id);
        if (!Directory.Exists(directory))
        {
            return Task.CompletedTask;
        }

        AssertNotReparsePoint(directory);
        foreach (var path in Directory.EnumerateFiles(directory, "*.part", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            AssertNotReparsePoint(path);
            if (File.GetLastWriteTimeUtc(path) <= cutoff.UtcDateTime)
            {
                File.Delete(path);
            }
        }

        return Task.CompletedTask;
    }

    public Task DeleteSucceededTransientFilesAsync(Job job, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(job);
        cancellationToken.ThrowIfCancellationRequested();
        var directory = GetExistingJobDirectory(job.Id);
        if (!Directory.Exists(directory))
        {
            return Task.CompletedTask;
        }

        AssertNotReparsePoint(directory);
        foreach (var path in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = Path.GetFileName(path);
            if (!name.StartsWith("input", StringComparison.OrdinalIgnoreCase) &&
                !name.StartsWith("work", StringComparison.OrdinalIgnoreCase) &&
                !name.EndsWith(".part", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            AssertNotReparsePoint(path);
            File.Delete(path);
        }

        return Task.CompletedTask;
    }

    public Task QuarantineAsync(SpoolJobDirectory directory, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(directory);
        cancellationToken.ThrowIfCancellationRequested();
        var expected = Path.GetFullPath(Path.Combine(_root, directory.Name));
        EnsureWithinRoot(expected);
        if (!string.Equals(expected, directory.Path, PathComparison()))
        {
            throw new SpoolException("invalid_spool_path");
        }

        if (!Directory.Exists(directory.Path))
        {
            return Task.CompletedTask;
        }

        AssertNotReparsePoint(directory.Path);
        var parent = Path.GetDirectoryName(_root) ?? throw new SpoolException("invalid_spool_path");
        var quarantine = Path.GetFullPath(Path.Combine(parent, "quarantine"));
        Directory.CreateDirectory(quarantine);
        AssertNotReparsePoint(quarantine);
        var destination = Path.Combine(quarantine, directory.Name);
        while (PathEntryExists(destination))
        {
            destination = Path.Combine(quarantine, $"{directory.Name}-{Guid.NewGuid():N}");
        }

        Directory.Move(directory.Path, destination);
        return Task.CompletedTask;
    }

    private string GetJobFilePath(Guid jobId, string fileStem, string extension, bool createDirectory)
    {
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("Job ID is required.", nameof(jobId));
        }

        ValidateExtension(extension);
        Directory.CreateDirectory(_root);
        ProtectRoot();
        AssertNotReparsePoint(_root);
        var directory = Path.GetFullPath(Path.Combine(_root, jobId.ToString("N")));
        EnsureWithinRoot(directory);
        if (createDirectory)
        {
            Directory.CreateDirectory(directory);
            AssertNotReparsePoint(directory);
            ProtectJobDirectory(directory);
        }

        var path = Path.GetFullPath(Path.Combine(directory, fileStem + extension));
        EnsureWithinRoot(path);
        return path;
    }

    private void EnsureWithinRoot(string path)
    {
        var rootWithSeparator = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!path.StartsWith(rootWithSeparator, comparison))
        {
            throw new SpoolException("invalid_spool_path");
        }
    }

    private string GetExistingJobDirectory(Guid jobId)
    {
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("Job ID is required.", nameof(jobId));
        }

        var directory = Path.GetFullPath(Path.Combine(_root, jobId.ToString("N")));
        EnsureWithinRoot(directory);
        return directory;
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private void ProtectRoot()
    {
        try
        {
            _aclPolicy.ProtectRoot(_root);
        }
        catch (SpoolAclException)
        {
            throw new SpoolException("acl_verification_failed");
        }
    }

    private void ProtectJobDirectory(string path)
    {
        try
        {
            _aclPolicy.ProtectJobDirectory(path);
        }
        catch (SpoolAclException)
        {
            throw new SpoolException("acl_verification_failed");
        }
    }

    private static void ValidateExtension(string extension)
    {
        if (!AllowedExtensions.Contains(extension) || !string.Equals(Path.GetExtension("input" + extension), extension, StringComparison.OrdinalIgnoreCase))
        {
            throw new SpoolException("invalid_extension");
        }
    }

    private static void AssertNotReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new SpoolException("invalid_spool_path");
        }
    }

    private static async Task<SpoolFile> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81_920];
        long size = 0;
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, buffer.Length, FileOptions.Asynchronous | FileOptions.SequentialScan);
        while (true)
        {
            var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0)
            {
                break;
            }

            hash.AppendData(buffer, 0, read);
            size += read;
        }

        return new SpoolFile(path, size, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
    }

    private async Task<SpoolFile> AcceptExistingFinalAsync(
        string resultPath,
        string partPath,
        string expectedSha256,
        long expectedSize,
        CancellationToken cancellationToken)
    {
        try
        {
            AssertNotReparsePoint(resultPath);
            try
            {
                _aclPolicy.ProtectFinalResult(resultPath);
            }
            catch (SpoolAclException)
            {
                throw new SpoolException("acl_verification_failed");
            }

            var existing = await HashFileAsync(resultPath, cancellationToken);
            if (existing.Size == expectedSize &&
                string.Equals(existing.Sha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                DeleteIfPresent(partPath);
                return existing;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SpoolException exception) when (exception.Code == "acl_verification_failed")
        {
            throw;
        }
        catch (SpoolException)
        {
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        DeleteIfPresent(partPath);
        throw new SpoolException("result_corrupt");
    }

    private static async Task<SpoolFile> VerifyClaimedFinalAsync(
        string resultPath,
        string partPath,
        string expectedSha256,
        long expectedSize,
        CancellationToken cancellationToken)
    {
        try
        {
            AssertNotReparsePoint(resultPath);
            var claimed = await HashFileAsync(resultPath, cancellationToken).ConfigureAwait(false);
            if (claimed.Size == expectedSize &&
                string.Equals(claimed.Sha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                DeleteIfPresent(partPath);
                return claimed;
            }
        }
        catch (OperationCanceledException)
        {
            // The rename is already durable. Leave the claimed final in place so
            // persisted Verifying metadata can resume validation after restart.
            throw;
        }
        catch (Exception exception) when (
            exception is SpoolException or IOException or UnauthorizedAccessException)
        {
        }

        TryDeleteIfPresent(resultPath);
        TryDeleteIfPresent(partPath);
        throw new SpoolException("result_corrupt");
    }

    private static bool IsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void DeleteIfPresent(string path)
    {
        if (File.Exists(path) || IsSymbolicLink(path))
        {
            File.Delete(path);
        }
    }

    private static void TryDeleteIfPresent(string path)
    {
        try
        {
            DeleteIfPresent(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static bool PathEntryExists(string path) =>
        File.Exists(path) || Directory.Exists(path) || IsSymbolicLink(path);

    private static bool IsSymbolicLink(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget is not null;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}
