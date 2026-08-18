using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Core.Security;

namespace SimplySignAuto.App.Commands;

internal sealed record InstallMediaFilePlan(
    string RelativePath,
    string SourcePath,
    string FinalPath,
    long Length,
    string Sha256);

internal sealed record InstallMediaPlan(
    string SourceRoot,
    string StagingRoot,
    string TargetRoot,
    string TargetExecutablePath,
    string PublisherIdentity,
    long RequiredBytes,
    IReadOnlyList<InstallMediaFilePlan> Files);

internal interface IInstallMediaStager
{
    Task<InstallMediaPlan> PlanAsync(CancellationToken cancellationToken);
    Task StageAsync(InstallMediaPlan plan, CancellationToken cancellationToken);
    Task AuthorizeAsync(InstallMediaPlan plan, string signingUserSid, CancellationToken cancellationToken);
    Task RollbackAsync(InstallMediaPlan plan);
}

internal interface IInstallMediaVerifier
{
    string VerifyInitialPublisher(string executablePath, string scriptPath);
    Task VerifyMediaAsync(
        string root,
        string expectedPublisherIdentity,
        CancellationToken cancellationToken);
}

internal static class InstallMediaPaths
{
    internal const string ProductDirectoryName = "SimplySignAuto";
    internal const string ExecutableFileName = "SimplySignAuto.exe";
    internal const string VerificationScriptFileName = "install-prerequisites.ps1";

    public static string GetTargetRoot(string programFilesRoot) =>
        Path.GetFullPath(Path.Combine(
            string.IsNullOrWhiteSpace(programFilesRoot)
                ? throw new SetupException("install_media_target_invalid")
                : programFilesRoot,
            ProductDirectoryName));

    public static string GetTargetExecutablePath(string programFilesRoot) =>
        Path.Combine(GetTargetRoot(programFilesRoot), ExecutableFileName);
}

internal static class InstallMediaPreflight
{
    public static void ValidateAvailableSpace(long availableBytes, long requiredBytes)
    {
        if (availableBytes < 0 || requiredBytes < 0 || availableBytes < requiredBytes)
        {
            throw new SetupException("install_media_space_insufficient");
        }
    }
}

internal sealed class WindowsInstallMediaStager : IInstallMediaStager
{
    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);
    private readonly string _sourceRoot;
    private readonly string _programFilesRoot;
    private readonly IInstallMediaVerifier _verifier;
    private readonly Func<string> _nonceFactory;
    private readonly IAtomicProtectedDirectoryOperations _directoryOperations;
    private InstallMediaPlan? _activePlan;
    private SourceMediaLease? _sourceLease;
    private LocalFileIdentity? _ownedDirectoryIdentity;
    private bool _stagingCreated;
    private bool _promoted;
    private bool _rollbackSafe;

    public WindowsInstallMediaStager()
        : this(
            GetProcessDirectory(),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            new WindowsInstallMediaVerifier(),
            () => Guid.NewGuid().ToString("N"),
            new WindowsAtomicProtectedDirectoryOperations())
    {
    }

    internal WindowsInstallMediaStager(
        string sourceRoot,
        string programFilesRoot,
        IInstallMediaVerifier verifier,
        Func<string> nonceFactory)
        : this(
            sourceRoot,
            programFilesRoot,
            verifier,
            nonceFactory,
            new WindowsAtomicProtectedDirectoryOperations())
    {
    }

    internal WindowsInstallMediaStager(
        string sourceRoot,
        string programFilesRoot,
        IInstallMediaVerifier verifier,
        Func<string> nonceFactory,
        IAtomicProtectedDirectoryOperations directoryOperations)
    {
        _sourceRoot = Path.GetFullPath(sourceRoot ?? throw new ArgumentNullException(nameof(sourceRoot)));
        _programFilesRoot = Path.GetFullPath(programFilesRoot ?? throw new ArgumentNullException(nameof(programFilesRoot)));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _nonceFactory = nonceFactory ?? throw new ArgumentNullException(nameof(nonceFactory));
        _directoryOperations = directoryOperations ??
            throw new ArgumentNullException(nameof(directoryOperations));
    }

    public async Task<InstallMediaPlan> PlanAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        if (_activePlan is not null)
        {
            throw new SetupException("install_media_preflight_failed");
        }

        SourceMediaLease? lease = null;
        try
        {
            VerifyCanonicalRoot(_sourceRoot);
            VerifyCanonicalRoot(_programFilesRoot);
            VerifySourceAncestors(_sourceRoot);
            VerifyTargetAncestors(_programFilesRoot);
            var targetRoot = InstallMediaPaths.GetTargetRoot(_programFilesRoot);
            if (EntryExists(targetRoot))
            {
                throw new SetupException("install_media_target_exists");
            }

            var nonce = _nonceFactory();
            if (string.IsNullOrWhiteSpace(nonce) || nonce.Any(character => !char.IsAsciiLetterOrDigit(character)))
            {
                throw new SetupException("install_media_preflight_failed");
            }

            var stagingRoot = Path.GetFullPath(Path.Combine(
                _programFilesRoot,
                $"{InstallMediaPaths.ProductDirectoryName}.part-{nonce}"));
            if (EntryExists(stagingRoot))
            {
                throw new SetupException("install_media_target_exists");
            }

            lease = await SourceMediaLease.CaptureAsync(_sourceRoot, cancellationToken).ConfigureAwait(false);
            if (!lease.Contains(InstallMediaPaths.ExecutableFileName) ||
                !lease.Contains(InstallMediaPaths.VerificationScriptFileName) ||
                !lease.Contains("release-files.cat"))
            {
                throw new SetupException("install_media_missing");
            }

            var beforeVerification = lease;
            lease = null;
            beforeVerification.Dispose();
            var publisher = _verifier.VerifyInitialPublisher(
                Path.Combine(_sourceRoot, InstallMediaPaths.ExecutableFileName),
                Path.Combine(_sourceRoot, InstallMediaPaths.VerificationScriptFileName));
            ValidatePublisherHash(publisher);
            await _verifier.VerifyMediaAsync(_sourceRoot, publisher, cancellationToken).ConfigureAwait(false);
            lease = await SourceMediaLease.CaptureAsync(_sourceRoot, cancellationToken).ConfigureAwait(false);
            if (!beforeVerification.RefersToSameSnapshot(lease))
            {
                throw new SetupException("install_media_source_changed");
            }

            await lease.VerifyUnchangedAsync(cancellationToken).ConfigureAwait(false);
            var requiredBytes = lease.Files.Sum(file => file.Length);
            InstallMediaPreflight.ValidateAvailableSpace(
                new DriveInfo(Path.GetPathRoot(_programFilesRoot)!).AvailableFreeSpace,
                requiredBytes);
            var files = lease.Files.Select(file => new InstallMediaFilePlan(
                    file.RelativePath,
                    file.Path,
                    CombineRelative(targetRoot, file.RelativePath),
                    file.Length,
                    file.Sha256))
                .ToArray();
            var plan = new InstallMediaPlan(
                _sourceRoot,
                stagingRoot,
                targetRoot,
                Path.Combine(targetRoot, InstallMediaPaths.ExecutableFileName),
                publisher,
                requiredBytes,
                files);
            _sourceLease = lease;
            lease = null;
            _activePlan = plan;
            return plan;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SetupException)
        {
            throw;
        }
        catch (InstallException error) when (error.Code.EndsWith("state_uncertain", StringComparison.Ordinal))
        {
            throw new SetupException("setup_state_uncertain");
        }
        catch
        {
            throw new SetupException("install_media_preflight_failed");
        }
        finally
        {
            lease?.Dispose();
        }
    }

    public async Task StageAsync(InstallMediaPlan plan, CancellationToken cancellationToken)
    {
        ValidateActivePlan(plan);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            CreateOwnedDirectory(_programFilesRoot, plan.StagingRoot, root: true);
            foreach (var directory in ExpectedDirectories(plan.Files)
                         .OrderBy(path => path.Count(character => character == '/'))
                         .ThenBy(path => path, StringComparer.Ordinal))
            {
                var fullPath = CombineRelative(plan.StagingRoot, directory);
                CreateOwnedDirectory(Path.GetDirectoryName(fullPath)!, fullPath, root: false);
            }

            foreach (var file in plan.Files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var source = _sourceLease?.Get(file.RelativePath)
                    ?? throw new SetupException("install_media_copy_failed");
                await CopyFileAsync(source, CombineRelative(plan.StagingRoot, file.RelativePath), file, cancellationToken)
                    .ConfigureAwait(false);
            }

            await (_sourceLease?.VerifyUnchangedAsync(cancellationToken)
                    ?? throw new SetupException("install_media_copy_failed"))
                .ConfigureAwait(false);
            ReleaseSourceLease();
            var stagedPublisher = _verifier.VerifyInitialPublisher(
                Path.Combine(plan.StagingRoot, InstallMediaPaths.ExecutableFileName),
                Path.Combine(plan.StagingRoot, InstallMediaPaths.VerificationScriptFileName));
            if (!string.Equals(stagedPublisher, plan.PublisherIdentity, StringComparison.Ordinal))
            {
                throw new SetupException("install_media_publisher_mismatch");
            }

            await _verifier.VerifyMediaAsync(plan.StagingRoot, plan.PublisherIdentity, cancellationToken)
                .ConfigureAwait(false);
            await VerifyTreeAsync(plan.StagingRoot, plan.Files, true, cancellationToken).ConfigureAwait(false);
            if (EntryExists(plan.TargetRoot))
            {
                throw new SetupException("install_media_target_exists");
            }

            Directory.Move(plan.StagingRoot, plan.TargetRoot);
            if (!SameIdentity(_ownedDirectoryIdentity, ReadDirectoryIdentity(plan.TargetRoot)))
            {
                throw new SetupException("setup_state_uncertain");
            }

            _promoted = true;
            await VerifyTreeAsync(plan.TargetRoot, plan.Files, true, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SetupException)
        {
            throw;
        }
        catch (InstallException error) when (error.Code.EndsWith("state_uncertain", StringComparison.Ordinal))
        {
            throw new SetupException("setup_state_uncertain");
        }
        catch
        {
            throw new SetupException("install_media_copy_failed");
        }
        finally
        {
            ReleaseSourceLease();
        }
    }

    public async Task AuthorizeAsync(
        InstallMediaPlan plan,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        ValidateActivePlan(plan);
        cancellationToken.ThrowIfCancellationRequested();
        if (!_promoted || !SameIdentity(_ownedDirectoryIdentity, ReadDirectoryIdentity(plan.TargetRoot)))
        {
            throw new SetupException("setup_state_uncertain");
        }

        try
        {
            await VerifyTreeAsync(plan.TargetRoot, plan.Files, true, cancellationToken).ConfigureAwait(false);
            var signingUser = new SecurityIdentifier(signingUserSid);
            if (!string.Equals(signingUser.Value, signingUserSid, StringComparison.Ordinal))
            {
                throw new SetupException("install_media_authorization_failed");
            }

            foreach (var file in plan.Files)
            {
                WindowsInstallAcl.ApplyFile(file.FinalPath, InstallAclProfile.SigningUserRead, signingUser);
            }

            foreach (var directory in ExpectedDirectories(plan.Files)
                         .OrderByDescending(path => path.Length))
            {
                WindowsInstallAcl.ApplyDirectory(
                    CombineRelative(plan.TargetRoot, directory),
                    InstallAclProfile.SigningUserRead,
                    signingUser);
            }

            WindowsInstallAcl.ApplyDirectory(plan.TargetRoot, InstallAclProfile.SigningUserRead, signingUser);
            WindowsInstallAcl.VerifyDirectory(plan.TargetRoot, InstallAclProfile.SigningUserRead, signingUser);
            foreach (var directory in ExpectedDirectories(plan.Files))
            {
                WindowsInstallAcl.VerifyDirectory(
                    CombineRelative(plan.TargetRoot, directory),
                    InstallAclProfile.SigningUserRead,
                    signingUser);
            }

            foreach (var file in plan.Files)
            {
                WindowsInstallAcl.VerifyFile(file.FinalPath, InstallAclProfile.SigningUserRead, signingUser);
            }

            await VerifyTreeAsync(plan.TargetRoot, plan.Files, false, cancellationToken).ConfigureAwait(false);
            await _verifier.VerifyMediaAsync(plan.TargetRoot, plan.PublisherIdentity, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SetupException)
        {
            throw;
        }
        catch
        {
            throw new SetupException("install_media_authorization_failed");
        }
    }

    public async Task RollbackAsync(InstallMediaPlan plan)
    {
        ValidateActivePlan(plan);
        ReleaseSourceLease();
        if (!_stagingCreated)
        {
            ClearState();
            return;
        }

        if (!_rollbackSafe)
        {
            throw new SetupException("setup_state_uncertain");
        }

        var ownedPath = _promoted ? plan.TargetRoot : plan.StagingRoot;
        try
        {
            if (!Directory.Exists(ownedPath) ||
                !SameIdentity(_ownedDirectoryIdentity, ReadDirectoryIdentity(ownedPath)))
            {
                throw new SetupException("setup_state_uncertain");
            }

            await VerifyRollbackTreeAsync(ownedPath, plan.Files, _promoted).ConfigureAwait(false);
            Directory.Delete(ownedPath, recursive: true);
            if (EntryExists(ownedPath))
            {
                throw new SetupException("setup_state_uncertain");
            }

            ClearState();
        }
        catch (SetupException error) when (!string.Equals(
            error.Code,
            "setup_state_uncertain",
            StringComparison.Ordinal))
        {
            throw new SetupException("setup_state_uncertain");
        }
        catch (SetupException)
        {
            throw;
        }
        catch
        {
            throw new SetupException("setup_state_uncertain");
        }
    }

    private async Task VerifyRollbackTreeAsync(
        string root,
        IReadOnlyList<InstallMediaFilePlan> files,
        bool requireComplete)
    {
        var expected = files.ToDictionary(file => file.RelativePath, StringComparer.Ordinal);
        var actualFiles = EnumerateFiles(root);
        if ((requireComplete && actualFiles.Count != expected.Count) ||
            actualFiles.Any(path => !expected.ContainsKey(path)))
        {
            throw new SetupException("setup_state_uncertain");
        }

        foreach (var relativePath in actualFiles)
        {
            var path = CombineRelative(root, relativePath);
            VerifyPlainSingleLink(path);
            if (!string.Equals(
                    await HashFileAsync(path, CancellationToken.None).ConfigureAwait(false),
                    expected[relativePath].Sha256,
                    StringComparison.Ordinal))
            {
                throw new SetupException("setup_state_uncertain");
            }
        }

        var expectedDirectories = ExpectedDirectories(files).ToHashSet(StringComparer.Ordinal);
        if (EnumerateDirectories(root).Any(path => !expectedDirectories.Contains(path)))
        {
            throw new SetupException("setup_state_uncertain");
        }
    }

    private static async Task VerifyTreeAsync(
        string root,
        IReadOnlyList<InstallMediaFilePlan> files,
        bool requireAdministratorsOnly,
        CancellationToken cancellationToken)
    {
        var actualFiles = EnumerateFiles(root);
        var actualDirectories = EnumerateDirectories(root);
        if (!actualFiles.ToHashSet(StringComparer.Ordinal).SetEquals(
                files.Select(file => file.RelativePath)) ||
            !actualDirectories.ToHashSet(StringComparer.Ordinal).SetEquals(ExpectedDirectories(files)))
        {
            throw new SetupException("install_media_readback_failed");
        }

        if (requireAdministratorsOnly)
        {
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadDirectory(root), directory: true);
        }

        foreach (var directory in actualDirectories)
        {
            var path = CombineRelative(root, directory);
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new SetupException("install_media_readback_failed");
            }

            if (requireAdministratorsOnly)
            {
                WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                    WindowsNoFollowSecurity.ReadDirectory(path), directory: true);
            }
        }

        var expected = files.ToDictionary(file => file.RelativePath, StringComparer.Ordinal);
        foreach (var relativePath in actualFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = CombineRelative(root, relativePath);
            VerifyPlainSingleLink(path);
            if (requireAdministratorsOnly)
            {
                WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                    WindowsNoFollowSecurity.ReadFile(path), directory: false);
            }

            if (new FileInfo(path).Length != expected[relativePath].Length ||
                !string.Equals(
                    await HashFileAsync(path, cancellationToken).ConfigureAwait(false),
                    expected[relativePath].Sha256,
                    StringComparison.Ordinal))
            {
                throw new SetupException("install_media_readback_failed");
            }
        }
    }

    private static async Task CopyFileAsync(
        SourceFileLease source,
        string destination,
        InstallMediaFilePlan expected,
        CancellationToken cancellationToken)
    {
        var temporary = destination + ".part";
        if (EntryExists(temporary) || EntryExists(destination))
        {
            throw new SetupException("install_media_copy_failed");
        }

        var binary = WindowsInstallAcl
            .CreateFileSecurity(InstallAclProfile.AdministratorsOnly, LocalSystem)
            .GetSecurityDescriptorBinaryForm();
        var created = false;
        LocalFileIdentity? temporaryIdentity = null;
        try
        {
            var destinationHandle = WindowsNativeProtectedObject.CreateFile(temporary, binary);
            temporaryIdentity = ReadIdentity(destinationHandle);
            await using (var destinationStream = new FileStream(
                destinationHandle,
                FileAccess.Write,
                1024 * 64,
                isAsync: true))
            {
                created = true;
                source.Stream.Position = 0;
                await source.Stream.CopyToAsync(destinationStream, 1024 * 64, cancellationToken)
                    .ConfigureAwait(false);
                await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                destinationStream.Flush(flushToDisk: true);
            }

            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadFile(temporary), directory: false);
            if (new FileInfo(temporary).Length != expected.Length ||
                !string.Equals(
                    await HashFileAsync(temporary, cancellationToken).ConfigureAwait(false),
                    expected.Sha256,
                    StringComparison.Ordinal))
            {
                throw new SetupException("install_media_copy_failed");
            }

            File.Move(temporary, destination);
            using var destinationReadback = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(destination);
            if (!SameIdentity(temporaryIdentity, ReadIdentity(destinationReadback)))
            {
                throw new SetupException("setup_state_uncertain");
            }
        }
        catch
        {
            if (created && EntryExists(temporary))
            {
                try
                {
                    using var temporaryReadback = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(temporary);
                    if (!SameIdentity(temporaryIdentity, ReadIdentity(temporaryReadback)))
                    {
                        throw new SetupException("setup_state_uncertain");
                    }

                    WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                        WindowsNoFollowSecurity.Read(temporaryReadback), directory: false);
                    File.Delete(temporary);
                }
                catch
                {
                    throw new SetupException("setup_state_uncertain");
                }
            }

            throw;
        }
    }

    private void ValidateActivePlan(InstallMediaPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (_activePlan is null || !ReferenceEquals(_activePlan, plan))
        {
            throw new SetupException("setup_state_uncertain");
        }
    }

    private void CreateOwnedDirectory(string trustedAnchor, string path, bool root)
    {
        var created = false;
        try
        {
            _directoryOperations.VerifyTrustedAnchor(trustedAnchor);
            if (_directoryOperations.EntryExistsNoFollow(path))
            {
                throw new SetupException("install_media_target_exists");
            }

            _directoryOperations.CreateNewWithSecurity(path);
            created = true;
            if (root)
            {
                _stagingCreated = true;
                _ownedDirectoryIdentity = ReadDirectoryIdentity(path);
            }

            _rollbackSafe = false;
            _directoryOperations.VerifyCreated(path);
            _rollbackSafe = true;
        }
        catch (SetupException)
        {
            throw;
        }
        catch when (created)
        {
            _rollbackSafe = false;
            throw new SetupException("setup_state_uncertain");
        }
        catch
        {
            throw new SetupException("install_media_copy_failed");
        }
    }

    private void ReleaseSourceLease()
    {
        _sourceLease?.Dispose();
        _sourceLease = null;
    }

    private void ClearState()
    {
        _activePlan = null;
        _ownedDirectoryIdentity = null;
        _stagingCreated = false;
        _promoted = false;
        _rollbackSafe = false;
    }

    private static void ValidatePublisherHash(string publisher)
    {
        if (publisher.Length != 40 || publisher.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new SetupException("install_media_publisher_invalid");
        }
    }

    private static void VerifyCanonicalRoot(string path)
    {
        if (!Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(path))
        {
            throw new SetupException("install_media_path_invalid");
        }
    }

    private static void VerifySourceAncestors(string sourceRoot)
    {
        for (var current = new DirectoryInfo(sourceRoot); current is not null; current = current.Parent)
        {
            if ((WindowsNoFollowSecurity.ReadDirectory(current.FullName).Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new SetupException("install_media_path_invalid");
            }
        }
    }

    private static void VerifyTargetAncestors(string programFilesRoot)
    {
        var root = new DirectoryInfo(programFilesRoot);
        WindowsExecutableSecurity.VerifyEntry(
            WindowsNoFollowSecurity.ReadDirectory(root.FullName),
            string.Empty,
            requireReadExecute: false);
        for (var current = root.Parent; current is not null; current = current.Parent)
        {
            if ((WindowsNoFollowSecurity.ReadDirectory(current.FullName).Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new SetupException("install_media_path_invalid");
            }
        }
    }

    private static string GetProcessDirectory()
    {
        var path = Environment.ProcessPath is { } processPath
            ? Path.GetFullPath(processPath)
            : throw new SetupException("install_media_source_invalid");
        return Path.GetDirectoryName(path) ?? throw new SetupException("install_media_source_invalid");
    }

    private static bool EntryExists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static string CombineRelative(string root, string relativePath) =>
        Path.GetFullPath(Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar)));

    private static IReadOnlyList<string> EnumerateFiles(string root) =>
        EnumerateTree(root)
            .Where(entry => !entry.Directory)
            .Select(entry => entry.RelativePath)
            .ToArray();

    private static IReadOnlyList<string> EnumerateDirectories(string root) =>
        EnumerateTree(root)
            .Where(entry => entry.Directory)
            .Select(entry => entry.RelativePath)
            .ToArray();

    private static IReadOnlyList<MediaTreeEntry> EnumerateTree(string root)
    {
        var rootPrefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var pending = new Stack<string>();
        var entries = new List<MediaTreeEntry>();
        pending.Push(root);
        while (pending.Count != 0)
        {
            var directory = pending.Pop();
            foreach (var path in Directory.EnumerateFileSystemEntries(directory)
                         .OrderBy(path => path, StringComparer.Ordinal))
            {
                var canonical = Path.GetFullPath(path);
                var attributes = File.GetAttributes(canonical);
                if (!canonical.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase) ||
                    (attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new SetupException("install_media_path_invalid");
                }

                var isDirectory = (attributes & FileAttributes.Directory) != 0;
                entries.Add(new MediaTreeEntry(canonical, GetRelative(root, canonical), isDirectory));
                if (isDirectory)
                {
                    pending.Push(canonical);
                }
            }
        }

        return entries.OrderBy(entry => entry.RelativePath, StringComparer.Ordinal).ToArray();
    }

    private static IEnumerable<string> ExpectedDirectories(IReadOnlyList<InstallMediaFilePlan> files) =>
        files.SelectMany(file => ParentPaths(file.RelativePath)).Distinct(StringComparer.Ordinal);

    private static IEnumerable<string> ParentPaths(string relativePath)
    {
        var parent = Path.GetDirectoryName(relativePath.Replace('/', Path.DirectorySeparatorChar));
        while (!string.IsNullOrEmpty(parent))
        {
            yield return parent.Replace(Path.DirectorySeparatorChar, '/');
            parent = Path.GetDirectoryName(parent);
        }
    }

    private static string GetRelative(string root, string path) =>
        Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');

    private static LocalFileIdentity ReadDirectoryIdentity(string path)
    {
        using var handle = WindowsNoFollowSecurity.OpenDirectoryHandle(path);
        return ReadIdentity(handle);
    }

    private static void VerifyPlainSingleLink(string path)
    {
        using var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path);
        if (ReadIdentity(handle).LinkCount != 1 ||
            (WindowsNoFollowSecurity.Read(handle).Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new SetupException("install_media_link_invalid");
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path),
            FileAccess.Read,
            1024 * 64,
            isAsync: false);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();
    }

    private static LocalFileIdentity ReadIdentity(SafeFileHandle handle)
    {
        if (!PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(handle, out var identity))
        {
            throw new SetupException("install_media_identity_failed");
        }

        return identity;
    }

    private static bool SameIdentity(LocalFileIdentity? expected, LocalFileIdentity actual) =>
        expected is { } value && value.RefersToSameFile(actual);

    private sealed record MediaTreeEntry(string Path, string RelativePath, bool Directory);

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new SetupException("windows_required");
        }
    }

    private sealed class SourceMediaLease : IDisposable
    {
        private readonly string _root;
        private readonly SafeFileHandle _rootHandle;
        private readonly LocalFileIdentity _rootIdentity;
        private readonly IReadOnlyList<SourceDirectoryLease> _directories;
        private readonly Dictionary<string, SourceFileLease> _files;
        private bool _disposed;

        private SourceMediaLease(
            string root,
            SafeFileHandle rootHandle,
            LocalFileIdentity rootIdentity,
            IReadOnlyList<SourceDirectoryLease> directories,
            Dictionary<string, SourceFileLease> files)
        {
            _root = root;
            _rootHandle = rootHandle;
            _rootIdentity = rootIdentity;
            _directories = directories;
            _files = files;
        }

        public IReadOnlyList<SourceFileLease> Files =>
            _files.Values.OrderBy(file => file.RelativePath, StringComparer.Ordinal).ToArray();

        public bool Contains(string relativePath) => _files.ContainsKey(relativePath);
        public SourceFileLease Get(string relativePath) => _files[relativePath];

        public bool RefersToSameSnapshot(SourceMediaLease other)
        {
            ArgumentNullException.ThrowIfNull(other);
            if (!_rootIdentity.RefersToSameFile(other._rootIdentity) ||
                _directories.Count != other._directories.Count ||
                _files.Count != other._files.Count)
            {
                return false;
            }

            var otherDirectories = other._directories.ToDictionary(
                directory => directory.RelativePath,
                StringComparer.Ordinal);
            foreach (var directory in _directories)
            {
                if (!otherDirectories.TryGetValue(directory.RelativePath, out var current) ||
                    !directory.Identity.RefersToSameFile(current.Identity))
                {
                    return false;
                }
            }

            foreach (var file in _files.Values)
            {
                if (!other._files.TryGetValue(file.RelativePath, out var current) ||
                    file.Length != current.Length ||
                    !string.Equals(file.Sha256, current.Sha256, StringComparison.Ordinal) ||
                    !file.Identity.RefersToSameFile(current.Identity))
                {
                    return false;
                }
            }

            return true;
        }

        public static async Task<SourceMediaLease> CaptureAsync(string root, CancellationToken cancellationToken)
        {
            SafeFileHandle? rootHandle = null;
            var directories = new List<SourceDirectoryLease>();
            var files = new Dictionary<string, SourceFileLease>(StringComparer.Ordinal);
            try
            {
                rootHandle = WindowsNoFollowSecurity.OpenDirectoryHandle(root);
                var rootIdentity = ReadIdentity(rootHandle);
                foreach (var entry in EnumerateTree(root))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (entry.Directory)
                    {
                        var handle = WindowsNoFollowSecurity.OpenDirectoryHandle(entry.Path);
                        directories.Add(new SourceDirectoryLease(
                            entry.RelativePath, handle, ReadIdentity(handle)));
                        continue;
                    }

                    var fileHandle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(entry.Path);
                    if (ReadIdentity(fileHandle).LinkCount != 1)
                    {
                        fileHandle.Dispose();
                        throw new SetupException("install_media_link_invalid");
                    }

                    var stream = new FileStream(fileHandle, FileAccess.Read, 1024 * 64, isAsync: false);
                    var hash = Convert.ToHexString(
                            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
                        .ToLowerInvariant();
                    stream.Position = 0;
                    files.Add(entry.RelativePath, new SourceFileLease(
                        entry.RelativePath,
                        entry.Path,
                        stream.Length,
                        hash,
                        ReadIdentity(fileHandle),
                        stream));
                }

                return new SourceMediaLease(root, rootHandle, rootIdentity, directories, files);
            }
            catch
            {
                foreach (var file in files.Values) file.Dispose();
                foreach (var directory in directories) directory.Dispose();
                rootHandle?.Dispose();
                throw;
            }
        }

        public async Task VerifyUnchangedAsync(CancellationToken cancellationToken)
        {
            if (_disposed || !_rootIdentity.RefersToSameFile(ReadIdentity(_rootHandle)) ||
                !EnumerateFiles(_root).ToHashSet(StringComparer.Ordinal).SetEquals(_files.Keys) ||
                !EnumerateDirectories(_root).ToHashSet(StringComparer.Ordinal).SetEquals(
                    _directories.Select(directory => directory.RelativePath)))
            {
                throw new SetupException("install_media_source_changed");
            }

            foreach (var directory in _directories)
            {
                if (!directory.Identity.RefersToSameFile(ReadIdentity(directory.Handle)))
                {
                    throw new SetupException("install_media_source_changed");
                }
            }

            foreach (var file in _files.Values)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var identity = ReadIdentity(file.Stream.SafeFileHandle);
                if (!file.Identity.RefersToSameFile(identity) || identity.LinkCount != 1 ||
                    file.Stream.Length != file.Length)
                {
                    throw new SetupException("install_media_source_changed");
                }

                file.Stream.Position = 0;
                var hash = Convert.ToHexString(
                        await SHA256.HashDataAsync(file.Stream, cancellationToken).ConfigureAwait(false))
                    .ToLowerInvariant();
                file.Stream.Position = 0;
                if (!string.Equals(hash, file.Sha256, StringComparison.Ordinal))
                {
                    throw new SetupException("install_media_source_changed");
                }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var file in _files.Values) file.Dispose();
            foreach (var directory in _directories) directory.Dispose();
            _rootHandle.Dispose();
        }
    }

    private sealed record SourceDirectoryLease(
        string RelativePath,
        SafeFileHandle Handle,
        LocalFileIdentity Identity) : IDisposable
    {
        public void Dispose() => Handle.Dispose();
    }

    private sealed record SourceFileLease(
        string RelativePath,
        string Path,
        long Length,
        string Sha256,
        LocalFileIdentity Identity,
        FileStream Stream) : IDisposable
    {
        public void Dispose() => Stream.Dispose();
    }
}

internal sealed class WindowsInstallMediaVerifier : IInstallMediaVerifier
{
    private static readonly TimeSpan VerificationTimeout = TimeSpan.FromMinutes(2);
    private const string VerifyCatalogThenRunScriptCommand =
        "$ErrorActionPreference='Stop';try{" +
        "$catalog=Test-FileCatalog -Detailed -Path $env:SSA_MEDIA_ROOT " +
        "-CatalogFilePath $env:SSA_MEDIA_CATALOG " +
        "-FilesToSkip @('release-files.cat','SimplySignAuto.exe') -ErrorAction Stop;" +
        "if([string]$catalog.Status-cne'Valid'){exit 1};" +
        "& $env:SSA_MEDIA_SCRIPT -ReleaseMediaRoot $env:SSA_MEDIA_ROOT -VerifyMediaOnly;" +
        "exit $LASTEXITCODE}catch{exit 1}";
    private readonly IAuthenticodeSignatureReader _signatureReader;

    public WindowsInstallMediaVerifier()
        : this(new WindowsAuthenticodeSignatureReader())
    {
    }

    internal WindowsInstallMediaVerifier(IAuthenticodeSignatureReader signatureReader) =>
        _signatureReader = signatureReader ?? throw new ArgumentNullException(nameof(signatureReader));

    public string VerifyInitialPublisher(string executablePath, string scriptPath)
    {
        try
        {
            var canonicalExecutable = Path.GetFullPath(executablePath);
            var canonicalScript = Path.GetFullPath(scriptPath);
            var mediaRoot = Path.GetDirectoryName(canonicalScript)
                ?? throw new SetupException("install_media_signature_invalid");
            if (!string.Equals(
                    Path.GetDirectoryName(canonicalExecutable),
                    mediaRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new SetupException("install_media_signature_invalid");
            }

            var catalogPath = Path.Combine(mediaRoot, "release-files.cat");
            var executableSigners = _signatureReader.ReadSignerThumbprints(canonicalExecutable);
            var catalogSigners = _signatureReader.ReadSignerThumbprints(catalogPath);
            if (executableSigners.Count != 1 || catalogSigners.Count != 1)
            {
                throw new SetupException("install_media_signature_invalid");
            }

            var executablePublisher = NormalizeThumbprint(executableSigners[0]);
            var catalogPublisher = NormalizeThumbprint(catalogSigners[0]);
            if (!string.Equals(executablePublisher, catalogPublisher, StringComparison.Ordinal))
            {
                throw new SetupException("install_media_publisher_mismatch");
            }

            return executablePublisher;
        }
        catch (SetupException)
        {
            throw;
        }
        catch
        {
            throw new SetupException("install_media_signature_invalid");
        }
    }

    private static string NormalizeThumbprint(string value)
    {
        if (value.Length != 40 || value.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new SetupException("install_media_signature_invalid");
        }

        return value.ToUpperInvariant();
    }

    public async Task VerifyMediaAsync(
        string root,
        string expectedPublisherIdentity,
        CancellationToken cancellationToken)
    {
        var mediaRoot = Path.GetFullPath(root);
        var scriptPath = Path.Combine(mediaRoot, InstallMediaPaths.VerificationScriptFileName);
        var catalogPath = Path.Combine(mediaRoot, "release-files.cat");
        if (!string.Equals(
                VerifyInitialPublisher(
                    Path.Combine(mediaRoot, InstallMediaPaths.ExecutableFileName),
                    scriptPath),
                expectedPublisherIdentity,
                StringComparison.Ordinal))
        {
            throw new SetupException("install_media_publisher_mismatch");
        }

        var start = new ProcessStartInfo
        {
            FileName = GetSystemPowerShell(),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in new[]
                 {
                     "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-Command", VerifyCatalogThenRunScriptCommand,
                 })
        {
            start.ArgumentList.Add(argument);
        }
        start.Environment["SSA_MEDIA_ROOT"] = mediaRoot;
        start.Environment["SSA_MEDIA_CATALOG"] = catalogPath;
        start.Environment["SSA_MEDIA_SCRIPT"] = scriptPath;

        using var process = Process.Start(start)
            ?? throw new SetupException("install_media_verification_failed");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(VerificationTimeout);
        try
        {
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            _ = await stdout.ConfigureAwait(false);
            _ = await stderr.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new SetupException("install_media_verification_timeout");
        }

        if (process.ExitCode != 0)
        {
            throw new SetupException("install_media_verification_failed");
        }
    }

    private static string GetSystemPowerShell()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system = Environment.Is64BitProcess ? Environment.SystemDirectory : Path.Combine(windows, "Sysnative");
        var path = Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(path) && !Environment.Is64BitProcess)
        {
            path = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        }

        return File.Exists(path) ? path : throw new SetupException("powershell_missing");
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
        }
        catch
        {
            // The stable timeout result takes precedence over best-effort process cleanup.
        }
    }
}
