using System.Security.Cryptography;
using System.Security.Principal;

namespace SimplySignAuto.App.Commands;

internal static class PurgeQuarantineCommand
{
    public static async Task<int> ExecuteAsync(
        string[] args,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(error);
        try
        {
            if (args is not ["--manifest", var manifestPath])
            {
                throw new InstallException("purge_cleanup_arguments_invalid");
            }

            await WindowsPurgeQuarantineCleaner
                .ExecuteAsync(manifestPath, cancellationToken)
                .ConfigureAwait(false);
            return 0;
        }
        catch (InstallException cleanupError)
        {
            await error.WriteLineAsync(cleanupError.Code).ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 1;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException or SystemException)
        {
            await error.WriteLineAsync("purge_cleanup_failed").ConfigureAwait(false);
            return 1;
        }
    }
}

internal static class WindowsPurgeQuarantineCleaner
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    public static async Task ExecuteAsync(
        string manifestPath,
        CancellationToken cancellationToken)
    {
        EnsureLocalSystem();
        manifestPath = ValidateManifestPath(manifestPath, out var operationId);
        var taskName = $"SimplySignAuto.Purge.{operationId}";
        var executablePath = Environment.ProcessPath is null
            ? throw new InstallException("purge_cleanup_identity_invalid")
            : Path.GetFullPath(Environment.ProcessPath);
        if (!File.Exists(manifestPath))
        {
            await DeleteOwnedCleanupTaskAsync(
                new PurgeIsolationPlan(
                    operationId,
                    manifestPath,
                    taskName,
                    executablePath,
                    []),
                cancellationToken).ConfigureAwait(false);
            DeleteEmptyOperationRoot(Path.GetDirectoryName(manifestPath)!);
            return;
        }

        if (WindowsPathSafety.IsReparse(manifestPath))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.ReadFile(manifestPath),
            directory: false);
        var manifest = PurgeQuarantineManifestCodec.Deserialize(
            await File.ReadAllTextAsync(manifestPath, cancellationToken).ConfigureAwait(false));
        if (!string.Equals(manifest.OperationId, operationId, StringComparison.Ordinal) ||
            !string.Equals(manifest.CleanupTaskName, taskName, StringComparison.Ordinal) ||
            !string.Equals(manifest.ExecutablePath, executablePath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                manifest.ExecutableSha256,
                await HashFileAsync(executablePath, cancellationToken).ConfigureAwait(false),
                StringComparison.Ordinal))
        {
            throw new InstallException("purge_cleanup_identity_invalid");
        }

        var plan = new PurgeIsolationPlan(
            operationId,
            manifestPath,
            taskName,
            executablePath,
            manifest.StagingRoots.Select(path => new PurgeIsolationGroup(
                Path.GetPathRoot(path)!,
                path,
                manifest.Targets
                    .Where(target => string.Equals(
                        Path.GetDirectoryName(target.StagedPath),
                        path,
                        StringComparison.OrdinalIgnoreCase))
                    .Select(target => new PurgeIsolationTarget(
                        target.SourcePath,
                        target.StagedPath))
                    .ToArray())).ToArray());
        await WindowsPurgeCleanupTask.VerifyAsync(
            plan,
            new DefaultWindowsCommandRunner(),
            cancellationToken).ConfigureAwait(false);

        foreach (var stagingRoot in manifest.StagingRoots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DeleteQuarantinedTree(stagingRoot);
        }

        DeleteRunningInstallTree(executablePath, manifest.SigningUserSid);

        FinalizeAutoLogon(
            manifest,
            (owner, sid, install) => WindowsAutoLogonPlatform.FinalizeDisabledAutoLogon(
                sid,
                owner,
                install));
        File.Delete(manifestPath);
        await DeleteOwnedCleanupTaskAsync(plan, cancellationToken).ConfigureAwait(false);
        var manifestDirectory = Path.GetDirectoryName(manifestPath)!;
        if (WindowsNoFollowSecurity.DirectoryEntryExists(manifestDirectory))
        {
            DeleteEmptyOperationRoot(manifestDirectory);
        }
    }

    internal static void FinalizeAutoLogon(
        PurgeQuarantineManifest manifest,
        Action<string, string, string> finalizer)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(finalizer);
        finalizer(
            manifest.InstallOwnerMarker,
            manifest.SigningUserSid,
            manifest.InstallInstanceId);
    }

    private static string ValidateManifestPath(string path, out string operationId)
    {
        if (!Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        var operationRootName = Path.GetFileName(Path.GetDirectoryName(path));
        const string prefix = "SimplySignAuto.Purge.";
        if (operationRootName is null ||
            !operationRootName.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        operationId = operationRootName[prefix.Length..];
        var expected = PurgeQuarantineManifestCodec.ExpectedManifestPath(operationId);
        if (!string.Equals(expected, path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        return expected;
    }

    private static void DeleteQuarantinedTree(string stagingRoot)
    {
        if (!WindowsPathSafety.EntryExists(stagingRoot))
        {
            return;
        }

        if (!Directory.Exists(stagingRoot) || WindowsPathSafety.IsReparse(stagingRoot))
        {
            throw new InstallException("purge_cleanup_path_invalid");
        }

        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.ReadDirectory(stagingRoot),
            directory: true);
        DeleteChildrenWithoutFollowingReparse(stagingRoot, retainedFile: null);
        Directory.Delete(stagingRoot, recursive: false);
    }

    private static void DeleteChildrenWithoutFollowingReparse(
        string directory,
        string? retainedFile)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            if (string.Equals(entry, retainedFile, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Directory.Delete(entry, recursive: false);
                }
                else
                {
                    File.Delete(entry);
                }

                continue;
            }

            if ((attributes & FileAttributes.Directory) != 0)
            {
                DeleteChildrenWithoutFollowingReparse(entry, retainedFile: null);
                Directory.Delete(entry, recursive: false);
            }
            else
            {
                File.Delete(entry);
            }
        }
    }

    private static void DeleteRunningInstallTree(string executablePath, string signingUserSid)
    {
        var expectedRoot = InstallMediaPaths.GetTargetRoot(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var programFilesRoot = Path.GetDirectoryName(executablePath);
        if (programFilesRoot is null ||
            !string.Equals(programFilesRoot, expectedRoot, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(executablePath),
                InstallMediaPaths.ExecutableFileName,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("purge_cleanup_path_invalid");
        }

        WindowsExecutableSecurity.VerifyEntry(
            WindowsNoFollowSecurity.ReadDirectory(programFilesRoot),
            signingUserSid,
            requireReadExecute: true);
        WindowsExecutableSecurity.VerifyEntry(
            WindowsNoFollowSecurity.ReadFile(executablePath),
            signingUserSid,
            requireReadExecute: true);
        DeleteChildrenWithoutFollowingReparse(programFilesRoot, executablePath);
        if (!Directory.EnumerateFileSystemEntries(programFilesRoot)
                .SequenceEqual([executablePath], StringComparer.OrdinalIgnoreCase))
        {
            throw new InstallException("purge_cleanup_path_invalid");
        }
    }

    private static async Task DeleteOwnedCleanupTaskAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken)
    {
        if (!WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName))
        {
            return;
        }

        var runner = new DefaultWindowsCommandRunner();
        await WindowsPurgeCleanupTask.VerifyAsync(plan, runner, cancellationToken).ConfigureAwait(false);
        await runner.RunCheckedAsync(
            "schtasks.exe",
            ["/Delete", "/TN", plan.CleanupTaskName, "/F"],
            "purge_cleanup_failed",
            cancellationToken).ConfigureAwait(false);
        if (WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName))
        {
            throw new InstallException("purge_cleanup_failed");
        }
    }

    private static void DeleteEmptyOperationRoot(string path)
    {
        if (!WindowsNoFollowSecurity.DirectoryEntryExists(path))
        {
            return;
        }

        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.ReadDirectory(path),
            directory: true);
        if (Directory.EnumerateFileSystemEntries(path).Any())
        {
            return;
        }

        Directory.Delete(path, recursive: false);
    }

    private static async Task<string> HashFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(
            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();
    }

    private static void EnsureLocalSystem()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is null || !LocalSystem.Equals(identity.User))
        {
            throw new InstallException("purge_cleanup_identity_invalid");
        }
    }
}
