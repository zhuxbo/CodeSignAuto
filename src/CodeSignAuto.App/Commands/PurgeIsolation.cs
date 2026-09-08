using System.Security.Cryptography;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.App.Commands;

internal sealed record PurgeIsolationTarget(string SourcePath, string StagedPath);

internal sealed record PurgeIsolationGroup(
    string VolumeRoot,
    string StagingRoot,
    IReadOnlyList<PurgeIsolationTarget> Targets);

internal sealed record PurgeIsolationSource(
    string Label,
    string SourcePath,
    string VolumeRoot);

internal static class PurgeIsolationSourcePolicy
{
    public static IReadOnlyList<PurgeIsolationSource> Create(
        string dataRoot,
        string? agentDirectory,
        string executablePath)
    {
        var executable = Canonical(executablePath);
        var programFilesRoot = Path.GetDirectoryName(executable)
            ?? throw new InstallException("uninstall_path_invalid");
        var sources = new List<PurgeIsolationSource>
        {
            CreateSource("program-data", dataRoot),
        };
        if (agentDirectory is not null)
        {
            sources.Add(CreateSource("agent-data", agentDirectory));
        }

        sources.Add(CreateSource("program-files", programFilesRoot));
        if (sources.Select(source => source.SourcePath).Distinct(PathComparer()).Count() != sources.Count)
        {
            throw new InstallException("uninstall_path_invalid");
        }

        return sources;
    }

    private static PurgeIsolationSource CreateSource(string label, string path)
    {
        var canonical = Canonical(path);
        var volume = Path.GetPathRoot(canonical)
            ?? throw new InstallException("uninstall_path_invalid");
        if (string.Equals(canonical, Path.TrimEndingDirectorySeparator(volume), PathComparison()))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        return new PurgeIsolationSource(label, canonical, volume);
    }

    private static string Canonical(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        var canonical = Path.GetFullPath(path);
        if (!string.Equals(path, canonical, PathComparison()))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        return canonical;
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static StringComparer PathComparer() =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}

internal sealed record PurgeInstallIdentity(
    string InstallOwnerMarker,
    string SigningUserSid,
    string InstallInstanceId,
    UninstallSigningUserOwnership SigningUserOwnership,
    string ExecutablePath);

internal static class PurgeIsolationGrouping
{
    public static IReadOnlyList<PurgeIsolationGroup> Create(
        string operationId,
        IReadOnlyList<PurgeIsolationSource> sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        if (operationId.Length != 32 ||
            operationId.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        var groups = new List<PurgeIsolationGroup>();
        foreach (var volumeGroup in sources.GroupBy(source => source.VolumeRoot, PathComparer()))
        {
            var index = groups.Count;
            var stagingRoot = Path.Combine(
                volumeGroup.Key,
                $".CodeSignAuto.quarantine.{operationId}.{index}");
            var targets = volumeGroup.Select(source =>
            {
                if (string.IsNullOrWhiteSpace(source.Label) ||
                    source.Label.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0)
                {
                    throw new InstallException("uninstall_path_invalid");
                }

                return new PurgeIsolationTarget(
                    source.SourcePath,
                    Path.Combine(stagingRoot, source.Label));
            }).ToArray();
            groups.Add(new PurgeIsolationGroup(volumeGroup.Key, stagingRoot, targets));
        }

        return groups;
    }

    private static StringComparer PathComparer() =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}

internal sealed record PurgeIsolationPlan(
    string OperationId,
    string ManifestPath,
    string CleanupTaskName,
    string ExecutablePath,
    IReadOnlyList<PurgeIsolationGroup> Groups,
    PurgeInstallIdentity? InstallIdentity = null,
    string? ExecutableSha256 = null);

internal interface IPurgeIsolationFileSystem
{
    PurgeIsolationPlan Plan(
        string dataRoot,
        string? agentDirectory,
        PurgeInstallIdentity installIdentity);

    void CreateProtectedOperationRoot(string path);

    Task WriteDurableManifestAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken);

    void CreateProtectedStaging(string path);

    void MoveToStaging(PurgeIsolationTarget target);

    void RollbackMove(PurgeIsolationTarget target);

    Task ScheduleDeferredCleanupAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken);

    Task RollbackDeferredCleanupAsync(PurgeIsolationPlan plan);

    void RemoveDurableManifest(PurgeIsolationPlan plan);

    void RemoveEmptyStaging(string path);

    void RemoveEmptyOperationRoot(string path);
}

internal sealed class PurgeIsolationCoordinator(IPurgeIsolationFileSystem fileSystem)
{
    public async Task ExecuteAsync(
        PurgeControlledData action,
        PurgeInstallIdentity installIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        var plan = fileSystem.Plan(
            action.DataRoot,
            action.IncludeAgentDirectory ? action.AgentDirectory : null,
            installIdentity);
        await ExecuteAsync(plan, cancellationToken).ConfigureAwait(false);
    }

    public async Task ExecuteAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var operationRoot = Path.GetDirectoryName(plan.ManifestPath)
            ?? throw new InstallException("uninstall_path_invalid");
        var operationRootCreated = false;
        var attemptedStaging = new List<string>();
        var moved = new List<PurgeIsolationTarget>();
        var cleanupAttempted = false;
        try
        {
            fileSystem.CreateProtectedOperationRoot(operationRoot);
            operationRootCreated = true;
            cleanupAttempted = true;
            await fileSystem
                .WriteDurableManifestAsync(plan, cancellationToken)
                .ConfigureAwait(false);
            foreach (var group in plan.Groups)
            {
                cancellationToken.ThrowIfCancellationRequested();
                fileSystem.CreateProtectedStaging(group.StagingRoot);
                attemptedStaging.Add(group.StagingRoot);
                foreach (var target in group.Targets)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fileSystem.MoveToStaging(target);
                    moved.Add(target);
                }
            }

            await fileSystem
                .ScheduleDeferredCleanupAsync(plan, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error)
        {
            var cleanupTaskRollbackFailed = false;
            var dataRollbackFailed = false;
            if (cleanupAttempted)
            {
                try
                {
                    await fileSystem.RollbackDeferredCleanupAsync(plan).ConfigureAwait(false);
                }
                catch
                {
                    cleanupTaskRollbackFailed = true;
                }
            }

            foreach (var target in moved.AsEnumerable().Reverse())
            {
                try
                {
                    fileSystem.RollbackMove(target);
                }
                catch
                {
                    dataRollbackFailed = true;
                }
            }

            foreach (var stagingRoot in attemptedStaging.AsEnumerable().Reverse())
            {
                try
                {
                    fileSystem.RemoveEmptyStaging(stagingRoot);
                }
                catch
                {
                    dataRollbackFailed = true;
                }
            }

            if (!dataRollbackFailed && cleanupAttempted)
            {
                try
                {
                    fileSystem.RemoveDurableManifest(plan);
                }
                catch
                {
                    dataRollbackFailed = true;
                }
            }

            if (!dataRollbackFailed && operationRootCreated)
            {
                try
                {
                    fileSystem.RemoveEmptyOperationRoot(operationRoot);
                }
                catch
                {
                    dataRollbackFailed = true;
                }
            }

            if (cleanupTaskRollbackFailed || dataRollbackFailed)
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            if (error is InstallException { Code: "uninstall_state_uncertain" })
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            if (error is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new InstallException("uninstall_isolation_failed");
        }
    }
}

internal sealed record PurgeResumeCandidate(string Path, bool IsReparse);

internal static class PurgeResumeDiscovery
{
    private const string Prefix = "CodeSignAuto.Purge.";

    public static string? SelectUnique(
        string programDataRoot,
        IReadOnlyList<PurgeResumeCandidate> candidates)
    {
        try
        {
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(programDataRoot));
            var exact = candidates.Where(candidate =>
            {
                var path = Path.GetFullPath(candidate.Path);
                var name = Path.GetFileName(path);
                return string.Equals(Path.GetDirectoryName(path), root, PathComparison()) &&
                    name.StartsWith(Prefix, StringComparison.Ordinal) &&
                    IsLowerGuidN(name[Prefix.Length..]);
            }).ToArray();
            if (exact.Any(candidate => candidate.IsReparse) || exact.Length > 1)
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            return exact.SingleOrDefault()?.Path;
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private static bool IsLowerGuidN(string value) =>
        value.Length == 32 &&
        Guid.TryParseExact(value, "N", out _) &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

internal static class PurgeResumeManifestValidator
{
    public static PurgeIsolationPlan Validate(
        string operationRoot,
        string programDataRoot,
        string executablePath,
        string executableSha256,
        DisabledOwnedAutoLogon disabledAutoLogon,
        UninstallSigningUserOwnership verifiedOwnership,
        PurgeQuarantineManifest manifest)
    {
        try
        {
            var canonicalProgramDataRoot = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(programDataRoot));
            var dataRoot = Path.Combine(canonicalProgramDataRoot, "CodeSignAuto");
            var agentRoot = Path.GetFullPath(Path.Combine(
                disabledAutoLogon.ProfilePath,
                "AppData",
                "Local",
                "CodeSignAuto"));
            var allowedSources = new HashSet<string>(PathComparer())
            {
                dataRoot,
            };
            allowedSources.Add(verifiedOwnership == UninstallSigningUserOwnership.ExistingUser
                ? agentRoot
                : Path.GetFullPath(disabledAutoLogon.ProfilePath));
            return ValidateCore(
                operationRoot,
                canonicalProgramDataRoot,
                executablePath,
                executableSha256,
                disabledAutoLogon.OwnerMarker,
                disabledAutoLogon.SigningUserSid,
                verifiedOwnership,
                dataRoot,
                allowedSources,
                manifest);
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    public static PurgeIsolationPlan ValidateManual(
        string operationRoot,
        string programDataRoot,
        string executablePath,
        string executableSha256,
        string profilePath,
        PurgeQuarantineManifest manifest)
    {
        try
        {
            var canonicalProgramDataRoot = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(programDataRoot));
            var dataRoot = Path.GetFullPath(Path.Combine(canonicalProgramDataRoot, "CodeSignAuto"));
            var manualRoot = Path.GetFullPath(Path.Combine(
                profilePath,
                "AppData",
                "Local",
                "CodeSignAuto",
                "manual"));
            return ValidateCore(
                operationRoot,
                canonicalProgramDataRoot,
                executablePath,
                executableSha256,
                manifest.InstallOwnerMarker,
                manifest.SigningUserSid,
                UninstallSigningUserOwnership.ExistingUser,
                dataRoot,
                new HashSet<string>(PathComparer()) { dataRoot, manualRoot },
                manifest);
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private static PurgeIsolationPlan ValidateCore(
        string operationRoot,
        string programDataRoot,
        string executablePath,
        string executableSha256,
        string expectedOwnerMarker,
        string expectedSigningUserSid,
        UninstallSigningUserOwnership expectedOwnership,
        string dataRoot,
        HashSet<string> allowedSources,
        PurgeQuarantineManifest manifest)
    {
        manifest = PurgeQuarantineManifestCodec.Validate(manifest);
        operationRoot = Path.GetFullPath(operationRoot);
        programDataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(programDataRoot));
        executablePath = Path.GetFullPath(executablePath);
        var manifestPath = Path.Combine(operationRoot, "manifest.json");
        if (!string.Equals(Path.GetDirectoryName(operationRoot), programDataRoot, PathComparison()) ||
            !string.Equals(
                Path.GetFileName(operationRoot),
                $"CodeSignAuto.Purge.{manifest.OperationId}",
                StringComparison.Ordinal) ||
            !string.Equals(manifest.InstallOwnerMarker, expectedOwnerMarker, StringComparison.Ordinal) ||
            !string.Equals(manifest.SigningUserSid, expectedSigningUserSid, StringComparison.Ordinal) ||
            manifest.SigningUserOwnership != expectedOwnership ||
            !string.Equals(manifest.ExecutablePath, executablePath, PathComparison()) ||
            !string.Equals(manifest.ExecutableSha256, executableSha256, StringComparison.Ordinal) ||
            !manifest.Targets.Any(target => string.Equals(target.SourcePath, dataRoot, PathComparison())) ||
            manifest.Targets.Any(target => !allowedSources.Contains(target.SourcePath)))
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        var groups = manifest.StagingRoots.Select(stagingRoot =>
            new PurgeIsolationGroup(
                Path.GetPathRoot(stagingRoot)!,
                stagingRoot,
                manifest.Targets
                    .Where(target => string.Equals(
                        Path.GetDirectoryName(target.StagedPath),
                        stagingRoot,
                        PathComparison()))
                    .Select(target => new PurgeIsolationTarget(target.SourcePath, target.StagedPath))
                    .ToArray()))
            .ToArray();
        return new PurgeIsolationPlan(
            manifest.OperationId,
            manifestPath,
            manifest.CleanupTaskName,
            executablePath,
            groups,
            new PurgeInstallIdentity(
                manifest.InstallOwnerMarker,
                manifest.SigningUserSid,
                manifest.InstallInstanceId,
                manifest.SigningUserOwnership,
                executablePath));
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static StringComparer PathComparer() =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}

internal enum PurgeResumeTargetPresence
{
    SourceOnly,
    StagedOnly,
    Both,
    Neither,
}

internal interface IPurgeResumeRuntime
{
    PurgeResumeTargetPresence Inspect(PurgeIsolationTarget target);

    bool StagingRootExists(string path);

    void VerifyProtectedStaging(string path);

    void CreateProtectedStaging(string path);

    void MoveToStaging(PurgeIsolationTarget target);

    bool CleanupTaskExists(PurgeIsolationPlan plan);

    Task VerifyCleanupTaskAsync(PurgeIsolationPlan plan, CancellationToken cancellationToken);

    Task ScheduleCleanupTaskAsync(PurgeIsolationPlan plan, CancellationToken cancellationToken);
}

internal sealed class PurgeResumeCoordinator(IPurgeResumeRuntime runtime)
{
    public async Task ResumeAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(plan);
            cancellationToken.ThrowIfCancellationRequested();
            var targets = plan.Groups
                .SelectMany(group => group.Targets)
                .Select(target => (Target: target, Presence: runtime.Inspect(target)))
                .ToArray();
            var cleanupTaskExists = runtime.CleanupTaskExists(plan);
            if (cleanupTaskExists)
            {
                await runtime.VerifyCleanupTaskAsync(plan, cancellationToken).ConfigureAwait(false);
            }

            if (targets.Any(item => item.Presence == PurgeResumeTargetPresence.Both) ||
                (!cleanupTaskExists && targets.Any(item => item.Presence == PurgeResumeTargetPresence.Neither)))
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            foreach (var group in plan.Groups)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var active = targets
                    .Where(item => group.Targets.Contains(item.Target) &&
                        item.Presence != PurgeResumeTargetPresence.Neither)
                    .ToArray();
                if (active.Length == 0)
                {
                    continue;
                }

                if (runtime.StagingRootExists(group.StagingRoot))
                {
                    runtime.VerifyProtectedStaging(group.StagingRoot);
                }
                else
                {
                    if (active.Any(item => item.Presence == PurgeResumeTargetPresence.StagedOnly))
                    {
                        throw new InstallException("uninstall_state_uncertain");
                    }

                    runtime.CreateProtectedStaging(group.StagingRoot);
                }

                foreach (var item in active.Where(item =>
                    item.Presence == PurgeResumeTargetPresence.SourceOnly))
                {
                    runtime.MoveToStaging(item.Target);
                }
            }

            if (!cleanupTaskExists)
            {
                await runtime.ScheduleCleanupTaskAsync(plan, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException error) when (error.Code == "uninstall_state_uncertain")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }
}

internal sealed class WindowsPurgeIsolationFileSystem : IPurgeIsolationFileSystem
{
    private readonly WindowsPurgeDeferredCleanup _cleanup = new();
    private readonly AtomicProtectedDirectoryCreator _protectedDirectoryCreator = new(
        new WindowsAtomicProtectedDirectoryOperations());

    public PurgeIsolationPlan Plan(
        string dataRoot,
        string? agentDirectory,
        PurgeInstallIdentity installIdentity)
    {
        EnsureWindows();
        ArgumentNullException.ThrowIfNull(installIdentity);
        var executablePath = Environment.ProcessPath is null
            ? throw new InstallException("uninstall_configuration_invalid")
            : Path.GetFullPath(Environment.ProcessPath);
        if (!string.Equals(
                installIdentity.ExecutablePath,
                executablePath,
                StringComparison.OrdinalIgnoreCase) ||
            !CanonicalWindowsSid.IsValid(installIdentity.SigningUserSid) ||
            !Enum.IsDefined(installIdentity.SigningUserOwnership) ||
            !CodeSignAuto.Service.InstallOwnershipMarker.IsExact(
                installIdentity.InstallOwnerMarker,
                installIdentity.InstallInstanceId))
        {
            throw new InstallException("uninstall_configuration_invalid");
        }

        var operationId = Guid.NewGuid().ToString("N");
        var controlledRoots = PurgeIsolationSourcePolicy.Create(
            dataRoot,
            agentDirectory,
            installIdentity.ExecutablePath);
        var existing = new List<PurgeIsolationSource>();
        PurgeIsolationSource? programFiles = null;
        foreach (var controlled in controlledRoots)
        {
            if (!WindowsPathSafety.EntryExists(controlled.SourcePath))
            {
                if (string.Equals(controlled.Label, "agent-data", StringComparison.Ordinal))
                {
                    continue;
                }

                throw new InstallException("uninstall_path_invalid");
            }

            if (!Directory.Exists(controlled.SourcePath) ||
                WindowsPathSafety.IsReparse(controlled.SourcePath))
            {
                throw new InstallException("uninstall_path_invalid");
            }

            EnsureExistingDirectoryWithoutReparseAncestors(controlled.SourcePath);
            EnsureExistingDirectoryWithoutReparseAncestors(controlled.VolumeRoot);
            if (string.Equals(controlled.Label, "program-files", StringComparison.Ordinal))
            {
                programFiles = controlled;
            }
            else
            {
                existing.Add(controlled);
            }
        }

        if (programFiles is null ||
            !string.Equals(
                programFiles.SourcePath,
                Path.GetDirectoryName(executablePath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        var groups = PurgeIsolationGrouping.Create(operationId, existing);
        if (groups.Count == 0)
        {
            throw new InstallException("uninstall_path_invalid");
        }

        if (groups.Any(group => WindowsPathSafety.EntryExists(group.StagingRoot)))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        var operationRoot = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            $"CodeSignAuto.Purge.{operationId}"));
        if (WindowsPathSafety.EntryExists(operationRoot))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        var executableSha256 = Convert.ToHexString(
            SHA256.HashData(File.ReadAllBytes(executablePath))).ToLowerInvariant();
        return new PurgeIsolationPlan(
            operationId,
            Path.Combine(operationRoot, "manifest.json"),
            $"CodeSignAuto.Purge.{operationId}",
            executablePath,
            groups,
            installIdentity,
            executableSha256);
    }

    public void CreateProtectedOperationRoot(string path)
    {
        var anchor = Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        _protectedDirectoryCreator.Create(anchor, path);
    }

    public Task WriteDurableManifestAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken) =>
        _cleanup.WriteManifestAsync(plan, cancellationToken);

    public void CreateProtectedStaging(string path)
    {
        var anchor = Path.GetPathRoot(path) ?? throw new InstallException("uninstall_path_invalid");
        _protectedDirectoryCreator.Create(anchor, path);
    }

    public void MoveToStaging(PurgeIsolationTarget target)
    {
        if (WindowsPathSafety.EntryExists(target.StagedPath))
        {
            throw new InstallException("uninstall_isolation_failed");
        }

        Directory.Move(target.SourcePath, target.StagedPath);
    }

    public void RollbackMove(PurgeIsolationTarget target)
    {
        if (WindowsPathSafety.EntryExists(target.SourcePath) ||
            !WindowsPathSafety.EntryExists(target.StagedPath))
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        Directory.Move(target.StagedPath, target.SourcePath);
    }

    public Task ScheduleDeferredCleanupAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken) =>
        _cleanup.ScheduleAsync(plan, cancellationToken);

    public Task RollbackDeferredCleanupAsync(PurgeIsolationPlan plan) =>
        _cleanup.RollbackTaskAsync(plan);

    public void RemoveDurableManifest(PurgeIsolationPlan plan) =>
        _cleanup.RemoveManifest(plan);

    public void RemoveEmptyStaging(string path)
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
            throw new InstallException("uninstall_state_uncertain");
        }

        Directory.Delete(path, recursive: false);
    }

    public void RemoveEmptyOperationRoot(string path) => RemoveEmptyStaging(path);

    internal static void EnsureExistingDirectoryWithoutReparseAncestors(string path)
    {
        var current = new DirectoryInfo(path);
        while (current is not null)
        {
            if (!current.Exists || WindowsPathSafety.IsReparse(current.FullName))
            {
                throw new InstallException("uninstall_path_invalid");
            }

            current = current.Parent;
        }
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }
    }
}

internal sealed class WindowsPurgeResumeRuntime : IPurgeResumeRuntime
{
    private readonly WindowsPurgeIsolationFileSystem _fileSystem = new();
    private readonly WindowsPurgeDeferredCleanup _cleanup = new();
    private readonly IWindowsCommandRunner _runner = new DefaultWindowsCommandRunner();

    public PurgeResumeTargetPresence Inspect(PurgeIsolationTarget target)
    {
        var source = IsValidDirectoryOrMissing(target.SourcePath);
        var staged = IsValidDirectoryOrMissing(target.StagedPath);
        return (source, staged) switch
        {
            (true, false) => PurgeResumeTargetPresence.SourceOnly,
            (false, true) => PurgeResumeTargetPresence.StagedOnly,
            (true, true) => PurgeResumeTargetPresence.Both,
            _ => PurgeResumeTargetPresence.Neither,
        };
    }

    public bool StagingRootExists(string path) => WindowsPathSafety.EntryExists(path);

    public void VerifyProtectedStaging(string path)
    {
        if (!Directory.Exists(path) || WindowsPathSafety.IsReparse(path))
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.ReadDirectory(path),
            directory: true);
    }

    public void CreateProtectedStaging(string path) => _fileSystem.CreateProtectedStaging(path);

    public void MoveToStaging(PurgeIsolationTarget target) => _fileSystem.MoveToStaging(target);

    public bool CleanupTaskExists(PurgeIsolationPlan plan) =>
        WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName);

    public Task VerifyCleanupTaskAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken) =>
        WindowsPurgeCleanupTask.VerifyAsync(plan, _runner, cancellationToken);

    public Task ScheduleCleanupTaskAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken) =>
        _cleanup.ScheduleAsync(plan, cancellationToken);

    private static bool IsValidDirectoryOrMissing(string path)
    {
        if (!WindowsPathSafety.EntryExists(path))
        {
            return false;
        }

        if (!Directory.Exists(path) || WindowsPathSafety.IsReparse(path))
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        WindowsPurgeIsolationFileSystem.EnsureExistingDirectoryWithoutReparseAncestors(path);

        return true;
    }
}

internal sealed class WindowsInterruptedPurgeResume
{
    public async Task<bool> TryResumeAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        try
        {
            var programDataRoot = Path.GetFullPath(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            var candidates = Directory
                .EnumerateDirectories(programDataRoot, "CodeSignAuto.Purge.*", SearchOption.TopDirectoryOnly)
                .Select(path => new PurgeResumeCandidate(path, WindowsPathSafety.IsReparse(path)))
                .ToArray();
            var operationRoot = PurgeResumeDiscovery.SelectUnique(programDataRoot, candidates);
            if (operationRoot is null)
            {
                return false;
            }

            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadDirectory(operationRoot),
                directory: true);
            var manifestPath = Path.Combine(operationRoot, "manifest.json");
            if (!File.Exists(manifestPath) || WindowsPathSafety.IsReparse(manifestPath))
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadFile(manifestPath),
                directory: false);
            var manifest = PurgeQuarantineManifestCodec.Deserialize(
                await File.ReadAllTextAsync(manifestPath, cancellationToken).ConfigureAwait(false));
            var executablePath = Environment.ProcessPath is null
                ? throw new InstallException("uninstall_state_uncertain")
                : Path.GetFullPath(Environment.ProcessPath);
            var executableSha256 = await HashFileAsync(executablePath, cancellationToken)
                .ConfigureAwait(false);
            var disabledAutoLogon = WindowsAutoLogonPlatform.ReadDisabledAutoLogon(
                manifest.InstallOwnerMarker);
            PurgeIsolationPlan plan;
            if (disabledAutoLogon is not null)
            {
                var verifiedOwnership = WindowsUninstallIdentity.InspectInterruptedOwnership(
                    disabledAutoLogon);
                plan = PurgeResumeManifestValidator.Validate(
                    operationRoot,
                    programDataRoot,
                    executablePath,
                    executableSha256,
                    disabledAutoLogon,
                    verifiedOwnership,
                    manifest);
            }
            else if (manifest.SigningUserOwnership == UninstallSigningUserOwnership.ExistingUser)
            {
                using var profileKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{manifest.SigningUserSid}",
                    writable: false);
                var profilePath = profileKey?.GetValue(
                    "ProfileImagePath",
                    null,
                    Microsoft.Win32.RegistryValueOptions.None) as string;
                if (string.IsNullOrWhiteSpace(profilePath) || !Path.IsPathFullyQualified(profilePath))
                {
                    throw new InstallException("uninstall_state_uncertain");
                }

                plan = PurgeResumeManifestValidator.ValidateManual(
                    operationRoot,
                    programDataRoot,
                    executablePath,
                    executableSha256,
                    Path.GetFullPath(profilePath),
                    manifest);
            }
            else
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            await new PurgeResumeCoordinator(new WindowsPurgeResumeRuntime())
                .ResumeAsync(plan, cancellationToken)
                .ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException error) when (error.Code == "windows_required")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
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
}
