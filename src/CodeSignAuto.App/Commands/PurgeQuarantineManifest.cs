using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Service;

namespace CodeSignAuto.App.Commands;

internal sealed record PurgeQuarantineTarget(
    string SourcePath,
    string StagedPath);

internal sealed record PurgeQuarantineManifest(
    int Version,
    string OwnerMarker,
    string OperationId,
    string CleanupTaskName,
    string InstallOwnerMarker,
    string SigningUserSid,
    string InstallInstanceId,
    [property: JsonRequired] UninstallSigningUserOwnership SigningUserOwnership,
    string ExecutablePath,
    string ExecutableSha256,
    IReadOnlyList<string> StagingRoots,
    IReadOnlyList<PurgeQuarantineTarget> Targets);

internal static class PurgeQuarantineManifestCodec
{
    public const string OwnerMarker = "CodeSignAuto/Purge/v1";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static PurgeQuarantineManifest Create(PurgeIsolationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var installIdentity = plan.InstallIdentity
            ?? throw new InstallException("purge_manifest_invalid");
        if (!string.Equals(
                plan.ManifestPath,
                ExpectedManifestPath(plan.OperationId),
                PathComparison()) ||
            plan.Groups.SelectMany(group => group.Targets).Any(target =>
                IsSameOrDescendant(target.SourcePath, plan.ManifestPath)))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        return Validate(new PurgeQuarantineManifest(
            Version: 1,
            OwnerMarker,
            plan.OperationId,
            plan.CleanupTaskName,
            installIdentity.InstallOwnerMarker,
            installIdentity.SigningUserSid,
            installIdentity.InstallInstanceId,
            installIdentity.SigningUserOwnership,
            plan.ExecutablePath,
            plan.ExecutableSha256 ??
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(plan.ExecutablePath))).ToLowerInvariant(),
            plan.Groups.Select(group => group.StagingRoot).ToArray(),
            plan.Groups
                .SelectMany(group => group.Targets)
                .Select(target => new PurgeQuarantineTarget(target.SourcePath, target.StagedPath))
                .ToArray()));
    }

    public static byte[] Serialize(PurgeQuarantineManifest manifest) =>
        JsonSerializer.SerializeToUtf8Bytes(Validate(manifest), SerializerOptions);

    public static PurgeQuarantineManifest Deserialize(string json)
    {
        try
        {
            StrictJson.RejectDuplicatePropertiesAndSecretShapes(json);
            return Validate(JsonSerializer.Deserialize<PurgeQuarantineManifest>(json, SerializerOptions)
                ?? throw new InstallException("purge_manifest_invalid"));
        }
        catch (JsonException)
        {
            throw new InstallException("purge_manifest_invalid");
        }
    }

    public static PurgeQuarantineManifest Validate(PurgeQuarantineManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.Version != 1 ||
            !string.Equals(manifest.OwnerMarker, OwnerMarker, StringComparison.Ordinal) ||
            !IsLowerGuidN(manifest.OperationId) ||
            !string.Equals(
                manifest.CleanupTaskName,
                $"CodeSignAuto.Purge.{manifest.OperationId}",
                StringComparison.Ordinal) ||
            !InstallOwnershipMarker.IsExact(
                manifest.InstallOwnerMarker,
                manifest.InstallInstanceId) ||
            !CanonicalWindowsSid.IsValid(manifest.SigningUserSid) ||
            !Enum.IsDefined(manifest.SigningUserOwnership) ||
            !Path.IsPathFullyQualified(manifest.ExecutablePath) ||
            !string.Equals(Path.GetFullPath(manifest.ExecutablePath), manifest.ExecutablePath, PathComparison()) ||
            !string.Equals(Path.GetFileName(manifest.ExecutablePath), "CodeSignAuto.exe", StringComparison.OrdinalIgnoreCase) ||
            !IsLowerSha256(manifest.ExecutableSha256) ||
            manifest.StagingRoots is not { Count: > 0 and <= 2 } ||
            manifest.Targets is not { Count: > 0 and <= 2 })
        {
            throw new InstallException("purge_manifest_invalid");
        }

        var seenVolumes = new HashSet<string>(PathComparer());
        for (var index = 0; index < manifest.StagingRoots.Count; index++)
        {
            var stagingRoot = manifest.StagingRoots[index];
            var volume = Path.GetPathRoot(stagingRoot);
            if (string.IsNullOrEmpty(volume) ||
                !Path.IsPathFullyQualified(stagingRoot) ||
                !string.Equals(Path.GetFullPath(stagingRoot), stagingRoot, PathComparison()) ||
                !string.Equals(Path.GetDirectoryName(stagingRoot), Path.TrimEndingDirectorySeparator(volume), PathComparison()) ||
                !string.Equals(
                    Path.GetFileName(stagingRoot),
                    $".CodeSignAuto.quarantine.{manifest.OperationId}.{index}",
                    StringComparison.Ordinal) ||
                !seenVolumes.Add(volume))
            {
                throw new InstallException("purge_manifest_invalid");
            }
        }

        var seenSources = new HashSet<string>(PathComparer());
        var seenStaged = new HashSet<string>(PathComparer());
        var usedStagingRoots = new HashSet<string>(PathComparer());
        foreach (var target in manifest.Targets)
        {
            var stagingRoot = manifest.StagingRoots.SingleOrDefault(root =>
                string.Equals(Path.GetDirectoryName(target.StagedPath), root, PathComparison()));
            if (!IsCanonicalPath(target.SourcePath) ||
                !IsCanonicalPath(target.StagedPath) ||
                stagingRoot is null ||
                !string.Equals(
                    Path.GetPathRoot(target.SourcePath),
                    Path.GetPathRoot(target.StagedPath),
                    PathComparison()) ||
                string.Equals(target.SourcePath, target.StagedPath, PathComparison()) ||
                IsSameOrDescendant(target.SourcePath, target.StagedPath) ||
                IsSameOrDescendant(target.StagedPath, target.SourcePath) ||
                !seenSources.Add(target.SourcePath) ||
                !seenStaged.Add(target.StagedPath))
            {
                throw new InstallException("purge_manifest_invalid");
            }

            usedStagingRoots.Add(stagingRoot);
        }

        if (usedStagingRoots.Count != manifest.StagingRoots.Count)
        {
            throw new InstallException("purge_manifest_invalid");
        }

        return manifest;
    }

    public static bool MatchesExpected(
        PurgeQuarantineManifest actual,
        PurgeQuarantineManifest expected) =>
        actual.Version == expected.Version &&
        string.Equals(actual.OwnerMarker, expected.OwnerMarker, StringComparison.Ordinal) &&
        string.Equals(actual.OperationId, expected.OperationId, StringComparison.Ordinal) &&
        string.Equals(actual.CleanupTaskName, expected.CleanupTaskName, StringComparison.Ordinal) &&
        string.Equals(actual.InstallOwnerMarker, expected.InstallOwnerMarker, StringComparison.Ordinal) &&
        string.Equals(actual.SigningUserSid, expected.SigningUserSid, StringComparison.Ordinal) &&
        string.Equals(actual.InstallInstanceId, expected.InstallInstanceId, StringComparison.Ordinal) &&
        actual.SigningUserOwnership == expected.SigningUserOwnership &&
        string.Equals(actual.ExecutablePath, expected.ExecutablePath, PathComparison()) &&
        string.Equals(actual.ExecutableSha256, expected.ExecutableSha256, StringComparison.Ordinal) &&
        actual.StagingRoots.SequenceEqual(expected.StagingRoots, PathComparer()) &&
        actual.Targets.SequenceEqual(expected.Targets, new PurgeTargetComparer());

    public static string ExpectedManifestPath(string operationId)
    {
        if (!IsLowerGuidN(operationId))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        return Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            $"CodeSignAuto.Purge.{operationId}",
            "manifest.json"));
    }

    private static bool IsLowerGuidN(string value) =>
        value.Length == 32 &&
        Guid.TryParseExact(value, "N", out _) &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsCanonicalPath(string path) =>
        Path.IsPathFullyQualified(path) &&
        string.Equals(Path.GetFullPath(path), path, PathComparison());

    private static bool IsSameOrDescendant(string root, string candidate)
    {
        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var normalizedCandidate = Path.GetFullPath(candidate);
        if (string.Equals(normalizedRoot, normalizedCandidate, PathComparison()))
        {
            return true;
        }

        return normalizedCandidate.Length > normalizedRoot.Length &&
            normalizedCandidate.StartsWith(normalizedRoot, PathComparison()) &&
            normalizedCandidate[normalizedRoot.Length] is '\\' or '/';
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static StringComparer PathComparer() =>
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private sealed class PurgeTargetComparer : IEqualityComparer<PurgeQuarantineTarget>
    {
        public bool Equals(PurgeQuarantineTarget? left, PurgeQuarantineTarget? right) =>
            left is not null &&
            right is not null &&
            string.Equals(left.SourcePath, right.SourcePath, PathComparison()) &&
            string.Equals(left.StagedPath, right.StagedPath, PathComparison());

        public int GetHashCode(PurgeQuarantineTarget value) =>
            HashCode.Combine(
                PathComparer().GetHashCode(value.SourcePath),
                PathComparer().GetHashCode(value.StagedPath));
    }
}
