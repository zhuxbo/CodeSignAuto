using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Linq;

namespace SimplySignAuto.Coverage;

public sealed class CoverageGateException : Exception
{
    public CoverageGateException(string code)
        : base(code) => Code = code;

    public string Code { get; }
}

public sealed record CoverageResult(int CoveredLines, int TotalLines, int BasisPoints, int RequiredBasisPoints);

public static class CoverageGate
{
    private const int MaximumReportCharacters = 128 * 1024 * 1024;
    private const int Sha256HexCharacters = 64;
    private static readonly IReadOnlyDictionary<string, int> Thresholds =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["SimplySignAuto.Core"] = 8_500,
            ["SimplySignAuto.Service"] = 8_500,
            ["SimplySignAuto.Protocol"] = 8_500,
            ["SimplySignAuto.Agent"] = 7_500,
            ["SimplySignAuto.UI.ViewModels"] = 8_000,
        };

    public static IReadOnlyDictionary<string, CoverageResult> EvaluateFiles(
        IReadOnlyList<string> reportPaths)
    {
        ArgumentNullException.ThrowIfNull(reportPaths);
        if (reportPaths.Count == 0)
        {
            throw Error("coverage_report_missing");
        }

        var reports = new List<string>(reportPaths.Count);
        foreach (var supplied in reportPaths)
        {
            try
            {
                var path = Path.GetFullPath(supplied);
                var info = new FileInfo(path);
                if (!info.Exists || info.LinkTarget is not null ||
                    !string.Equals(info.Name, "coverage.cobertura.xml", StringComparison.Ordinal) ||
                    info.Length is <= 0 or > MaximumReportCharacters)
                {
                    throw Error("coverage_report_invalid");
                }

                reports.Add(File.ReadAllText(path));
            }
            catch (CoverageGateException)
            {
                throw;
            }
            catch (Exception error) when (
                error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                throw Error("coverage_report_invalid");
            }
        }

        return EvaluateXmlReports(reports);
    }

    public static IReadOnlyDictionary<string, CoverageResult> EvaluateManifest(string manifestPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
        try
        {
            var manifestInfo = new FileInfo(Path.GetFullPath(manifestPath));
            if (!manifestInfo.Exists || manifestInfo.LinkTarget is not null ||
                manifestInfo.Length is <= 0 or > 1024 * 1024)
            {
                throw Error("coverage_manifest_invalid");
            }

            var manifest = JsonSerializer.Deserialize<CoverageRunManifest>(
                File.ReadAllText(manifestInfo.FullName),
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = false,
                    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
                }) ?? throw Error("coverage_manifest_invalid");
            return EvaluateManifest(manifestInfo, manifest);
        }
        catch (CoverageGateException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException or JsonException or CryptographicException)
        {
            throw Error("coverage_manifest_invalid");
        }
    }

    internal static void ValidateProjectArtifacts(
        string runRoot,
        string repositoryRoot,
        CoverageProjectDescriptor project)
    {
        var projectRoot = GetProjectRoot(runRoot, project);
        if (!IsOrdinaryDirectory(projectRoot))
        {
            throw Error("coverage_project_missing");
        }

        var trx = GetSingleArtifact(projectRoot, "*.trx", "coverage_trx_invalid");
        var report = GetSingleArtifact(projectRoot, "coverage.cobertura.xml", "coverage_report_invalid");
        var stdout = Path.Combine(projectRoot, "stdout.txt");
        var stderr = Path.Combine(projectRoot, "stderr.txt");
        ValidateOrdinaryFile(stdout, allowEmpty: true, "coverage_output_invalid");
        ValidateOrdinaryFile(stderr, allowEmpty: true, "coverage_output_invalid");
        ValidateTrx(trx, project, out var trxOutput);
        var reportText = File.ReadAllText(report);
        ValidateCoverageIdentity(reportText, repositoryRoot, project);
        var scanText = SanitizeKnownCollectorSource(reportText);
        var allowedRoots = new[] { Path.GetFullPath(runRoot), Path.GetFullPath(repositoryRoot) };
        if (SensitiveOutputScanner.FindArtifact(File.ReadAllText(stdout), allowedRoots).Count != 0 ||
            SensitiveOutputScanner.FindArtifact(File.ReadAllText(stderr), allowedRoots).Count != 0 ||
            SensitiveOutputScanner.FindArtifact(trxOutput, allowedRoots).Count != 0 ||
            SensitiveOutputScanner.FindArtifact(scanText, allowedRoots).Count != 0)
        {
            throw Error("coverage_sensitive_output");
        }
    }

    internal static string WriteCoordinatorManifest(string runRoot, string repositoryRoot, string nonce)
    {
        var root = Path.GetFullPath(runRoot);
        var manifestPath = Path.Combine(root, CoverageRunContract.ManifestName);
        using (var stream = new FileStream(manifestPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            JsonSerializer.Serialize(stream, CreateCoordinatorManifest(root, repositoryRoot, nonce));
            stream.Flush(flushToDisk: true);
        }

        return manifestPath;
    }

    internal static string CreateCoordinatorManifestJson(
        string runRoot,
        string repositoryRoot,
        string nonce) =>
        JsonSerializer.Serialize(CreateCoordinatorManifest(runRoot, repositoryRoot, nonce));

    private static CoverageRunManifest CreateCoordinatorManifest(
        string runRoot,
        string repositoryRoot,
        string nonce)
    {
        var root = Path.GetFullPath(runRoot);
        var started = Path.Combine(root, CoverageRunContract.StartedMarkerName);
        var completed = Path.Combine(root, CoverageRunContract.CompletedMarkerName);
        ValidateMarker(started, nonce);
        ValidateMarker(completed, nonce);
        repositoryRoot = Path.GetFullPath(repositoryRoot);
        var projects = CoverageRunContract.Projects.Select(project =>
        {
            ValidateProjectArtifacts(root, repositoryRoot, project);
            var projectRoot = GetProjectRoot(root, project);
            var trx = GetSingleArtifact(projectRoot, "*.trx", "coverage_trx_invalid");
            var report = GetSingleArtifact(projectRoot, "coverage.cobertura.xml", "coverage_report_invalid");
            var stdout = Path.Combine(projectRoot, "stdout.txt");
            var stderr = Path.Combine(projectRoot, "stderr.txt");
            var projectStarted = Path.Combine(projectRoot, "project.started");
            var projectCompleted = Path.Combine(projectRoot, "project.completed");
            return new CoverageRunProject(
                project.Name,
                project.ProjectFile,
                Path.GetRelativePath(root, projectRoot),
                project.TestAssembly,
                Path.GetRelativePath(root, trx),
                Hash(trx),
                Path.GetRelativePath(root, report),
                Hash(report),
                Path.GetRelativePath(root, stdout),
                Hash(stdout),
                Path.GetRelativePath(root, stderr),
                Hash(stderr),
                Path.GetRelativePath(root, projectStarted),
                Hash(projectStarted),
                Path.GetRelativePath(root, projectCompleted),
                Hash(projectCompleted),
                "clean");
        }).ToArray();
        return new CoverageRunManifest(
            2,
            nonce,
            repositoryRoot,
            new CoverageRunMarker(CoverageRunContract.StartedMarkerName, Hash(started)),
            new CoverageRunMarker(CoverageRunContract.CompletedMarkerName, Hash(completed)),
            projects);
    }

    private static IReadOnlyDictionary<string, CoverageResult> EvaluateManifest(
        FileInfo manifestInfo,
        CoverageRunManifest manifest)
    {
        var root = manifestInfo.DirectoryName is { } parent ? Path.GetFullPath(parent) : string.Empty;
        if (manifest.Schema != 2 || !IsNonce(manifest.RunNonce) ||
            !string.Equals(Path.GetFileName(root), "ssa-coverage-" + manifest.RunNonce, StringComparison.Ordinal) ||
            !IsOrdinaryDirectory(root) || string.IsNullOrWhiteSpace(manifest.RepositoryRoot) ||
            !IsOrdinaryDirectory(Path.GetFullPath(manifest.RepositoryRoot)) || manifest.Projects is null ||
            manifest.Projects.Length != CoverageRunContract.Projects.Length)
        {
            throw Error("coverage_manifest_invalid");
        }

        var repositoryRoot = Path.GetFullPath(manifest.RepositoryRoot);
        var startedPath = ValidateManifestMarker(root, manifest.Started, CoverageRunContract.StartedMarkerName, manifest.RunNonce!);
        var completedPath = ValidateManifestMarker(root, manifest.Completed, CoverageRunContract.CompletedMarkerName, manifest.RunNonce!);
        var started = File.GetLastWriteTimeUtc(startedPath);
        var completed = File.GetLastWriteTimeUtc(completedPath);
        if (completed < started || manifestInfo.LastWriteTimeUtc < completed)
        {
            throw Error("coverage_manifest_invalid");
        }

        var reportPaths = new List<string>(CoverageRunContract.Projects.Length);
        var expectedTrx = new HashSet<string>(StringComparer.Ordinal);
        var expectedReports = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < CoverageRunContract.Projects.Length; index++)
        {
            var expected = CoverageRunContract.Projects[index];
            var supplied = manifest.Projects[index];
            if (!string.Equals(supplied.Project, expected.Name, StringComparison.Ordinal) ||
                !string.Equals(supplied.ProjectFile, expected.ProjectFile, StringComparison.Ordinal) ||
                !string.Equals(supplied.TestAssembly, expected.TestAssembly, StringComparison.Ordinal) ||
                !string.Equals(supplied.Scan, "clean", StringComparison.Ordinal))
            {
                throw Error("coverage_project_unexpected");
            }

            var projectFile = Path.GetFullPath(Path.Combine(
                repositoryRoot,
                expected.ProjectFile.Replace('/', Path.DirectorySeparatorChar)));
            ValidateOrdinaryFile(projectFile, allowEmpty: false, "coverage_project_missing");
            var projectRoot = GetProjectRoot(root, expected);
            if (!string.Equals(
                    supplied.ResultsDirectory,
                    Path.GetRelativePath(root, projectRoot),
                    StringComparison.Ordinal))
            {
                throw Error("coverage_project_unexpected");
            }

            var trx = GetSingleArtifact(projectRoot, "*.trx", "coverage_trx_invalid");
            var report = GetSingleArtifact(projectRoot, "coverage.cobertura.xml", "coverage_report_invalid");
            var stdout = Path.Combine(projectRoot, "stdout.txt");
            var stderr = Path.Combine(projectRoot, "stderr.txt");
            var projectStarted = Path.Combine(projectRoot, "project.started");
            var projectCompleted = Path.Combine(projectRoot, "project.completed");
            ValidateProjectMarker(
                root,
                supplied.ProjectStarted,
                supplied.ProjectStartedSha256,
                projectStarted,
                manifest.RunNonce!,
                expected.Name,
                started,
                completed);
            ValidateProjectMarker(
                root,
                supplied.ProjectCompleted,
                supplied.ProjectCompletedSha256,
                projectCompleted,
                manifest.RunNonce!,
                expected.Name,
                started,
                completed);
            var projectStartedUtc = File.GetLastWriteTimeUtc(projectStarted);
            var projectCompletedUtc = File.GetLastWriteTimeUtc(projectCompleted);
            if (projectCompletedUtc < projectStartedUtc)
            {
                throw Error("coverage_report_stale");
            }

            ValidateBoundArtifact(root, supplied.Trx, supplied.TrxSha256, trx, projectStartedUtc, projectCompletedUtc, false);
            ValidateBoundArtifact(root, supplied.Coverage, supplied.CoverageSha256, report, projectStartedUtc, projectCompletedUtc, false);
            ValidateBoundArtifact(root, supplied.Stdout, supplied.StdoutSha256, stdout, projectStartedUtc, projectCompletedUtc, true);
            ValidateBoundArtifact(root, supplied.Stderr, supplied.StderrSha256, stderr, projectStartedUtc, projectCompletedUtc, true);
            ValidateProjectArtifacts(root, repositoryRoot, expected);
            expectedTrx.Add(trx);
            expectedReports.Add(report);
            reportPaths.Add(report);
        }

        var allTrx = Directory.EnumerateFiles(root, "*.trx", SearchOption.AllDirectories)
            .Select(Path.GetFullPath).ToHashSet(StringComparer.Ordinal);
        var allReports = Directory.EnumerateFiles(root, "coverage.cobertura.xml", SearchOption.AllDirectories)
            .Select(Path.GetFullPath).ToHashSet(StringComparer.Ordinal);
        if (!allTrx.SetEquals(expectedTrx) || !allReports.SetEquals(expectedReports))
        {
            throw Error("coverage_report_extra");
        }

        return EvaluateFiles(reportPaths);
    }

    private static string ValidateManifestMarker(
        string root,
        CoverageRunMarker? marker,
        string expectedName,
        string nonce)
    {
        if (marker is null || !string.Equals(marker.Path, expectedName, StringComparison.Ordinal))
        {
            throw Error("coverage_manifest_invalid");
        }

        var path = Path.Combine(root, expectedName);
        ValidateMarker(path, nonce);
        ValidateHash(path, marker.Sha256, "coverage_manifest_invalid");
        return path;
    }

    private static void ValidateMarker(string path, string nonce)
    {
        ValidateOrdinaryFile(path, allowEmpty: false, "coverage_manifest_invalid");
        if (!string.Equals(File.ReadAllText(path), nonce, StringComparison.Ordinal))
        {
            throw Error("coverage_manifest_invalid");
        }
    }

    private static void ValidateBoundArtifact(
        string root,
        string? suppliedRelative,
        string? suppliedHash,
        string actualPath,
        DateTime started,
        DateTime completed,
        bool allowEmpty)
    {
        ValidateOrdinaryFile(actualPath, allowEmpty, "coverage_report_invalid");
        if (string.IsNullOrWhiteSpace(suppliedRelative) || Path.IsPathRooted(suppliedRelative) ||
            !string.Equals(suppliedRelative, Path.GetRelativePath(root, actualPath), StringComparison.Ordinal))
        {
            throw Error("coverage_report_invalid");
        }

        var written = File.GetLastWriteTimeUtc(actualPath);
        if (written < started || written > completed)
        {
            throw Error("coverage_report_stale");
        }

        ValidateHash(actualPath, suppliedHash, "coverage_report_hash_mismatch");
    }

    private static void ValidateProjectMarker(
        string root,
        string? suppliedRelative,
        string? suppliedHash,
        string actualPath,
        string nonce,
        string project,
        DateTime runStarted,
        DateTime runCompleted)
    {
        ValidateOrdinaryFile(actualPath, allowEmpty: false, "coverage_manifest_invalid");
        if (string.IsNullOrWhiteSpace(suppliedRelative) || Path.IsPathRooted(suppliedRelative) ||
            !string.Equals(suppliedRelative, Path.GetRelativePath(root, actualPath), StringComparison.Ordinal) ||
            !string.Equals(File.ReadAllText(actualPath), nonce + "\n" + project, StringComparison.Ordinal))
        {
            throw Error("coverage_manifest_invalid");
        }

        var written = File.GetLastWriteTimeUtc(actualPath);
        if (written < runStarted || written > runCompleted)
        {
            throw Error("coverage_report_stale");
        }

        ValidateHash(actualPath, suppliedHash, "coverage_manifest_invalid");
    }

    private static void ValidateHash(string path, string? suppliedHash, string code)
    {
        if (string.IsNullOrWhiteSpace(suppliedHash) || suppliedHash.Length != Sha256HexCharacters ||
            suppliedHash.Any(static character => !Uri.IsHexDigit(character)))
        {
            throw Error(code);
        }

        var actual = Hash(path);
        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(actual),
                System.Text.Encoding.ASCII.GetBytes(suppliedHash.ToLowerInvariant())))
        {
            throw Error(code);
        }
    }

    private static void ValidateTrx(
        string path,
        CoverageProjectDescriptor project,
        out string output)
    {
        XDocument document;
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersInDocument = 128 * 1024 * 1024,
                XmlResolver = null,
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (Exception error) when (error is XmlException or IOException or InvalidOperationException)
        {
            throw Error("coverage_trx_invalid");
        }

        if (document.Root?.Name.LocalName != "TestRun")
        {
            throw Error("coverage_trx_invalid");
        }

        var summaries = document.Descendants().Where(element => element.Name.LocalName == "ResultSummary").ToArray();
        var counters = summaries.Length == 1
            ? summaries[0].Elements().Where(element => element.Name.LocalName == "Counters").ToArray()
            : [];
        if (summaries.Length != 1 || counters.Length != 1 ||
            !string.Equals(Attribute(summaries[0], "outcome"), "Completed", StringComparison.Ordinal) ||
            ParseCounter(counters[0], "total") <= 0 || ParseCounter(counters[0], "failed") != 0 ||
            ParseCounter(counters[0], "error") != 0 || ParseCounter(counters[0], "timeout") != 0 ||
            ParseCounter(counters[0], "aborted") != 0)
        {
            throw Error("coverage_trx_failed");
        }

        var storages = document.Descendants()
            .Where(element => element.Name.LocalName == "UnitTest")
            .Select(element => Attribute(element, "storage"))
            .ToArray();
        if (storages.Length == 0 || storages.Any(storage =>
                !string.Equals(Path.GetFileName(storage), project.TestAssembly, StringComparison.OrdinalIgnoreCase)))
        {
            throw Error("coverage_project_identity_mismatch");
        }

        output = string.Join("\n", document.Descendants()
            .SelectMany(static element => element.Attributes())
            .Select(static attribute => attribute.Value)
            .Concat(document.DescendantNodes().Select(static node => node switch
            {
                XText text => text.Value,
                XComment comment => comment.Value,
                XProcessingInstruction instruction => instruction.Data,
                _ => null,
            }))
            .Where(static value => !string.IsNullOrWhiteSpace(value)));
    }

    private static void ValidateCoverageIdentity(
        string report,
        string repositoryRoot,
        CoverageProjectDescriptor project)
    {
        XDocument document;
        try
        {
            using var text = new StringReader(report);
            using var reader = XmlReader.Create(text, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersInDocument = MaximumReportCharacters,
                XmlResolver = null,
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (Exception error) when (error is XmlException or InvalidOperationException)
        {
            throw Error("coverage_report_invalid");
        }

        var root = document.Root;
        var packages = root is { Name.LocalName: "coverage", Name.NamespaceName.Length: 0 }
            ? root.Elements("packages").SingleOrDefault()
            : null;
        if (packages is null)
        {
            throw Error("coverage_report_invalid");
        }

        var repository = Path.GetFullPath(repositoryRoot);
        var expectedSourceRoot = Path.GetFullPath(Path.Combine(
            repository,
            "tests",
            project.Name));
        var package = packages.Elements("package").SingleOrDefault(element =>
            string.Equals(
                element.Attribute("name")?.Value,
                Path.GetFileNameWithoutExtension(project.TestAssembly),
                StringComparison.Ordinal));
        if (package is null || package.Elements("classes").SingleOrDefault() is not { } classes ||
            !classes.Elements("class").Any(@class => IsControlledTestSource(
                @class.Attribute("filename")?.Value,
                repository,
                expectedSourceRoot)))
        {
            throw Error("coverage_project_identity_mismatch");
        }
    }

    private static bool IsControlledTestSource(
        string? supplied,
        string repositoryRoot,
        string expectedSourceRoot)
    {
        if (string.IsNullOrWhiteSpace(supplied) || supplied.Any(char.IsControl))
        {
            return false;
        }

        try
        {
            var normalized = supplied.Replace('/', Path.DirectorySeparatorChar);
            var source = Path.GetFullPath(Path.IsPathRooted(normalized)
                ? normalized
                : Path.Combine(repositoryRoot, normalized));
            var comparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            var relative = Path.GetRelativePath(expectedSourceRoot, source);
            return relative.Length > 0 && relative != "." && !Path.IsPathRooted(relative) &&
                relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, comparison) &&
                string.Equals(Path.GetExtension(source), ".cs", comparison) &&
                new FileInfo(source) is { Exists: true, LinkTarget: null } info &&
                (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static string SanitizeKnownCollectorSource(string report)
    {
        XDocument document;
        try
        {
            using var text = new StringReader(report);
            using var reader = XmlReader.Create(text, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersInDocument = MaximumReportCharacters,
                XmlResolver = null,
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (Exception error) when (error is XmlException or InvalidOperationException)
        {
            throw Error("coverage_report_invalid");
        }

        foreach (var @class in document.Descendants("class"))
        {
            var name = @class.Attribute("name")?.Value;
            var fileName = @class.Attribute("filename")?.Value;
            if (!string.Equals(name, "AutoGeneratedProgram", StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(fileName))
            {
                continue;
            }

            var normalized = fileName.Replace('\\', '/');
            if (normalized.Contains("/.nuget/packages/microsoft.net.test.sdk/", StringComparison.OrdinalIgnoreCase) &&
                normalized.EndsWith("/build/net8.0/Microsoft.NET.Test.Sdk.Program.cs", StringComparison.OrdinalIgnoreCase))
            {
                @class.SetAttributeValue("filename", "known-test-sdk-generated-source");
            }
        }

        var numericAttributes = new HashSet<string>(StringComparer.Ordinal)
        {
            "line-rate",
            "branch-rate",
            "complexity",
            "timestamp",
            "lines-covered",
            "lines-valid",
            "branches-covered",
            "branches-valid",
            "number",
            "hits",
            "condition-coverage",
            "coverage",
        };
        var scanValues = document.DescendantNodes().OfType<XComment>()
            .Select(comment => comment.Value)
            .Concat(document.Descendants()
                .SelectMany(element => element.Attributes())
                .Where(attribute => !numericAttributes.Contains(attribute.Name.LocalName))
                .Select(attribute => attribute.Value));
        return string.Join("\n", scanValues);
    }

    private static int ParseCounter(XElement counters, string name)
    {
        if (!int.TryParse(Attribute(counters, name), NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < 0)
        {
            throw Error("coverage_trx_invalid");
        }

        return value;
    }

    private static string Attribute(XElement element, string name)
    {
        var attributes = element.Attributes().Where(attribute => attribute.Name.LocalName == name).ToArray();
        return attributes.Length == 1 && !string.IsNullOrWhiteSpace(attributes[0].Value)
            ? attributes[0].Value
            : throw Error("coverage_trx_invalid");
    }

    private static string GetProjectRoot(string root, CoverageProjectDescriptor project) =>
        Path.Combine(Path.GetFullPath(root), "projects", project.Name);

    private static string GetSingleArtifact(string root, string pattern, string code)
    {
        if (!IsOrdinaryDirectory(root))
        {
            throw Error(code);
        }

        var matches = Directory.EnumerateFiles(root, pattern, SearchOption.AllDirectories)
            .Select(Path.GetFullPath).ToArray();
        if (matches.Length != 1)
        {
            throw Error(code);
        }

        ValidateOrdinaryFile(matches[0], allowEmpty: false, code);
        return matches[0];
    }

    private static bool IsOrdinaryDirectory(string path)
    {
        var info = new DirectoryInfo(path);
        return info.Exists && info.LinkTarget is null &&
            (info.Attributes & FileAttributes.ReparsePoint) == 0;
    }

    private static void ValidateOrdinaryFile(string path, bool allowEmpty, string code)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
            !allowEmpty && info.Length <= 0 || info.Length > MaximumReportCharacters)
        {
            throw Error(code);
        }
    }

    private static bool IsNonce(string? nonce) =>
        nonce is { Length: 32 } && nonce.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string Hash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    public static IReadOnlyDictionary<string, CoverageResult> EvaluateXmlReports(
        IReadOnlyList<string> reports)
    {
        ArgumentNullException.ThrowIfNull(reports);
        if (reports.Count == 0)
        {
            throw Error("coverage_report_missing");
        }

        var linesByTarget = Thresholds.Keys.ToDictionary(
            target => target,
            _ => new Dictionary<SourceLine, bool>(),
            StringComparer.Ordinal);
        foreach (var report in reports)
        {
            ParseReport(report, linesByTarget);
        }

        var results = new Dictionary<string, CoverageResult>(StringComparer.Ordinal);
        foreach (var (target, required) in Thresholds)
        {
            var lines = linesByTarget[target];
            if (lines.Count == 0)
            {
                throw Error("coverage_target_missing");
            }

            var covered = lines.Values.Count(static hit => hit);
            var basisPoints = checked((int)((long)covered * 10_000 / lines.Count));
            if (basisPoints < required)
            {
                throw Error("coverage_below_threshold");
            }

            results.Add(target, new CoverageResult(covered, lines.Count, basisPoints, required));
        }

        return results;
    }

    private static void ParseReport(
        string report,
        IReadOnlyDictionary<string, Dictionary<SourceLine, bool>> linesByTarget)
    {
        if (string.IsNullOrWhiteSpace(report) || report.Length > MaximumReportCharacters)
        {
            throw Error("coverage_report_invalid");
        }

        XDocument document;
        try
        {
            using var text = new StringReader(report);
            using var reader = XmlReader.Create(text, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersInDocument = MaximumReportCharacters,
                XmlResolver = null,
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (Exception error) when (error is XmlException or InvalidOperationException)
        {
            throw Error("coverage_report_invalid");
        }

        var root = document.Root;
        var packages = root is { Name.LocalName: "coverage", Name.NamespaceName.Length: 0 }
            ? root.Elements("packages").SingleOrDefault()
            : null;
        if (packages is null)
        {
            throw Error("coverage_report_invalid");
        }

        var seenPackages = new HashSet<string>(StringComparer.Ordinal);
        foreach (var package in packages.Elements("package"))
        {
            var name = RequiredAttribute(package, "name");
            if (!seenPackages.Add(name))
            {
                throw Error("coverage_module_duplicate");
            }

            var exactTarget = linesByTarget.ContainsKey(name) && name != "SimplySignAuto.UI.ViewModels"
                ? name
                : null;
            var uiPackage = string.Equals(name, "SimplySignAuto", StringComparison.Ordinal);
            var classes = package.Elements("classes").SingleOrDefault();
            if (classes is null)
            {
                continue;
            }

            foreach (var @class in classes.Elements("class"))
            {
                _ = RequiredAttribute(@class, "name");
                var suppliedFileName = RequiredAttribute(@class, "filename");
                if (exactTarget is not null)
                {
                    var fileName = NormalizeSourcePath(suppliedFileName, exactTarget);
                    if (fileName is not null)
                    {
                        AddClassLines(@class, fileName, linesByTarget[exactTarget]);
                    }
                }

                var uiFileName = uiPackage
                    ? NormalizeSourcePath(suppliedFileName, "SimplySignAuto.App")
                    : null;
                if (uiFileName is not null &&
                    uiFileName.StartsWith("SimplySignAuto.App/UI/", StringComparison.Ordinal) &&
                    uiFileName.EndsWith("ViewModel.cs", StringComparison.Ordinal))
                {
                    AddClassLines(@class, uiFileName, linesByTarget["SimplySignAuto.UI.ViewModels"]);
                }
            }
        }
    }

    private static void AddClassLines(
        XElement @class,
        string fileName,
        Dictionary<SourceLine, bool> target)
    {
        var lines = @class.Elements("lines").SingleOrDefault();
        if (lines is null)
        {
            return;
        }

        foreach (var line in lines.Elements("line"))
        {
            if (!int.TryParse(RequiredAttribute(line, "number"), NumberStyles.None, CultureInfo.InvariantCulture, out var number) ||
                number <= 0 ||
                !long.TryParse(RequiredAttribute(line, "hits"), NumberStyles.None, CultureInfo.InvariantCulture, out var hits) ||
                hits < 0)
            {
                throw Error("coverage_report_invalid");
            }

            var key = new SourceLine(fileName, number);
            target[key] = target.GetValueOrDefault(key) || hits > 0;
        }
    }

    private static string RequiredAttribute(XElement element, string name)
    {
        var attributes = element.Attributes(name).ToArray();
        if (attributes.Length != 1 || string.IsNullOrWhiteSpace(attributes[0].Value) ||
            attributes[0].Value.Any(char.IsControl))
        {
            throw Error("coverage_report_invalid");
        }

        return attributes[0].Value;
    }

    private static string? NormalizeSourcePath(string path, string moduleDirectory)
    {
        var normalized = path.Replace('\\', '/');
        if (normalized.StartsWith("../", StringComparison.Ordinal) ||
            normalized.Contains("/../", StringComparison.Ordinal) ||
            normalized.Length > 4096)
        {
            throw Error("coverage_report_invalid");
        }

        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Contains("obj", StringComparer.Ordinal))
        {
            return null;
        }

        var moduleMarker = moduleDirectory + "/";
        for (var start = normalized.IndexOf(moduleMarker, StringComparison.Ordinal);
             start >= 0;
             start = normalized.IndexOf(moduleMarker, start + 1, StringComparison.Ordinal))
        {
            if (start == 0 || normalized[start - 1] == '/')
            {
                return normalized[start..];
            }
        }

        if (normalized.StartsWith("src/", StringComparison.Ordinal) ||
            Path.IsPathRooted(normalized) ||
            normalized.Contains(':', StringComparison.Ordinal))
        {
            throw Error("coverage_report_invalid");
        }

        return moduleMarker + normalized.TrimStart('.', '/');
    }

    private static CoverageGateException Error(string code) => new(code);

    private static bool IsWithinRoot(string root, string path)
    {
        var relative = Path.GetRelativePath(root, path);
        return relative.Length > 0 && relative != "." && !Path.IsPathRooted(relative) &&
            relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private sealed record CoverageRunManifest(
        [property: JsonPropertyName("schema")] int Schema,
        [property: JsonPropertyName("runNonce")] string? RunNonce,
        [property: JsonPropertyName("repositoryRoot")] string? RepositoryRoot,
        [property: JsonPropertyName("started")] CoverageRunMarker? Started,
        [property: JsonPropertyName("completed")] CoverageRunMarker? Completed,
        [property: JsonPropertyName("projects")] CoverageRunProject[]? Projects);

    private sealed record CoverageRunMarker(
        [property: JsonPropertyName("path")] string? Path,
        [property: JsonPropertyName("sha256")] string? Sha256);

    private sealed record CoverageRunProject(
        [property: JsonPropertyName("project")] string? Project,
        [property: JsonPropertyName("projectFile")] string? ProjectFile,
        [property: JsonPropertyName("resultsDirectory")] string? ResultsDirectory,
        [property: JsonPropertyName("testAssembly")] string? TestAssembly,
        [property: JsonPropertyName("trx")] string? Trx,
        [property: JsonPropertyName("trxSha256")] string? TrxSha256,
        [property: JsonPropertyName("coverage")] string? Coverage,
        [property: JsonPropertyName("coverageSha256")] string? CoverageSha256,
        [property: JsonPropertyName("stdout")] string? Stdout,
        [property: JsonPropertyName("stdoutSha256")] string? StdoutSha256,
        [property: JsonPropertyName("stderr")] string? Stderr,
        [property: JsonPropertyName("stderrSha256")] string? StderrSha256,
        [property: JsonPropertyName("projectStarted")] string? ProjectStarted,
        [property: JsonPropertyName("projectStartedSha256")] string? ProjectStartedSha256,
        [property: JsonPropertyName("projectCompleted")] string? ProjectCompleted,
        [property: JsonPropertyName("projectCompletedSha256")] string? ProjectCompletedSha256,
        [property: JsonPropertyName("scan")] string? Scan);

    private readonly record struct SourceLine(string FileName, int Number);
}
