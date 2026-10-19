using System.IO.Compression;
using System.Text.Json;

namespace CodeSignAuto.Core.Diagnostics;

public sealed record DiagnosticSource(string Directory, string AccountSid);

public static class DiagnosticArchive
{
    public static void Create(string outputPath, IEnumerable<DiagnosticSource> directories)
    {
        var fullPath = Path.GetFullPath(outputPath);
        DiagnosticSession.RejectLinks(Path.GetDirectoryName(fullPath)!);
        using var output = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var archive = new ZipArchive(output, ZipArchiveMode.Create);
        var sources = new List<object>();
        long remaining = 128L * 1024 * 1024;
        var index = 0;
        foreach (var item in directories.DistinctBy(item => item.Directory, StringComparer.OrdinalIgnoreCase))
        {
            var directory = item.Directory;
            var source = $"source-{index++}";
            var copied = 0;
            var skipped = 0;
            var status = "collected";
            try
            {
                DiagnosticSession.RejectLinks(directory);
                var files = new DirectoryInfo(directory).EnumerateFiles("diagnostic-*.jsonl")
                    .OrderByDescending(file => file.LastWriteTimeUtc).Take(16);
                foreach (var file in files)
                {
                    try
                    {
                        if ((file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                            file.Length > 5L * 1024 * 1024 || file.Length > remaining)
                        {
                            skipped++;
                            continue;
                        }
                        using var input = new FileStream(file.FullName, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete);
                        // Snapshot only the observed size; a running process may append while exporting.
                        var count = (int)Math.Min(input.Length, file.Length);
                        var snapshot = new byte[count];
                        input.ReadExactly(snapshot);
                        // Do not export a half-written final JSONL record.
                        var completeLength = Array.LastIndexOf(snapshot, (byte)'\n') + 1;
                        var entry = archive.CreateEntry(source + "/" + file.Name, CompressionLevel.Fastest);
                        using var destination = entry.Open();
                        destination.Write(snapshot, 0, completeLength);
                        remaining -= completeLength;
                        copied++;
                    }
                    catch (IOException) { skipped++; }
                    catch (UnauthorizedAccessException) { skipped++; }
                }
            }
            catch (DirectoryNotFoundException) { status = "missing"; }
            catch (IOException) { status = "unavailable"; }
            catch (UnauthorizedAccessException) { status = "access_denied"; }
            sources.Add(new { source, accountSid = item.AccountSid, status, copied, skipped });
        }
        using var manifest = archive.CreateEntry("manifest.json").Open();
        JsonSerializer.Serialize(manifest, new
        {
            schema = 1,
            createdUtc = DateTimeOffset.UtcNow,
            os = Environment.OSVersion.VersionString,
            runtime = Environment.Version.ToString(),
            architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            sources,
        });
    }
}
