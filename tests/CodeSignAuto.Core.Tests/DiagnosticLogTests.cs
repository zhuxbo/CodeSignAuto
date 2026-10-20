using Xunit;
using System.IO.Compression;
using System.Text.Json;
using CodeSignAuto.Core.Diagnostics;

namespace CodeSignAuto.Core.Tests;

public sealed class DiagnosticLogTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "codesignauto-diagnostics-" + Guid.NewGuid().ToString("N"));

    public DiagnosticLogTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void ExceptionChainIsFlushedWithoutMessagesDataOrActualValues()
    {
        using var log = new DiagnosticSession(_root, "Setup");
        Exception caught;
        try { throw new ArgumentOutOfRangeException("secret_parameter", "token-value", "otpauth://secret-and-document-content"); }
        catch (Exception error) { caught = error; }
        caught.Data["token"] = "private-data";
        log.Write("ui_failed", new AggregateException("raw-sensitive-message", caught, new IOException("private-file-content")));
        var text = ReadLog(Directory.GetFiles(_root).Single());
        Assert.DoesNotContain("token-value", text);
        Assert.DoesNotContain("secret_parameter", text);
        Assert.DoesNotContain("private-", text);
        Assert.DoesNotContain("raw-sensitive-message", text);
        Assert.DoesNotContain("otpauth", text);
        using var json = JsonDocument.Parse(text);
        Assert.Equal(3, json.RootElement.GetProperty("exceptions").GetArrayLength());
        Assert.Contains(nameof(ExceptionChainIsFlushedWithoutMessagesDataOrActualValues),
            json.RootElement.GetProperty("exceptions")[1].GetProperty("stack").GetString());
        Assert.Equal(Environment.ProcessId, json.RootElement.GetProperty("process").GetInt32());
    }

    [Fact]
    public void DebugIsOptInAndRotationRetainsRecentBoundedFiles()
    {
        using (var log = new DiagnosticSession(_root, "Service", fileLimit: 1024))
        {
            log.Write("debug_hidden", debug: true);
            Assert.Empty(Directory.GetFiles(_root));
            for (var i = 0; i < 200; i++) log.Write("stage", result: i);
        }
        var files = Directory.GetFiles(_root);
        Assert.InRange(files.Length, 2, 16);
        Assert.All(files, file => Assert.True(new FileInfo(file).Length <= 1024));
        Assert.Contains(files.Select(ReadLog), line => line.Contains("\"result\":199", StringComparison.Ordinal));
        using var debugLog = new DiagnosticSession(_root, "Agent", debug: true);
        debugLog.Write("debug_visible", debug: true);
        Assert.Contains(Directory.GetFiles(_root).Select(ReadLog), line => line.Contains("debug_visible", StringComparison.Ordinal));
    }

    [Fact]
    public void ConcurrentWritersDoNotMixRecordsAndFailureDoesNotEscape()
    {
        using var first = new DiagnosticSession(_root, "Agent");
        using var second = new DiagnosticSession(_root, "Agent");
        Parallel.For(0, 100, i => (i % 2 == 0 ? first : second).Write("parallel", result: i));
        var lines = Directory.GetFiles(_root).SelectMany(path => ReadLog(path).Split('\n', StringSplitOptions.RemoveEmptyEntries)).ToArray();
        Assert.Equal(100, lines.Length);
        Assert.All(lines, line => { using var parsed = JsonDocument.Parse(line); Assert.Equal("parallel", parsed.RootElement.GetProperty("code").GetString()); });
        var blocked = Path.Combine(_root, "not-a-directory");
        File.WriteAllText(blocked, "occupied");
        using var unavailable = new DiagnosticSession(blocked, "Setup");
        unavailable.Write("must_not_throw", new Exception("secret"));
        Assert.Equal("occupied", File.ReadAllText(blocked));
    }

    [Fact]
    public void ArchiveContainsOnlyDiagnosticLogsAndReportsMissingSources()
    {
        using var log = new DiagnosticSession(_root, "Setup");
        log.Write("failed", new IOException("sensitive"));
        File.WriteAllText(Path.Combine(_root, "service.json"), "secret-config");
        File.WriteAllText(Path.Combine(_root, "desktop-agent.log"), "legacy-unfiltered-content");
        var archivePath = Path.Combine(_root, "report.zip");
        DiagnosticArchive.Create(archivePath, [new(_root, "S-1-5-18"), new(Path.Combine(_root, "missing"), "S-1-5-19")]);
        using var archive = ZipFile.OpenRead(archivePath);
        Assert.Equal(2, archive.Entries.Count);
        Assert.Contains(archive.Entries, entry => entry.Name == "manifest.json");
        Assert.Contains(archive.Entries, entry => entry.Name.StartsWith("diagnostic-", StringComparison.Ordinal));
        using var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open());
        Assert.Equal("S-1-5-19", manifest.RootElement.GetProperty("sources")[1].GetProperty("accountSid").GetString());
        Assert.Equal("missing", manifest.RootElement.GetProperty("sources")[1].GetProperty("status").GetString());
        Assert.Throws<IOException>(() => DiagnosticArchive.Create(archivePath, [new(_root, "S-1-5-18")]));
    }


    [Fact]
    public void ArchiveOmitsIncompleteLastRecord()
    {
        File.WriteAllText(Path.Combine(_root, "diagnostic-test.jsonl"), "{\"code\":\"complete\"}\n{\"code\":");
        var path = Path.Combine(_root, "partial.zip");
        DiagnosticArchive.Create(path, [new(_root, "S-1-5-18")]);
        using var archive = ZipFile.OpenRead(path);
        using var reader = new StreamReader(archive.GetEntry("source-0/diagnostic-test.jsonl")!.Open());
        Assert.Equal("{\"code\":\"complete\"}\n", reader.ReadToEnd());
    }

    private static string ReadLog(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);
}
