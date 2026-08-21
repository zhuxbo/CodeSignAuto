using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class PdfReleaseDecisionTests
{
    [WindowsFact]
    public void First_release_publishes_pdf_extension()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");

        var decision = fixture.Decide("1.0.0");

        Assert.True(decision.ReleasePdf);
        Assert.Equal("first_release", decision.Reason);
        Assert.Null(decision.BaselineTag);
    }

    [WindowsFact]
    public void Unchanged_pdf_inputs_skip_pdf_extension()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Write("README.md", "main-only change");
        fixture.Commit("main only");

        var decision = fixture.Decide("1.0.1");

        Assert.False(decision.ReleasePdf);
        Assert.Equal("pdf_inputs_unchanged", decision.Reason);
        Assert.Equal("v1.0.0", decision.BaselineTag);
        Assert.Empty(decision.ChangedPaths);
    }

    [WindowsFact]
    public void Previous_release_tag_on_current_commit_skips_pdf_extension()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Tag("v1.0.1");

        var decision = fixture.Decide("1.0.1");

        Assert.False(decision.ReleasePdf);
        Assert.Equal("pdf_inputs_unchanged", decision.Reason);
        Assert.Equal("v1.0.0", decision.BaselineTag);
        Assert.Empty(decision.ChangedPaths);
    }

    [WindowsFact]
    public void Current_version_tag_on_an_older_commit_fails_closed()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.1");
        fixture.Write("README.md", "later commit");
        fixture.Commit("later");

        var result = fixture.RunDecision("1.0.1");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("pdf_release_current_tag_invalid", result.StandardError, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Helper_production_change_publishes_pdf_extension()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Write("tools/pdf-signer/simplysign_pdf_signer.py", "VERSION = '1.0.1'");
        fixture.Commit("helper change");

        var decision = fixture.Decide("1.0.1");

        Assert.True(decision.ReleasePdf);
        Assert.Equal("pdf_inputs_changed", decision.Reason);
        Assert.Equal(
            ["tools/pdf-signer/simplysign_pdf_signer.py"],
            decision.ChangedPaths);
    }

    [WindowsFact]
    public void Pdf_test_only_change_skips_pdf_extension()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Write("tools/pdf-signer/tests/test_probe.py", "def test_new_case(): pass");
        fixture.Commit("test only");

        var decision = fixture.Decide("1.0.1");

        Assert.False(decision.ReleasePdf);
        Assert.Equal("pdf_inputs_unchanged", decision.Reason);
        Assert.Empty(decision.ChangedPaths);
    }

    [WindowsFact]
    public void Shared_pdf_setup_change_publishes_pdf_extension()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Write("src/SimplySignAuto.Setup/Program.cs", "// setup fix");
        fixture.Commit("setup change");

        var decision = fixture.Decide("1.0.1");

        Assert.True(decision.ReleasePdf);
        Assert.Equal("pdf_inputs_changed", decision.Reason);
        Assert.Equal(["src/SimplySignAuto.Setup/Program.cs"], decision.ChangedPaths);
    }

    [WindowsFact]
    public void Pdf_packaging_script_change_publishes_pdf_extension()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Write("scripts/build-release.ps1", "# changed PDF packaging");
        fixture.Commit("PDF packaging change");

        var decision = fixture.Decide("1.0.1");

        Assert.True(decision.ReleasePdf);
        Assert.Equal("pdf_inputs_changed", decision.Reason);
        Assert.Equal(["scripts/build-release.ps1"], decision.ChangedPaths);
    }

    [WindowsFact]
    public void Shallow_history_fails_closed()
    {
        using var source = DecisionFixture.Create();
        source.Commit("initial");
        source.Tag("v1.0.0");
        source.Write("README.md", "next");
        source.Commit("next");
        using var shallow = DecisionFixture.CloneShallow(source.Root);

        var result = shallow.RunDecision("1.0.1");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("pdf_release_history_incomplete", result.StandardError, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Equidistant_baseline_tags_fail_closed()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Tag("v1.0.1");
        fixture.Write("README.md", "main-only change");
        fixture.Commit("main only");

        var result = fixture.RunDecision("1.0.2");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("pdf_release_baseline_ambiguous", result.StandardError, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Uncommitted_tracked_pdf_input_fails_closed()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Write("tools/pdf-signer/simplysign_pdf_signer.py", "VERSION = '1.0.1'");

        var result = fixture.RunDecision("1.0.1");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("pdf_release_worktree_dirty", result.StandardError, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Untracked_pdf_setup_input_fails_closed()
    {
        using var fixture = DecisionFixture.Create();
        fixture.Commit("initial");
        fixture.Tag("v1.0.0");
        fixture.Write("src/SimplySignAuto.Setup/NewSetupInput.cs", "// untracked setup input");

        var result = fixture.RunDecision("1.0.1");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("pdf_release_worktree_dirty", result.StandardError, StringComparison.Ordinal);
    }

    private sealed class DecisionFixture : IDisposable
    {
        private DecisionFixture(string root)
        {
            Root = root;
        }

        public string Root { get; }

        public static DecisionFixture Create()
        {
            var root = Path.Combine(Path.GetTempPath(), $"simplysign-pdf-release-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var fixture = new DecisionFixture(root);
            fixture.Git("init");
            fixture.Git("config", "user.name", "Release Test");
            fixture.Git("config", "user.email", "release-test@example.invalid");
            fixture.Write("tools/pdf-signer/simplysign_pdf_signer.py", "VERSION = '1.0.0'");
            fixture.Write("tools/pdf-signer/simplysign_pdf_validator.py", "validator = True");
            fixture.Write("tools/pdf-signer/pdf-signer.spec", "spec");
            fixture.Write("tools/pdf-signer/pyproject.toml", "[project]");
            fixture.Write("tools/pdf-signer/uv.lock", "lock");
            fixture.Write("tools/pdf-signer/tests/test_probe.py", "def test_probe(): pass");
            fixture.Write("src/SimplySignAuto.Setup/Program.cs", "// setup");
            fixture.Write("scripts/build-release.ps1", "# release packaging");
            fixture.Write("Directory.Build.props", "<Project />");
            fixture.Write("Directory.Packages.props", "<Project />");
            fixture.Write("global.json", "{}");
            fixture.Write("LICENSE", "license");
            fixture.Write("THIRD-PARTY-NOTICES.txt", "notices");
            fixture.Write("README.md", "readme");
            return fixture;
        }

        public static DecisionFixture CloneShallow(string sourceRoot)
        {
            var parent = Path.Combine(Path.GetTempPath(), $"simplysign-pdf-shallow-{Guid.NewGuid():N}");
            var root = Path.Combine(parent, "clone");
            Directory.CreateDirectory(parent);
            RunGit(
                parent,
                "clone",
                "--depth",
                "1",
                new Uri(sourceRoot + Path.DirectorySeparatorChar).AbsoluteUri,
                root);
            return new DecisionFixture(root);
        }

        public void Write(string relativePath, string content)
        {
            var path = Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content, new UTF8Encoding(false));
        }

        public void Commit(string message)
        {
            Git("add", "--all");
            Git("commit", "--message", message);
        }

        public void Tag(string tag) => Git("tag", tag);

        public Decision Decide(string version)
        {
            var result = RunDecision(version);
            Assert.True(
                result.ExitCode == 0,
                $"decision_exit_{result.ExitCode}: {result.StandardError}");
            Assert.Equal(string.Empty, result.StandardError);
            using var document = JsonDocument.Parse(result.StandardOutput);
            var root = document.RootElement;
            return new Decision(
                root.GetProperty("releasePdf").GetBoolean(),
                root.GetProperty("reason").GetString()!,
                root.GetProperty("baselineTag").ValueKind == JsonValueKind.Null
                    ? null
                    : root.GetProperty("baselineTag").GetString(),
                root.GetProperty("changedPaths")
                    .EnumerateArray()
                    .Select(entry => entry.GetString()!)
                    .ToArray());
        }

        public ProcessResult RunDecision(string version) => RunProcess(
            "powershell.exe",
            Root,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            Path.Combine(FindRepositoryRoot(), "scripts", "get-pdf-release-decision.ps1"),
            "-RepositoryRoot",
            Root,
            "-Version",
            version);

        public void Dispose()
        {
            var parent = Directory.GetParent(Root)?.FullName;
            if (Directory.Exists(Root))
            {
                DeleteGitTree(Root);
            }
            if (parent is not null &&
                Path.GetFileName(parent).StartsWith("simplysign-pdf-shallow-", StringComparison.Ordinal) &&
                Directory.Exists(parent))
            {
                DeleteGitTree(parent);
            }
        }

        private void Git(params string[] arguments) => RunGit(Root, arguments);

        private static void DeleteGitTree(string path)
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(file, FileAttributes.Normal);
            }
            Directory.Delete(path, recursive: true);
        }
    }

    private static void RunGit(string workingDirectory, params string[] arguments)
    {
        var result = RunProcess("git.exe", workingDirectory, arguments);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"git_exit_{result.ExitCode}: {result.StandardError}");
        }
    }

    private static ProcessResult RunProcess(
        string fileName,
        string workingDirectory,
        params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("process_start_failed");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromSeconds(30)))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException("process_timeout");
        }

        return new ProcessResult(
            process.ExitCode,
            standardOutput.GetAwaiter().GetResult(),
            standardError.GetAwaiter().GetResult());
    }

    private static string FindRepositoryRoot()
    {
        var candidate = AppContext.BaseDirectory;
        while (candidate is not null)
        {
            if (File.Exists(Path.Combine(candidate, "scripts", "build-release.ps1")))
            {
                return candidate;
            }
            candidate = Directory.GetParent(candidate)?.FullName;
        }
        throw new InvalidOperationException("repository_root_not_found");
    }

    private sealed record Decision(
        bool ReleasePdf,
        string Reason,
        string? BaselineTag,
        IReadOnlyList<string> ChangedPaths);

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);
}
