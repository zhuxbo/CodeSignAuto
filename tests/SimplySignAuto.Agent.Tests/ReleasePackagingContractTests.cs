using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SimplySignAuto.App.Tools;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class ReleasePackagingContractTests
{
    private static readonly string[] ExpectedTestProjects =
    [
        "SimplySignAuto.Core.Tests",
        "SimplySignAuto.Protocol.Tests",
        "SimplySignAuto.Service.Tests",
        "SimplySignAuto.Agent.Tests",
        "SimplySignAuto.UI.Tests",
        "SimplySignAuto.EndToEnd.Tests"
    ];

    [Fact]
    public void Sbom_reads_only_current_production_lock_files()
    {
        var repositoryRoot = FindRepositoryRoot();
        var script = File.ReadAllText(Path.Combine(repositoryRoot, "scripts", "build-release.ps1"));

        Assert.Contains("function Get-ReleasePackageLockPaths", script, StringComparison.Ordinal);
        Assert.Contains("Join-Path $RepoRoot 'src'", script, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Get-ChildItem -LiteralPath $RepoRoot -Recurse -File -Filter 'packages.lock.json'",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Release_publish_contract_is_framework_dependent_and_language_closed()
    {
        var repositoryRoot = FindRepositoryRoot();
        var properties = File.ReadAllText(Path.Combine(repositoryRoot, "Directory.Build.props"));
        var project = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "SimplySignAuto.App",
            "SimplySignAuto.App.csproj"));
        var setupProject = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "SimplySignAuto.Setup",
            "SimplySignAuto.Setup.csproj"));
        var script = ReadBuildScript();
        var publishPropertyGroupStart = project.IndexOf(
            "<PropertyGroup Condition=\"'$(RuntimeIdentifier)' == 'win-x64'\">",
            StringComparison.Ordinal);
        var publishPropertyGroupEnd = project.IndexOf(
            "</PropertyGroup>",
            publishPropertyGroupStart,
            StringComparison.Ordinal);
        var setupPublishPropertyGroupStart = setupProject.IndexOf(
            "<PropertyGroup Condition=\"'$(RuntimeIdentifier)' == 'win-x64'\">",
            StringComparison.Ordinal);
        var setupPublishPropertyGroupEnd = setupProject.IndexOf(
            "</PropertyGroup>",
            setupPublishPropertyGroupStart,
            StringComparison.Ordinal);

        Assert.Contains("<SatelliteResourceLanguages>zh-Hans;en</SatelliteResourceLanguages>", properties, StringComparison.Ordinal);
        Assert.Contains("<SelfContained>false</SelfContained>", project, StringComparison.Ordinal);
        Assert.NotEqual(-1, publishPropertyGroupStart);
        Assert.NotEqual(-1, publishPropertyGroupEnd);
        var publishProperties = project[publishPropertyGroupStart..publishPropertyGroupEnd];
        Assert.Contains("<PublishSingleFile>true</PublishSingleFile>", publishProperties, StringComparison.Ordinal);
        Assert.Contains("<EnableCompressionInSingleFile>false</EnableCompressionInSingleFile>", publishProperties, StringComparison.Ordinal);
        Assert.Contains("<EnableSingleFileAnalyzer>false</EnableSingleFileAnalyzer>", publishProperties, StringComparison.Ordinal);
        Assert.Contains("<PublishReadyToRun>false</PublishReadyToRun>", project, StringComparison.Ordinal);
        Assert.Contains("<PublishTrimmed>false</PublishTrimmed>", project, StringComparison.Ordinal);
        Assert.DoesNotContain("<SelfContained>true</SelfContained>", setupProject, StringComparison.Ordinal);
        Assert.NotEqual(-1, setupPublishPropertyGroupStart);
        Assert.NotEqual(-1, setupPublishPropertyGroupEnd);
        var setupPublishProperties = setupProject[
            setupPublishPropertyGroupStart..setupPublishPropertyGroupEnd];
        Assert.Contains(
            "<EnableCompressionInSingleFile>false</EnableCompressionInSingleFile>",
            setupPublishProperties,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "<EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>",
            setupPublishProperties,
            StringComparison.Ordinal);
        Assert.Equal(2, Count(script, "'--self-contained', 'false'"));
        Assert.DoesNotContain("'--self-contained', 'true'", script, StringComparison.Ordinal);
        Assert.Contains("'--self-contained', 'false'", script, StringComparison.Ordinal);
        Assert.Contains("'-p:PublishSingleFile=true'", script, StringComparison.Ordinal);
        Assert.Equal(2, Count(script, "'-p:EnableCompressionInSingleFile=false'"));
        Assert.DoesNotContain(
            "'-p:EnableCompressionInSingleFile=true'",
            script,
            StringComparison.Ordinal);
        Assert.Contains("'-p:EnableSingleFileAnalyzer=false'", script, StringComparison.Ordinal);
        Assert.Contains("'-p:PublishReadyToRun=false'", script, StringComparison.Ordinal);
        Assert.Contains("'-p:PublishTrimmed=false'", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_script_requires_one_controlled_TRX_per_expected_test_project()
    {
        var script = ReadBuildScript();

        Assert.Contains("function Invoke-ReleaseTestSuite", script, StringComparison.Ordinal);
        Assert.Contains("--logger", script, StringComparison.Ordinal);
        Assert.Contains("--results-directory", script, StringComparison.Ordinal);
        foreach (var project in ExpectedTestProjects)
        {
            Assert.Contains($"'{project}'", script, StringComparison.Ordinal);
        }

        foreach (var counter in new[] { "total", "executed", "passed", "failed", "error", "aborted", "timeout" })
        {
            Assert.Contains($"'{counter}'", script, StringComparison.Ordinal);
        }

        Assert.Contains("http://microsoft.com/schemas/VisualStudio/TeamTest/2010", script, StringComparison.Ordinal);
        Assert.Contains("SelectNodes('/trx:TestRun'", script, StringComparison.Ordinal);
        Assert.Contains("SelectNodes('trx:ResultSummary'", script, StringComparison.Ordinal);
        Assert.Contains("SelectNodes('trx:Counters'", script, StringComparison.Ordinal);
        Assert.Contains("$value -lt 0", script, StringComparison.Ordinal);
        Assert.DoesNotContain("local-name()", script, StringComparison.Ordinal);
        Assert.DoesNotContain("SelectSingleNode", script, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Invoke-Checked -FilePath $Dotnet -WorkingDirectory $RepoRoot -ArgumentList @('test', $Solution",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Release_script_has_an_explicit_PowerShell_File_exit_contract()
    {
        var script = ReadBuildScript();

        Assert.Contains("function Invoke-BuildReleaseMain", script, StringComparison.Ordinal);
        Assert.Contains("if ($MyInvocation.InvocationName -ne '.')", script, StringComparison.Ordinal);
        Assert.Contains("exit 1", script, StringComparison.Ordinal);
        Assert.Contains("exit 0", script, StringComparison.Ordinal);
        Assert.Equal(1, Count(script, "release_ok version="));
    }

    [Fact]
    public void GitHub_release_workflow_is_manual_tag_bound_and_publishes_only_two_installers()
    {
        var workflowPath = Path.Combine(
            FindRepositoryRoot(),
            ".github",
            "workflows",
            "release.yml");

        Assert.True(File.Exists(workflowPath), "github_release_workflow_missing");
        var workflow = File.ReadAllText(workflowPath);
        Assert.Contains("workflow_dispatch:", workflow, StringComparison.Ordinal);
        Assert.Contains("version:", workflow, StringComparison.Ordinal);
        Assert.Contains("required: true", workflow, StringComparison.Ordinal);
        Assert.Contains("environment: release", workflow, StringComparison.Ordinal);
        Assert.Contains("runs-on: windows-latest", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "if: github.ref == format('refs/tags/v{0}', inputs.version)",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_SIGNING_BASE_URL: ${{ vars.SIMPLYSIGN_SIGNING_BASE_URL }}", workflow, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_SIGNING_BEARER_TOKEN: ${{ secrets.SIMPLYSIGN_SIGNING_BEARER_TOKEN }}", workflow, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL: ${{ vars.SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL }}", workflow, StringComparison.Ordinal);
        Assert.Contains("contents: write", workflow, StringComparison.Ordinal);
        Assert.Contains(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains("gh release create", workflow, StringComparison.Ordinal);
        Assert.Contains("--verify-tag", workflow, StringComparison.Ordinal);
        var buildStep = workflow.IndexOf("- name: Build and sign both installers", StringComparison.Ordinal);
        var signingToken = workflow.IndexOf(
            "SIMPLYSIGN_SIGNING_BEARER_TOKEN: ${{ secrets.SIMPLYSIGN_SIGNING_BEARER_TOKEN }}",
            StringComparison.Ordinal);
        var verifyStep = workflow.IndexOf("- name: Verify release closure and signatures", StringComparison.Ordinal);
        Assert.True(buildStep >= 0 && signingToken > buildStep && signingToken < verifyStep);
        var buildContract = workflow[buildStep..verifyStep];
        Assert.Contains("shell: powershell", buildContract, StringComparison.Ordinal);
        Assert.Contains(
            "run: powershell.exe -NoLogo -NoProfile -File scripts/build-release.ps1",
            buildContract,
            StringComparison.Ordinal);
        Assert.Equal(1, Count(workflow, "SimplySignAutoSetup-${{ inputs.version }}-win-x64.exe"));
        Assert.Equal(1, Count(workflow, "SimplySignAutoPdfSetup-${{ inputs.version }}-win-x64.exe"));
        Assert.Equal(1, Count(workflow, "${{ secrets.SIMPLYSIGN_SIGNING_BEARER_TOKEN }}"));
        Assert.DoesNotContain("artifacts/release/*", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void Pre_release_gate_requires_licenses_and_rejects_development_process_residue()
    {
        var repositoryRoot = FindRepositoryRoot();
        var script = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "scripts",
            "pre-release-check.ps1"));

        Assert.Contains("'LICENSE'", script, StringComparison.Ordinal);
        Assert.Contains("'THIRD-PARTY-NOTICES.txt'", script, StringComparison.Ordinal);
        Assert.Contains("release_history_message_forbidden", script, StringComparison.Ordinal);
        Assert.Contains("release_process_reference_forbidden", script, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void GitHub_release_notes_are_deterministic_and_describe_the_exact_two_artifacts()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-notes-{Guid.NewGuid():N}");
        var releaseRoot = Path.Combine(root, "release");
        var outputPath = Path.Combine(root, "notes.md");
        Directory.CreateDirectory(releaseRoot);
        var version = "1.2.3-test.4";
        var mainName = $"SimplySignAutoSetup-{version}-win-x64.exe";
        var pdfName = $"SimplySignAutoPdfSetup-{version}-win-x64.exe";
        File.WriteAllBytes(Path.Combine(releaseRoot, mainName), [1, 2, 3]);
        File.WriteAllBytes(Path.Combine(releaseRoot, pdfName), [4, 5, 6, 7]);
        try
        {
            var result = RunPowerShell(
                Path.Combine(FindRepositoryRoot(), "scripts", "write-github-release-notes.ps1"),
                ["-ReleaseRoot", releaseRoot, "-Version", version, "-OutputPath", outputPath],
                environment: null);

            Assert.True(
                result.ExitCode == 0,
                $"powershell_exit_{result.ExitCode}: {result.StandardError}");
            Assert.Equal(string.Empty, result.StandardError);
            var expected =
                "## 安装包\r\n\r\n" +
                $"- `{pdfName}` — 4 bytes — SHA-256 `{LowerSha256(Path.Combine(releaseRoot, pdfName))}`\r\n" +
                $"- `{mainName}` — 3 bytes — SHA-256 `{LowerSha256(Path.Combine(releaseRoot, mainName))}`\r\n";
            Assert.Equal(expected, File.ReadAllText(outputPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Release_media_signer_uses_the_bounded_signing_api_and_no_test_bypass()
    {
        var repositoryRoot = FindRepositoryRoot();
        var signerPath = Path.Combine(repositoryRoot, "scripts", "sign-release-media.ps1");

        Assert.True(File.Exists(signerPath), "release_signing_script_missing");
        var signer = File.ReadAllText(signerPath);
        Assert.Contains("sign-via-simplysign.ps1", signer, StringComparison.Ordinal);
        Assert.Contains("Invoke-SimplySignArtifact", signer, StringComparison.Ordinal);
        Assert.Contains("[string]$BaseUrl", signer, StringComparison.Ordinal);
        Assert.Contains("[string]$BearerToken", signer, StringComparison.Ordinal);
        Assert.Contains("[string]$CertificateSerialNumber", signer, StringComparison.Ordinal);
        Assert.Contains("[TimeSpan]$SigningTimeout", signer, StringComparison.Ordinal);
        Assert.Contains("-Certificate $applicationSignature.SignerCertificate", signer, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("publisherCertificateSha256", signer, StringComparison.Ordinal);
        Assert.DoesNotContain("TestScenario", signer, StringComparison.Ordinal);
        Assert.DoesNotContain("tracePath", signer, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("otp", signer, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", signer, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Release_build_verifies_unsigned_reproducibility_before_signing_and_archiving()
    {
        var script = ReadBuildScript();
        var reproducibility = script.LastIndexOf(
            "Assert-Reproducibility -First $first -Second $second",
            StringComparison.Ordinal);
        var packageClosure = script.IndexOf(
            "Assert-ReleasePackageFileSet -Root $packageRoot -ExpectedFiles $expectedPackageFiles",
            StringComparison.Ordinal);
        var signer = script.IndexOf("scripts/sign-release-media.ps1", StringComparison.Ordinal);
        var mainArchive = script.IndexOf(
            "New-DeterministicZip -SourceRoot $packageRoot",
            StringComparison.Ordinal);
        var mainSetup = script.IndexOf("-PublishName 'main'", StringComparison.Ordinal);
        var pdfSetup = script.IndexOf("-PublishName 'pdf'", StringComparison.Ordinal);
        var releaseClosure = script.IndexOf(
            "Assert-ReleasePackageFileSet -Root $ReleaseRoot -ExpectedFiles $expectedReleaseFiles",
            StringComparison.Ordinal);

        Assert.True(reproducibility >= 0, "release_reproducibility_gate_missing");
        Assert.True(packageClosure > reproducibility, "release_payload_closure_must_follow_reproducibility");
        Assert.True(signer > packageClosure, "release_signing_must_follow_unsigned_reproducibility_and_payload_closure");
        Assert.True(mainArchive > signer, "release_archive_must_follow_signing");
        Assert.True(mainSetup > mainArchive, "release_main_setup_must_follow_signed_archive");
        Assert.True(pdfSetup > mainSetup, "release_pdf_setup_must_follow_main_setup");
        Assert.True(releaseClosure > pdfSetup, "release_closure_must_follow_both_setups");
        Assert.Contains("SIMPLYSIGN_SIGNING_BASE_URL", script, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_SIGNING_BEARER_TOKEN", script, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL", script, StringComparison.Ordinal);
        Assert.Contains("Invoke-SimplySignArtifact", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_build_produces_two_signed_offline_setup_packages()
    {
        var script = ReadBuildScript();
        var helperBuild = script.IndexOf("'run', 'pyinstaller'", StringComparison.Ordinal);
        var helperValidation = script.IndexOf(
            "'frozen_executable_validates_real_pades_and_probe_surface'",
            StringComparison.Ordinal);
        var helperSign = script.IndexOf("-IdempotencyPrefix 'release-pdf-helper'", StringComparison.Ordinal);
        var helperHash = script.IndexOf(
            "Get-LowerSha256 -Path $pdfHelperArtifactPath",
            StringComparison.Ordinal);
        var manifest = script.IndexOf("Write-PdfExtensionManifest", helperHash + 1, StringComparison.Ordinal);
        var pdfArchive = script.IndexOf(
            "New-DeterministicZip -SourceRoot $pdfPackageRoot",
            StringComparison.Ordinal);
        var mainArchive = script.IndexOf(
            "New-DeterministicZip -SourceRoot $packageRoot",
            StringComparison.Ordinal);
        var mainSetup = script.IndexOf("-PublishName 'main'", StringComparison.Ordinal);
        var pdfSetup = script.IndexOf("-PublishName 'pdf'", StringComparison.Ordinal);
        var releaseClosure = script.IndexOf(
            "Assert-ReleasePackageFileSet -Root $ReleaseRoot -ExpectedFiles $expectedReleaseFiles",
            StringComparison.Ordinal);

        Assert.True(helperBuild >= 0 && helperValidation > helperBuild);
        Assert.True(mainSetup > mainArchive && helperSign > mainSetup);
        Assert.True(helperSign > helperValidation && helperHash > helperSign);
        Assert.True(manifest > helperHash && pdfArchive > manifest);
        Assert.True(pdfSetup > pdfArchive && releaseClosure > pdfSetup);
        Assert.Contains("SimplySignAutoSetup-$Version-win-x64.exe", script, StringComparison.Ordinal);
        Assert.Contains("SimplySignAutoPdfSetup-$Version-win-x64.exe", script, StringComparison.Ordinal);
        Assert.Contains("function Publish-SetupArtifact", script, StringComparison.Ordinal);
        Assert.Contains("Join-Path $RepoRoot 'LICENSE'", script, StringComparison.Ordinal);
        Assert.Equal(2, Count(script, "Join-Path $RepoRoot 'THIRD-PARTY-NOTICES.txt'"));
        Assert.Contains("Join-Path $pdfPackageRoot 'LICENSE.txt'", script, StringComparison.Ordinal);
        Assert.Contains("Join-Path $pdfPackageRoot 'THIRD-PARTY-NOTICES.txt'", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_pdf_helper_uses_only_trusted_windows_fonts()
    {
        var repositoryRoot = FindRepositoryRoot();
        var script = ReadBuildScript();
        var spec = File.ReadAllText(Path.Combine(repositoryRoot, "tools", "pdf-signer", "pdf-signer.spec"));
        var notices = File.ReadAllText(Path.Combine(repositoryRoot, "THIRD-PARTY-NOTICES.txt"));

        Assert.DoesNotContain("Get-PinnedReleaseInput", script, StringComparison.Ordinal);
        Assert.DoesNotContain("notofonts/noto-cjk", script, StringComparison.Ordinal);
        Assert.DoesNotContain("SIMPLYSIGN_PDF_FONT_PATH", spec, StringComparison.Ordinal);
        Assert.DoesNotContain("SIMPLYSIGN_PDF_FONT_LICENSE_PATH", spec, StringComparison.Ordinal);
        Assert.Contains("datas = []", spec, StringComparison.Ordinal);
        Assert.DoesNotContain("Noto Sans CJK SC 2.004", notices, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Windows_release_writes_the_exact_pdf_extension_manifest()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-pdf-manifest-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var output = Path.Combine(root, "extension.json");
        var harness = Path.Combine(root, "manifest.ps1");
        File.WriteAllText(
            harness,
            "param([string]$BuildScript,[string]$OutputPath)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "Write-PdfExtensionManifest -OutputPath $OutputPath -ProductVersion '1.2.3' -HelperVersion '0.1.0' -HelperLength 42 -HelperSha256 ('a' * 64) -PublisherCertificateSha256 ('b' * 64)\n",
            new UTF8Encoding(false));
        try
        {
            var result = RunPowerShell(
                harness,
                ["-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"), "-OutputPath", output],
                environment: null);

            Assert.Equal(0, result.ExitCode);
            using var manifest = JsonDocument.Parse(File.ReadAllBytes(output));
            Assert.Equal(
                [
                    "helperLength", "helperSha256", "helperVersion", "productVersion",
                    "publisherCertificateSha256", "schemaVersion",
                ],
                manifest.RootElement.EnumerateObject().Select(item => item.Name).Order().ToArray());
            Assert.Equal(42, manifest.RootElement.GetProperty("helperLength").GetInt64());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [WindowsFact]
    public void Windows_setup_metadata_binds_each_payload_to_its_product_kind()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-setup-metadata-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var payload = Path.Combine(root, "payload.zip");
        var main = Path.Combine(root, "main.json");
        var pdf = Path.Combine(root, "pdf.json");
        var harness = Path.Combine(root, "metadata.ps1");
        File.WriteAllBytes(payload, "payload"u8.ToArray());
        File.WriteAllText(
            harness,
            "param([string]$BuildScript,[string]$Payload,[string]$Main,[string]$Pdf)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "Write-SetupPayloadMetadata -PayloadPath $Payload -OutputPath $Main -ProductKind main -PublisherCertificateSha256 ('b' * 64)\n" +
            "Write-SetupPayloadMetadata -PayloadPath $Payload -OutputPath $Pdf -ProductKind pdf-extension -PublisherCertificateSha256 ('b' * 64)\n",
            new UTF8Encoding(false));
        try
        {
            var result = RunPowerShell(
                harness,
                [
                    "-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                    "-Payload", payload, "-Main", main, "-Pdf", pdf,
                ],
                environment: null);

            Assert.True(
                result.ExitCode == 0,
                $"powershell_exit_{result.ExitCode}: {result.StandardError}");
            using var mainMetadata = JsonDocument.Parse(File.ReadAllBytes(main));
            using var pdfMetadata = JsonDocument.Parse(File.ReadAllBytes(pdf));
            Assert.Equal("main", mainMetadata.RootElement.GetProperty("productKind").GetString());
            Assert.Equal("pdf-extension", pdfMetadata.RootElement.GetProperty("productKind").GetString());
            Assert.Equal(
                mainMetadata.RootElement.GetProperty("payloadSha256").GetString(),
                pdfMetadata.RootElement.GetProperty("payloadSha256").GetString());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [WindowsFact]
    public void Windows_publish_payload_policy_rejects_loose_runtime_python_helper_and_other_languages()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-policy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var harness = Path.Combine(root, "payload-policy.ps1");
        File.WriteAllText(
            harness,
            "param([string]$BuildScript)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "$allowed=@('SimplySignAuto.exe','e_sqlite3.dll')\n" +
            "Assert-PublishPayloadPolicy -RelativePaths $allowed\n" +
            "$withRuntimeConfig=@('SimplySignAuto.exe','e_sqlite3.dll','SimplySignAuto.runtimeconfig.json')\n" +
            "Assert-PublishPayloadPolicy -RelativePaths $withRuntimeConfig\n" +
            "$forbidden=@('dotnet-runtime-10.0.1-win-x64.exe','windowsdesktop-runtime-10.0.1-win-x64.exe','aspnetcore-runtime-10.0.1-win-x64.exe','python.exe','python313.dll','module.pyd','base_library.zip','lib/python3.13/os.py','SimplySignPdfSigner.exe','embedded-tools.json','nested/runtime/hostfxr.dll','hostpolicy.dll','coreclr.dll','clrjit.dll','SimplySignAuto.pdb','zh-Hans/SimplySignAuto.resources.dll','en/SimplySignAuto.resources.dll','fr/SimplySignAuto.resources.dll','unexpected.txt')\n" +
            "foreach($path in $forbidden){try{Assert-PublishPayloadPolicy -RelativePaths @('SimplySignAuto.exe','e_sqlite3.dll',$path);throw 'forbidden_payload_accepted'}catch{if($_.Exception.Message-cne'release_publish_payload_forbidden'){throw}}}\n" +
            "try{Assert-PublishPayloadPolicy -RelativePaths @('SimplySignAuto.exe');throw 'missing_payload_accepted'}catch{if($_.Exception.Message-cne'release_publish_payload_missing'){throw}}\n" +
            "[Console]::Out.WriteLine('release_publish_policy_ok')\n",
            new UTF8Encoding(false));
        try
        {
            var result = RunPowerShell(
                harness,
                ["-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1")],
                environment: null);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("release_publish_policy_ok", result.StandardOutput, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Release_signing_orders_exe_before_the_closed_signed_catalog()
    {
        var signer = ReadSigningScript();
        var application = signer.IndexOf(
            "Invoke-RemoteArtifactSignInPlace `\n        -Path $applicationPath",
            StringComparison.Ordinal);
        var publisherIdentity = signer.IndexOf(
            "Write-PublisherIdentity -Path $prerequisiteScriptPath",
            StringComparison.Ordinal);
        var catalogCreation = signer.IndexOf("New-FileCatalog -Path $PackageRoot", StringComparison.Ordinal);
        var catalogSigning = signer.IndexOf(
            "Invoke-RemoteArtifactSignInPlace `\n            -Path $temporaryCatalogPath",
            StringComparison.Ordinal);
        var catalogVerification = signer.IndexOf("Test-FileCatalog", StringComparison.Ordinal);

        Assert.True(application >= 0, "release_application_signing_missing");
        Assert.True(publisherIdentity > application, "release_publisher_identity_must_follow_application_signing");
        Assert.True(catalogCreation > publisherIdentity, "release_catalog_must_cover_the_frozen_payload_bytes");
        Assert.True(catalogSigning > catalogCreation, "release_catalog_signing_must_follow_catalog_creation");
        Assert.True(catalogVerification > catalogSigning, "release_catalog_verification_must_follow_catalog_signing");
        Assert.Contains("release-files.cat", signer, StringComparison.Ordinal);
        Assert.Contains("CatalogItems.Keys", signer, StringComparison.Ordinal);
        Assert.Contains("PathItems.Keys", signer, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature", signer, StringComparison.Ordinal);
        Assert.Contains("SignatureStatus]::Valid", signer, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Release_media_signer_rejects_missing_remote_signing_parameters_before_mutation()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-cmdless-media-{Guid.NewGuid():N}");
        var packageRoot = Path.Combine(root, "package");
        Directory.CreateDirectory(packageRoot);
        File.WriteAllText(Path.Combine(packageRoot, "SimplySignAuto.exe"), "unsigned-app", new UTF8Encoding(false));
        File.WriteAllText(
            Path.Combine(packageRoot, "install-prerequisites.ps1"),
            "$releasePublisherCertificateSha256 = '__SIMPLYSIGNAUTO_PUBLISHER_CERTIFICATE_SHA256__'",
            new UTF8Encoding(false));
        try
        {
            var result = RunPowerShell(
                Path.Combine(FindRepositoryRoot(), "scripts", "sign-release-media.ps1"),
                [
                    "-PackageRoot", packageRoot,
                ],
                new Dictionary<string, string>
                {
                    ["SIMPLYSIGN_SIGNING_BASE_URL"] = string.Empty,
                    ["SIMPLYSIGN_SIGNING_BEARER_TOKEN"] = string.Empty,
                    ["SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL"] = string.Empty,
                });

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("release_signing_parameters_invalid", result.StandardError, StringComparison.Ordinal);
            Assert.Equal("unsigned-app", File.ReadAllText(Path.Combine(packageRoot, "SimplySignAuto.exe")));
            Assert.False(File.Exists(Path.Combine(packageRoot, "release-files.cat")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Release_managed_hashes_target_the_exact_framework_dependent_publish_inputs()
    {
        var script = ReadBuildScript();

        Assert.Contains("src/SimplySignAuto.App", script, StringComparison.Ordinal);
        Assert.Contains("bin/Release/net10.0-windows/win-x64", script, StringComparison.Ordinal);
        Assert.Contains("net10.0-windows", script, StringComparison.Ordinal);
        Assert.Contains("win-x64", script, StringComparison.Ordinal);
    }

    [WindowsFact]
    public void Windows_managed_hash_reader_uses_all_five_exact_framework_dependent_publish_inputs()
    {
        var fixture = CreateManagedOutputFixture();
        try
        {
            var result = RunPowerShell(
                fixture.Harness,
                [
                    "-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                    "-RepoRoot", fixture.Root
                ],
                environment: null);

            Assert.True(
                result.ExitCode == 0,
                $"powershell_exit_{result.ExitCode}: {result.StandardError}");
            var actual = result.StandardOutput
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Split('=', 2))
                .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.Ordinal);
            Assert.Equal(fixture.ExpectedHashes, actual);

            File.Delete(Path.Combine(fixture.BundleRoot, "SimplySignAuto.Service.dll"));
            var missing = RunPowerShell(
                fixture.Harness,
                [
                    "-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                    "-RepoRoot", fixture.Root
                ],
                environment: null);
            Assert.NotEqual(0, missing.ExitCode);
            Assert.Contains("release_managed_output_missing", missing.StandardError, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [WindowsFact]
    public void Windows_release_publish_payload_copy_preserves_the_exact_framework_dependent_files()
    {
        var fixture = CreatePublishPayloadFixture();
        try
        {
            var result = RunPowerShell(
                fixture.Harness,
                [
                    "-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                    "-PublishRoot", fixture.PublishRoot,
                    "-PackageRoot", fixture.PackageRoot
                ],
                environment: null);

            Assert.Equal(0, result.ExitCode);
            var actualPaths = Directory.GetFiles(fixture.PackageRoot, "*", SearchOption.AllDirectories)
                .Select(path => Path.GetRelativePath(fixture.PackageRoot, path).Replace('\\', '/'))
                .Order(StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(fixture.Files.Keys.Order(StringComparer.Ordinal).ToArray(), actualPaths);
            foreach (var file in fixture.Files)
            {
                Assert.Equal(file.Value, File.ReadAllBytes(Path.Combine(fixture.PackageRoot, file.Key)));
            }
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    [WindowsFact]
    public void Windows_release_tree_rejects_hardlinks_before_signing()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-hardlink-{Guid.NewGuid():N}");
        var packageRoot = Path.Combine(root, "package");
        var harness = Path.Combine(root, "tree-contract.ps1");
        Directory.CreateDirectory(packageRoot);
        File.WriteAllText(Path.Combine(packageRoot, "payload.json"), "{}", new UTF8Encoding(false));
        Assert.True(
            CreateHardLinkW(
                Path.Combine(packageRoot, "payload-link.json"),
                Path.Combine(packageRoot, "payload.json"),
                IntPtr.Zero),
            $"CreateHardLinkW failed with {Marshal.GetLastWin32Error()}.");
        File.WriteAllText(
            harness,
            "param([string]$BuildScript,[string]$PackageRoot)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "Assert-ReleaseTree -Root $PackageRoot\n",
            new UTF8Encoding(false));
        try
        {
            var result = RunPowerShell(
                harness,
                [
                    "-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                    "-PackageRoot", packageRoot
                ],
                environment: null);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("release_package_link_invalid", result.StandardError, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [WindowsFact]
    public void Windows_catalog_closes_nested_payload_and_detects_byte_mutation()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-catalog-{Guid.NewGuid():N}");
        var packageRoot = Path.Combine(root, "package");
        var catalogPath = Path.Combine(root, "release-files.cat");
        var harness = Path.Combine(root, "catalog-contract.ps1");
        Directory.CreateDirectory(Path.Combine(packageRoot, "zh-Hans"));
        Directory.CreateDirectory(Path.Combine(packageRoot, "en"));
        var files = new[]
        {
            "SimplySignAuto.exe",
            "install-prerequisites.ps1",
            "runtime-prerequisites.json",
            "sbom.spdx.json",
            "README.txt",
            "zh-Hans/SimplySignAuto.resources.dll",
            "en/SimplySignAuto.resources.dll",
        };
        foreach (var relative in files)
        {
            var path = Path.Combine(packageRoot, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, $"payload:{relative}", new UTF8Encoding(false));
        }
        File.WriteAllText(
            harness,
            "param([string]$PackageRoot,[string]$CatalogPath)\n" +
            "$ErrorActionPreference='Stop'\n" +
            "$null=New-FileCatalog -Path $PackageRoot -CatalogFilePath $CatalogPath -CatalogVersion 2.0\n" +
            "$first=Test-FileCatalog -Detailed -Path $PackageRoot -CatalogFilePath $CatalogPath\n" +
            "$expected=@(Get-ChildItem -LiteralPath $PackageRoot -Recurse -File | ForEach-Object {$_.FullName.Substring($PackageRoot.Length).TrimStart('\\','/').Replace('\\','/')} | Sort-Object)\n" +
            "$catalog=@($first.CatalogItems.Keys | ForEach-Object {$_.Replace('\\','/')} | Sort-Object)\n" +
            "$paths=@($first.PathItems.Keys | ForEach-Object {$_.Replace('\\','/')} | Sort-Object)\n" +
            "if([string]$first.Status-cne'Valid'-or@(Compare-Object $expected $catalog -CaseSensitive).Count-ne0-or@(Compare-Object $expected $paths -CaseSensitive).Count-ne0){throw'catalog_initial_invalid'}\n" +
            "$inside=Join-Path $PackageRoot 'release-files.cat';[IO.File]::Move($CatalogPath,$inside)\n" +
            "$closed=Test-FileCatalog -Detailed -Path $PackageRoot -CatalogFilePath $inside -FilesToSkip 'release-files.cat'\n" +
            "if([string]$closed.Status-cne'Valid'){throw'catalog_closed_invalid'}\n" +
            "[IO.File]::AppendAllText((Join-Path $PackageRoot 'runtime-prerequisites.json'),'tampered')\n" +
            "$tampered=Test-FileCatalog -Detailed -Path $PackageRoot -CatalogFilePath $inside -FilesToSkip 'release-files.cat'\n" +
            "if([string]$tampered.Status-ceq'Valid'){throw'catalog_mutation_not_detected'}\n" +
            "[Console]::Out.WriteLine('catalog_nested_tamper_ok')\n",
            new UTF8Encoding(false));
        try
        {
            var result = RunPowerShell(
                harness,
                ["-PackageRoot", packageRoot, "-CatalogPath", catalogPath],
                environment: null);

            Assert.True(
                result.ExitCode == 0,
                $"powershell_exit_{result.ExitCode}: {result.StandardError}");
            Assert.Contains("catalog_nested_tamper_ok", result.StandardOutput, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [WindowsFact]
    public void Windows_checked_command_output_does_not_pollute_the_callers_result_object()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-output-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var harness = Path.Combine(root, "checked-output.ps1");
        File.WriteAllText(
            harness,
            "param([string]$BuildScript,[string]$WorkingDirectory)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "$captured = @(\n" +
            "    Invoke-Checked -FilePath $env:ComSpec -ArgumentList @('/d','/c','echo native-output') -WorkingDirectory $WorkingDirectory\n" +
            "    [pscustomobject]@{ Files = @('only-result') }\n" +
            ")\n" +
            "if ($captured.Count -ne 1 -or $captured[0].Files[0] -cne 'only-result') { throw 'release_checked_output_leaked' }\n",
            new UTF8Encoding(false));
        try
        {
            var result = RunPowerShell(
                harness,
                [
                    "-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                    "-WorkingDirectory", root
                ],
                environment: null);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("native-output", result.StandardOutput, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [WindowsFact]
    public void Windows_release_gate_enforces_TRX_closure_and_PowerShell_File_exit_semantics()
    {
        var fixture = CreateGateFixture();
        try
        {
            var failures = new (string Mode, string Error)[]
            {
                ("failed", "release_test_result_failed"),
                ("missing", "release_test_result_missing"),
                ("native-failure", "release_test_command_failed"),
                ("extra", "release_test_project_closure_mismatch"),
                ("wrong-namespace", "release_test_result_invalid"),
                ("empty-namespace", "release_test_result_invalid"),
                ("wrong-root", "release_test_result_invalid"),
                ("duplicate-summary", "release_test_result_invalid"),
                ("duplicate-counters", "release_test_result_invalid"),
                ("dtd", "release_test_result_invalid"),
                ("missing-field", "release_test_result_invalid"),
                ("negative", "release_test_result_invalid"),
                ("overflow", "release_test_result_invalid")
            };
            foreach (var failure in failures)
            {
                if (Directory.Exists(fixture.ResultsRoot))
                {
                    Directory.Delete(fixture.ResultsRoot, recursive: true);
                }

                var result = RunGate(fixture, failure.Mode);
                Assert.NotEqual(0, result.ExitCode);
                Assert.Contains(failure.Error, result.StandardError, StringComparison.Ordinal);
                Assert.DoesNotContain("release_ok", result.StandardOutput, StringComparison.Ordinal);
            }

            Directory.Delete(fixture.ResultsRoot, recursive: true);
            var passed = RunGate(fixture, "pass");
            Assert.Equal(0, passed.ExitCode);
            Assert.Equal(
                ExpectedTestProjects.Order(StringComparer.Ordinal).ToArray(),
                Directory.GetFiles(fixture.ResultsRoot, "*.trx")
                    .Select(Path.GetFileNameWithoutExtension)
                    .Order(StringComparer.Ordinal)
                    .ToArray());

            var entryFailure = RunPowerShell(
                Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                ["-Version", "not-a-version"],
                environment: null);
            Assert.NotEqual(0, entryFailure.ExitCode);
            Assert.DoesNotContain("release_ok", entryFailure.StandardOutput, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(fixture.Root, recursive: true);
        }
    }

    private static string ReadBuildScript() =>
        File.ReadAllText(Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"));

    private static string ReadSigningScript() =>
        File.ReadAllText(Path.Combine(FindRepositoryRoot(), "scripts", "sign-release-media.ps1"))
            .Replace("\r\n", "\n", StringComparison.Ordinal);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    private static int Count(string value, string pattern)
    {
        var count = 0;
        var offset = 0;
        while ((offset = value.IndexOf(pattern, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += pattern.Length;
        }

        return count;
    }

    private static string LowerSha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    private static PowerShellResult RunPowerShell(
        string script,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment)
    {
        var startInfo = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(script);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        if (environment is not null)
        {
            foreach (var pair in environment)
            {
                startInfo.Environment[pair.Key] = pair.Value;
            }
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("powershell_start_failed");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromSeconds(30)))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException("powershell_timeout");
        }

        return new PowerShellResult(
            process.ExitCode,
            standardOutput.GetAwaiter().GetResult(),
            standardError.GetAwaiter().GetResult());
    }

    private sealed record PowerShellResult(int ExitCode, string StandardOutput, string StandardError);

    private static GateFixture CreateGateFixture()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-gate-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var fixture = new GateFixture(
            root,
            Path.Combine(root, "gate.ps1"),
            Path.Combine(root, "fake-dotnet.cmd"),
            Path.Combine(root, "fake-dotnet.ps1"),
            Path.Combine(root, "results"));
        File.WriteAllText(
            fixture.Harness,
            "param([string]$BuildScript,[string]$RepoRoot,[string]$ResultsRoot,[string]$FakeDotnet)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "Invoke-ReleaseTestSuite -Dotnet $FakeDotnet -RepoRoot $RepoRoot -ResultsRoot $ResultsRoot\n",
            new UTF8Encoding(false));
        File.WriteAllText(
            fixture.FakeCommand,
            "@echo off\r\npowershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%SSA_FAKE_DOTNET_SCRIPT%\" %*\r\nexit /b %ERRORLEVEL%\r\n",
            Encoding.ASCII);
        File.WriteAllText(
            fixture.FakeScript,
            """
            $ErrorActionPreference = 'Stop'
            $project = @($args | Where-Object { $_ -like '*.csproj' })[0]
            $projectName = [IO.Path]::GetFileNameWithoutExtension($project)
            $logger = $null
            $resultsRoot = $null
            for ($index = 0; $index -lt $args.Count; $index++) {
                if ($args[$index] -eq '--logger') { $logger = $args[$index + 1] }
                if ($args[$index] -eq '--results-directory') { $resultsRoot = $args[$index + 1] }
            }
            if ($env:SSA_FAKE_TRX_MODE -eq 'missing' -and $projectName -eq 'SimplySignAuto.UI.Tests') { exit 0 }
            $failed = if ($env:SSA_FAKE_TRX_MODE -eq 'failed' -and $projectName -eq 'SimplySignAuto.Agent.Tests') { 1 } else { 0 }
            $passed = if ($failed -eq 0) { 1 } else { 0 }
            $logName = @($logger -split 'LogFileName=', 2)[1]
            [IO.Directory]::CreateDirectory($resultsRoot) | Out-Null
            $counters = '<Counters total="1" executed="1" passed="' + $passed + '" failed="' + $failed + '" error="0" timeout="0" aborted="0" />'
            $xml = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary>' + $counters + '</ResultSummary></TestRun>'
            switch ($env:SSA_FAKE_TRX_MODE) {
                'wrong-namespace' { $xml = $xml.Replace('http://microsoft.com/schemas/VisualStudio/TeamTest/2010', 'urn:wrong') }
                'empty-namespace' { $xml = $xml.Replace(' xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"', '') }
                'wrong-root' { $xml = $xml.Replace('<TestRun ', '<NotTestRun ').Replace('</TestRun>', '</NotTestRun>') }
                'duplicate-summary' { $xml = $xml.Replace('</TestRun>', '<ResultSummary>' + $counters + '</ResultSummary></TestRun>') }
                'duplicate-counters' { $xml = $xml.Replace('</ResultSummary>', $counters + '</ResultSummary>') }
                'dtd' { $xml = '<!DOCTYPE TestRun [<!ENTITY x "value">]>' + $xml }
                'missing-field' { $xml = $xml.Replace(' timeout="0"', '') }
                'negative' { $xml = $xml.Replace(' error="0"', ' error="-1"') }
                'overflow' { $xml = $xml.Replace(' total="1"', ' total="2147483648"') }
            }
            [IO.File]::WriteAllText((Join-Path $resultsRoot $logName), $xml, [Text.UTF8Encoding]::new($false))
            if ($env:SSA_FAKE_TRX_MODE -eq 'extra' -and $projectName -eq 'SimplySignAuto.EndToEnd.Tests') {
                [IO.File]::WriteAllText((Join-Path $resultsRoot 'unexpected.trx'), $xml, [Text.UTF8Encoding]::new($false))
            }
            if ($env:SSA_FAKE_TRX_MODE -eq 'native-failure' -and $projectName -eq 'SimplySignAuto.Agent.Tests') { exit 7 }
            exit 0
            """,
            new UTF8Encoding(false));
        return fixture;
    }

    private static PowerShellResult RunGate(GateFixture fixture, string mode) =>
        RunPowerShell(
            fixture.Harness,
            [
                "-BuildScript", Path.Combine(FindRepositoryRoot(), "scripts", "build-release.ps1"),
                "-RepoRoot", FindRepositoryRoot(),
                "-ResultsRoot", fixture.ResultsRoot,
                "-FakeDotnet", fixture.FakeCommand
            ],
            new Dictionary<string, string>
            {
                ["SSA_FAKE_DOTNET_SCRIPT"] = fixture.FakeScript,
                ["SSA_FAKE_TRX_MODE"] = mode
            });

    private sealed record GateFixture(
        string Root,
        string Harness,
        string FakeCommand,
        string FakeScript,
        string ResultsRoot);

    private static PublishPayloadFixture CreatePublishPayloadFixture()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-publish-copy-{Guid.NewGuid():N}");
        var publishRoot = Path.Combine(root, "publish");
        var packageRoot = Path.Combine(root, "package");
        Directory.CreateDirectory(publishRoot);
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["SimplySignAuto.exe"] = Encoding.UTF8.GetBytes("host"),
            ["e_sqlite3.dll"] = Encoding.UTF8.GetBytes("native-sqlite"),
            ["SimplySignAuto.runtimeconfig.json"] = Encoding.UTF8.GetBytes("{}")
        };
        foreach (var file in files)
        {
            var path = Path.Combine(publishRoot, file.Key);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, file.Value);
        }

        var harness = Path.Combine(root, "copy-publish-payload.ps1");
        File.WriteAllText(
            harness,
            "param([string]$BuildScript,[string]$PublishRoot,[string]$PackageRoot)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "$copied = @(Copy-PublishPayload -PublishRoot $PublishRoot -PackageRoot $PackageRoot)\n" +
            "$expected = @('e_sqlite3.dll','SimplySignAuto.exe','SimplySignAuto.runtimeconfig.json')\n" +
            "if (@(Compare-Object -ReferenceObject $expected -DifferenceObject $copied -CaseSensitive).Count -ne 0) { throw 'release_publish_copy_manifest_invalid' }\n",
            new UTF8Encoding(false));
        return new PublishPayloadFixture(root, publishRoot, packageRoot, harness, files);
    }

    private sealed record PublishPayloadFixture(
        string Root,
        string PublishRoot,
        string PackageRoot,
        string Harness,
        IReadOnlyDictionary<string, byte[]> Files);

    private static ManagedOutputFixture CreateManagedOutputFixture()
    {
        var root = Path.Combine(Path.GetTempPath(), $"simplysign-release-managed-{Guid.NewGuid():N}");
        var bundleRoot = Path.Combine(
            root,
            "src",
            "SimplySignAuto.App",
            "bin",
            "Release",
            "net10.0-windows",
            "win-x64");
        Directory.CreateDirectory(bundleRoot);
        var names = new[]
        {
            "SimplySignAuto.Core",
            "SimplySignAuto.Protocol",
            "SimplySignAuto.Agent",
            "SimplySignAuto.Service",
            "SimplySignAuto"
        };
        var expected = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in names)
        {
            var content = Encoding.UTF8.GetBytes($"bundle-input:{name}");
            File.WriteAllBytes(Path.Combine(bundleRoot, $"{name}.dll"), content);
            expected[name] = Convert.ToHexStringLower(SHA256.HashData(content));

            var oldOutput = Path.Combine(root, "src", name, "obj", "Release", "net10.0-windows");
            Directory.CreateDirectory(oldOutput);
            File.WriteAllText(Path.Combine(oldOutput, $"{name}.dll"), $"rid-neutral-decoy:{name}");
        }

        var nonR2r = Directory.GetParent(bundleRoot)!.FullName;
        File.WriteAllText(Path.Combine(nonR2r, "SimplySignAuto.dll"), "non-r2r-app-decoy");
        var harness = Path.Combine(root, "managed-hashes.ps1");
        File.WriteAllText(
            harness,
            "param([string]$BuildScript,[string]$RepoRoot)\n" +
            ". $BuildScript -Version '1.2.3'\n" +
            "$hashes = Get-ManagedAssemblyHashes -RepoRoot $RepoRoot\n" +
            "foreach ($entry in $hashes.GetEnumerator()) { [Console]::Out.WriteLine($entry.Key + '=' + $entry.Value) }\n",
            new UTF8Encoding(false));
        return new ManagedOutputFixture(root, harness, bundleRoot, expected);
    }

    private sealed record ManagedOutputFixture(
        string Root,
        string Harness,
        string BundleRoot,
        IReadOnlyDictionary<string, string> ExpectedHashes);

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
}
