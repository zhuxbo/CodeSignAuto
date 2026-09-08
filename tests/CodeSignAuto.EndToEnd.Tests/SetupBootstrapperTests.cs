using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using CodeSignAuto.App.Commands;
using CodeSignAuto.Setup;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class SetupBootstrapperTests
{
    [Theory]
    [InlineData("--silent")]
    [InlineData("/repair")]
    public void Public_setup_rejects_all_command_line_arguments(string argument)
    {
        var failure = Assert.Throws<SetupBootstrapperException>(() =>
            SetupCommandLine.Validate([argument]));

        Assert.Equal("setup_arguments_invalid", failure.Code);
    }

    [Theory]
    [InlineData("required_runtime_missing", ".NET 10", "https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime")]
    [InlineData("simplysign_desktop_missing", "SimplySign Desktop", "https://support.certum.eu/en/software/procertum-smartsign/")]
    [InlineData("simplysign_pkcs11_missing", "SimplySignPKCS.dll", "修复或重新安装")]
    [InlineData("os_unsupported", "不支持当前 Windows", "Windows Server 2019/2022/2025")]
    [InlineData("desktop_experience_required", "Desktop Experience", "不支持 Server Core")]
    [InlineData("architecture_unsupported", "x64", "64 位")]
    [InlineData("elevation_required", "管理员", "重新运行")]
    [InlineData("domain_controller_unsupported", "域控制器", "成员服务器")]
    [InlineData("autologon_conflict", "自动登录", "不会覆盖")]
    [InlineData("autologon_plaintext_password_present", "仍保存自动登录凭据", "安全移除")]
    public void Missing_prerequisites_have_actionable_localized_messages(
        string code,
        string expectedReason,
        string expectedAction)
    {
        var failure = new SetupBootstrapperException(code);
        var message = failure.GetLocalizedMessage(SetupCulture.ResolveSelection("zh-CN"));

        Assert.Equal(code, failure.Code);
        Assert.Contains(expectedReason, message, StringComparison.Ordinal);
        Assert.Contains(expectedAction, message, StringComparison.Ordinal);
        Assert.Contains($"错误代码：{code}", message, StringComparison.Ordinal);
    }

    [Fact]
    public void AutoLogon_conflict_safely_displays_only_the_detected_account_and_manual_option()
    {
        var account = Assert.IsType<string>(SetupAutoLogonConflict.FormatAccountName(
            "administrator",
            "SIGNING-SERVER"));
        var failure = new SetupBootstrapperException("autologon_conflict");

        var message = failure.GetLocalizedMessage(
            SetupCulture.ResolveSelection("zh-CN"),
            account);

        Assert.Equal(@"SIGNING-SERVER\administrator", account);
        Assert.Contains(account, message, StringComparison.Ordinal);
        Assert.Contains("手工签名模式", message, StringComparison.Ordinal);
        Assert.Contains("不会覆盖", message, StringComparison.Ordinal);
        Assert.DoesNotContain("password", message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(SetupAutoLogonConflict.FormatAccountName("bad\nname", "DOMAIN"));
    }

    [Theory]
    [InlineData("autologon_conflict", "Service", true, true)]
    [InlineData("autologon_conflict", "Manual", true, false)]
    [InlineData("autologon_conflict", "Service", false, false)]
    [InlineData("autologon_plaintext_password_present", "Service", true, true)]
    public void Changeable_service_AutoLogon_issues_return_to_mode_selection(
        string code,
        string modeName,
        bool canChange,
        bool expected)
    {
        var mode = Enum.Parse<SetupInstallationMode>(modeName);

        Assert.Equal(expected, SetupFailurePolicy.CanReturnToModeSelection(
            SetupProductKind.Main,
            mode,
            canChange,
            code));
    }

    [Fact]
    public void Unknown_setup_failure_is_actionable_without_exposing_an_exception()
    {
        var failure = new SetupBootstrapperException("setup_resource_conflict");
        var message = failure.GetLocalizedMessage(SetupCulture.ResolveSelection("zh-CN"));

        Assert.Contains("安装未完成", message, StringComparison.Ordinal);
        Assert.Contains("错误代码：setup_resource_conflict", message, StringComparison.Ordinal);
        Assert.DoesNotContain("Exception", message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Product_failure_with_an_auxiliary_code_uses_the_primary_actionable_error()
    {
        var failure = new SetupBootstrapperException(
            "simplysign_desktop_missing install_simplysign_desktop_required");
        var message = failure.GetLocalizedMessage(SetupCulture.ResolveSelection("zh-CN"));

        Assert.Equal("simplysign_desktop_missing", failure.Code);
        Assert.Contains("SimplySign Desktop", message, StringComparison.Ordinal);
        Assert.Contains(
            "错误代码：simplysign_desktop_missing install_simplysign_desktop_required",
            message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Payload_metadata_is_strict_and_complete()
    {
        var metadata = SetupPayloadMetadataCodec.Decode(Encoding.UTF8.GetBytes("""
            {
              "schemaVersion": 1,
              "productKind": "main",
              "productVersion": "0.14.0",
              "payloadLength": 123,
              "payloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "publisherCertificateSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
            """));

        Assert.Equal(1, metadata.SchemaVersion);
        Assert.Equal(SetupProductKind.Main, metadata.ProductKind);
        Assert.Equal("0.14.0", metadata.ProductVersion);
        Assert.Equal(123, metadata.PayloadLength);
        Assert.Equal(new string('a', 64), metadata.PayloadSha256);
        Assert.Equal(new string('b', 64), metadata.PublisherCertificateSha256);

        var unknown = Assert.Throws<SetupBootstrapperException>(() =>
            SetupPayloadMetadataCodec.Decode(Encoding.UTF8.GetBytes("""
                {
                  "schemaVersion": 1,
                  "productKind": "main",
                  "productVersion": "0.14.0",
                  "payloadLength": 123,
                  "payloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "publisherCertificateSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                  "legacy": true
                }
                """)));
        Assert.Equal("setup_payload_invalid", unknown.Code);

        var duplicate = Assert.Throws<SetupBootstrapperException>(() =>
            SetupPayloadMetadataCodec.Decode(Encoding.UTF8.GetBytes("""
                {
                  "schemaVersion": 1,
                  "schemaVersion": 1,
                  "productKind": "main",
                  "productVersion": "0.14.0",
                  "payloadLength": 123,
                  "payloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "publisherCertificateSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }
                """)));
        Assert.Equal("setup_payload_invalid", duplicate.Code);
    }

    [Theory]
    [InlineData("main", "Main")]
    [InlineData("pdf-extension", "PdfExtension")]
    public void Payload_metadata_requires_one_exact_product_kind(
        string productKind,
        string expected)
    {
        var metadata = SetupPayloadMetadataCodec.Decode(Encoding.UTF8.GetBytes($$"""
            {
              "schemaVersion": 1,
              "productKind": "{{productKind}}",
              "productVersion": "0.14.0",
              "payloadLength": 123,
              "payloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "publisherCertificateSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
            """));

        Assert.Equal(expected, metadata.ProductKind.ToString());
    }

    [Theory]
    [InlineData("../outside.txt")]
    [InlineData("nested/../../outside.txt")]
    [InlineData("C:/outside.txt")]
    [InlineData("/outside.txt")]
    public async Task Payload_archive_rejects_paths_outside_the_destination(string entryName)
    {
        var destination = Path.Combine(Path.GetTempPath(), "ssa-setup-archive-" + Guid.NewGuid().ToString("N"));
        await using var archiveBytes = new MemoryStream();
        using (var archive = new ZipArchive(archiveBytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry(entryName, CompressionLevel.NoCompression);
            await using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            await writer.WriteAsync("payload");
        }

        archiveBytes.Position = 0;
        try
        {
            var failure = await Assert.ThrowsAsync<SetupBootstrapperException>(() =>
                SetupPayloadArchive.ExtractAsync(archiveBytes, destination, CancellationToken.None));
            Assert.Equal("setup_payload_invalid", failure.Code);
            Assert.False(Directory.Exists(destination));
        }
        finally
        {
            if (Directory.Exists(destination))
            {
                Directory.Delete(destination, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Payload_archive_rejects_case_insensitive_duplicate_entries()
    {
        var destination = Path.Combine(Path.GetTempPath(), "ssa-setup-duplicate-" + Guid.NewGuid().ToString("N"));
        await using var archiveBytes = new MemoryStream();
        using (var archive = new ZipArchive(archiveBytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            await using (var first = archive.CreateEntry("nested/payload.txt").Open())
            {
                await first.WriteAsync("first"u8.ToArray());
            }

            await using (var second = archive.CreateEntry("NESTED/PAYLOAD.TXT").Open())
            {
                await second.WriteAsync("second"u8.ToArray());
            }
        }

        archiveBytes.Position = 0;
        var failure = await Assert.ThrowsAsync<SetupBootstrapperException>(() =>
            SetupPayloadArchive.ExtractAsync(archiveBytes, destination, CancellationToken.None));

        Assert.Equal("setup_payload_invalid", failure.Code);
        Assert.False(Directory.Exists(destination));
    }

    [Fact]
    public async Task Bootstrapper_runs_install_once_and_cleans_the_staged_payload()
    {
        var operations = new RecordingSetupOperations(installExitCode: 0);
        var bootstrapper = new SetupBootstrapper(operations);

        var exitCode = await bootstrapper.RunAsync(
            SetupInstallationMode.Manual,
            progress: null,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(["stage", "install:C:\\staged", "cleanup:C:\\staged"], operations.Events);
    }

    [Fact]
    public async Task Bootstrapper_remediation_uses_verified_main_payload_and_always_cleans_it()
    {
        var operations = new RecordingSetupOperations(installExitCode: 0);
        var bootstrapper = new SetupBootstrapper(operations);

        await bootstrapper.DisableAutoLogonAsync(
            progress: null,
            CancellationToken.None);

        Assert.Equal(
            ["stage", "disable-autologon:C:\\staged", "cleanup:C:\\staged"],
            operations.Events);
    }

    [Fact]
    public async Task Bootstrapper_cleans_the_staged_payload_after_install_failure()
    {
        var operations = new RecordingSetupOperations(installExitCode: 1);
        var bootstrapper = new SetupBootstrapper(operations);

        var exitCode = await bootstrapper.RunAsync(
            SetupInstallationMode.Manual,
            progress: null,
            CancellationToken.None);

        Assert.Equal(1, exitCode);
        Assert.Equal(["stage", "install:C:\\staged", "cleanup:C:\\staged"], operations.Events);
    }

    [Fact]
    public async Task Bootstrapper_progress_advances_only_after_real_completed_stages()
    {
        var operations = new RecordingSetupOperations(installExitCode: 0)
        {
            InstallProgress =
            [
                new SetupProgress(55, "运行时已验证"),
                new SetupProgress(95, "产品安装完成"),
            ],
        };
        var reported = new List<SetupProgress>();

        var exitCode = await new SetupBootstrapper(operations).RunAsync(
            SetupInstallationMode.Manual,
            new InlineProgress<SetupProgress>(reported.Add),
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(
            [25, 55, 95, 100],
            reported.Select(item => item.Percent));
        Assert.Equal("ProgressInstallComplete", reported[^1].Message);
        Assert.Equal(["stage", "install:C:\\staged", "cleanup:C:\\staged"], operations.Events);
    }

    [Fact]
    public async Task Failed_install_keeps_the_last_real_progress_value_after_cleanup()
    {
        var operations = new RecordingSetupOperations(installExitCode: 1)
        {
            InstallProgress = [new SetupProgress(55, "运行时已验证")],
        };
        var reported = new List<SetupProgress>();

        var exitCode = await new SetupBootstrapper(operations).RunAsync(
            SetupInstallationMode.Manual,
            new InlineProgress<SetupProgress>(reported.Add),
            CancellationToken.None);

        Assert.Equal(1, exitCode);
        Assert.Equal([25, 55], reported.Select(item => item.Percent));
        Assert.Equal(["stage", "install:C:\\staged", "cleanup:C:\\staged"], operations.Events);
    }

    [Fact]
    public async Task Setup_operations_reject_a_payload_hash_mismatch_before_workspace_creation()
    {
        var payload = CreatePayloadArchive();
        var events = new List<string>();
        var operations = new SetupBootstrapperOperations(
            new FixedPayloadSource(
                payload,
                Metadata(payload, payloadSha256: new string('0', 64)),
                events),
            new RecordingPublisherVerifier(events),
            new RecordingSetupWorkspace(events),
            new RecordingMediaRunner(events, installExitCode: 0));

        var failure = await Assert.ThrowsAsync<SetupBootstrapperException>(() =>
            operations.StageAsync(CancellationToken.None));

        Assert.Equal("setup_payload_invalid", failure.Code);
        Assert.Equal(["metadata", "publisher", "payload"], events);
    }

    [Fact]
    public async Task Setup_operations_reject_a_publisher_mismatch_before_payload_or_workspace_access()
    {
        var payload = CreatePayloadArchive();
        var events = new List<string>();
        var operations = new SetupBootstrapperOperations(
            new FixedPayloadSource(payload, Metadata(payload), events),
            new RejectingPublisherVerifier(events),
            new RecordingSetupWorkspace(events),
            new RecordingMediaRunner(events, installExitCode: 0));

        var failure = await Assert.ThrowsAsync<SetupBootstrapperException>(() =>
            operations.StageAsync(CancellationToken.None));

        Assert.Equal("setup_signature_invalid", failure.Code);
        Assert.Equal(["metadata", "publisher"], events);
    }

    [Fact]
    public async Task Setup_operations_stage_the_verified_payload_and_run_the_media_chain_once()
    {
        var root = Path.Combine(Path.GetTempPath(), "ssa-setup-operations-" + Guid.NewGuid().ToString("N"));
        var payload = CreatePayloadArchive();
        var events = new List<string>();
        var operations = new SetupBootstrapperOperations(
            new FixedPayloadSource(payload, Metadata(payload), events),
            new RecordingPublisherVerifier(events),
            new RecordingSetupWorkspace(events, root),
            new RecordingMediaRunner(events, installExitCode: 27));
        try
        {
            var staged = await operations.StageAsync(CancellationToken.None);
            var exitCode = await operations.InstallAsync(
                staged,
                SetupInstallationMode.Service,
                progress: null,
                CancellationToken.None);
            var stagedContent = await File.ReadAllTextAsync(Path.Combine(root, "nested", "payload.txt"));
            await operations.CleanupAsync(staged.MediaRoot);

            Assert.Equal(root, staged.MediaRoot);
            Assert.Equal(SetupProductKind.Main, staged.Metadata.ProductKind);
            Assert.Equal(27, exitCode);
            Assert.Equal("payload", stagedContent);
            Assert.Equal(
                ["metadata", "publisher", "payload", "workspace", "media", "cleanup"],
                events);
            Assert.False(Directory.Exists(root));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Setup_operations_await_publisher_verification_without_blocking_the_caller()
    {
        var root = Path.Combine(Path.GetTempPath(), "ssa-setup-async-publisher-" + Guid.NewGuid().ToString("N"));
        var payload = CreatePayloadArchive();
        var events = new List<string>();
        var verifier = new PausedPublisherVerifier();
        var operations = new SetupBootstrapperOperations(
            new FixedPayloadSource(payload, Metadata(payload), events),
            verifier,
            new RecordingSetupWorkspace(events, root),
            new RecordingMediaRunner(events, installExitCode: 0));
        try
        {
            var stage = operations.StageAsync(CancellationToken.None);

            Assert.False(stage.IsCompleted);
            verifier.Complete();
            var staged = await stage.WaitAsync(TimeSpan.FromSeconds(1));
            await operations.CleanupAsync(staged.MediaRoot);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task PowerShell_runner_verifies_the_closed_media_before_installing_it()
    {
        var invoker = new RecordingPowerShellInvoker([0, 27]);
        var runner = new WindowsSetupProcessRunner(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            invoker,
            @"C:\Program Files");

        var exitCode = await runner.RunAsync(
            SetupProductKind.Main,
            "C:\\media",
            SetupInstallationMode.Manual,
            progress: null,
            CancellationToken.None);

        Assert.Equal(27, exitCode);
        Assert.Equal(2, invoker.Arguments.Count);
        Assert.Equal(
            [
                "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", "C:\\media\\install-prerequisites.ps1",
                "-ReleaseMediaRoot", "C:\\media", "-InstallMode", "manual", "-VerifyMediaOnly",
            ],
            invoker.Arguments[0]);
        Assert.Equal(
            [
                "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", "C:\\media\\install-prerequisites.ps1",
                "-ReleaseMediaRoot", "C:\\media", "-InstallMode", "manual",
            ],
            invoker.Arguments[1]);
    }

    [Fact]
    public async Task PowerShell_runner_maps_only_observed_child_stages_to_monotonic_progress()
    {
        var invoker = new RecordingPowerShellInvoker(
            [0, 0],
            [
                ["phase=media code=ready"],
                [
                    "phase=media code=ready",
                    "phase=manifest code=ready",
                    "phase=preflight code=ready",
                    "phase=detection code=ready",
                    "phase=probe code=ready",
                    "phase=complete code=ready",
                ],
            ]);
        var reported = new List<SetupProgress>();
        var runner = new WindowsSetupProcessRunner(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            invoker,
            @"C:\Program Files");

        var exitCode = await runner.RunAsync(
            SetupProductKind.Main,
            "C:\\media",
            SetupInstallationMode.Service,
            new InlineProgress<SetupProgress>(reported.Add),
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal([35, 40, 45, 50, 90, 92], reported.Select(item => item.Percent));
        Assert.Equal(
            [
                "ProgressPublisherMediaVerified",
                "ProgressRuntimeManifestVerified",
                "ProgressSystemPrerequisitesComplete",
                "ProgressRuntimeStatusChecked",
                "ProgressLaunchConditionsVerified",
                "ProgressProductInitializationComplete",
            ],
            reported.Select(item => item.Message));
        Assert.All(reported, item =>
        {
            Assert.False(string.IsNullOrWhiteSpace(SetupCulture.GetString(
                item.Message,
                SetupCulture.ResolveSelection("zh-CN"))));
            Assert.False(string.IsNullOrWhiteSpace(SetupCulture.GetString(
                item.Message,
                SetupCulture.ResolveSelection("en-US"))));
        });
    }

    [Theory]
    [InlineData("preflight", "simplysign_desktop_missing")]
    [InlineData("preflight", "simplysign_pkcs11_missing")]
    [InlineData("detection", "required_runtime_missing")]
    public async Task PowerShell_runner_surfaces_the_prerequisite_failure_instead_of_exit_code_one(
        string phase,
        string code)
    {
        var invoker = new RecordingPowerShellInvoker(
            [0, 1],
            [
                ["phase=media code=ready"],
                ["phase=media code=ready", $"phase={phase} code={code}"],
            ]);
        var runner = new WindowsSetupProcessRunner(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            invoker,
            @"C:\Program Files");

        var failure = await Assert.ThrowsAsync<SetupBootstrapperException>(() =>
            runner.RunAsync(
                SetupProductKind.Main,
                "C:\\media",
                SetupInstallationMode.Service,
                progress: null,
                CancellationToken.None));

        Assert.Equal(code, failure.Code);
    }

    [WindowsAdministratorFact]
    public async Task Pdf_extension_runner_uses_only_the_fixed_installed_main_and_internal_route()
    {
        var workspace = new WindowsSetupWorkspace(Path.GetTempPath());
        var mediaRoot = workspace.Create();
        await using var payload = CreatePdfPayloadArchive();
        var invoker = new RecordingPowerShellInvoker(
            [0],
            [["phase=pdf_extension_media code=ready", "pdf_extension_installed"]]);
        var reported = new List<SetupProgress>();
        var runner = new WindowsSetupProcessRunner(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            invoker,
            @"C:\Program Files");

        try
        {
            await SetupPayloadArchive.ExtractIntoExistingAsync(
                payload,
                mediaRoot,
                CancellationToken.None);
            var exitCode = await runner.RunAsync(
                SetupProductKind.PdfExtension,
                mediaRoot,
                null,
                new InlineProgress<SetupProgress>(reported.Add),
                CancellationToken.None);

            Assert.Equal(0, exitCode);
            Assert.Equal(
                @"C:\Program Files\CodeSignAuto\CodeSignAuto.exe",
                Assert.Single(invoker.Executables));
            Assert.Equal(
                ["pdf-extension", "install", "--media-root", mediaRoot],
                Assert.Single(invoker.Arguments));
            Assert.Equal([55, 92], reported.Select(item => item.Percent));
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadFile(Path.Combine(mediaRoot, "extension.json")),
                directory: false);
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadFile(Path.Combine(mediaRoot, "CodeSignAutoPdfSigner.exe")),
                directory: false);
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadFile(Path.Combine(mediaRoot, "LICENSE.txt")),
                directory: false);
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.ReadFile(Path.Combine(mediaRoot, "THIRD-PARTY-NOTICES.txt")),
                directory: false);
        }
        finally
        {
            await workspace.CleanupAsync(mediaRoot);
        }
    }

    [WindowsFact]
    public async Task Process_output_advances_progress_before_the_child_process_exits()
    {
        var releasePath = Path.Combine(
            Path.GetTempPath(),
            "ssa-setup-output-release-" + Guid.NewGuid().ToString("N"));
        var observed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var progress = new InlineProgress<string>(line =>
        {
            if (line == "first-stage")
            {
                observed.TrySetResult();
            }
        });

        var running = SetupProcessExecution.RunAsync(
            SetupPowerShell.ResolveSystemPath(),
            [
                "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "[Console]::Out.WriteLine('first-stage'); " +
                $"while (-not (Test-Path -LiteralPath '{releasePath.Replace("'", "''", StringComparison.Ordinal)}')) " +
                "{ Start-Sleep -Milliseconds 25 }; exit 0",
            ],
            environment: null,
            TimeSpan.FromSeconds(15),
            progress,
            CancellationToken.None);

        try
        {
            await observed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(running.IsCompleted);
            await File.WriteAllTextAsync(releasePath, "release");
            Assert.Equal(0, await running.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        finally
        {
            await File.WriteAllTextAsync(releasePath, "release");
            try
            {
                await running.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch
            {
                // Preserve the original assertion while still releasing the child process.
            }
            File.Delete(releasePath);
        }
    }

    [WindowsFact]
    public async Task Product_process_stable_stderr_is_exposed_to_the_setup_ui()
    {
        var error = await Assert.ThrowsAsync<SetupBootstrapperException>(() =>
            new PowerShellSetupProcessInvoker().RunAsync(
                SetupPowerShell.ResolveSystemPath(),
                [
                    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                    "[Console]::Error.WriteLine('autologon_conflict'); exit 1",
                ],
                progress: null,
                CancellationToken.None));

        Assert.Equal("autologon_conflict", error.Code);
    }

    [WindowsAdministratorFact]
    public async Task Windows_setup_workspace_is_admin_only_and_cleanup_is_exact()
    {
        var workspace = new WindowsSetupWorkspace(Path.GetTempPath());
        var root = workspace.Create();
        var outside = Path.Combine(Path.GetTempPath(), "ssa-setup-outside-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outside);
        var sentinel = Path.Combine(outside, "sentinel.txt");
        await File.WriteAllTextAsync(sentinel, "keep");
        try
        {
            var security = new DirectoryInfo(root).GetAccessControl();
            var owner = Assert.IsType<SecurityIdentifier>(security.GetOwner(typeof(SecurityIdentifier)));
            Assert.Equal("S-1-5-32-544", owner.Value);
            var allowed = security.GetAccessRules(
                    includeExplicit: true,
                    includeInherited: false,
                    typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Where(rule => rule.AccessControlType == AccessControlType.Allow)
                .ToArray();
            Assert.Equal(2, allowed.Length);
            Assert.Equal(
                ["S-1-5-18", "S-1-5-32-544"],
                allowed.Select(rule => rule.IdentityReference.Value).Order(StringComparer.Ordinal));
            Assert.All(allowed, rule => Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights));

            await workspace.CleanupAsync(root);

            Assert.False(Directory.Exists(root));
            Assert.Equal("keep", await File.ReadAllTextAsync(sentinel));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }

            Directory.Delete(outside, recursive: true);
        }
    }

    [WindowsAdministratorFact]
    public async Task Windows_setup_workspace_is_created_under_the_real_common_application_data_root()
    {
        var parent = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var workspace = new WindowsSetupWorkspace(parent);
        string? root = null;
        try
        {
            root = workspace.Create();

            Assert.Equal(
                Path.GetFullPath(parent),
                Directory.GetParent(root)!.FullName,
                ignoreCase: true);

            await workspace.CleanupAsync(root);
            Assert.False(Directory.Exists(root));
        }
        finally
        {
            if (root is not null && Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static byte[] CreatePayloadArchive()
    {
        using var bytes = new MemoryStream();
        using (var archive = new ZipArchive(bytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("nested/payload.txt", CompressionLevel.NoCompression);
            using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            writer.Write("payload");
        }

        return bytes.ToArray();
    }

    private static MemoryStream CreatePdfPayloadArchive()
    {
        var bytes = new MemoryStream();
        using (var archive = new ZipArchive(bytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var name in new[]
                     {
                         "extension.json", "LICENSE.txt", "CodeSignAutoPdfSigner.exe",
                         "THIRD-PARTY-NOTICES.txt",
                     })
            {
                var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                writer.Write(name);
            }
        }

        bytes.Position = 0;
        return bytes;
    }

    private static byte[] Metadata(byte[] payload, string? payloadSha256 = null) =>
        Encoding.UTF8.GetBytes($$"""
            {
              "schemaVersion": 1,
              "productKind": "main",
              "productVersion": "0.14.0",
              "payloadLength": {{payload.Length}},
              "payloadSha256": "{{payloadSha256 ?? Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant()}}",
              "publisherCertificateSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
            """);

    private sealed class RecordingSetupOperations(int installExitCode) : ISetupBootstrapperOperations
    {
        public List<string> Events { get; } = [];

        public IReadOnlyList<SetupProgress> InstallProgress { get; init; } = [];

        public Task<StagedSetupPayload> StageAsync(CancellationToken cancellationToken)
        {
            Events.Add("stage");
            return Task.FromResult(new StagedSetupPayload(
                "C:\\staged",
                new SetupPayloadMetadata(
                    1,
                    SetupProductKind.Main,
                    "0.14.0",
                    123,
                    new string('a', 64),
                    new string('b', 64))));
        }

        public Task<int> InstallAsync(
            StagedSetupPayload staged,
            SetupInstallationMode? mode,
            IProgress<SetupProgress>? progress,
            CancellationToken cancellationToken)
        {
            Events.Add("install:" + staged.MediaRoot);
            foreach (var item in InstallProgress)
            {
                progress?.Report(item);
            }

            return Task.FromResult(installExitCode);
        }

        public Task DisableAutoLogonAsync(
            StagedSetupPayload staged,
            IProgress<SetupProgress>? progress,
            CancellationToken cancellationToken)
        {
            Assert.Equal(SetupProductKind.Main, staged.Metadata.ProductKind);
            Events.Add("disable-autologon:" + staged.MediaRoot);
            return Task.CompletedTask;
        }

        public Task CleanupAsync(string mediaRoot)
        {
            Events.Add("cleanup:" + mediaRoot);
            return Task.CompletedTask;
        }
    }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private sealed class FixedPayloadSource(
        byte[] payload,
        byte[] metadata,
        List<string> events) : ISetupPayloadSource
    {
        public string ExecutablePath => "C:\\CodeSignAutoSetup.exe";

        public byte[] ReadMetadata()
        {
            events.Add("metadata");
            return metadata;
        }

        public Stream OpenPayload()
        {
            events.Add("payload");
            return new MemoryStream(payload, writable: false);
        }
    }

    private sealed class RecordingPublisherVerifier(List<string> events) : ISetupPublisherVerifier
    {
        public Task VerifyAsync(
            string executablePath,
            string expectedPublisherCertificateSha256,
            CancellationToken cancellationToken)
        {
            Assert.Equal("C:\\CodeSignAutoSetup.exe", executablePath);
            Assert.Equal(new string('b', 64), expectedPublisherCertificateSha256);
            events.Add("publisher");
            return Task.CompletedTask;
        }
    }

    private sealed class PausedPublisherVerifier : ISetupPublisherVerifier
    {
        private readonly TaskCompletionSource _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task VerifyAsync(
            string executablePath,
            string expectedPublisherCertificateSha256,
            CancellationToken cancellationToken) => _completion.Task.WaitAsync(cancellationToken);

        public void Complete() => _completion.SetResult();
    }

    private sealed class RejectingPublisherVerifier(List<string> events) : ISetupPublisherVerifier
    {
        public Task VerifyAsync(
            string executablePath,
            string expectedPublisherCertificateSha256,
            CancellationToken cancellationToken)
        {
            events.Add("publisher");
            throw new SetupBootstrapperException("setup_signature_invalid");
        }
    }

    private sealed class RecordingSetupWorkspace(List<string> events, string? root = null) : ISetupWorkspace
    {
        public string Create()
        {
            events.Add("workspace");
            var path = root ?? throw new InvalidOperationException("Workspace creation was not expected.");
            Directory.CreateDirectory(path);
            return path;
        }

        public Task CleanupAsync(string mediaRoot)
        {
            events.Add("cleanup");
            if (Directory.Exists(mediaRoot))
            {
                Directory.Delete(mediaRoot, recursive: true);
            }

            return Task.CompletedTask;
        }
    }

    private sealed class RecordingMediaRunner(List<string> events, int installExitCode) : ISetupProcessRunner
    {
        public Task<int> RunAsync(
            SetupProductKind productKind,
            string mediaRoot,
            SetupInstallationMode? mode,
            IProgress<SetupProgress>? progress,
            CancellationToken cancellationToken)
        {
            Assert.Equal(SetupProductKind.Main, productKind);
            events.Add("media");
            return Task.FromResult(installExitCode);
        }

        public Task DisableAutoLogonAsync(
            SetupProductKind productKind,
            string mediaRoot,
            IProgress<SetupProgress>? progress,
            CancellationToken cancellationToken)
        {
            Assert.Equal(SetupProductKind.Main, productKind);
            events.Add("disable-autologon");
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingPowerShellInvoker(
        IReadOnlyList<int> exitCodes,
        IReadOnlyList<IReadOnlyList<string>>? outputByCall = null) : ISetupProcessInvoker
    {
        private readonly Queue<int> _exitCodes = new(exitCodes);
        private int _callIndex;

        public List<IReadOnlyList<string>> Arguments { get; } = [];

        public List<string> Executables { get; } = [];

        public Task<int> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            Executables.Add(executable);
            Arguments.Add(arguments.ToArray());
            if (outputByCall is not null)
            {
                foreach (var line in outputByCall[_callIndex])
                {
                    progress?.Report(line);
                }
            }

            _callIndex++;
            return Task.FromResult(_exitCodes.Dequeue());
        }
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows PowerShell.";
            }
        }
    }
}
