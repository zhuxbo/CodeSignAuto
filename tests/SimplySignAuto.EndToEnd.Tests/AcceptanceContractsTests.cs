using SimplySignAuto.Acceptance.Contracts;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class AcceptanceContractsTests
{
    [Fact]
    public void Acceptance_diagnostics_redact_only_totp_secrets_and_keep_full_failure_context()
    {
        const string secret = "JBSWY3DPEHPK3PXP";
        const string otherSecret = "MFRGGZDFMZTWQ2LK";
        var diagnostic =
            "stage=controller_preflight\n" +
            "type=System.InvalidOperationException\n" +
            "message=failed for user@example.test\n" +
            "path=C:\\ProgramData\\SSA-Acceptance\\scripts\\acceptance-test.ps1\n" +
            "line=3223 hresult=0x80131509 win32=5 exit=23\n" +
            "stdout=full stdout for test.name\n" +
            "stderr=full stderr and stack at Invoke-ChildWork\n" +
            $"secret={secret}\n" +
            $"uri=otpauth://totp/SimplySign:user@example.test?secret={secret}&issuer=SimplySign\n" +
            $"other=otpauth://totp/Other:user@example.com?issuer=Other&amp;secret={otherSecret}&amp;digits=6\n";

        var redacted = SecretScanPolicy.Redact(diagnostic, secret);

        Assert.Equal(
            secret,
            SecretScanPolicy.ExtractTotpSecret(
                $"otpauth://totp/SimplySign:user@example.test?secret={secret}&issuer=SimplySign"));
        Assert.True(SecretScanPolicy.ContainsSensitive(diagnostic, secret));
        Assert.False(SecretScanPolicy.ContainsSensitive(redacted, secret));
        Assert.DoesNotContain(secret, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(otherSecret, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secret=[REDACTED_TOTP_SECRET]", redacted, StringComparison.Ordinal);
        Assert.Contains("user@example.test", redacted, StringComparison.Ordinal);
        Assert.Contains(@"C:\ProgramData\SSA-Acceptance\scripts\acceptance-test.ps1", redacted, StringComparison.Ordinal);
        Assert.Contains("System.InvalidOperationException", redacted, StringComparison.Ordinal);
        Assert.Contains("line=3223 hresult=0x80131509 win32=5 exit=23", redacted, StringComparison.Ordinal);
        Assert.Contains("stdout=full stdout for test.name", redacted, StringComparison.Ordinal);
        Assert.Contains("stderr=full stderr and stack at Invoke-ChildWork", redacted, StringComparison.Ordinal);

        var artifact = Path.Combine(Path.GetTempPath(), $"ssa-diagnostic-{Guid.NewGuid():N}.log");
        try
        {
            File.WriteAllText(artifact, redacted);
            var saved = File.ReadAllText(artifact);
            Assert.False(SecretScanPolicy.ContainsSensitive(saved, secret));
            Assert.DoesNotContain(secret, saved, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(otherSecret, saved, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(@"C:\ProgramData\SSA-Acceptance\scripts\acceptance-test.ps1", saved, StringComparison.Ordinal);
            Assert.Contains("System.InvalidOperationException", saved, StringComparison.Ordinal);
            Assert.Contains("stdout=full stdout for test.name", saved, StringComparison.Ordinal);
            Assert.Contains("stderr=full stderr and stack at Invoke-ChildWork", saved, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(artifact);
        }
    }

    [Fact]
    public void Acceptance_scripts_keep_stable_codes_and_full_diagnostics_without_broad_redaction()
    {
        var acceptance = AcceptanceScript();
        var uiAcceptance = UiAcceptanceScript();

        Assert.Contains("acceptance_unhandled_exception", acceptance, StringComparison.Ordinal);
        Assert.Contains("acceptance_diagnostic_begin", acceptance, StringComparison.Ordinal);
        Assert.Contains("exception_type=", acceptance, StringComparison.Ordinal);
        Assert.Contains("script_stack_begin", acceptance, StringComparison.Ordinal);
        Assert.Contains("process_stdout_begin", acceptance, StringComparison.Ordinal);
        Assert.Contains("process_stderr_begin", acceptance, StringComparison.Ordinal);
        Assert.Contains("while ($null -ne $exception)", acceptance, StringComparison.Ordinal);
        Assert.Contains("trusted_executable_diagnostic_begin", acceptance, StringComparison.Ordinal);
        Assert.Contains("actual_publisher_sha256=", acceptance, StringComparison.Ordinal);
        Assert.Contains("pssa_finding_begin", acceptance, StringComparison.Ordinal);
        Assert.Contains("finding_message=", acceptance, StringComparison.Ordinal);
        Assert.Contains("run_directory_acl_diagnostic_begin", acceptance, StringComparison.Ordinal);
        Assert.Contains("actual_rule=", acceptance, StringComparison.Ordinal);
        Assert.Contains(
            "$modifyRights = [System.Security.AccessControl.FileSystemRights]::Modify -bor\n" +
            "        [System.Security.AccessControl.FileSystemRights]::Synchronize",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains(
            "$readAndExecuteRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor\n" +
            "        [System.Security.AccessControl.FileSystemRights]::Synchronize",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains("Rights = $modifyRights", acceptance, StringComparison.Ordinal);
        Assert.Contains("Rights = $readAndExecuteRights", acceptance, StringComparison.Ordinal);
        Assert.Contains(
            "[DateTimeOffset]::TryParseExact(\n" +
            "            $timestampText,\n" +
            "            'ddd MMM dd HH:mm:ss yyyy',\n" +
            "            [System.Globalization.CultureInfo]::GetCultureInfo('en-US')",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains("[bool]$RequireAcceptanceWindow = $true", acceptance, StringComparison.Ordinal);
        Assert.Equal(1, CountOrdinal(acceptance, "120 `\n        $false"));
        Assert.Contains("SignatureTimestampPolicy]::ValidateSignerIdentity", acceptance, StringComparison.Ordinal);
        Assert.Contains("function Get-ProcessDiagnosticFromTask", acceptance, StringComparison.Ordinal);
        const string processDiagnostic =
            "$script:LastProcessDiagnostic = Get-ProcessDiagnosticFromTask $process $Executable $stdout $stderr";
        var timeoutDiagnostic = acceptance.IndexOf(processDiagnostic, StringComparison.Ordinal);
        var cleanupDiagnostic = acceptance.IndexOf(
            processDiagnostic,
            timeoutDiagnostic + processDiagnostic.Length,
            StringComparison.Ordinal);
        Assert.True(timeoutDiagnostic < acceptance.IndexOf("throw 'acceptance_process_timeout'", StringComparison.Ordinal));
        Assert.True(cleanupDiagnostic < acceptance.IndexOf("throw 'acceptance_process_cleanup_timeout'", StringComparison.Ordinal));
        Assert.Contains(
            "Invoke-ScriptAnalyzer -Path $canonical -Severity Error -ErrorAction Stop",
            acceptance,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Invoke-ScriptAnalyzer -Path $canonical -Severity Error, Warning",
            acceptance,
            StringComparison.Ordinal);
        Assert.True(
            acceptance.IndexOf("$FailureRunDirectory = $runDirectory", StringComparison.Ordinal) <
            acceptance.IndexOf("Assert-RunDirectoryAcl $runDirectory", StringComparison.Ordinal));
        Assert.Contains("SecretScanPolicy]::ExtractTotpSecret", acceptance, StringComparison.Ordinal);
        Assert.Contains("SecretScanPolicy]::Redact", acceptance, StringComparison.Ordinal);
        Assert.DoesNotContain("acceptance_debug_", acceptance, StringComparison.Ordinal);
        Assert.DoesNotContain("else {`n            'acceptance_failed'", acceptance, StringComparison.Ordinal);

        var productionUi = ReadSourceText(Path.Combine(
            RepositoryRoot(),
            "tests",
            "SimplySignAuto.UI.Tests",
            "Desktop",
            "ProductionQuickSignAcceptanceTests.cs"));
        Assert.Contains(
            ": \"production_ui_acceptance_failed\";\n            throw new InvalidOperationException(code, error);",
            productionUi,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            ": \"production_ui_acceptance_failed\";\n            throw new InvalidOperationException(code);",
            productionUi,
            StringComparison.Ordinal);

        Assert.Contains("ui_acceptance_unhandled_exception", uiAcceptance, StringComparison.Ordinal);
        Assert.Contains("ui_acceptance_diagnostic_begin", uiAcceptance, StringComparison.Ordinal);
        Assert.Contains("ui_child_task_result", uiAcceptance, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization\\s*:", uiAcceptance, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("bearer\\s+", uiAcceptance, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Acceptance_trusts_executables_from_both_program_files_roots()
    {
        var acceptance = AcceptanceScript();

        Assert.Equal(4, CountOrdinal(
            acceptance,
            "$canonicalProgramFilesX86 = Get-CanonicalExistingPath ${env:ProgramFiles(x86)} Container"));
        Assert.Equal(4, CountOrdinal(
            acceptance,
            "$canonicalProgramFiles, $canonicalProgramFilesX86,"));
        Assert.Contains("function Get-CanonicalAcceptanceRoot", acceptance, StringComparison.Ordinal);
        Assert.Equal(4, CountOrdinal(
            acceptance,
            "$canonicalAcceptanceRoot = Get-CanonicalAcceptanceRoot"));
        Assert.Equal(4, CountOrdinal(
            acceptance,
            "$canonicalProgramFilesX86, $canonicalAcceptanceRoot,"));
        Assert.Contains(
            "$canonicalProgramFilesX86, $canonicalAcceptanceRoot,",
            acceptance,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("FreshInstall", false, AcceptanceRunMode.FreshInstall)]
    [InlineData("ExistingInstall", true, AcceptanceRunMode.ExistingInstall)]
    public void Run_mode_and_api_token_file_contract_are_mutually_exclusive(
        string mode,
        bool hasApiTokenFile,
        AcceptanceRunMode expected)
    {
        Assert.Equal(expected, AcceptanceModePolicy.Validate(mode, hasApiTokenFile));
    }

    [Theory]
    [InlineData("FreshInstall", true)]
    [InlineData("ExistingInstall", false)]
    [InlineData("freshinstall", false)]
    [InlineData("Unknown", false)]
    public void Contradictory_or_unknown_run_modes_fail_closed(string mode, bool hasApiTokenFile)
    {
        AssertCode(
            "acceptance_mode_invalid",
            () => AcceptanceModePolicy.Validate(mode, hasApiTokenFile));
    }

    [Theory]
    [InlineData("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde\n")]
    [InlineData("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde\r\n")]
    public void Setup_ui_acceptance_reads_the_exact_protected_token_file(string content)
    {
        Assert.Equal(
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde",
            SetupTokenFilePolicy.ValidateAndExtract(content));
    }

    [Theory]
    [InlineData("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde")]
    [InlineData("short\n")]
    [InlineData("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde\nextra\n")]
    public void Setup_ui_acceptance_rejects_an_invalid_token_file(string content)
    {
        AssertCode(
            "acceptance_install_token_invalid",
            () => SetupTokenFilePolicy.ValidateAndExtract(content));
    }

    [Fact]
    public void Remote_matrix_requires_exact_append_sequences_and_real_native_fixture_slots()
    {
        RemoteAcceptanceMatrixPolicy.ValidateSignerSequence(
            ["11223344", "AABBCCDD"],
            ["11223344", "AABBCCDD"]);
        AssertCode(
            "acceptance_signer_sequence_invalid",
            () => RemoteAcceptanceMatrixPolicy.ValidateSignerSequence(
                ["AABBCCDD", "11223344"],
                ["11223344", "AABBCCDD"]));
        AssertCode(
            "acceptance_signer_sequence_invalid",
            () => RemoteAcceptanceMatrixPolicy.ValidateSignerSequence(
                ["11223344", "AABBCCDD", "AABBCCDD"],
                ["11223344", "AABBCCDD"]));

        RemoteAcceptanceMatrixPolicy.ValidateNativeFixtureSlots(
            [".msi", ".cat", ".sys", ".dll"]);
        AssertCode(
            "acceptance_native_fixture_invalid",
            () => RemoteAcceptanceMatrixPolicy.ValidateNativeFixtureSlots(
                [".msi", ".cat", ".exe", ".dll"]));
    }

    [Fact]
    public void Native_fixture_source_is_auto_only_when_all_overrides_are_absent()
    {
        Assert.Equal(
            NativeFixtureSourceMode.AutoGenerated,
            NativeFixtureSourcePolicy.Plan(string.Empty, string.Empty, string.Empty, string.Empty));
        Assert.Equal(
            NativeFixtureSourceMode.ExplicitOverride,
            NativeFixtureSourcePolicy.Plan(
                @"C:\fixtures\sample.msi",
                @"C:\fixtures\sample.cat",
                @"C:\fixtures\sample.sys",
                @"C:\fixtures\sample.dll"));
    }

    [Fact]
    public void Native_fixture_source_rejects_partial_or_wrong_extension_overrides()
    {
        var mutations = new[]
        {
            new[] { @"C:\fixtures\sample.msi", "", "", "" },
            new[] { @"C:\fixtures\sample.msi", @"C:\fixtures\sample.cat", @"C:\fixtures\sample.sys", "" },
            new[] { @"C:\fixtures\sample.exe", @"C:\fixtures\sample.cat", @"C:\fixtures\sample.sys", @"C:\fixtures\sample.dll" },
        };
        foreach (var mutation in mutations)
        {
            AssertCode(
                "acceptance_native_fixture_invalid",
                () => NativeFixtureSourcePolicy.Plan(
                    mutation[0],
                    mutation[1],
                    mutation[2],
                    mutation[3]));
        }
    }

    [Fact]
    public void Auto_native_fixture_requires_three_independent_tool_publisher_hashes()
    {
        var hashA = new string('a', 64);
        var hashB = new string('b', 64);
        var hashC = new string('c', 64);
        NativeFixtureSourcePolicy.ValidateToolPublisherHashes(
            NativeFixtureSourceMode.AutoGenerated,
            hashA,
            hashB,
            hashC);

        AssertCode(
            "acceptance_native_fixture_tool_invalid",
            () => NativeFixtureSourcePolicy.ValidateToolPublisherHashes(
                NativeFixtureSourceMode.AutoGenerated,
                hashA,
                string.Empty,
                hashC));
        NativeFixtureSourcePolicy.ValidateToolPublisherHashes(
            NativeFixtureSourceMode.ExplicitOverride,
            string.Empty,
            string.Empty,
            string.Empty);
    }

    [Fact]
    public void Explicit_native_fixture_requires_four_independent_content_hashes()
    {
        var hashA = new string('a', 64);
        var hashB = new string('b', 64);
        var hashC = new string('c', 64);
        var hashD = new string('d', 64);
        NativeFixtureSourcePolicy.ValidateFixtureHashes(
            NativeFixtureSourceMode.ExplicitOverride,
            hashA,
            hashB,
            hashC,
            hashD);
        AssertCode(
            "acceptance_native_fixture_invalid",
            () => NativeFixtureSourcePolicy.ValidateFixtureHashes(
                NativeFixtureSourceMode.ExplicitOverride,
                hashA,
                hashB,
                string.Empty,
                hashD));
        NativeFixtureSourcePolicy.ValidateFixtureHashes(
            NativeFixtureSourceMode.AutoGenerated,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty);
    }

    [Fact]
    public void Remote_queue_contract_requires_five_fifo_jobs_single_concurrency_and_idempotency()
    {
        string[] submitted = ["01", "02", "03", "04", "05"];
        RemoteAcceptanceMatrixPolicy.ValidateQueueRecovery(
            submitted,
            ["01", "02", "03", "04", "05"],
            ["01", "02", "03", "04", "05"],
            observedMaximumActive: 1,
            idempotentOriginal: "01",
            idempotentRetry: "01",
            changedInputConflict: true,
            serviceRestartObserved: true,
            agentRecoveryObserved: true);

        AssertCode(
            "acceptance_queue_recovery_invalid",
            () => RemoteAcceptanceMatrixPolicy.ValidateQueueRecovery(
                submitted,
                ["01", "02", "03", "04", "05"],
                ["02", "01", "03", "04", "05"],
                1,
                "01",
                "01",
                true,
                true,
                true));
    }

    [Fact]
    public void Remote_failure_session_and_boot_matrix_requires_every_observed_transition()
    {
        RemoteAcceptanceMatrixPolicy.ValidateFailureSessionAndBootMatrix(
            unauthorizedIs401: true,
            corruptPdfRejectedWithoutResult: true,
            autoReloginAfterClose: true,
            disconnectedSessionUnavailable: true,
            sessionZeroUnavailable: true,
            activeSessionRecovered: true,
            managedPurgeObserved: true,
            rebootCleanupResumed: true,
            pssaClean: true,
            timeSynchronized: true,
            urlAclExact: true);

        AssertCode(
            "acceptance_remote_matrix_incomplete",
            () => RemoteAcceptanceMatrixPolicy.ValidateFailureSessionAndBootMatrix(
                true, true, false, true, true, true, true, true, true, true, true));
        AssertCode(
            "acceptance_remote_matrix_incomplete",
            () => RemoteAcceptanceMatrixPolicy.ValidateFailureSessionAndBootMatrix(
                true, true, true, true, true, true, true, false, true, true, true));
    }

    [Fact]
    public void Unattended_relogin_requires_agent_survival_one_same_generation_login_and_two_verified_configured_transport_jobs()
    {
        var closedAt = new DateTimeOffset(2026, 8, 10, 1, 0, 0, TimeSpan.Zero);
        var transitions = ReloginTransitions(closedAt);

        UnattendedReloginEvidencePolicy.Validate(
            agentPidBeforeClose: 321,
            agentPidAfterClose: 321,
            agentAliveAfterClose: true,
            closedAtUtc: closedAt,
            readyGeneration: 8,
            transitions: transitions,
            configuredTransport: "http",
            codeJobTransport: "http",
            pdfJobTransport: "http",
            codeSignatureVerified: true,
            pdfSignatureVerified: true);
    }

    [Theory]
    [InlineData("agent-changed")]
    [InlineData("missing-wait")]
    [InlineData("duplicate-login")]
    [InlineData("mixed-generation")]
    [InlineData("before-close")]
    [InlineData("code-not-verified")]
    [InlineData("pdf-wrong-transport")]
    public void Unattended_relogin_rejects_every_false_green(string mutation)
    {
        var closedAt = new DateTimeOffset(2026, 8, 10, 1, 0, 0, TimeSpan.Zero);
        var transitions = ReloginTransitions(closedAt).ToList();
        if (mutation == "missing-wait")
        {
            transitions.RemoveAt(4);
        }
        else if (mutation == "duplicate-login")
        {
            transitions.Insert(4, new ReloginTransitionSnapshot(
                5, "LOGINNING", 8, closedAt.AddSeconds(5), 1));
        }
        else if (mutation == "mixed-generation")
        {
            transitions[3] = new ReloginTransitionSnapshot(
                4, "LOGINNING", 9, closedAt.AddSeconds(4), 1);
        }
        else if (mutation == "before-close")
        {
            transitions[0] = new ReloginTransitionSnapshot(
                1, "UNKNOWN", 8, closedAt.AddSeconds(-1), 0);
        }

        AssertCode(
            "acceptance_unattended_relogin_invalid",
            () => UnattendedReloginEvidencePolicy.Validate(
                321,
                mutation == "agent-changed" ? 654 : 321,
                true,
                closedAt,
                8,
                transitions,
                "http",
                "http",
                mutation == "pdf-wrong-transport" ? "https" : "http",
                mutation != "code-not-verified",
                true));
    }

    [Fact]
    public void Acceptance_script_keeps_close_relogin_before_the_separate_agent_crash_gate()
    {
        var source = AcceptanceScript();
        var code = source.IndexOf("$closeCodeJob = Invoke-CreateJob", StringComparison.Ordinal);
        var pdf = source.IndexOf("$closePdfJob = Invoke-CreateJob", StringComparison.Ordinal);
        var relogin = source.IndexOf(
            "[SimplySignAuto.Acceptance.Contracts.UnattendedReloginEvidencePolicy]::Validate(",
            StringComparison.Ordinal);
        var crash = source.LastIndexOf(
            "Invoke-AgentCrashRecoveryGate $canonicalApp",
            StringComparison.Ordinal);

        Assert.True(code > 0 && pdf > code && relogin > pdf && crash > relogin);
    }

    [Fact]
    public void Acceptance_script_derives_configured_transport_from_the_validated_base_uri_once()
    {
        var source = AcceptanceScript();

        Assert.Contains("$configuredTransport = ([Uri]$safeBaseUrl).Scheme", source, StringComparison.Ordinal);
        Assert.DoesNotContain("$safeBaseUrl.Scheme", source, StringComparison.Ordinal);
        Assert.Equal(
            4,
            System.Text.RegularExpressions.Regex.Matches(
                source,
                System.Text.RegularExpressions.Regex.Escape("$configuredTransport"),
                System.Text.RegularExpressions.RegexOptions.CultureInvariant).Count);
    }

    [Fact]
    public void Interactive_task_creation_uses_the_cmdlet_enum_while_readback_requires_the_xml_value()
    {
        var acceptance = AcceptanceScript();
        var uiAcceptance = UiAcceptanceScript();

        Assert.Contains(
            "New-ScheduledTaskPrincipal -UserId $signingSid.Value -LogonType Interactive -RunLevel Highest",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains(
            "New-ScheduledTaskPrincipal -UserId $AdministratorUser -LogonType Interactive -RunLevel Highest",
            uiAcceptance,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "New-ScheduledTaskPrincipal -UserId $SigningUser",
            uiAcceptance,
            StringComparison.Ordinal);
        Assert.DoesNotContain("-LogonType InteractiveToken", acceptance, StringComparison.Ordinal);
        Assert.DoesNotContain("-LogonType InteractiveToken", uiAcceptance, StringComparison.Ordinal);
        Assert.Contains("'InteractiveToken'", acceptance, StringComparison.Ordinal);
        Assert.Contains("-eq 'InteractiveToken'", uiAcceptance, StringComparison.Ordinal);
    }

    [Fact]
    public void Production_ui_and_otp_import_run_only_in_the_administrator_acceptance_session()
    {
        var acceptance = AcceptanceScript();
        var uiAcceptance = UiAcceptanceScript();
        var repositoryRoot = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var productionUi = ReadSourceText(Path.Combine(
            repositoryRoot,
            "tests",
            "SimplySignAuto.UI.Tests",
            "Desktop",
            "ProductionQuickSignAcceptanceTests.cs"));

        Assert.DoesNotContain("@('configure-otp')", acceptance, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Invoke-ProductionQuickSignAcceptance `",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains("'-ProductionOtpUriFile', $canonicalOtp", acceptance, StringComparison.Ordinal);
        Assert.Contains("-ProductionExeInput", acceptance, StringComparison.Ordinal);
        Assert.Contains("-ProductionOtpUriFile", uiAcceptance, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_PRODUCTION_UI_OTP_URI_FILE", uiAcceptance, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_PRODUCTION_UI_OTP_URI_FILE", productionUi, StringComparison.Ordinal);
        Assert.DoesNotContain("-OtpUriFile $($escaped", acceptance, StringComparison.Ordinal);
        Assert.DoesNotContain("$canonicalOtp = Get-CanonicalExistingPath $OtpUriFile Leaf\n    $otpUriForRedaction", acceptance, StringComparison.Ordinal);
    }

    [Fact]
    public void Acceptance_uses_the_certum_report_template_signature_box_everywhere()
    {
        var repositoryRoot = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var acceptance = AcceptanceScript();
        var fixtures = ReadSourceText(
            Path.Combine(repositoryRoot, "scripts", "install-test-fixtures.ps1"));
        var productionUi = ReadSourceText(
            Path.Combine(
                repositoryRoot,
                "tests",
                "SimplySignAuto.UI.Tests",
                "Desktop",
                "ProductionQuickSignAcceptanceTests.cs"));

        Assert.Equal(1, CountOrdinal(
            acceptance,
            "$productionPdfBox = @(200.0, 642.0, 548.0, 680.0)"));
        Assert.Equal(1, CountOrdinal(
            acceptance,
            "if ($PdfPage -ne 2) { throw 'acceptance_arguments_invalid' }"));
        Assert.Equal(1, CountOrdinal(
            fixtures,
            "$manifest.pdfPageCount -isnot [int] -or $manifest.pdfPageCount -ne 2"));
        Assert.Equal(1, CountOrdinal(fixtures, "pdfPageCount = 2"));
        Assert.Equal(1, CountOrdinal(
            fixtures,
            "(@($manifest.visibleSignatureBox) -join ',') -cne '200,642,548,680'"));
        Assert.Equal(1, CountOrdinal(fixtures, "visibleSignatureBox = @(200, 642, 548, 680)"));

        var expectedUiValues = new[]
        {
            "SetValue(process, mainWindow, \"PDF 签名页码\", \"2\")",
            "SetValue(process, mainWindow, \"签名区域左边界\", \"200\")",
            "SetValue(process, mainWindow, \"签名区域下边界\", \"642\")",
            "SetValue(process, mainWindow, \"签名区域右边界\", \"548\")",
            "SetValue(process, mainWindow, \"签名区域上边界\", \"680\")",
        };
        Assert.All(expectedUiValues, expected => Assert.Equal(1, CountOrdinal(productionUi, expected)));
        Assert.Equal(
            expectedUiValues.Length,
            expectedUiValues.Sum(expected => CountOrdinal(productionUi, expected)));
        Assert.DoesNotContain("200,657,548,695", acceptance + fixtures + productionUi,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Production_quick_sign_contract_requires_real_composition_two_unchanged_inputs_and_tray_restore()
    {
        RemoteAcceptanceMatrixPolicy.ValidateProductionQuickSign(
            Hash('A'),
            Hash('A'),
            Hash('B'),
            Hash('C'),
            Hash('C'),
            Hash('D'),
            productionComposition: true,
            readinessVisible: true,
            hiddenSubmissionCompleted: true,
            trayRestoreObserved: true,
            secretScanClean: true);

        AssertCode(
            "acceptance_production_ui_invalid",
            () => RemoteAcceptanceMatrixPolicy.ValidateProductionQuickSign(
                Hash('A'), Hash('B'), Hash('C'), Hash('D'), Hash('D'), Hash('E'),
                true, true, true, true, true));
        AssertCode(
            "acceptance_production_ui_invalid",
            () => RemoteAcceptanceMatrixPolicy.ValidateProductionQuickSign(
                Hash('A'), Hash('A'), Hash('B'), Hash('C'), Hash('C'), Hash('D'),
                false, true, true, true, true));
    }

    [Fact]
    public void Only_one_matching_nonzero_WTS_active_session_is_selected()
    {
        var candidates = new[]
        {
            new SessionCandidate(0, "Active", Hash('A')),
            new SessionCandidate(2, "Disconnected", Hash('A')),
            new SessionCandidate(3, "Active", Hash('B')),
            new SessionCandidate(7, "Active", Hash('A')),
        };

        Assert.Equal(7, SessionSelectionPolicy.SelectUniqueActive(candidates, Hash('A')));
    }

    [Fact]
    public void Multiple_active_sessions_fail_closed_instead_of_falling_back()
    {
        var candidates = new[]
        {
            new SessionCandidate(3, "Active", Hash('A')),
            new SessionCandidate(7, "Active", Hash('A')),
        };

        AssertCode(
            "acceptance_session_unavailable",
            () => SessionSelectionPolicy.SelectUniqueActive(candidates, Hash('A')));
    }

    [Fact]
    public void Trusted_executable_requires_a_boundary_safe_root_protected_acl_and_expected_publisher()
    {
        var trusted = TrustedExecutableSnapshot(
            @"C:\Program Files\dotnet\dotnet.exe",
            identity: "VOL:1:FILE:1",
            hash: Hash('a'),
            signatureValid: true,
            publisherSha256: Hash('b'));

        TrustedExecutablePolicy.Validate(
            trusted,
            trusted,
            [@"C:\Program Files", @"C:\Windows"],
            ExecutableTrustKind.PlatformPublisher,
            Hash('b'));

        AssertCode(
            "acceptance_executable_untrusted",
            () => TrustedExecutablePolicy.Validate(
                TrustedExecutableSnapshot(
                    @"C:\attacker\dotnet.exe",
                    "VOL:1:FILE:1",
                    Hash('a'),
                    true,
                    Hash('b')),
                trusted,
                [@"C:\Program Files", @"C:\Windows"],
                ExecutableTrustKind.PlatformPublisher,
                Hash('b')));
        AssertCode(
            "acceptance_executable_untrusted",
            () => TrustedExecutablePolicy.Validate(
                TrustedExecutableSnapshot(
                    @"C:\Program Files Evil\dotnet\dotnet.exe",
                    "VOL:1:FILE:1",
                    Hash('a'),
                    true,
                    Hash('b')),
                TrustedExecutableSnapshot(
                    @"C:\Program Files Evil\dotnet\dotnet.exe",
                    "VOL:1:FILE:1",
                    Hash('a'),
                    true,
                    Hash('b')),
                [@"C:\Program Files"],
                ExecutableTrustKind.PlatformPublisher,
                Hash('b')));
        AssertCode(
            "acceptance_executable_untrusted",
            () => TrustedExecutablePolicy.Validate(
                TrustedExecutableSnapshot(
                    @"C:\Program Files\dotnet\dotnet.exe",
                    "VOL:1:FILE:1",
                    Hash('a'),
                    true,
                    Hash('b'),
                    ancestorsProtected: false),
                trusted,
                [@"C:\Program Files"],
                ExecutableTrustKind.PlatformPublisher,
                Hash('b')));
        AssertCode(
            "acceptance_executable_untrusted",
            () => TrustedExecutablePolicy.Validate(
                TrustedExecutableSnapshot(
                    @"C:\Program Files\dotnet\dotnet.exe",
                    "VOL:1:FILE:1",
                    Hash('a'),
                    true,
                    Hash('b'),
                    daclProtected: false),
                trusted,
                [@"C:\Program Files"],
                ExecutableTrustKind.PlatformPublisher,
                Hash('b')));
    }

    [Fact]
    public void Windows_system_publishers_are_bound_to_each_exact_tool_id()
    {
        var publisherA = Hash('a');
        var publisherB = Hash('b');
        var publisherC = Hash('c');
        var publisherD = Hash('d');
        var expected = WindowsSystemPublisherMapPolicy.Parse(
            $"w32tm={publisherD};netsh={publisherB};sc={publisherB};" +
            $"taskkill={publisherC};tsdiscon={publisherB};tscon={publisherB};" +
            $"certutil={publisherA}");

        Assert.Equal(7, expected.Count);
        Assert.Equal(publisherD, expected["w32tm"]);
        Assert.Equal(publisherB, expected["netsh"]);
        Assert.Equal(publisherB, expected["sc"]);
        Assert.Equal(publisherC, expected["taskkill"]);
        Assert.Equal(publisherB, expected["tsdiscon"]);
        Assert.Equal(publisherB, expected["tscon"]);
        Assert.Equal(publisherA, expected["certutil"]);

        var observed = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["w32tm"] = publisherD,
            ["netsh"] = publisherB,
            ["sc"] = publisherB,
            ["taskkill"] = publisherC,
            ["tsdiscon"] = publisherB,
            ["tscon"] = publisherB,
            ["certutil"] = publisherA,
        };
        var singlePublisherFailures = 0;
        foreach (var tool in observed)
        {
            var executablePath = $@"C:\Windows\System32\{tool.Key}.exe";
            Assert.Equal(
                tool.Value,
                expected.ResolveExpectedPublisherSha256(executablePath));
            var snapshot = TrustedExecutableSnapshot(
                executablePath,
                $"VOL:1:FILE:{tool.Key}",
                Hash('e'),
                signatureValid: true,
                publisherSha256: tool.Value);
            try
            {
                TrustedExecutablePolicy.Validate(
                    snapshot,
                    snapshot,
                    [@"C:\Windows"],
                    ExecutableTrustKind.PlatformPublisher,
                    publisherA);
            }
            catch (AcceptanceContractException exception)
            {
                Assert.Equal("acceptance_executable_untrusted", exception.Message);
                singlePublisherFailures++;
            }

            TrustedExecutablePolicy.Validate(
                snapshot,
                snapshot,
                [@"C:\Windows"],
                ExecutableTrustKind.PlatformPublisher,
                expected[tool.Key]);
        }

        Assert.Equal(6, singlePublisherFailures);

        var swapped = WindowsSystemPublisherMapPolicy.Parse(
            $"w32tm={publisherD};netsh={publisherB};sc={publisherB};" +
            $"taskkill={publisherA};tsdiscon={publisherB};tscon={publisherB};" +
            $"certutil={publisherC}");
        foreach (var toolId in new[] { "taskkill", "certutil" })
        {
            var executablePath = $@"C:\Windows\System32\{toolId}.exe";
            var snapshot = TrustedExecutableSnapshot(
                executablePath,
                $"VOL:1:FILE:{toolId}",
                Hash('e'),
                signatureValid: true,
                publisherSha256: observed[toolId]);
            AssertCode(
                "acceptance_executable_untrusted",
                () => TrustedExecutablePolicy.Validate(
                    snapshot,
                    snapshot,
                    [@"C:\Windows"],
                    ExecutableTrustKind.PlatformPublisher,
                    swapped.ResolveExpectedPublisherSha256(executablePath)));
        }

        AssertCode(
            "acceptance_windows_system_publisher_map_invalid",
            () => WindowsSystemPublisherMapPolicy.Parse(publisherA));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("unknown")]
    [InlineData("tool-case")]
    [InlineData("hash-case")]
    [InlineData("hash-length")]
    public void Windows_system_publisher_map_rejects_non_exact_input(string mutation)
    {
        var publisherA = Hash('a');
        var publisherB = Hash('b');
        var publisherC = Hash('c');
        var publisherD = Hash('d');
        var entries = new[]
        {
            $"w32tm={publisherD}",
            $"netsh={publisherB}",
            $"sc={publisherB}",
            $"taskkill={publisherC}",
            $"tsdiscon={publisherB}",
            $"tscon={publisherB}",
            $"certutil={publisherA}",
        }.ToList();

        switch (mutation)
        {
            case "missing":
                entries.RemoveAt(6);
                break;
            case "duplicate":
                entries[6] = $"sc={publisherA}";
                break;
            case "unknown":
                entries[6] = $"whoami={publisherA}";
                break;
            case "tool-case":
                entries[0] = $"W32tm={publisherD}";
                break;
            case "hash-case":
                entries[0] = $"w32tm={publisherD.ToUpperInvariant()}";
                break;
            case "hash-length":
                entries[0] = $"w32tm={publisherD[..^1]}";
                break;
        }

        AssertCode(
            "acceptance_windows_system_publisher_map_invalid",
            () => WindowsSystemPublisherMapPolicy.Parse(string.Join(';', entries)));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\whoami.exe")]
    [InlineData(@"C:\Windows\System32\TaskKill.exe")]
    [InlineData("taskkill.exe")]
    [InlineData(@"C:\Windows\System32\..\System32\taskkill.exe")]
    [InlineData(@"C:\Windows\System32\taskkill.exe:alternate")]
    [InlineData(@"C:\Windows\System32\taskkill.exe.")]
    [InlineData(@"C:/Windows/System32/taskkill.exe")]
    public void Windows_system_publisher_resolver_rejects_unknown_case_and_path_spoofing(
        string executablePath)
    {
        var publisher = Hash('a');
        var expected = WindowsSystemPublisherMapPolicy.Parse(
            $"w32tm={publisher};netsh={publisher};sc={publisher};" +
            $"taskkill={publisher};tsdiscon={publisher};tscon={publisher};" +
            $"certutil={publisher}");

        AssertCode(
            "acceptance_windows_system_publisher_map_invalid",
            () => expected.ResolveExpectedPublisherSha256(executablePath));
    }

    [Theory]
    [InlineData("Leap Indicator: 0 (no warning); Stratum: 3")]
    [InlineData("跃点指示器: 0(无警告); 层次: 3")]
    public void Time_synchronization_uses_recent_numeric_events_not_localized_status_text(
        string localizedStatus)
    {
        var collectedAt = new DateTimeOffset(2026, 8, 10, 12, 0, 0, TimeSpan.Zero);
        var evidence = new TimeSynchronizationEvidence(
            serviceRunning: true,
            queryExitCode: 0,
            localizedStatus,
            collectedAt,
            latestValidDataUtc: collectedAt.AddMinutes(-10),
            latestFailureUtc: collectedAt.AddMinutes(-30),
            sourceIsLocalClock: false);

        TimeSynchronizationPolicy.Validate(evidence);
    }

    [Theory]
    [InlineData("service-stopped")]
    [InlineData("query-failed")]
    [InlineData("no-success")]
    [InlineData("old-success")]
    [InlineData("future-success")]
    [InlineData("local-cmos")]
    [InlineData("newer-failure")]
    [InlineData("same-time-failure")]
    public void Time_synchronization_rejects_unsynchronized_or_stale_numeric_evidence(
        string mutation)
    {
        var collectedAt = new DateTimeOffset(2026, 8, 10, 12, 0, 0, TimeSpan.Zero);
        var validAt = mutation switch
        {
            "no-success" => DateTimeOffset.MinValue,
            "old-success" => collectedAt.AddMinutes(-121),
            "future-success" => collectedAt.AddMinutes(6),
            _ => collectedAt.AddMinutes(-10),
        };
        var failureAt = mutation switch
        {
            "newer-failure" => collectedAt.AddMinutes(-5),
            "same-time-failure" => validAt,
            _ => collectedAt.AddMinutes(-30),
        };
        var evidence = new TimeSynchronizationEvidence(
            serviceRunning: mutation != "service-stopped",
            queryExitCode: mutation == "query-failed" ? 1 : 0,
            "Leap Indicator: 0 (no warning); Stratum: 3",
            collectedAt,
            validAt,
            failureAt,
            sourceIsLocalClock: mutation == "local-cmos");

        AssertCode(
            "acceptance_time_unsynchronized",
            () => TimeSynchronizationPolicy.Validate(evidence));
    }

    [Fact]
    public void Trusted_executable_rejects_a_path_swap_and_manifest_hash_mismatch()
    {
        var before = TrustedExecutableSnapshot(
            @"D:\protected-repo\SimplySignAuto.exe",
            "VOL:1:FILE:1",
            Hash('a'),
            signatureValid: false,
            publisherSha256: string.Empty);
        var swapped = TrustedExecutableSnapshot(
            @"D:\protected-repo\SimplySignAuto.exe",
            "VOL:1:FILE:2",
            Hash('c'),
            signatureValid: false,
            publisherSha256: string.Empty);

        AssertCode(
            "acceptance_executable_changed",
            () => TrustedExecutablePolicy.Validate(
                before,
                swapped,
                [@"D:\protected-repo"],
                ExecutableTrustKind.ManifestSha256,
                Hash('a')));
        AssertCode(
            "acceptance_executable_untrusted",
            () => TrustedExecutablePolicy.Validate(
                before,
                before,
                [@"D:\protected-repo"],
                ExecutableTrustKind.ManifestSha256,
                Hash('d')));
    }

    [Fact]
    public void Session_selection_binds_the_canonical_sid_not_a_display_name_hash()
    {
        const string expectedSid = "S-1-5-21-111-222-333-1001";
        var candidates = new[]
        {
            new SidSessionCandidate(3, "Active", "S-1-5-21-111-222-333-1002"),
            new SidSessionCandidate(7, "Active", expectedSid),
        };

        Assert.Equal(7, SidSessionSelectionPolicy.SelectUniqueActive(candidates, expectedSid));
        AssertCode(
            "acceptance_session_unavailable",
            () => SidSessionSelectionPolicy.SelectUniqueActive(candidates, "DOMAIN\\same-display-name"));
    }

    [Fact]
    public void Scheduled_task_cleanup_requires_every_owned_field_to_match_exactly()
    {
        var expected = ExpectedTask();
        Assert.True(TaskOwnershipPolicy.IsExact(expected, ExpectedTask()));
        Assert.False(TaskOwnershipPolicy.IsExact(
            expected,
            new AcceptanceTaskSnapshot(
                expected.Description,
                expected.PrincipalHash,
                "InteractiveToken",
                "Highest",
                expected.ExecutableIdentity,
                expected.ArgumentsHash,
                expected.ExecutionTimeLimitSeconds,
                actionCount: 2)));
        Assert.False(TaskOwnershipPolicy.IsExact(
            expected,
            new AcceptanceTaskSnapshot(
                expected.Description,
                expected.PrincipalHash,
                "Password",
                "Highest",
                expected.ExecutableIdentity,
                expected.ArgumentsHash,
                expected.ExecutionTimeLimitSeconds,
                actionCount: 1)));
    }

    [Fact]
    public void Ui_artifact_acl_is_exactly_scoped_to_the_ui_root_and_read_back_twice()
    {
        UiArtifactAclPolicy.Validate(
            topLevelSigningUserCanModify: false,
            uiRootSigningUserCanModify: true,
            beforeReadbackExact: true,
            afterReadbackExact: true);

        AssertCode(
            "acceptance_ui_acl_invalid",
            () => UiArtifactAclPolicy.Validate(true, true, true, true));
        AssertCode(
            "acceptance_ui_acl_invalid",
            () => UiArtifactAclPolicy.Validate(false, true, true, false));
    }

    [Fact]
    public void Agent_task_must_keep_every_execution_field_exact_before_each_action()
    {
        var expected = new AgentTaskExecutionSnapshot(
            "S-1-5-21-111-222-333-1001",
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            "agent --background",
            "InteractiveToken",
            "HighestAvailable",
            "LogonTrigger",
            "SimplySignAuto/v1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "SimplySignAuto/v1",
            networkRequired: true,
            enabled: true,
            triggerCount: 1,
            actionCount: 1);

        AgentTaskExecutionPolicy.Validate(expected, expected);
        AssertCode(
            "acceptance_agent_task_invalid",
            () => AgentTaskExecutionPolicy.Validate(
                expected,
                new AgentTaskExecutionSnapshot(
                    expected.PrincipalSid,
                    expected.ExecutablePath,
                    "agent --replaced",
                    expected.LogonType,
                    expected.RunLevel,
                    expected.TriggerKind,
                    expected.Source,
                    expected.Description,
                    expected.NetworkRequired,
                    expected.Enabled,
                    expected.TriggerCount,
                    expected.ActionCount)));
    }

    [Fact]
    public void Agent_task_trigger_snapshot_reads_the_actual_xml_local_name()
    {
        var trigger = AgentTaskTriggerXmlPolicy.Read(ExactAgentTriggerXml());

        Assert.Equal("LogonTrigger", trigger.Kind);
        Assert.Equal(2, trigger.ChildCount);
    }

    [Theory]
    [InlineData("boot")]
    [InlineData("time")]
    [InlineData("delay")]
    public void Agent_task_trigger_snapshot_rejects_boot_time_and_delayed_logon(string mutation)
    {
        var xml = mutation switch
        {
            "boot" => ExactAgentTriggerXml()
                .Replace("LogonTrigger", "BootTrigger", StringComparison.Ordinal),
            "time" => ExactAgentTriggerXml()
                .Replace("LogonTrigger", "TimeTrigger", StringComparison.Ordinal),
            "delay" => ExactAgentTriggerXml()
                .Replace("</LogonTrigger>", "<Delay>PT1M</Delay></LogonTrigger>", StringComparison.Ordinal),
            _ => throw new InvalidOperationException(),
        };

        AssertCode(
            "acceptance_agent_task_invalid",
            () => AgentTaskTriggerXmlPolicy.Read(xml));
    }

    [Fact]
    public void Controller_observation_binds_child_pid_sid_session_executable_and_run_id()
    {
        var expected = new ChildProcessObservation(
            4321,
            "S-1-5-21-111-222-333-1001",
            7,
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            new string('a', 32),
            commandLineMatches: true);

        ChildProcessObservationPolicy.Validate(expected, expected);
        AssertCode(
            "acceptance_child_process_invalid",
            () => ChildProcessObservationPolicy.Validate(
                expected,
                new ChildProcessObservation(
                    4322,
                    expected.PrincipalSid,
                    expected.SessionId,
                    expected.ExecutablePath,
                    expected.RunId,
                    true)));
        AssertCode(
            "acceptance_child_process_invalid",
            () => ChildProcessObservationPolicy.Validate(
                expected,
                new ChildProcessObservation(
                    expected.ProcessId,
                    expected.PrincipalSid,
                    expected.SessionId,
                    expected.ExecutablePath,
                    expected.RunId,
                    false)));
    }

    [Fact]
    public void Artifact_set_is_exact_ordinal_and_rejects_missing_extra_duplicate_or_case_variant()
    {
        string[] expected = ["summary.json", "native.trx", "ui/manifest.json"];

        ArtifactSetPolicy.ValidateExact(expected, ["summary.json", "native.trx", "ui/manifest.json"]);
        AssertCode("acceptance_artifact_set_invalid", () => ArtifactSetPolicy.ValidateExact(expected, ["summary.json", "native.trx"]));
        AssertCode("acceptance_artifact_set_invalid", () => ArtifactSetPolicy.ValidateExact(expected, ["summary.json", "native.trx", "ui/manifest.json", "extra.log"]));
        AssertCode("acceptance_artifact_set_invalid", () => ArtifactSetPolicy.ValidateExact(expected, ["summary.json", "native.trx", "UI/manifest.json"]));
        AssertCode("acceptance_artifact_set_invalid", () => ArtifactSetPolicy.ValidateExact(expected, ["summary.json", "native.trx", "native.trx"]));
    }

    [Theory]
    [InlineData(true, false, true, 1, true)]
    [InlineData(false, false, true, 1, false)]
    [InlineData(true, true, true, 1, false)]
    [InlineData(true, false, false, 1, false)]
    [InlineData(true, false, true, 2, false)]
    public void Cleanup_requires_exact_owner_identity_regular_single_link_file(
        bool ownerMatches,
        bool reparse,
        bool ordinaryFile,
        int linkCount,
        bool expected)
    {
        Assert.Equal(expected, CleanupOwnershipPolicy.CanDelete(
            expectedRunId: new string('a', 32),
            markerRunId: ownerMatches ? new string('a', 32) : new string('b', 32),
            expectedIdentity: "VOL:0001:FILE:0002",
            actualIdentity: "VOL:0001:FILE:0002",
            isReparse: reparse,
            isOrdinaryFile: ordinaryFile,
            linkCount: linkCount));
    }

    [Fact]
    public void Token_file_cleanup_rejects_identity_change()
    {
        Assert.False(CleanupOwnershipPolicy.CanDelete(
            new string('a', 32),
            new string('a', 32),
            "VOL:0001:FILE:0002",
            "VOL:0001:FILE:0003",
            isReparse: false,
            isOrdinaryFile: true,
            linkCount: 1));
    }

    [Theory]
    [InlineData(false, true, true, true, false, true, 1, true)]
    [InlineData(true, true, true, true, false, true, 1, false)]
    [InlineData(false, false, true, true, false, true, 1, false)]
    [InlineData(false, true, false, true, false, true, 1, false)]
    [InlineData(false, true, true, false, false, true, 1, false)]
    [InlineData(false, true, true, true, true, true, 1, false)]
    [InlineData(false, true, true, true, false, false, 1, false)]
    [InlineData(false, true, true, true, false, true, 2, false)]
    public void Fresh_install_token_cleanup_requires_a_new_exact_owned_file(
        bool existedBefore,
        bool ownerAndAclExact,
        bool identityExact,
        bool hashExact,
        bool isReparse,
        bool ordinaryFile,
        int linkCount,
        bool expected)
    {
        Assert.Equal(expected, InstallTokenCleanupPolicy.CanDelete(
            existedBefore,
            ownerAndAclExact,
            "VOL:0001:FILE:0002",
            identityExact ? "VOL:0001:FILE:0002" : "VOL:0001:FILE:0003",
            new string('a', 64),
            hashExact ? new string('a', 64) : new string('b', 64),
            isReparse,
            ordinaryFile,
            linkCount));
    }

    [Fact]
    public async Task Fresh_install_token_cleanup_retries_a_transient_Windows_delete_failure()
    {
        var retryDelete = typeof(WindowsFileIdentity).GetMethod(
            "DeleteOrdinaryFileIfExactWithRetry",
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
        Assert.NotNull(retryDelete);
        Assert.Equal(
            2,
            CountOrdinal(AcceptanceScript(), "DeleteOrdinaryFileIfExactWithRetry("));

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var path = Path.Combine(Path.GetTempPath(), $"ssa-token-delete-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path, "one-time-token");
        try
        {
            var identity = WindowsFileIdentity.Read(path, directory: false).Identity;
            var sha256 = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(path)))
                .ToLowerInvariant();
            using var blocker = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite);
            var release = new Thread(() =>
            {
                Thread.Sleep(200);
                blocker.Dispose();
            })
            {
                IsBackground = true,
                Name = "SimplySignAuto transient delete test release",
            };
            release.Start();

            bool deleted;
            try
            {
                deleted = (bool)retryDelete!.Invoke(
                    null,
                    [path, identity, sha256, 2_000, 20])!;
            }
            finally
            {
                Assert.True(
                    release.Join(TimeSpan.FromSeconds(5)),
                    "Dedicated file-blocker release thread did not exit.");
            }

            Assert.True(deleted);
            Assert.False(File.Exists(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Fresh_install_token_cleanup_preserves_the_last_Win32_delete_failure()
    {
        var retryDelete = typeof(WindowsFileIdentity).GetMethod(
            "DeleteOrdinaryFileIfExactWithRetry",
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
        Assert.NotNull(retryDelete);

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var path = Path.Combine(Path.GetTempPath(), $"ssa-token-delete-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "one-time-token");
        try
        {
            var identity = WindowsFileIdentity.Read(path, directory: false).Identity;
            var sha256 = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)))
                .ToLowerInvariant();
            using var blocker = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite);

            var failure = Assert.Throws<System.Reflection.TargetInvocationException>(() =>
                retryDelete!.Invoke(null, [path, identity, sha256, 100, 20]));
            var native = Assert.IsType<System.ComponentModel.Win32Exception>(failure.InnerException);

            Assert.Equal(32, native.NativeErrorCode);
            Assert.True(File.Exists(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(true, true, false, false, true, false, false)]
    [InlineData(true, true, true, true, true, true, true)]
    [InlineData(true, false, false, true, false, false, true)]
    [InlineData(false, false, false, true, false, false, true)]
    public void Failure_cleanup_is_planned_from_attempts_not_success_flags(
        bool freshInstall,
        bool installInvocationAttempted,
        bool oneTimeTokenObserved,
        bool fixtureInvocationAttempted,
        bool expectedPurge,
        bool expectedTokenCleanup,
        bool expectedFixtureCleanup)
    {
        var plan = FailureCleanupPolicy.Plan(
            freshInstall,
            installInvocationAttempted,
            oneTimeTokenObserved,
            fixtureInvocationAttempted);

        Assert.Equal(expectedPurge, plan.RequirePurgeUninstall);
        Assert.Equal(expectedTokenCleanup, plan.RequireOneTimeTokenCleanup);
        Assert.Equal(expectedFixtureCleanup, plan.RequireFixtureCleanup);
        Assert.True(plan.PreserveFirstFailure);
    }

    [Fact]
    public void Cleanup_sentinel_must_be_an_independent_sibling_and_remain_exact()
    {
        SentinelLayoutPolicy.Validate(
            @"D:\run\fixtures",
            @"D:\run\fixture-external-sentinel.bin",
            "VOL:1:FILE:9",
            "VOL:1:FILE:9",
            Hash('a'),
            Hash('a'));

        AssertCode(
            "acceptance_fixture_sentinel_invalid",
            () => SentinelLayoutPolicy.Validate(
                @"D:\run\fixtures",
                @"D:\run\fixtures\sentinel.bin",
                "VOL:1:FILE:9",
                "VOL:1:FILE:9",
                Hash('a'),
                Hash('a')));
        AssertCode(
            "acceptance_fixture_sentinel_invalid",
            () => SentinelLayoutPolicy.Validate(
                @"D:\run\fixtures",
                @"D:\run\fixture-external-sentinel.bin",
                "VOL:1:FILE:9",
                "VOL:1:FILE:10",
                Hash('a'),
                Hash('b')));
    }

    [Fact]
    public void Only_totp_secrets_are_redacted_from_diagnostics()
    {
        const string secret = "JBSWY3DPEHPK3PXP";
        Assert.True(SecretScanPolicy.ContainsSensitive(
            $"otpauth://totp/Test?secret={secret}"));
        Assert.True(SecretScanPolicy.ContainsSensitive($"raw={secret}", secret));

        string[] retainedValues =
        [
            "Authorization: Bearer AbCdEfGhIjKlMnOpQrStUvWxYz012345",
            "current otp 123456",
            "S-1-5-21-111111111-222222222-333333333-1001",
            "C:\\Users\\signer\\Desktop\\secret.txt",
            "System.Security.Cryptography.CryptographicException: native detail",
        ];

        Assert.All(retainedValues, value => Assert.False(SecretScanPolicy.ContainsSensitive(value, secret)));
    }

    [Fact]
    public void Trx_sanitizer_preserves_diagnostics_and_redacts_only_totp_secrets()
    {
        const string raw = """
            <?xml version="1.0" encoding="utf-8"?>
            <TestRun id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" name="signer@HOST01 2026-08-09" runUser="DOMAIN\signer" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
              <Results>
                <UnitTestResult testId="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" testName="Safe.Test" computerName="HOST01" duration="00:00:00.1" startTime="2026-08-09T00:00:00Z" endTime="2026-08-09T00:00:01Z" testType="cccccccc-cccc-cccc-cccc-cccccccccccc" outcome="Passed" testListId="dddddddd-dddd-dddd-dddd-dddddddddddd" relativeResultsDirectory="C:\Users\signer\AppData\Local\Temp\result" />
              </Results>
              <TestDefinitions><UnitTest name="Safe.Test" storage="C:\repo\bin\SimplySignAuto.EndToEnd.Tests.dll" /></TestDefinitions>
              <ResultSummary outcome="Completed"><Counters total="1" executed="1" passed="1" failed="0" error="0" timeout="0" aborted="0" inconclusive="0" passedButRunAborted="0" notRunnable="0" notExecuted="0" disconnected="0" warning="0" completed="1" inProgress="0" pending="0" /></ResultSummary>
            </TestRun>
            """;

        var sanitized = TrxArtifactPolicy.Sanitize(
            raw,
            "SimplySignAuto.EndToEnd.Tests.dll",
            "HOST01",
            @"DOMAIN\signer");

        Assert.Contains("HOST01", sanitized, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("signer", sanitized, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"C:\", sanitized, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Safe.Test", sanitized, StringComparison.Ordinal);
        Assert.Contains("computerName=\"HOST01\"", sanitized, StringComparison.Ordinal);
        Assert.Contains("storage=\"C:\\repo\\bin\\SimplySignAuto.EndToEnd.Tests.dll\"", sanitized, StringComparison.Ordinal);

        var mutated = raw.Replace(
            "<Results>",
            "<Results injected=\"otpauth://totp/Test?secret=AAAA\">",
            StringComparison.Ordinal);
        var redacted = TrxArtifactPolicy.Sanitize(
            mutated,
            "SimplySignAuto.EndToEnd.Tests.dll",
            "HOST01",
            @"DOMAIN\signer");
        Assert.DoesNotContain("secret=AAAA", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secret=[REDACTED_TOTP_SECRET]", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Actual_vstest_trx_is_sanitized_before_publish_and_secret_mutation_is_rejected()
    {
        var dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        Assert.True(File.Exists(dotnet), "DOTNET_HOST_PATH must identify the current trusted test host.");
        var project = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "SimplySignAuto.EndToEnd.Tests.csproj"));
        Assert.True(File.Exists(project));
        var root = Path.Combine(Path.GetTempPath(), "ssa-trx-behavior", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var start = new System.Diagnostics.ProcessStartInfo
            {
                FileName = dotnet,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var argument in new[]
            {
                "test", project, "-c", "Release", "--no-restore", "--no-build",
                "--logger", "trx;LogFileName=actual.raw.trx", "--results-directory", root,
                "--filter", "FullyQualifiedName~Certificate_serial_input_accepts_bounded_hex_values",
                "-m:1", "-nodeReuse:false",
            })
            {
                start.ArgumentList.Add(argument);
            }

            using var process = System.Diagnostics.Process.Start(start);
            Assert.NotNull(process);
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                throw new Xunit.Sdk.XunitException("nested VSTest did not exit within the bound");
            }
            var output = await stdout;
            var error = await stderr;
            Assert.True(process.ExitCode == 0, output + error);

            var raw = File.ReadAllText(Path.Combine(root, "actual.raw.trx"));
            var xml = new System.Xml.XmlDocument { XmlResolver = null };
            xml.LoadXml(raw);
            var documentElement = Assert.IsType<System.Xml.XmlElement>(xml.DocumentElement);
            var computerName = Assert.IsType<System.Xml.XmlElement>(
                xml.SelectSingleNode("//*[local-name()='UnitTestResult']"))
                .GetAttribute("computerName");
            var generatedRunUser = documentElement.GetAttribute("runUser");
            var runUser = string.IsNullOrWhiteSpace(generatedRunUser)
                ? Environment.UserName
                : generatedRunUser;
            Assert.False(string.IsNullOrWhiteSpace(computerName));
            Assert.False(string.IsNullOrWhiteSpace(runUser));

            var safe = TrxArtifactPolicy.Sanitize(
                raw,
                "SimplySignAuto.EndToEnd.Tests.dll",
                computerName,
                runUser);
            Assert.Contains(computerName, safe, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(runUser, safe, StringComparison.OrdinalIgnoreCase);
            Assert.Contains($"computerName=\"{computerName}\"", safe, StringComparison.Ordinal);

            var mutated = raw.Replace(
                "<Results>",
                "<Results actualSecret=\"otpauth://totp/Test?secret=AAAA\">",
                StringComparison.Ordinal);
            var redacted = TrxArtifactPolicy.Sanitize(
                mutated,
                "SimplySignAuto.EndToEnd.Tests.dll",
                computerName,
                runUser);
            Assert.DoesNotContain("secret=AAAA", redacted, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("secret=[REDACTED_TOTP_SECRET]", redacted, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("52A1B4C9")]
    [InlineData("6f09d233")]
    [InlineData("00FF")]
    public void Certificate_serial_input_accepts_bounded_hex_values(string value)
    {
        Assert.True(AcceptanceInputPolicy.IsCertificateSerialNumber(value));
    }

    [Theory]
    [InlineData(59)]
    [InlineData(1801)]
    public void Timeout_outside_supported_bounds_is_rejected(int timeoutSeconds)
    {
        Assert.False(AcceptanceInputPolicy.IsTimeout(timeoutSeconds));
    }

    [Fact]
    public void Acceptance_http_client_allows_http_mode_without_a_certificate_pin()
    {
        using var client = PinnedHttpClientFactory.Create(string.Empty, new string('A', 43));

        Assert.NotNull(client);
        Assert.Equal("Bearer", client.DefaultRequestHeaders.Authorization?.Scheme);
    }

    [Fact]
    public void Fresh_acceptance_uses_only_the_parameterless_standard_setup_contract()
    {
        var acceptance = AcceptanceScript();

        Assert.Contains("@('http', 'https') -cnotcontains $uri.Scheme", acceptance, StringComparison.Ordinal);
        Assert.Contains("([Uri]$SafeBaseUrl).Scheme -cne 'http'", acceptance, StringComparison.Ordinal);
        Assert.Contains("([Uri]$SafeBaseUrl).Port -ne 7080", acceptance, StringComparison.Ordinal);
        Assert.Contains("Invoke-BoundedSetupUi", acceptance, StringComparison.Ordinal);
        Assert.Contains("$start.FileName = $CanonicalSetup", acceptance, StringComparison.Ordinal);
        Assert.Contains("$start.Arguments = ''", acceptance, StringComparison.Ordinal);
        Assert.Contains("SetupTokenFilePolicy]::ValidateAndExtract", acceptance, StringComparison.Ordinal);
    }

    [Fact]
    public void Fresh_acceptance_uses_the_installed_main_program_for_managed_single_root_hard_stop_cleanup()
    {
        var acceptance = AcceptanceScript();
        var start = acceptance.IndexOf("function Prepare-PurgeRebootStage", StringComparison.Ordinal);
        var end = acceptance.IndexOf("if ($RunChild)", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        var purge = acceptance[start..end];

        Assert.Contains("Invoke-HardStopUninstallAtFirstStagedMove", purge, StringComparison.Ordinal);
        Assert.Contains(
            "@('uninstall', '--purge-data', '--confirm', 'PURGE')",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains("@($manifest.stagingRoots).Count -ne 1", acceptance, StringComparison.Ordinal);
        Assert.Contains("$sourceRoots = @($DataRoot)", purge, StringComparison.Ordinal);
        Assert.Contains("$exactOwnedProfileRemoved =", acceptance, StringComparison.Ordinal);
        Assert.Contains("stagingVolumeCount = $stagingVolumes.Count", acceptance, StringComparison.Ordinal);
    }

    [Fact]
    public void Fresh_setup_precedes_signing_identity_resolution_and_resumes_from_the_exact_boot_task()
    {
        var acceptance = AcceptanceScript();
        var controller = acceptance.LastIndexOf(
            "$script:DiagnosticStage = 'controller_preflight'",
            StringComparison.Ordinal);
        var setup = acceptance.IndexOf("Invoke-FreshSetupStage `", controller, StringComparison.Ordinal);
        var signingIdentity = acceptance.IndexOf(
            "$account = [System.Security.Principal.NTAccount]::new($SigningUser)",
            controller,
            StringComparison.Ordinal);
        var freshResume = acceptance.IndexOf(
            "$checkpoint.phase -ceq 'fresh-install'",
            StringComparison.Ordinal);
        var pendingSummary = acceptance.IndexOf(
            "$pendingSummaryPath = Get-CanonicalExistingPath",
            freshResume,
            StringComparison.Ordinal);

        Assert.True(controller >= 0 && setup > controller && signingIdentity > setup);
        Assert.True(freshResume >= 0 && pendingSummary > freshResume);
        Assert.Contains("Register-ExactBootResumeTask", acceptance, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_ACCEPTANCE_FRESH_STATE", acceptance, StringComparison.Ordinal);
        Assert.Contains("AcceptanceLsaSecret]::StoreNew($lsaKey, $token)", acceptance, StringComparison.Ordinal);
    }

    [Fact]
    public void Fresh_resume_does_not_report_success_before_the_full_matrix_hands_off_to_the_next_reboot()
    {
        var acceptance = AcceptanceScript();
        var freshResume = acceptance.IndexOf(
            "$checkpoint.phase -ceq 'fresh-install'",
            StringComparison.Ordinal);
        var unattendedResume = acceptance.IndexOf(
            "$checkpoint.phase -ceq 'unattended'",
            freshResume,
            StringComparison.Ordinal);
        var branch = acceptance[freshResume..unattendedResume];

        Assert.DoesNotContain("if ($secretAbsent) { break }", branch, StringComparison.Ordinal);
        Assert.Contains("$continuation.WaitForExit", branch, StringComparison.Ordinal);
        Assert.Contains("$continuation.ExitCode -ne 194", branch, StringComparison.Ordinal);
        Assert.True(CountOrdinal(branch, "Assert-BootResumeTaskExact") >= 2);
        Assert.Contains("exit 194", branch, StringComparison.Ordinal);
        Assert.DoesNotContain("        return\n", branch, StringComparison.Ordinal);
    }

    [Fact]
    public void Fresh_resume_reuses_the_setup_run_and_keeps_its_reboot_evidence_in_the_exact_artifact_set()
    {
        var acceptance = AcceptanceScript();

        Assert.Contains(
            "$runIdLocal = [string]$FreshSetupContinuation.Checkpoint.runId",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains(
            "$runDirectory = $FreshSetupContinuation.RunDirectory",
            acceptance,
            StringComparison.Ordinal);
        Assert.Contains("'fresh-setup-completed.json'", acceptance, StringComparison.Ordinal);
        Assert.Contains(
            "Assert-AcceptanceArtifactLayout $canonicalRun $true ($pending.mode -ceq 'FreshInstall')",
            acceptance,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Fresh_setup_timeout_terminates_the_entire_setup_process_tree()
    {
        var acceptance = AcceptanceScript();
        var start = acceptance.IndexOf("function Invoke-BoundedSetupUi", StringComparison.Ordinal);
        var end = acceptance.IndexOf("function Get-DotnetRuntimePreservationEvidence", start, StringComparison.Ordinal);
        var helper = acceptance[start..end];
        var treeStart = acceptance.IndexOf("function Stop-ExactProcessTree", StringComparison.Ordinal);
        var treeEnd = acceptance.IndexOf("function Invoke-BoundedProcessCapture", treeStart, StringComparison.Ordinal);
        var treeHelper = acceptance[treeStart..treeEnd];

        Assert.Contains("/PID $($Process.Id) /T /F", treeHelper, StringComparison.Ordinal);
        Assert.Contains("Stop-ExactProcessTree $process", helper, StringComparison.Ordinal);
        Assert.Contains("throw 'acceptance_process_timeout'", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void Setup_ui_uses_no_arguments_and_observes_the_one_time_install_token()
    {
        var acceptance = AcceptanceScript();
        var start = acceptance.IndexOf("function Invoke-BoundedSetupUi", StringComparison.Ordinal);
        var end = acceptance.IndexOf("function Get-DotnetRuntimePreservationEvidence", start, StringComparison.Ordinal);
        var helper = acceptance[start..end];

        Assert.Contains("$start.Arguments = ''", helper, StringComparison.Ordinal);
        Assert.Contains("Observe-OneTimeInstallToken -Path $ObserveOneTimeTokenPath", helper, StringComparison.Ordinal);
        Assert.Contains("Invoke-SetupUiButton $process '安装'", helper, StringComparison.Ordinal);
        Assert.Contains("Invoke-SetupUiButton $process '关闭'", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void Purge_task_acceptance_matches_the_production_system_boot_task_xml()
    {
        var acceptance = AcceptanceScript();
        var start = acceptance.IndexOf("function Assert-ProductionPurgeTaskExact", StringComparison.Ordinal);
        var end = acceptance.IndexOf("function Assert-InstalledState", start, StringComparison.Ordinal);
        var helper = acceptance[start..end];

        Assert.DoesNotContain(
            "'//t:Principals/t:Principal/t:LogonType' = 'ServiceAccount'",
            helper,
            StringComparison.Ordinal);
        Assert.Contains(
            "$logonTypeNodes = @($taskXml.SelectNodes(",
            helper,
            StringComparison.Ordinal);
        Assert.Contains("if ($logonTypeNodes.Count -ne 0)", helper, StringComparison.Ordinal);
        Assert.Contains("'/t:Task/t:Actions' = 'Exec'", helper, StringComparison.Ordinal);
        Assert.Contains("'/t:Task/t:Triggers' = 'BootTrigger'", helper, StringComparison.Ordinal);
        Assert.Contains("'/t:Task/t:Principals' = 'Principal'", helper, StringComparison.Ordinal);
        Assert.Contains("$containerNodes.Count -ne 1", helper, StringComparison.Ordinal);
        Assert.Contains("$childNodes.Count -ne 1", helper, StringComparison.Ordinal);
        Assert.Contains("$childNodes[0].LocalName -cne $shape.Value", helper, StringComparison.Ordinal);
        Assert.Contains("$childNodes[0].NamespaceURI -cne", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void Fresh_boot_resume_uses_an_administrators_only_staged_script_and_contract_sources()
    {
        var acceptance = AcceptanceScript();

        Assert.Contains("function New-ProtectedResumeSourceBundle", acceptance, StringComparison.Ordinal);
        Assert.Contains("Initialize-AdministratorsOnlyDirectory $resumeRoot", acceptance, StringComparison.Ordinal);
        Assert.Contains("Set-AdministratorsOnlyFileAcl", acceptance, StringComparison.Ordinal);
        Assert.Contains("resumeScriptSha256", acceptance, StringComparison.Ordinal);
        Assert.Contains("acceptanceContractsSha256", acceptance, StringComparison.Ordinal);
        Assert.Contains("strictJsonSha256", acceptance, StringComparison.Ordinal);
        Assert.Contains("$resumeSource.ScriptPath `", acceptance, StringComparison.Ordinal);
        Assert.Contains("$resumeSource.Root `", acceptance, StringComparison.Ordinal);
        Assert.Contains("SIMPLYSIGN_ACCEPTANCE_CONTRACT_ROOT", acceptance, StringComparison.Ordinal);
        Assert.Contains("Assert-ProtectedResumeSourceBundle", acceptance, StringComparison.Ordinal);
    }

    [Fact]
    public void Native_test_routing_and_acceptance_script_use_the_merged_theme_tray_case()
    {
        var interactive = NativeTestRoutingPolicy.GetInteractiveTests();
        var acceptance = AcceptanceScript();
        var repositoryRoot = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var uiIntegrationTests = ReadSourceText(Path.Combine(
            repositoryRoot,
            "tests",
            "SimplySignAuto.UI.Tests",
            "WindowsDesktopIntegrationTests.cs"));
        var expectedTestsStart = acceptance.IndexOf(
            "$ExpectedWindowsNativeTests = @(",
            StringComparison.Ordinal);
        var expectedTestsEnd = acceptance.IndexOf(
            "\n)",
            expectedTestsStart,
            StringComparison.Ordinal);
        var expectedTests = acceptance[expectedTestsStart..expectedTestsEnd];
        const string uiPrefix = "SimplySignAuto.UI.Tests.WindowsDesktopIntegrationTests.";
        const string mergedMethod =
            "Wpf_runtime_preserves_theme_icon_tray_and_opens_settings_on_its_visible_main_window";
        const string merged = uiPrefix + mergedMethod;

        Assert.Equal(11, interactive.Length);
        Assert.Equal(11, interactive.Distinct(StringComparer.Ordinal).Count());
        Assert.All(interactive, test => Assert.True(NativeTestRoutingPolicy.IsInteractive(test)));
        Assert.True(NativeTestRoutingPolicy.IsInteractive(
            "SimplySignAuto.Agent.Tests.DpapiOtpStoreTests.Saves_and_loads_for_current_windows_user"));
        Assert.True(NativeTestRoutingPolicy.IsInteractive(
            "SimplySignAuto.Service.Tests.WindowsSpoolAclPolicyTests.Windows_signing_user_can_delete_only_the_part_it_created"));
        Assert.True(NativeTestRoutingPolicy.IsInteractive(merged));
        Assert.Equal(1, CountOrdinal(
            uiIntegrationTests,
            "public async Task " + mergedMethod + "()"));
        Assert.Equal(42, expectedTests.Split('\n').Count(line =>
            line.TrimStart().StartsWith("'SimplySignAuto.", StringComparison.Ordinal)));
        Assert.Equal(1, CountOrdinal(expectedTests, merged));
        Assert.Equal(1, CountOrdinal(
            acceptance,
            "$ExpectedWindowsNativeTests.Count -ne 42"));
        Assert.Equal(1, CountOrdinal(acceptance, "windowsNativeExecuted = 42"));
    }

    [Fact]
    public void Pdf_dual_validation_binds_one_independent_valid_result_and_both_certificate_chains()
    {
        PdfDualValidationPolicy.Validate(
            projectValidatorOk: true,
            independentExitCode: 0,
            independentOutput: "VALID\r\n",
            documentChainValid: true,
            timestampChainValid: true);
    }

    [Theory]
    [InlineData(false, 0, "VALID\n", true, true)]
    [InlineData(true, 1, "VALID\n", true, true)]
    [InlineData(true, 0, "VALID\nVALID\n", true, true)]
    [InlineData(true, 0, "INDETERMINATE\n", true, true)]
    [InlineData(true, 0, "VALID\n", false, true)]
    [InlineData(true, 0, "VALID\n", true, false)]
    public void Pdf_dual_validation_rejects_missing_ambiguous_or_untrusted_evidence(
        bool projectOk,
        int independentExitCode,
        string independentOutput,
        bool documentChainValid,
        bool timestampChainValid)
    {
        AssertCode(
            "acceptance_pdf_dual_validation_failed",
            () => PdfDualValidationPolicy.Validate(
                projectOk,
                independentExitCode,
                independentOutput,
                documentChainValid,
                timestampChainValid));
    }

    [Fact]
    public void Signature_timestamp_binds_expected_tsa_identity_subject_and_acceptance_window()
    {
        SignatureTimestampPolicy.Validate(
            "2026-08-09T02:03:04Z",
            new DateTimeOffset(2026, 8, 9, 2, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 8, 9, 2, 5, 0, TimeSpan.Zero),
            new string('a', 64),
            new string('a', 64),
            "CN=Certum TSA, O=Asseco Data Systems S.A.",
            "O=Asseco Data Systems S.A.");
    }

    [Fact]
    public void Existing_signature_timestamp_binds_tsa_identity_without_current_acceptance_window()
    {
        SignatureTimestampPolicy.ValidateSignerIdentity(
            "2026-04-24T10:22:28Z",
            new string('a', 64),
            new string('a', 64),
            "CN=Certum TSA, O=Asseco Data Systems S.A.",
            "O=Asseco Data Systems S.A.");
    }

    [Theory]
    [InlineData("2026-08-09T01:54:59Z", 'a', 'a', "O=Asseco Data Systems S.A.")]
    [InlineData("2026-08-09T02:10:01Z", 'a', 'a', "O=Asseco Data Systems S.A.")]
    [InlineData("2026-08-09 02:03:04Z", 'a', 'a', "O=Asseco Data Systems S.A.")]
    [InlineData("2026-08-09T02:03:04Z", 'a', 'b', "O=Asseco Data Systems S.A.")]
    [InlineData("2026-08-09T02:03:04Z", 'a', 'a', "CN=Other TSA")]
    public void Signature_timestamp_rejects_out_of_window_or_wrong_tsa(
        string timestampUtc,
        char actualHash,
        char expectedHash,
        string subject)
    {
        AssertCode(
            "acceptance_timestamp_invalid",
            () => SignatureTimestampPolicy.Validate(
                timestampUtc,
                new DateTimeOffset(2026, 8, 9, 2, 0, 0, TimeSpan.Zero),
                new DateTimeOffset(2026, 8, 9, 2, 5, 0, TimeSpan.Zero),
                new string(actualHash, 64),
                new string(expectedHash, 64),
                subject,
                "O=Asseco Data Systems S.A."));
    }

    [Fact]
    public void Purge_hard_stop_requires_exact_identity_pre_task_termination_wrapper_resume_and_preservation()
    {
        var operationId = new string('a', 32);
        var sources = new[] { @"C:\ProgramData\SimplySignAuto" };
        var staged = new[]
        {
            @"C:\.SimplySignAuto.quarantine.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.0\program-data",
        };

        PurgeHardStopEvidencePolicy.Validate(
            operationId,
            operationId,
            sources,
            sources,
            staged,
            staged,
            stagedTargetCountAtTermination: 1,
            cleanupTaskAbsentAtTermination: true,
            processTreeTerminated: true,
            checkpointSecretScanClean: true,
            rootUninstallResumed: true,
            exactOwnedProductRemoved: true,
            exactOwnedUserRemoved: true,
            exactOwnedProfileRemoved: true,
            simplySignDesktopPreserved: true,
            pkcs11Preserved: true,
            desktopRuntimePreserved: true,
            aspNetCoreRuntimePreserved: true);

        AssertCode(
            "acceptance_purge_hard_stop_invalid",
            () => PurgeHardStopEvidencePolicy.Validate(
                operationId,
                new string('b', 32),
                sources,
                sources,
                staged,
                staged,
                stagedTargetCountAtTermination: 1,
                cleanupTaskAbsentAtTermination: true,
                processTreeTerminated: true,
                checkpointSecretScanClean: true,
                rootUninstallResumed: true,
                exactOwnedProductRemoved: true,
                exactOwnedUserRemoved: true,
                exactOwnedProfileRemoved: true,
                simplySignDesktopPreserved: true,
                pkcs11Preserved: true,
                desktopRuntimePreserved: true,
                aspNetCoreRuntimePreserved: true));
    }

    [Theory]
    [InlineData("source-identity-mismatch")]
    [InlineData("staged-identity-mismatch")]
    [InlineData("no-staged-source")]
    [InlineData("cleanup-task-present")]
    [InlineData("tree-not-terminated")]
    [InlineData("checkpoint-sensitive")]
    [InlineData("wrapper-not-resumed")]
    [InlineData("owned-profile-remains")]
    [InlineData("simplysign-removed")]
    [InlineData("pkcs11-removed")]
    [InlineData("desktop-runtime-removed")]
    [InlineData("aspnet-runtime-removed")]
    [InlineData("extra-source-target")]
    public void Purge_hard_stop_rejects_every_false_green(string mutation)
    {
        var operationId = new string('a', 32);
        var sources = mutation == "extra-source-target"
            ? new[] { @"C:\ProgramData\SimplySignAuto", @"C:\Users\SimplySignAgent\Data" }
            : new[] { @"C:\ProgramData\SimplySignAuto" };
        var staged = mutation == "extra-source-target"
            ? new[]
            {
                @"C:\.SimplySignAuto.quarantine.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.0\program-data",
                @"C:\.SimplySignAuto.quarantine.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.0\agent-data",
            }
            : new[]
            {
                @"C:\.SimplySignAuto.quarantine.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.0\program-data",
            };
        var actualSources = mutation == "source-identity-mismatch"
            ? new[] { @"C:\ProgramData\Other" }
            : sources;
        var actualStaged = mutation == "staged-identity-mismatch"
            ? new[] { staged[0] + "-other" }
            : staged;

        AssertCode(
            "acceptance_purge_hard_stop_invalid",
            () => PurgeHardStopEvidencePolicy.Validate(
                operationId,
                operationId,
                sources,
                actualSources,
                staged,
                actualStaged,
                mutation == "no-staged-source" ? 0 : 1,
                mutation != "cleanup-task-present",
                mutation != "tree-not-terminated",
                mutation != "checkpoint-sensitive",
                mutation != "wrapper-not-resumed",
                true,
                true,
                mutation != "owned-profile-remains",
                mutation != "simplysign-removed",
                mutation != "pkcs11-removed",
                mutation != "desktop-runtime-removed",
                mutation != "aspnet-runtime-removed"));
    }

    [Fact]
    public void Purge_acceptance_hard_stops_once_then_reboots_and_resumes_the_root_wrapper()
    {
        var source = AcceptanceScript();
        var hardStopStart = source.IndexOf(
            "function Invoke-HardStopUninstallAtFirstStagedMove",
            StringComparison.Ordinal);
        var purgeStart = source.IndexOf(
            "function Prepare-PurgeHardStopRebootStage",
            StringComparison.Ordinal);
        var resumeStart = source.IndexOf(
            "$checkpoint.phase -ceq 'purge-hard-stop'",
            StringComparison.Ordinal);

        Assert.True(hardStopStart >= 0 && purgeStart > hardStopStart && resumeStart >= 0);
        Assert.Contains("$stagedTargetCount -lt 1", source, StringComparison.Ordinal);
        Assert.Contains("Get-ScheduledTask -TaskName $manifest.cleanupTaskName", source, StringComparison.Ordinal);
        Assert.Contains("function Stop-ExactProcessTree", source, StringComparison.Ordinal);
        Assert.Contains("/PID $($Process.Id) /T /F", source, StringComparison.Ordinal);
        Assert.Contains("checkpointSecretScanClean", source, StringComparison.Ordinal);
        Assert.Contains("$sourceRoots = @($DataRoot)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("$sourceRoots = @($DataRoot, $profilePath)", source, StringComparison.Ordinal);
        Assert.Contains("@($manifest.targets).Count -ne 1", source, StringComparison.Ordinal);
        Assert.Contains("for ($index = 0; $index -lt 1; $index++)", source, StringComparison.Ordinal);
        Assert.Contains("@($checkpoint.sourcePaths).Count -ne 1", source, StringComparison.Ordinal);
        Assert.Contains("@($checkpoint.stagedPaths).Count -ne 1", source, StringComparison.Ordinal);
        Assert.Contains(
            "$checkpoint.stagedTargetCountAtTermination -ne 1",
            source,
            StringComparison.Ordinal);
        Assert.Contains("@($checkpoint.manifestSourcePaths).Count -ne 1", source, StringComparison.Ordinal);
        Assert.Contains("@($checkpoint.manifestStagedPaths).Count -ne 1", source, StringComparison.Ordinal);
        Assert.Contains("$exactOwnedUserRemoved =", source, StringComparison.Ordinal);
        Assert.Contains("$exactOwnedProfileRemoved =", source, StringComparison.Ordinal);
        Assert.Contains("Invoke-BoundedProcessCapture", source[resumeStart..], StringComparison.Ordinal);
        Assert.Contains(
            "@('uninstall', '--purge-data', '--confirm', 'PURGE')",
            source[resumeStart..],
            StringComparison.Ordinal);
        Assert.Contains("Microsoft.WindowsDesktop.App ", source, StringComparison.Ordinal);
        Assert.Contains("Microsoft.AspNetCore.App ", source, StringComparison.Ordinal);
        Assert.Contains("PurgeHardStopEvidencePolicy]::Validate(", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Purge_hard_stop_resume_uses_ps51_joins_and_defers_final_evidence_until_cleanup_reboot()
    {
        var source = AcceptanceScript();
        var hardStopResumeStart = source.IndexOf(
            "if ($checkpoint.phase -ceq 'purge-hard-stop') {",
            StringComparison.Ordinal);
        var cleanupResumeStart = source.IndexOf(
            "if ($checkpoint.phase -cne 'purge-cleanup') {",
            hardStopResumeStart + 1,
            StringComparison.Ordinal);

        Assert.True(hardStopResumeStart >= 0 && cleanupResumeStart > hardStopResumeStart);
        var hardStopResume = source[hardStopResumeStart..cleanupResumeStart];
        Assert.Contains("Assert-ProductionPurgeTaskExact", hardStopResume, StringComparison.Ordinal);
        var rootWrapperResume = hardStopResume.IndexOf(
            "Invoke-BoundedProcessCapture",
            StringComparison.Ordinal);
        var cleanupTaskReadback = hardStopResume.IndexOf(
            "Assert-ProductionPurgeTaskExact",
            StringComparison.Ordinal);
        var prepareCleanupReboot = hardStopResume.IndexOf(
            "Prepare-PurgeRebootStage",
            StringComparison.Ordinal);
        Assert.True(
            rootWrapperResume >= 0 &&
            cleanupTaskReadback > rootWrapperResume &&
            prepareCleanupReboot > cleanupTaskReadback);
        Assert.DoesNotContain("$watch =", hardStopResume, StringComparison.Ordinal);
        Assert.DoesNotContain("'boot-cleanup.json'", hardStopResume, StringComparison.Ordinal);

        var prepareStart = source.IndexOf(
            "function Prepare-PurgeRebootStage",
            StringComparison.Ordinal);
        var prepareEnd = source.IndexOf(
            "function Prepare-PurgeHardStopRebootStage",
            prepareStart + 1,
            StringComparison.Ordinal);
        Assert.True(prepareStart >= 0 && prepareEnd > prepareStart);
        var prepareCleanupStage = source[prepareStart..prepareEnd];
        Assert.Contains("[System.IO.File]::Replace", prepareCleanupStage, StringComparison.Ordinal);
        Assert.Contains("Assert-BootResumeTaskExact", prepareCleanupStage, StringComparison.Ordinal);
        Assert.Contains(
            "$script:UnattendedRebootCleanupArmed = $false",
            prepareCleanupStage,
            StringComparison.Ordinal);
        Assert.Contains("Restart-Computer -Force", prepareCleanupStage, StringComparison.Ordinal);

        var finalEvidence = source.IndexOf(
            "New-CreateNewText (Join-Path $canonicalRun 'boot-cleanup.json')",
            cleanupResumeStart,
            StringComparison.Ordinal);
        Assert.True(finalEvidence > cleanupResumeStart);
        Assert.Equal(
            finalEvidence,
            source.LastIndexOf(
                "New-CreateNewText (Join-Path $canonicalRun 'boot-cleanup.json')",
                StringComparison.Ordinal));
        Assert.Contains(
            "$desktopRuntimeAfter = [string]::Join(\"`n\", @($runtimeAfter.Desktop))",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "$aspNetCoreRuntimeAfter = [string]::Join(\"`n\", @($runtimeAfter.AspNetCore))",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("-cjoin", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Managed_purge_boot_resume_requires_one_volume_a_real_reboot_and_complete_cleanup()
    {
        PurgeBootEvidencePolicy.Validate(
            new string('a', 32),
            [@"C:\"],
            new DateTimeOffset(2026, 8, 9, 1, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 8, 9, 1, 1, 0, TimeSpan.Zero),
            sourceRootsIsolated: true,
            manifestRemoved: true,
            cleanupTaskRemoved: true,
            stagingRootsRemoved: true,
            resumeTaskOwnerExact: true);
    }

    [Fact]
    public void Unattended_reboot_requires_console_autologon_exact_agent_fresh_heartbeat_and_two_verified_signatures()
    {
        UnattendedRebootEvidencePolicy.Validate(
            new DateTimeOffset(2026, 8, 10, 1, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 8, 10, 1, 1, 0, TimeSpan.Zero),
            3,
            "S-1-5-21-1-2-3-1001",
            "S-1-5-21-1-2-3-1001",
            wtsClientProtocol: 0,
            agentTaskExact: true,
            agentTaskRunning: true,
            agentProcessId: 321,
            agentProcessSessionId: 3,
            heartbeatAgeSeconds: 2,
            readyElapsedSeconds: 42,
            authenticodeReady: true,
            pdfReady: true,
            authenticodeVerified: true,
            pdfVerified: true);
    }

    [Theory]
    [InlineData("no-reboot")]
    [InlineData("session-zero")]
    [InlineData("wrong-sid")]
    [InlineData("rdp")]
    [InlineData("task-not-running")]
    [InlineData("wrong-agent-session")]
    [InlineData("stale-heartbeat")]
    [InlineData("ready-timeout")]
    [InlineData("pdf-not-ready")]
    [InlineData("code-not-verified")]
    public void Unattended_reboot_rejects_every_false_green(string mutation)
    {
        var before = new DateTimeOffset(2026, 8, 10, 1, 0, 0, TimeSpan.Zero);
        AssertCode(
            "acceptance_unattended_reboot_invalid",
            () => UnattendedRebootEvidencePolicy.Validate(
                before,
                mutation == "no-reboot" ? before : before.AddMinutes(1),
                mutation == "session-zero" ? 0 : 3,
                "S-1-5-21-1-2-3-1001",
                mutation == "wrong-sid" ? "S-1-5-21-1-2-3-1002" : "S-1-5-21-1-2-3-1001",
                mutation == "rdp" ? 2 : 0,
                true,
                mutation != "task-not-running",
                321,
                mutation == "wrong-agent-session" ? 4 : 3,
                mutation == "stale-heartbeat" ? 16 : 2,
                mutation == "ready-timeout" ? 301 : 42,
                true,
                mutation != "pdf-not-ready",
                mutation != "code-not-verified",
                true));
    }

    [Fact]
    public void Acceptance_script_reboot_resume_requires_console_protocol_and_real_dual_signing()
    {
        var source = AcceptanceScript();

        Assert.Contains("$bootAfter = Get-CurrentBootUtc", source, StringComparison.Ordinal);
        Assert.Contains("Get-WtsClientProtocol $signingSession", source, StringComparison.Ordinal);
        Assert.Contains("$wtsProtocol -ne 0", source, StringComparison.Ordinal);
        Assert.Contains("Get-ExactAgentProcess $CanonicalApp $signingSession $signingSid", source, StringComparison.Ordinal);
        Assert.Contains("$readyWatch.Elapsed.TotalSeconds -lt 300", source, StringComparison.Ordinal);
        Assert.Contains("$codeJob = Invoke-RebootJob", source, StringComparison.Ordinal);
        Assert.Contains("$pdfJob = Invoke-RebootJob", source, StringComparison.Ordinal);
        Assert.Contains("UnattendedRebootEvidencePolicy]::Validate(", source, StringComparison.Ordinal);
        Assert.Contains("UnattendedRebootCleanupPolicy]::IsIdentityExact(", source, StringComparison.Ordinal);
        Assert.Contains("AcceptanceLsaSecret]::Remove(", source, StringComparison.Ordinal);
        Assert.Contains("Fail-Stable (Invoke-UnattendedRebootCleanup 'acceptance_reboot_failed')", source,
            StringComparison.Ordinal);
        Assert.Contains("$resumeFailure = Invoke-UnattendedRebootCleanup $firstFailure", source,
            StringComparison.Ordinal);
        Assert.Contains("if ($UnattendedRebootCleanupArmed -and $null -ne $StableFailure)", source,
            StringComparison.Ordinal);
        Assert.Contains("$StableFailure = Invoke-UnattendedRebootCleanup $StableFailure", source,
            StringComparison.Ordinal);
        var taskReadback = source.IndexOf(
            "Assert-BootResumeTaskExact $ResumeTaskName $BootResumeExpectedTask",
            StringComparison.Ordinal);
        var taskRemoval = source.IndexOf(
            "Unregister-ScheduledTask -TaskName $ResumeTaskName",
            StringComparison.Ordinal);
        Assert.True(taskReadback > 0 && taskRemoval > taskReadback);
        Assert.DoesNotContain("/dest:rdp", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Post_reboot_process_arms_exact_cleanup_before_invoking_any_resume_preflight()
    {
        var source = AcceptanceScript();
        var resumeBranch = source.LastIndexOf("if ($ResumeAfterReboot)", StringComparison.Ordinal);
        var arm = source.IndexOf(
            "Initialize-PostRebootCleanupState $RunId",
            resumeBranch,
            StringComparison.Ordinal);
        var invoke = source.IndexOf("try { Invoke-RebootResume }", resumeBranch, StringComparison.Ordinal);

        Assert.True(resumeBranch > 0 && arm > resumeBranch && invoke > arm);
    }

    [Theory]
    [InlineData("owner", "Get-Content -LiteralPath (Join-Path $canonicalRun 'owner.txt')")]
    [InlineData("app-missing", "Get-CanonicalExistingPath $AppHostPath Leaf")]
    [InlineData("trust", "Add-TrustedExecutableGuard $canonicalPowerShell")]
    public void Post_reboot_owner_app_and_trust_failures_have_exact_task_ownership_before_they_can_exit(
        string scenario,
        string failureBoundary)
    {
        var source = AcceptanceScript();
        var start = source.IndexOf("function Invoke-RebootResume", StringComparison.Ordinal);
        var end = source.IndexOf("function Prepare-UnattendedRebootStage", start, StringComparison.Ordinal);
        var body = source[start..end];
        var expectation = body.IndexOf(
            "Initialize-PostRebootTaskExpectation",
            StringComparison.Ordinal);
        var boundary = body.IndexOf(failureBoundary, StringComparison.Ordinal);

        Assert.True(expectation >= 0, scenario);
        Assert.True(boundary > expectation, scenario);

        var cleanupStart = source.IndexOf(
            "function Invoke-UnattendedRebootCleanup",
            StringComparison.Ordinal);
        var cleanupEnd = source.IndexOf(
            "function Initialize-AdministratorsOnlyDirectory",
            cleanupStart,
            StringComparison.Ordinal);
        var cleanup = source[cleanupStart..cleanupEnd];
        Assert.Contains("AcceptanceLsaSecret]::Remove(", cleanup, StringComparison.Ordinal);
        Assert.Contains("$secretAbsent = $true", cleanup, StringComparison.Ordinal);
        Assert.Contains(
            "Assert-BootResumeTaskExact $ResumeTaskName $BootResumeExpectedTask",
            cleanup,
            StringComparison.Ordinal);
        Assert.Contains(
            "Unregister-ScheduledTask -TaskName $ResumeTaskName",
            cleanup,
            StringComparison.Ordinal);
        Assert.Contains("$taskAbsent = $null -eq (", cleanup, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("acceptance_owner_invalid")]
    [InlineData("acceptance_path_invalid")]
    [InlineData("acceptance_executable_untrusted")]
    public void Post_reboot_preflight_failure_preserves_first_error_after_exact_lsa_and_task_absence(
        string firstFailure)
    {
        Assert.Equal(
            firstFailure,
            UnattendedRebootCleanupPolicy.Resolve(
                firstFailure,
                new string('a', 32),
                "SimplySignAuto/Acceptance/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Api",
                secretStored: true,
                secretAbsent: true,
                "SimplySignAuto.Acceptance.Boot.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                taskRegistered: true,
                taskOwnershipExact: true,
                taskAbsent: true));
    }

    [Theory]
    [InlineData("acceptance_reboot_failed")]
    [InlineData("acceptance_unattended_reboot_invalid")]
    public void Unattended_reboot_cleanup_preserves_restart_or_session_failure_after_exact_cleanup(
        string firstFailure)
    {
        Assert.Equal(
            firstFailure,
            UnattendedRebootCleanupPolicy.Resolve(
                firstFailure,
                new string('a', 32),
                "SimplySignAuto/Acceptance/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Api",
                secretStored: true,
                secretAbsent: true,
                "SimplySignAuto.Acceptance.Boot.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                taskRegistered: true,
                taskOwnershipExact: true,
                taskAbsent: true));
    }

    [Theory]
    [InlineData("wrong-key")]
    [InlineData("wrong-task")]
    [InlineData("secret-remains")]
    [InlineData("task-owner-swap")]
    [InlineData("task-remains")]
    public void Unattended_reboot_cleanup_failure_upgrades_to_state_uncertain(string mutation)
    {
        Assert.Equal(
            "acceptance_state_uncertain",
            UnattendedRebootCleanupPolicy.Resolve(
                "acceptance_unattended_reboot_invalid",
                new string('a', 32),
                mutation == "wrong-key"
                    ? "SimplySignAuto/Acceptance/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/Api"
                    : "SimplySignAuto/Acceptance/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Api",
                secretStored: true,
                secretAbsent: mutation != "secret-remains",
                mutation == "wrong-task"
                    ? "SimplySignAuto.Acceptance.Boot.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    : "SimplySignAuto.Acceptance.Boot.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                taskRegistered: true,
                taskOwnershipExact: mutation != "task-owner-swap",
                taskAbsent: mutation != "task-remains"));
    }

    [Fact]
    public void Unattended_reboot_cleanup_identity_must_be_exact_before_any_mutation()
    {
        Assert.True(UnattendedRebootCleanupPolicy.IsIdentityExact(
            new string('a', 32),
            "SimplySignAuto/Acceptance/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Api",
            "SimplySignAuto.Acceptance.Boot.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        Assert.False(UnattendedRebootCleanupPolicy.IsIdentityExact(
            new string('a', 32),
            "SimplySignAuto/Acceptance/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/Api",
            "SimplySignAuto.Acceptance.Boot.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    [Theory]
    [InlineData("wrong-volume-count")]
    [InlineData("no-reboot")]
    [InlineData("source-present")]
    [InlineData("manifest-present")]
    [InlineData("task-present")]
    [InlineData("staging-present")]
    [InlineData("resume-owner-mismatch")]
    public void Purge_boot_resume_rejects_every_false_green(string mutation)
    {
        var volumes = mutation == "wrong-volume-count" ? new[] { @"C:\", @"D:\" } : new[] { @"C:\" };
        var before = new DateTimeOffset(2026, 8, 9, 1, 0, 0, TimeSpan.Zero);
        var after = mutation == "no-reboot" ? before : before.AddMinutes(1);
        AssertCode(
            "acceptance_purge_boot_invalid",
            () => PurgeBootEvidencePolicy.Validate(
                new string('a', 32),
                volumes,
                before,
                after,
                mutation != "source-present",
                mutation != "manifest-present",
                mutation != "task-present",
                mutation != "staging-present",
                mutation != "resume-owner-mismatch"));
    }

    [Fact]
    public void Boot_resume_task_requires_exact_system_startup_owner_and_action()
    {
        var expected = new BootResumeTaskSnapshot(
            "S-1-5-18", "ServiceAccount", "Highest", Hash('A'), Hash('B'),
            "AtStartup", "SimplySignAuto/v1", "SimplySignAuto/AcceptanceBoot/v1", 900, 1);

        BootResumeTaskPolicy.Validate(expected, expected);
        AssertCode(
            "acceptance_boot_task_invalid",
            () => BootResumeTaskPolicy.Validate(
                expected,
                new BootResumeTaskSnapshot(
                    "S-1-5-18", "ServiceAccount", "Highest", Hash('A'), Hash('C'),
                    "AtStartup", "SimplySignAuto/v1", "SimplySignAuto/AcceptanceBoot/v1", 900, 1)));
    }

    [Theory]
    [InlineData("SimplySignAuto.Agent.Tests.SigningWorkerTests.Holds_input_handle_without_write_or_delete_sharing_until_signer_finishes")]
    [InlineData("SimplySignAuto.EndToEnd.Tests.InstallCommandTests.Windows_executor_creates_verifies_and_rolls_back_temporary_native_resources")]
    [InlineData("SimplySignAuto.Service.Tests.SpoolStoreTests.Windows_local_upload_hardlink_rejection_preserves_external_hash_owner_and_dacl")]
    [InlineData("")]
    public void Elevated_or_noninteractive_native_tests_never_route_to_the_signing_user(string testName)
    {
        Assert.False(NativeTestRoutingPolicy.IsInteractive(testName));
    }

    private static AcceptanceTaskSnapshot ExpectedTask() => new(
        "SimplySignAuto Acceptance owner=" + new string('a', 32),
        Hash('A'),
        "InteractiveToken",
        "Highest",
        Hash('B'),
        Hash('C'),
        600,
        1);

    private static ReloginTransitionSnapshot[] ReloginTransitions(DateTimeOffset closedAt) =>
    [
        new(1, "UNKNOWN", 8, closedAt.AddSeconds(1), 0),
        new(2, "CHECKING", 8, closedAt.AddSeconds(2), 0),
        new(3, "LOGIN_REQUIRED", 8, closedAt.AddSeconds(3), 0),
        new(4, "LOGINNING", 8, closedAt.AddSeconds(4), 1),
        new(5, "WAIT_TOKEN", 8, closedAt.AddSeconds(5), 1),
        new(6, "READY", 8, closedAt.AddSeconds(6), 1),
    ];

    private static string Hash(char character) => new(character, 64);

    private static string ExactAgentTriggerXml() =>
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
        "<Triggers><LogonTrigger><Enabled>true</Enabled>" +
        "<UserId>S-1-5-21-111-222-333-1001</UserId></LogonTrigger></Triggers></Task>";

    private static string AcceptanceScript() => NormalizeLineEndings(File.ReadAllText(
        Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "..",
                "..",
                "..",
                "..",
                "..",
                "scripts",
                "acceptance-test.ps1"))));

    private static string UiAcceptanceScript() => NormalizeLineEndings(File.ReadAllText(
        Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "..",
                "..",
                "..",
                "..",
                "..",
                "scripts",
                "ui-acceptance.ps1"))));

    private static string NormalizeLineEndings(string value) =>
        value.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static string ReadSourceText(string path) =>
        NormalizeLineEndings(File.ReadAllText(path));

    private static string RepositoryRoot() => Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    private static int CountOrdinal(string source, string value)
    {
        var count = 0;
        var offset = 0;
        while ((offset = source.IndexOf(value, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += value.Length;
        }

        return count;
    }

    private static ExecutableTrustSnapshot TrustedExecutableSnapshot(
        string path,
        string identity,
        string hash,
        bool signatureValid,
        string publisherSha256,
        bool ownerProtected = true,
        bool daclProtected = true,
        bool ancestorsProtected = true) => new(
            path,
            identity,
            hash,
            isOrdinaryFile: true,
            isReparse: false,
            ownerProtected,
            daclProtected,
            ancestorsProtected,
            signatureValid,
            publisherSha256);

    private static void AssertCode(string code, Action action)
    {
        var error = Assert.Throws<AcceptanceContractException>(action);
        Assert.Equal(code, error.Message);
    }
}
