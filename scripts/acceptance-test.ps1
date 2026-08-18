[CmdletBinding(DefaultParameterSetName = 'Controller')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidateSet('FreshInstall', 'ExistingInstall')]
    [string]$Mode,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [string]$RepoPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [string]$ArtifactRoot,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$SigningUser,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$AdministratorUser,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$DotnetPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$DotnetPublisherSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [string]$AppHostPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$AppHostSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$SetupPath,

    [Parameter(ParameterSetName = 'Controller')]
    [AllowEmptyString()]
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -cmatch '^[0-9a-f]{64}$' })]
    [string]$SetupSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$SignToolPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$SignToolPublisherSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$SimplySignDesktopPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$SimplySignPublisherSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$PdfHelperPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$PdfHelperSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$IndependentPdfValidatorPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$IndependentPdfValidatorSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$PowerShellPublisherSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [ValidateLength(1, 1024)]
    [string]$WindowsSystemPublisherSha256Map,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidateCount(1, 16)]
    [string[]]$PdfTrustRootFiles,

    [Parameter(ParameterSetName = 'Controller')]
    [ValidateCount(0, 32)]
    [string[]]$PdfIntermediateCertificateFiles = @(),

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$BaseUrl,

    [Parameter(ParameterSetName = 'Controller')]
    [AllowEmptyString()]
    [ValidateScript({ [string]::IsNullOrEmpty($_) -or $_ -cmatch '^[0-9A-F]{64}$' })]
    [string]$TlsCertificatePin,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$OtpUriFile,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$ApiTokenFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9A-Fa-f]{2,128}$')]
    [string]$CodeSignCertificateSerialNumber,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9A-Fa-f]{2,128}$')]
    [string]$DocumentCertificateSerialNumber,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9A-F]{8}$')]
    [string]$CodeSignThumbprintSuffix,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9A-F]{8}$')]
    [string]$ExistingSignerThumbprintSuffix,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9A-F]{8}$')]
    [string]$DocumentThumbprintSuffix,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$DocumentSignerSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$DocumentSignerCertificateFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$TimestampSignerCertificateFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$TimestampSignerSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[A-Za-z0-9 .,_=()\-]{1,160}$')]
    [string]$TimestampSignerSubjectSuffix,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [string]$PdfFixturePath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$PdfFixtureSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidateRange(1, 10000)]
    [int]$PdfPage,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [ValidateCount(4, 4)]
    [double[]]$PdfBox,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$AgentConfigurationPath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$ExistingSignedPePath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$MsiFixturePath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$MsiFixtureSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$CatFixturePath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$CatFixtureSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$SysFixturePath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$SysFixtureSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$DllFixturePath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$DllFixtureSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$MakeCatPath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$MakeCatPublisherSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$CscPath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$CscPublisherSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$SystemDriverPath,

    [Parameter(ParameterSetName = 'Controller')]
    [string]$SystemDriverPublisherSha256,

    [Parameter(ParameterSetName = 'Controller')]
    [Parameter(ParameterSetName = 'Resume')]
    [ValidateRange(60, 1800)]
    [int]$TimeoutSeconds = 900,

    [Parameter(ParameterSetName = 'Controller')]
    [switch]$AllowMachineMutation,

    [Parameter(ParameterSetName = 'Controller')]
    [switch]$OpenFirewall,

    [Parameter(ParameterSetName = 'Controller')]
    [switch]$KeepInstalledState,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [switch]$RunChild,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RunId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Resume')]
    [switch]$ResumeAfterReboot,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [ValidateRange(1, 2147483647)]
    [int]$ExpectedSessionId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [ValidatePattern('^SimplySignAuto/v1/[0-9a-f]{32}$')]
    [string]$ExpectedAgentTaskSource,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [ValidateRange(60, 1800)]
    [int]$ChildTimeoutSeconds
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$TaskName = $null
$ExpectedTask = $null
$TaskCreated = $false
$StableFailure = $null
$ApiToken = $null
$signingSid = $null
$InstallMutationAttempted = $false
$FixtureInvocationAttempted = $false
$FreshInstallTokenPathForCleanup = $null
$FreshTokenObserved = $false
$FreshTokenFirstIdentity = $null
$FreshTokenCleaned = $false
$FixtureScriptForCleanup = $null
$RunDirectoryForCleanup = $null
$RunIdForCleanup = $null
$CanonicalRepoForCleanup = $null
$CanonicalPowerShellForCleanup = $null
$InteractiveAclFixturePath = $null
$InteractiveAclFixtureIdentity = $null
$InteractiveAclSiblingIdentity = $null
$InteractiveAclSiblingSha256 = $null
$InteractiveAclSiblingPath = $null
$InteractiveAclFixtureCleaned = $false
$InstalledState = $null
$FinalSummary = $null
$SuccessfulRunDirectory = $null
$SuccessfulRunId = $null
$FailureRunDirectory = $null
$FailureRunId = $null
$QueueRecoveryEvidence = $null
$TimeSynchronized = $false
$DiagnosticStage = 'startup'
$TotpSecretForRedaction = ''
$LastProcessDiagnostic = $null
$LastErrorDiagnostic = $null
$PssaClean = $false
$UrlAclExact = $false
$RebootStagePrepared = $false
$ResumeTaskName = $null
$BootResumeExpectedTask = $null
$UnattendedRebootCleanupArmed = $false
$UnattendedRebootLsaKey = $null
$UnattendedRebootSecretStored = $false
$UnattendedRebootTaskRegistered = $false
$AcceptanceStartedUtc = [DateTimeOffset]::UtcNow
$PowerShellPath = (Get-Process -Id $PID).Path
$ExecutableGuards = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$InteractiveWindowsNativeTests = $null
$NativeFixturePathsForCleanup = @()
$ProductionUiEvidence = $null
$ProductionUiDirectory = $null
$FreshSetupResumed = $false
$FreshSetupStatePath = $null
$FreshSetupContinuation = $null
$AutoReloginAfterCloseObserved = $false
$ExpectedWindowsNativeTests = @(
    'SimplySignAuto.Agent.Tests.DpapiOtpStoreTests.Protects_file_acl_for_current_user_and_system_only',
    'SimplySignAuto.Agent.Tests.DpapiOtpStoreTests.Reports_corrupt_when_ciphertext_is_tampered',
    'SimplySignAuto.Agent.Tests.DpapiOtpStoreTests.Saves_and_loads_for_current_windows_user',
    'SimplySignAuto.Agent.Tests.SigningWorkerTests.Holds_input_handle_without_write_or_delete_sharing_until_signer_finishes',
    'SimplySignAuto.Agent.Tests.AgentHostTests.Windows_local_mutex_rejects_a_second_owner_for_the_same_sid',
    'SimplySignAuto.Agent.Tests.LocalJobClientTests.Released_accepted_source_no_longer_blocks_replacing_the_old_source_on_windows',
    'SimplySignAuto.Agent.Tests.DpapiOtpStoreTests.Reports_missing_for_missing_file',
    'SimplySignAuto.Agent.Tests.AgentHostTests.Windows_local_mutex_lease_can_be_disposed_from_a_different_thread',
    'SimplySignAuto.Agent.Tests.AgentHostTests.Windows_session_ending_monitor_can_start_and_stop_its_hidden_window',
    'SimplySignAuto.EndToEnd.Tests.ConfigureServiceCommandTests.Windows_native_protected_publish_guard_blocks_reinstall_after_verification',
    'SimplySignAuto.EndToEnd.Tests.InstallCommandTests.Windows_install_acl_rejects_a_correct_dacl_owned_by_the_signing_user',
    'SimplySignAuto.EndToEnd.Tests.InstallCommandTests.Windows_executor_creates_verifies_and_rolls_back_temporary_native_resources',
    'SimplySignAuto.EndToEnd.Tests.ConfigureServiceCommandTests.Windows_native_protected_publish_guard_blocks_in_place_write_after_verification',
    'SimplySignAuto.EndToEnd.Tests.ConfigureServiceCommandTests.Windows_native_protected_configuration_cas_rejects_in_place_content_change',
    'SimplySignAuto.EndToEnd.Tests.ConfigureServiceCommandTests.Windows_native_protected_configuration_cas_rejects_reinstalled_target',
    'SimplySignAuto.EndToEnd.Tests.ConfigureServiceCommandTests.Windows_native_protected_configuration_rejects_a_reparse_target_without_touching_its_victim',
    'SimplySignAuto.EndToEnd.Tests.UninstallSafetyTests.Windows_atomic_isolation_never_follows_a_root_replaced_with_a_directory_link',
    'SimplySignAuto.Service.Tests.SpoolStoreTests.Windows_local_upload_hardlink_rejection_preserves_external_hash_owner_and_dacl',
    'SimplySignAuto.Service.Tests.UploadedContentValidatorTests.Native_path_validation_guard_denies_delete_during_the_native_call_window',
    'SimplySignAuto.Service.Tests.AgentPipeIdentityTests.Windows_pipe_acl_grants_only_system_and_configured_user',
    'SimplySignAuto.Service.Tests.WindowsSpoolAclPolicyTests.Windows_signing_user_can_delete_only_the_part_it_created',
    'SimplySignAuto.UI.Tests.Desktop.ExternalScenarioAutomationTests.Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy',
    'SimplySignAuto.UI.Tests.Desktop.NavigationAutomationTests.Five_pages_have_fixed_unique_names_and_real_selection_navigation',
    'SimplySignAuto.UI.Tests.Desktop.NavigationAutomationTests.Active_state_disables_relogin_and_settings_use_fake_elevation_only',
    'SimplySignAuto.UI.Tests.WindowsDesktopIntegrationTests.Wpf_runtime_preserves_theme_icon_tray_and_opens_settings_on_its_visible_main_window',
    'SimplySignAuto.UI.Tests.Desktop.ExternalScenarioAutomationTests.Overview_exposes_busy_state_and_opens_the_real_jobs_page',
    'SimplySignAuto.UI.Tests.Desktop.WindowGeometryTests.Real_process_window_is_1024_by_768_landscape_four_by_three',
    'SimplySignAuto.UI.Tests.Desktop.QuickSignAutomationTests.Copy_can_be_cancelled_before_finalizing_and_original_remains_unchanged',
    'SimplySignAuto.UI.Tests.Desktop.QuickSignAutomationTests.Exe_and_pdf_selection_switch_controls_and_submit_without_changing_input',
    'SimplySignAuto.UI.Tests.Desktop.DpiLayoutTests.Activation_primary_action_is_validly_nested_and_reachable_at_all_four_dpi_levels',
    'SimplySignAuto.UI.Tests.Desktop.QuickSignAutomationTests.Jobs_save_uses_signed_default_and_publishes_only_to_the_chosen_artifact_path',
    'SimplySignAuto.UI.Tests.WindowsDesktopIntegrationTests.Activation_pipe_is_exclusive_and_accepts_only_the_current_signing_user',
    'SimplySignAuto.UI.Tests.Desktop.ActivationAutomationTests.Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret',
    'SimplySignAuto.UI.Tests.Desktop.AccessibilityAutomationTests.Every_interactive_element_has_a_stable_non_secret_name',
    'SimplySignAuto.UI.Tests.Desktop.DpiLayoutTests.Four_dpi_levels_render_all_five_real_pages_inside_minimum_and_default_clients',
    'SimplySignAuto.UI.Tests.Desktop.ActivationAutomationTests.Import_is_modal_focus_trapped_escape_clears_and_restores_launcher_focus',
    'SimplySignAuto.UI.Tests.Desktop.AccessibilityAutomationTests.Keyboard_arrows_enter_space_tab_and_escape_drive_the_real_window',
    'SimplySignAuto.UI.Tests.Desktop.NavigationAutomationTests.Overview_refresh_and_close_hide_keep_fake_heartbeat_alive',
    'SimplySignAuto.UI.Tests.WindowsDesktopIntegrationTests.A_preexisting_pipe_squatter_cannot_be_claimed_and_never_starts_the_agent',
    'SimplySignAuto.UI.Tests.Desktop.ExternalScenarioAutomationTests.Quick_sign_exposes_finalizing_before_opening_jobs',
    'SimplySignAuto.UI.Tests.Desktop.ExternalScenarioAutomationTests.Actual_tray_exit_exits_safe_state_and_refuses_active_and_unknown',
    'SimplySignAuto.UI.Tests.Desktop.WindowGeometryTests.Target_window_capture_is_not_replaced_by_a_covering_window'
)

function Fail-Stable {
    param([Parameter(Mandatory = $true)][string]$Code, [int]$ExitCode = 1)
    [Console]::Out.WriteLine($Code)
    exit $ExitCode
}

function Protect-TotpDiagnosticText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    if ('SimplySignAuto.Acceptance.Contracts.SecretScanPolicy' -as [type]) {
        return [SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::Redact(
            $Text,
            [string]$script:TotpSecretForRedaction)
    }
    return [regex]::Replace(
        $Text,
        '(?i)(otpauth://[^\s\r\n]*?(?:[?&]|&amp;)secret=)[^&\s\r\n#<>]+',
        '$1[REDACTED_TOTP_SECRET]')
}

function Get-StableErrorCode {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord, [string]$Fallback)
    $exception = if ($null -ne $ErrorRecord) { $ErrorRecord.Exception } else { $null }
    while ($null -ne $exception) {
        if ($exception.Message -cmatch '^acceptance_[a-z0-9_]+$') {
            return $exception.Message
        }
        $exception = $exception.InnerException
    }
    return $Fallback
}

function Format-AcceptanceDiagnostic {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Code,
        [string]$Stage
    )
    $exception = $ErrorRecord.Exception
    $hresult = '0x{0:X8}' -f (([int64]$exception.HResult) -band 4294967295)
    $nativeError = if ($null -ne $exception.PSObject.Properties['NativeErrorCode']) {
        [string]$exception.NativeErrorCode
    } else { '' }
    $lastProcess = ''
    if ($null -ne $script:LastProcessDiagnostic) {
        $lastProcess = @(
            'last_process_begin',
            "process_stage=$($script:LastProcessDiagnostic.Stage)",
            "process_executable=$($script:LastProcessDiagnostic.Executable)",
            "process_exit_code=$($script:LastProcessDiagnostic.ExitCode)",
            'process_stdout_begin',
            [string]$script:LastProcessDiagnostic.Stdout,
            'process_stdout_end',
            'process_stderr_begin',
            [string]$script:LastProcessDiagnostic.Stderr,
            'process_stderr_end',
            'last_process_end') -join "`n"
    }
    $diagnostic = @(
        'acceptance_diagnostic_begin',
        "stable_code=$Code",
        "stage=$Stage",
        "exception_type=$($exception.GetType().FullName)",
        "message=$($exception.Message)",
        "hresult=$hresult",
        "win32_error=$nativeError",
        "script_name=$($ErrorRecord.InvocationInfo.ScriptName)",
        "script_line=$($ErrorRecord.InvocationInfo.ScriptLineNumber)",
        "offset_in_line=$($ErrorRecord.InvocationInfo.OffsetInLine)",
        "fully_qualified_error_id=$($ErrorRecord.FullyQualifiedErrorId)",
        "category=$($ErrorRecord.CategoryInfo)",
        'position_begin',
        [string]$ErrorRecord.InvocationInfo.PositionMessage,
        'position_end',
        'exception_begin',
        $exception.ToString(),
        'exception_end',
        'script_stack_begin',
        [string]$ErrorRecord.ScriptStackTrace,
        'script_stack_end',
        $lastProcess,
        'acceptance_diagnostic_end') -join "`n"
    return Protect-TotpDiagnosticText $diagnostic
}

function Write-AcceptanceDiagnostic {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Code,
        [string]$Stage,
        [AllowNull()][string]$RunDirectory
    )
    $diagnostic = Format-AcceptanceDiagnostic $ErrorRecord $Code $Stage
    $script:LastErrorDiagnostic = $diagnostic
    [Console]::Error.WriteLine($diagnostic)
    if (-not [string]::IsNullOrWhiteSpace($RunDirectory) -and
        (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
        $stderrPath = Join-Path $RunDirectory 'controller.stderr.txt'
        $stdoutPath = Join-Path $RunDirectory 'controller.stdout.txt'
        if (-not (Test-Path -LiteralPath $stderrPath)) {
            New-CreateNewText $stderrPath $diagnostic
        }
        if (-not (Test-Path -LiteralPath $stdoutPath)) {
            New-CreateNewText $stdoutPath $Code
        }
    }
}

function Get-CanonicalExistingPath {
    param([string]$Path, [ValidateSet('Container', 'Leaf')][string]$Kind)
    if ($Path -notmatch '^[A-Za-z]:\\' -or
        -not [string]::Equals([System.IO.Path]::GetFullPath($Path), $Path, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Path.IndexOfAny([char[]]"`r`n`0") -ge 0) {
        throw 'acceptance_path_invalid'
    }
    $item = Get-Item -LiteralPath $Path -Force
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'acceptance_path_invalid'
        }
        $cursor = if ($cursor -is [System.IO.FileInfo]) { $cursor.Directory } else { $cursor.Parent }
    }
    if (($Kind -eq 'Container' -and -not $item.PSIsContainer) -or ($Kind -eq 'Leaf' -and $item.PSIsContainer)) {
        throw 'acceptance_path_invalid'
    }
    return $item.FullName
}

function Test-PathUnder {
    param([string]$Path, [string]$Root)
    return $Path.StartsWith(
        $Root.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-Sha256Text {
    param([string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') }
    finally { $sha.Dispose(); [System.Array]::Clear($bytes, 0, $bytes.Length) }
}

function New-CreateNewText {
    param([string]$Path, [string]$Text)
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $bytes = $encoding.GetBytes($Text)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
        finally { [System.Array]::Clear($bytes, 0, $bytes.Length) }
    } finally { $stream.Dispose() }
}

function Initialize-ContractSources {
    param([string]$CanonicalRepo)
    if ('SimplySignAuto.Acceptance.Contracts.AcceptanceModePolicy' -as [type]) {
        throw 'acceptance_contract_invalid'
    }
    $contractPath = Get-CanonicalExistingPath -Path (Join-Path $CanonicalRepo 'scripts\AcceptanceContracts.cs') -Kind Leaf
    $contractBytes = [System.IO.File]::ReadAllBytes($contractPath)
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    Add-Type -TypeDefinition $utf8.GetString($contractBytes) -Language CSharp `
        -ReferencedAssemblies @('System.dll', 'System.Core.dll', 'System.Net.Http.dll', 'System.Xml.dll') -ErrorAction Stop
    [System.Array]::Clear($contractBytes, 0, $contractBytes.Length)

    $jsonPath = Get-CanonicalExistingPath -Path (Join-Path $CanonicalRepo 'scripts\UiAcceptanceStrictJson.cs') -Kind Leaf
    $jsonBytes = [System.IO.File]::ReadAllBytes($jsonPath)
    Add-Type -TypeDefinition $utf8.GetString($jsonBytes) -Language CSharp -ErrorAction Stop
    [System.Array]::Clear($jsonBytes, 0, $jsonBytes.Length)
    $script:InteractiveWindowsNativeTests =
        [SimplySignAuto.Acceptance.Contracts.NativeTestRoutingPolicy]::GetInteractiveTests()
}

function Get-CertificateSha256 {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if ($null -eq $Certificate) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $sha.ComputeHash($Certificate.RawData)).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-TrustedAclState {
    param([string]$Path)
    $security = Get-Acl -LiteralPath $Path
    $system = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $admins = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $trusted = New-Object System.Collections.Generic.List[System.Security.Principal.SecurityIdentifier]
    $trusted.Add($system)
    $trusted.Add($admins)
    try {
        $trustedInstaller = [System.Security.Principal.NTAccount]::new('NT SERVICE', 'TrustedInstaller')
        $trusted.Add([System.Security.Principal.SecurityIdentifier]$trustedInstaller.Translate(
                [System.Security.Principal.SecurityIdentifier]))
    } catch {
    }
    $owner = [System.Security.Principal.SecurityIdentifier]$security.GetOwner(
        [System.Security.Principal.SecurityIdentifier])
    $ownerProtected = @($trusted | Where-Object { $_ -eq $owner }).Count -eq 1
    $dangerous = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $daclProtected = $true
    foreach ($rule in $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = [System.Security.Principal.SecurityIdentifier]$rule.IdentityReference
        $isTrusted = @($trusted | Where-Object { $_ -eq $sid }).Count -eq 1
        if (-not $isTrusted -and ($rule.FileSystemRights -band $dangerous) -ne 0) {
            $daclProtected = $false
            break
        }
    }
    return [pscustomobject]@{ OwnerProtected = $ownerProtected; DaclProtected = $daclProtected }
}

function Assert-TrustedRootAcl {
    param([string]$Path)
    $state = Get-TrustedAclState $Path
    if (-not $state.OwnerProtected -or -not $state.DaclProtected) {
        throw 'acceptance_executable_untrusted'
    }
}

function Begin-FreshSetupContinuation {
    param(
        [string]$CanonicalArtifactRoot,
        [string]$CanonicalApp
    )
    $runIdLocal = [Environment]::GetEnvironmentVariable('SIMPLYSIGN_ACCEPTANCE_FRESH_RUN_ID')
    $checkpointInput = [Environment]::GetEnvironmentVariable('SIMPLYSIGN_ACCEPTANCE_FRESH_STATE')
    if ($Mode -cne 'FreshInstall' -or
        $runIdLocal -cnotmatch '^[0-9a-f]{32}$' -or
        [string]::IsNullOrWhiteSpace($checkpointInput)) {
        return $null
    }
    $checkpointPath = Get-CanonicalExistingPath $checkpointInput Leaf
    if (-not (Test-PathUnder $checkpointPath $CanonicalArtifactRoot) -or
        [System.IO.Path]::GetFileName($checkpointPath) -cne 'checkpoint.json' -or
        [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($checkpointPath)) -cne '.reboot') {
        throw 'acceptance_owner_invalid'
    }
    $runDirectory = Get-CanonicalExistingPath `
        ([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetDirectoryName($checkpointPath))) `
        Container
    if ([System.IO.Path]::GetFileName($runDirectory) -cne $runIdLocal -or
        (Get-Content -LiteralPath (Join-Path $runDirectory 'owner.txt') -Raw) -cne $runIdLocal) {
        throw 'acceptance_owner_invalid'
    }
    $checkpoint = ConvertFrom-StrictJson (Get-Content -LiteralPath $checkpointPath -Raw)
    Assert-ExactProperties $checkpoint @(
        'schemaVersion', 'phase', 'runId', 'acceptanceStartedUtc', 'bootBeforeUtc',
        'administratorUser', 'administratorSid', 'signingUser', 'signingSid',
        'installInstanceHash', 'agentTaskSource', 'controllerStateFile', 'controllerStateSha256',
        'resumeScriptSha256', 'acceptanceContractsSha256', 'strictJsonSha256')
    if ($checkpoint.schemaVersion -ne 1 -or
        $checkpoint.phase -cne 'fresh-install' -or
        $checkpoint.runId -cne $runIdLocal -or
        $checkpoint.administratorUser -cne $AdministratorUser -or
        $checkpoint.signingUser -cne $SigningUser -or
        $checkpoint.controllerStateFile -cne 'controller-parameters.clixml' -or
        $checkpoint.controllerStateSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $checkpoint.installInstanceHash -cnotmatch '^[0-9A-F]{64}$' -or
        $checkpoint.agentTaskSource -cnotmatch '^SimplySignAuto/v1/[0-9a-f]{32}$') {
        throw 'acceptance_fresh_install_state_invalid'
    }
    $statePath = Get-CanonicalExistingPath `
        (Join-Path ([System.IO.Path]::GetDirectoryName($checkpointPath)) $checkpoint.controllerStateFile) `
        Leaf
    if ((Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        [string]$checkpoint.controllerStateSha256) {
        throw 'acceptance_fresh_install_state_invalid'
    }
    $resume = Assert-ProtectedResumeSourceBundle `
        $runDirectory `
        ([string]$checkpoint.resumeScriptSha256) `
        ([string]$checkpoint.acceptanceContractsSha256) `
        ([string]$checkpoint.strictJsonSha256)
    $started = [DateTimeOffset]::MinValue
    $bootBefore = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$checkpoint.acceptanceStartedUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal',
            [ref]$started) -or
        -not [DateTimeOffset]::TryParseExact(
            [string]$checkpoint.bootBeforeUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal',
            [ref]$bootBefore) -or
        (Get-CurrentBootUtc) -le $bootBefore) {
        throw 'acceptance_fresh_install_reboot_invalid'
    }
    $administratorSid = [System.Security.Principal.NTAccount]::new($AdministratorUser).Translate(
        [System.Security.Principal.SecurityIdentifier])
    $signingSid = [System.Security.Principal.NTAccount]::new($SigningUser).Translate(
        [System.Security.Principal.SecurityIdentifier])
    $script:signingSid = $signingSid
    if ($administratorSid.Value -cne [string]$checkpoint.administratorSid -or
        $signingSid.Value -cne [string]$checkpoint.signingSid) {
        throw 'acceptance_fresh_install_session_invalid'
    }
    $sessionWatch = [Diagnostics.Stopwatch]::StartNew()
    $administratorSession = $null
    $signingSession = $null
    do {
        try { $administratorSession = Get-UniqueActiveSession $administratorSid } catch {
            if ($_.Exception.Message -cne 'acceptance_session_unavailable') { throw }
        }
        try { $signingSession = Get-UniqueActiveSession $signingSid } catch {
            if ($_.Exception.Message -cne 'acceptance_session_unavailable') { throw }
        }
        if ($null -ne $administratorSession -and $null -ne $signingSession) { break }
        Start-Sleep -Milliseconds 500
    } while ($sessionWatch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    if ($null -eq $administratorSession -or $null -eq $signingSession) {
        throw 'acceptance_fresh_install_session_invalid'
    }
    if ((Get-WtsClientProtocol $signingSession) -ne 0) {
        throw 'acceptance_fresh_install_session_invalid'
    }
    $lsaKey = "SimplySignAuto/Acceptance/$runIdLocal/Api"
    $token = [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::Retrieve($lsaKey)
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'acceptance_install_token_invalid'
    }
    [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::Remove($lsaKey)
    $script:AcceptanceStartedUtc = $started
    $script:FreshSetupStatePath = $checkpointPath
    [Environment]::SetEnvironmentVariable('SIMPLYSIGN_ACCEPTANCE_FRESH_RUN_ID', $null)
    [Environment]::SetEnvironmentVariable('SIMPLYSIGN_ACCEPTANCE_FRESH_STATE', $null)
    return [pscustomobject]@{
        Token = $token
        Checkpoint = $checkpoint
        CheckpointPath = $checkpointPath
        StatePath = $statePath
        RunDirectory = $runDirectory
        SigningSid = $signingSid
        SigningSession = $signingSession
        CanonicalApp = $CanonicalApp
        Resume = $resume
    }
}

function Complete-FreshSetupContinuation {
    param(
        $Continuation,
        $InstalledState
    )
    if ($InstalledState.InstallInstanceHash -cne [string]$Continuation.Checkpoint.installInstanceHash -or
        $InstalledState.AgentTask.Source -cne [string]$Continuation.Checkpoint.agentTaskSource) {
        throw 'acceptance_fresh_install_state_invalid'
    }
    $rawDirectory = [System.IO.Path]::GetDirectoryName($Continuation.CheckpointPath)
    Remove-Item -LiteralPath $Continuation.StatePath -Force
    Remove-Item -LiteralPath $Continuation.CheckpointPath -Force
    if (@(Get-ChildItem -LiteralPath $rawDirectory -Force).Count -ne 0) {
        throw 'acceptance_state_uncertain'
    }
    Remove-Item -LiteralPath $rawDirectory -Force
    $evidence = [ordered]@{
        schemaVersion = 1
        runId = [string]$Continuation.Checkpoint.runId
        state = 'setup-reboot-verified'
        signingSid = [string]$Continuation.Checkpoint.signingSid
        installInstanceHash = [string]$Continuation.Checkpoint.installInstanceHash
    } | ConvertTo-Json -Compress
    New-CreateNewText (Join-Path $Continuation.RunDirectory 'fresh-setup-completed.json') $evidence
}

function Get-CanonicalAcceptanceRoot {
    param([string]$CanonicalRepo)
    $acceptanceRoot = Get-CanonicalExistingPath `
        ([System.IO.Path]::GetDirectoryName($CanonicalRepo)) `
        Container
    Assert-TrustedRootAcl $acceptanceRoot
    return $acceptanceRoot
}

function Test-ProtectedAncestorChain {
    param([string]$Path, [string[]]$TrustedRoots)

    $parent = [System.IO.Path]::GetDirectoryName($Path)
    foreach ($root in $TrustedRoots) {
        if (-not (Test-PathUnder -Path $Path -Root $root)) { continue }
        $cursor = $parent
        while (-not [string]::IsNullOrWhiteSpace($cursor)) {
            $acl = Get-TrustedAclState $cursor
            if (-not $acl.OwnerProtected -or -not $acl.DaclProtected) { break }
            if ([string]::Equals($cursor, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
            $next = [System.IO.Path]::GetDirectoryName($cursor)
            if ([string]::Equals($next, $cursor, [System.StringComparison]::OrdinalIgnoreCase)) { break }
            $cursor = $next
        }
    }
    return $false
}

function Get-ExecutableTrustSnapshot {
    param([string]$Path, [string[]]$TrustedRoots)
    $item = Get-Item -LiteralPath $Path -Force
    $acl = Get-TrustedAclState $Path
    $identity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($Path, $false)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    return [SimplySignAuto.Acceptance.Contracts.ExecutableTrustSnapshot]::new(
        $item.FullName,
        $identity.Identity,
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant(),
        -not $item.PSIsContainer,
        (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0),
        [bool]$acl.OwnerProtected,
        [bool]$acl.DaclProtected,
        (Test-ProtectedAncestorChain $Path $TrustedRoots),
        ($signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid),
        (Get-CertificateSha256 $signature.SignerCertificate))
}

function Add-TrustedExecutableGuard {
    param(
        [string]$Path,
        [string[]]$TrustedRoots,
        [ValidateSet('PlatformPublisher', 'ManifestSha256')][string]$TrustKind,
        [string]$ExpectedSha256
    )
    if ($ExecutableGuards.ContainsKey($Path)) { return }
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $snapshot = Get-ExecutableTrustSnapshot $Path $TrustedRoots
        $kind = [SimplySignAuto.Acceptance.Contracts.ExecutableTrustKind]::$TrustKind
        try {
            [SimplySignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
                $snapshot, $snapshot, $TrustedRoots, $kind, $ExpectedSha256)
        }
        catch {
            $diagnostic = @(
                'trusted_executable_diagnostic_begin',
                "path=$($snapshot.Path)",
                "trust_kind=$TrustKind",
                "expected_sha256=$ExpectedSha256",
                "trusted_roots=$($TrustedRoots -join ';')",
                "actual_identity=$($snapshot.Identity)",
                "actual_file_sha256=$($snapshot.Sha256)",
                "actual_publisher_sha256=$($snapshot.PublisherSha256)",
                "is_ordinary_file=$($snapshot.IsOrdinaryFile)",
                "is_reparse=$($snapshot.IsReparse)",
                "owner_protected=$($snapshot.OwnerProtected)",
                "dacl_protected=$($snapshot.DaclProtected)",
                "ancestors_protected=$($snapshot.AncestorsProtected)",
                "signature_valid=$($snapshot.SignatureValid)",
                "exception_type=$($_.Exception.GetType().FullName)",
                "exception_message=$($_.Exception.Message)",
                'trusted_executable_diagnostic_end') -join "`n"
            [Console]::Error.WriteLine((Protect-TotpDiagnosticText $diagnostic))
            throw
        }
        $ExecutableGuards.Add($Path, [pscustomobject]@{
                Stream = $stream
                Snapshot = $snapshot
                TrustedRoots = $TrustedRoots
                TrustKind = $kind
                ExpectedSha256 = $ExpectedSha256
            })
        $stream = $null
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Assert-TrustedExecutableUnchanged {
    param([string]$Path)
    if (-not $ExecutableGuards.ContainsKey($Path)) { throw 'acceptance_executable_untrusted' }
    $guard = $ExecutableGuards[$Path]
    $after = Get-ExecutableTrustSnapshot $Path ([string[]]$guard.TrustedRoots)
    [SimplySignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
        $guard.Snapshot,
        $after,
        [string[]]$guard.TrustedRoots,
        $guard.TrustKind,
        [string]$guard.ExpectedSha256)
}

function Close-TrustedExecutableGuards {
    foreach ($guard in $ExecutableGuards.Values) {
        try { Assert-TrustedExecutableUnchanged $guard.Snapshot.Path } finally { $guard.Stream.Dispose() }
    }
    $ExecutableGuards.Clear()
}

function Close-TrustedExecutableGuard {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not $ExecutableGuards.ContainsKey($Path)) { return }
    $guard = $ExecutableGuards[$Path]
    try {
        [SimplySignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
            $guard.Snapshot,
            (Get-ExecutableTrustSnapshot $Path ([string[]]$guard.TrustedRoots)),
            [string[]]$guard.TrustedRoots,
            $guard.TrustKind,
            [string]$guard.ExpectedSha256)
    } finally {
        $guard.Stream.Dispose()
        $ExecutableGuards.Remove($Path) | Out-Null
    }
}

function ConvertFrom-StrictJson {
    param([string]$Json)
    if ($Json -isnot [string] -or [string]::IsNullOrWhiteSpace($Json) -or $Json.Length -gt 1048576) {
        throw 'acceptance_json_invalid'
    }
    [SimplySignAuto.UiAcceptance.StrictJson.Preflight]::ValidateObject($Json, 24, 1048576)
    $value = $Json | ConvertFrom-Json
    if ($null -eq $value -or $value -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'acceptance_json_invalid'
    }
    return $value
}

function Assert-ExactProperties {
    param($Value, [string[]]$Expected)
    if ($Value -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'acceptance_json_invalid'
    }
    [SimplySignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact(
        $Expected,
        @($Value.PSObject.Properties.Name))
}

function ConvertTo-SafeArgument {
    param([string]$Value)
    if ($Value.IndexOfAny([char[]]"`r`n`0`"") -ge 0 -or $Value.EndsWith('\', [System.StringComparison]::Ordinal)) {
        throw 'acceptance_process_argument_invalid'
    }
    if ($Value -match '\s') { return '"' + $Value + '"' }
    return $Value
}

function Get-ProcessDiagnosticFromTask {
    param(
        [System.Diagnostics.Process]$Process,
        [string]$Executable,
        [System.Threading.Tasks.Task]$StdoutTask,
        [System.Threading.Tasks.Task]$StderrTask
    )
    $completed = [System.Threading.Tasks.TaskStatus]::RanToCompletion
    return [pscustomobject]@{
        Stage = $script:DiagnosticStage
        Executable = $Executable
        ExitCode = if ($Process.HasExited) { $Process.ExitCode } else { -1 }
        Stdout = if ($StdoutTask.Status -eq $completed) {
            [string]$StdoutTask.Result
        } else { '[stdout capture incomplete]' }
        Stderr = if ($StderrTask.Status -eq $completed) {
            [string]$StderrTask.Result
        } else { '[stderr capture incomplete]' }
    }
}

function Stop-ExactProcessTree {
    param([System.Diagnostics.Process]$Process)
    if ($Process.HasExited) { return $false }
    $taskkill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
    if (-not $ExecutableGuards.ContainsKey($taskkill)) {
        throw 'acceptance_executable_untrusted'
    }
    Assert-TrustedExecutableUnchanged $taskkill
    $killer = [System.Diagnostics.Process]::Start(
        $taskkill,
        "/PID $($Process.Id) /T /F")
    if ($null -eq $killer) { throw 'acceptance_state_uncertain' }
    try {
        if (-not $killer.WaitForExit(10000) -or $killer.ExitCode -ne 0 -or
            -not $Process.WaitForExit(10000)) {
            throw 'acceptance_state_uncertain'
        }
    } finally { $killer.Dispose() }
    Assert-TrustedExecutableUnchanged $taskkill
    return $true
}

function Invoke-BoundedProcessCapture {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [int]$BoundSeconds,
        [string]$StandardInput,
        [string]$ObserveOneTimeTokenPath
    )
    if (-not $ExecutableGuards.ContainsKey($Executable)) { throw 'acceptance_executable_untrusted' }
    Assert-TrustedExecutableUnchanged $Executable
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.Arguments = (@($Arguments | ForEach-Object { ConvertTo-SafeArgument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $null -ne $StandardInput
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    $script:LastProcessDiagnostic = $null
    $stdout = $null
    $stderr = $null
    try {
        if (-not $process.Start()) { throw 'acceptance_process_start_failed' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($null -ne $StandardInput) {
            $process.StandardInput.Write($StandardInput)
            $process.StandardInput.Close()
        }
        $exited = $false
        if ([string]::IsNullOrWhiteSpace($ObserveOneTimeTokenPath)) {
            $exited = $process.WaitForExit($BoundSeconds * 1000)
        } else {
            $watch = [System.Diagnostics.Stopwatch]::StartNew()
            do {
                Observe-OneTimeInstallToken -Path $ObserveOneTimeTokenPath
                $exited = $process.WaitForExit(100)
            } while (-not $exited -and $watch.Elapsed.TotalSeconds -lt $BoundSeconds)
            Observe-OneTimeInstallToken -Path $ObserveOneTimeTokenPath
        }
        if (-not $exited) {
            $null = Stop-ExactProcessTree $process
            try {
                [System.Threading.Tasks.Task]::WaitAll(
                    [System.Threading.Tasks.Task[]]@($stdout, $stderr), 10000) | Out-Null
            } catch { $null = $_.Exception }
            $script:LastProcessDiagnostic = Get-ProcessDiagnosticFromTask $process $Executable $stdout $stderr
            throw 'acceptance_process_timeout'
        }
        if (-not [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($stdout, $stderr), 10000)) {
            $script:LastProcessDiagnostic = Get-ProcessDiagnosticFromTask $process $Executable $stdout $stderr
            throw 'acceptance_process_cleanup_timeout'
        }
        $script:LastProcessDiagnostic = Get-ProcessDiagnosticFromTask $process $Executable $stdout $stderr
        $result = [pscustomobject]@{
            ExitCode = $script:LastProcessDiagnostic.ExitCode
            Stdout = $script:LastProcessDiagnostic.Stdout
            Stderr = $script:LastProcessDiagnostic.Stderr
        }
        return $result
    } finally {
        if ($null -ne $process -and -not $process.HasExited) {
            try { $process.Kill(); $process.WaitForExit(10000) | Out-Null } catch {}
        }
        $process.Dispose()
        Assert-TrustedExecutableUnchanged $Executable
    }
}

function Invoke-SetupUiButton {
    param(
        [System.Diagnostics.Process]$Process,
        [string]$ButtonName
    )
    if ($Process.HasExited -or $Process.MainWindowHandle -eq [IntPtr]::Zero) {
        return $false
    }

    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $window = [System.Windows.Automation.AutomationElement]::FromHandle($Process.MainWindowHandle)
    if ($null -eq $window) { return $false }
    $condition = [System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            $ButtonName),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Button))
    $button = $window.FindFirst([System.Windows.Automation.TreeScope]::Subtree, $condition)
    $pattern = $null
    if ($null -eq $button -or
        -not $button.TryGetCurrentPattern(
            [System.Windows.Automation.InvokePattern]::Pattern,
            [ref]$pattern)) {
        return $false
    }

    ([System.Windows.Automation.InvokePattern]$pattern).Invoke()
    return $true
}

function Invoke-BoundedSetupUi {
    param(
        [string]$CanonicalSetup,
        [int]$BoundSeconds,
        [string]$ObserveOneTimeTokenPath
    )
    if (-not $ExecutableGuards.ContainsKey($CanonicalSetup)) {
        throw 'acceptance_executable_untrusted'
    }
    Assert-TrustedExecutableUnchanged $CanonicalSetup
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $CanonicalSetup
    $start.Arguments = ''
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $false
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'acceptance_process_start_failed' }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $installStarted = $false
        do {
            $process.Refresh()
            Observe-OneTimeInstallToken -Path $ObserveOneTimeTokenPath
            if (-not $installStarted) {
                try { $installStarted = Invoke-SetupUiButton $process '安装' }
                catch { $installStarted = $false }
            } else {
                try { $null = Invoke-SetupUiButton $process '关闭' }
                catch { $null = $_.Exception }
            }
            if ($process.WaitForExit(100)) { break }
        } while ($watch.Elapsed.TotalSeconds -lt $BoundSeconds)
        Observe-OneTimeInstallToken -Path $ObserveOneTimeTokenPath
        if (-not $process.HasExited) {
            $null = Stop-ExactProcessTree $process
            throw 'acceptance_process_timeout'
        }
        return [pscustomobject]@{ ExitCode = $process.ExitCode }
    } finally {
        if (-not $process.HasExited) {
            try { $null = Stop-ExactProcessTree $process } catch { $null = $_.Exception }
        }
        $process.Dispose()
        Assert-TrustedExecutableUnchanged $CanonicalSetup
    }
}

function Get-DotnetRuntimePreservationEvidence {
    param([string]$CanonicalDotnet, [int]$BoundSeconds)
    $result = Invoke-BoundedProcessCapture `
        $CanonicalDotnet `
        @('--list-runtimes') `
        $BoundSeconds `
        $null `
        $null
    if ($result.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($result.Stderr)) {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    $lines = @($result.Stdout.Replace("`r`n", "`n").Split("`n") | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        })
    $desktop = @($lines | Where-Object { $_.StartsWith(
                'Microsoft.WindowsDesktop.App ',
                [System.StringComparison]::Ordinal) })
    $aspNetCore = @($lines | Where-Object { $_.StartsWith(
                'Microsoft.AspNetCore.App ',
                [System.StringComparison]::Ordinal) })
    if ($desktop.Count -lt 1 -or $aspNetCore.Count -lt 1 -or
        @($desktop + $aspNetCore | Where-Object {
                $_ -cnotmatch '^Microsoft\.(?:WindowsDesktop|AspNetCore)\.App [^\s]+ \[[A-Za-z]:\\[^\r\n\[\]]+\]$'
            }).Count -ne 0) {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    return [pscustomobject]@{
        Desktop = $desktop
        AspNetCore = $aspNetCore
    }
}

function Observe-OneTimeInstallToken {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($script:FreshTokenObserved -or -not (Test-Path -LiteralPath $Path)) { return }
    try {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [string]::Equals($item.FullName, $Path, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'acceptance_state_uncertain'
        }
        $identity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($Path, $false)
        if ($identity.LinkCount -ne 1) { throw 'acceptance_state_uncertain' }
        $script:FreshTokenFirstIdentity = $identity.Identity
        $script:FreshTokenObserved = $true
    } catch [System.IO.FileNotFoundException] {
        return
    }
}

function Read-SecretFile {
    param([string]$Path)
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 4096) { throw 'acceptance_secret_file_invalid' }
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.UTF8Encoding]::new($false, $true), $true, 4096, $true)
        try { $value = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $trimmed = $value.TrimEnd("`r", "`n")
    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.IndexOfAny([char[]]"`r`n`0") -ge 0) {
        throw 'acceptance_secret_file_invalid'
    }
    return $trimmed
}

function Read-SetupTokenFile {
    param([string]$Path)
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::None)
    try {
        if ($stream.Length -lt 44 -or $stream.Length -gt 45) {
            throw 'acceptance_install_token_invalid'
        }
        $reader = [System.IO.StreamReader]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false, $true),
            $false,
            128,
            $true)
        try { return $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    } finally {
        $stream.Dispose()
    }
}

function Assert-SecretAcl {
    param(
        [string]$Path,
        [System.Security.Principal.SecurityIdentifier]$SigningSid,
        [ValidateSet('SigningUser', 'Machine', 'AnyRestricted')]
        [string]$OwnerPolicy
    )
    $security = (Get-Item -LiteralPath $Path -Force).GetAccessControl()
    $owner = [System.Security.Principal.SecurityIdentifier]$security.GetOwner([System.Security.Principal.SecurityIdentifier])
    $system = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $admins = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $ownerAllowed = switch ($OwnerPolicy) {
        'SigningUser' { $owner -eq $SigningSid }
        'Machine' { $owner -eq $admins -or $owner -eq $system }
        'AnyRestricted' { $owner -eq $SigningSid -or $owner -eq $admins -or $owner -eq $system }
    }
    if (-not $security.AreAccessRulesProtected -or -not $ownerAllowed) {
        throw 'acceptance_secret_acl_invalid'
    }
    foreach ($rule in $security.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        $sid = [System.Security.Principal.SecurityIdentifier]$rule.IdentityReference
        if ($sid -ne $SigningSid -and $sid -ne $system -and $sid -ne $admins) {
            throw 'acceptance_secret_acl_invalid'
        }
    }
}

function Assert-ProtectedAcl {
    param(
        [string]$Path,
        [System.Security.Principal.SecurityIdentifier]$SigningSid,
        [ValidateSet('AdministratorsOnly', 'SigningUserModify', 'SigningUserRead', 'SigningUserData')]
        [string]$Profile,
        [bool]$Directory
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Directory -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'acceptance_install_acl_invalid'
    }
    $security = $item.GetAccessControl()
    $system = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $admins = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $owner = [System.Security.Principal.SecurityIdentifier]$security.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (-not $security.AreAccessRulesProtected -or $owner -ne $system) {
        throw 'acceptance_install_acl_invalid'
    }
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $expected = New-Object System.Collections.Generic.List[object]
    $expected.Add([pscustomobject]@{ Sid = $system; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl })
    $expected.Add([pscustomobject]@{ Sid = $admins; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl })
    $modifyRights = [System.Security.AccessControl.FileSystemRights]::Modify -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    $readAndExecuteRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    if ($Profile -eq 'SigningUserModify') {
        $expected.Add([pscustomobject]@{ Sid = $SigningSid; Rights = $modifyRights })
    } elseif ($Profile -eq 'SigningUserRead') {
        $expected.Add([pscustomobject]@{ Sid = $SigningSid; Rights = $readAndExecuteRights })
    } elseif ($Profile -eq 'SigningUserData') {
        $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
            [System.Security.AccessControl.FileSystemRights]::Write -bor
            [System.Security.AccessControl.FileSystemRights]::Synchronize
        $expected.Add([pscustomobject]@{ Sid = $SigningSid; Rights = $rights })
    }
    $rules = @($security.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expected.Count) { throw 'acceptance_install_acl_invalid' }
    foreach ($wanted in $expected) {
        $matches = @($rules | Where-Object {
            $_.IdentityReference -eq $wanted.Sid -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $_.FileSystemRights -eq $wanted.Rights -and
            $_.InheritanceFlags -eq $inheritance -and
            $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None -and
            -not $_.IsInherited
        })
        if ($matches.Count -ne 1) { throw 'acceptance_install_acl_invalid' }
    }
}

function Get-AgentTaskExecutionSnapshot {
    param([string]$CanonicalApp)
    [xml]$taskXml = Export-ScheduledTask -TaskName 'SimplySignAuto.Agent'
    $trigger = [SimplySignAuto.Acceptance.Contracts.AgentTaskTriggerXmlPolicy]::Read(
        $taskXml.OuterXml)
    $namespace = [System.Xml.XmlNamespaceManager]::new($taskXml.NameTable)
    $namespace.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    function Get-TaskNodeText {
        param([string]$XPath)
        $nodes = @($taskXml.SelectNodes($XPath, $namespace))
        if ($nodes.Count -ne 1) { throw 'acceptance_agent_task_invalid' }
        return [string]$nodes[0].InnerText
    }
    $principalAccount = [System.Security.Principal.NTAccount]::new(
        (Get-TaskNodeText '//t:Principals/t:Principal/t:UserId'))
    $principalSid = [System.Security.Principal.SecurityIdentifier]$principalAccount.Translate(
        [System.Security.Principal.SecurityIdentifier])
    $command = Get-TaskNodeText '//t:Actions/t:Exec/t:Command'
    if (-not [string]::Equals($command, $CanonicalApp, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'acceptance_agent_task_invalid'
    }
    return [SimplySignAuto.Acceptance.Contracts.AgentTaskExecutionSnapshot]::new(
        $principalSid.Value,
        $command,
        (Get-TaskNodeText '//t:Actions/t:Exec/t:Arguments'),
        (Get-TaskNodeText '//t:Principals/t:Principal/t:LogonType'),
        (Get-TaskNodeText '//t:Principals/t:Principal/t:RunLevel'),
        $trigger.Kind,
        (Get-TaskNodeText '//t:RegistrationInfo/t:Source'),
        (Get-TaskNodeText '//t:RegistrationInfo/t:Description'),
        ((Get-TaskNodeText '//t:Settings/t:RunOnlyIfNetworkAvailable') -ceq 'true'),
        ((Get-TaskNodeText '//t:Settings/t:Enabled') -ceq 'true'),
        @($taskXml.SelectNodes('//t:Triggers/*', $namespace)).Count,
        @($taskXml.SelectNodes('//t:Actions/*', $namespace)).Count,
        (Get-TaskNodeText '//t:Settings/t:RestartOnFailure/t:Interval'),
        [int](Get-TaskNodeText '//t:Settings/t:RestartOnFailure/t:Count'))
}

function Assert-AgentTaskExact {
    param(
        [SimplySignAuto.Acceptance.Contracts.AgentTaskExecutionSnapshot]$Expected,
        [string]$CanonicalApp
    )
    $actual = Get-AgentTaskExecutionSnapshot $CanonicalApp
    [SimplySignAuto.Acceptance.Contracts.AgentTaskExecutionPolicy]::Validate($Expected, $actual)
}

function Get-ExactAgentProcess {
    param(
        [string]$CanonicalApp,
        [int]$ExpectedSession,
        [System.Security.Principal.SecurityIdentifier]$ExpectedSid
    )
    $matches = New-Object System.Collections.Generic.List[object]
    foreach ($candidate in @(Get-CimInstance Win32_Process -Filter "Name='SimplySignAuto.exe'")) {
        if ([int]$candidate.SessionId -ne $ExpectedSession -or
            -not [string]::Equals(
                [string]$candidate.ExecutablePath,
                $CanonicalApp,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]$candidate.CommandLine -cnotmatch '(?:^|\s)agent\s+--background(?:\s|$)') {
            continue
        }
        $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid
        if ($owner.ReturnValue -eq 0 -and $owner.Sid -ceq $ExpectedSid.Value) {
            $matches.Add($candidate)
        }
    }
    if ($matches.Count -ne 1) { throw 'acceptance_agent_process_invalid' }
    return $matches[0]
}

function Invoke-AgentCrashRecoveryGate {
    param(
        [string]$CanonicalApp,
        [int]$ExpectedSession,
        [System.Security.Principal.SecurityIdentifier]$ExpectedSid,
        [SimplySignAuto.Acceptance.Contracts.AgentTaskExecutionSnapshot]$ExpectedTask
    )
    Assert-AgentTaskExact $ExpectedTask $CanonicalApp
    $before = Get-ExactAgentProcess $CanonicalApp $ExpectedSession $ExpectedSid
    $beforePid = [int]$before.ProcessId
    Stop-Process -Id $beforePid -Force -ErrorAction Stop
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $after = $null
    do {
        Start-Sleep -Milliseconds 500
        try {
            $candidate = Get-ExactAgentProcess $CanonicalApp $ExpectedSession $ExpectedSid
            if ([int]$candidate.ProcessId -ne $beforePid) { $after = $candidate; break }
        } catch {
            if ($_.Exception.Message -cne 'acceptance_agent_process_invalid') { throw }
        }
    } while ($watch.Elapsed.TotalSeconds -lt 90)
    if ($null -eq $after) { throw 'acceptance_agent_restart_failed' }
    Assert-AgentTaskExact $ExpectedTask $CanonicalApp
    $task = Get-ScheduledTask -TaskName 'SimplySignAuto.Agent' -ErrorAction Stop
    if ($task.State -ne 'Running') { throw 'acceptance_agent_restart_failed' }
}

function Get-AcceptanceTaskSnapshot {
    param([string]$Name)
    $current = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
    if (@($current.Actions).Count -ne 1) { throw 'acceptance_task_invalid' }
    $principalSid = [System.Security.Principal.NTAccount]::new(
        [string]$current.Principal.UserId).Translate([System.Security.Principal.SecurityIdentifier])
    return [SimplySignAuto.Acceptance.Contracts.AcceptanceTaskSnapshot]::new(
        [string]$current.Description,
        (Get-Sha256Text $principalSid.Value),
        [string]$current.Principal.LogonType,
        [string]$current.Principal.RunLevel,
        (Get-Sha256Text (([string]$current.Actions[0].Execute).ToUpperInvariant())),
        (Get-Sha256Text ([string]$current.Actions[0].Arguments)),
        [int]$current.Settings.ExecutionTimeLimit.TotalSeconds,
        @($current.Actions).Count)
}

function New-BootResumeArguments {
    param(
        [string]$CanonicalScript,
        [string]$CanonicalRepo,
        [string]$RunDirectory,
        [string]$CanonicalApp,
        [string]$ExpectedAppHash,
        [string]$ExpectedPowerShellPublisher,
        [string]$ExpectedWindowsPublisherMap,
        [string]$ExpectedRunId,
        [int]$BoundSeconds
    )
    $escaped = @(
        $CanonicalScript, $CanonicalRepo, $RunDirectory, $CanonicalApp, $ExpectedAppHash,
        $ExpectedPowerShellPublisher, $ExpectedWindowsPublisherMap, $ExpectedRunId,
        [string]$BoundSeconds) | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }
    return "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $($escaped[0]) " +
        "-ResumeAfterReboot -RepoPath $($escaped[1]) -ArtifactRoot $($escaped[2]) " +
        "-AppHostPath $($escaped[3]) -AppHostSha256 $($escaped[4]) " +
        "-PowerShellPublisherSha256 $($escaped[5]) -WindowsSystemPublisherSha256Map $($escaped[6]) " +
        "-RunId $($escaped[7]) -TimeoutSeconds $($escaped[8])"
}

function Get-BootResumeTaskSnapshot {
    param([string]$Name)
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
    if (@($task.Triggers).Count -ne 1 -or
        $task.Triggers[0].CimClass.CimClassName -cne 'MSFT_TaskBootTrigger') {
        throw 'acceptance_boot_task_invalid'
    }
    $principalSid = [System.Security.Principal.NTAccount]::new(
        [string]$task.Principal.UserId).Translate([System.Security.Principal.SecurityIdentifier])
    return [SimplySignAuto.Acceptance.Contracts.BootResumeTaskSnapshot]::new(
        $principalSid.Value,
        [string]$task.Principal.LogonType,
        [string]$task.Principal.RunLevel,
        (Get-Sha256Text (([string]$task.Actions[0].Execute).ToUpperInvariant())),
        (Get-Sha256Text ([string]$task.Actions[0].Arguments)),
        'AtStartup',
        [string]$task.Source,
        [string]$task.Description,
        [int]$task.Settings.ExecutionTimeLimit.TotalSeconds,
        @($task.Actions).Count)
}

function Initialize-PostRebootCleanupState {
    param([string]$ValidatedRunId)
    if ($ValidatedRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'acceptance_state_uncertain'
    }

    $script:ResumeTaskName = "SimplySignAuto.Acceptance.Boot.$ValidatedRunId"
    $script:UnattendedRebootLsaKey = "SimplySignAuto/Acceptance/$ValidatedRunId/Api"
    $script:UnattendedRebootSecretStored = $true
    $script:UnattendedRebootTaskRegistered = $true
    $script:UnattendedRebootCleanupArmed = $true
}

function Initialize-PostRebootTaskExpectation {
    $resumeArguments = New-BootResumeArguments `
        $PSCommandPath `
        $RepoPath `
        $ArtifactRoot `
        $AppHostPath `
        $AppHostSha256 `
        $PowerShellPublisherSha256 `
        $WindowsSystemPublisherSha256Map `
        $RunId `
        $TimeoutSeconds
    $script:BootResumeExpectedTask = `
        [SimplySignAuto.Acceptance.Contracts.BootResumeTaskSnapshot]::new(
            'S-1-5-18',
            'ServiceAccount',
            'Highest',
            (Get-Sha256Text $PowerShellPath.ToUpperInvariant()),
            (Get-Sha256Text $resumeArguments),
            'AtStartup',
            'SimplySignAuto/v1',
            'SimplySignAuto/AcceptanceBoot/v1',
            $TimeoutSeconds,
            1)
}

function Assert-BootResumeTaskExact {
    param(
        [string]$Name,
        [SimplySignAuto.Acceptance.Contracts.BootResumeTaskSnapshot]$Expected
    )
    [SimplySignAuto.Acceptance.Contracts.BootResumeTaskPolicy]::Validate(
        $Expected,
        (Get-BootResumeTaskSnapshot $Name))
}

function New-ControllerParameterState {
    param(
        [System.Collections.IDictionary]$BoundParameters,
        [string]$Path
    )
    $state = @{}
    foreach ($key in @($BoundParameters.Keys)) {
        if ($key -in @('ApiTokenFile', 'ResumeAfterReboot', 'RunChild', 'RunId')) {
            continue
        }
        $value = $BoundParameters[$key]
        $state[$key] = if ($value -is [System.Management.Automation.SwitchParameter]) {
            [bool]$value
        } else {
            $value
        }
    }
    if ($state.Mode -cne 'FreshInstall' -or $state.ContainsKey('ApiTokenFile')) {
        throw 'acceptance_fresh_install_arguments_invalid'
    }
    $serialized = [System.Management.Automation.PSSerializer]::Serialize($state, 12)
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $serialized,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }
    New-CreateNewText $Path $serialized
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Register-ExactBootResumeTask {
    param(
        [string]$CanonicalScript,
        [string]$CanonicalRepo,
        [string]$CanonicalPowerShell,
        [string]$RunDirectory,
        [string]$CanonicalApp,
        [string]$ExpectedAppHash,
        [string]$ExpectedPowerShellPublisher,
        [string]$ExpectedWindowsPublisherMap,
        [string]$ExpectedRunId,
        [int]$BoundSeconds
    )
    $taskName = "SimplySignAuto.Acceptance.Boot.$ExpectedRunId"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'acceptance_boot_task_invalid'
    }
    $arguments = New-BootResumeArguments `
        $CanonicalScript `
        $CanonicalRepo `
        $RunDirectory `
        $CanonicalApp `
        $ExpectedAppHash `
        $ExpectedPowerShellPublisher `
        $ExpectedWindowsPublisherMap `
        $ExpectedRunId `
        $BoundSeconds
    $action = New-ScheduledTaskAction -Execute $CanonicalPowerShell -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::FromSeconds($BoundSeconds)) `
        -AllowStartIfOnBatteries `
        -StartWhenAvailable
    $definition = New-ScheduledTask `
        -Action $action `
        -Principal $principal `
        -Trigger $trigger `
        -Settings $settings `
        -Description 'SimplySignAuto/AcceptanceBoot/v1'
    $definition.Source = 'SimplySignAuto/v1'
    $expected = [SimplySignAuto.Acceptance.Contracts.BootResumeTaskSnapshot]::new(
        'S-1-5-18',
        'ServiceAccount',
        'Highest',
        (Get-Sha256Text $CanonicalPowerShell.ToUpperInvariant()),
        (Get-Sha256Text $arguments),
        'AtStartup',
        'SimplySignAuto/v1',
        'SimplySignAuto/AcceptanceBoot/v1',
        $BoundSeconds,
        1)
    Register-ScheduledTask -TaskName $taskName -InputObject $definition | Out-Null
    Assert-BootResumeTaskExact $taskName $expected
    return [pscustomobject]@{ Name = $taskName; Expected = $expected }
}

function Remove-OneTimeInstallToken {
    param(
        [string]$Path,
        [System.Security.Principal.SecurityIdentifier]$SigningSid
    )
    Observe-OneTimeInstallToken -Path $Path
    if (-not $FreshTokenObserved) { throw 'acceptance_install_token_invalid' }
    $canonical = Get-CanonicalExistingPath $Path Leaf
    Assert-SecretAcl $canonical $SigningSid 'Machine'
    $content = Read-SetupTokenFile $canonical
    try {
        $token = [SimplySignAuto.Acceptance.Contracts.SetupTokenFilePolicy]::ValidateAndExtract(
            $content)
        $expectedHash = (Get-Sha256Text $content).ToLowerInvariant()
        $identity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($canonical, $false)
        $after = Read-SetupTokenFile $canonical
        try { $actualHash = (Get-Sha256Text $after).ToLowerInvariant() }
        finally { $after = $null }
        $item = Get-Item -LiteralPath $canonical -Force
        if (-not [SimplySignAuto.Acceptance.Contracts.InstallTokenCleanupPolicy]::CanDelete(
                $false,
                $true,
                $FreshTokenFirstIdentity,
                $identity.Identity,
                $expectedHash,
                $actualHash,
                (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0),
                (-not $item.PSIsContainer),
                [int]$identity.LinkCount) -or
            -not [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::DeleteOrdinaryFileIfExactWithRetry(
                $canonical,
                $identity.Identity,
                $actualHash,
                5000,
                100)) {
            throw 'acceptance_state_uncertain'
        }
        if (Test-Path -LiteralPath $canonical) { throw 'acceptance_state_uncertain' }
        $script:FreshTokenCleaned = $true
        return $token
    } finally {
        $content = $null
    }
}

function Invoke-FreshSetupStage {
    param(
        [string]$CanonicalRepo,
        [string]$CanonicalArtifactRoot,
        [string]$CanonicalScript,
        [string]$CanonicalPowerShell,
        [string]$CanonicalSetup,
        [string]$CanonicalApp,
        [string]$CanonicalProgramFiles,
        [string]$SafeBaseUrl,
        [System.Collections.IDictionary]$ControllerParameters
    )
    $expectedUser = "$env:COMPUTERNAME\SimplySignAgent"
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $administratorSid = [System.Security.Principal.NTAccount]::new($AdministratorUser).Translate(
        [System.Security.Principal.SecurityIdentifier])
    if ($SigningUser -cne $expectedUser -or
        $currentIdentity.User -ne $administratorSid -or
        ([Uri]$SafeBaseUrl).Scheme -cne 'http' -or
        ([Uri]$SafeBaseUrl).Port -ne 7080 -or
        -not [string]::IsNullOrWhiteSpace($TlsCertificatePin) -or
        -not [string]::IsNullOrWhiteSpace($AgentConfigurationPath) -or
        $OpenFirewall -or
        -not [string]::IsNullOrWhiteSpace($ApiTokenFile)) {
        throw 'acceptance_fresh_install_arguments_invalid'
    }
    $existingUsers = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='SimplySignAgent'")
    if ($existingUsers.Count -ne 0 -or
        (Test-Path -LiteralPath (Join-Path $env:SystemDrive 'Users\SimplySignAgent')) -or
        (Test-Path -LiteralPath (Join-Path $env:ProgramData 'SimplySignAuto')) -or
        $null -ne (Get-Service -Name 'SimplySignAuto.Service' -ErrorAction SilentlyContinue) -or
        $null -ne (Get-ScheduledTask -TaskName 'SimplySignAuto.Agent' -ErrorAction SilentlyContinue)) {
        throw 'acceptance_fresh_install_not_clean'
    }

    $runIdLocal = [guid]::NewGuid().ToString('N')
    $runDirectory = Join-Path $CanonicalArtifactRoot $runIdLocal
    Initialize-AdministratorsOnlyDirectory $runDirectory
    New-CreateNewText (Join-Path $runDirectory 'owner.txt') $runIdLocal
    Set-AdministratorsOnlyFileAcl (Join-Path $runDirectory 'owner.txt')
    $resumeSource = New-ProtectedResumeSourceBundle $CanonicalRepo $CanonicalScript $runDirectory
    $rawDirectory = Join-Path $runDirectory '.reboot'
    Initialize-AdministratorsOnlyDirectory $rawDirectory
    $statePath = Join-Path $rawDirectory 'controller-parameters.clixml'
    $stateHash = New-ControllerParameterState $ControllerParameters $statePath
    Set-AdministratorsOnlyFileAcl $statePath
    $tokenPath = Join-Path $env:ProgramData 'SimplySignAuto\install-token.txt'
    if (Test-Path -LiteralPath $tokenPath) { throw 'acceptance_install_token_exists' }
    $script:FreshInstallTokenPathForCleanup = $tokenPath
    $script:FailureRunDirectory = $runDirectory
    $script:FailureRunId = $runIdLocal
    $script:FailureRunId = $runIdLocal
    $script:InstallMutationAttempted = $true
    $setup = Invoke-BoundedSetupUi `
        $CanonicalSetup `
        $TimeoutSeconds `
        $tokenPath
    if ($setup.ExitCode -ne 0) {
        throw 'acceptance_install_failed'
    }
    $installedApp = Get-CanonicalExistingPath $CanonicalApp Leaf
    if ($installedApp -cne $CanonicalApp) { throw 'acceptance_install_failed' }
    Add-TrustedExecutableGuard `
        $installedApp `
        @($CanonicalProgramFiles) `
        ManifestSha256 `
        $AppHostSha256
    $signingSid = [System.Security.Principal.NTAccount]::new($SigningUser).Translate(
        [System.Security.Principal.SecurityIdentifier])
    $script:signingSid = $signingSid
    $token = Remove-OneTimeInstallToken `
        $tokenPath `
        $signingSid
    $script:LastProcessDiagnostic = $null
    $resume = $null
    try {
        $installed = Assert-InstalledState `
            $CanonicalApp `
            $SafeBaseUrl `
            $token `
            $signingSid `
            $false `
            ''
        try {
            $null = Get-UniqueActiveSession $signingSid
            throw 'acceptance_fresh_install_session_invalid'
        } catch {
            if ($_.Exception.Message -cne 'acceptance_session_unavailable') { throw }
        }
        $lsaKey = "SimplySignAuto/Acceptance/$runIdLocal/Api"
        [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::StoreNew($lsaKey, $token)
        $checkpoint = [ordered]@{
            schemaVersion = 1
            phase = 'fresh-install'
            runId = $runIdLocal
            acceptanceStartedUtc = $AcceptanceStartedUtc.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            bootBeforeUtc = (Get-CurrentBootUtc).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            administratorUser = $AdministratorUser
            administratorSid = $administratorSid.Value
            signingUser = $SigningUser
            signingSid = $signingSid.Value
            installInstanceHash = $installed.InstallInstanceHash
            agentTaskSource = $installed.AgentTask.Source
            controllerStateFile = 'controller-parameters.clixml'
            controllerStateSha256 = $stateHash
            resumeScriptSha256 = $resumeSource.ScriptSha256
            acceptanceContractsSha256 = $resumeSource.AcceptanceContractsSha256
            strictJsonSha256 = $resumeSource.StrictJsonSha256
        } | ConvertTo-Json -Compress
        $checkpointPath = Join-Path $rawDirectory 'checkpoint.json'
        New-CreateNewText $checkpointPath $checkpoint
        Set-AdministratorsOnlyFileAcl $checkpointPath
        $resume = Register-ExactBootResumeTask `
            $resumeSource.ScriptPath `
            $resumeSource.Root `
            $CanonicalPowerShell `
            $runDirectory `
            $CanonicalApp `
            $AppHostSha256 `
            $PowerShellPublisherSha256 `
            $WindowsSystemPublisherSha256Map `
            $runIdLocal `
            $TimeoutSeconds
        [Console]::Out.WriteLine('acceptance_fresh_setup_reboot_started')
        Restart-Computer -Force -ErrorAction Stop
        exit 194
    } catch {
        try { [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::Remove("SimplySignAuto/Acceptance/$runIdLocal/Api") } catch {}
        if ($null -ne $resume) {
            try {
                Assert-BootResumeTaskExact $resume.Name $resume.Expected
                Unregister-ScheduledTask -TaskName $resume.Name -Confirm:$false
            } catch { throw 'acceptance_state_uncertain' }
        }
        throw
    } finally {
        $token = $null
    }
}

function Invoke-UnattendedRebootCleanup {
    param([AllowNull()][string]$FirstFailure)
    if (-not $UnattendedRebootCleanupArmed) { return $FirstFailure }
    $identityExact = $RunId -cmatch '^[0-9a-f]{32}$' -and
        $UnattendedRebootLsaKey -ceq "SimplySignAuto/Acceptance/$RunId/Api" -and
        $ResumeTaskName -ceq "SimplySignAuto.Acceptance.Boot.$RunId"
    $cleanupPolicyAvailable = $null -ne (
        'SimplySignAuto.Acceptance.Contracts.UnattendedRebootCleanupPolicy' -as [type])
    if (-not $identityExact -or
        ($cleanupPolicyAvailable -and
            -not [SimplySignAuto.Acceptance.Contracts.UnattendedRebootCleanupPolicy]::IsIdentityExact(
                $RunId,
                $UnattendedRebootLsaKey,
                $ResumeTaskName))) {
        return 'acceptance_state_uncertain'
    }

    $secretAbsent = -not $UnattendedRebootSecretStored
    if ($UnattendedRebootSecretStored) {
        try {
            [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::Remove(
                $UnattendedRebootLsaKey)
            $secretAbsent = $true
        } catch {
            $secretAbsent = $false
        }
    }

    $taskOwnershipExact = -not $UnattendedRebootTaskRegistered
    $taskAbsent = -not $UnattendedRebootTaskRegistered
    if ($UnattendedRebootTaskRegistered) {
        try {
            Assert-BootResumeTaskExact $ResumeTaskName $BootResumeExpectedTask
            $taskOwnershipExact = $true
            Unregister-ScheduledTask -TaskName $ResumeTaskName -Confirm:$false
            $taskAbsent = $null -eq (
                Get-ScheduledTask -TaskName $ResumeTaskName -ErrorAction SilentlyContinue)
        } catch {
            $taskOwnershipExact = $false
            $taskAbsent = $false
        }
    }

    if ($cleanupPolicyAvailable) {
        $resolved = [SimplySignAuto.Acceptance.Contracts.UnattendedRebootCleanupPolicy]::Resolve(
            $FirstFailure,
            $RunId,
            $UnattendedRebootLsaKey,
            $UnattendedRebootSecretStored,
            $secretAbsent,
            $ResumeTaskName,
            $UnattendedRebootTaskRegistered,
            $taskOwnershipExact,
            $taskAbsent)
    } elseif (($UnattendedRebootSecretStored -and -not $secretAbsent) -or
        ($UnattendedRebootTaskRegistered -and
            (-not $taskOwnershipExact -or -not $taskAbsent)) -or
        ($null -ne $FirstFailure -and $FirstFailure -cnotmatch '^acceptance_[a-z0-9_]+$')) {
        $resolved = 'acceptance_state_uncertain'
    } else {
        $resolved = $FirstFailure
    }
    if ($secretAbsent) { $script:UnattendedRebootSecretStored = $false }
    if ($taskAbsent) { $script:UnattendedRebootTaskRegistered = $false }
    if ($secretAbsent -and $taskAbsent) { $script:UnattendedRebootCleanupArmed = $false }
    return $resolved
}

function Initialize-AdministratorsOnlyDirectory {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { throw 'acceptance_artifact_collision' }
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    $admins = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($system)
    foreach ($sid in @($system, $admins)) {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow))
    }
    [System.IO.Directory]::SetAccessControl($Path, $security)
    Assert-TrustedRootAcl $Path
}

function Set-AdministratorsOnlyFileAcl {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'acceptance_path_invalid'
    }
    $admins = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($system)
    foreach ($sid in @($system, $admins)) {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow))
    }
    [System.IO.File]::SetAccessControl($Path, $security)
    Assert-TrustedRootAcl $Path
}

function New-ProtectedResumeSourceBundle {
    param(
        [string]$CanonicalRepo,
        [string]$CanonicalScript,
        [string]$RunDirectory
    )
    $resumeRoot = Join-Path $RunDirectory '.resume'
    Initialize-AdministratorsOnlyDirectory $resumeRoot
    $resumeScripts = Join-Path $resumeRoot 'scripts'
    Initialize-AdministratorsOnlyDirectory $resumeScripts
    $scriptPath = Join-Path $resumeRoot 'acceptance-test.ps1'
    $contractPath = Join-Path $resumeScripts 'AcceptanceContracts.cs'
    $strictJsonPath = Join-Path $resumeScripts 'UiAcceptanceStrictJson.cs'
    $sources = @(
        [pscustomobject]@{ Source = $CanonicalScript; Destination = $scriptPath }
        [pscustomobject]@{
            Source = Get-CanonicalExistingPath (Join-Path $CanonicalRepo 'scripts\AcceptanceContracts.cs') Leaf
            Destination = $contractPath
        }
        [pscustomobject]@{
            Source = Get-CanonicalExistingPath (Join-Path $CanonicalRepo 'scripts\UiAcceptanceStrictJson.cs') Leaf
            Destination = $strictJsonPath
        })
    foreach ($source in $sources) {
        [System.IO.File]::Copy([string]$source.Source, [string]$source.Destination, $false)
        Set-AdministratorsOnlyFileAcl ([string]$source.Destination)
    }
    return [pscustomobject]@{
        Root = $resumeRoot
        ScriptPath = $scriptPath
        ScriptSha256 = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        AcceptanceContractsSha256 = (Get-FileHash -LiteralPath $contractPath -Algorithm SHA256).Hash.ToLowerInvariant()
        StrictJsonSha256 = (Get-FileHash -LiteralPath $strictJsonPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Assert-ProtectedResumeSourceBundle {
    param(
        [string]$RunDirectory,
        [string]$ScriptSha256,
        [string]$AcceptanceContractsSha256,
        [string]$StrictJsonSha256
    )
    foreach ($hash in @($ScriptSha256, $AcceptanceContractsSha256, $StrictJsonSha256)) {
        if ($hash -cnotmatch '^[0-9a-f]{64}$') { throw 'acceptance_fresh_install_state_invalid' }
    }
    $resumeRoot = Get-CanonicalExistingPath (Join-Path $RunDirectory '.resume') Container
    $resumeScripts = Get-CanonicalExistingPath (Join-Path $resumeRoot 'scripts') Container
    $scriptPath = Get-CanonicalExistingPath (Join-Path $resumeRoot 'acceptance-test.ps1') Leaf
    $contractPath = Get-CanonicalExistingPath (Join-Path $resumeScripts 'AcceptanceContracts.cs') Leaf
    $strictJsonPath = Get-CanonicalExistingPath (Join-Path $resumeScripts 'UiAcceptanceStrictJson.cs') Leaf
    Assert-ExactChildren $resumeRoot @('acceptance-test.ps1', 'scripts')
    Assert-ExactChildren $resumeScripts @('AcceptanceContracts.cs', 'UiAcceptanceStrictJson.cs')
    foreach ($path in @($resumeRoot, $resumeScripts, $scriptPath, $contractPath, $strictJsonPath)) {
        Assert-TrustedRootAcl $path
    }
    if ((Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ScriptSha256 -or
        (Get-FileHash -LiteralPath $contractPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $AcceptanceContractsSha256 -or
        (Get-FileHash -LiteralPath $strictJsonPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $StrictJsonSha256) {
        throw 'acceptance_fresh_install_state_invalid'
    }
    return [pscustomobject]@{ Root = $resumeRoot; ScriptPath = $scriptPath }
}

function Remove-ProtectedResumeSourceBundle {
    param([string]$RunDirectory)
    $resumeRoot = Get-CanonicalExistingPath (Join-Path $RunDirectory '.resume') Container
    if (-not (Test-PathUnder $resumeRoot $RunDirectory) -or
        [System.IO.Path]::GetFileName($resumeRoot) -cne '.resume') {
        throw 'acceptance_state_uncertain'
    }
    Assert-TrustedRootAcl $resumeRoot
    Remove-Item -LiteralPath $resumeRoot -Recurse -Force
    if (Test-Path -LiteralPath $resumeRoot) { throw 'acceptance_state_uncertain' }
}

function Get-CurrentBootUtc {
    $value = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    return [DateTimeOffset](([DateTime]$value).ToUniversalTime())
}

function Assert-ProductionPurgeTaskExact {
    param(
        [string]$TaskName,
        [string]$OperationId,
        [string]$CanonicalApp,
        [string]$ManifestPath
    )
    [xml]$taskXml = Export-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $namespace = [System.Xml.XmlNamespaceManager]::new($taskXml.NameTable)
    $namespace.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $checks = @{
        '//t:RegistrationInfo/t:Description' = 'SimplySignAuto/Purge/v1'
        '//t:RegistrationInfo/t:Source' = $OperationId
        '//t:Triggers/t:BootTrigger/t:Enabled' = 'true'
        '//t:Principals/t:Principal/t:UserId' = 'S-1-5-18'
        '//t:Principals/t:Principal/t:RunLevel' = 'HighestAvailable'
        '//t:Settings/t:MultipleInstancesPolicy' = 'IgnoreNew'
        '//t:Settings/t:StartWhenAvailable' = 'true'
        '//t:Settings/t:Enabled' = 'true'
        '//t:Settings/t:ExecutionTimeLimit' = 'PT1H'
        '//t:Actions/t:Exec/t:Command' = $CanonicalApp
        '//t:Actions/t:Exec/t:Arguments' = ('purge-quarantine --manifest "' + $ManifestPath + '"')
    }
    foreach ($check in $checks.GetEnumerator()) {
        $nodes = @($taskXml.SelectNodes($check.Key, $namespace))
        if ($nodes.Count -ne 1 -or $nodes[0].InnerText -cne $check.Value) {
            throw 'acceptance_purge_boot_invalid'
        }
    }
    $containerShapes = [ordered]@{
        '/t:Task/t:Actions' = 'Exec'
        '/t:Task/t:Triggers' = 'BootTrigger'
        '/t:Task/t:Principals' = 'Principal'
    }
    foreach ($shape in $containerShapes.GetEnumerator()) {
        $containerNodes = @($taskXml.SelectNodes($shape.Key, $namespace))
        if ($containerNodes.Count -ne 1) {
            throw 'acceptance_purge_boot_invalid'
        }
        $childNodes = @($containerNodes[0].ChildNodes | Where-Object {
                $_.NodeType -eq [System.Xml.XmlNodeType]::Element
            })
        if ($childNodes.Count -ne 1 -or
            $childNodes[0].LocalName -cne $shape.Value -or
            $childNodes[0].NamespaceURI -cne 'http://schemas.microsoft.com/windows/2004/02/mit/task') {
            throw 'acceptance_purge_boot_invalid'
        }
    }
    $logonTypeNodes = @($taskXml.SelectNodes(
            '//t:Principals/t:Principal/t:LogonType',
            $namespace))
    if ($logonTypeNodes.Count -ne 0) {
        throw 'acceptance_purge_boot_invalid'
    }
}

function Assert-InstalledState {
    param(
        [string]$CanonicalApp,
        [string]$ApiTokenValue,
        [System.Security.Principal.SecurityIdentifier]$SigningSid,
        [bool]$FirewallExpected
    )
    $dataRoot = Get-CanonicalExistingPath (Join-Path $env:ProgramData 'SimplySignAuto') Container
    $serviceConfigPath = Get-CanonicalExistingPath (Join-Path $dataRoot 'service.json') Leaf
    Assert-ProtectedAcl $dataRoot $SigningSid 'AdministratorsOnly' $true
    Assert-ProtectedAcl $serviceConfigPath $SigningSid 'AdministratorsOnly' $false
    $configuration = ConvertFrom-StrictJson (Get-Content -LiteralPath $serviceConfigPath -Raw)
    Assert-ExactProperties $configuration @(
        'tokenHash', 'signingUserSid', 'dataRoot', 'spoolRoot', 'listenPort',
        'ownerMarker', 'installInstanceId', 'executablePath', 'agentConfigurationPath', 'retentionHours')
    $expectedTokenHash = (Get-Sha256Text $ApiTokenValue).ToLowerInvariant()
    if ($configuration.tokenHash -isnot [string] -or $configuration.tokenHash -cne $expectedTokenHash -or
        $configuration.signingUserSid -isnot [string] -or $configuration.signingUserSid -cne $SigningSid.Value -or
        $configuration.dataRoot -isnot [string] -or $configuration.dataRoot -ine $dataRoot -or
        $configuration.spoolRoot -isnot [string] -or
            $configuration.spoolRoot -ine (Join-Path $dataRoot 'spool') -or
        $configuration.listenPort -isnot [int] -or $configuration.listenPort -lt 1 -or
            $configuration.listenPort -gt 65535 -or
        $configuration.ownerMarker -isnot [string] -or $configuration.ownerMarker -cne 'SimplySignAuto/v1' -or
        $configuration.installInstanceId -isnot [string] -or
            $configuration.installInstanceId -cnotmatch '^[0-9a-f]{32}$' -or
        $configuration.executablePath -isnot [string] -or $configuration.executablePath -ine $CanonicalApp -or
        $configuration.agentConfigurationPath -isnot [string] -or
            [System.IO.Path]::GetFileName($configuration.agentConfigurationPath) -ine 'agent.json' -or
        $configuration.retentionHours -isnot [int] -or $configuration.retentionHours -lt 0 -or
            $configuration.retentionHours -gt 168) {
        throw 'acceptance_install_configuration_invalid'
    }

    $jobsRoot = Get-CanonicalExistingPath (Join-Path $dataRoot 'jobs') Container
    $toolsRoot = Get-CanonicalExistingPath (Join-Path $dataRoot 'tools') Container
    $logsRoot = Get-CanonicalExistingPath (Join-Path $dataRoot 'logs') Container
    $spoolRoot = Get-CanonicalExistingPath ([string]$configuration.spoolRoot) Container
    $jobsDatabase = Get-CanonicalExistingPath (Join-Path $dataRoot 'jobs.db') Leaf
    $agentConfiguration = Get-CanonicalExistingPath ([string]$configuration.agentConfigurationPath) Leaf
    $agentDirectory = Get-CanonicalExistingPath ([System.IO.Path]::GetDirectoryName($agentConfiguration)) Container
    Assert-ProtectedAcl $jobsRoot $SigningSid 'SigningUserModify' $true
    Assert-ProtectedAcl $toolsRoot $SigningSid 'SigningUserRead' $true
    Assert-ProtectedAcl $logsRoot $SigningSid 'AdministratorsOnly' $true
    Assert-ProtectedAcl $spoolRoot $SigningSid 'SigningUserRead' $true
    Assert-ProtectedAcl $jobsDatabase $SigningSid 'AdministratorsOnly' $false
    Assert-ProtectedAcl $agentDirectory $SigningSid 'SigningUserData' $true
    Assert-ProtectedAcl $agentConfiguration $SigningSid 'SigningUserRead' $false

    $ownerMarker = "SimplySignAuto/v1/$($configuration.installInstanceId)"
    $serviceKey = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SimplySignAuto.Service'
    $expectedImage = '"' + $CanonicalApp + '" service'
    if ($serviceKey.ImagePath -cne $expectedImage -or $serviceKey.ObjectName -ine 'LocalSystem' -or
        [int]$serviceKey.Start -ne 2 -or [int]$serviceKey.DelayedAutoStart -ne 1 -or
        $serviceKey.DisplayName -cne 'SimplySignAuto.Service' -or
        $serviceKey.Description -cne $ownerMarker -or
        $serviceKey.SimplySignAutoInstallOwner -cne $ownerMarker -or
        (Get-Service -Name 'SimplySignAuto.Service').Status -ne 'Running') {
        throw 'acceptance_service_registration_invalid'
    }
    $sc = Get-CanonicalExistingPath (Join-Path $env:SystemRoot 'System32\sc.exe') Leaf
    $recovery = Invoke-BoundedProcessCapture $sc @('qfailure', 'SimplySignAuto.Service') 30 $null
    $recoveryNumbers = @([regex]::Matches($recovery.Stdout, '(?<![0-9])[0-9]+(?![0-9])') | ForEach-Object { $_.Value })
    $failureFlag = Invoke-BoundedProcessCapture $sc @('qfailureflag', 'SimplySignAuto.Service') 30 $null
    $flagNumbers = @([regex]::Matches($failureFlag.Stdout, '(?<![0-9])[0-9]+(?![0-9])') | ForEach-Object { $_.Value })
    if ($recovery.ExitCode -ne 0 -or ($recoveryNumbers -join ',') -cne '86400,5000,15000,60000' -or
        $failureFlag.ExitCode -ne 0 -or ($flagNumbers -join ',') -cne '1') {
        throw 'acceptance_service_recovery_invalid'
    }

    [xml]$taskXml = Export-ScheduledTask -TaskName 'SimplySignAuto.Agent'
    $namespace = [System.Xml.XmlNamespaceManager]::new($taskXml.NameTable)
    $namespace.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $taskChecks = @{
        '//t:RegistrationInfo/t:Description' = 'SimplySignAuto/v1'
        '//t:RegistrationInfo/t:Source' = $ownerMarker
        '//t:Triggers/t:LogonTrigger/t:Enabled' = 'true'
        '//t:Triggers/t:LogonTrigger/t:UserId' = $SigningSid.Value
        '//t:Principals/t:Principal/t:UserId' = $SigningSid.Value
        '//t:Principals/t:Principal/t:LogonType' = 'InteractiveToken'
        '//t:Principals/t:Principal/t:RunLevel' = 'HighestAvailable'
        '//t:Settings/t:RunOnlyIfNetworkAvailable' = 'true'
        '//t:Settings/t:Enabled' = 'true'
        '//t:Settings/t:RestartOnFailure/t:Interval' = 'PT1M'
        '//t:Settings/t:RestartOnFailure/t:Count' = '3'
        '//t:Actions/t:Exec/t:Command' = $CanonicalApp
        '//t:Actions/t:Exec/t:Arguments' = 'agent --background'
    }
    foreach ($check in $taskChecks.GetEnumerator()) {
        $nodes = @($taskXml.SelectNodes($check.Key, $namespace))
        if ($nodes.Count -ne 1 -or $nodes[0].InnerText -cne $check.Value) {
            throw 'acceptance_agent_task_invalid'
        }
    }
    $expectedAgentTask = [SimplySignAuto.Acceptance.Contracts.AgentTaskExecutionSnapshot]::new(
        $SigningSid.Value,
        $CanonicalApp,
        'agent --background',
        'InteractiveToken',
        'HighestAvailable',
        'LogonTrigger',
        $ownerMarker,
        'SimplySignAuto/v1',
        $true,
        $true,
        1,
        1)
    Assert-AgentTaskExact $expectedAgentTask $CanonicalApp

    $firewallPolicy = $null
    try {
        $firewallPolicy = New-Object -ComObject HNetCfg.FwPolicy2
        $rules = @($firewallPolicy.Rules | Where-Object { $_.Name -ceq 'SimplySignAuto API' })
        if (-not $FirewallExpected -and $rules.Count -ne 0) { throw 'acceptance_firewall_invalid' }
        if ($FirewallExpected -and ($rules.Count -ne 1 -or $rules[0].Description -cne $ownerMarker -or
            $rules[0].Grouping -cne $ownerMarker -or [int]$rules[0].Protocol -ne 6 -or
            $rules[0].LocalPorts -cne ([string]$configuration.listenPort) -or [int]$rules[0].Direction -ne 1 -or
            [int]$rules[0].Action -ne 1 -or $rules[0].Enabled -ne $true -or
            [int]$rules[0].Profiles -ne [int]::MaxValue)) {
            throw 'acceptance_firewall_invalid'
        }
    } finally {
        if ($null -ne $firewallPolicy -and [System.Runtime.InteropServices.Marshal]::IsComObject($firewallPolicy)) {
            [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($firewallPolicy) | Out-Null
        }
    }

    return [pscustomobject]@{
        InstallInstanceHash = Get-Sha256Text ([string]$configuration.installInstanceId)
        DataRoot = $dataRoot
        AgentDirectory = $agentDirectory
        AgentTask = $expectedAgentTask
    }
}

function Test-WtsActive {
    param([int]$SessionId)
    if (-not ('SimplySignAuto.Acceptance.NativeWts' -as [type])) {
        Add-Type -TypeDefinition @'
namespace SimplySignAuto.Acceptance {
    public static class NativeWts {
        [System.Runtime.InteropServices.DllImport("wtsapi32.dll", SetLastError=true)]
        static extern bool WTSQuerySessionInformationW(System.IntPtr server, int id, int cls, out System.IntPtr buffer, out int bytes);
        [System.Runtime.InteropServices.DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(System.IntPtr memory);
        public static bool IsActive(int id) {
            if (id <= 0) return false;
            System.IntPtr buffer = System.IntPtr.Zero;
            try {
                int bytes;
                return WTSQuerySessionInformationW(System.IntPtr.Zero, id, 8, out buffer, out bytes) && buffer != System.IntPtr.Zero && bytes >= 4 && System.Runtime.InteropServices.Marshal.ReadInt32(buffer) == 0;
            } finally { if (buffer != System.IntPtr.Zero) WTSFreeMemory(buffer); }
        }
        public static int GetClientProtocol(int id) {
            if (id <= 0) return -1;
            System.IntPtr buffer = System.IntPtr.Zero;
            try {
                int bytes;
                return WTSQuerySessionInformationW(System.IntPtr.Zero, id, 16, out buffer, out bytes) &&
                    buffer != System.IntPtr.Zero && bytes >= 2
                    ? System.Runtime.InteropServices.Marshal.ReadInt16(buffer)
                    : -1;
            } finally { if (buffer != System.IntPtr.Zero) WTSFreeMemory(buffer); }
        }
    }
}
'@
    }
    try { return [SimplySignAuto.Acceptance.NativeWts]::IsActive($SessionId) } catch { return $false }
}

function Get-WtsClientProtocol {
    param([int]$SessionId)
    $null = Test-WtsActive $SessionId
    try { return [SimplySignAuto.Acceptance.NativeWts]::GetClientProtocol($SessionId) }
    catch { return -1 }
}

function Get-UniqueActiveSession {
    param([System.Security.Principal.SecurityIdentifier]$Identity)
    $candidates = New-Object System.Collections.Generic.List[SimplySignAuto.Acceptance.Contracts.SidSessionCandidate]
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'")) {
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if ($owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace([string]$owner.Sid)) { continue }
        $state = if (Test-WtsActive ([int]$process.SessionId)) { 'Active' } else { 'Unavailable' }
        $candidates.Add([SimplySignAuto.Acceptance.Contracts.SidSessionCandidate]::new(
                [int]$process.SessionId, $state, [string]$owner.Sid))
    }
    return [SimplySignAuto.Acceptance.Contracts.SidSessionSelectionPolicy]::SelectUniqueActive(
        $candidates, $Identity.Value)
}

function Get-ObservedChildProcess {
    param(
        [string]$CanonicalPowerShell,
        [string]$ExpectedArguments,
        [string]$ExpectedRunId,
        [int]$ExpectedSessionId,
        [System.Security.Principal.SecurityIdentifier]$ExpectedSid
    )
    $matches = New-Object System.Collections.Generic.List[object]
    foreach ($process in @(Get-CimInstance Win32_Process | Where-Object {
                [int]$_.SessionId -eq $ExpectedSessionId -and
                [string]::Equals(
                    [string]$_.ExecutablePath,
                    $CanonicalPowerShell,
                    [System.StringComparison]::OrdinalIgnoreCase) -and
                -not [string]::IsNullOrWhiteSpace([string]$_.CommandLine) -and
                ([string]$_.CommandLine).EndsWith($ExpectedArguments, [System.StringComparison]::Ordinal)
            })) {
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
        if ($owner.ReturnValue -eq 0 -and [string]$owner.Sid -ceq $ExpectedSid.Value) {
            $matches.Add($process)
        }
    }
    if ($matches.Count -gt 1) { throw 'acceptance_child_process_invalid' }
    if ($matches.Count -eq 0) { return $null }
    $actual = [SimplySignAuto.Acceptance.Contracts.ChildProcessObservation]::new(
        [int]$matches[0].ProcessId,
        $ExpectedSid.Value,
        [int]$matches[0].SessionId,
        [string]$matches[0].ExecutablePath,
        $ExpectedRunId,
        $true)
    [SimplySignAuto.Acceptance.Contracts.ChildProcessObservationPolicy]::Validate($actual, $actual)
    return $actual
}

function Assert-WindowsPreflight {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) {
        throw 'acceptance_windows_required'
    }
    $caption = (Get-CimInstance Win32_OperatingSystem).Caption
    $build = [Environment]::OSVersion.Version.Build
    if ($caption -notmatch 'Windows Server 2025' -or $build -lt 26100 -or $PSVersionTable.PSVersion.Major -ne 5) {
        throw 'acceptance_os_invalid'
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'acceptance_admin_required'
    }
}

function Assert-TimeSynchronization {
    param([Parameter(Mandatory = $true)][string]$CanonicalW32Time)

    try {
        $service = Get-Service -Name 'w32time' -ErrorAction Stop
        $time = Invoke-BoundedProcessCapture $CanonicalW32Time @('/query', '/status', '/verbose') 30 $null
        $collectedAt = [DateTimeOffset]::UtcNow
        $events = @(
            Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Microsoft-Windows-Time-Service'
                StartTime = $collectedAt.UtcDateTime.AddDays(-7)
            } -ErrorAction Stop |
                Select-Object -First 512)
    } catch {
        throw 'acceptance_time_unsynchronized'
    }

    $latestValid = @($events | Where-Object {
            $_.Id -eq 37 -and [int]$_.Level -eq 4
        } | Sort-Object TimeCreated -Descending | Select-Object -First 1)
    $latestFailure = @($events | Where-Object {
            [int]$_.Level -in @(1, 2, 3)
        } | Sort-Object TimeCreated -Descending | Select-Object -First 1)
    $latestValidUtc = [DateTimeOffset]::MinValue
    $latestFailureUtc = [DateTimeOffset]::MinValue
    $sourceIsLocalClock = $false
    if ($latestValid.Count -eq 1) {
        $latestValidUtc = [DateTimeOffset]$latestValid[0].TimeCreated
        foreach ($property in @($latestValid[0].Properties)) {
            if ($property.Value -is [string] -and
                [string]::Equals(
                    ([string]$property.Value).Trim(),
                    'Local CMOS Clock',
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                $sourceIsLocalClock = $true
            }
        }
    }
    if ($latestFailure.Count -eq 1) {
        $latestFailureUtc = [DateTimeOffset]$latestFailure[0].TimeCreated
    }

    $evidence = [SimplySignAuto.Acceptance.Contracts.TimeSynchronizationEvidence]::new(
        ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running),
        $time.ExitCode,
        $time.Stdout,
        $collectedAt,
        $latestValidUtc,
        $latestFailureUtc,
        $sourceIsLocalClock)
    [SimplySignAuto.Acceptance.Contracts.TimeSynchronizationPolicy]::Validate($evidence)
}

function Assert-PssaGate {
    param([Parameter(Mandatory = $true)][string]$CanonicalRepo)

    $module = Get-Module -ListAvailable -Name PSScriptAnalyzer |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($null -eq $module) { throw 'acceptance_pssa_pending' }
    Import-Module $module.Path -Force -ErrorAction Stop
    $paths = @(
        (Join-Path $CanonicalRepo 'scripts\acceptance-test.ps1'),
        (Join-Path $CanonicalRepo 'scripts\install-test-fixtures.ps1'),
        (Join-Path $CanonicalRepo 'scripts\ui-acceptance.ps1'))
    foreach ($path in $paths) {
        $canonical = Get-CanonicalExistingPath $path Leaf
        $findings = @(Invoke-ScriptAnalyzer -Path $canonical -Severity Error -ErrorAction Stop)
        if ($findings.Count -eq 0) { continue }
        foreach ($finding in $findings) {
            $diagnostic = @(
                'pssa_finding_begin',
                "finding_path=$canonical",
                "finding_rule=$($finding.RuleName)",
                "finding_severity=$($finding.Severity)",
                "finding_line=$($finding.Line)",
                "finding_column=$($finding.Column)",
                "finding_message=$($finding.Message)",
                'pssa_finding_end') -join [Environment]::NewLine
            [Console]::Error.WriteLine((Protect-AcceptanceOutput $diagnostic))
        }
        throw 'acceptance_pssa_failed'
    }
}

function Assert-UrlAclExact {
    param(
        [Parameter(Mandatory = $true)][string]$CanonicalNetsh,
        [Parameter(Mandatory = $true)][string]$SafeBaseUrl
    )

    $reservation = $SafeBaseUrl.TrimEnd('/') + '/'
    $readback = Invoke-BoundedProcessCapture $CanonicalNetsh @('http', 'show', 'urlacl', "url=$reservation") 30 $null
    if ($readback.ExitCode -ne 0 -or
        @([regex]::Matches($readback.Stdout, [regex]::Escape($reservation), 'IgnoreCase')).Count -ne 1 -or
        @([regex]::Matches($readback.Stdout, 'D:\(A;;GX;;;SY\)', 'CultureInvariant')).Count -ne 1) {
        throw 'acceptance_urlacl_invalid'
    }
}

function Assert-BaseUrl {
    param([string]$Value)
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        @('http', 'https') -cnotcontains $uri.Scheme -or
        [string]::IsNullOrWhiteSpace($uri.DnsSafeHost) -or -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or -not [string]::IsNullOrEmpty($uri.Fragment) -or
        $uri.AbsolutePath -cne '/') { throw 'acceptance_base_url_invalid' }
    return $uri.AbsoluteUri.TrimEnd('/')
}

function Set-RunDirectoryAcl {
    param([string]$Path, [System.Security.Principal.SecurityIdentifier]$SigningSid, [bool]$Interactive)

    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $admins = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    foreach ($sid in @($admins, $system)) {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, [System.Security.AccessControl.AccessControlType]::Allow))
    }
    if ($Interactive) {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($SigningSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inherit, $none, [System.Security.AccessControl.AccessControlType]::Allow))
    } else {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($SigningSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.InheritanceFlags]::None, $none, [System.Security.AccessControl.AccessControlType]::Allow))
    }
    [System.IO.Directory]::SetAccessControl($Path, $security)
}

function Assert-RunDirectoryAcl {
    param([string]$Path, [System.Security.Principal.SecurityIdentifier]$SigningSid, [bool]$Interactive)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        [Console]::Error.WriteLine((Protect-AcceptanceOutput (@(
                    'run_directory_acl_diagnostic_begin',
                    "path=$Path",
                    "interactive=$Interactive",
                    "is_container=$($item.PSIsContainer)",
                    "attributes=$([int64]$item.Attributes)",
                    'run_directory_acl_diagnostic_end') -join [Environment]::NewLine)))
        throw 'acceptance_ui_acl_invalid'
    }
    $security = $item.GetAccessControl()
    $admins = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $readAndExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    $modify = [System.Security.AccessControl.FileSystemRights]::Modify -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    $expected = @(
        [pscustomobject]@{ Sid = $admins; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl; Inheritance = $inherit },
        [pscustomobject]@{ Sid = $system; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl; Inheritance = $inherit },
        [pscustomobject]@{
            Sid = $SigningSid
            Rights = if ($Interactive) { $modify } else { $readAndExecute }
            Inheritance = if ($Interactive) { $inherit } else { [System.Security.AccessControl.InheritanceFlags]::None }
        })
    $rules = @($security.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    $invalid = -not $security.AreAccessRulesProtected -or $rules.Count -ne $expected.Count
    foreach ($wanted in $expected) {
        $match = @($rules | Where-Object {
                $_.IdentityReference -eq $wanted.Sid -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $_.FileSystemRights -eq $wanted.Rights -and
                $_.InheritanceFlags -eq $wanted.Inheritance -and
                $_.PropagationFlags -eq $none -and
                -not $_.IsInherited
            })
        if ($match.Count -ne 1) { $invalid = $true }
    }
    if ($invalid) {
        $diagnostic = New-Object System.Collections.Generic.List[string]
        $diagnostic.Add('run_directory_acl_diagnostic_begin')
        $diagnostic.Add("path=$Path")
        $diagnostic.Add("interactive=$Interactive")
        $diagnostic.Add("owner=$($security.Owner)")
        $diagnostic.Add("access_rules_protected=$($security.AreAccessRulesProtected)")
        foreach ($wanted in $expected) {
            $diagnostic.Add(
                "expected_rule=$($wanted.Sid.Value)|rights=$([int64]$wanted.Rights)|inheritance=$([int]$wanted.Inheritance)|propagation=$([int]$none)|type=Allow|inherited=False")
        }
        foreach ($rule in $rules) {
            $diagnostic.Add(
                "actual_rule=$($rule.IdentityReference.Value)|rights=$([int64]$rule.FileSystemRights)|inheritance=$([int]$rule.InheritanceFlags)|propagation=$([int]$rule.PropagationFlags)|type=$($rule.AccessControlType)|inherited=$($rule.IsInherited)")
        }
        $diagnostic.Add('run_directory_acl_diagnostic_end')
        [Console]::Error.WriteLine((Protect-AcceptanceOutput ($diagnostic -join [Environment]::NewLine)))
        throw 'acceptance_ui_acl_invalid'
    }
}

function Initialize-InteractiveAclFixture {
    param(
        [string]$InteractiveDirectory,
        [System.Security.Principal.SecurityIdentifier]$SigningSid
    )

    $path = Join-Path $InteractiveDirectory 'spool-acl'
    if (Test-Path -LiteralPath $path) { throw 'acceptance_acl_fixture_collision' }
    [System.IO.Directory]::CreateDirectory($path) | Out-Null
    $admins = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $creator = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $directorySecurity = [System.Security.AccessControl.DirectorySecurity]::new()
    $directorySecurity.SetAccessRuleProtection($true, $false)
    $directorySecurity.SetOwner($system)
    foreach ($sid in @($system, $admins)) {
        $directorySecurity.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            $none,
            [System.Security.AccessControl.AccessControlType]::Allow))
    }
    $signingRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    $directorySecurity.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $SigningSid,
        $signingRights,
        $inherit,
        $none,
        [System.Security.AccessControl.AccessControlType]::Allow))
    $directorySecurity.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $creator,
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
        [System.Security.AccessControl.AccessControlType]::Allow))
    [System.IO.Directory]::SetAccessControl($path, $directorySecurity)

    $sibling = Join-Path $InteractiveDirectory 'spool-acl-system-sibling.part'
    if (Test-Path -LiteralPath $sibling) { throw 'acceptance_acl_fixture_collision' }
    New-CreateNewText $sibling 'LocalSystem sibling sentinel'
    $fileSecurity = [System.Security.AccessControl.FileSecurity]::new()
    $fileSecurity.SetAccessRuleProtection($true, $false)
    $fileSecurity.SetOwner($system)
    foreach ($sid in @($system, $admins)) {
        $fileSecurity.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow))
    }
    $fileSecurity.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $SigningSid,
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.AccessControlType]::Allow))
    [System.IO.File]::SetAccessControl($sibling, $fileSecurity)
    return [pscustomobject]@{
        Path = $path
        SiblingPath = $sibling
        DirectoryIdentity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($path, $true).Identity
        SiblingIdentity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($sibling, $false).Identity
        SiblingSha256 = (Get-FileHash -LiteralPath $sibling -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Remove-InteractiveAclFixture {
    param(
        [string]$Path,
        [string]$SiblingPath,
        [string]$ExpectedDirectoryIdentity,
        [string]$ExpectedSiblingIdentity,
        [string]$ExpectedSiblingSha256
    )

    $item = Get-Item -LiteralPath $Path -Force
    $directoryIdentity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($Path, $true)
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $directoryIdentity.Identity -cne $ExpectedDirectoryIdentity) {
        throw 'acceptance_state_uncertain'
    }
    if ([SimplySignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::IsWithinTrustedRoot(
            $SiblingPath,
            @($Path))) {
        throw 'acceptance_state_uncertain'
    }
    [SimplySignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact(
        @(),
        @(Get-ChildItem -LiteralPath $Path -Force | ForEach-Object { $_.Name }))
    $siblingIdentity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($SiblingPath, $false)
    if ($siblingIdentity.Identity -cne $ExpectedSiblingIdentity -or $siblingIdentity.LinkCount -ne 1 -or
        (Get-FileHash -LiteralPath $SiblingPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSiblingSha256) {
        throw 'acceptance_state_uncertain'
    }
    [SimplySignAuto.Acceptance.Contracts.SentinelLayoutPolicy]::Validate(
        $Path,
        $SiblingPath,
        $ExpectedSiblingIdentity,
        $siblingIdentity.Identity,
        $ExpectedSiblingSha256,
        (Get-FileHash -LiteralPath $SiblingPath -Algorithm SHA256).Hash.ToLowerInvariant())
    $directoryAfter = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($Path, $true)
    if ($directoryAfter.Identity -cne $ExpectedDirectoryIdentity -or
        @(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) {
        throw 'acceptance_state_uncertain'
    }
    Remove-Item -LiteralPath $Path -Force
    if (Test-Path -LiteralPath $Path) { throw 'acceptance_state_uncertain' }
    if (-not [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::DeleteOrdinaryFileIfExact(
            $SiblingPath,
            $ExpectedSiblingIdentity,
            $ExpectedSiblingSha256) -or
        (Test-Path -LiteralPath $SiblingPath)) {
        throw 'acceptance_state_uncertain'
    }
}

function Assert-TrxAndCollect {
    param([string]$Path, [System.Collections.Generic.HashSet[string]]$PassedTests)
    [xml]$document = Get-Content -LiteralPath $Path -Raw
    $counters = $document.TestRun.ResultSummary.Counters
    if ($null -eq $counters -or [int]$counters.executed -le 0 -or [int]$counters.failed -ne 0 -or
        [int]$counters.error -ne 0 -or [int]$counters.timeout -ne 0 -or [int]$counters.aborted -ne 0 -or
        [int]$counters.notExecuted -ne 0) { throw 'acceptance_trx_invalid' }
    foreach ($result in @($document.SelectNodes("//*[local-name()='UnitTestResult']"))) {
        if ($result.outcome -eq 'Passed') { $null = $PassedTests.Add([string]$result.testName) }
    }
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $raw,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }
}

function Publish-SafeTrx {
    param(
        [string]$RawPath,
        [string]$FinalPath,
        [string]$ExpectedAssembly,
        [string]$RawDirectory
    )
    $partPath = $FinalPath + '.part'
    try {
        $rawItem = Get-Item -LiteralPath $RawPath -Force
        if ($rawItem.PSIsContainer -or
            ($rawItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Test-Path -LiteralPath $FinalPath) -or
            (Test-Path -LiteralPath $partPath)) {
            throw 'acceptance_trx_invalid'
        }
        $stream = [System.IO.FileStream]::new(
            $RawPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None)
        try {
            if ($stream.Length -lt 1 -or $stream.Length -gt 16777216) { throw 'acceptance_trx_invalid' }
            $reader = [System.IO.StreamReader]::new(
                $stream,
                [System.Text.UTF8Encoding]::new($false, $true),
                $true,
                65536,
                $true)
            try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        $safe = [SimplySignAuto.Acceptance.Contracts.TrxArtifactPolicy]::Sanitize(
            $raw,
            $ExpectedAssembly,
            [Environment]::MachineName,
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            [string]$script:TotpSecretForRedaction)
        New-CreateNewText $partPath $safe
        [System.IO.File]::Move($partPath, $FinalPath)
    } finally {
        $raw = $null
        $safe = $null
        if (Test-Path -LiteralPath $partPath -PathType Leaf) { Remove-Item -LiteralPath $partPath -Force }
        if (Test-Path -LiteralPath $RawPath -PathType Leaf) {
            $rawItem = Get-Item -LiteralPath $RawPath -Force
            if (($rawItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'acceptance_state_uncertain'
            }
            Remove-Item -LiteralPath $RawPath -Force
        }
        if (Test-Path -LiteralPath $RawDirectory -PathType Container) {
            if (@(Get-ChildItem -LiteralPath $RawDirectory -Force).Count -ne 0) {
                throw 'acceptance_state_uncertain'
            }
            Remove-Item -LiteralPath $RawDirectory -Force
        }
    }
}

function Assert-AuthenticodeSequence {
    param(
        [string]$Path,
        [string[]]$ExpectedSignerSuffixes,
        [string]$CanonicalSignTool,
        [int]$BoundSeconds,
        [bool]$RequireAcceptanceWindow = $true
    )

    $verify = Invoke-BoundedProcessCapture `
        $CanonicalSignTool `
        @('verify', '/pa', '/all', '/v', $Path) `
        $BoundSeconds `
        $null
    if ($verify.ExitCode -ne 0 -or
        [SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $verify.Stdout + $verify.Stderr,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_authenticode_verify_failed'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.TimeStamperCertificate) {
        throw 'acceptance_authenticode_verify_failed'
    }
    $timestampMatches = [regex]::Matches(
        $verify.Stdout,
        '(?im)^\s*The signature is timestamped:\s*(?<value>[^\r\n]+?)\s*$')
    if ($timestampMatches.Count -ne $ExpectedSignerSuffixes.Count) {
        throw 'acceptance_authenticode_timestamp_invalid'
    }
    $observedTimestamp = [DateTimeOffset]::MinValue
    $timestampText = $timestampMatches[$timestampMatches.Count - 1].Groups['value'].Value
    $timestampStyles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor
        [System.Globalization.DateTimeStyles]::AssumeLocal
    if (-not [DateTimeOffset]::TryParseExact(
            $timestampText,
            'ddd MMM dd HH:mm:ss yyyy',
            [System.Globalization.CultureInfo]::GetCultureInfo('en-US'),
            $timestampStyles,
            [ref]$observedTimestamp) -and
        -not [DateTimeOffset]::TryParse(
            $timestampText,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeLocal,
            [ref]$observedTimestamp) -and
        -not [DateTimeOffset]::TryParse(
            $timestampText,
            [System.Globalization.CultureInfo]::CurrentCulture,
            [System.Globalization.DateTimeStyles]::AssumeLocal,
            [ref]$observedTimestamp)) {
        throw 'acceptance_authenticode_timestamp_invalid'
    }
    $timestampUtc = $observedTimestamp.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    if ($RequireAcceptanceWindow) {
        [SimplySignAuto.Acceptance.Contracts.SignatureTimestampPolicy]::Validate(
            $timestampUtc,
            $AcceptanceStartedUtc,
            [DateTimeOffset]::UtcNow,
            (Get-CertificateSha256 $signature.TimeStamperCertificate),
            $TimestampSignerSha256,
            $signature.TimeStamperCertificate.Subject,
            $TimestampSignerSubjectSuffix)
    } else {
        [SimplySignAuto.Acceptance.Contracts.SignatureTimestampPolicy]::ValidateSignerIdentity(
            $timestampUtc,
            (Get-CertificateSha256 $signature.TimeStamperCertificate),
            $TimestampSignerSha256,
            $signature.TimeStamperCertificate.Subject,
            $TimestampSignerSubjectSuffix)
    }
    $actual = [SimplySignAuto.Acceptance.Contracts.AuthenticodeSignatureSequence]::ReadSuffixes($Path)
    [SimplySignAuto.Acceptance.Contracts.RemoteAcceptanceMatrixPolicy]::ValidateSignerSequence(
        $actual,
        $ExpectedSignerSuffixes)
}

function Assert-PublicCertificateChain {
    param(
        [string]$CanonicalCertUtil,
        [string]$CertificatePath,
        [string]$ExpectedSha256,
        [string]$ExpectedSubjectSuffix
    )

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
    try {
        if ((Get-CertificateSha256 $certificate) -cne $ExpectedSha256 -or
            (-not [string]::IsNullOrEmpty($ExpectedSubjectSuffix) -and
                -not $certificate.Subject.EndsWith(
                    $ExpectedSubjectSuffix,
                    [System.StringComparison]::Ordinal))) {
            throw 'acceptance_certificate_identity_invalid'
        }
        $verified = Invoke-BoundedProcessCapture `
            $CanonicalCertUtil `
            @('-verify', '-silent', $CertificatePath) `
            60 `
            $null
        if ($verified.ExitCode -ne 0 -or
            -not [string]::IsNullOrWhiteSpace($verified.Stderr) -or
            [SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
                $verified.Stdout + $verified.Stderr,
                [string]$script:TotpSecretForRedaction)) {
            throw 'acceptance_certificate_chain_invalid'
        }
    } finally { $certificate.Dispose() }
}

function Invoke-IndependentPdfValidation {
    param(
        [string]$CanonicalValidator,
        [string]$OutputPath,
        [string[]]$TrustRoots,
        [string[]]$IntermediateCertificates,
        [bool]$ProjectValidatorOk,
        [bool]$DocumentChainValid,
        [bool]$TimestampChainValid
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($value in @('sign', 'validate', '--executive-summary', '--trust-replace', '--no-revocation-check')) {
        $arguments.Add($value)
    }
    foreach ($trustRoot in $TrustRoots) {
        $arguments.Add('--trust')
        $arguments.Add($trustRoot)
    }
    foreach ($intermediate in $IntermediateCertificates) {
        $arguments.Add('--other-certs')
        $arguments.Add($intermediate)
    }
    $arguments.Add($OutputPath)
    $independent = Invoke-BoundedProcessCapture $CanonicalValidator $arguments.ToArray() 60 $null
    if (-not [string]::IsNullOrWhiteSpace($independent.Stderr) -or
        [SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $independent.Stdout + $independent.Stderr,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_pdf_dual_validation_failed'
    }
    [SimplySignAuto.Acceptance.Contracts.PdfDualValidationPolicy]::Validate(
        $ProjectValidatorOk,
        $independent.ExitCode,
        $independent.Stdout,
        $DocumentChainValid,
        $TimestampChainValid)
}

function Assert-ExactChildren {
    param([string]$Path, [string[]]$Expected)
    [SimplySignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact(
        $Expected,
        @(Get-ChildItem -LiteralPath $Path -Force | ForEach-Object { $_.Name }))
}

function Assert-AcceptanceArtifactLayout {
    param(
        [string]$RunDirectory,
        [bool]$SummaryExpected,
        [bool]$FreshInstallExpected
    )

    $top = @(
        'authenticode.append-different.exe', 'authenticode.append-same.exe',
        'authenticode.signed.exe', 'boot-cleanup.json', 'close-recovery.signed.exe',
        'close-recovery.signed.pdf', 'controller.stderr.txt', 'controller.stdout.txt', 'event-log.json',
        'document.signed.pdf', 'fixture-external-sentinel.bin', 'fixtures', 'interactive', 'native-signed.cat',
        'native-signed.dll', 'native-signed.msi', 'native-signed.sys',
        'job-manifest.json', 'native', 'owner.txt', 'preflight.json',
        'queue-01.signed.pdf', 'queue-02.signed.pdf', 'queue-03.signed.pdf',
        'queue-04.signed.pdf', 'queue-05.signed.pdf', 'reboot-authenticode.signed.exe',
        'reboot-document.signed.pdf', 'sync.signed.pdf', 'ui', 'unattended-reboot.json')
    if ($SummaryExpected) { $top += 'summary.json' }
    if ($FreshInstallExpected) { $top += 'fresh-setup-completed.json' }
    Assert-ExactChildren $RunDirectory $top

    $native = Join-Path $RunDirectory 'native'
    Assert-ExactChildren $native @('agent', 'core', 'e2e', 'protocol', 'service', 'ui')
    foreach ($name in @('agent', 'core', 'e2e', 'protocol', 'service', 'ui')) {
        Assert-ExactChildren (Join-Path $native $name) @("$name.trx")
    }

    $interactive = Join-Path $RunDirectory 'interactive'
    Assert-ExactChildren $interactive @('interactive-result.json', 'native', 'owner.txt', 'production-ui')
    $interactiveNative = Join-Path $interactive 'native'
    Assert-ExactChildren $interactiveNative @('agent', 'service', 'ui')
    foreach ($name in @('agent', 'service', 'ui')) {
        Assert-ExactChildren (Join-Path $interactiveNative $name) @("$name-interactive.trx")
    }
    Assert-ExactChildren (Join-Path $interactive 'production-ui') @(
        'input.exe', 'input.pdf', 'production-ui-result.json', 'production-ui.trx',
        'quick-exe.signed.exe', 'quick-pdf.signed.pdf')

    $fixtureDirectory = Join-Path $RunDirectory 'fixtures'
    Assert-ExactChildren $fixtureDirectory @('fixture-manifest.json', 'fixture-owner.txt')

    $uiRoot = Join-Path $RunDirectory 'ui'
    $uiRuns = @(Get-ChildItem -LiteralPath $uiRoot -Directory -Force)
    if (@(Get-ChildItem -LiteralPath $uiRoot -File -Force).Count -ne 0 -or $uiRuns.Count -ne 1 -or
        $uiRuns[0].Name -cnotmatch '^[0-9a-f]{32}$' -or
        (Get-Content -LiteralPath (Join-Path $uiRuns[0].FullName 'owner.txt') -Raw) -cne $uiRuns[0].Name) {
        throw 'acceptance_artifact_set_invalid'
    }
    $uiNames = @(
        'activation-saved.png', 'activation-saved.png.attestation.json',
        'desktop.stderr.txt', 'desktop.stdout.txt', 'jobs-loaded.png',
        'jobs-loaded.png.attestation.json', 'manifest.json', 'overview-busy.png',
        'overview-busy.png.attestation.json', 'owner.txt', 'quick-finalizing.png',
        'quick-finalizing.png.attestation.json', 'ui-acceptance.trx', 'window-geometry.png',
        'window-geometry.png.attestation.json')
    Assert-ExactChildren $uiRuns[0].FullName $uiNames
}

function New-SafeEventLogSummary {
    param([string]$Path, [string]$RunId, [DateTimeOffset]$StartedUtc)

    $null = Get-WinEvent -ListLog Application -ErrorAction Stop
    $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $StartedUtc.UtcDateTime
        } -MaxEvents 2048 -ErrorAction SilentlyContinue)
    if ($events.Count -eq 2048) { throw 'acceptance_event_log_incomplete' }
    $selected = @($events | Where-Object {
            ([string]$_.ProviderName).StartsWith('SimplySignAuto', [System.StringComparison]::OrdinalIgnoreCase) -or
            ([string]$_.Message).IndexOf('SimplySignAuto', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        })
    foreach ($eventRecord in $selected) {
        $message = [string]$eventRecord.Message
        if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
                $message,
                [string]$script:TotpSecretForRedaction)) {
            throw 'acceptance_sensitive_artifact'
        }
    }
    $records = @($selected |
        Group-Object ProviderName, Id, Level |
        ForEach-Object {
            $sample = $_.Group[0]
            $provider = [string]$sample.ProviderName
            if ($provider -notmatch '^[A-Za-z0-9 ._-]{1,128}$') {
                throw 'acceptance_event_log_invalid'
            }
            [ordered]@{
                provider = $provider
                eventId = [int]$sample.Id
                level = [int]$sample.Level
                count = [int]$_.Count
            }
        })
    $payload = [ordered]@{
        schemaVersion = 1
        runId = $RunId
        startedUtc = $StartedUtc.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        completedUtc = [DateTimeOffset]::UtcNow.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        messageScanned = $true
        secretScan = 'clean'
        records = $records
    } | ConvertTo-Json -Compress -Depth 4
    $parsed = ConvertFrom-StrictJson $payload
    Assert-ExactProperties $parsed @(
        'schemaVersion', 'runId', 'startedUtc', 'completedUtc', 'messageScanned',
        'secretScan', 'records')
    foreach ($record in @($parsed.records)) {
        Assert-ExactProperties $record @('provider', 'eventId', 'level', 'count')
    }
    New-CreateNewText $Path $payload
}

function Invoke-NativeTests {
    param([string]$CanonicalRepo, [string]$CanonicalDotnet, [string]$RunDirectory, [int]$BoundSeconds)
    $native = Join-Path $RunDirectory 'native'
    [System.IO.Directory]::CreateDirectory($native) | Out-Null
    $restore = Invoke-BoundedProcessCapture $CanonicalDotnet @('restore', (Join-Path $CanonicalRepo 'SimplySignAuto.sln'), '--locked-mode', '--force-evaluate', '-m:1', '-nodeReuse:false') $BoundSeconds $null
    if ($restore.ExitCode -ne 0) { throw 'acceptance_restore_failed' }
    $projects = [ordered]@{
        core = 'tests\SimplySignAuto.Core.Tests\SimplySignAuto.Core.Tests.csproj'
        protocol = 'tests\SimplySignAuto.Protocol.Tests\SimplySignAuto.Protocol.Tests.csproj'
        agent = 'tests\SimplySignAuto.Agent.Tests\SimplySignAuto.Agent.Tests.csproj'
        service = 'tests\SimplySignAuto.Service.Tests\SimplySignAuto.Service.Tests.csproj'
        e2e = 'tests\SimplySignAuto.EndToEnd.Tests\SimplySignAuto.EndToEnd.Tests.csproj'
        ui = 'tests\SimplySignAuto.UI.Tests\SimplySignAuto.UI.Tests.csproj'
    }
    $oldAdminIntegration = $env:SIMPLYSIGN_RUN_ADMIN_INTEGRATION
    $env:SIMPLYSIGN_RUN_ADMIN_INTEGRATION = '1'
    try {
        foreach ($entry in $projects.GetEnumerator()) {
            $resultDirectory = Join-Path $native $entry.Key
            [System.IO.Directory]::CreateDirectory($resultDirectory) | Out-Null
            $rawDirectory = Join-Path $resultDirectory '.raw'
            [System.IO.Directory]::CreateDirectory($rawDirectory) | Out-Null
            $rawTrx = Join-Path $rawDirectory 'results.raw.trx'
            $finalTrx = Join-Path $resultDirectory "$($entry.Key).trx"
            $arguments = @('test', (Join-Path $CanonicalRepo $entry.Value), '-c', 'Release', '--no-restore', '--logger', 'trx;LogFileName=results.raw.trx', '--results-directory', $rawDirectory, '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false')
            $filters = New-Object System.Collections.Generic.List[string]
            if ($entry.Key -eq 'agent') { $filters.Add('FullyQualifiedName!~Does_not_create_a_non_windows_encryption_fallback') }
            if ($entry.Key -eq 'ui') {
                $filters.Add('Category!=Desktop')
                $filters.Add('Category!=ProductionAcceptance')
            }
            $assemblySegment = switch ($entry.Key) {
                'ui' { 'UI' }
                'e2e' { 'EndToEnd' }
                default { $entry.Key.Substring(0, 1).ToUpperInvariant() + $entry.Key.Substring(1) }
            }
            $prefix = "SimplySignAuto.$assemblySegment.Tests."
            foreach ($interactiveTest in @($InteractiveWindowsNativeTests | Where-Object { $_.StartsWith($prefix, [System.StringComparison]::Ordinal) })) {
                $filters.Add("FullyQualifiedName!=$interactiveTest")
            }
            if ($filters.Count -gt 0) { $arguments += @('--filter', ($filters -join '&')) }
            $run = $null
            try {
                $run = Invoke-BoundedProcessCapture $CanonicalDotnet $arguments $BoundSeconds $null
            } finally {
                if (Test-Path -LiteralPath $rawTrx -PathType Leaf) {
                    Publish-SafeTrx $rawTrx $finalTrx "SimplySignAuto.$assemblySegment.Tests.dll" $rawDirectory
                } elseif ((Test-Path -LiteralPath $rawDirectory -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $rawDirectory -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $rawDirectory -Force
                }
            }
            if ($run.ExitCode -ne 0) { throw 'acceptance_native_tests_failed' }
            if (-not (Test-Path -LiteralPath $finalTrx -PathType Leaf)) { throw 'acceptance_trx_invalid' }
        }
    } finally {
        if ($null -eq $oldAdminIntegration) { Remove-Item Env:SIMPLYSIGN_RUN_ADMIN_INTEGRATION -ErrorAction SilentlyContinue }
        else { $env:SIMPLYSIGN_RUN_ADMIN_INTEGRATION = $oldAdminIntegration }
    }
}

function Invoke-InteractiveNativeTests {
    param(
        [string]$CanonicalRepo,
        [string]$CanonicalDotnet,
        [string]$InteractiveDirectory,
        [string]$AclFixtureDirectory,
        [int]$BoundSeconds
    )

    $projects = [ordered]@{
        agent = 'tests\SimplySignAuto.Agent.Tests\SimplySignAuto.Agent.Tests.csproj'
        service = 'tests\SimplySignAuto.Service.Tests\SimplySignAuto.Service.Tests.csproj'
        ui = 'tests\SimplySignAuto.UI.Tests\SimplySignAuto.UI.Tests.csproj'
    }
    $resultRoot = Join-Path $InteractiveDirectory 'native'
    [System.IO.Directory]::CreateDirectory($resultRoot) | Out-Null
    $oldAclEnabled = $env:SIMPLYSIGN_RUN_INTERACTIVE_ACL_INTEGRATION
    $oldAclPath = $env:SIMPLYSIGN_ACL_ACCEPTANCE_DIRECTORY
    $env:SIMPLYSIGN_RUN_INTERACTIVE_ACL_INTEGRATION = '1'
    $env:SIMPLYSIGN_ACL_ACCEPTANCE_DIRECTORY = $AclFixtureDirectory
    try {
        foreach ($entry in $projects.GetEnumerator()) {
            $assemblySegment = if ($entry.Key -eq 'ui') {
                'UI'
            } else {
                $entry.Key.Substring(0, 1).ToUpperInvariant() + $entry.Key.Substring(1)
            }
            $prefix = "SimplySignAuto.$assemblySegment.Tests."
            $tests = @($InteractiveWindowsNativeTests | Where-Object { $_.StartsWith($prefix, [System.StringComparison]::Ordinal) })
            if ($tests.Count -eq 0) { continue }
            $resultDirectory = Join-Path $resultRoot $entry.Key
            [System.IO.Directory]::CreateDirectory($resultDirectory) | Out-Null
            $rawDirectory = Join-Path $resultDirectory '.raw'
            [System.IO.Directory]::CreateDirectory($rawDirectory) | Out-Null
            $rawTrx = Join-Path $rawDirectory 'results.raw.trx'
            $finalTrx = Join-Path $resultDirectory "$($entry.Key)-interactive.trx"
            $filter = @($tests | ForEach-Object { "FullyQualifiedName=$_" }) -join '|'
            $run = $null
            try {
                $run = Invoke-BoundedProcessCapture $CanonicalDotnet @(
                    'test', (Join-Path $CanonicalRepo $entry.Value), '-c', 'Release', '--no-restore', '--no-build',
                    '--logger', 'trx;LogFileName=results.raw.trx', '--results-directory',
                    $rawDirectory, '--filter', $filter, '-m:1', '-nodeReuse:false') $BoundSeconds $null
            } finally {
                if (Test-Path -LiteralPath $rawTrx -PathType Leaf) {
                    Publish-SafeTrx $rawTrx $finalTrx "SimplySignAuto.$assemblySegment.Tests.dll" $rawDirectory
                } elseif ((Test-Path -LiteralPath $rawDirectory -PathType Container) -and
                    @(Get-ChildItem -LiteralPath $rawDirectory -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $rawDirectory -Force
                }
            }
            if ($run.ExitCode -ne 0) { throw 'acceptance_native_tests_failed' }
            if (-not (Test-Path -LiteralPath $finalTrx -PathType Leaf)) { throw 'acceptance_trx_invalid' }
        }
    } finally {
        if ($null -eq $oldAclEnabled) { Remove-Item Env:SIMPLYSIGN_RUN_INTERACTIVE_ACL_INTEGRATION -ErrorAction SilentlyContinue }
        else { $env:SIMPLYSIGN_RUN_INTERACTIVE_ACL_INTEGRATION = $oldAclEnabled }
        if ($null -eq $oldAclPath) { Remove-Item Env:SIMPLYSIGN_ACL_ACCEPTANCE_DIRECTORY -ErrorAction SilentlyContinue }
        else { $env:SIMPLYSIGN_ACL_ACCEPTANCE_DIRECTORY = $oldAclPath }
    }
}

function Invoke-ChildWork {
    $script:DiagnosticStage = 'child_preflight'
    $canonicalRepo = Get-CanonicalExistingPath $RepoPath Container
    Assert-TrustedRootAcl $canonicalRepo
    Initialize-ContractSources $canonicalRepo
    $windowsSystemPublishers =
        [SimplySignAuto.Acceptance.Contracts.WindowsSystemPublisherMapPolicy]::Parse(
            $WindowsSystemPublisherSha256Map)
    $canonicalRun = Get-CanonicalExistingPath $ArtifactRoot Container
    $canonicalInteractive = Get-CanonicalExistingPath (Join-Path $canonicalRun 'interactive') Container
    $canonicalDotnet = Get-CanonicalExistingPath $DotnetPath Leaf
    $canonicalApp = Get-CanonicalExistingPath $AppHostPath Leaf
    $canonicalSimplySign = Get-CanonicalExistingPath $SimplySignDesktopPath Leaf
    $canonicalPowerShell = Get-CanonicalExistingPath $PowerShellPath Leaf
    $canonicalSystemRoot = Get-CanonicalExistingPath $env:SystemRoot Container
    $canonicalTaskKill = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\taskkill.exe') Leaf
    $canonicalProgramFiles = Get-CanonicalExistingPath $env:ProgramFiles Container
    $canonicalProgramFilesX86 = Get-CanonicalExistingPath ${env:ProgramFiles(x86)} Container
    $canonicalAcceptanceRoot = Get-CanonicalAcceptanceRoot $canonicalRepo
    $canonicalAppRoot = Get-CanonicalExistingPath ([System.IO.Path]::GetDirectoryName($canonicalApp)) Container
    $trustedRoots = @(
        $canonicalSystemRoot, $canonicalProgramFiles, $canonicalProgramFilesX86, $canonicalAcceptanceRoot,
        $canonicalRepo, $canonicalAppRoot)
    Add-TrustedExecutableGuard $canonicalPowerShell $trustedRoots PlatformPublisher $PowerShellPublisherSha256
    Add-TrustedExecutableGuard $canonicalDotnet $trustedRoots PlatformPublisher $DotnetPublisherSha256
    Add-TrustedExecutableGuard $canonicalApp $trustedRoots ManifestSha256 $AppHostSha256
    Add-TrustedExecutableGuard $canonicalSimplySign $trustedRoots PlatformPublisher $SimplySignPublisherSha256
    Add-TrustedExecutableGuard `
        $canonicalTaskKill `
        $trustedRoots `
        PlatformPublisher `
        ($windowsSystemPublishers.ResolveExpectedPublisherSha256($canonicalTaskKill))
    if ([System.IO.Path]::GetFileName($canonicalRun) -cne $RunId -or
        (Get-Content -LiteralPath (Join-Path $canonicalInteractive 'owner.txt') -Raw) -cne $RunId) { throw 'acceptance_owner_invalid' }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $expectedIdentity = [System.Security.Principal.NTAccount]::new($SigningUser).Translate(
        [System.Security.Principal.SecurityIdentifier])
    $principalHash = Get-Sha256Text $identity.User.Value
    $session = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($identity.User -ne $expectedIdentity -or $session -ne $ExpectedSessionId -or -not (Test-WtsActive $session)) {
        throw 'acceptance_session_unavailable'
    }
    $expectedAgentTask = [SimplySignAuto.Acceptance.Contracts.AgentTaskExecutionSnapshot]::new(
        $expectedIdentity.Value,
        $canonicalApp,
        'agent --background',
        'InteractiveToken',
        'HighestAvailable',
        'LogonTrigger',
        $ExpectedAgentTaskSource,
        'SimplySignAuto/v1',
        $true,
        $true,
        1,
        1)
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='SimplySignDesktop.exe'" | Where-Object { [int]$_.SessionId -eq $session })) {
        if (-not [string]::Equals([string]$process.ExecutablePath, $canonicalSimplySign, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'acceptance_simplysign_identity_invalid'
        }
    }
    Assert-AgentTaskExact $expectedAgentTask $canonicalApp
    $agentTask = Get-ScheduledTask -TaskName 'SimplySignAuto.Agent' -ErrorAction Stop
    if ($agentTask.State -eq 'Running') {
        Assert-AgentTaskExact $expectedAgentTask $canonicalApp
        Stop-ScheduledTask -TaskName 'SimplySignAuto.Agent'
        $stopWatch = [Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Milliseconds 250
            $agentTask = Get-ScheduledTask -TaskName 'SimplySignAuto.Agent'
        } while ($agentTask.State -eq 'Running' -and $stopWatch.Elapsed.TotalSeconds -lt 30)
        if ($agentTask.State -eq 'Running') { throw 'acceptance_agent_stop_timeout' }
    }
    $aclFixture = Get-CanonicalExistingPath (Join-Path $canonicalInteractive 'spool-acl') Container
    Invoke-InteractiveNativeTests `
        $canonicalRepo `
        $canonicalDotnet `
        $canonicalInteractive `
        $aclFixture `
        $ChildTimeoutSeconds
    Assert-AgentTaskExact $expectedAgentTask $canonicalApp
    Start-ScheduledTask -TaskName 'SimplySignAuto.Agent'
    $agentWatch = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 250
        $agentTask = Get-ScheduledTask -TaskName 'SimplySignAuto.Agent'
    } while ($agentTask.State -ne 'Running' -and $agentWatch.Elapsed.TotalSeconds -lt 30)
    if ($agentTask.State -ne 'Running') { throw 'acceptance_agent_start_timeout' }
    $agentBeforeClose = Get-ExactAgentProcess $canonicalApp $session $expectedIdentity
    $agentPidBeforeClose = [int]$agentBeforeClose.ProcessId
    # The baseline signatures above prove the configured credential first. The controlled close is
    # deliberately last in this interactive child: no OTP import, UI action, or manual login follows it.
    # The controller's next bounded readiness/HTTPS job must therefore exercise automatic recovery.
    $closed = Invoke-BoundedProcessCapture $canonicalSimplySign @('/close') ([Math]::Min(60, $ChildTimeoutSeconds)) $null
    if ($closed.ExitCode -ne 0) { throw 'acceptance_simplysign_close_failed' }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $remaining = @(Get-CimInstance Win32_Process -Filter "Name='SimplySignDesktop.exe'" | Where-Object { [int]$_.SessionId -eq $session })
        if ($remaining.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt 30)
    if ($remaining.Count -ne 0) { throw 'acceptance_simplysign_close_timeout' }
    $simplySignClosedAtUtc = [DateTimeOffset]::UtcNow
    $agentAfterClose = Get-ExactAgentProcess $canonicalApp $session $expectedIdentity
    $agentPidAfterClose = [int]$agentAfterClose.ProcessId
    if ($agentPidAfterClose -ne $agentPidBeforeClose) { throw 'acceptance_agent_process_invalid' }
    $result = [ordered]@{
        schemaVersion = 4
        runId = $RunId
        sessionId = $session
        principalHash = $principalHash
        childPid = $PID
        otpConfigured = $false
        productionUi = $false
        simplySignClosed = $true
        simplySignClosedAtUtc = $simplySignClosedAtUtc.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
        agentPidBeforeClose = $agentPidBeforeClose
        agentPidAfterClose = $agentPidAfterClose
    } | ConvertTo-Json -Compress
    New-CreateNewText (Join-Path $canonicalInteractive 'interactive-result.json') $result
    [Console]::Out.WriteLine('acceptance_interactive_pass')
}

function Invoke-UnattendedRebootResume {
    param(
        [string]$CanonicalRepo,
        [string]$CanonicalRun,
        [string]$CanonicalApp,
        [string]$CanonicalPowerShell,
        [string]$CanonicalScript,
        [string]$RawDirectory,
        $Checkpoint,
        [string]$ResumeTaskName,
        [SimplySignAuto.Acceptance.Contracts.BootResumeTaskSnapshot]$ExpectedResumeTask
    )
    $windowsSystemPublishers =
        [SimplySignAuto.Acceptance.Contracts.WindowsSystemPublisherMapPolicy]::Parse(
            $WindowsSystemPublisherSha256Map)
    Assert-ExactProperties $Checkpoint @(
        'schemaVersion', 'phase', 'runId', 'acceptanceStartedUtc', 'bootBeforeUtc',
        'signingSid', 'baseUrl', 'tlsCertificatePin', 'agentTaskSource',
        'codeCertificateSerialNumber', 'documentCertificateSerialNumber',
        'codeSignSuffix', 'documentSignerSha256',
        'timestampSignerSha256', 'timestampSignerSubjectSuffix', 'expectedTimestampSignerSubject',
        'documentSignerCertificate', 'timestampSignerCertificate', 'pdfPage', 'pdfBox',
        'signToolPath', 'signToolPublisherSha256', 'pdfHelperPath', 'pdfHelperSha256',
        'independentPdfValidatorPath', 'independentPdfValidatorSha256', 'pdfTrustRoots',
        'pdfIntermediates', 'codeInput', 'pdfInput', 'codeInputSha256', 'pdfInputSha256',
        'dataRoot', 'agentDirectory', 'installInstanceHash', 'dotnetPath',
        'dotnetPublisherSha256', 'simplySignDesktopPath', 'simplySignPublisherSha256')
    if ($Checkpoint.schemaVersion -ne 2 -or $Checkpoint.phase -cne 'unattended' -or
        $Checkpoint.runId -cne $RunId -or
        $Checkpoint.signingSid -isnot [string] -or
        $Checkpoint.signingSid -notmatch '^S-1-[0-9]+(?:-[0-9]+)+$' -or
        $Checkpoint.agentTaskSource -isnot [string] -or
        $Checkpoint.agentTaskSource -notmatch '^SimplySignAuto/v1/[0-9a-f]{32}$' -or
        $Checkpoint.codeInputSha256 -isnot [string] -or
        $Checkpoint.codeInputSha256 -notmatch '^[0-9a-f]{64}$' -or
        $Checkpoint.pdfInputSha256 -isnot [string] -or
        $Checkpoint.pdfInputSha256 -notmatch '^[0-9a-f]{64}$' -or
        $Checkpoint.pdfBox -isnot [System.Array] -or @($Checkpoint.pdfBox).Count -ne 4 -or
        $Checkpoint.pdfTrustRoots -isnot [System.Array] -or @($Checkpoint.pdfTrustRoots).Count -lt 1 -or
        $Checkpoint.pdfIntermediates -isnot [System.Array] -or
        $Checkpoint.installInstanceHash -isnot [string] -or
        $Checkpoint.installInstanceHash -cnotmatch '^[0-9A-F]{64}$' -or
        $Checkpoint.dotnetPublisherSha256 -isnot [string] -or
        $Checkpoint.dotnetPublisherSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Checkpoint.simplySignPublisherSha256 -isnot [string] -or
        $Checkpoint.simplySignPublisherSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'acceptance_unattended_reboot_invalid'
    }
    $acceptanceStarted = [DateTimeOffset]::MinValue
    $bootBefore = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Checkpoint.acceptanceStartedUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal',
            [ref]$acceptanceStarted) -or
        -not [DateTimeOffset]::TryParseExact(
            [string]$Checkpoint.bootBeforeUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal',
            [ref]$bootBefore)) {
        throw 'acceptance_unattended_reboot_invalid'
    }
    $script:AcceptanceStartedUtc = $acceptanceStarted
    $bootAfter = Get-CurrentBootUtc
    if ($bootAfter -le $bootBefore) { throw 'acceptance_unattended_reboot_invalid' }

    $canonicalSystemRoot = Get-CanonicalExistingPath $env:SystemRoot Container
    $canonicalProgramFiles = Get-CanonicalExistingPath $env:ProgramFiles Container
    $canonicalProgramFilesX86 = Get-CanonicalExistingPath ${env:ProgramFiles(x86)} Container
    $canonicalAcceptanceRoot = Get-CanonicalAcceptanceRoot $CanonicalRepo
    $canonicalAppRoot = Get-CanonicalExistingPath ([System.IO.Path]::GetDirectoryName($CanonicalApp)) Container
    $trustedRoots = @(
        $canonicalSystemRoot, $canonicalProgramFiles, $canonicalProgramFilesX86, $canonicalAcceptanceRoot,
        $CanonicalRepo, $canonicalAppRoot)
    $canonicalSignTool = Get-CanonicalExistingPath ([string]$Checkpoint.signToolPath) Leaf
    $canonicalPdfHelper = Get-CanonicalExistingPath ([string]$Checkpoint.pdfHelperPath) Leaf
    $canonicalIndependentPdfValidator = Get-CanonicalExistingPath (
        [string]$Checkpoint.independentPdfValidatorPath) Leaf
    $canonicalDotnet = Get-CanonicalExistingPath ([string]$Checkpoint.dotnetPath) Leaf
    $canonicalSimplySign = Get-CanonicalExistingPath (
        [string]$Checkpoint.simplySignDesktopPath) Leaf
    $canonicalCertUtil = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\certutil.exe') Leaf
    Add-TrustedExecutableGuard `
        $canonicalSignTool $trustedRoots PlatformPublisher ([string]$Checkpoint.signToolPublisherSha256)
    Add-TrustedExecutableGuard `
        $canonicalPdfHelper $trustedRoots ManifestSha256 ([string]$Checkpoint.pdfHelperSha256)
    Add-TrustedExecutableGuard `
        $canonicalIndependentPdfValidator $trustedRoots ManifestSha256 `
        ([string]$Checkpoint.independentPdfValidatorSha256)
    Add-TrustedExecutableGuard `
        $canonicalDotnet $trustedRoots PlatformPublisher ([string]$Checkpoint.dotnetPublisherSha256)
    Add-TrustedExecutableGuard `
        $canonicalSimplySign $trustedRoots PlatformPublisher `
        ([string]$Checkpoint.simplySignPublisherSha256)
    Add-TrustedExecutableGuard `
        $canonicalCertUtil `
        $trustedRoots `
        PlatformPublisher `
        ($windowsSystemPublishers.ResolveExpectedPublisherSha256($canonicalCertUtil))
    $codeInput = Get-CanonicalExistingPath ([string]$Checkpoint.codeInput) Leaf
    $pdfInput = Get-CanonicalExistingPath ([string]$Checkpoint.pdfInput) Leaf
    if (-not (Test-PathUnder $codeInput $RawDirectory) -or
        -not (Test-PathUnder $pdfInput $RawDirectory) -or
        (Get-FileHash -LiteralPath $codeInput -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            [string]$Checkpoint.codeInputSha256 -or
        (Get-FileHash -LiteralPath $pdfInput -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            [string]$Checkpoint.pdfInputSha256) {
        throw 'acceptance_unattended_reboot_invalid'
    }

    $signingSid = [System.Security.Principal.SecurityIdentifier]::new([string]$Checkpoint.signingSid)
    $sessionWatch = [Diagnostics.Stopwatch]::StartNew()
    $signingSession = 0
    do {
        try { $signingSession = Get-UniqueActiveSession $signingSid } catch { $signingSession = 0 }
        if ($signingSession -gt 0 -and (Get-WtsClientProtocol $signingSession) -eq 0) { break }
        Start-Sleep -Milliseconds 500
    } while ($sessionWatch.Elapsed.TotalSeconds -lt 300)
    $wtsProtocol = Get-WtsClientProtocol $signingSession
    if ($signingSession -le 0 -or $wtsProtocol -ne 0) {
        throw 'acceptance_unattended_reboot_invalid'
    }
    $expectedAgentTask = [SimplySignAuto.Acceptance.Contracts.AgentTaskExecutionSnapshot]::new(
        $signingSid.Value,
        $CanonicalApp,
        'agent --background',
        'InteractiveToken',
        'HighestAvailable',
        'LogonTrigger',
        [string]$Checkpoint.agentTaskSource,
        'SimplySignAuto/v1',
        $true,
        $true,
        1,
        1)
    Assert-AgentTaskExact $expectedAgentTask $CanonicalApp
    $agentWatch = [Diagnostics.Stopwatch]::StartNew()
    $agentProcess = $null
    do {
        try { $agentProcess = Get-ExactAgentProcess $CanonicalApp $signingSession $signingSid }
        catch { $agentProcess = $null }
        if ($null -ne $agentProcess) { break }
        Start-Sleep -Milliseconds 500
    } while ($agentWatch.Elapsed.TotalSeconds -lt 300)
    $agentTask = Get-ScheduledTask -TaskName 'SimplySignAuto.Agent' -ErrorAction Stop
    if ($null -eq $agentProcess -or $agentTask.State -ne 'Running') {
        throw 'acceptance_unattended_reboot_invalid'
    }

    $lsaKey = "SimplySignAuto/Acceptance/$RunId/Api"
    $bearer = $null
    $client = $null
    try {
        $bearer = [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::Retrieve($lsaKey)
        $client = [SimplySignAuto.Acceptance.Contracts.PinnedHttpClientFactory]::Create(
            [string]$Checkpoint.tlsCertificatePin,
            $bearer)
        $readyWatch = [Diagnostics.Stopwatch]::StartNew()
        $ready = $null
        do {
            $response = $client.GetAsync("$($Checkpoint.baseUrl)/v1/health/ready").GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -eq 200) {
                    $ready = ConvertFrom-StrictJson (
                        $response.Content.ReadAsStringAsync().GetAwaiter().GetResult())
                    break
                }
            } finally { $response.Dispose() }
            Start-Sleep -Milliseconds 500
        } while ($readyWatch.Elapsed.TotalSeconds -lt 300)
        if ($null -eq $ready) { throw 'acceptance_unattended_reboot_invalid' }
        Assert-ExactProperties $ready @(
            'service', 'agent', 'simplySign', 'session', 'capabilities', 'queue')
        if ($ready.service -cne 'ready' -or $ready.agent.sessionId -ne $signingSession -or
            $ready.agent.heartbeatAgeSeconds -isnot [int] -or
            $ready.capabilities.authenticode.ready -ne $true -or
            $ready.capabilities.pdf.ready -ne $true) {
            throw 'acceptance_unattended_reboot_invalid'
        }

        function Invoke-RebootJob {
            param([string]$InputPath, [string]$ParametersJson, [string]$OutputPath)
            $multipart = [System.Net.Http.MultipartFormDataContent]::new(
                'ssa-' + [guid]::NewGuid().ToString('N'))
            $inputStream = [System.IO.File]::Open(
                $InputPath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read)
            $request = $null
            $response = $null
            try {
                $multipart.Add(
                    [System.Net.Http.StringContent]::new(
                        $ParametersJson,
                        [System.Text.Encoding]::UTF8,
                        'application/json'),
                    'parameters')
                $multipart.Add(
                    [System.Net.Http.StreamContent]::new($inputStream),
                    'file',
                    [System.IO.Path]::GetFileName($InputPath))
                $request = [System.Net.Http.HttpRequestMessage]::new(
                    [System.Net.Http.HttpMethod]::Post,
                    "$($Checkpoint.baseUrl)/v1/jobs")
                $request.Headers.Add('Idempotency-Key', [guid]::NewGuid().ToString('N'))
                $request.Content = $multipart
                $response = $client.SendAsync($request).GetAwaiter().GetResult()
                if ([int]$response.StatusCode -ne 202) { throw 'acceptance_unattended_reboot_invalid' }
                $created = ConvertFrom-StrictJson (
                    $response.Content.ReadAsStringAsync().GetAwaiter().GetResult())
                $jobId = [guid]$created.jobId
            } finally {
                if ($null -ne $response) { $response.Dispose() }
                if ($null -ne $request) { $request.Dispose() }
                $multipart.Dispose()
                $inputStream.Dispose()
            }
            $jobWatch = [Diagnostics.Stopwatch]::StartNew()
            do {
                Start-Sleep -Milliseconds 500
                $poll = $client.GetAsync(
                    "$($Checkpoint.baseUrl)/v1/jobs/$($jobId.ToString('D'))").GetAwaiter().GetResult()
                try {
                    $status = ConvertFrom-StrictJson (
                        $poll.Content.ReadAsStringAsync().GetAwaiter().GetResult())
                } finally { $poll.Dispose() }
                if ($status.state -in @('failed', 'expired')) {
                    throw 'acceptance_unattended_reboot_invalid'
                }
            } while ($status.state -cne 'succeeded' -and $jobWatch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
            if ($status.state -cne 'succeeded') { throw 'acceptance_unattended_reboot_invalid' }
            $download = $client.GetAsync(
                "$($Checkpoint.baseUrl)/v1/jobs/$($jobId.ToString('D'))/result").GetAwaiter().GetResult()
            try {
                if ([int]$download.StatusCode -ne 200) { throw 'acceptance_unattended_reboot_invalid' }
                $bytes = $download.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            } finally { $download.Dispose() }
            try {
                $output = [System.IO.FileStream]::new(
                    $OutputPath,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None)
                try { $output.Write($bytes, 0, $bytes.Length); $output.Flush($true) }
                finally { $output.Dispose() }
            } finally { [System.Array]::Clear($bytes, 0, $bytes.Length) }
            if ($status.resultSha256 -cne
                (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
                throw 'acceptance_unattended_reboot_invalid'
            }
            return $jobId
        }

        $codeOutput = Join-Path $CanonicalRun 'reboot-authenticode.signed.exe'
        $codeParameters = [ordered]@{
            kind = 'authenticode'
            certificateSerialNumber = [string]$Checkpoint.codeCertificateSerialNumber
            digestAlgorithm = 'sha256'
            appendSignature = $false
        } | ConvertTo-Json -Compress
        $codeInputHash = (Get-FileHash -LiteralPath $codeInput -Algorithm SHA256).Hash
        $codeJob = Invoke-RebootJob $codeInput $codeParameters $codeOutput
        if ((Get-FileHash -LiteralPath $codeInput -Algorithm SHA256).Hash -cne $codeInputHash) {
            throw 'acceptance_unattended_reboot_invalid'
        }
        Assert-AuthenticodeSequence `
            $codeOutput @([string]$Checkpoint.codeSignSuffix) $canonicalSignTool 120

        $pdfOutput = Join-Path $CanonicalRun 'reboot-document.signed.pdf'
        $pdfParameters = [ordered]@{
            kind = 'pdf'
            certificateSerialNumber = [string]$Checkpoint.documentCertificateSerialNumber
            digestAlgorithm = 'sha256'
            page = [int]$Checkpoint.pdfPage
            box = @($Checkpoint.pdfBox)
            fieldName = 'CertumDocumentSignature'
            reason = 'Acceptance'
            location = 'CN'
        } | ConvertTo-Json -Compress
        $pdfInputHash = (Get-FileHash -LiteralPath $pdfInput -Algorithm SHA256).Hash
        $pdfJob = Invoke-RebootJob $pdfInput $pdfParameters $pdfOutput
        if ((Get-FileHash -LiteralPath $pdfInput -Algorithm SHA256).Hash -cne $pdfInputHash) {
            throw 'acceptance_unattended_reboot_invalid'
        }
        Assert-PublicCertificateChain `
            $canonicalCertUtil `
            (Get-CanonicalExistingPath ([string]$Checkpoint.documentSignerCertificate) Leaf) `
            ([string]$Checkpoint.documentSignerSha256) `
            ''
        Assert-PublicCertificateChain `
            $canonicalCertUtil `
            (Get-CanonicalExistingPath ([string]$Checkpoint.timestampSignerCertificate) Leaf) `
            ([string]$Checkpoint.timestampSignerSha256) `
            ([string]$Checkpoint.timestampSignerSubjectSuffix)
        $validateRequest = Join-Path $RawDirectory 'reboot-pdf.validate.request.json'
        $requestJson = [ordered]@{
            inputPath = $pdfInput
            outputPath = $pdfOutput
            fieldName = 'CertumDocumentSignature'
            expectedInputSha256 = $pdfInputHash.ToLowerInvariant()
            expectedSignerSha256 = [string]$Checkpoint.documentSignerSha256
            page = [int]$Checkpoint.pdfPage
            box = @($Checkpoint.pdfBox)
            trustRoots = @($Checkpoint.pdfTrustRoots)
            intermediateCertificates = @($Checkpoint.pdfIntermediates)
        } | ConvertTo-Json -Compress
        New-CreateNewText $validateRequest $requestJson
        try {
            $validated = Invoke-BoundedProcessCapture `
                $canonicalPdfHelper @('validate', '--request', $validateRequest) 60 $null
            if ($validated.ExitCode -ne 0) { throw 'acceptance_unattended_reboot_invalid' }
            $pdfEvidence = ConvertFrom-StrictJson $validated.Stdout
            if ($pdfEvidence.ok -ne $true -or $pdfEvidence.signatureCount -ne 1 -or
                $pdfEvidence.wholeFile -ne $true -or $pdfEvidence.timestampPresent -ne $true -or
                $pdfEvidence.signerTrusted -ne $true -or $pdfEvidence.timestampTrusted -ne $true -or
                $pdfEvidence.inputUnchanged -ne $true) {
                throw 'acceptance_unattended_reboot_invalid'
            }
            [SimplySignAuto.Acceptance.Contracts.SignatureTimestampPolicy]::Validate(
                [string]$pdfEvidence.timestampUtc,
                $acceptanceStarted,
                [DateTimeOffset]::UtcNow,
                [string]$pdfEvidence.timestampSignerSha256,
                [string]$Checkpoint.timestampSignerSha256,
                [string]$Checkpoint.expectedTimestampSignerSubject,
                [string]$Checkpoint.timestampSignerSubjectSuffix)
            Invoke-IndependentPdfValidation `
                $canonicalIndependentPdfValidator `
                $pdfOutput `
                @($Checkpoint.pdfTrustRoots) `
                @($Checkpoint.pdfIntermediates) `
                $true `
                $true `
                $true
        } finally {
            if (Test-Path -LiteralPath $validateRequest -PathType Leaf) {
                Remove-Item -LiteralPath $validateRequest -Force
            }
        }

        [SimplySignAuto.Acceptance.Contracts.UnattendedRebootEvidencePolicy]::Validate(
            $bootBefore,
            $bootAfter,
            $signingSession,
            $signingSid.Value,
            $signingSid.Value,
            $wtsProtocol,
            $true,
            ($agentTask.State -eq 'Running'),
            [int]$agentProcess.ProcessId,
            [int]$agentProcess.SessionId,
            [int]$ready.agent.heartbeatAgeSeconds,
            [int][Math]::Ceiling($readyWatch.Elapsed.TotalSeconds),
            [bool]$ready.capabilities.authenticode.ready,
            [bool]$ready.capabilities.pdf.ready,
            $true,
            $true)
        $evidence = [ordered]@{
            schemaVersion = 1
            runId = $RunId
            bootBeforeUtc = $bootBefore.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            bootAfterUtc = $bootAfter.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            signingSessionId = $signingSession
            wtsClientProtocol = $wtsProtocol
            agentTask = 'exact-running'
            heartbeatAgeSeconds = [int]$ready.agent.heartbeatAgeSeconds
            readyElapsedSeconds = [int][Math]::Ceiling($readyWatch.Elapsed.TotalSeconds)
            authenticodeJobId = $codeJob.ToString('D')
            authenticodeResultSha256 = (Get-FileHash -LiteralPath $codeOutput -Algorithm SHA256).Hash.ToLowerInvariant()
            pdfJobId = $pdfJob.ToString('D')
            pdfResultSha256 = (Get-FileHash -LiteralPath $pdfOutput -Algorithm SHA256).Hash.ToLowerInvariant()
        } | ConvertTo-Json -Compress
        New-CreateNewText (Join-Path $CanonicalRun 'unattended-reboot.json') $evidence
    } finally {
        if ($null -ne $client) { $client.Dispose() }
        $bearer = $null
    }

    $cleanupFailure = Invoke-UnattendedRebootCleanup $null
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    $pendingSummaryPath = Get-CanonicalExistingPath (
        (Join-Path $RawDirectory 'summary.pending.json')) Leaf
    $pendingSummary = Get-Content -LiteralPath $pendingSummaryPath -Raw
    Remove-Item -LiteralPath (Join-Path $RawDirectory 'checkpoint.json') -Force
    Remove-Item -LiteralPath $pendingSummaryPath -Force
    Remove-Item -LiteralPath $codeInput -Force
    Remove-Item -LiteralPath $pdfInput -Force
    if (@(Get-ChildItem -LiteralPath $RawDirectory -Force).Count -ne 0) {
        throw 'acceptance_state_uncertain'
    }
    Remove-Item -LiteralPath $RawDirectory -Force

    Prepare-PurgeHardStopRebootStage `
        $CanonicalRepo `
        $CanonicalScript `
        $CanonicalPowerShell `
        $CanonicalApp `
        $CanonicalRun `
        $RunId `
        ([string]$Checkpoint.dataRoot) `
        ([string]$Checkpoint.agentDirectory) `
        ([string]$Checkpoint.signingSid) `
        $pendingSummary `
        $TimeoutSeconds `
        $true `
        $Checkpoint
    [Console]::Out.WriteLine('acceptance_unattended_reboot_pass')
    Restart-Computer -Force -ErrorAction Stop
    exit 194
}

function Invoke-RebootResume {
    Assert-WindowsPreflight
    $canonicalRepo = Get-CanonicalExistingPath $RepoPath Container
    Assert-TrustedRootAcl $canonicalRepo
    Initialize-ContractSources $canonicalRepo
    $windowsSystemPublishers = [SimplySignAuto.Acceptance.Contracts.WindowsSystemPublisherMapPolicy]::Parse(
        $WindowsSystemPublisherSha256Map)
    Initialize-PostRebootTaskExpectation
    $canonicalRun = Get-CanonicalExistingPath $ArtifactRoot Container
    if ([System.IO.Path]::GetFileName($canonicalRun) -cne $RunId -or
        (Get-Content -LiteralPath (Join-Path $canonicalRun 'owner.txt') -Raw) -cne $RunId) {
        throw 'acceptance_owner_invalid'
    }
    $canonicalApp = Get-CanonicalExistingPath $AppHostPath Leaf
    $canonicalPowerShell = Get-CanonicalExistingPath $PowerShellPath Leaf
    $canonicalScript = Get-CanonicalExistingPath $PSCommandPath Leaf
    $canonicalSystemRoot = Get-CanonicalExistingPath $env:SystemRoot Container
    $canonicalProgramFiles = Get-CanonicalExistingPath $env:ProgramFiles Container
    $canonicalProgramFilesX86 = Get-CanonicalExistingPath ${env:ProgramFiles(x86)} Container
    $canonicalAcceptanceRoot = Get-CanonicalAcceptanceRoot $canonicalRepo
    $canonicalAppRoot = Get-CanonicalExistingPath ([System.IO.Path]::GetDirectoryName($canonicalApp)) Container
    $trustedRoots = @(
        $canonicalSystemRoot, $canonicalProgramFiles, $canonicalProgramFilesX86, $canonicalAcceptanceRoot,
        $canonicalRepo, $canonicalAppRoot)
    Add-TrustedExecutableGuard $canonicalPowerShell $trustedRoots PlatformPublisher $PowerShellPublisherSha256
    Add-TrustedExecutableGuard $canonicalApp $trustedRoots ManifestSha256 $AppHostSha256
    $canonicalTaskKill = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\taskkill.exe') Leaf
    Add-TrustedExecutableGuard `
        $canonicalTaskKill `
        $trustedRoots `
        PlatformPublisher `
        ($windowsSystemPublishers.ResolveExpectedPublisherSha256($canonicalTaskKill))

    $resumeTaskName = $ResumeTaskName
    $expectedTask = $BootResumeExpectedTask

    $rawDirectory = Get-CanonicalExistingPath (Join-Path $canonicalRun '.reboot') Container
    Assert-TrustedRootAcl $rawDirectory
    $checkpointPath = Get-CanonicalExistingPath (Join-Path $rawDirectory 'checkpoint.json') Leaf
    $checkpoint = ConvertFrom-StrictJson (Get-Content -LiteralPath $checkpointPath -Raw)
    if ($null -ne $checkpoint.PSObject.Properties['phase'] -and
        $checkpoint.phase -ceq 'fresh-install') {
        Assert-ExactProperties $checkpoint @(
            'schemaVersion', 'phase', 'runId', 'acceptanceStartedUtc', 'bootBeforeUtc',
            'administratorUser', 'administratorSid', 'signingUser', 'signingSid',
            'installInstanceHash', 'agentTaskSource', 'controllerStateFile', 'controllerStateSha256',
            'resumeScriptSha256', 'acceptanceContractsSha256', 'strictJsonSha256')
        if ($checkpoint.schemaVersion -ne 1 -or
            $checkpoint.runId -cne $RunId -or
            $checkpoint.controllerStateFile -cne 'controller-parameters.clixml' -or
            $checkpoint.controllerStateSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'acceptance_fresh_install_state_invalid'
        }
        $statePath = Get-CanonicalExistingPath `
            (Join-Path $rawDirectory ([string]$checkpoint.controllerStateFile)) `
            Leaf
        if ((Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            [string]$checkpoint.controllerStateSha256) {
            throw 'acceptance_fresh_install_state_invalid'
        }
        $resumeSource = Assert-ProtectedResumeSourceBundle `
            $canonicalRun `
            ([string]$checkpoint.resumeScriptSha256) `
            ([string]$checkpoint.acceptanceContractsSha256) `
            ([string]$checkpoint.strictJsonSha256)
        if (-not [string]::Equals(
                $resumeSource.Root, $canonicalRepo, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals(
                $resumeSource.ScriptPath, $canonicalScript, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'acceptance_fresh_install_state_invalid'
        }
        $bootBefore = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact(
                [string]$checkpoint.bootBeforeUtc,
                'yyyy-MM-ddTHH:mm:ssZ',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal',
                [ref]$bootBefore) -or
            (Get-CurrentBootUtc) -le $bootBefore) {
            throw 'acceptance_fresh_install_reboot_invalid'
        }
        Assert-BootResumeTaskExact $resumeTaskName $expectedTask
        Unregister-ScheduledTask -TaskName $resumeTaskName -Confirm:$false
        if ($null -ne (Get-ScheduledTask -TaskName $resumeTaskName -ErrorAction SilentlyContinue)) {
            throw 'acceptance_state_uncertain'
        }
        $script:UnattendedRebootTaskRegistered = $false
        $escapedState = $statePath.Replace("'", "''")
        $escapedScript = $canonicalScript.Replace("'", "''")
        $command = "`$p=Import-Clixml -LiteralPath '$escapedState'; & '$escapedScript' @p; exit `$LASTEXITCODE"
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $canonicalPowerShell
        $start.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
            $command.Replace('"', '""') + '"'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.EnvironmentVariables['SIMPLYSIGN_ACCEPTANCE_FRESH_RUN_ID'] = $RunId
        $start.EnvironmentVariables['SIMPLYSIGN_ACCEPTANCE_FRESH_STATE'] = $checkpointPath
        $start.EnvironmentVariables['SIMPLYSIGN_ACCEPTANCE_CONTRACT_ROOT'] = $canonicalRepo
        $start.EnvironmentVariables['SIMPLYSIGN_ACCEPTANCE_FRESH_HANDOFF'] = '1'
        $continuation = [Diagnostics.Process]::Start($start)
        if ($null -eq $continuation) { throw 'acceptance_process_start_failed' }
        try {
            if (-not $continuation.WaitForExit($TimeoutSeconds * 1000)) {
                Assert-TrustedExecutableUnchanged $canonicalTaskKill
                $killer = [Diagnostics.Process]::Start(
                    $canonicalTaskKill,
                    "/PID $($continuation.Id) /T /F")
                if ($null -ne $killer) {
                    $killer.WaitForExit(10000) | Out-Null
                    $killer.Dispose()
                }
                Assert-TrustedExecutableUnchanged $canonicalTaskKill
                $continuation.WaitForExit(10000) | Out-Null
                throw 'acceptance_fresh_install_resume_failed'
            }
            if ($continuation.ExitCode -ne 194) {
                throw 'acceptance_fresh_install_resume_failed'
            }
            $script:UnattendedRebootTaskRegistered = $null -ne (
                Get-ScheduledTask -TaskName $resumeTaskName -ErrorAction SilentlyContinue)
            if (-not $UnattendedRebootTaskRegistered) {
                throw 'acceptance_fresh_install_resume_failed'
            }
            Assert-BootResumeTaskExact $resumeTaskName $expectedTask
            $handoffToken = [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::Retrieve(
                $UnattendedRebootLsaKey)
            if ([string]::IsNullOrWhiteSpace($handoffToken)) {
                throw 'acceptance_fresh_install_resume_failed'
            }
            $handoffToken = $null
            $script:UnattendedRebootSecretStored = $true
            $script:UnattendedRebootCleanupArmed = $false
        } finally {
            $continuation.Dispose()
        }
        [Console]::Out.WriteLine('acceptance_fresh_matrix_reboot_started')
        Restart-Computer -Force -ErrorAction Stop
        exit 194
    }
    if ($null -ne $checkpoint.PSObject.Properties['phase'] -and
        $checkpoint.phase -ceq 'unattended') {
        Assert-BootResumeTaskExact $resumeTaskName $expectedTask
        Invoke-UnattendedRebootResume `
            $canonicalRepo `
            $canonicalRun `
            $canonicalApp `
            $canonicalPowerShell `
            $canonicalScript `
            $rawDirectory `
            $checkpoint `
            $resumeTaskName `
            $expectedTask
        return
    }
    if ($null -eq $checkpoint.PSObject.Properties['phase'] -or
        $checkpoint.phase -notin @('purge-hard-stop', 'purge-cleanup')) {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    # Both purge phases reuse the same protected checkpoint and exact SYSTEM boot task.
    $script:UnattendedRebootSecretStored = $false
    Assert-BootResumeTaskExact $resumeTaskName $expectedTask
    $pendingSummaryPath = Get-CanonicalExistingPath (Join-Path $rawDirectory 'summary.pending.json') Leaf
    $checkpointProperties = @(
        'schemaVersion', 'phase', 'runId', 'operationId', 'acceptanceStartedUtc', 'bootBeforeUtc',
        'stagingRoots', 'sourcePaths', 'stagedPaths', 'stagedTargetCountAtTermination',
        'cleanupTaskAbsentAtTermination', 'processTreeTerminated', 'profilePath',
        'signingUserName', 'signingSid',
        'installOwnerMarker', 'installInstanceHash', 'simplySignDesktopPath',
        'simplySignDesktopSha256', 'pkcs11Path', 'pkcs11Sha256', 'dotnetPath',
        'dotnetSha256', 'dotnetPublisherSha256', 'desktopRuntimes', 'aspNetCoreRuntimes',
        'checkpointSecretScanClean', 'prebootMatrixComplete')
    if ($checkpoint.phase -ceq 'purge-cleanup') {
        $checkpointProperties += @(
            'manifestReadbackExact', 'manifestOperationId', 'manifestSourcePaths',
            'manifestStagedPaths', 'rootUninstallResumed', 'cleanupTaskReadbackExact')
    }
    Assert-ExactProperties $checkpoint $checkpointProperties
    if ($checkpoint.schemaVersion -ne 1 -or
        $checkpoint.runId -cne $RunId -or
        $checkpoint.operationId -isnot [string] -or
        $checkpoint.operationId -notmatch '^[0-9a-f]{32}$' -or
        $checkpoint.stagingRoots -isnot [System.Array] -or
        @($checkpoint.stagingRoots).Count -ne 1 -or
        $checkpoint.sourcePaths -isnot [System.Array] -or
        @($checkpoint.sourcePaths).Count -ne 1 -or
        $checkpoint.stagedPaths -isnot [System.Array] -or
        @($checkpoint.stagedPaths).Count -ne 1 -or
        $checkpoint.stagedTargetCountAtTermination -isnot [int] -or
        $checkpoint.stagedTargetCountAtTermination -ne 1 -or
        $checkpoint.cleanupTaskAbsentAtTermination -ne $true -or
        $checkpoint.processTreeTerminated -ne $true -or
        $checkpoint.checkpointSecretScanClean -ne $true -or
        $checkpoint.desktopRuntimes -isnot [System.Array] -or
        @($checkpoint.desktopRuntimes).Count -lt 1 -or
        $checkpoint.aspNetCoreRuntimes -isnot [System.Array] -or
        @($checkpoint.aspNetCoreRuntimes).Count -lt 1 -or
        ($checkpoint.phase -ceq 'purge-cleanup' -and
            ($checkpoint.manifestReadbackExact -ne $true -or
                $checkpoint.manifestOperationId -isnot [string] -or
                $checkpoint.manifestSourcePaths -isnot [System.Array] -or
                @($checkpoint.manifestSourcePaths).Count -ne 1 -or
                $checkpoint.manifestStagedPaths -isnot [System.Array] -or
                @($checkpoint.manifestStagedPaths).Count -ne 1 -or
                $checkpoint.rootUninstallResumed -ne $true -or
                $checkpoint.cleanupTaskReadbackExact -ne $true)) -or
        $checkpoint.prebootMatrixComplete -ne $true) {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    $checkpointJson = Get-Content -LiteralPath $checkpointPath -Raw
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $checkpointJson,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }
    $acceptanceStarted = [DateTimeOffset]::MinValue
    $bootBefore = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$checkpoint.acceptanceStartedUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal',
            [ref]$acceptanceStarted) -or
        -not [DateTimeOffset]::TryParseExact(
            [string]$checkpoint.bootBeforeUtc,
            'yyyy-MM-ddTHH:mm:ssZ',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal',
            [ref]$bootBefore)) {
        throw 'acceptance_purge_boot_invalid'
    }
    $script:AcceptanceStartedUtc = $acceptanceStarted
    $bootAfter = Get-CurrentBootUtc
    if ($bootAfter -le $bootBefore) {
        throw 'acceptance_purge_boot_invalid'
    }
    $operationId = [string]$checkpoint.operationId
    $productionTaskName = "SimplySignAuto.Purge.$operationId"
    $manifestPath = Join-Path $env:ProgramData "SimplySignAuto.Purge.$operationId\manifest.json"
    if ($checkpoint.phase -ceq 'purge-hard-stop') {
        $operationRoot = Get-CanonicalExistingPath (
            [System.IO.Path]::GetDirectoryName($manifestPath)) Container
        $manifestReadback = Read-ExactPurgeHardStopManifest `
            $operationRoot `
            $canonicalApp `
            ([string]$checkpoint.installOwnerMarker) `
            ([string]$checkpoint.installInstanceHash) `
            ([string]$checkpoint.signingSid) `
            @($checkpoint.sourcePaths)
        $resumeUninstall = Invoke-BoundedProcessCapture `
            $canonicalApp `
            @('uninstall', '--purge-data', '--confirm', 'PURGE') `
            $TimeoutSeconds `
            $null `
            $null
        $expectedResumeOutput =
            'Interrupted product data isolation resumed; physical cleanup will complete after restart.' + "`n"
        if ($resumeUninstall.ExitCode -ne 0 -or
            -not [string]::IsNullOrWhiteSpace($resumeUninstall.Stderr) -or
            $resumeUninstall.Stdout.Replace("`r`n", "`n") -cne $expectedResumeOutput -or
            [SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
                $resumeUninstall.Stdout + $resumeUninstall.Stderr,
                [string]$script:TotpSecretForRedaction)) {
            throw 'acceptance_purge_hard_stop_invalid'
        }
        $manifestReadback = Read-ExactPurgeHardStopManifest `
            $operationRoot `
            $canonicalApp `
            ([string]$checkpoint.installOwnerMarker) `
            ([string]$checkpoint.installInstanceHash) `
            ([string]$checkpoint.signingSid) `
            @($checkpoint.sourcePaths)
        Assert-ProductionPurgeTaskExact `
            ([string]$manifestReadback.Manifest.cleanupTaskName) `
            $operationId `
            $canonicalApp `
            ([string]$manifestReadback.ManifestPath)
        Prepare-PurgeRebootStage `
            $checkpoint `
            $checkpointPath `
            $resumeTaskName `
            $expectedTask `
            $manifestReadback
        return
    }
    if ($checkpoint.phase -cne 'purge-cleanup') {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    $rootUninstallResumed = [bool]$checkpoint.rootUninstallResumed
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $productionTaskPresent = $null -ne (Get-ScheduledTask -TaskName $productionTaskName -ErrorAction SilentlyContinue)
        $manifestPresent = Test-Path -LiteralPath $manifestPath
        $stagingPresent = @($checkpoint.stagingRoots | Where-Object { Test-Path -LiteralPath ([string]$_) }).Count -ne 0
        if (-not $productionTaskPresent -and -not $manifestPresent -and -not $stagingPresent) { break }
        Start-Sleep -Milliseconds 500
    } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    $sourceRootsIsolated = @($checkpoint.sourcePaths | Where-Object {
            Test-Path -LiteralPath ([string]$_)
        }).Count -eq 0
    $stagingRootsRemoved = @($checkpoint.stagingRoots | Where-Object { Test-Path -LiteralPath ([string]$_) }).Count -eq 0
    $manifestRemoved = -not (Test-Path -LiteralPath $manifestPath)
    $cleanupTaskRemoved = $null -eq (Get-ScheduledTask -TaskName $productionTaskName -ErrorAction SilentlyContinue)
    $exactOwnedProductRemoved = $sourceRootsIsolated -and
        $null -eq (Get-Service -Name 'SimplySignAuto.Service' -ErrorAction SilentlyContinue) -and
        $null -eq (Get-ScheduledTask -TaskName 'SimplySignAuto.Agent' -ErrorAction SilentlyContinue)
    $exactOwnedUserRemoved = $null -eq (
        Get-LocalUser -Name ([string]$checkpoint.signingUserName) -ErrorAction SilentlyContinue)
    $exactOwnedProfileRemoved = -not (Test-Path -LiteralPath ([string]$checkpoint.profilePath)) -and
        -not (Test-Path -LiteralPath (
            "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($checkpoint.signingSid)"))
    $canonicalDotnet = Get-CanonicalExistingPath ([string]$checkpoint.dotnetPath) Leaf
    $canonicalSimplySign = Get-CanonicalExistingPath ([string]$checkpoint.simplySignDesktopPath) Leaf
    $canonicalPkcs11 = Get-CanonicalExistingPath ([string]$checkpoint.pkcs11Path) Leaf
    Add-TrustedExecutableGuard `
        $canonicalDotnet `
        $trustedRoots `
        PlatformPublisher `
        ([string]$checkpoint.dotnetPublisherSha256)
    $simplySignDesktopPreserved =
        (Get-FileHash -LiteralPath $canonicalSimplySign -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            [string]$checkpoint.simplySignDesktopSha256
    $pkcs11Preserved =
        (Get-FileHash -LiteralPath $canonicalPkcs11 -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            [string]$checkpoint.pkcs11Sha256
    $dotnetPreserved =
        (Get-FileHash -LiteralPath $canonicalDotnet -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            [string]$checkpoint.dotnetSha256
    $runtimeAfter = Get-DotnetRuntimePreservationEvidence $canonicalDotnet $TimeoutSeconds
    $desktopRuntimeAfter = [string]::Join("`n", @($runtimeAfter.Desktop))
    $desktopRuntimeBefore = [string]::Join("`n", @($checkpoint.desktopRuntimes))
    $aspNetCoreRuntimeAfter = [string]::Join("`n", @($runtimeAfter.AspNetCore))
    $aspNetCoreRuntimeBefore = [string]::Join("`n", @($checkpoint.aspNetCoreRuntimes))
    $desktopRuntimePreserved = $dotnetPreserved -and
        $desktopRuntimeAfter -ceq $desktopRuntimeBefore
    $aspNetCoreRuntimePreserved = $dotnetPreserved -and
        $aspNetCoreRuntimeAfter -ceq $aspNetCoreRuntimeBefore
    $cleanupFailure = Invoke-UnattendedRebootCleanup $null
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    $resumeTaskRemoved = $true
    $stagingVolumes = @($checkpoint.stagingRoots | ForEach-Object { [System.IO.Path]::GetPathRoot([string]$_) })
    [SimplySignAuto.Acceptance.Contracts.PurgeBootEvidencePolicy]::Validate(
        $operationId,
        $stagingVolumes,
        $bootBefore,
        $bootAfter,
        $sourceRootsIsolated,
        $manifestRemoved,
        $cleanupTaskRemoved,
        $stagingRootsRemoved,
        $resumeTaskRemoved)
    [SimplySignAuto.Acceptance.Contracts.PurgeHardStopEvidencePolicy]::Validate(
        $operationId,
        ([string]$checkpoint.manifestOperationId),
        @($checkpoint.sourcePaths),
        @($checkpoint.manifestSourcePaths),
        @($checkpoint.stagedPaths),
        @($checkpoint.manifestStagedPaths),
        ([int]$checkpoint.stagedTargetCountAtTermination),
        ([bool]$checkpoint.cleanupTaskAbsentAtTermination),
        ([bool]$checkpoint.processTreeTerminated),
        ([bool]$checkpoint.checkpointSecretScanClean),
        $rootUninstallResumed,
        $exactOwnedProductRemoved,
        $exactOwnedUserRemoved,
        $exactOwnedProfileRemoved,
        $simplySignDesktopPreserved,
        $pkcs11Preserved,
        $desktopRuntimePreserved,
        $aspNetCoreRuntimePreserved)
    [SimplySignAuto.Acceptance.Contracts.RemoteAcceptanceMatrixPolicy]::ValidateFailureSessionAndBootMatrix(
        $true, $true, $true, $true, $true, $true, $true, $true, $true, $true, $true)

    $pending = ConvertFrom-StrictJson (Get-Content -LiteralPath $pendingSummaryPath -Raw)
    if ($pending.schemaVersion -ne 2 -or $pending.runId -cne $RunId -or
        $pending.state -cne 'reboot_pending') {
        throw 'acceptance_purge_boot_invalid'
    }
    $pending.state = 'passed'
    $pending | Add-Member -NotePropertyName remoteMatrix -NotePropertyValue ([ordered]@{
        unauthorized401 = 'passed'
        corruptPdfNoResult = 'passed'
        autoRelogin = 'passed'
        sessionDisconnectZeroRecovery = 'passed'
        managedPurge = 'passed'
        rebootCleanupResume = 'passed'
        pssa = 'passed'
        timeSynchronization = 'passed'
        urlAcl = 'passed'
    })
    $finalSummary = $pending | ConvertTo-Json -Compress -Depth 5
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $finalSummary,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }
    $bootEvidence = [ordered]@{
        schemaVersion = 1
        runId = $RunId
        operationId = $operationId
        hardStop = 'after-first-staged-before-cleanup-task'
        stagedTargetCountAtTermination = [int]$checkpoint.stagedTargetCountAtTermination
        manifestReadbackExact = $true
        rootUninstallResumed = $true
        cleanupTaskReadbackExact = $true
        bootBeforeUtc = $bootBefore.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        bootAfterUtc = $bootAfter.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        stagingVolumeCount = $stagingVolumes.Count
        sourceRootsIsolated = $true
        manifestRemoved = $true
        cleanupTaskRemoved = $true
        stagingRootsRemoved = $true
        resumeTaskRemoved = $true
        exactOwnedProductRemoved = $true
        exactOwnedUserRemoved = $true
        exactOwnedProfileRemoved = $true
        simplySignDesktopPreserved = $true
        pkcs11Preserved = $true
        desktopRuntimePreserved = $true
        aspNetCoreRuntimePreserved = $true
    } | ConvertTo-Json -Compress
    New-CreateNewText (Join-Path $canonicalRun 'boot-cleanup.json') $bootEvidence
    Remove-Item -LiteralPath $checkpointPath -Force
    Remove-Item -LiteralPath $pendingSummaryPath -Force
    if (@(Get-ChildItem -LiteralPath $rawDirectory -Force).Count -ne 0) {
        throw 'acceptance_state_uncertain'
    }
    Remove-Item -LiteralPath $rawDirectory -Force
    New-CreateNewText (Join-Path $canonicalRun 'controller.stdout.txt') 'acceptance_pass'
    New-CreateNewText (Join-Path $canonicalRun 'controller.stderr.txt') ''
    New-SafeEventLogSummary `
        (Join-Path $canonicalRun 'event-log.json') `
        $RunId `
        $acceptanceStarted
    New-CreateNewText (Join-Path $canonicalRun 'summary.json') $finalSummary
    Remove-ProtectedResumeSourceBundle $canonicalRun
    Assert-AcceptanceArtifactLayout $canonicalRun $true ($pending.mode -ceq 'FreshInstall')
    $artifactCompletedUtc = [DateTime]::UtcNow
    foreach ($artifact in @(Get-ChildItem -LiteralPath $canonicalRun -File -Recurse)) {
        if ($artifact.LastWriteTimeUtc -lt $acceptanceStarted.UtcDateTime.AddSeconds(-2) -or
            $artifact.LastWriteTimeUtc -gt $artifactCompletedUtc.AddSeconds(2)) {
            throw 'acceptance_artifact_mtime_invalid'
        }
        if ($artifact.Extension -in '.json', '.trx', '.xml', '.txt', '.log') {
            $artifactText = Get-Content -LiteralPath $artifact.FullName -Raw
            if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
                    $artifactText,
                    [string]$script:TotpSecretForRedaction)) {
                throw 'acceptance_sensitive_artifact'
            }
        }
    }
    Close-TrustedExecutableGuards
}

function Prepare-UnattendedRebootStage {
    param(
        [string]$CanonicalRepo,
        [string]$CanonicalScript,
        [string]$CanonicalPowerShell,
        [string]$CanonicalApp,
        [string]$RunDirectory,
        [string]$ExpectedRunId,
        [string]$PendingSummaryJson,
        [System.Collections.IDictionary]$CheckpointData,
        [string]$BearerSecret,
        [int]$BoundSeconds
    )
    if ($Mode -cne 'FreshInstall' -or $KeepInstalledState) {
        throw 'acceptance_purge_reboot_requires_fresh_install'
    }
    $rawDirectory = Join-Path $RunDirectory '.reboot'
    Initialize-AdministratorsOnlyDirectory $rawDirectory
    $codeInput = Join-Path $rawDirectory 'unsigned-x64.exe'
    $pdfInput = Join-Path $rawDirectory 'input.pdf'
    [System.IO.File]::Copy([string]$CheckpointData.codeInputSource, $codeInput, $false)
    [System.IO.File]::Copy([string]$CheckpointData.pdfInputSource, $pdfInput, $false)
    $null = $CheckpointData.Remove('codeInputSource')
    $null = $CheckpointData.Remove('pdfInputSource')
    $CheckpointData['schemaVersion'] = 2
    $CheckpointData['phase'] = 'unattended'
    $CheckpointData['runId'] = $ExpectedRunId
    $CheckpointData['acceptanceStartedUtc'] = $AcceptanceStartedUtc.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $CheckpointData['bootBeforeUtc'] = (Get-CurrentBootUtc).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $CheckpointData['codeInput'] = $codeInput
    $CheckpointData['pdfInput'] = $pdfInput
    $CheckpointData['codeInputSha256'] = (Get-FileHash -LiteralPath $codeInput -Algorithm SHA256).Hash.ToLowerInvariant()
    $CheckpointData['pdfInputSha256'] = (Get-FileHash -LiteralPath $pdfInput -Algorithm SHA256).Hash.ToLowerInvariant()
    $checkpointJson = $CheckpointData | ConvertTo-Json -Compress -Depth 6
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $checkpointJson,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }
    $lsaKey = "SimplySignAuto/Acceptance/$ExpectedRunId/Api"
    $script:UnattendedRebootCleanupArmed = $true
    $script:UnattendedRebootLsaKey = $lsaKey
    $script:UnattendedRebootSecretStored = $false
    $resumeTaskName = "SimplySignAuto.Acceptance.Boot.$ExpectedRunId"
    $script:ResumeTaskName = $resumeTaskName
    try {
        [SimplySignAuto.Acceptance.Contracts.AcceptanceLsaSecret]::StoreNew($lsaKey, $BearerSecret)
        $script:UnattendedRebootSecretStored = $true
        New-CreateNewText (Join-Path $rawDirectory 'checkpoint.json') $checkpointJson
        New-CreateNewText (Join-Path $rawDirectory 'summary.pending.json') $PendingSummaryJson

        $resumeArguments = New-BootResumeArguments `
            $CanonicalScript `
            $CanonicalRepo `
            $RunDirectory `
            $CanonicalApp `
            $AppHostSha256 `
            $PowerShellPublisherSha256 `
            $WindowsSystemPublisherSha256Map `
            $ExpectedRunId `
            $BoundSeconds
        if (Get-ScheduledTask -TaskName $resumeTaskName -ErrorAction SilentlyContinue) {
            throw 'acceptance_boot_task_invalid'
        }
        $action = New-ScheduledTaskAction -Execute $CanonicalPowerShell -Argument $resumeArguments
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit ([TimeSpan]::FromSeconds($BoundSeconds)) `
            -AllowStartIfOnBatteries `
            -StartWhenAvailable
        $definition = New-ScheduledTask `
            -Action $action `
            -Principal $principal `
            -Trigger $trigger `
            -Settings $settings `
            -Description 'SimplySignAuto/AcceptanceBoot/v1'
        $definition.Source = 'SimplySignAuto/v1'
        $expectedTask = [SimplySignAuto.Acceptance.Contracts.BootResumeTaskSnapshot]::new(
            'S-1-5-18',
            'ServiceAccount',
            'Highest',
            (Get-Sha256Text $CanonicalPowerShell.ToUpperInvariant()),
            (Get-Sha256Text $resumeArguments),
            'AtStartup',
            'SimplySignAuto/v1',
            'SimplySignAuto/AcceptanceBoot/v1',
            $BoundSeconds,
            1)
        $script:BootResumeExpectedTask = $expectedTask
        Register-ScheduledTask -TaskName $resumeTaskName -InputObject $definition | Out-Null
        $script:UnattendedRebootTaskRegistered = $true
        Assert-BootResumeTaskExact $resumeTaskName $expectedTask
        $script:RebootStagePrepared = $true
    } catch {
        if (-not $UnattendedRebootTaskRegistered) {
            try {
                if ($null -ne (Get-ScheduledTask `
                        -TaskName $resumeTaskName `
                        -ErrorAction SilentlyContinue)) {
                    $script:UnattendedRebootTaskRegistered = $true
                }
            } catch {
                # Unknown post-registration state must take the exact-owner cleanup path.
                $script:UnattendedRebootTaskRegistered = $true
            }
        }
        $firstFailure = if ($_.Exception.Message -cmatch '^acceptance_[a-z0-9_]+$') {
            $_.Exception.Message
        } else {
            'acceptance_reboot_prepare_failed'
        }
        $resolvedFailure = Invoke-UnattendedRebootCleanup $firstFailure
        if ($FreshSetupResumed -and -not $UnattendedRebootTaskRegistered) {
            try { Remove-ProtectedResumeSourceBundle $runDirectory } catch {
                $resolvedFailure = 'acceptance_state_uncertain'
            }
        }
        throw $resolvedFailure
    }
}

function Read-ExactPurgeHardStopManifest {
    param(
        [string]$OperationRoot,
        [string]$CanonicalApp,
        [string]$InstallOwnerMarker,
        [string]$InstallInstanceHash,
        [string]$SigningSid,
        [string[]]$ExpectedSourcePaths
    )
    $operationRoot = Get-CanonicalExistingPath $OperationRoot Container
    Assert-TrustedRootAcl $operationRoot
    if ([System.IO.Path]::GetFileName($operationRoot) -cnotmatch
        '^SimplySignAuto\.Purge\.(?<id>[0-9a-f]{32})$') {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    $operationId = $Matches['id']
    $manifestPath = Get-CanonicalExistingPath (Join-Path $operationRoot 'manifest.json') Leaf
    $manifest = ConvertFrom-StrictJson (Get-Content -LiteralPath $manifestPath -Raw)
    Assert-ExactProperties $manifest @(
        'version', 'ownerMarker', 'operationId', 'cleanupTaskName', 'installOwnerMarker',
        'signingUserSid', 'installInstanceId', 'signingUserOwnership', 'executablePath',
        'executableSha256', 'stagingRoots', 'targets')
    if ($manifest.version -ne 1 -or
        $manifest.ownerMarker -cne 'SimplySignAuto/Purge/v1' -or
        $manifest.operationId -cne $operationId -or
        $manifest.cleanupTaskName -cne "SimplySignAuto.Purge.$operationId" -or
        $manifest.installOwnerMarker -cne $InstallOwnerMarker -or
        $manifest.signingUserSid -cne $SigningSid -or
        $manifest.installInstanceId -isnot [string] -or
        (Get-Sha256Text ([string]$manifest.installInstanceId)) -cne $InstallInstanceHash -or
        $manifest.signingUserOwnership -ne 1 -or
        $manifest.executablePath -ine $CanonicalApp -or
        $manifest.executableSha256 -cne
            (Get-FileHash -LiteralPath $CanonicalApp -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $manifest.stagingRoots -isnot [System.Array] -or @($manifest.stagingRoots).Count -ne 1 -or
        $manifest.targets -isnot [System.Array] -or @($manifest.targets).Count -ne 1 -or
        @($ExpectedSourcePaths).Count -ne 1) {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    $stagingRootValue = [string](@($manifest.stagingRoots)[0])
    $stagingRoot = [System.IO.Path]::GetFullPath($stagingRootValue)
    $sourceVolume = [System.IO.Path]::GetPathRoot([string]$ExpectedSourcePaths[0])
    if ($stagingRootValue -cne $stagingRoot -or
        [System.IO.Path]::GetDirectoryName($stagingRoot) -ine $sourceVolume -or
        [System.IO.Path]::GetFileName($stagingRoot) -cne
            ".SimplySignAuto.quarantine.$operationId.0") {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    $actualSources = [System.Collections.Generic.List[string]]::new()
    $actualStaged = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt 1; $index++) {
        $target = @($manifest.targets)[$index]
        Assert-ExactProperties $target @('sourcePath', 'stagedPath')
        $sourcePath = [System.IO.Path]::GetFullPath([string]$target.sourcePath)
        $stagedPath = [System.IO.Path]::GetFullPath([string]$target.stagedPath)
        if ($target.sourcePath -cne $sourcePath -or $target.stagedPath -cne $stagedPath -or
            $sourcePath -ine [string]$ExpectedSourcePaths[$index] -or
            [System.IO.Path]::GetDirectoryName($stagedPath) -ine $stagingRoot -or
            [System.IO.Path]::GetPathRoot($sourcePath) -ine [System.IO.Path]::GetPathRoot($stagedPath)) {
            throw 'acceptance_purge_hard_stop_invalid'
        }
        $actualSources.Add($sourcePath)
        $actualStaged.Add($stagedPath)
    }
    return [pscustomobject]@{
        OperationId = $operationId
        ManifestPath = $manifestPath
        Manifest = $manifest
        StagingRoot = $stagingRoot
        SourcePaths = @($actualSources | ForEach-Object { $_ })
        StagedPaths = @($actualStaged | ForEach-Object { $_ })
    }
}

function Invoke-HardStopUninstallAtFirstStagedMove {
    param(
        [string[]]$BeforeOperations,
        [string]$CanonicalApp,
        [string]$InstallOwnerMarker,
        [string]$InstallInstanceHash,
        [string]$SigningSid,
        [string[]]$ExpectedSourcePaths,
        [int]$BoundSeconds
    )
    Assert-TrustedExecutableUnchanged $CanonicalApp
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $CanonicalApp
    $start.Arguments = (@('uninstall', '--purge-data', '--confirm', 'PURGE') |
            ForEach-Object { ConvertTo-SafeArgument $_ }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = $null
    $stderr = $null
    $started = $false
    try {
        if (-not $process.Start()) { throw 'acceptance_process_start_failed' }
        $started = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            if ($process.HasExited) { throw 'acceptance_purge_hard_stop_invalid' }
            $newOperations = @(Get-ChildItem `
                    -LiteralPath $env:ProgramData `
                    -Directory `
                    -Force `
                    -Filter 'SimplySignAuto.Purge.*' |
                    Where-Object { $BeforeOperations -notcontains $_.Name })
            if ($newOperations.Count -gt 1) { throw 'acceptance_purge_hard_stop_invalid' }
            if ($newOperations.Count -eq 1 -and
                (Test-Path -LiteralPath (Join-Path $newOperations[0].FullName 'manifest.json'))) {
                $readback = Read-ExactPurgeHardStopManifest `
                    $newOperations[0].FullName `
                    $CanonicalApp `
                    $InstallOwnerMarker `
                    $InstallInstanceHash `
                    $SigningSid `
                    $ExpectedSourcePaths
                $manifest = $readback.Manifest
                if (Test-Path -LiteralPath $readback.StagingRoot) {
                    $stagingRootReadback = Get-CanonicalExistingPath $readback.StagingRoot Container
                    Assert-TrustedRootAcl $stagingRootReadback
                }
                $stagedTargetCount = 0
                for ($index = 0; $index -lt $readback.SourcePaths.Count; $index++) {
                    $sourcePresent = Test-Path -LiteralPath $readback.SourcePaths[$index]
                    $stagedPresent = Test-Path -LiteralPath $readback.StagedPaths[$index]
                    if ($sourcePresent -and $stagedPresent) {
                        throw 'acceptance_purge_hard_stop_invalid'
                    }
                    if (-not $sourcePresent -and $stagedPresent) { $stagedTargetCount++ }
                }
                if ($stagedTargetCount -lt 1) {
                    Start-Sleep -Milliseconds 10
                    continue
                }
                if ($null -ne (Get-ScheduledTask -TaskName $manifest.cleanupTaskName -ErrorAction SilentlyContinue)) {
                    throw 'acceptance_purge_hard_stop_invalid'
                }
                if (-not (Stop-ExactProcessTree $process)) {
                    throw 'acceptance_purge_hard_stop_invalid'
                }
                if ($null -ne (Get-ScheduledTask `
                        -TaskName $readback.Manifest.cleanupTaskName `
                        -ErrorAction SilentlyContinue)) {
                    throw 'acceptance_purge_hard_stop_invalid'
                }
                if (-not [Threading.Tasks.Task]::WaitAll(
                        [Threading.Tasks.Task[]]@($stdout, $stderr),
                        10000)) {
                    throw 'acceptance_process_cleanup_timeout'
                }
                $combined = [string]$stdout.Result + [string]$stderr.Result
                if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
                        $combined,
                        [string]$script:TotpSecretForRedaction)) {
                    throw 'acceptance_sensitive_artifact'
                }
                return [pscustomobject]@{
                    Readback = $readback
                    StagedTargetCount = $stagedTargetCount
                    ProcessTreeTerminated = $true
                    CleanupTaskAbsent = $true
                }
            }
            Start-Sleep -Milliseconds 10
        } while ($watch.Elapsed.TotalSeconds -lt $BoundSeconds)
        throw 'acceptance_purge_hard_stop_invalid'
    } finally {
        $terminationUncertain = $false
        if ($started -and -not $process.HasExited) {
            try { $null = Stop-ExactProcessTree $process } catch { $terminationUncertain = $true }
        }
        if ($null -ne $process) { $process.Dispose() }
        Assert-TrustedExecutableUnchanged $CanonicalApp
        if ($terminationUncertain) {
            throw 'acceptance_state_uncertain'
        }
    }
}

function Prepare-PurgeRebootStage {
    param(
        $Checkpoint,
        [string]$CheckpointPath,
        [string]$ResumeTaskName,
        $ExpectedTask,
        $ManifestReadback
    )
    if ($Checkpoint.phase -cne 'purge-hard-stop' -or
        $ManifestReadback.OperationId -cne $Checkpoint.operationId) {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    $expectedSources = [string]::Join("`n", @($Checkpoint.sourcePaths))
    $actualSources = [string]::Join("`n", @($ManifestReadback.SourcePaths))
    $expectedStaged = [string]::Join("`n", @($Checkpoint.stagedPaths))
    $actualStaged = [string]::Join("`n", @($ManifestReadback.StagedPaths))
    if ($actualSources -cne $expectedSources -or $actualStaged -cne $expectedStaged) {
        throw 'acceptance_purge_hard_stop_invalid'
    }
    Assert-BootResumeTaskExact $ResumeTaskName $ExpectedTask

    $Checkpoint.phase = 'purge-cleanup'
    $Checkpoint.bootBeforeUtc = (Get-CurrentBootUtc).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Checkpoint | Add-Member -NotePropertyName manifestReadbackExact -NotePropertyValue $true
    $Checkpoint | Add-Member `
        -NotePropertyName manifestOperationId `
        -NotePropertyValue ([string]$ManifestReadback.OperationId)
    $Checkpoint | Add-Member `
        -NotePropertyName manifestSourcePaths `
        -NotePropertyValue @($ManifestReadback.SourcePaths)
    $Checkpoint | Add-Member `
        -NotePropertyName manifestStagedPaths `
        -NotePropertyValue @($ManifestReadback.StagedPaths)
    $Checkpoint | Add-Member -NotePropertyName rootUninstallResumed -NotePropertyValue $true
    $Checkpoint | Add-Member -NotePropertyName cleanupTaskReadbackExact -NotePropertyValue $true
    $checkpointJson = $Checkpoint | ConvertTo-Json -Compress -Depth 6
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $checkpointJson,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }

    $nextCheckpointPath = Join-Path (
        [System.IO.Path]::GetDirectoryName($CheckpointPath)) 'checkpoint.next.json'
    New-CreateNewText $nextCheckpointPath $checkpointJson
    try {
        [System.IO.File]::Replace($nextCheckpointPath, $CheckpointPath, $null)
    } finally {
        if (Test-Path -LiteralPath $nextCheckpointPath) {
            Remove-Item -LiteralPath $nextCheckpointPath -Force
        }
    }
    $canonicalCheckpoint = Get-CanonicalExistingPath $CheckpointPath Leaf
    if ($canonicalCheckpoint -ine $CheckpointPath -or
        (Get-Content -LiteralPath $canonicalCheckpoint -Raw) -cne $checkpointJson) {
        throw 'acceptance_state_uncertain'
    }
    Assert-BootResumeTaskExact $ResumeTaskName $ExpectedTask
    [Console]::Out.WriteLine('acceptance_purge_cleanup_reboot_started')
    $script:UnattendedRebootCleanupArmed = $false
    try {
        Restart-Computer -Force -ErrorAction Stop
        exit 194
    } catch {
        $script:UnattendedRebootCleanupArmed = $true
        throw
    }
}

function Prepare-PurgeHardStopRebootStage {
    param(
        [string]$CanonicalRepo,
        [string]$CanonicalScript,
        [string]$CanonicalPowerShell,
        [string]$CanonicalApp,
        [string]$RunDirectory,
        [string]$ExpectedRunId,
        [string]$DataRoot,
        [string]$AgentDirectory,
        [string]$SigningSid,
        [string]$PendingSummaryJson,
        [int]$BoundSeconds,
        [bool]$FreshInstallPurgeAuthorized,
        $PreservationCheckpoint
    )
    if (-not $FreshInstallPurgeAuthorized) {
        throw 'acceptance_purge_reboot_requires_fresh_install'
    }
    $profilePath = [System.IO.Directory]::GetParent(
        [System.IO.Directory]::GetParent(
            [System.IO.Directory]::GetParent($AgentDirectory).FullName).FullName).FullName
    $sourceRoots = @($DataRoot)
    $sourceVolume = [System.IO.Path]::GetPathRoot($DataRoot)
    $beforeOperations = @(
        Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -Filter 'SimplySignAuto.Purge.*' |
            ForEach-Object { $_.Name })
    $bootBefore = Get-CurrentBootUtc
    $canonicalDotnet = Get-CanonicalExistingPath ([string]$PreservationCheckpoint.dotnetPath) Leaf
    $canonicalSimplySign = Get-CanonicalExistingPath (
        [string]$PreservationCheckpoint.simplySignDesktopPath) Leaf
    $canonicalPkcs11 = Get-CanonicalExistingPath (
        (Join-Path $env:SystemRoot 'System32\SimplySignPKCS.dll')) Leaf
    $dotnetSha256 = (Get-FileHash -LiteralPath $canonicalDotnet -Algorithm SHA256).Hash.ToLowerInvariant()
    $simplySignDesktopSha256 =
        (Get-FileHash -LiteralPath $canonicalSimplySign -Algorithm SHA256).Hash.ToLowerInvariant()
    $pkcs11Sha256 = (Get-FileHash -LiteralPath $canonicalPkcs11 -Algorithm SHA256).Hash.ToLowerInvariant()
    $runtimeBefore = Get-DotnetRuntimePreservationEvidence $canonicalDotnet $BoundSeconds
    $hardStop = Invoke-HardStopUninstallAtFirstStagedMove `
        $beforeOperations `
        $CanonicalApp `
        ([string]$PreservationCheckpoint.agentTaskSource) `
        ([string]$PreservationCheckpoint.installInstanceHash) `
        $SigningSid `
        $sourceRoots `
        $BoundSeconds
    $script:InstallMutationAttempted = $false
    $operationId = [string]$hardStop.Readback.OperationId
    $stagingRoots = @([string]$hardStop.Readback.StagingRoot)
    $stagingVolumes = @($stagingRoots | ForEach-Object { [System.IO.Path]::GetPathRoot($_) })
    if ($stagingVolumes.Count -ne 1 -or
        -not [string]::Equals(
            $stagingVolumes[0], $sourceVolume, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'acceptance_purge_hard_stop_invalid'
    }

    $rawDirectory = Join-Path $RunDirectory '.reboot'
    Initialize-AdministratorsOnlyDirectory $rawDirectory
    $checkpointData = [ordered]@{
        schemaVersion = 1
        phase = 'purge-hard-stop'
        runId = $ExpectedRunId
        operationId = $operationId
        acceptanceStartedUtc = $AcceptanceStartedUtc.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        bootBeforeUtc = $bootBefore.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        stagingRoots = $stagingRoots
        sourcePaths = @($hardStop.Readback.SourcePaths)
        stagedPaths = @($hardStop.Readback.StagedPaths)
        stagedTargetCountAtTermination = [int]$hardStop.StagedTargetCount
        cleanupTaskAbsentAtTermination = [bool]$hardStop.CleanupTaskAbsent
        processTreeTerminated = [bool]$hardStop.ProcessTreeTerminated
        profilePath = $profilePath
        signingUserName = 'SimplySignAgent'
        signingSid = $SigningSid
        installOwnerMarker = [string]$PreservationCheckpoint.agentTaskSource
        installInstanceHash = [string]$PreservationCheckpoint.installInstanceHash
        simplySignDesktopPath = $canonicalSimplySign
        simplySignDesktopSha256 = $simplySignDesktopSha256
        pkcs11Path = $canonicalPkcs11
        pkcs11Sha256 = $pkcs11Sha256
        dotnetPath = $canonicalDotnet
        dotnetSha256 = $dotnetSha256
        dotnetPublisherSha256 = [string]$PreservationCheckpoint.dotnetPublisherSha256
        desktopRuntimes = @($runtimeBefore.Desktop)
        aspNetCoreRuntimes = @($runtimeBefore.AspNetCore)
        checkpointSecretScanClean = $true
        prebootMatrixComplete = $true
    }
    $checkpointJson = $checkpointData | ConvertTo-Json -Compress -Depth 6
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $checkpointJson,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }
    New-CreateNewText (Join-Path $rawDirectory 'checkpoint.json') $checkpointJson
    New-CreateNewText (Join-Path $rawDirectory 'summary.pending.json') $PendingSummaryJson

    $resumeTaskName = "SimplySignAuto.Acceptance.Boot.$ExpectedRunId"
    $script:ResumeTaskName = $resumeTaskName
    $script:UnattendedRebootCleanupArmed = $true
    $script:UnattendedRebootSecretStored = $false
    $script:UnattendedRebootTaskRegistered = $true
    $registered = Register-ExactBootResumeTask `
        $CanonicalScript `
        $CanonicalRepo `
        $CanonicalPowerShell `
        $RunDirectory `
        $CanonicalApp `
        $AppHostSha256 `
        $PowerShellPublisherSha256 `
        $WindowsSystemPublisherSha256Map `
        $ExpectedRunId `
        $BoundSeconds
    $script:ResumeTaskName = $registered.Name
    $script:BootResumeExpectedTask = $registered.Expected
    $script:RebootStagePrepared = $true
}

if ($RunChild) {
    $childFailure = $null
    try { Invoke-ChildWork } catch {
        $childFailure = Get-StableErrorCode $_ 'acceptance_child_failed'
        Write-AcceptanceDiagnostic $_ $childFailure $script:DiagnosticStage $ArtifactRoot
    } finally {
        try { Close-TrustedExecutableGuards } catch {
            $childFailure = Get-StableErrorCode $_ 'acceptance_child_cleanup_failed'
            Write-AcceptanceDiagnostic $_ $childFailure 'child_cleanup' $ArtifactRoot
        }
    }
    if ($null -ne $childFailure) { Fail-Stable $childFailure 1 }
    exit 0
}

if ($ResumeAfterReboot) {
    $script:DiagnosticStage = 'reboot_resume'
    Initialize-PostRebootCleanupState $RunId
    $resumeFailure = $null
    try { Invoke-RebootResume } catch {
        $resumeFailure = Get-StableErrorCode $_ 'acceptance_reboot_resume_failed'
        Write-AcceptanceDiagnostic $_ $resumeFailure $script:DiagnosticStage $ArtifactRoot
    } finally {
        if ($UnattendedRebootCleanupArmed) {
            $firstFailure = if ($null -ne $resumeFailure) {
                $resumeFailure
            } else {
                'acceptance_reboot_resume_failed'
            }
            $resumeFailure = Invoke-UnattendedRebootCleanup $firstFailure
        }
        if ($ExecutableGuards.Count -ne 0) {
            try { Close-TrustedExecutableGuards } catch { $resumeFailure = 'acceptance_state_uncertain' }
        }
    }
    if ($null -ne $resumeFailure) { Fail-Stable $resumeFailure 1 }
    [Console]::Out.WriteLine('acceptance_pass')
    exit 0
}

try {
    $script:DiagnosticStage = 'controller_preflight'
    Assert-WindowsPreflight
    $canonicalRepo = Get-CanonicalExistingPath $RepoPath Container
    Assert-TrustedRootAcl $canonicalRepo
    $canonicalArtifactRoot = Get-CanonicalExistingPath $ArtifactRoot Container
    Assert-TrustedRootAcl $canonicalArtifactRoot
    $canonicalDotnet = Get-CanonicalExistingPath $DotnetPath Leaf
    $fixedAppPath = [System.IO.Path]::GetFullPath(
        (Join-Path $env:ProgramFiles 'SimplySignAuto\SimplySignAuto.exe'))
    $canonicalSetup = $null
    if ($Mode -ceq 'FreshInstall') {
        if ([string]::IsNullOrWhiteSpace($SetupPath) -or
            $SetupSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'acceptance_fresh_install_arguments_invalid'
        }
        $canonicalSetup = Get-CanonicalExistingPath $SetupPath Leaf
        $canonicalApp = [System.IO.Path]::GetFullPath($AppHostPath)
        if (-not [string]::Equals(
                $canonicalApp,
                $fixedAppPath,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            (Test-Path -LiteralPath $canonicalApp)) {
            throw 'acceptance_fresh_install_not_clean'
        }
    } else {
        if (-not [string]::IsNullOrWhiteSpace($SetupPath) -or
            -not [string]::IsNullOrWhiteSpace($SetupSha256)) {
            throw 'acceptance_arguments_invalid'
        }
        $canonicalApp = Get-CanonicalExistingPath $AppHostPath Leaf
    }
    $canonicalSignTool = Get-CanonicalExistingPath $SignToolPath Leaf
    $canonicalSimplySign = Get-CanonicalExistingPath $SimplySignDesktopPath Leaf
    $canonicalPdfHelper = Get-CanonicalExistingPath $PdfHelperPath Leaf
    $canonicalIndependentPdfValidator = Get-CanonicalExistingPath $IndependentPdfValidatorPath Leaf
    $certificatePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $canonicalPdfTrustRoots = @($PdfTrustRootFiles | ForEach-Object {
        $certificatePath = Get-CanonicalExistingPath $_ Leaf
        if ([System.IO.Path]::GetExtension($certificatePath) -inotmatch '^\.(cer|crt|pem)$' -or
            -not $certificatePaths.Add($certificatePath)) { throw 'acceptance_pdf_trust_invalid' }
        $certificatePath
    })
    $canonicalPdfIntermediates = @($PdfIntermediateCertificateFiles | ForEach-Object {
        $certificatePath = Get-CanonicalExistingPath $_ Leaf
        if ([System.IO.Path]::GetExtension($certificatePath) -inotmatch '^\.(cer|crt|pem)$' -or
            -not $certificatePaths.Add($certificatePath)) { throw 'acceptance_pdf_trust_invalid' }
        $certificatePath
    })
    $canonicalDocumentSignerCertificate = Get-CanonicalExistingPath $DocumentSignerCertificateFile Leaf
    $canonicalTimestampSignerCertificate = Get-CanonicalExistingPath $TimestampSignerCertificateFile Leaf
    foreach ($certificatePath in @($canonicalDocumentSignerCertificate, $canonicalTimestampSignerCertificate)) {
        if ([System.IO.Path]::GetExtension($certificatePath) -inotmatch '^\.(cer|crt|pem)$' -or
            -not $certificatePaths.Add($certificatePath)) {
            throw 'acceptance_pdf_trust_invalid'
        }
    }
    $canonicalOtp = Get-CanonicalExistingPath $OtpUriFile Leaf
    $canonicalPowerShell = Get-CanonicalExistingPath $PowerShellPath Leaf
    $canonicalScript = Get-CanonicalExistingPath $PSCommandPath Leaf
    $controlledContractRoot = [Environment]::GetEnvironmentVariable(
        'SIMPLYSIGN_ACCEPTANCE_CONTRACT_ROOT')
    $canonicalControlledContractRoot = $null
    if (-not [string]::IsNullOrWhiteSpace($controlledContractRoot)) {
        $canonicalControlledContractRoot = Get-CanonicalExistingPath $controlledContractRoot Container
    }
    $scriptSourceValid = Test-PathUnder $canonicalScript $canonicalRepo
    if ($null -ne $canonicalControlledContractRoot) {
        $scriptSourceValid = $scriptSourceValid -or (
            [string]::Equals(
                $canonicalScript,
                (Join-Path $canonicalControlledContractRoot 'acceptance-test.ps1'),
                [System.StringComparison]::OrdinalIgnoreCase))
    }
    if (-not $scriptSourceValid -or
        [System.IO.Path]::GetFileName($canonicalApp) -ine 'SimplySignAuto.exe' -or
        ($null -ne $canonicalSetup -and
            [System.IO.Path]::GetFileName($canonicalSetup) -cnotmatch
                '^SimplySignAutoSetup-.+-win-x64\.exe$') -or
        [System.IO.Path]::GetFileName($canonicalSignTool) -ine 'signtool.exe' -or
        [System.IO.Path]::GetFileName($canonicalSimplySign) -ine 'SimplySignDesktop.exe' -or
        [System.IO.Path]::GetFileName($canonicalPdfHelper) -ine 'SimplySignPdfSigner.exe' -or
        [System.IO.Path]::GetFileName($canonicalIndependentPdfValidator) -ine 'pyhanko.exe' -or
        [System.IO.Path]::GetFileName($canonicalDotnet) -ine 'dotnet.exe') { throw 'acceptance_executable_invalid' }
    $contractSourceRepo = $canonicalRepo
    if ($null -ne $canonicalControlledContractRoot) {
        $contractSourceRepo = $canonicalControlledContractRoot
        if (-not (Test-PathUnder $contractSourceRepo $canonicalArtifactRoot) -or
            [System.IO.Path]::GetFileName($contractSourceRepo) -cne '.resume') {
            throw 'acceptance_fresh_install_state_invalid'
        }
        Assert-TrustedRootAcl $contractSourceRepo
    }
    Initialize-ContractSources $contractSourceRepo
    $otpUriForRedaction = Read-SecretFile $canonicalOtp
    try {
        $script:TotpSecretForRedaction =
            [SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ExtractTotpSecret($otpUriForRedaction)
    } finally { $otpUriForRedaction = $null }
    $script:DiagnosticStage = 'controller_contracts_loaded'
    $windowsSystemPublishers =
        [SimplySignAuto.Acceptance.Contracts.WindowsSystemPublisherMapPolicy]::Parse(
            $WindowsSystemPublisherSha256Map)
    $canonicalSystemRoot = Get-CanonicalExistingPath $env:SystemRoot Container
    $canonicalProgramFiles = Get-CanonicalExistingPath $env:ProgramFiles Container
    $canonicalProgramFilesX86 = Get-CanonicalExistingPath ${env:ProgramFiles(x86)} Container
    $canonicalAcceptanceRoot = Get-CanonicalAcceptanceRoot $canonicalRepo
    $trustedRoots = @(
        $canonicalSystemRoot, $canonicalProgramFiles, $canonicalProgramFilesX86, $canonicalAcceptanceRoot,
        $canonicalRepo)
    $trustedFixtureRoots = @($trustedRoots + $canonicalArtifactRoot)
    $canonicalW32Time = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\w32tm.exe') Leaf
    $canonicalNetsh = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\netsh.exe') Leaf
    $canonicalSc = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\sc.exe') Leaf
    $canonicalTaskKill = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\taskkill.exe') Leaf
    $canonicalTsDiscon = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\tsdiscon.exe') Leaf
    $canonicalTsCon = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\tscon.exe') Leaf
    $canonicalCertUtil = Get-CanonicalExistingPath (Join-Path $canonicalSystemRoot 'System32\certutil.exe') Leaf
    Add-TrustedExecutableGuard $canonicalPowerShell $trustedRoots PlatformPublisher $PowerShellPublisherSha256
    Add-TrustedExecutableGuard $canonicalDotnet $trustedRoots PlatformPublisher $DotnetPublisherSha256
    Add-TrustedExecutableGuard $canonicalSignTool $trustedRoots PlatformPublisher $SignToolPublisherSha256
    Add-TrustedExecutableGuard $canonicalSimplySign $trustedRoots PlatformPublisher $SimplySignPublisherSha256
    if ($null -eq $canonicalSetup) {
        Add-TrustedExecutableGuard $canonicalApp $trustedRoots ManifestSha256 $AppHostSha256
    } else {
        Add-TrustedExecutableGuard $canonicalSetup $trustedFixtureRoots ManifestSha256 $SetupSha256
    }
    Add-TrustedExecutableGuard `
        $canonicalScript `
        $trustedRoots `
        ManifestSha256 `
        (Get-FileHash -LiteralPath $canonicalScript -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-TrustedExecutableGuard $canonicalPdfHelper $trustedRoots ManifestSha256 $PdfHelperSha256
    Add-TrustedExecutableGuard `
        $canonicalIndependentPdfValidator `
        $trustedRoots `
        ManifestSha256 `
        $IndependentPdfValidatorSha256
    foreach ($systemExecutable in @(
            $canonicalW32Time, $canonicalNetsh, $canonicalSc, $canonicalTaskKill,
            $canonicalTsDiscon, $canonicalTsCon, $canonicalCertUtil)) {
        Add-TrustedExecutableGuard `
            $systemExecutable `
            $trustedRoots `
            PlatformPublisher `
            ($windowsSystemPublishers.ResolveExpectedPublisherSha256($systemExecutable))
    }
    Assert-TimeSynchronization $canonicalW32Time
    $TimeSynchronized = $true
    Assert-PssaGate $canonicalRepo
    $PssaClean = $true
    $hasTokenFile = -not [string]::IsNullOrWhiteSpace($ApiTokenFile)
    $runMode = [SimplySignAuto.Acceptance.Contracts.AcceptanceModePolicy]::Validate($Mode, $hasTokenFile)
    if (-not $AllowMachineMutation) { throw 'acceptance_machine_mutation_not_allowed' }
    if (-not [SimplySignAuto.Acceptance.Contracts.AcceptanceInputPolicy]::IsCertificateSerialNumber(
            $CodeSignCertificateSerialNumber) -or
        -not [SimplySignAuto.Acceptance.Contracts.AcceptanceInputPolicy]::IsCertificateSerialNumber(
            $DocumentCertificateSerialNumber) -or
        -not [SimplySignAuto.Acceptance.Contracts.AcceptanceInputPolicy]::IsTimeout($TimeoutSeconds)) { throw 'acceptance_arguments_invalid' }
    if (@($PdfBox | Where-Object { [double]::IsNaN($_) -or [double]::IsInfinity($_) }).Count -ne 0 -or
        $PdfBox[0] -ge $PdfBox[2] -or $PdfBox[1] -ge $PdfBox[3]) {
        throw 'acceptance_arguments_invalid'
    }
    $productionPdfBox = @(200.0, 642.0, 548.0, 680.0)
    if ($PdfPage -ne 2) { throw 'acceptance_arguments_invalid' }
    for ($boxIndex = 0; $boxIndex -lt 4; $boxIndex++) {
        if ([Math]::Abs($PdfBox[$boxIndex] - $productionPdfBox[$boxIndex]) -gt 0.001) {
            throw 'acceptance_arguments_invalid'
        }
    }
    $safeBaseUrl = Assert-BaseUrl $BaseUrl
    $configuredTransport = ([Uri]$safeBaseUrl).Scheme
    if ($runMode -eq [SimplySignAuto.Acceptance.Contracts.AcceptanceRunMode]::FreshInstall) {
        $FreshSetupContinuation = Begin-FreshSetupContinuation $canonicalArtifactRoot $canonicalApp
        if ($null -eq $FreshSetupContinuation) {
            Invoke-FreshSetupStage `
                $canonicalRepo `
                $canonicalArtifactRoot `
                $canonicalScript `
                $canonicalPowerShell `
                $canonicalSetup `
                $canonicalApp `
                $canonicalProgramFiles `
                $safeBaseUrl `
                $PSBoundParameters
            throw 'acceptance_fresh_install_reboot_invalid'
        }
        $FreshSetupResumed = $true
        $InstallMutationAttempted = $true
        $FreshTokenCleaned = $true
        $ApiToken = [string]$FreshSetupContinuation.Token
    }
    Assert-UrlAclExact $canonicalNetsh $safeBaseUrl
    $UrlAclExact = $true
    Assert-PublicCertificateChain `
        $canonicalCertUtil `
        $canonicalDocumentSignerCertificate `
        $DocumentSignerSha256 `
        ''
    $DocumentCertificateChainValid = $true
    Assert-PublicCertificateChain `
        $canonicalCertUtil `
        $canonicalTimestampSignerCertificate `
        $TimestampSignerSha256 `
        $TimestampSignerSubjectSuffix
    $TimestampCertificateChainValid = $true
    $timestampCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $canonicalTimestampSignerCertificate)
    try { $ExpectedTimestampSignerSubject = $timestampCertificate.Subject }
    finally { $timestampCertificate.Dispose() }
    $account = [System.Security.Principal.NTAccount]::new($SigningUser)
    $signingSid = [System.Security.Principal.SecurityIdentifier]$account.Translate([System.Security.Principal.SecurityIdentifier])
    $principalHash = Get-Sha256Text $signingSid.Value
    Assert-SecretAcl $canonicalOtp $signingSid 'AnyRestricted'
    $sessionId = Get-UniqueActiveSession $signingSid
    if ($runMode -eq [SimplySignAuto.Acceptance.Contracts.AcceptanceRunMode]::FreshInstall) {
        if (-not $FreshSetupResumed -or
            -not [string]::IsNullOrWhiteSpace($AgentConfigurationPath) -or
            $OpenFirewall) {
            throw 'acceptance_fresh_install_arguments_invalid'
        }
    } else {
        $canonicalToken = Get-CanonicalExistingPath $ApiTokenFile Leaf
        Assert-SecretAcl $canonicalToken $signingSid 'AnyRestricted'
    }

    if ($FreshSetupResumed) {
        $runIdLocal = [string]$FreshSetupContinuation.Checkpoint.runId
        $runDirectory = $FreshSetupContinuation.RunDirectory
        Assert-ExactChildren $runDirectory @('.reboot', '.resume', 'owner.txt')
    } else {
        $runIdLocal = [guid]::NewGuid().ToString('N')
        $runDirectory = Join-Path $canonicalArtifactRoot $runIdLocal
        if (Test-Path -LiteralPath $runDirectory) { throw 'acceptance_artifact_collision' }
        [System.IO.Directory]::CreateDirectory($runDirectory) | Out-Null
        New-CreateNewText (Join-Path $runDirectory 'owner.txt') $runIdLocal
    }
    $interactiveDirectory = Join-Path $runDirectory 'interactive'
    [System.IO.Directory]::CreateDirectory($interactiveDirectory) | Out-Null
    New-CreateNewText (Join-Path $interactiveDirectory 'owner.txt') $runIdLocal
    $productionUiDirectory = Join-Path $interactiveDirectory 'production-ui'
    [System.IO.Directory]::CreateDirectory($productionUiDirectory) | Out-Null
    $FailureRunDirectory = $runDirectory
    $FailureRunId = $runIdLocal
    Set-RunDirectoryAcl $runDirectory $signingSid $false
    Set-RunDirectoryAcl $interactiveDirectory $signingSid $true
    Set-RunDirectoryAcl $productionUiDirectory $signingSid $true
    Assert-RunDirectoryAcl $runDirectory $signingSid $false
    Assert-RunDirectoryAcl $interactiveDirectory $signingSid $true
    Assert-RunDirectoryAcl $productionUiDirectory $signingSid $true

    $nativeFixtureSourceMode = [SimplySignAuto.Acceptance.Contracts.NativeFixtureSourcePolicy]::Plan(
        $MsiFixturePath,
        $CatFixturePath,
        $SysFixturePath,
        $DllFixturePath)
    [SimplySignAuto.Acceptance.Contracts.NativeFixtureSourcePolicy]::ValidateToolPublisherHashes(
        $nativeFixtureSourceMode,
        $MakeCatPublisherSha256,
        $CscPublisherSha256,
        $SystemDriverPublisherSha256)
    [SimplySignAuto.Acceptance.Contracts.NativeFixtureSourcePolicy]::ValidateFixtureHashes(
        $nativeFixtureSourceMode,
        $MsiFixtureSha256,
        $CatFixtureSha256,
        $SysFixtureSha256,
        $DllFixtureSha256)
    foreach ($requiredNative in @($PdfFixturePath, $ExistingSignedPePath)) {
        if ([string]::IsNullOrWhiteSpace($requiredNative)) { throw 'acceptance_native_fixture_pending' }
    }
    $canonicalPdfFixture = Get-CanonicalExistingPath $PdfFixturePath Leaf
    $canonicalExistingSignedPe = Get-CanonicalExistingPath $ExistingSignedPePath Leaf
    $canonicalMsiFixture = $null
    $canonicalCatFixture = $null
    $canonicalSysFixture = $null
    $canonicalDllFixture = $null
    if ($nativeFixtureSourceMode -eq [SimplySignAuto.Acceptance.Contracts.NativeFixtureSourceMode]::ExplicitOverride) {
        $canonicalMsiFixture = Get-CanonicalExistingPath $MsiFixturePath Leaf
        $canonicalCatFixture = Get-CanonicalExistingPath $CatFixturePath Leaf
        $canonicalSysFixture = Get-CanonicalExistingPath $SysFixturePath Leaf
        $canonicalDllFixture = Get-CanonicalExistingPath $DllFixturePath Leaf
        [SimplySignAuto.Acceptance.Contracts.RemoteAcceptanceMatrixPolicy]::ValidateNativeFixtureSlots(@(
            [System.IO.Path]::GetExtension($canonicalMsiFixture).ToLowerInvariant(),
            [System.IO.Path]::GetExtension($canonicalCatFixture).ToLowerInvariant(),
            [System.IO.Path]::GetExtension($canonicalSysFixture).ToLowerInvariant(),
            [System.IO.Path]::GetExtension($canonicalDllFixture).ToLowerInvariant()))
    }
    if ([System.IO.Path]::GetExtension($canonicalPdfFixture) -ine '.pdf' -or
        (Get-FileHash -LiteralPath $canonicalPdfFixture -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PdfFixtureSha256) {
        throw 'acceptance_pdf_fixture_invalid'
    }
    Add-TrustedExecutableGuard $canonicalPdfFixture $trustedRoots ManifestSha256 $PdfFixtureSha256
    if ([System.IO.Path]::GetExtension($canonicalExistingSignedPe) -ine '.exe' -or
        $ExistingSignerThumbprintSuffix -ceq $CodeSignThumbprintSuffix) {
        throw 'acceptance_native_fixture_invalid'
    }
    Add-TrustedExecutableGuard `
        $canonicalExistingSignedPe `
        $trustedFixtureRoots `
        ManifestSha256 `
        (Get-FileHash -LiteralPath $canonicalExistingSignedPe -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-AuthenticodeSequence `
        $canonicalExistingSignedPe `
        @($ExistingSignerThumbprintSuffix) `
        $canonicalSignTool `
        120 `
        $false

    if ($runMode -eq [SimplySignAuto.Acceptance.Contracts.AcceptanceRunMode]::ExistingInstall) {
        $ApiToken = Read-SecretFile $canonicalToken
    }

    $InstalledState = Assert-InstalledState `
        $canonicalApp `
        $ApiToken `
        $signingSid `
        ([bool]$OpenFirewall)
    if ($FreshSetupResumed) {
        Complete-FreshSetupContinuation $FreshSetupContinuation $InstalledState
        $FreshSetupContinuation.Token = $null
    }

    $fixtureScript = Get-CanonicalExistingPath (Join-Path $canonicalRepo 'scripts\install-test-fixtures.ps1') Leaf
    $FixtureScriptForCleanup = $fixtureScript
    $RunDirectoryForCleanup = $runDirectory
    $RunIdForCleanup = $runIdLocal
    $CanonicalRepoForCleanup = $canonicalRepo
    $CanonicalPowerShellForCleanup = $canonicalPowerShell
    $FixtureInvocationAttempted = $true
    $fixtureArguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $fixtureScript,
        '-RepoPath', $canonicalRepo,
        '-RunDirectory', $runDirectory,
        '-DotnetPath', $canonicalDotnet,
        '-DotnetPublisherSha256', $DotnetPublisherSha256,
        '-WindowsSystemPublisherSha256Map', $WindowsSystemPublisherSha256Map,
        '-RunId', $runIdLocal,
        '-TimeoutSeconds', [string][Math]::Min(600, $TimeoutSeconds))
    if ($nativeFixtureSourceMode -eq [SimplySignAuto.Acceptance.Contracts.NativeFixtureSourceMode]::AutoGenerated) {
        $fixtureArguments += @(
            '-GenerateNativeFixtures',
            '-MakeCatPublisherSha256', $MakeCatPublisherSha256,
            '-CscPublisherSha256', $CscPublisherSha256,
            '-SystemDriverPublisherSha256', $SystemDriverPublisherSha256)
        foreach ($toolOverride in @(
                [pscustomobject]@{ Name = 'MakeCatPath'; Value = $MakeCatPath }
                [pscustomobject]@{ Name = 'CscPath'; Value = $CscPath }
                [pscustomobject]@{ Name = 'SystemDriverPath'; Value = $SystemDriverPath })) {
            if (-not [string]::IsNullOrWhiteSpace([string]$toolOverride.Value)) {
                $fixtureArguments += @("-$($toolOverride.Name)", [string]$toolOverride.Value)
            }
        }
    }
    $fixtures = Invoke-BoundedProcessCapture `
        $canonicalPowerShell `
        $fixtureArguments `
        $TimeoutSeconds `
        $null
    if ($fixtures.ExitCode -ne 0 -or $fixtures.Stdout.Trim() -cne 'acceptance_fixtures_ready') { throw 'acceptance_fixture_failed' }
    $nativeExpectedHashes = [ordered]@{
        msi = $MsiFixtureSha256
        cat = $CatFixtureSha256
        sys = $SysFixtureSha256
        dll = $DllFixtureSha256
    }
    if ($nativeFixtureSourceMode -eq [SimplySignAuto.Acceptance.Contracts.NativeFixtureSourceMode]::AutoGenerated) {
        $canonicalMsiFixture = Get-CanonicalExistingPath (Join-Path $runDirectory 'fixtures\native-fixture.msi') Leaf
        $canonicalCatFixture = Get-CanonicalExistingPath (Join-Path $runDirectory 'fixtures\native-fixture.cat') Leaf
        $canonicalSysFixture = Get-CanonicalExistingPath (Join-Path $runDirectory 'fixtures\native-fixture.sys') Leaf
        $canonicalDllFixture = Get-CanonicalExistingPath (Join-Path $runDirectory 'fixtures\native-fixture.dll') Leaf
        $fixtureManifestPath = Get-CanonicalExistingPath `
            (Join-Path $runDirectory 'fixtures\fixture-manifest.json') `
            Leaf
        $fixtureManifest = ConvertFrom-StrictJson (Get-Content -LiteralPath $fixtureManifestPath -Raw)
        Assert-ExactProperties $fixtureManifest @(
            'schemaVersion', 'runId', 'pdfPageCount', 'pdfSecondPageCropBox',
            'visibleSignatureBox', 'entries', 'sentinelFileName', 'sentinelIdentity', 'sentinelSha256')
        if ($fixtureManifest.schemaVersion -isnot [int] -or $fixtureManifest.schemaVersion -ne 2 -or
            $fixtureManifest.runId -isnot [string] -or $fixtureManifest.runId -cne $runIdLocal -or
            $fixtureManifest.entries -isnot [System.Array] -or @($fixtureManifest.entries).Count -ne 15) {
            throw 'acceptance_fixture_manifest_invalid'
        }
        $expectedNativeNames = @(
            'native-fixture.msi', 'native-fixture.cat', 'native-fixture.sys', 'native-fixture.dll')
        foreach ($nativeName in $expectedNativeNames) {
            $matchingEntries = @($fixtureManifest.entries | Where-Object { $_.relativePath -ceq $nativeName })
            if ($matchingEntries.Count -ne 1) { throw 'acceptance_fixture_manifest_invalid' }
            $entry = $matchingEntries[0]
            Assert-ExactProperties $entry @('relativePath', 'kind', 'sha256', 'identity', 'linkCount', 'cleanup')
            $entryPath = Get-CanonicalExistingPath (Join-Path $runDirectory "fixtures\$nativeName") Leaf
            $entryIdentity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($entryPath, $false)
            if ($entry.kind -isnot [string] -or $entry.kind -cne 'ordinary' -or
                $entry.cleanup -isnot [bool] -or -not $entry.cleanup -or
                $entry.linkCount -isnot [int] -or $entry.linkCount -ne 1 -or
                $entry.identity -isnot [string] -or $entry.identity -cne $entryIdentity.Identity -or
                $entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '^[0-9A-F]{64}$' -or
                $entry.sha256 -cne (Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash) {
                throw 'acceptance_fixture_manifest_invalid'
            }
            $nativeExpectedHashes[[System.IO.Path]::GetExtension($nativeName).TrimStart('.')] =
                ([string]$entry.sha256).ToLowerInvariant()
        }
    }
    [SimplySignAuto.Acceptance.Contracts.RemoteAcceptanceMatrixPolicy]::ValidateNativeFixtureSlots(@(
        [System.IO.Path]::GetExtension($canonicalMsiFixture).ToLowerInvariant(),
        [System.IO.Path]::GetExtension($canonicalCatFixture).ToLowerInvariant(),
        [System.IO.Path]::GetExtension($canonicalSysFixture).ToLowerInvariant(),
        [System.IO.Path]::GetExtension($canonicalDllFixture).ToLowerInvariant()))
    $nativeFixtureBindings = @(
        [pscustomobject]@{ Path = $canonicalMsiFixture; Hash = $nativeExpectedHashes.msi }
        [pscustomobject]@{ Path = $canonicalCatFixture; Hash = $nativeExpectedHashes.cat }
        [pscustomobject]@{ Path = $canonicalSysFixture; Hash = $nativeExpectedHashes.sys }
        [pscustomobject]@{ Path = $canonicalDllFixture; Hash = $nativeExpectedHashes.dll })
    foreach ($nativeFixtureBinding in $nativeFixtureBindings) {
        if ((Get-FileHash -LiteralPath $nativeFixtureBinding.Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            [string]$nativeFixtureBinding.Hash) {
            throw 'acceptance_native_fixture_invalid'
        }
        Add-TrustedExecutableGuard `
            $nativeFixtureBinding.Path `
            $trustedFixtureRoots `
            ManifestSha256 `
            ([string]$nativeFixtureBinding.Hash)
    }
    $NativeFixturePathsForCleanup = @(
        $canonicalMsiFixture, $canonicalCatFixture, $canonicalSysFixture, $canonicalDllFixture)
    [System.IO.File]::Copy(
        (Get-CanonicalExistingPath (Join-Path $runDirectory 'fixtures\unsigned-x64.exe') Leaf),
        (Join-Path $productionUiDirectory 'input.exe'),
        $false)
    [System.IO.File]::Copy(
        $canonicalPdfFixture,
        (Join-Path $productionUiDirectory 'input.pdf'),
        $false)

    $aclFixture = Initialize-InteractiveAclFixture $interactiveDirectory $signingSid
    $InteractiveAclFixturePath = $aclFixture.Path
    $InteractiveAclSiblingPath = $aclFixture.SiblingPath
    $InteractiveAclFixtureIdentity = $aclFixture.DirectoryIdentity
    $InteractiveAclSiblingIdentity = $aclFixture.SiblingIdentity
    $InteractiveAclSiblingSha256 = $aclFixture.SiblingSha256

    Invoke-NativeTests $canonicalRepo $canonicalDotnet $runDirectory $TimeoutSeconds

    $TaskName = "SimplySignAuto Acceptance Interactive $runIdLocal"
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw 'acceptance_task_exists' }
    $description = "SimplySignAuto Acceptance owner=$runIdLocal"
    $escaped = @($canonicalScript, $canonicalRepo, $runDirectory, $SigningUser, $canonicalDotnet, $DotnetPublisherSha256, $canonicalApp, $AppHostSha256, $canonicalSimplySign, $SimplySignPublisherSha256, $PowerShellPublisherSha256, $WindowsSystemPublisherSha256Map, $runIdLocal, [string]$sessionId, $InstalledState.AgentTask.Source, [string]$TimeoutSeconds) | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $($escaped[0]) -RunChild -RepoPath $($escaped[1]) -ArtifactRoot $($escaped[2]) -SigningUser $($escaped[3]) -DotnetPath $($escaped[4]) -DotnetPublisherSha256 $($escaped[5]) -AppHostPath $($escaped[6]) -AppHostSha256 $($escaped[7]) -SimplySignDesktopPath $($escaped[8]) -SimplySignPublisherSha256 $($escaped[9]) -PowerShellPublisherSha256 $($escaped[10]) -WindowsSystemPublisherSha256Map $($escaped[11]) -RunId $($escaped[12]) -ExpectedSessionId $($escaped[13]) -ExpectedAgentTaskSource $($escaped[14]) -ChildTimeoutSeconds $($escaped[15])"
    $action = New-ScheduledTaskAction -Execute $canonicalPowerShell -Argument $arguments
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $signingSid.Value -LogonType Interactive -RunLevel Highest
    $limit = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit $limit -AllowStartIfOnBatteries
    $ExpectedTask = [SimplySignAuto.Acceptance.Contracts.AcceptanceTaskSnapshot]::new($description, $principalHash, 'InteractiveToken', 'Highest', (Get-Sha256Text $canonicalPowerShell.ToUpperInvariant()), (Get-Sha256Text $arguments), $TimeoutSeconds, 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $taskPrincipal -Settings $settings -Description $description | Out-Null
    $TaskCreated = $true
    $preStartTask = Get-AcceptanceTaskSnapshot $TaskName
    if (-not [SimplySignAuto.Acceptance.Contracts.TaskOwnershipPolicy]::IsExact($ExpectedTask, $preStartTask)) {
        throw 'acceptance_task_invalid'
    }
    Start-ScheduledTask -TaskName $TaskName
    $taskWatch = [Diagnostics.Stopwatch]::StartNew()
    $observedChild = $null
    do {
        Start-Sleep -Milliseconds 250
        $task = Get-ScheduledTask -TaskName $TaskName
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
        if ($null -eq $observedChild) {
            $observedChild = Get-ObservedChildProcess `
                $canonicalPowerShell `
                $arguments `
                $runIdLocal `
                $sessionId `
                $signingSid
        }
    } while (($task.State -eq 'Running' -or $task.State -eq 'Queued' -or $taskInfo.LastTaskResult -eq 267009 -or $taskInfo.LastTaskResult -eq 267011) -and $taskWatch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    if ($task.State -eq 'Running' -or $task.State -eq 'Queued') { Stop-ScheduledTask -TaskName $TaskName; throw 'acceptance_interactive_timeout' }
    if ($taskInfo.LastTaskResult -ne 0) { throw 'acceptance_interactive_failed' }
    if ($null -eq $observedChild) { throw 'acceptance_child_process_invalid' }
    $interactiveResult = ConvertFrom-StrictJson (Get-Content -LiteralPath (Join-Path $interactiveDirectory 'interactive-result.json') -Raw)
    Assert-ExactProperties $interactiveResult @(
        'schemaVersion', 'runId', 'sessionId', 'principalHash', 'childPid', 'otpConfigured',
        'productionUi', 'simplySignClosed', 'simplySignClosedAtUtc',
        'agentPidBeforeClose', 'agentPidAfterClose')
    $reportedChildPid = 0
    $closedAtUtc = [DateTimeOffset]::MinValue
    $reportedAgentPidBeforeClose = 0
    $reportedAgentPidAfterClose = 0
    if ([int]$interactiveResult.schemaVersion -ne 4 -or $interactiveResult.runId -cne $runIdLocal -or [int]$interactiveResult.sessionId -ne $sessionId -or $interactiveResult.principalHash -cne $principalHash -or -not [int]::TryParse([string]$interactiveResult.childPid, [ref]$reportedChildPid) -or $reportedChildPid -ne $observedChild.ProcessId -or $interactiveResult.otpConfigured -ne $false -or $interactiveResult.productionUi -ne $false -or $interactiveResult.simplySignClosed -ne $true -or
        -not [DateTimeOffset]::TryParseExact(
            [string]$interactiveResult.simplySignClosedAtUtc,
            'O',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$closedAtUtc) -or
        -not [int]::TryParse([string]$interactiveResult.agentPidBeforeClose, [ref]$reportedAgentPidBeforeClose) -or
        -not [int]::TryParse([string]$interactiveResult.agentPidAfterClose, [ref]$reportedAgentPidAfterClose) -or
        $reportedAgentPidBeforeClose -le 0 -or
        $reportedAgentPidAfterClose -ne $reportedAgentPidBeforeClose) {
        throw 'acceptance_interactive_result_invalid'
    }
    if (@(Get-CimInstance Win32_Process -Filter "ProcessId=$reportedChildPid").Count -ne 0) {
        throw 'acceptance_child_process_invalid'
    }
    $agentAfterChild = Get-ExactAgentProcess $canonicalApp $sessionId $signingSid
    if ([int]$agentAfterChild.ProcessId -ne $reportedAgentPidAfterClose) {
        throw 'acceptance_agent_process_invalid'
    }
    Remove-InteractiveAclFixture `
        $InteractiveAclFixturePath `
        $InteractiveAclSiblingPath `
        $InteractiveAclFixtureIdentity `
        $InteractiveAclSiblingIdentity `
        $InteractiveAclSiblingSha256
    $InteractiveAclFixtureCleaned = $true

    $uiRoot = Join-Path $runDirectory 'ui'
    [System.IO.Directory]::CreateDirectory($uiRoot) | Out-Null
    Set-RunDirectoryAcl $uiRoot $signingSid $true
    Assert-RunDirectoryAcl $runDirectory $signingSid $false
    Assert-RunDirectoryAcl $uiRoot $signingSid $true
    $uiScript = Get-CanonicalExistingPath (Join-Path $canonicalRepo 'scripts\ui-acceptance.ps1') Leaf
    $ui = Invoke-BoundedProcessCapture $canonicalPowerShell @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $uiScript, '-RepoPath', $canonicalRepo, '-ArtifactRoot', $uiRoot, '-SigningUser', $SigningUser, '-AdministratorUser', $AdministratorUser, '-DotnetPath', $canonicalDotnet, '-AppHostPath', $canonicalApp, '-ProductionExeInput', (Join-Path $productionUiDirectory 'input.exe'), '-ProductionPdfInput', (Join-Path $productionUiDirectory 'input.pdf'), '-ProductionOtpUriFile', $canonicalOtp, '-ProductionArtifactRoot', $productionUiDirectory, '-TimeoutSeconds', [string][Math]::Min(600, $TimeoutSeconds)) $TimeoutSeconds $null
    if ($ui.ExitCode -ne 0 -or $ui.Stdout.Trim() -cne 'ui_acceptance_pass') { throw 'acceptance_ui_failed' }
    Assert-RunDirectoryAcl $runDirectory $signingSid $false
    Assert-RunDirectoryAcl $uiRoot $signingSid $true
    [SimplySignAuto.Acceptance.Contracts.UiArtifactAclPolicy]::Validate($false, $true, $true, $true)

    $ProductionUiDirectory = Get-CanonicalExistingPath $productionUiDirectory Container
    $ProductionUiEvidence = ConvertFrom-StrictJson (
        Get-Content -LiteralPath (Join-Path $ProductionUiDirectory 'production-ui-result.json') -Raw)
    Assert-ExactProperties $ProductionUiEvidence @(
        'schemaVersion', 'exeInputBefore', 'exeInputAfter', 'exeResult',
        'pdfInputBefore', 'pdfInputAfter', 'pdfResult', 'productionComposition',
        'readinessVisible', 'hiddenSubmissionCompleted', 'trayRestoreObserved', 'secretScanClean')
    if ($ProductionUiEvidence.schemaVersion -ne 1) { throw 'acceptance_production_ui_invalid' }
    [SimplySignAuto.Acceptance.Contracts.RemoteAcceptanceMatrixPolicy]::ValidateProductionQuickSign(
        [string]$ProductionUiEvidence.exeInputBefore,
        [string]$ProductionUiEvidence.exeInputAfter,
        [string]$ProductionUiEvidence.exeResult,
        [string]$ProductionUiEvidence.pdfInputBefore,
        [string]$ProductionUiEvidence.pdfInputAfter,
        [string]$ProductionUiEvidence.pdfResult,
        [bool]$ProductionUiEvidence.productionComposition,
        [bool]$ProductionUiEvidence.readinessVisible,
        [bool]$ProductionUiEvidence.hiddenSubmissionCompleted,
        [bool]$ProductionUiEvidence.trayRestoreObserved,
        [bool]$ProductionUiEvidence.secretScanClean)
    $productionExe = Get-CanonicalExistingPath (Join-Path $ProductionUiDirectory 'quick-exe.signed.exe') Leaf
    $productionPdf = Get-CanonicalExistingPath (Join-Path $ProductionUiDirectory 'quick-pdf.signed.pdf') Leaf
    if ((Get-FileHash -LiteralPath (Join-Path $ProductionUiDirectory 'input.exe') -Algorithm SHA256).Hash -cne $ProductionUiEvidence.exeInputBefore -or
        (Get-FileHash -LiteralPath (Join-Path $ProductionUiDirectory 'input.pdf') -Algorithm SHA256).Hash -cne $ProductionUiEvidence.pdfInputBefore -or
        (Get-FileHash -LiteralPath $productionExe -Algorithm SHA256).Hash -cne $ProductionUiEvidence.exeResult -or
        (Get-FileHash -LiteralPath $productionPdf -Algorithm SHA256).Hash -cne $ProductionUiEvidence.pdfResult) {
        throw 'acceptance_production_ui_invalid'
    }
    Assert-AuthenticodeSequence $productionExe @($CodeSignThumbprintSuffix) $canonicalSignTool 120
    $otpPath = Get-CanonicalExistingPath (Join-Path $InstalledState.AgentDirectory 'otp.dat') Leaf
    Assert-SecretAcl $otpPath $signingSid 'SigningUser'

    $passedTests = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($trx in @(Get-ChildItem -LiteralPath $runDirectory -Filter '*.trx' -File -Recurse)) { Assert-TrxAndCollect $trx.FullName $passedTests }
    $missingNative = @($ExpectedWindowsNativeTests | Where-Object { -not $passedTests.Contains($_) })
    if ($ExpectedWindowsNativeTests.Count -ne 42 -or $missingNative.Count -ne 0) { throw 'acceptance_windows_native_incomplete' }

    $jobEvidenceRecords = New-Object System.Collections.Generic.List[object]
    $client = [SimplySignAuto.Acceptance.Contracts.PinnedHttpClientFactory]::Create($TlsCertificatePin, $ApiToken)
    try {
        $invalidBearer = $(if ($ApiToken[0] -cne 'A') {
            'A' + $ApiToken.Substring(1)
        } else {
            'B' + $ApiToken.Substring(1)
        })
        $unauthorizedClient = [SimplySignAuto.Acceptance.Contracts.PinnedHttpClientFactory]::Create(
            $TlsCertificatePin,
            $invalidBearer)
        try {
            $unauthorized = $unauthorizedClient.GetAsync("$safeBaseUrl/v1/health/ready").GetAwaiter().GetResult()
            try {
                if ([int]$unauthorized.StatusCode -ne 401) { throw 'acceptance_authentication_invalid' }
            } finally { $unauthorized.Dispose() }
        } finally {
            $invalidBearer = $null
            $unauthorizedClient.Dispose()
        }
        $unauthorizedObserved = $true

        function Get-ValidatedReadySnapshot {
            $readyWatch = [Diagnostics.Stopwatch]::StartNew()
            $readyResponse = $null
            try {
                do {
                    if ($null -ne $readyResponse) { $readyResponse.Dispose(); $readyResponse = $null }
                    $readyCts = [System.Threading.CancellationTokenSource]::new(
                        [TimeSpan]::FromSeconds([Math]::Min(30, $TimeoutSeconds)))
                    try {
                        $readyResponse = $client.GetAsync(
                            "$safeBaseUrl/v1/health/ready",
                            $readyCts.Token).GetAwaiter().GetResult()
                    } finally { $readyCts.Dispose() }
                    if ([int]$readyResponse.StatusCode -eq 200) { break }
                    Start-Sleep -Milliseconds 500
                } while ($readyWatch.Elapsed.TotalSeconds -lt [Math]::Min(300, $TimeoutSeconds))
                if ([int]$readyResponse.StatusCode -ne 200) { throw 'acceptance_agent_not_ready' }
                $readiness = ConvertFrom-StrictJson (
                    $readyResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult())
            } finally {
                if ($null -ne $readyResponse) { $readyResponse.Dispose() }
            }
            Assert-ExactProperties $readiness @(
                'service', 'agent', 'simplySign', 'session', 'capabilities', 'queue')
            Assert-ExactProperties $readiness.agent @('connected', 'sessionId', 'heartbeatAgeSeconds')
            Assert-ExactProperties $readiness.simplySign @('process', 'token')
            Assert-ExactProperties $readiness.session @('generation', 'transitions')
            Assert-ExactProperties $readiness.capabilities @('authenticode', 'pdf')
            Assert-ExactProperties $readiness.capabilities.authenticode @('ready', 'certificate', 'privateKey')
            Assert-ExactProperties $readiness.capabilities.pdf @('ready', 'certificate', 'privateKey')
            Assert-ExactProperties $readiness.queue @('queued', 'active')
            if ($readiness.service -cne 'ready' -or $readiness.agent.connected -ne $true -or
                $readiness.agent.sessionId -isnot [int] -or $readiness.agent.sessionId -ne $sessionId -or
                $readiness.agent.heartbeatAgeSeconds -isnot [int] -or
                    $readiness.agent.heartbeatAgeSeconds -lt 0 -or $readiness.agent.heartbeatAgeSeconds -gt 15 -or
                $readiness.simplySign.process -ne $true -or $readiness.simplySign.token -ne $true -or
                $readiness.session.generation -isnot [long] -or $readiness.session.generation -le 0 -or
                $readiness.session.transitions -isnot [System.Array] -or
                    @($readiness.session.transitions).Count -gt 64 -or
                $readiness.capabilities.authenticode.ready -ne $true -or
                $readiness.capabilities.authenticode.certificate -ne $true -or
                $readiness.capabilities.authenticode.privateKey -ne $true -or
                $readiness.capabilities.pdf.ready -ne $true -or
                $readiness.capabilities.pdf.certificate -ne $true -or
                $readiness.capabilities.pdf.privateKey -ne $true -or
                $readiness.queue.queued -isnot [int] -or $readiness.queue.queued -lt 0 -or
                $readiness.queue.active -isnot [int] -or $readiness.queue.active -lt 0) {
                throw 'acceptance_agent_not_ready'
            }
            return $readiness
        }

        # Real signing is deliberately reached only after native/UI/identity gates. The request helper below
        # never places the bearer value in arguments, environment variables, JSON, TRX, or files.
        function Invoke-CreateJob {
            param([string]$InputPath, [string]$ParametersJson, [string]$OutputPath)
            $boundary = 'ssa-' + [guid]::NewGuid().ToString('N')
            $multipart = [System.Net.Http.MultipartFormDataContent]::new($boundary)
            $fileStream = [System.IO.File]::Open($InputPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                $parametersContent = [System.Net.Http.StringContent]::new($ParametersJson, [System.Text.Encoding]::UTF8, 'application/json')
                $fileContent = [System.Net.Http.StreamContent]::new($fileStream)
                $multipart.Add($parametersContent, 'parameters')
                $multipart.Add($fileContent, 'file', [System.IO.Path]::GetFileName($InputPath))
                $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$safeBaseUrl/v1/jobs")
                $request.Headers.Add('Idempotency-Key', [guid]::NewGuid().ToString('N'))
                $request.Content = $multipart
                $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
                try { $response = $client.SendAsync($request, $cts.Token).GetAwaiter().GetResult() } finally { $cts.Dispose() }
                $responseJson = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ([int]$response.StatusCode -ne 202) { throw 'acceptance_job_submit_failed' }
                $created = ConvertFrom-StrictJson $responseJson
                Assert-ExactProperties $created @('jobId', 'state', 'statusUrl', 'resultUrl', 'expiresAt')
                $jobId = [guid]$created.jobId
                if ($created.jobId -isnot [string] -or $created.jobId -cne $jobId.ToString('D') -or
                    $created.state -isnot [string] -or $created.state -cnotmatch '^(queued|waiting_for_agent|signing|succeeded)$' -or
                    $created.statusUrl -cne "/v1/jobs/$($jobId.ToString('D'))" -or
                    $created.resultUrl -cne "/v1/jobs/$($jobId.ToString('D'))/result") {
                    throw 'acceptance_job_response_invalid'
                }
                $response.Dispose(); $request.Dispose()
            } finally { $multipart.Dispose(); $fileStream.Dispose() }

            $watch = [Diagnostics.Stopwatch]::StartNew()
            do {
                Start-Sleep -Seconds 1
                $poll = $client.GetAsync("$safeBaseUrl/v1/jobs/$($jobId.ToString('D'))").GetAwaiter().GetResult()
                $statusJson = $poll.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $status = ConvertFrom-StrictJson $statusJson
                Assert-ExactProperties $status @(
                    'jobId', 'state', 'originalName', 'inputSha256', 'resultSha256', 'errorCode',
                    'errorMessage', 'createdAt', 'startedAt', 'completedAt', 'expiresAt')
                $poll.Dispose()
                if ($status.jobId -isnot [string] -or $status.jobId -cne $jobId.ToString('D') -or
                    $status.state -isnot [string] -or
                        $status.state -cnotmatch '^(queued|waiting_for_agent|signing|succeeded|failed|expired)$' -or
                    $status.originalName -isnot [string] -or
                        $status.originalName -cne [System.IO.Path]::GetFileName($InputPath) -or
                    $status.inputSha256 -isnot [string] -or
                        $status.inputSha256 -cne (Get-FileHash -LiteralPath $InputPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
                    throw 'acceptance_job_response_invalid'
                }
                if ($status.state -ceq 'failed' -or $status.state -ceq 'expired') { throw 'acceptance_job_failed' }
            } while ($status.state -cne 'succeeded' -and $watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
            if ($status.state -cne 'succeeded') { throw 'acceptance_job_timeout' }
            $download = $client.GetAsync("$safeBaseUrl/v1/jobs/$($jobId.ToString('D'))/result").GetAwaiter().GetResult()
            if ([int]$download.StatusCode -ne 200) { throw 'acceptance_result_download_failed' }
            $bytes = $download.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            $download.Dispose()
            $stream = [System.IO.FileStream]::new($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose(); [System.Array]::Clear($bytes, 0, $bytes.Length) }
            if ($status.resultSha256 -isnot [string] -or
                $status.resultSha256 -cne (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
                $null -ne $status.errorCode -or $null -ne $status.errorMessage) {
                throw 'acceptance_job_response_invalid'
            }
            return $jobId
        }

        function Invoke-SubmitOnly {
            param(
                [string]$InputPath,
                [string]$ParametersJson,
                [string]$IdempotencyKey,
                [int]$ExpectedStatus = 202
            )
            if ($IdempotencyKey -notmatch '^[A-Za-z0-9._-]{1,128}$') {
                throw 'acceptance_job_submit_failed'
            }
            $multipart = [System.Net.Http.MultipartFormDataContent]::new('ssa-' + [guid]::NewGuid().ToString('N'))
            $fileStream = [System.IO.File]::Open($InputPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $request = $null
            $response = $null
            try {
                $parametersContent = [System.Net.Http.StringContent]::new($ParametersJson, [System.Text.Encoding]::UTF8, 'application/json')
                $fileContent = [System.Net.Http.StreamContent]::new($fileStream)
                $multipart.Add($parametersContent, 'parameters')
                $multipart.Add($fileContent, 'file', [System.IO.Path]::GetFileName($InputPath))
                $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$safeBaseUrl/v1/jobs")
                $request.Headers.Add('Idempotency-Key', $IdempotencyKey)
                $request.Content = $multipart
                $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
                try { $response = $client.SendAsync($request, $cts.Token).GetAwaiter().GetResult() }
                finally { $cts.Dispose() }
                $json = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ([int]$response.StatusCode -ne $ExpectedStatus) { throw 'acceptance_job_submit_failed' }
                $payload = ConvertFrom-StrictJson $json
                if ($ExpectedStatus -eq 409) {
                    Assert-ExactProperties $payload @('type', 'title', 'status', 'code', 'correlationId', 'jobId')
                    if ($payload.type -cne 'about:blank' -or $payload.status -isnot [int] -or
                        $payload.status -ne 409 -or $payload.code -cne 'idempotency_conflict' -or
                        $payload.correlationId -isnot [string] -or $payload.correlationId -notmatch '^[0-9a-f]{32}$' -or
                        $null -ne $payload.jobId) {
                        throw 'acceptance_idempotency_invalid'
                    }
                    return $null
                }
                Assert-ExactProperties $payload @('jobId', 'state', 'statusUrl', 'resultUrl', 'expiresAt')
                $jobId = [guid]$payload.jobId
                if ($payload.jobId -isnot [string] -or $payload.jobId -cne $jobId.ToString('D') -or
                    $payload.state -isnot [string] -or $payload.state -cnotmatch '^(queued|waiting_for_agent|signing|succeeded)$' -or
                    $payload.statusUrl -cne "/v1/jobs/$($jobId.ToString('D'))" -or
                    $payload.resultUrl -cne "/v1/jobs/$($jobId.ToString('D'))/result") {
                    throw 'acceptance_job_response_invalid'
                }
                return $payload
            } finally {
                if ($null -ne $response) { $response.Dispose() }
                if ($null -ne $request) { $request.Dispose() }
                $multipart.Dispose()
                $fileStream.Dispose()
            }
        }

        function Get-StrictJobStatus {
            param([guid]$JobId, [string]$InputPath)
            $response = $client.GetAsync("$safeBaseUrl/v1/jobs/$($JobId.ToString('D'))").GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -ne 200) { throw 'acceptance_job_response_invalid' }
                $status = ConvertFrom-StrictJson ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult())
            } finally { $response.Dispose() }
            Assert-ExactProperties $status @(
                'jobId', 'state', 'originalName', 'inputSha256', 'resultSha256', 'errorCode',
                'errorMessage', 'createdAt', 'startedAt', 'completedAt', 'expiresAt')
            if ($status.jobId -isnot [string] -or $status.jobId -cne $JobId.ToString('D') -or
                $status.state -isnot [string] -or
                    $status.state -cnotmatch '^(queued|waiting_for_agent|signing|verifying|succeeded|failed|expired)$' -or
                $status.originalName -isnot [string] -or
                    $status.originalName -cne [System.IO.Path]::GetFileName($InputPath) -or
                $status.inputSha256 -isnot [string] -or
                    $status.inputSha256 -cne (Get-FileHash -LiteralPath $InputPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
                throw 'acceptance_job_response_invalid'
            }
            return $status
        }

        function Save-JobResult {
            param([guid]$JobId, [string]$OutputPath, [string]$ExpectedSha256)
            $download = $client.GetAsync("$safeBaseUrl/v1/jobs/$($JobId.ToString('D'))/result").GetAwaiter().GetResult()
            try {
                if ([int]$download.StatusCode -ne 200) { throw 'acceptance_result_download_failed' }
                $bytes = $download.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            } finally { $download.Dispose() }
            try {
                $stream = [System.IO.FileStream]::new($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
            } finally { [System.Array]::Clear($bytes, 0, $bytes.Length) }
            if ((Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
                throw 'acceptance_job_response_invalid'
            }
        }

        function Invoke-SynchronousSign {
            param([string]$InputPath, [string]$ParametersJson, [string]$OutputPath)
            $multipart = [System.Net.Http.MultipartFormDataContent]::new('ssa-' + [guid]::NewGuid().ToString('N'))
            $fileStream = [System.IO.File]::Open($InputPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $request = $null
            $response = $null
            try {
                $multipart.Add([System.Net.Http.StringContent]::new($ParametersJson, [System.Text.Encoding]::UTF8, 'application/json'), 'parameters')
                $multipart.Add([System.Net.Http.StreamContent]::new($fileStream), 'file', [System.IO.Path]::GetFileName($InputPath))
                $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$safeBaseUrl/v1/sign?waitSeconds=120")
                $request.Headers.Add('Idempotency-Key', [guid]::NewGuid().ToString('N'))
                $request.Content = $multipart
                $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds([Math]::Min(180, $TimeoutSeconds)))
                try { $response = $client.SendAsync($request, $cts.Token).GetAwaiter().GetResult() }
                finally { $cts.Dispose() }
                if ([int]$response.StatusCode -ne 200 -or
                    $response.Content.Headers.ContentType.MediaType -cne 'application/pdf') {
                    throw 'acceptance_sync_sign_failed'
                }
                $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
                try {
                    $stream = [System.IO.FileStream]::new($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
                } finally { [System.Array]::Clear($bytes, 0, $bytes.Length) }
            } finally {
                if ($null -ne $response) { $response.Dispose() }
                if ($null -ne $request) { $request.Dispose() }
                $multipart.Dispose()
                $fileStream.Dispose()
            }
        }

        function Assert-CorruptPdfRejected {
            param([string]$InputPath, [string]$ParametersJson)

            $multipart = [System.Net.Http.MultipartFormDataContent]::new('ssa-' + [guid]::NewGuid().ToString('N'))
            $stream = [System.IO.File]::Open($InputPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $request = $null
            $response = $null
            try {
                $multipart.Add([System.Net.Http.StringContent]::new(
                        $ParametersJson,
                        [System.Text.Encoding]::UTF8,
                        'application/json'), 'parameters')
                $multipart.Add([System.Net.Http.StreamContent]::new($stream), 'file', 'corrupt.pdf')
                $request = [System.Net.Http.HttpRequestMessage]::new(
                    [System.Net.Http.HttpMethod]::Post,
                    "$safeBaseUrl/v1/jobs")
                $request.Headers.Add('Idempotency-Key', "$runIdLocal-corrupt")
                $request.Content = $multipart
                $response = $client.SendAsync($request).GetAwaiter().GetResult()
                if ([int]$response.StatusCode -ne 400) { throw 'acceptance_corrupt_pdf_invalid' }
                $problem = ConvertFrom-StrictJson ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult())
                Assert-ExactProperties $problem @('type', 'title', 'status', 'code', 'correlationId', 'jobId')
                if ($problem.type -cne 'about:blank' -or $problem.status -ne 400 -or
                    $problem.code -cne 'file_signature_mismatch' -or
                    $problem.correlationId -isnot [string] -or
                    $problem.correlationId -notmatch '^[A-Za-z0-9._:-]{1,128}$' -or
                    $null -ne $problem.jobId) {
                    throw 'acceptance_corrupt_pdf_invalid'
                }
            } finally {
                if ($null -ne $response) { $response.Dispose() }
                if ($null -ne $request) { $request.Dispose() }
                $multipart.Dispose()
                $stream.Dispose()
            }
        }

        function Assert-PdfSignedResult {
            param(
                [string]$InputPath,
                [string]$OutputPath,
                [string]$EvidenceName,
                [ValidateSet('CertumDocumentSignature', 'SimplySignAutoSignature')]
                [string]$FieldName = 'CertumDocumentSignature'
            )
            if ($EvidenceName -notmatch '^[a-z0-9-]{1,40}$') { throw 'acceptance_pdf_verify_failed' }
            $requestPath = Join-Path $interactiveDirectory "$EvidenceName.validate.request.json"
            try {
                $inputHash = (Get-FileHash -LiteralPath $InputPath -Algorithm SHA256).Hash.ToLowerInvariant()
                $requestJson = [ordered]@{
                    inputPath = $InputPath
                    outputPath = $OutputPath
                    fieldName = $FieldName
                    expectedInputSha256 = $inputHash
                    expectedSignerSha256 = $DocumentSignerSha256
                    page = $PdfPage
                    box = @($PdfBox)
                    trustRoots = $canonicalPdfTrustRoots
                    intermediateCertificates = $canonicalPdfIntermediates
                } | ConvertTo-Json -Compress
                New-CreateNewText $requestPath $requestJson
                $validated = Invoke-BoundedProcessCapture $canonicalPdfHelper @('validate', '--request', $requestPath) 60 $null
                if ($validated.ExitCode -ne 0) { throw 'acceptance_pdf_verify_failed' }
                $evidence = ConvertFrom-StrictJson $validated.Stdout
                Assert-ExactProperties $evidence @(
                    'ok', 'failureCode', 'signatureCount', 'wholeFile', 'timestampPresent',
                    'signerTrusted', 'timestampTrusted', 'timestampSignerSha256', 'timestampUtc',
                    'signerSuffix', 'certificateNotAfterUtc', 'page', 'box', 'fieldName', 'inputUnchanged')
                if ($evidence.ok -ne $true -or $null -ne $evidence.failureCode -or
                    $evidence.signatureCount -ne 1 -or $evidence.wholeFile -ne $true -or
                    $evidence.timestampPresent -ne $true -or $evidence.signerTrusted -ne $true -or
                    $evidence.timestampTrusted -ne $true -or
                    $evidence.signerSuffix -cne $DocumentSignerSha256.Substring(56, 8).ToUpperInvariant() -or
                    $evidence.page -ne $PdfPage -or @($evidence.box).Count -ne 4 -or
                    $evidence.fieldName -cne $FieldName -or $evidence.inputUnchanged -ne $true) {
                    throw 'acceptance_pdf_verify_failed'
                }
                for ($boxIndex = 0; $boxIndex -lt 4; $boxIndex++) {
                    if ([Math]::Abs([double]$evidence.box[$boxIndex] - $PdfBox[$boxIndex]) -gt 0.001) {
                        throw 'acceptance_pdf_verify_failed'
                    }
                }
                [SimplySignAuto.Acceptance.Contracts.SignatureTimestampPolicy]::Validate(
                    $evidence.timestampUtc,
                    $AcceptanceStartedUtc,
                    [DateTimeOffset]::UtcNow,
                    $evidence.timestampSignerSha256,
                    $TimestampSignerSha256,
                    $ExpectedTimestampSignerSubject,
                    $TimestampSignerSubjectSuffix)
                Invoke-IndependentPdfValidation `
                    $canonicalIndependentPdfValidator `
                    $OutputPath `
                    $canonicalPdfTrustRoots `
                    $canonicalPdfIntermediates `
                    $true `
                    $DocumentCertificateChainValid `
                    $TimestampCertificateChainValid
            } finally {
                if (Test-Path -LiteralPath $requestPath -PathType Leaf) { Remove-Item -LiteralPath $requestPath -Force }
            }
        }

        # Deterministic unattended relogin gate. No readiness poll, OTP input, UI action, RDP,
        # or Agent restart occurs between the child /close and these two configured-transport jobs.
        $closeCodeInput = Join-Path $runDirectory 'fixtures\unsigned-x64.exe'
        $closeCodeOutput = Join-Path $runDirectory 'close-recovery.signed.exe'
        $closeCodeInputHash = (Get-FileHash -LiteralPath $closeCodeInput -Algorithm SHA256).Hash
        $closeAuthJson = [ordered]@{
            kind = 'authenticode'
            certificateSerialNumber = $CodeSignCertificateSerialNumber
            digestAlgorithm = 'sha256'
            appendSignature = $false
        } | ConvertTo-Json -Compress
        $closeCodeTransport = $null
        $closeCodeVerified = $false
        $closeCodeJob = Invoke-CreateJob $closeCodeInput $closeAuthJson $closeCodeOutput
        $closeCodeTransport = $configuredTransport
        if ((Get-FileHash -LiteralPath $closeCodeInput -Algorithm SHA256).Hash -cne $closeCodeInputHash) {
            throw 'acceptance_input_modified'
        }
        Assert-AuthenticodeSequence $closeCodeOutput @($CodeSignThumbprintSuffix) $canonicalSignTool 120
        $closeCodeVerified = $true

        $closePdfInput = $canonicalPdfFixture
        $closePdfOutput = Join-Path $runDirectory 'close-recovery.signed.pdf'
        $closePdfInputHash = (Get-FileHash -LiteralPath $closePdfInput -Algorithm SHA256).Hash
        $closePdfJson = [ordered]@{
            kind = 'pdf'
            certificateSerialNumber = $DocumentCertificateSerialNumber
            digestAlgorithm = 'sha256'
            page = $PdfPage
            box = @($PdfBox)
            fieldName = 'CertumDocumentSignature'
            reason = 'Acceptance'
            location = 'CN'
        } | ConvertTo-Json -Compress
        $closePdfTransport = $null
        $closePdfVerified = $false
        $closePdfJob = Invoke-CreateJob $closePdfInput $closePdfJson $closePdfOutput
        $closePdfTransport = $configuredTransport
        if ((Get-FileHash -LiteralPath $closePdfInput -Algorithm SHA256).Hash -cne $closePdfInputHash) {
            throw 'acceptance_input_modified'
        }
        Assert-PdfSignedResult $closePdfInput $closePdfOutput 'close-recovery'
        $closePdfVerified = $true

        $transitionWatch = [Diagnostics.Stopwatch]::StartNew()
        $closeReadiness = $null
        $postCloseLoginningObserved = $false
        do {
            $closeReadiness = Get-ValidatedReadySnapshot
            foreach ($candidateTransition in @($closeReadiness.session.transitions)) {
                $candidateTime = [DateTimeOffset]::MinValue
                if ($candidateTransition.state -ceq 'LOGINNING' -and
                    [DateTimeOffset]::TryParseExact(
                        [string]$candidateTransition.transitionedAtUtc,
                        'O',
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::AssumeUniversal -bor
                            [Globalization.DateTimeStyles]::AdjustToUniversal,
                        [ref]$candidateTime) -and
                    $candidateTime -ge $closedAtUtc) {
                    $postCloseLoginningObserved = $true
                    break
                }
            }
            if (-not $postCloseLoginningObserved) { Start-Sleep -Milliseconds 500 }
        } while (-not $postCloseLoginningObserved -and
            $transitionWatch.Elapsed.TotalSeconds -lt [Math]::Min(300, $TimeoutSeconds))
        if (-not $postCloseLoginningObserved) { throw 'acceptance_unattended_relogin_invalid' }
        $reloginTransitions = New-Object `
            'System.Collections.Generic.List[SimplySignAuto.Acceptance.Contracts.ReloginTransitionSnapshot]'
        foreach ($transition in @($closeReadiness.session.transitions)) {
            Assert-ExactProperties $transition @(
                'sequence', 'state', 'sessionGeneration',
                'transitionedAtUtc', 'attempt')
            $transitionTime = [DateTimeOffset]::MinValue
            if ($transition.sequence -isnot [long] -or $transition.sequence -le 0 -or
                $transition.state -isnot [string] -or
                $transition.sessionGeneration -isnot [long] -or
                $transition.attempt -isnot [int] -or
                -not [DateTimeOffset]::TryParseExact(
                    [string]$transition.transitionedAtUtc,
                    'O',
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal -bor
                        [Globalization.DateTimeStyles]::AdjustToUniversal,
                    [ref]$transitionTime)) {
                throw 'acceptance_unattended_relogin_invalid'
            }
            $reloginTransitions.Add(
                [SimplySignAuto.Acceptance.Contracts.ReloginTransitionSnapshot]::new(
                    [long]$transition.sequence,
                    [string]$transition.state,
                    [long]$transition.sessionGeneration,
                    $transitionTime,
                    [int]$transition.attempt))
        }
        $agentBeforeCrash = Get-ExactAgentProcess $canonicalApp $sessionId $signingSid
        [SimplySignAuto.Acceptance.Contracts.UnattendedReloginEvidencePolicy]::Validate(
            $reportedAgentPidBeforeClose,
            [int]$agentBeforeCrash.ProcessId,
            $true,
            $closedAtUtc,
            [long]$closeReadiness.session.generation,
            $reloginTransitions,
            $configuredTransport,
            $closeCodeTransport,
            $closePdfTransport,
            $closeCodeVerified,
            $closePdfVerified)
        $AutoReloginAfterCloseObserved = $true
        $jobEvidenceRecords.Add([ordered]@{
                name = 'authenticode-close-recovery'
                channel = 'async'
                jobId = $closeCodeJob.ToString('D')
                inputSha256 = $closeCodeInputHash.ToLowerInvariant()
                resultSha256 = (Get-FileHash -LiteralPath $closeCodeOutput -Algorithm SHA256).Hash.ToLowerInvariant()
                verifier = 'signtool_wintrust_sequence'
                signerSequence = @($CodeSignThumbprintSuffix)
                timestamp = 'present'
            })
        $jobEvidenceRecords.Add([ordered]@{
                name = 'pdf-close-recovery'
                channel = 'async'
                jobId = $closePdfJob.ToString('D')
                inputSha256 = $closePdfInputHash.ToLowerInvariant()
                resultSha256 = (Get-FileHash -LiteralPath $closePdfOutput -Algorithm SHA256).Hash.ToLowerInvariant()
                verifier = 'project_helper_plus_independent_pyhanko_and_certutil'
                signerSequence = @($DocumentSignerSha256.Substring(56, 8).ToUpperInvariant())
                timestamp = 'tsa-identity-and-window-verified'
            })

        # Only after the /close recovery pair and its state evidence pass do we force-kill Agent.
        Invoke-AgentCrashRecoveryGate $canonicalApp $sessionId $signingSid $InstalledState.AgentTask
        $null = Get-ValidatedReadySnapshot

        $productionPdfInput = Join-Path $ProductionUiDirectory 'input.pdf'
        $productionPdfOutput = Join-Path $ProductionUiDirectory 'quick-pdf.signed.pdf'
        Assert-PdfSignedResult `
            $productionPdfInput `
            $productionPdfOutput `
            'production-quick-sign' `
            'SimplySignAutoSignature'
        $productionPdfSignerSuffix = $DocumentSignerSha256.Substring(56, 8).ToUpperInvariant()
        $jobEvidenceRecords.Add([ordered]@{
                name = 'authenticode-quick-sign'
                channel = 'quick-sign'
                jobId = $null
                inputSha256 = $ProductionUiEvidence.exeInputBefore.ToLowerInvariant()
                resultSha256 = $ProductionUiEvidence.exeResult.ToLowerInvariant()
                verifier = 'production_uia_signtool_wintrust_sequence'
                signerSequence = @($CodeSignThumbprintSuffix)
                timestamp = 'present'
            })
        $jobEvidenceRecords.Add([ordered]@{
                name = 'pdf-quick-sign'
                channel = 'quick-sign'
                jobId = $null
                inputSha256 = $ProductionUiEvidence.pdfInputBefore.ToLowerInvariant()
                resultSha256 = $ProductionUiEvidence.pdfResult.ToLowerInvariant()
                verifier = 'production_uia_project_helper_plus_independent_pyhanko_and_certutil'
                signerSequence = @($productionPdfSignerSuffix)
                timestamp = 'tsa-identity-and-window-verified'
            })

        $unsigned = Join-Path $runDirectory 'fixtures\unsigned-x64.exe'
        $unsignedHash = (Get-FileHash -LiteralPath $unsigned -Algorithm SHA256).Hash
        $signedExe = Join-Path $runDirectory 'authenticode.signed.exe'
        $authJson = [ordered]@{ kind = 'authenticode'; certificateSerialNumber = $CodeSignCertificateSerialNumber; digestAlgorithm = 'sha256'; appendSignature = $false } | ConvertTo-Json -Compress
        $authJob = Invoke-CreateJob $unsigned $authJson $signedExe
        if ((Get-FileHash -LiteralPath $unsigned -Algorithm SHA256).Hash -cne $unsignedHash) { throw 'acceptance_input_modified' }
        Assert-AuthenticodeSequence $signedExe @($CodeSignThumbprintSuffix) $canonicalSignTool 120
        $jobEvidenceRecords.Add([ordered]@{
                name = 'authenticode-base'
                channel = 'async'
                jobId = $authJob.ToString('D')
                inputSha256 = $unsignedHash.ToLowerInvariant()
                resultSha256 = (Get-FileHash -LiteralPath $signedExe -Algorithm SHA256).Hash.ToLowerInvariant()
                verifier = 'signtool_wintrust_sequence'
                signerSequence = @($CodeSignThumbprintSuffix)
                timestamp = 'present'
            })

        $appendJson = [ordered]@{ kind = 'authenticode'; certificateSerialNumber = $CodeSignCertificateSerialNumber; digestAlgorithm = 'sha256'; appendSignature = $true } | ConvertTo-Json -Compress
        $existingInputHash = (Get-FileHash -LiteralPath $canonicalExistingSignedPe -Algorithm SHA256).Hash
        $appendDifferentPath = Join-Path $runDirectory 'authenticode.append-different.exe'
        $appendDifferentJob = Invoke-CreateJob $canonicalExistingSignedPe $appendJson $appendDifferentPath
        if ((Get-FileHash -LiteralPath $canonicalExistingSignedPe -Algorithm SHA256).Hash -cne $existingInputHash) {
            throw 'acceptance_input_modified'
        }
        Assert-AuthenticodeSequence `
            $appendDifferentPath `
            @($ExistingSignerThumbprintSuffix, $CodeSignThumbprintSuffix) `
            $canonicalSignTool `
            120
        $jobEvidenceRecords.Add([ordered]@{
                name = 'authenticode-append-different'
                channel = 'async'
                jobId = $appendDifferentJob.ToString('D')
                inputSha256 = $existingInputHash.ToLowerInvariant()
                resultSha256 = (Get-FileHash -LiteralPath $appendDifferentPath -Algorithm SHA256).Hash.ToLowerInvariant()
                verifier = 'signtool_wintrust_sequence'
                signerSequence = @($ExistingSignerThumbprintSuffix, $CodeSignThumbprintSuffix)
                timestamp = 'present'
            })

        $sameInputHash = (Get-FileHash -LiteralPath $signedExe -Algorithm SHA256).Hash
        $appendSamePath = Join-Path $runDirectory 'authenticode.append-same.exe'
        $appendSameJob = Invoke-CreateJob $signedExe $appendJson $appendSamePath
        if ((Get-FileHash -LiteralPath $signedExe -Algorithm SHA256).Hash -cne $sameInputHash) {
            throw 'acceptance_input_modified'
        }
        Assert-AuthenticodeSequence `
            $appendSamePath `
            @($CodeSignThumbprintSuffix, $CodeSignThumbprintSuffix) `
            $canonicalSignTool `
            120
        $jobEvidenceRecords.Add([ordered]@{
                name = 'authenticode-append-same'
                channel = 'async'
                jobId = $appendSameJob.ToString('D')
                inputSha256 = $sameInputHash.ToLowerInvariant()
                resultSha256 = (Get-FileHash -LiteralPath $appendSamePath -Algorithm SHA256).Hash.ToLowerInvariant()
                verifier = 'signtool_wintrust_sequence'
                signerSequence = @($CodeSignThumbprintSuffix, $CodeSignThumbprintSuffix)
                timestamp = 'present'
            })

        $nativeFixtures = [ordered]@{
            msi = $canonicalMsiFixture
            cat = $canonicalCatFixture
            sys = $canonicalSysFixture
            dll = $canonicalDllFixture
        }
        $nativeJobIds = @{}
        foreach ($nativeFixture in $nativeFixtures.GetEnumerator()) {
            $nativeInputHash = (Get-FileHash -LiteralPath $nativeFixture.Value -Algorithm SHA256).Hash
            $nativeOutput = Join-Path $runDirectory "native-signed.$($nativeFixture.Key)"
            $nativeJobId = Invoke-CreateJob $nativeFixture.Value $authJson $nativeOutput
            if ((Get-FileHash -LiteralPath $nativeFixture.Value -Algorithm SHA256).Hash -cne $nativeInputHash) {
                throw 'acceptance_input_modified'
            }
            Assert-AuthenticodeSequence $nativeOutput @($CodeSignThumbprintSuffix) $canonicalSignTool 120
            $nativeJobIds[$nativeFixture.Key] = $nativeJobId
            $jobEvidenceRecords.Add([ordered]@{
                    name = "authenticode-native-$($nativeFixture.Key)"
                    channel = 'async'
                    jobId = $nativeJobId.ToString('D')
                    inputSha256 = $nativeInputHash.ToLowerInvariant()
                    resultSha256 = (Get-FileHash -LiteralPath $nativeOutput -Algorithm SHA256).Hash.ToLowerInvariant()
                    verifier = 'native_parser_signtool_wintrust_sequence'
                    signerSequence = @($CodeSignThumbprintSuffix)
                    timestamp = 'present'
                })
        }

        $unsignedPdf = $canonicalPdfFixture
        $pdfInputHash = (Get-FileHash -LiteralPath $unsignedPdf -Algorithm SHA256).Hash
        $signedPdf = Join-Path $runDirectory 'document.signed.pdf'
        $pdfJson = [ordered]@{ kind = 'pdf'; certificateSerialNumber = $DocumentCertificateSerialNumber; digestAlgorithm = 'sha256'; page = $PdfPage; box = @($PdfBox); fieldName = 'CertumDocumentSignature'; reason = 'Acceptance'; location = 'CN' } | ConvertTo-Json -Compress
        Assert-CorruptPdfRejected (Join-Path $runDirectory 'fixtures\corrupt.pdf') $pdfJson
        $corruptPdfRejectedWithoutResult = $true
        $pdfJob = Invoke-CreateJob $unsignedPdf $pdfJson $signedPdf
        if ((Get-FileHash -LiteralPath $unsignedPdf -Algorithm SHA256).Hash -cne $pdfInputHash) { throw 'acceptance_input_modified' }
        Assert-PdfSignedResult $unsignedPdf $signedPdf 'base'
        $expectedPdfSignerSuffix = $DocumentSignerSha256.Substring(56, 8).ToUpperInvariant()
        $jobEvidenceRecords.Add([ordered]@{
                name = 'pdf-base'
                channel = 'async'
                jobId = $pdfJob.ToString('D')
                inputSha256 = $pdfInputHash.ToLowerInvariant()
                resultSha256 = (Get-FileHash -LiteralPath $signedPdf -Algorithm SHA256).Hash.ToLowerInvariant()
                verifier = 'project_helper_plus_independent_pyhanko_and_certutil'
                signerSequence = @($expectedPdfSignerSuffix)
                timestamp = 'tsa-identity-and-window-verified'
            })

        $syncInputHash = (Get-FileHash -LiteralPath $unsignedPdf -Algorithm SHA256).Hash
        $syncOutput = Join-Path $runDirectory 'sync.signed.pdf'
        Invoke-SynchronousSign $unsignedPdf $pdfJson $syncOutput
        if ((Get-FileHash -LiteralPath $unsignedPdf -Algorithm SHA256).Hash -cne $syncInputHash) {
            throw 'acceptance_input_modified'
        }
        Assert-PdfSignedResult $unsignedPdf $syncOutput 'sync'
        $jobEvidenceRecords.Add([ordered]@{
                name = 'pdf-sync'
                channel = 'sync'
                jobId = $null
                inputSha256 = $syncInputHash.ToLowerInvariant()
                resultSha256 = (Get-FileHash -LiteralPath $syncOutput -Algorithm SHA256).Hash.ToLowerInvariant()
                verifier = 'project_helper_plus_independent_pyhanko_and_certutil'
                signerSequence = @($expectedPdfSignerSuffix)
                timestamp = 'tsa-identity-and-window-verified'
            })

        $installedAgentTask = Get-ScheduledTask -TaskName 'SimplySignAuto.Agent' -ErrorAction Stop
        if ($installedAgentTask.Principal.UserId -ine $SigningUser -or
            $installedAgentTask.Principal.LogonType -ne 'InteractiveToken' -or
            $installedAgentTask.Principal.RunLevel -ne 'Highest' -or
            @($installedAgentTask.Actions).Count -ne 1 -or
            $installedAgentTask.Actions[0].Execute -ine $canonicalApp) {
            throw 'acceptance_agent_task_invalid'
        }
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0 -or (Test-WtsActive 0)) {
            throw 'acceptance_session_zero_invalid'
        }
        $sessionZeroUnavailable = $true
        Assert-AgentTaskExact $InstalledState.AgentTask $canonicalApp
        $disconnect = Invoke-BoundedProcessCapture $canonicalTsDiscon @([string]$sessionId) 30 $null
        if ($disconnect.ExitCode -ne 0) { throw 'acceptance_session_disconnect_failed' }
        $agentStopWatch = [Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Milliseconds 250
            $installedAgentTask = Get-ScheduledTask -TaskName 'SimplySignAuto.Agent'
        } while (($installedAgentTask.State -eq 'Running' -or (Test-WtsActive $sessionId)) -and
            $agentStopWatch.Elapsed.TotalSeconds -lt 30)
        if ($installedAgentTask.State -eq 'Running' -or (Test-WtsActive $sessionId)) {
            throw 'acceptance_session_disconnect_failed'
        }
        try {
            $null = Get-UniqueActiveSession $signingSid
            throw 'acceptance_session_disconnect_failed'
        } catch [SimplySignAuto.Acceptance.Contracts.AcceptanceContractException] {
            if ($_.Exception.Message -cne 'acceptance_session_unavailable') { throw }
        }
        $notReadyResponse = $client.GetAsync("$safeBaseUrl/v1/health/ready").GetAwaiter().GetResult()
        try {
            if ([int]$notReadyResponse.StatusCode -ne 503) { throw 'acceptance_session_disconnect_failed' }
            $notReady = ConvertFrom-StrictJson ($notReadyResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult())
            Assert-ExactProperties $notReady @(
                'service', 'agent', 'simplySign', 'session', 'capabilities', 'queue')
            Assert-ExactProperties $notReady.session @('generation', 'transitions')
            if ($notReady.service -cne 'not_ready' -or $notReady.agent.connected -ne $false -or
                $notReady.agent.sessionId -ne 0 -or $notReady.simplySign.process -ne $false -or
                $notReady.simplySign.token -ne $false) {
                throw 'acceptance_session_disconnect_failed'
            }
        } finally { $notReadyResponse.Dispose() }
        $disconnectedSessionUnavailable = $true

        $queueKeys = @(
            "$runIdLocal-q1", "$runIdLocal-q2", "$runIdLocal-q3", "$runIdLocal-q4", "$runIdLocal-q5")
        $submittedIds = New-Object System.Collections.Generic.List[string]
        foreach ($queueKey in $queueKeys) {
            $created = Invoke-SubmitOnly $unsignedPdf $pdfJson $queueKey
            $submittedIds.Add(([guid]$created.jobId).ToString('D'))
        }
        $waitingIds = New-Object System.Collections.Generic.List[string]
        foreach ($submittedId in $submittedIds) {
            $waitingWatch = [Diagnostics.Stopwatch]::StartNew()
            do {
                $waitingStatus = Get-StrictJobStatus ([guid]$submittedId) $unsignedPdf
                if ($waitingStatus.state -in @('signing', 'verifying', 'succeeded', 'failed', 'expired')) {
                    throw 'acceptance_queue_recovery_invalid'
                }
                if ($waitingStatus.state -ceq 'waiting_for_agent') { break }
                Start-Sleep -Milliseconds 250
            } while ($waitingWatch.Elapsed.TotalSeconds -lt 30)
            if ($waitingStatus.state -cne 'waiting_for_agent') { throw 'acceptance_queue_recovery_invalid' }
            $waitingIds.Add($submittedId)
        }

        Restart-Service -Name 'SimplySignAuto.Service' -Force -ErrorAction Stop
        $serviceWatch = [Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Milliseconds 250
            $serviceState = (Get-Service -Name 'SimplySignAuto.Service' -ErrorAction Stop).Status
        } while ($serviceState -ne 'Running' -and $serviceWatch.Elapsed.TotalSeconds -lt 30)
        if ($serviceState -ne 'Running') { throw 'acceptance_service_restart_failed' }
        foreach ($submittedId in $submittedIds) {
            if ((Get-StrictJobStatus ([guid]$submittedId) $unsignedPdf).state -cne 'waiting_for_agent') {
                throw 'acceptance_queue_recovery_invalid'
            }
        }
        $idempotentRetry = Invoke-SubmitOnly $unsignedPdf $pdfJson $queueKeys[0]
        $idempotentRetryId = ([guid]$idempotentRetry.jobId).ToString('D')
        $null = Invoke-SubmitOnly $signedPdf $pdfJson $queueKeys[0] 409

        $reconnect = Invoke-BoundedProcessCapture `
            $canonicalTsCon `
            @([string]$sessionId, '/dest:console') `
            30 `
            $null
        if ($reconnect.ExitCode -ne 0) { throw 'acceptance_session_recovery_failed' }
        $sessionWatch = [Diagnostics.Stopwatch]::StartNew()
        do {
            if (Test-WtsActive $sessionId) { break }
            Start-Sleep -Milliseconds 250
        } while ($sessionWatch.Elapsed.TotalSeconds -lt 30)
        if (-not (Test-WtsActive $sessionId) -or (Get-UniqueActiveSession $signingSid) -ne $sessionId) {
            throw 'acceptance_session_recovery_failed'
        }
        Assert-AgentTaskExact $InstalledState.AgentTask $canonicalApp
        Start-ScheduledTask -TaskName 'SimplySignAuto.Agent'
        $agentRecoveryObserved = $false
        $observedMaximumActive = 0
        $queueWatch = [Diagnostics.Stopwatch]::StartNew()
        $terminalStatuses = @{}
        do {
            $activeCount = 0
            $allSucceeded = $true
            foreach ($submittedId in $submittedIds) {
                $status = Get-StrictJobStatus ([guid]$submittedId) $unsignedPdf
                if ($status.state -in @('signing', 'verifying')) { $activeCount++ }
                if ($status.state -ceq 'failed' -or $status.state -ceq 'expired') {
                    throw 'acceptance_queue_recovery_invalid'
                }
                if ($status.state -cne 'succeeded') { $allSucceeded = $false }
                else { $terminalStatuses[$submittedId] = $status }
            }
            if ($activeCount -gt 1) { throw 'acceptance_queue_recovery_invalid' }
            $observedMaximumActive = [Math]::Max($observedMaximumActive, $activeCount)
            if ($activeCount -eq 1) { $agentRecoveryObserved = $true }
            if (-not $allSucceeded) { Start-Sleep -Milliseconds 200 }
        } while (-not $allSucceeded -and $queueWatch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        if (-not $allSucceeded -or $terminalStatuses.Count -ne 5) {
            throw 'acceptance_queue_recovery_invalid'
        }
        $activeSessionRecovered = $true
        $completionIds = @($terminalStatuses.GetEnumerator() |
            Sort-Object {
                [DateTimeOffset]::Parse(
                    [string]$_.Value.startedAt,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::RoundtripKind)
            } |
            ForEach-Object { [string]$_.Key })
        [SimplySignAuto.Acceptance.Contracts.RemoteAcceptanceMatrixPolicy]::ValidateQueueRecovery(
            $submittedIds.ToArray(),
            $waitingIds.ToArray(),
            $completionIds,
            $observedMaximumActive,
            $submittedIds[0],
            $idempotentRetryId,
            $true,
            $true,
            $agentRecoveryObserved)

        for ($queueIndex = 0; $queueIndex -lt 5; $queueIndex++) {
            $queueId = [guid]$submittedIds[$queueIndex]
            $queueStatus = $terminalStatuses[$submittedIds[$queueIndex]]
            if ($queueStatus.resultSha256 -isnot [string] -or
                $queueStatus.resultSha256 -notmatch '^[0-9a-f]{64}$' -or
                $null -ne $queueStatus.errorCode -or $null -ne $queueStatus.errorMessage) {
                throw 'acceptance_queue_recovery_invalid'
            }
            $queueNumber = ($queueIndex + 1).ToString('00')
            $queueOutput = Join-Path $runDirectory "queue-$queueNumber.signed.pdf"
            Save-JobResult $queueId $queueOutput $queueStatus.resultSha256
            Assert-PdfSignedResult $unsignedPdf $queueOutput "queue-$queueNumber"
            $jobEvidenceRecords.Add([ordered]@{
                    name = "pdf-queue-$queueNumber"
                    channel = 'async-recovery'
                    jobId = $queueId.ToString('D')
                    inputSha256 = $pdfInputHash.ToLowerInvariant()
                    resultSha256 = $queueStatus.resultSha256
                    verifier = 'project_helper_plus_independent_pyhanko_and_certutil'
                    signerSequence = @($expectedPdfSignerSuffix)
                    timestamp = 'tsa-identity-and-window-verified'
                })
        }
        $QueueRecoveryEvidence = [ordered]@{
            submittedJobIds = $submittedIds.ToArray()
            waitingJobIds = $waitingIds.ToArray()
            completedJobIds = $completionIds
            maximumActive = $observedMaximumActive
            idempotentJobId = $idempotentRetryId
            changedInputConflict = $true
            serviceRestart = 'passed'
            agentRecovery = 'passed'
        }
    } finally { $client.Dispose() }

    $preflight = [ordered]@{
        schemaVersion = 2
        runId = $runIdLocal
        mode = $Mode
        osBuild = [Environment]::OSVersion.Version.Build
        powershellMajor = $PSVersionTable.PSVersion.Major
        sessionId = $sessionId
        principalHash = $principalHash
        installInstanceHash = $InstalledState.InstallInstanceHash
        controller = 'elevated'
        session = 'active_nonzero'
        installReadback = 'exact'
        secrets = 'acl_restricted'
        timeSynchronization = 'passed'
        pssa = 'passed'
        urlAcl = 'exact'
    } | ConvertTo-Json -Compress
    $preflightObject = ConvertFrom-StrictJson $preflight
    Assert-ExactProperties $preflightObject @(
        'schemaVersion', 'runId', 'mode', 'osBuild', 'powershellMajor', 'sessionId',
        'principalHash', 'installInstanceHash', 'controller', 'session', 'installReadback', 'secrets',
        'timeSynchronization', 'pssa', 'urlAcl')
    New-CreateNewText (Join-Path $runDirectory 'preflight.json') $preflight

    $jobManifest = [ordered]@{
        schemaVersion = 2
        runId = $runIdLocal
        jobs = $jobEvidenceRecords.ToArray()
        queueRecovery = $QueueRecoveryEvidence
    } | ConvertTo-Json -Compress -Depth 5
    $jobManifestObject = ConvertFrom-StrictJson $jobManifest
    Assert-ExactProperties $jobManifestObject @('schemaVersion', 'runId', 'jobs', 'queueRecovery')
    if ($jobManifestObject.schemaVersion -ne 2 -or $jobManifestObject.jobs -isnot [System.Array] -or
        @($jobManifestObject.jobs).Count -ne 18) {
        throw 'acceptance_json_invalid'
    }
    foreach ($job in @($jobManifestObject.jobs)) {
        Assert-ExactProperties $job @(
            'name', 'channel', 'jobId', 'inputSha256', 'resultSha256', 'verifier',
            'signerSequence', 'timestamp')
        if ($job.channel -in @('sync', 'quick-sign')) {
            if ($null -ne $job.jobId) { throw 'acceptance_json_invalid' }
        } elseif ($job.jobId -isnot [string] -or $job.jobId -notmatch '^[0-9a-f-]{36}$') {
            throw 'acceptance_json_invalid'
        }
    }
    Assert-ExactProperties $jobManifestObject.queueRecovery @(
        'submittedJobIds', 'waitingJobIds', 'completedJobIds', 'maximumActive',
        'idempotentJobId', 'changedInputConflict', 'serviceRestart', 'agentRecovery')
    New-CreateNewText (Join-Path $runDirectory 'job-manifest.json') $jobManifest

    if (-not $unauthorizedObserved -or -not $corruptPdfRejectedWithoutResult -or
        -not $AutoReloginAfterCloseObserved -or
        -not $disconnectedSessionUnavailable -or -not $sessionZeroUnavailable -or
        -not $activeSessionRecovered -or -not $PssaClean -or
        -not $TimeSynchronized -or -not $UrlAclExact) {
        throw 'acceptance_remote_matrix_incomplete'
    }
    $pendingSummary = [ordered]@{
        schemaVersion = 2
        runId = $runIdLocal
        state = 'reboot_pending'
        mode = $Mode
        osBuild = [Environment]::OSVersion.Version.Build
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        sessionId = $sessionId
        principalHash = $principalHash
        installInstanceHash = $InstalledState.InstallInstanceHash
        windowsNativeExecuted = 42
        authenticodeJobId = $authJob.ToString('D')
        pdfJobId = $pdfJob.ToString('D')
        authenticodeInputSha256 = $unsignedHash
        authenticodeResultSha256 = (Get-FileHash -LiteralPath $signedExe -Algorithm SHA256).Hash
        pdfInputSha256 = $pdfInputHash
        pdfResultSha256 = (Get-FileHash -LiteralPath $signedPdf -Algorithm SHA256).Hash
        codeSignSuffix = $CodeSignThumbprintSuffix
        documentSuffix = $DocumentThumbprintSuffix
        uiState = 'passed'
        productionQuickSign = 'passed'
        secretScan = 'clean'
    } | ConvertTo-Json -Compress
    $unattendedCheckpoint = [ordered]@{
        signingSid = $signingSid.Value
        baseUrl = $safeBaseUrl
        tlsCertificatePin = $TlsCertificatePin
        agentTaskSource = $InstalledState.AgentTask.Source
        codeCertificateSerialNumber = $CodeSignCertificateSerialNumber
        documentCertificateSerialNumber = $DocumentCertificateSerialNumber
        codeSignSuffix = $CodeSignThumbprintSuffix
        documentSignerSha256 = $DocumentSignerSha256
        timestampSignerSha256 = $TimestampSignerSha256
        timestampSignerSubjectSuffix = $TimestampSignerSubjectSuffix
        expectedTimestampSignerSubject = $ExpectedTimestampSignerSubject
        documentSignerCertificate = $canonicalDocumentSignerCertificate
        timestampSignerCertificate = $canonicalTimestampSignerCertificate
        pdfPage = $PdfPage
        pdfBox = @($PdfBox)
        signToolPath = $canonicalSignTool
        signToolPublisherSha256 = $SignToolPublisherSha256
        pdfHelperPath = $canonicalPdfHelper
        pdfHelperSha256 = $PdfHelperSha256
        independentPdfValidatorPath = $canonicalIndependentPdfValidator
        independentPdfValidatorSha256 = $IndependentPdfValidatorSha256
        pdfTrustRoots = @($canonicalPdfTrustRoots)
        pdfIntermediates = @($canonicalPdfIntermediates)
        codeInputSource = $unsigned
        pdfInputSource = $unsignedPdf
        dataRoot = $InstalledState.DataRoot
        agentDirectory = $InstalledState.AgentDirectory
        installInstanceHash = $InstalledState.InstallInstanceHash
        dotnetPath = $canonicalDotnet
        dotnetPublisherSha256 = $DotnetPublisherSha256
        simplySignDesktopPath = $canonicalSimplySign
        simplySignPublisherSha256 = $SimplySignPublisherSha256
    }
    $resumeRepoForTask = $canonicalRepo
    $resumeScriptForTask = $canonicalScript
    if ($FreshSetupResumed) {
        $resumeRepoForTask = $FreshSetupContinuation.Resume.Root
        $resumeScriptForTask = $FreshSetupContinuation.Resume.ScriptPath
    }
    Prepare-UnattendedRebootStage `
        $resumeRepoForTask `
        $resumeScriptForTask `
        $canonicalPowerShell `
        $canonicalApp `
        $runDirectory `
        $runIdLocal `
        $pendingSummary `
        $unattendedCheckpoint `
        $ApiToken `
        $TimeoutSeconds
} catch {
    if ($null -eq $StableFailure) {
        $StableFailure = Get-StableErrorCode $_ 'acceptance_unhandled_exception'
    }
    Write-AcceptanceDiagnostic $_ $StableFailure $script:DiagnosticStage $FailureRunDirectory
    if ($null -ne $FailureRunDirectory -and $null -ne $FailureRunId) {
        try {
            $failureSummaryPath = Join-Path $FailureRunDirectory 'summary.json'
            if (-not (Test-Path -LiteralPath $failureSummaryPath)) {
                $failureState = if ($StableFailure -in @(
                        'acceptance_native_fixture_pending',
                        'acceptance_pssa_pending',
                        'acceptance_independent_pdf_validator_pending',
                        'acceptance_cross_volume_fixture_pending',
                        'acceptance_purge_reboot_requires_fresh_install')) { 'pending' } else { 'failed' }
                $failureSummary = [ordered]@{
                    schemaVersion = 1
                    runId = $FailureRunId
                    state = $failureState
                    code = $StableFailure
                    remoteWindowsExecuted = $false
                } | ConvertTo-Json -Compress
                New-CreateNewText $failureSummaryPath $failureSummary
            }
        } catch {
            Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'failure_summary' $FailureRunDirectory
            $StableFailure = 'acceptance_state_uncertain'
        }
    }
} finally {
    $ApiToken = $null
    if ($TaskCreated) {
        try {
            $current = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            $currentPrincipalSid = [System.Security.Principal.NTAccount]::new(
                [string]$current.Principal.UserId).Translate([System.Security.Principal.SecurityIdentifier])
            $actual = [SimplySignAuto.Acceptance.Contracts.AcceptanceTaskSnapshot]::new(
                [string]$current.Description,
                (Get-Sha256Text $currentPrincipalSid.Value),
                [string]$current.Principal.LogonType,
                [string]$current.Principal.RunLevel,
                (Get-Sha256Text (([string]$current.Actions[0].Execute).ToUpperInvariant())),
                (Get-Sha256Text ([string]$current.Actions[0].Arguments)),
                [int]$current.Settings.ExecutionTimeLimit.TotalSeconds,
                @($current.Actions).Count)
            if ([SimplySignAuto.Acceptance.Contracts.TaskOwnershipPolicy]::IsExact($ExpectedTask, $actual)) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            } else { $StableFailure = 'acceptance_state_uncertain' }
        } catch {
            Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'controller_cleanup_task' $FailureRunDirectory
            $StableFailure = 'acceptance_state_uncertain'
        }
    }
    if ($null -ne $FreshInstallTokenPathForCleanup -and -not $FreshTokenCleaned) {
        try {
            Observe-OneTimeInstallToken -Path $FreshInstallTokenPathForCleanup
            if ($FreshTokenObserved) {
                if (-not (Test-Path -LiteralPath $FreshInstallTokenPathForCleanup -PathType Leaf)) {
                    throw 'acceptance_state_uncertain'
                }
                Assert-SecretAcl $FreshInstallTokenPathForCleanup $signingSid 'Machine'
                $item = Get-Item -LiteralPath $FreshInstallTokenPathForCleanup -Force
                $identity = [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read(
                    $FreshInstallTokenPathForCleanup,
                    $false)
                $hash = (Get-FileHash -LiteralPath $FreshInstallTokenPathForCleanup -Algorithm SHA256).Hash.ToLowerInvariant()
                if (-not [SimplySignAuto.Acceptance.Contracts.InstallTokenCleanupPolicy]::CanDelete(
                        $false,
                        $true,
                        $FreshTokenFirstIdentity,
                        $identity.Identity,
                        $hash,
                        $hash,
                        (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0),
                        (-not $item.PSIsContainer),
                        [int]$identity.LinkCount) -or
                    -not [SimplySignAuto.Acceptance.Contracts.WindowsFileIdentity]::DeleteOrdinaryFileIfExactWithRetry(
                        $FreshInstallTokenPathForCleanup,
                        $identity.Identity,
                        $hash,
                        5000,
                        100)) {
                    throw 'acceptance_state_uncertain'
                }
                $FreshTokenCleaned = -not (Test-Path -LiteralPath $FreshInstallTokenPathForCleanup)
                if (-not $FreshTokenCleaned) { throw 'acceptance_state_uncertain' }
            } elseif (Test-Path -LiteralPath $FreshInstallTokenPathForCleanup) {
                throw 'acceptance_state_uncertain'
            }
        } catch {
            Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'controller_cleanup_install_token' $FailureRunDirectory
            $StableFailure = 'acceptance_state_uncertain'
        }
    }
    if ($InstallMutationAttempted -and ((-not $KeepInstalledState) -or $null -ne $StableFailure)) {
        try {
            $uninstall = Invoke-BoundedProcessCapture `
                $canonicalApp `
                @('uninstall', '--purge-data', '--confirm', 'PURGE') `
                $TimeoutSeconds `
                $null
            if ($uninstall.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($uninstall.Stderr)) {
                $StableFailure = 'acceptance_state_uncertain'
            }
        } catch {
            Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'controller_cleanup_uninstall' $FailureRunDirectory
            $StableFailure = 'acceptance_state_uncertain'
        }
    }
    foreach ($nativeFixturePath in @($NativeFixturePathsForCleanup)) {
        try { Close-TrustedExecutableGuard $nativeFixturePath } catch {
            Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'controller_cleanup_native_guard' $FailureRunDirectory
            $StableFailure = 'acceptance_state_uncertain'
        }
    }
    if ($FixtureInvocationAttempted) {
        try {
            $fixturePathForCleanup = Join-Path $RunDirectoryForCleanup 'fixtures'
            if (Test-Path -LiteralPath $fixturePathForCleanup) {
                $fixtureCleanup = Invoke-BoundedProcessCapture $CanonicalPowerShellForCleanup @(
                    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
                    $FixtureScriptForCleanup, '-Cleanup', '-RepoPath', $CanonicalRepoForCleanup,
                    '-RunDirectory', $RunDirectoryForCleanup, '-RunId', $RunIdForCleanup) 120 $null
                if ($fixtureCleanup.ExitCode -ne 0 -or
                    $fixtureCleanup.Stdout.Trim() -cne 'acceptance_fixture_cleanup_pass') {
                    $StableFailure = 'acceptance_state_uncertain'
                }
            }
        } catch {
            Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'controller_cleanup_fixture' $FailureRunDirectory
            $StableFailure = 'acceptance_state_uncertain'
        }
    }
    if ($null -ne $InteractiveAclFixturePath -and -not $InteractiveAclFixtureCleaned) {
        try {
            Remove-InteractiveAclFixture `
                $InteractiveAclFixturePath `
                $InteractiveAclSiblingPath `
                $InteractiveAclFixtureIdentity `
                $InteractiveAclSiblingIdentity `
                $InteractiveAclSiblingSha256
            $InteractiveAclFixtureCleaned = $true
        } catch {
            Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'controller_cleanup_acl_fixture' $FailureRunDirectory
            $StableFailure = 'acceptance_state_uncertain'
        }
    }
    try { Close-TrustedExecutableGuards } catch {
        Write-AcceptanceDiagnostic $_ 'acceptance_state_uncertain' 'controller_cleanup_executable_guards' $FailureRunDirectory
        $StableFailure = 'acceptance_state_uncertain'
    }
}

if ($UnattendedRebootCleanupArmed -and $null -ne $StableFailure) {
    $StableFailure = Invoke-UnattendedRebootCleanup $StableFailure
}
if ($RebootStagePrepared -and -not $StableFailure) {
    [Console]::Out.WriteLine('acceptance_reboot_started')
    if ([Environment]::GetEnvironmentVariable('SIMPLYSIGN_ACCEPTANCE_FRESH_HANDOFF') -ceq '1') {
        exit 194
    }
    try {
        Restart-Computer -Force -ErrorAction Stop
        exit 194
    } catch {
        Fail-Stable (Invoke-UnattendedRebootCleanup 'acceptance_reboot_failed') 1
    }
}
if ($StableFailure) { Fail-Stable $StableFailure 1 }
try {
    $script:DiagnosticStage = 'finalize_acceptance_artifacts'
    if ([string]::IsNullOrWhiteSpace($SuccessfulRunDirectory) -or
        [string]::IsNullOrWhiteSpace($SuccessfulRunId) -or
        [string]::IsNullOrWhiteSpace($FinalSummary)) {
        throw 'acceptance_state_uncertain'
    }
    New-CreateNewText (Join-Path $SuccessfulRunDirectory 'controller.stdout.txt') 'acceptance_pass'
    New-CreateNewText (Join-Path $SuccessfulRunDirectory 'controller.stderr.txt') ''
    New-SafeEventLogSummary `
        (Join-Path $SuccessfulRunDirectory 'event-log.json') `
        $SuccessfulRunId `
        $AcceptanceStartedUtc
    if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
            $FinalSummary,
            [string]$script:TotpSecretForRedaction)) {
        throw 'acceptance_sensitive_artifact'
    }
    New-CreateNewText (Join-Path $SuccessfulRunDirectory 'summary.json') $FinalSummary
    if ($Mode -ceq 'FreshInstall' -and
        (Test-Path -LiteralPath (Join-Path $SuccessfulRunDirectory '.resume'))) {
        Remove-ProtectedResumeSourceBundle $SuccessfulRunDirectory
    }
    Assert-AcceptanceArtifactLayout `
        $SuccessfulRunDirectory `
        $true `
        ($Mode -ceq 'FreshInstall')
    $artifactCompletedUtc = [DateTime]::UtcNow
    foreach ($artifact in @(Get-ChildItem -LiteralPath $SuccessfulRunDirectory -File -Recurse)) {
        if ($artifact.LastWriteTimeUtc -lt $AcceptanceStartedUtc.UtcDateTime.AddSeconds(-2) -or
            $artifact.LastWriteTimeUtc -gt $artifactCompletedUtc.AddSeconds(2)) {
            throw 'acceptance_artifact_mtime_invalid'
        }
        if ($artifact.Extension -in '.json', '.trx', '.xml', '.txt', '.log') {
            $artifactText = Get-Content -LiteralPath $artifact.FullName -Raw
            if ([SimplySignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive(
                    $artifactText,
                    [string]$script:TotpSecretForRedaction)) {
                throw 'acceptance_sensitive_artifact'
            }
        }
    }
} catch {
    $finalFailure = Get-StableErrorCode $_ 'acceptance_unhandled_exception'
    Write-AcceptanceDiagnostic $_ $finalFailure $script:DiagnosticStage $SuccessfulRunDirectory
    Fail-Stable $finalFailure 1
}
[Console]::Out.WriteLine('acceptance_pass')
$script:TotpSecretForRedaction = $null
exit 0
