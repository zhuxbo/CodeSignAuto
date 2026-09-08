[CmdletBinding(DefaultParameterSetName = 'Controller')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$RepoPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$ArtifactRoot,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$SigningUser,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$AdministratorUser,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$DotnetPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Controller')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [string]$AppHostPath,

    [Parameter(ParameterSetName = 'Controller')]
    [Parameter(ParameterSetName = 'Child')]
    [string]$ProductionExeInput,

    [Parameter(ParameterSetName = 'Controller')]
    [Parameter(ParameterSetName = 'Child')]
    [string]$ProductionPdfInput,

    [Parameter(ParameterSetName = 'Controller')]
    [Parameter(ParameterSetName = 'Child')]
    [string]$ProductionOtpUriFile,

    [Parameter(ParameterSetName = 'Controller')]
    [Parameter(ParameterSetName = 'Child')]
    [string]$ProductionArtifactRoot,

    [Parameter(ParameterSetName = 'Controller')]
    [ValidateRange(60, 600)]
    [int]$TimeoutSeconds = 600,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [switch]$RunChild,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RunId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Child')]
    [ValidateRange(1, 2147483647)]
    [int]$ExpectedSessionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$TaskName = 'CodeSignAuto UI Acceptance'
$StableFailure = $null
$CreatedTask = $false
$ExpectedTaskDescription = $null
$ExpectedActionArguments = $null
$ExpectedExecutionTimeLimit = $null
$PowerShellPath = (Get-Process -Id $PID).Path
$StrictJsonPreflightInitialized = $false
$StrictJsonSourceSha256 = $null
$TrxPolicyInitialized = $false
$DiagnosticStage = 'startup'
$runDirectory = $null
$ExpectedPngTests = [ordered]@{
    'activation-saved.png' = [ordered]@{
        TestName = 'Saving_rejects_escape_cancel_and_title_close_then_closes_once_and_clears_secret'
        CurrentPageAnchor = 'current_page_title:激活与证书'
    }
    'jobs-loaded.png' = [ordered]@{
        TestName = 'Jobs_load_exactly_100_then_more_with_active_first_and_terminal_button_policy'
        CurrentPageAnchor = 'current_page_title:签名任务'
    }
    'overview-busy.png' = [ordered]@{
        TestName = 'Overview_exposes_busy_state_and_opens_the_real_jobs_page'
        CurrentPageAnchor = 'current_page_title:概览'
    }
    'quick-finalizing.png' = [ordered]@{
        TestName = 'Quick_sign_exposes_finalizing_before_opening_jobs'
        CurrentPageAnchor = 'current_page_title:快速签名'
    }
    'window-geometry.png' = [ordered]@{
        TestName = 'Real_process_window_is_1024_by_768_landscape_four_by_three'
        CurrentPageAnchor = 'current_page_title:概览'
    }
}

function Fail-Stable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Code,
        [int]$ExitCode = 1
    )

    [Console]::Out.WriteLine($Code)
    exit $ExitCode
}

function Protect-UiDiagnosticText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    if ('CodeSignAuto.Acceptance.Contracts.SecretScanPolicy' -as [type]) {
        return [CodeSignAuto.Acceptance.Contracts.SecretScanPolicy]::Redact($Text, '')
    }
    return [regex]::Replace(
        $Text,
        '(?i)(otpauth://[^\s\r\n]*?(?:[?&]|&amp;)secret=)[^&\s\r\n#<>]+',
        '$1[REDACTED_TOTP_SECRET]')
}

function Write-UiDiagnostic {
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Code,
        [string]$Stage,
        [AllowNull()][string]$RunDirectory
    )
    $exception = $ErrorRecord.Exception
    $nativeError = if ($null -ne $exception.PSObject.Properties['NativeErrorCode']) {
        [string]$exception.NativeErrorCode
    } else { '' }
    $diagnostic = Protect-UiDiagnosticText (@(
        'ui_acceptance_diagnostic_begin',
        "stable_code=$Code",
        "stage=$Stage",
        "exception_type=$($exception.GetType().FullName)",
        "message=$($exception.Message)",
        ('hresult=0x{0:X8}' -f (([int64]$exception.HResult) -band 4294967295)),
        "win32_error=$nativeError",
        "script_name=$($ErrorRecord.InvocationInfo.ScriptName)",
        "script_line=$($ErrorRecord.InvocationInfo.ScriptLineNumber)",
        "offset_in_line=$($ErrorRecord.InvocationInfo.OffsetInLine)",
        'position_begin',
        [string]$ErrorRecord.InvocationInfo.PositionMessage,
        'position_end',
        'exception_begin',
        $exception.ToString(),
        'exception_end',
        'script_stack_begin',
        [string]$ErrorRecord.ScriptStackTrace,
        'script_stack_end',
        'ui_acceptance_diagnostic_end') -join "`n")
    [Console]::Error.WriteLine($diagnostic)
    if (-not [string]::IsNullOrWhiteSpace($RunDirectory) -and
        (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
        $path = Join-Path $RunDirectory 'ui-controller-diagnostic.log'
        if (-not (Test-Path -LiteralPath $path)) {
            New-CreateNewTextFile -Path $path -Content $diagnostic
        }
    }
}

function Get-CanonicalExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Container', 'Leaf')]
        [string]$Kind
    )

    if ($Path -notmatch '^[A-Za-z]:\\' -or
        -not [string]::Equals([System.IO.Path]::GetFullPath($Path), $Path, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Path.IndexOfAny([char[]]"`r`n") -ge 0) {
        throw 'path_invalid'
    }

    $item = Get-Item -LiteralPath $Path -Force
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'path_invalid'
        }
        $cursor = if ($cursor -is [System.IO.FileInfo]) { $cursor.Directory } else { $cursor.Parent }
    }

    if ($Kind -eq 'Container' -and -not $item.PSIsContainer) {
        throw 'path_invalid'
    }

    if ($Kind -eq 'Leaf' -and $item.PSIsContainer) {
        throw 'path_invalid'
    }

    return $item.FullName
}

function Test-PathUnder {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    return $Path.StartsWith(
        $Root.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-TrustedExecutables {
    param(
        [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][string]$Dotnet,
        [Parameter(Mandatory = $true)][string]$AppHost,
        [Parameter(Mandatory = $true)][string]$PowerShell
    )

    if (-not [string]::Equals([System.IO.Path]::GetFileName($Dotnet), 'dotnet.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'dotnet_invalid'
    }

    $trustedDotnet = Test-PathUnder -Path $Dotnet -Root $Repo
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432)) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $dotnetRoot = Join-Path $root 'dotnet'
            if (Test-Path -LiteralPath $dotnetRoot -PathType Container) {
                $canonicalRoot = Get-CanonicalExistingPath -Path $dotnetRoot -Kind Container
                $trustedDotnet = $trustedDotnet -or (Test-PathUnder -Path $Dotnet -Root $canonicalRoot)
            }
        }
    }
    if (-not $trustedDotnet) {
        throw 'dotnet_invalid'
    }

    if (-not [string]::Equals([System.IO.Path]::GetFileName($AppHost), 'CodeSignAuto.exe', [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-PathUnder -Path $AppHost -Root $Repo)) {
        throw 'apphost_invalid'
    }

    $systemRoot = Get-CanonicalExistingPath -Path $env:SystemRoot -Kind Container
    if (-not [string]::Equals([System.IO.Path]::GetFileName($PowerShell), 'powershell.exe', [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-PathUnder -Path $PowerShell -Root $systemRoot)) {
        throw 'powershell_invalid'
    }
}

function Assert-SafeIdentity {
    param([Parameter(Mandatory = $true)][string]$Identity)

    if ($Identity.Length -gt 256 -or $Identity.IndexOfAny([char[]]"`r`n`0") -ge 0) {
        throw 'signing_user_invalid'
    }

    $account = [System.Security.Principal.NTAccount]::new($Identity)
    $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
    if (-not $sid -or -not $sid.Value.StartsWith('S-1-', [System.StringComparison]::Ordinal)) {
        throw 'signing_user_invalid'
    }
}

function Test-WtsActiveSession {
    param([Parameter(Mandatory = $true)][int]$SessionId)

    if ($SessionId -le 0) {
        return $false
    }

    if (-not ('CodeSignAuto.UiAcceptance.NativeWts' -as [type])) {
        Add-Type -TypeDefinition @'
namespace CodeSignAuto.UiAcceptance {
    public static class NativeWts {
        [System.Runtime.InteropServices.DllImport("wtsapi32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool WTSQuerySessionInformationW(
            System.IntPtr serverHandle,
            int sessionId,
            int informationClass,
            out System.IntPtr buffer,
            out int bytesReturned);

        [System.Runtime.InteropServices.DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(System.IntPtr memory);

        public static bool IsActive(int sessionId) {
            if (sessionId <= 0) {
                return false;
            }

            System.IntPtr buffer = System.IntPtr.Zero;
            try {
                int bytesReturned;
                if (!WTSQuerySessionInformationW(
                        System.IntPtr.Zero,
                        sessionId,
                        8,
                        out buffer,
                        out bytesReturned) ||
                    buffer == System.IntPtr.Zero ||
                    bytesReturned < sizeof(int)) {
                    return false;
                }

                return System.Runtime.InteropServices.Marshal.ReadInt32(buffer) == 0;
            } finally {
                if (buffer != System.IntPtr.Zero) {
                    WTSFreeMemory(buffer);
                }
            }
        }
    }
}
'@
    }

    try {
        return [CodeSignAuto.UiAcceptance.NativeWts]::IsActive($SessionId)
    } catch {
        return $false
    }
}

function Get-InteractiveSessionId {
    param([Parameter(Mandatory = $true)][string]$Identity)

    $sessions = New-Object System.Collections.Generic.List[int]
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'")) {
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
        if ($owner.ReturnValue -ne 0) {
            continue
        }

        $candidate = if ([string]::IsNullOrEmpty($owner.Domain)) {
            $owner.User
        } else {
            "$($owner.Domain)\$($owner.User)"
        }
        if ([string]::Equals($candidate, $Identity, [System.StringComparison]::OrdinalIgnoreCase) -and
            [int]$process.SessionId -gt 0 -and
            (Test-WtsActiveSession -SessionId ([int]$process.SessionId))) {
            $sessions.Add([int]$process.SessionId)
        }
    }

    $unique = @($sessions | Sort-Object -Unique)
    if ($unique.Count -ne 1) {
        return $null
    }

    return [int]$unique[0]
}

function New-CreateNewTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $writer = [System.IO.StreamWriter]::new($stream, $encoding, 4096, $true)
        try {
            $writer.Write($Content)
            $writer.Flush()
            $stream.Flush($true)
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Read-StrictJsonObject {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        Initialize-StrictJsonPreflight
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $raw = [System.IO.File]::ReadAllText($Path, $encoding)
        if ($raw -isnot [string] -or [string]::IsNullOrWhiteSpace($raw) -or $raw.Length -gt 1048576) {
            throw 'ui_acceptance_json_invalid'
        }
        [CodeSignAuto.UiAcceptance.StrictJson.Preflight]::ValidateObject($raw, 16, 1048576)
        $value = $raw | ConvertFrom-Json
    } catch {
        throw 'ui_acceptance_json_invalid'
    }
    if ($null -eq $value -or $value -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'ui_acceptance_json_invalid'
    }

    return $value
}

function Initialize-StrictJsonPreflight {
    if ($script:StrictJsonPreflightInitialized) {
        if ([string]::IsNullOrWhiteSpace($script:StrictJsonSourceSha256) -or
            -not ('CodeSignAuto.UiAcceptance.StrictJson.Preflight' -as [type])) {
            throw 'ui_acceptance_json_parser_invalid'
        }
        return
    }

    if ('CodeSignAuto.UiAcceptance.StrictJson.Preflight' -as [type]) {
        throw 'ui_acceptance_json_parser_invalid'
    }

    $canonicalScriptRoot = Get-CanonicalExistingPath -Path $PSScriptRoot -Kind Container
    $canonicalScript = Get-CanonicalExistingPath -Path $PSCommandPath -Kind Leaf
    $sourcePath = Join-Path $canonicalScriptRoot 'UiAcceptanceStrictJson.cs'
    $canonicalSource = Get-CanonicalExistingPath -Path $sourcePath -Kind Leaf
    if (-not [string]::Equals(
            [System.IO.Path]::GetDirectoryName($canonicalScript),
            $canonicalScriptRoot,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals(
            [System.IO.Path]::GetDirectoryName($canonicalSource),
            $canonicalScriptRoot,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals(
            [System.IO.Path]::GetFileName($canonicalSource),
            'UiAcceptanceStrictJson.cs',
            [System.StringComparison]::Ordinal)) {
        throw 'ui_acceptance_json_parser_invalid'
    }

    $sourceBytes = [System.IO.File]::ReadAllBytes($canonicalSource)
    if ($sourceBytes -isnot [byte[]] -or $sourceBytes.Length -lt 256 -or $sourceBytes.Length -gt 131072) {
        throw 'ui_acceptance_json_parser_invalid'
    }
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $sourceText = $encoding.GetString($sourceBytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $sourceHash = [System.BitConverter]::ToString($sha256.ComputeHash($sourceBytes)).Replace('-', '')
    } finally {
        $sha256.Dispose()
    }
    if ($sourceHash -cnotmatch '^[0-9A-F]{64}$') {
        throw 'ui_acceptance_json_parser_invalid'
    }

    Add-Type -TypeDefinition $sourceText -Language CSharp -ErrorAction Stop
    if (-not ('CodeSignAuto.UiAcceptance.StrictJson.Preflight' -as [type])) {
        throw 'ui_acceptance_json_parser_invalid'
    }

    $script:StrictJsonSourceSha256 = $sourceHash
    $script:StrictJsonPreflightInitialized = $true
}

function Initialize-TrxPolicy {
    param([Parameter(Mandatory = $true)][string]$CanonicalRepo)

    if ($script:TrxPolicyInitialized) {
        if (-not ('CodeSignAuto.Acceptance.Contracts.TrxArtifactPolicy' -as [type])) {
            throw 'ui_acceptance_trx_policy_invalid'
        }
        return
    }
    if ('CodeSignAuto.Acceptance.Contracts.TrxArtifactPolicy' -as [type]) {
        throw 'ui_acceptance_trx_policy_invalid'
    }

    $source = Get-CanonicalExistingPath `
        -Path (Join-Path $CanonicalRepo 'scripts\AcceptanceContracts.cs') `
        -Kind Leaf
    if (-not (Test-PathUnder -Path $source -Root $CanonicalRepo)) {
        throw 'ui_acceptance_trx_policy_invalid'
    }
    $bytes = [System.IO.File]::ReadAllBytes($source)
    if ($bytes.Length -lt 256 -or $bytes.Length -gt 1048576) {
        throw 'ui_acceptance_trx_policy_invalid'
    }
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    Add-Type -TypeDefinition $utf8.GetString($bytes) -Language CSharp `
        -ReferencedAssemblies @('System.dll', 'System.Core.dll', 'System.Net.Http.dll', 'System.Xml.dll') `
        -ErrorAction Stop
    if (-not ('CodeSignAuto.Acceptance.Contracts.TrxArtifactPolicy' -as [type])) {
        throw 'ui_acceptance_trx_policy_invalid'
    }
    $script:TrxPolicyInitialized = $true
}

function Assert-JsonObjectExact {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$ExpectedProperties
    )

    if ($null -eq $Value -or $Value -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'ui_acceptance_json_invalid'
    }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $ExpectedProperties.Count -or
        @($actual | Sort-Object -Unique).Count -ne $actual.Count -or
        @($ExpectedProperties | Where-Object { $_ -cnotin $actual }).Count -ne 0) {
        throw 'ui_acceptance_json_invalid'
    }
}

function Assert-JsonString {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][int]$MaximumLength,
        [string]$Pattern
    )

    if ($Value -isnot [string]) {
        throw 'ui_acceptance_json_invalid'
    }
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt $MaximumLength -or
        $Value.IndexOfAny([char[]]"`r`n`0") -ge 0 -or
        (-not [string]::IsNullOrEmpty($Pattern) -and $Value -cnotmatch $Pattern)) {
        throw 'ui_acceptance_json_invalid'
    }

    return [string]$Value
}

function Assert-JsonBoolean {
    param([AllowNull()][object]$Value)

    if ($Value -isnot [bool]) {
        throw 'ui_acceptance_json_invalid'
    }

    return [bool]$Value
}

function Assert-JsonInteger {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][long]$Minimum,
        [Parameter(Mandatory = $true)][long]$Maximum
    )

    if ($Value -isnot [int] -and $Value -isnot [long]) {
        throw 'ui_acceptance_json_invalid'
    }

    $number = [long]$Value
    if ($number -lt $Minimum -or $number -gt $Maximum) {
        throw 'ui_acceptance_json_invalid'
    }

    return $number
}

function Assert-JsonNumber {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][double]$Minimum,
        [Parameter(Mandatory = $true)][double]$Maximum
    )

    if ($Value -isnot [int] -and $Value -isnot [long] -and
        $Value -isnot [double] -and $Value -isnot [decimal]) {
        throw 'ui_acceptance_json_invalid'
    }
    $number = [double]$Value
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or
        $number -lt $Minimum -or $number -gt $Maximum) {
        throw 'ui_acceptance_json_invalid'
    }

    return $number
}

function Assert-JsonArray {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][int]$ExpectedCount
    )

    if ($Value -isnot [System.Array] -or $Value.Count -ne $ExpectedCount) {
        throw 'ui_acceptance_json_invalid'
    }
}

function Assert-JsonStringArray {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][int]$ExpectedCount,
        [Parameter(Mandatory = $true)][int]$MaximumElementLength
    )

    Assert-JsonArray -Value $Value -ExpectedCount $ExpectedCount
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in $Value) {
        $text = Assert-JsonString -Value $item -MaximumLength $MaximumElementLength
        if (-not $seen.Add($text)) {
            throw 'ui_acceptance_json_invalid'
        }
    }
}

function Assert-JsonRectangle {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Value)

    Assert-JsonObjectExact -Value $Value -ExpectedProperties @('Left', 'Top', 'Width', 'Height')
    $null = Assert-JsonNumber -Value $Value.Left -Minimum -1000000 -Maximum 1000000
    $null = Assert-JsonNumber -Value $Value.Top -Minimum -1000000 -Maximum 1000000
    $null = Assert-JsonNumber -Value $Value.Width -Minimum 0.000001 -Maximum 100000
    $null = Assert-JsonNumber -Value $Value.Height -Minimum 0.000001 -Maximum 100000
}

function ConvertTo-FixedProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value.IndexOfAny([char[]]"`r`n`0`"") -ge 0) {
        throw 'process_argument_invalid'
    }
    if ($Value.EndsWith('\', [System.StringComparison]::Ordinal)) {
        throw 'process_argument_invalid'
    }
    if ($Value -match '\s') {
        return '"' + $Value + '"'
    }
    return $Value
}

function Invoke-ProcessWithCreateNewLogs {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )

    $stdoutStream = $null
    $stderrStream = $null
    $process = $null
    $started = $false
    try {
        $stdoutStream = [System.IO.FileStream]::new(
            $StdoutPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read)
        $stderrStream = [System.IO.FileStream]::new(
            $StderrPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read)
        $start = [System.Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $Executable
        $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-FixedProcessArgument -Value $_ }) -join ' ')
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) {
            throw 'ui_acceptance_process_start_failed'
        }
        $started = $true
        $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        $process.WaitForExit()
        [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($stdoutCopy, $stderrCopy))
        $stdoutStream.Flush($true)
        $stderrStream.Flush($true)
        return $process.ExitCode
    } finally {
        if ($started -and -not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit()
        }
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $stderrStream) { $stderrStream.Dispose() }
        if ($null -ne $stdoutStream) { $stdoutStream.Dispose() }
    }
}

function Publish-SafeUiTrx {
    param(
        [Parameter(Mandatory = $true)][string]$RawPath,
        [Parameter(Mandatory = $true)][string]$FinalPath,
        [Parameter(Mandatory = $true)][string]$RawDirectory
    )

    $partPath = $FinalPath + '.part'
    try {
        $rawItem = Get-Item -LiteralPath $RawPath -Force
        if ($rawItem.PSIsContainer -or
            ($rawItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Test-Path -LiteralPath $FinalPath) -or
            (Test-Path -LiteralPath $partPath)) {
            throw 'ui_acceptance_trx_invalid'
        }
        $stream = [System.IO.FileStream]::new(
            $RawPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None)
        try {
            if ($stream.Length -lt 1 -or $stream.Length -gt 16777216) {
                throw 'ui_acceptance_trx_invalid'
            }
            $reader = [System.IO.StreamReader]::new(
                $stream,
                [System.Text.UTF8Encoding]::new($false, $true),
                $true,
                65536,
                $true)
            try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }

        $safe = [CodeSignAuto.Acceptance.Contracts.TrxArtifactPolicy]::Sanitize(
            $raw,
            'CodeSignAuto.UI.Tests.dll',
            [Environment]::MachineName,
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        New-CreateNewTextFile -Path $partPath -Content $safe
        [System.IO.File]::Move($partPath, $FinalPath)
    } finally {
        $raw = $null
        $safe = $null
        if (Test-Path -LiteralPath $partPath -PathType Leaf) {
            Remove-Item -LiteralPath $partPath -Force
        }
        if (Test-Path -LiteralPath $RawPath -PathType Leaf) {
            $rawItem = Get-Item -LiteralPath $RawPath -Force
            if (($rawItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'ui_acceptance_state_uncertain'
            }
            Remove-Item -LiteralPath $RawPath -Force
        }
        if (Test-Path -LiteralPath $RawDirectory -PathType Container) {
            if (@(Get-ChildItem -LiteralPath $RawDirectory -Force).Count -ne 0) {
                throw 'ui_acceptance_state_uncertain'
            }
            Remove-Item -LiteralPath $RawDirectory -Force
        }
    }
}

function Get-SystemDpi {
    if (-not ('CodeSignAuto.UiAcceptance.NativeDpi' -as [type])) {
        Add-Type -TypeDefinition @'
namespace CodeSignAuto.UiAcceptance {
    internal static class NativeDpi {
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        internal static extern uint GetDpiForSystem();
    }
}
'@
    }

    return [int][CodeSignAuto.UiAcceptance.NativeDpi]::GetDpiForSystem()
}

function Assert-ArtifactGate {
    param(
        [Parameter(Mandatory = $true)][string]$RunDirectory,
        [Parameter(Mandatory = $true)][int]$DesktopExitCode,
        [Parameter(Mandatory = $true)][int]$SessionId,
        [Parameter(Mandatory = $true)][int]$Dpi
    )

    if ($DesktopExitCode -ne 0 -or $SessionId -le 0 -or $Dpi -lt 96) {
        throw 'ui_acceptance_failed'
    }

    $trx = @(Get-ChildItem -LiteralPath $RunDirectory -Filter '*.trx' -File)
    if ($trx.Count -ne 1) {
        throw 'ui_acceptance_trx_invalid'
    }

    [xml]$document = Get-Content -LiteralPath $trx[0].FullName -Raw
    $counters = $document.TestRun.ResultSummary.Counters
    if (-not $counters -or [int]$counters.failed -ne 0 -or [int]$counters.error -ne 0 -or
        [int]$counters.timeout -ne 0 -or [int]$counters.aborted -ne 0 -or [int]$counters.notExecuted -ne 0 -or
        [int]$counters.executed -le 0) {
        throw 'ui_acceptance_trx_invalid'
    }

    $pngs = @(Get-ChildItem -LiteralPath $RunDirectory -Filter '*.png' -File -Recurse)
    if ($pngs.Count -ne $ExpectedPngTests.Count) {
        throw 'ui_acceptance_png_missing'
    }

    Add-Type -AssemblyName System.Drawing
    $pngEvidence = New-Object System.Collections.Generic.List[object]
    foreach ($expectedPng in $ExpectedPngTests.GetEnumerator()) {
        $matches = @($pngs | Where-Object { $_.Name -ceq $expectedPng.Key })
        if ($matches.Count -ne 1) {
            throw 'ui_acceptance_png_missing'
        }

        $png = $matches[0]
        $attestationPath = $png.FullName + '.attestation.json'
        if (-not (Test-Path -LiteralPath $attestationPath -PathType Leaf)) {
            throw 'ui_acceptance_png_attestation_invalid'
        }

        $attestation = Read-StrictJsonObject -Path $attestationPath
        $requiredAttestationProperties = @(
            'schemaVersion', 'runId', 'sessionId', 'testName', 'windowPid', 'title', 'dpi',
            'logicalOuter', 'physicalOuter', 'logicalClient', 'physicalClient',
            'pngFileName', 'pngWidth', 'pngHeight', 'pngSha256',
            'captureMethod', 'targetHwnd', 'validatedAnchorCount', 'validatedAnchors',
            'currentPageAnchor', 'secretInputsEmpty', 'secretVerificationMethod')
        Assert-JsonObjectExact -Value $attestation -ExpectedProperties $requiredAttestationProperties
        $schemaVersion = Assert-JsonInteger -Value $attestation.schemaVersion -Minimum 3 -Maximum 3
        $attestedRunId = Assert-JsonString -Value $attestation.runId -MaximumLength 32 -Pattern '^[0-9a-f]{32}$'
        $attestedSessionId = Assert-JsonInteger -Value $attestation.sessionId -Minimum 1 -Maximum 2147483647
        $attestedTestName = Assert-JsonString -Value $attestation.testName -MaximumLength 160 -Pattern '^[A-Za-z0-9._]{1,160}$'
        $attestedWindowPid = Assert-JsonInteger -Value $attestation.windowPid -Minimum 1 -Maximum 2147483647
        $attestedHwnd = Assert-JsonString -Value $attestation.targetHwnd -MaximumLength 32 -Pattern '^0x[1-9A-F][0-9A-F]*$'
        $attestedTitle = Assert-JsonString -Value $attestation.title -MaximumLength 80
        $attestedDpi = Assert-JsonInteger -Value $attestation.dpi -Minimum 96 -Maximum 768
        Assert-JsonRectangle -Value $attestation.logicalOuter
        Assert-JsonRectangle -Value $attestation.physicalOuter
        Assert-JsonRectangle -Value $attestation.logicalClient
        Assert-JsonRectangle -Value $attestation.physicalClient
        $attestedPngFileName = Assert-JsonString -Value $attestation.pngFileName -MaximumLength 80 -Pattern '^[a-z0-9-]+\.png$'
        $attestedPngWidth = Assert-JsonInteger -Value $attestation.pngWidth -Minimum 1 -Maximum 100000
        $attestedPngHeight = Assert-JsonInteger -Value $attestation.pngHeight -Minimum 1 -Maximum 100000
        $attestedPngSha256 = Assert-JsonString -Value $attestation.pngSha256 -MaximumLength 64 -Pattern '^[0-9A-F]{64}$'
        $attestedCaptureMethod = Assert-JsonString -Value $attestation.captureMethod -MaximumLength 80
        $attestedAnchorCount = Assert-JsonInteger -Value $attestation.validatedAnchorCount -Minimum 3 -Maximum 3
        Assert-JsonStringArray -Value $attestation.validatedAnchors -ExpectedCount 3 -MaximumElementLength 160
        $validatedAnchors = $attestation.validatedAnchors
        $attestedCurrentPageAnchor = Assert-JsonString `
            -Value $attestation.currentPageAnchor `
            -MaximumLength 160 `
            -Pattern '^current_page_title:.{1,80}$'
        $attestedSecretEmpty = Assert-JsonBoolean -Value $attestation.secretInputsEmpty
        $attestedSecretMethod = Assert-JsonString -Value $attestation.secretVerificationMethod -MaximumLength 80

        if ($schemaVersion -ne 3 -or
            $attestedRunId -cne $RunId -or
            $attestedSessionId -ne $SessionId -or
            $attestedTestName -cne $expectedPng.Value.TestName -or
            $attestedTitle -cne 'CodeSignAuto' -or
            $attestedPngFileName -cne $expectedPng.Key -or
            $attestedCaptureMethod -cne 'PrintWindow.PW_RENDERFULLCONTENT.24bppRgb' -or
            $attestedAnchorCount -ne 3 -or
            $validatedAnchors[0] -cne 'main_navigation' -or
            $validatedAnchors[1] -cne 'fixed_header' -or
            $validatedAnchors[2] -cne $expectedPng.Value.CurrentPageAnchor -or
            $attestedCurrentPageAnchor -cne $expectedPng.Value.CurrentPageAnchor -or
            $attestedCurrentPageAnchor -cne $validatedAnchors[2] -or
            $attestedSecretEmpty -ne $true -or
            $attestedSecretMethod -cne 'UIAutomationValuePattern') {
            throw 'ui_acceptance_png_attestation_invalid'
        }

        $logicalWidth = [double]$attestation.logicalOuter.Width
        $logicalHeight = [double]$attestation.logicalOuter.Height
        $physicalWidth = [double]$attestation.physicalOuter.Width
        $physicalHeight = [double]$attestation.physicalOuter.Height
        if ($logicalWidth -le $logicalHeight -or
            [Math]::Abs(($logicalWidth / $logicalHeight) - (4.0 / 3.0)) -gt 0.003 -or
            [Math]::Abs((($logicalWidth * $attestedDpi) / 96.0) - $physicalWidth) -gt 1.1 -or
            [Math]::Abs((($logicalHeight * $attestedDpi) / 96.0) - $physicalHeight) -gt 1.1 -or
            $attestedPngWidth -ne [long]$physicalWidth -or
            $attestedPngHeight -ne [long]$physicalHeight -or
            [Math]::Abs(([double]$attestedPngWidth / [double]$attestedPngHeight) - (4.0 / 3.0)) -gt 0.003 -or
            $attestedPngSha256 -cne (Get-FileHash -LiteralPath $png.FullName -Algorithm SHA256).Hash) {
            throw 'ui_acceptance_png_attestation_invalid'
        }

        $image = [System.Drawing.Image]::FromFile($png.FullName)
        try {
            if ($image.Width -ne [int]$attestation.pngWidth -or
                $image.Height -ne [int]$attestation.pngHeight -or
                $image.PixelFormat -ne [System.Drawing.Imaging.PixelFormat]::Format24bppRgb) {
                throw 'ui_acceptance_png_invalid'
            }
        } finally {
            $image.Dispose()
        }

        $pngEvidence.Add([ordered]@{
            fileName = $expectedPng.Key
            testName = $attestation.testName
            sessionId = [int]$attestation.sessionId
            windowPid = [int]$attestation.windowPid
            targetHwnd = $attestation.targetHwnd
            title = $attestation.title
            dpi = $attestedDpi
            logicalOuter = $attestation.logicalOuter
            physicalOuter = $attestation.physicalOuter
            logicalClient = $attestation.logicalClient
            physicalClient = $attestation.physicalClient
            sha256 = $attestation.pngSha256
            captureMethod = $attestation.captureMethod
            validatedAnchorCount = [int]$attestation.validatedAnchorCount
            validatedAnchors = $validatedAnchors
            currentPageAnchor = $attestation.currentPageAnchor
            secretInputsEmpty = $true
            secretVerificationMethod = $attestation.secretVerificationMethod
        })
    }

    $attestations = @(Get-ChildItem -LiteralPath $RunDirectory -Filter '*.png.attestation.json' -File -Recurse)
    if ($attestations.Count -ne $ExpectedPngTests.Count) {
        throw 'ui_acceptance_png_attestation_invalid'
    }

    foreach ($file in @(Get-ChildItem -LiteralPath $RunDirectory -File -Recurse | Where-Object { $_.Extension -in '.trx', '.txt', '.log', '.json' })) {
        $text = Get-Content -LiteralPath $file.FullName -Raw
        $redacted = [CodeSignAuto.Acceptance.Contracts.SecretScanPolicy]::Redact($text, '')
        if (-not [string]::Equals($text, $redacted, [System.StringComparison]::Ordinal)) {
            if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'ui_acceptance_sensitive_artifact'
            }
            [System.IO.File]::WriteAllText(
                $file.FullName,
                $redacted,
                [System.Text.UTF8Encoding]::new($false, $true))
        }
        if ([CodeSignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive($redacted, '')) {
            throw 'ui_acceptance_sensitive_artifact'
        }
    }

    return $pngEvidence.ToArray()
}

function Assert-ManifestPngEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][string]$ExpectedFileName,
        [Parameter(Mandatory = $true)][int]$ExpectedSessionId,
        [Parameter(Mandatory = $true)][int]$ExpectedDpi,
        [Parameter(Mandatory = $true)][string]$RunDirectory
    )

    $properties = @(
        'fileName', 'testName', 'sessionId', 'windowPid', 'targetHwnd', 'title', 'dpi',
        'logicalOuter', 'physicalOuter', 'logicalClient', 'physicalClient', 'sha256',
        'captureMethod', 'validatedAnchorCount', 'validatedAnchors', 'currentPageAnchor',
        'secretInputsEmpty', 'secretVerificationMethod')
    Assert-JsonObjectExact -Value $Evidence -ExpectedProperties $properties
    $fileName = Assert-JsonString -Value $Evidence.fileName -MaximumLength 80 -Pattern '^[a-z0-9-]+\.png$'
    $testName = Assert-JsonString -Value $Evidence.testName -MaximumLength 160 -Pattern '^[A-Za-z0-9._]{1,160}$'
    $sessionId = Assert-JsonInteger -Value $Evidence.sessionId -Minimum 1 -Maximum 2147483647
    $windowPid = Assert-JsonInteger -Value $Evidence.windowPid -Minimum 1 -Maximum 2147483647
    $targetHwnd = Assert-JsonString -Value $Evidence.targetHwnd -MaximumLength 32 -Pattern '^0x[1-9A-F][0-9A-F]*$'
    $title = Assert-JsonString -Value $Evidence.title -MaximumLength 80
    $dpi = Assert-JsonInteger -Value $Evidence.dpi -Minimum 96 -Maximum 768
    Assert-JsonRectangle -Value $Evidence.logicalOuter
    Assert-JsonRectangle -Value $Evidence.physicalOuter
    Assert-JsonRectangle -Value $Evidence.logicalClient
    Assert-JsonRectangle -Value $Evidence.physicalClient
    $sha256 = Assert-JsonString -Value $Evidence.sha256 -MaximumLength 64 -Pattern '^[0-9A-F]{64}$'
    $captureMethod = Assert-JsonString -Value $Evidence.captureMethod -MaximumLength 80
    $anchorCount = Assert-JsonInteger -Value $Evidence.validatedAnchorCount -Minimum 3 -Maximum 3
    Assert-JsonStringArray -Value $Evidence.validatedAnchors -ExpectedCount 3 -MaximumElementLength 160
    $anchors = $Evidence.validatedAnchors
    $currentPageAnchor = Assert-JsonString `
        -Value $Evidence.currentPageAnchor `
        -MaximumLength 160 `
        -Pattern '^current_page_title:.{1,80}$'
    $secretEmpty = Assert-JsonBoolean -Value $Evidence.secretInputsEmpty
    $secretMethod = Assert-JsonString -Value $Evidence.secretVerificationMethod -MaximumLength 80

    $png = @(Get-ChildItem -LiteralPath $RunDirectory -Filter $ExpectedFileName -File -Recurse)
    if ($fileName -cne $ExpectedFileName -or
        $testName -cne $Expected.TestName -or
        $sessionId -ne $ExpectedSessionId -or
        $dpi -ne $ExpectedDpi -or
        $title -cne 'CodeSignAuto' -or
        $captureMethod -cne 'PrintWindow.PW_RENDERFULLCONTENT.24bppRgb' -or
        $anchorCount -ne 3 -or
        $anchors[0] -cne 'main_navigation' -or
        $anchors[1] -cne 'fixed_header' -or
        $anchors[2] -cne $Expected.CurrentPageAnchor -or
        $currentPageAnchor -cne $Expected.CurrentPageAnchor -or
        $currentPageAnchor -cne $anchors[2] -or
        $secretEmpty -ne $true -or
        $secretMethod -cne 'UIAutomationValuePattern' -or
        $png.Count -ne 1 -or
        $sha256 -cne (Get-FileHash -LiteralPath $png[0].FullName -Algorithm SHA256).Hash) {
        throw 'ui_acceptance_manifest_invalid'
    }
}

function Assert-ManifestContract {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId,
        [Parameter(Mandatory = $true)][int]$ExpectedSessionId,
        [Parameter(Mandatory = $true)][string]$ExpectedAppHost,
        [Parameter(Mandatory = $true)][string]$RunDirectory
    )

    $manifest = Read-StrictJsonObject -Path $Path
    $properties = @(
        'schemaVersion', 'runId', 'sessionId', 'dpi', 'exitCode', 'trxSha256', 'appSha256',
        'strictJsonSourceSha256',
        'expectedScreenshots', 'pngs')
    Assert-JsonObjectExact -Value $manifest -ExpectedProperties $properties
    $schemaVersion = Assert-JsonInteger -Value $manifest.schemaVersion -Minimum 3 -Maximum 3
    $runId = Assert-JsonString -Value $manifest.runId -MaximumLength 32 -Pattern '^[0-9a-f]{32}$'
    $sessionId = Assert-JsonInteger -Value $manifest.sessionId -Minimum 1 -Maximum 2147483647
    $dpi = Assert-JsonInteger -Value $manifest.dpi -Minimum 96 -Maximum 768
    $exitCode = Assert-JsonInteger -Value $manifest.exitCode -Minimum 0 -Maximum 0
    $trxSha256 = Assert-JsonString -Value $manifest.trxSha256 -MaximumLength 64 -Pattern '^[0-9A-F]{64}$'
    $appSha256 = Assert-JsonString -Value $manifest.appSha256 -MaximumLength 64 -Pattern '^[0-9A-F]{64}$'
    $strictJsonSourceSha256 = Assert-JsonString `
        -Value $manifest.strictJsonSourceSha256 `
        -MaximumLength 64 `
        -Pattern '^[0-9A-F]{64}$'
    Assert-JsonArray -Value $manifest.expectedScreenshots -ExpectedCount $ExpectedPngTests.Count
    Assert-JsonArray -Value $manifest.pngs -ExpectedCount $ExpectedPngTests.Count

    $expectedEntries = @($ExpectedPngTests.GetEnumerator())
    $seenExpectedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    for ($index = 0; $index -lt $expectedEntries.Count; $index++) {
        $expected = $expectedEntries[$index]
        $item = $manifest.expectedScreenshots[$index]
        Assert-JsonObjectExact -Value $item -ExpectedProperties @('pngFileName', 'testName', 'currentPageAnchor')
        $fileName = Assert-JsonString -Value $item.pngFileName -MaximumLength 80 -Pattern '^[a-z0-9-]+\.png$'
        $testName = Assert-JsonString -Value $item.testName -MaximumLength 160 -Pattern '^[A-Za-z0-9._]{1,160}$'
        $pageAnchor = Assert-JsonString `
            -Value $item.currentPageAnchor `
            -MaximumLength 160 `
            -Pattern '^current_page_title:.{1,80}$'
        if (-not $seenExpectedFiles.Add($fileName) -or
            $fileName -cne $expected.Key -or
            $testName -cne $expected.Value.TestName -or
            $pageAnchor -cne $expected.Value.CurrentPageAnchor) {
            throw 'ui_acceptance_manifest_invalid'
        }
    }

    for ($index = 0; $index -lt $expectedEntries.Count; $index++) {
        $expected = $expectedEntries[$index]
        Assert-ManifestPngEvidence `
            -Evidence $manifest.pngs[$index] `
            -Expected $expected.Value `
            -ExpectedFileName $expected.Key `
            -ExpectedSessionId $ExpectedSessionId `
            -ExpectedDpi ([int]$dpi) `
            -RunDirectory $RunDirectory
    }

    $trxPath = Join-Path $RunDirectory 'ui-acceptance.trx'
    if ($schemaVersion -ne 3 -or $runId -cne $ExpectedRunId -or
        $sessionId -ne $ExpectedSessionId -or $exitCode -ne 0 -or
        $strictJsonSourceSha256 -cne $script:StrictJsonSourceSha256 -or
        -not (Test-Path -LiteralPath $trxPath -PathType Leaf) -or
        $trxSha256 -cne (Get-FileHash -LiteralPath $trxPath -Algorithm SHA256).Hash -or
        $appSha256 -cne (Get-FileHash -LiteralPath $ExpectedAppHost -Algorithm SHA256).Hash) {
        throw 'ui_acceptance_manifest_invalid'
    }
}

function Assert-ChildResultContract {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId
    )

    $result = Read-StrictJsonObject -Path $Path
    Assert-JsonObjectExact -Value $result -ExpectedProperties @('schemaVersion', 'result', 'runId')
    $schemaVersion = Assert-JsonInteger -Value $result.schemaVersion -Minimum 1 -Maximum 1
    $resultCode = Assert-JsonString -Value $result.result -MaximumLength 80 -Pattern '^[a-z_]+$'
    $runId = Assert-JsonString -Value $result.runId -MaximumLength 32 -Pattern '^[0-9a-f]{32}$'
    if ($schemaVersion -ne 1 -or $resultCode -cne 'ui_session_unavailable' -or $runId -cne $ExpectedRunId) {
        throw 'ui_acceptance_child_result_invalid'
    }
}

function Invoke-ChildRun {
    $script:DiagnosticStage = 'ui_child_preflight'
    $canonicalRepo = Get-CanonicalExistingPath -Path $RepoPath -Kind Container
    Initialize-TrxPolicy -CanonicalRepo $canonicalRepo
    $canonicalArtifacts = Get-CanonicalExistingPath -Path $ArtifactRoot -Kind Container
    $canonicalDotnet = Get-CanonicalExistingPath -Path $DotnetPath -Kind Leaf
    $canonicalAppHost = Get-CanonicalExistingPath -Path $AppHostPath -Kind Leaf
    $canonicalPowerShell = Get-CanonicalExistingPath -Path $PowerShellPath -Kind Leaf
    $productionValues = @(
        $ProductionExeInput,
        $ProductionPdfInput,
        $ProductionOtpUriFile,
        $ProductionArtifactRoot)
    $productionEnabled = @($productionValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
    if ($productionEnabled -and
        @($productionValues | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
        throw 'ui_production_arguments_invalid'
    }
    $canonicalProductionExe = $null
    $canonicalProductionPdf = $null
    $canonicalProductionOtp = $null
    $canonicalProductionRoot = $null
    if ($productionEnabled) {
        $canonicalProductionExe = Get-CanonicalExistingPath -Path $ProductionExeInput -Kind Leaf
        $canonicalProductionPdf = Get-CanonicalExistingPath -Path $ProductionPdfInput -Kind Leaf
        $canonicalProductionOtp = Get-CanonicalExistingPath -Path $ProductionOtpUriFile -Kind Leaf
        $canonicalProductionRoot = Get-CanonicalExistingPath -Path $ProductionArtifactRoot -Kind Container
        if ([System.IO.Path]::GetExtension($canonicalProductionExe) -ine '.exe' -or
            [System.IO.Path]::GetExtension($canonicalProductionPdf) -ine '.pdf') {
            throw 'ui_production_arguments_invalid'
        }
    }
    Assert-SafeIdentity -Identity $SigningUser
    Assert-SafeIdentity -Identity $AdministratorUser
    Assert-TrustedExecutables -Repo $canonicalRepo -Dotnet $canonicalDotnet -AppHost $canonicalAppHost -PowerShell $canonicalPowerShell
    if (-not [string]::Equals([System.IO.Path]::GetFileName($canonicalArtifacts), $RunId, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals((Get-Content -LiteralPath (Join-Path $canonicalArtifacts 'owner.txt') -Raw), $RunId, [System.StringComparison]::Ordinal)) {
        throw 'ui_acceptance_owner_invalid'
    }

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $currentSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    if (-not [string]::Equals($currentIdentity, $AdministratorUser, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'ui_session_invalid'
    }
    if ($currentSession -le 0 -or
        $currentSession -ne $ExpectedSessionId -or
        -not (Test-WtsActiveSession -SessionId $currentSession)) {
        throw 'ui_session_unavailable'
    }

    $testProject = Join-Path $canonicalRepo 'tests\CodeSignAuto.UI.Tests\CodeSignAuto.UI.Tests.csproj'
    if (-not (Test-Path -LiteralPath $testProject -PathType Leaf)) {
        throw 'test_project_missing'
    }

    $stdoutPath = Join-Path $canonicalArtifacts 'desktop.stdout.txt'
    $stderrPath = Join-Path $canonicalArtifacts 'desktop.stderr.txt'
    $rawDirectory = Join-Path $canonicalArtifacts '.raw'
    $rawTrx = Join-Path $rawDirectory 'results.raw.trx'
    $finalTrx = Join-Path $canonicalArtifacts 'ui-acceptance.trx'
    if ((Test-Path -LiteralPath $stdoutPath) -or (Test-Path -LiteralPath $stderrPath) -or
        (Test-Path -LiteralPath $rawDirectory) -or (Test-Path -LiteralPath $finalTrx)) {
        throw 'ui_acceptance_artifact_collision'
    }
    [System.IO.Directory]::CreateDirectory($rawDirectory) | Out-Null

    $env:SIMPLYSIGN_UI_TEST_APPHOST = $canonicalAppHost
    $env:SIMPLYSIGN_UI_TEST_ARTIFACTS = $canonicalArtifacts
    $env:SIMPLYSIGN_UI_TEST_RUN_ID = $RunId
    try {
        try {
            $arguments = @(
                'test', $testProject,
                '-c', 'Release',
                '--no-restore',
                '--filter', 'Category=Desktop',
                '--logger', 'trx;LogFileName=results.raw.trx',
                '--results-directory', $rawDirectory,
                '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false'
            )
            $desktopExitCode = Invoke-ProcessWithCreateNewLogs `
                -Executable $canonicalDotnet `
                -Arguments $arguments `
                -StdoutPath $stdoutPath `
                -StderrPath $stderrPath
        } finally {
            if (Test-Path -LiteralPath $rawTrx -PathType Leaf) {
                Publish-SafeUiTrx -RawPath $rawTrx -FinalPath $finalTrx -RawDirectory $rawDirectory
            } elseif ((Test-Path -LiteralPath $rawDirectory -PathType Container) -and
                @(Get-ChildItem -LiteralPath $rawDirectory -Force).Count -eq 0) {
                Remove-Item -LiteralPath $rawDirectory -Force
            } else {
                throw 'ui_acceptance_state_uncertain'
            }
        }
    } finally {
        Remove-Item Env:SIMPLYSIGN_UI_TEST_APPHOST -ErrorAction SilentlyContinue
        Remove-Item Env:SIMPLYSIGN_UI_TEST_ARTIFACTS -ErrorAction SilentlyContinue
        Remove-Item Env:SIMPLYSIGN_UI_TEST_RUN_ID -ErrorAction SilentlyContinue
    }

    if ($productionEnabled) {
        $script:DiagnosticStage = 'ui_production_acceptance'
        $productionRaw = Join-Path $canonicalProductionRoot '.raw'
        $productionRawTrx = Join-Path $productionRaw 'results.raw.trx'
        $productionTrx = Join-Path $canonicalProductionRoot 'production-ui.trx'
        $productionStdout = Join-Path $productionRaw 'stdout.txt'
        $productionStderr = Join-Path $productionRaw 'stderr.txt'
        if ((Test-Path -LiteralPath $productionRaw) -or
            (Test-Path -LiteralPath $productionTrx)) {
            throw 'ui_acceptance_artifact_collision'
        }
        [System.IO.Directory]::CreateDirectory($productionRaw) | Out-Null
        $savedProductionEnvironment = [ordered]@{
            Run = $env:SIMPLYSIGN_RUN_PRODUCTION_UI_ACCEPTANCE
            App = $env:SIMPLYSIGN_PRODUCTION_UI_APPHOST
            Exe = $env:SIMPLYSIGN_PRODUCTION_UI_EXE_INPUT
            Pdf = $env:SIMPLYSIGN_PRODUCTION_UI_PDF_INPUT
            Otp = $env:SIMPLYSIGN_PRODUCTION_UI_OTP_URI_FILE
            Output = $env:SIMPLYSIGN_PRODUCTION_UI_ARTIFACT_DIRECTORY
        }
        $env:SIMPLYSIGN_RUN_PRODUCTION_UI_ACCEPTANCE = '1'
        $env:SIMPLYSIGN_PRODUCTION_UI_APPHOST = $canonicalAppHost
        $env:SIMPLYSIGN_PRODUCTION_UI_EXE_INPUT = $canonicalProductionExe
        $env:SIMPLYSIGN_PRODUCTION_UI_PDF_INPUT = $canonicalProductionPdf
        $env:SIMPLYSIGN_PRODUCTION_UI_OTP_URI_FILE = $canonicalProductionOtp
        $env:SIMPLYSIGN_PRODUCTION_UI_ARTIFACT_DIRECTORY = $canonicalProductionRoot
        try {
            $productionArguments = @(
                'test', $testProject,
                '-c', 'Release',
                '--no-restore', '--no-build',
                '--filter', 'FullyQualifiedName=CodeSignAuto.UI.Tests.Desktop.ProductionQuickSignAcceptanceTests.Production_composition_signs_exe_and_pdf_hides_during_completion_and_restores_from_tray',
                '--logger', 'trx;LogFileName=results.raw.trx',
                '--results-directory', $productionRaw,
                '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false'
            )
            $productionExitCode = Invoke-ProcessWithCreateNewLogs `
                -Executable $canonicalDotnet `
                -Arguments $productionArguments `
                -StdoutPath $productionStdout `
                -StderrPath $productionStderr
            $sensitiveProductionLog = $false
            foreach ($logPath in @($productionStdout, $productionStderr)) {
                $logText = Get-Content -LiteralPath $logPath -Raw
                if ([CodeSignAuto.Acceptance.Contracts.SecretScanPolicy]::ContainsSensitive($logText, '')) {
                    $sensitiveProductionLog = $true
                }
                Remove-Item -LiteralPath $logPath -Force
            }
            if ($sensitiveProductionLog) {
                throw 'ui_acceptance_sensitive_artifact'
            }
            if (Test-Path -LiteralPath $productionRawTrx -PathType Leaf) {
                Publish-SafeUiTrx `
                    -RawPath $productionRawTrx `
                    -FinalPath $productionTrx `
                    -RawDirectory $productionRaw
            } else {
                throw 'ui_acceptance_trx_invalid'
            }
            if ($productionExitCode -ne 0 -or
                -not (Test-Path -LiteralPath (Join-Path $canonicalProductionRoot 'production-ui-result.json') -PathType Leaf)) {
                throw 'ui_production_acceptance_failed'
            }
        } finally {
            foreach ($logPath in @($productionStdout, $productionStderr)) {
                if (Test-Path -LiteralPath $logPath -PathType Leaf) {
                    Remove-Item -LiteralPath $logPath -Force
                }
            }
            foreach ($entry in $savedProductionEnvironment.GetEnumerator()) {
                $name = switch ($entry.Key) {
                    'Run' { 'SIMPLYSIGN_RUN_PRODUCTION_UI_ACCEPTANCE' }
                    'App' { 'SIMPLYSIGN_PRODUCTION_UI_APPHOST' }
                    'Exe' { 'SIMPLYSIGN_PRODUCTION_UI_EXE_INPUT' }
                    'Pdf' { 'SIMPLYSIGN_PRODUCTION_UI_PDF_INPUT' }
                    'Otp' { 'SIMPLYSIGN_PRODUCTION_UI_OTP_URI_FILE' }
                    'Output' { 'SIMPLYSIGN_PRODUCTION_UI_ARTIFACT_DIRECTORY' }
                }
                if ($null -eq $entry.Value) {
                    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
                } else {
                    Set-Item "Env:$name" ([string]$entry.Value)
                }
            }
        }
    }

    $dpi = Get-SystemDpi
    if (-not (Test-WtsActiveSession -SessionId $currentSession)) {
        throw 'ui_session_unavailable'
    }
    $pngEvidence = @(Assert-ArtifactGate -RunDirectory $canonicalArtifacts -DesktopExitCode $desktopExitCode -SessionId $currentSession -Dpi $dpi)
    $manifest = [ordered]@{
        schemaVersion = 3
        runId = $RunId
        sessionId = $currentSession
        dpi = $dpi
        exitCode = $desktopExitCode
        trxSha256 = (Get-FileHash -LiteralPath $finalTrx -Algorithm SHA256).Hash
        appSha256 = (Get-FileHash -LiteralPath $canonicalAppHost -Algorithm SHA256).Hash
        strictJsonSourceSha256 = $script:StrictJsonSourceSha256
        expectedScreenshots = @($ExpectedPngTests.GetEnumerator() | ForEach-Object {
            [ordered]@{
                pngFileName = $_.Key
                testName = $_.Value.TestName
                currentPageAnchor = $_.Value.CurrentPageAnchor
            }
        })
        pngs = $pngEvidence
    } | ConvertTo-Json -Compress -Depth 8
    New-CreateNewTextFile -Path (Join-Path $canonicalArtifacts 'manifest.json') -Content $manifest
    [Console]::Out.WriteLine('ui_acceptance_pass')
}

if ($RunChild) {
    try {
        Invoke-ChildRun
        exit 0
    } catch {
        $childError = $_
        $childCode = if ($childError.Exception.Message -cmatch '^ui_[a-z0-9_]+$') {
            $childError.Exception.Message
        } else { 'ui_acceptance_unhandled_exception' }
        Write-UiDiagnostic $childError $childCode $script:DiagnosticStage $ArtifactRoot
        if ($_.Exception.Message -ceq 'ui_session_unavailable') {
            try {
                $childResult = [ordered]@{
                    schemaVersion = 1
                    result = 'ui_session_unavailable'
                    runId = $RunId
                } | ConvertTo-Json -Compress
                New-CreateNewTextFile `
                    -Path (Join-Path $ArtifactRoot 'child-result.json') `
                    -Content $childResult
                Fail-Stable -Code 'ui_session_unavailable' -ExitCode 3
            } catch {
                Write-UiDiagnostic $_ 'ui_acceptance_unhandled_exception' 'ui_child_result_write' $ArtifactRoot
                Fail-Stable -Code 'ui_acceptance_unhandled_exception' -ExitCode 1
            }
        }
        Fail-Stable -Code $childCode -ExitCode 1
    }
}

try {
    $script:DiagnosticStage = 'ui_controller_preflight'
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        Fail-Stable -Code 'ui_windows_required' -ExitCode 2
    }

    $canonicalRepo = Get-CanonicalExistingPath -Path $RepoPath -Kind Container
    $canonicalArtifactRoot = if (Test-Path -LiteralPath $ArtifactRoot) {
        Get-CanonicalExistingPath -Path $ArtifactRoot -Kind Container
    } else {
        if ($ArtifactRoot -notmatch '^[A-Za-z]:\\' -or
            -not [string]::Equals([System.IO.Path]::GetFullPath($ArtifactRoot), $ArtifactRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'artifact_root_invalid'
        }
        [System.IO.Directory]::CreateDirectory($ArtifactRoot) | Out-Null
        Get-CanonicalExistingPath -Path $ArtifactRoot -Kind Container
    }
    $canonicalDotnet = Get-CanonicalExistingPath -Path $DotnetPath -Kind Leaf
    $canonicalAppHost = Get-CanonicalExistingPath -Path $AppHostPath -Kind Leaf
    $canonicalPowerShell = Get-CanonicalExistingPath -Path $PowerShellPath -Kind Leaf
    $canonicalScript = Get-CanonicalExistingPath -Path $PSCommandPath -Kind Leaf
    $productionValues = @(
        $ProductionExeInput,
        $ProductionPdfInput,
        $ProductionOtpUriFile,
        $ProductionArtifactRoot)
    $productionEnabled = @($productionValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
    if ($productionEnabled -and
        @($productionValues | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
        throw 'ui_production_arguments_invalid'
    }
    if ($productionEnabled) {
        $ProductionExeInput = Get-CanonicalExistingPath -Path $ProductionExeInput -Kind Leaf
        $ProductionPdfInput = Get-CanonicalExistingPath -Path $ProductionPdfInput -Kind Leaf
        $ProductionOtpUriFile = Get-CanonicalExistingPath -Path $ProductionOtpUriFile -Kind Leaf
        $ProductionArtifactRoot = Get-CanonicalExistingPath -Path $ProductionArtifactRoot -Kind Container
    }
    Assert-SafeIdentity -Identity $SigningUser
    Assert-SafeIdentity -Identity $AdministratorUser
    Assert-TrustedExecutables -Repo $canonicalRepo -Dotnet $canonicalDotnet -AppHost $canonicalAppHost -PowerShell $canonicalPowerShell
    if (-not (Test-PathUnder -Path $canonicalScript -Root $canonicalRepo)) {
        throw 'script_invalid'
    }

    $sessionId = Get-InteractiveSessionId -Identity $AdministratorUser
    if ($null -eq $sessionId) {
        Fail-Stable -Code 'ui_session_unavailable' -ExitCode 3
    }

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Fail-Stable -Code 'ui_acceptance_task_exists' -ExitCode 4
    }

    $runId = [guid]::NewGuid().ToString('N')
    $runDirectory = Join-Path $canonicalArtifactRoot $runId
    if (Test-Path -LiteralPath $runDirectory) {
        Fail-Stable -Code 'ui_acceptance_artifact_collision' -ExitCode 5
    }
    [System.IO.Directory]::CreateDirectory($runDirectory) | Out-Null
    New-CreateNewTextFile -Path (Join-Path $runDirectory 'owner.txt') -Content $runId

    $ExpectedTaskDescription = "CodeSignAuto UI Acceptance owner=$runId"
    $escaped = @($canonicalScript, $canonicalRepo, $runDirectory, $SigningUser, $AdministratorUser, $canonicalDotnet, $canonicalAppHost, $runId) |
        ForEach-Object { '"' + $_.Replace('"', '""') + '"' }
    $ExpectedActionArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $($escaped[0]) -RunChild -RepoPath $($escaped[1]) -ArtifactRoot $($escaped[2]) -SigningUser $($escaped[3]) -AdministratorUser $($escaped[4]) -DotnetPath $($escaped[5]) -AppHostPath $($escaped[6]) -RunId $($escaped[7]) -ExpectedSessionId $sessionId"
    if ($productionEnabled) {
        $escapedProduction = @(
            $ProductionExeInput,
            $ProductionPdfInput,
            $ProductionOtpUriFile,
            $ProductionArtifactRoot) | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }
        $ExpectedActionArguments += " -ProductionExeInput $($escapedProduction[0]) -ProductionPdfInput $($escapedProduction[1]) -ProductionOtpUriFile $($escapedProduction[2]) -ProductionArtifactRoot $($escapedProduction[3])"
    }
    $action = New-ScheduledTaskAction -Execute $PowerShellPath -Argument $ExpectedActionArguments
    $principal = New-ScheduledTaskPrincipal -UserId $AdministratorUser -LogonType Interactive -RunLevel Highest
    $ExpectedExecutionTimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit $ExpectedExecutionTimeLimit -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Description $ExpectedTaskDescription | Out-Null
    $CreatedTask = $true
    Start-ScheduledTask -TaskName $TaskName

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskName $TaskName
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
    } while (($task.State -eq 'Running' -or $task.State -eq 'Queued' -or
        $info.LastTaskResult -eq 267009 -or $info.LastTaskResult -eq 267011) -and
        $watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)

    if ($task.State -eq 'Running' -or $task.State -eq 'Queued' -or
        $info.LastTaskResult -eq 267009 -or $info.LastTaskResult -eq 267011) {
        Stop-ScheduledTask -TaskName $TaskName
        $StableFailure = 'ui_acceptance_timeout'
    } else {
        $manifestPath = Join-Path $runDirectory 'manifest.json'
        if ($info.LastTaskResult -ne 0 -or -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            [Console]::Error.WriteLine(
                "ui_child_task_result stage=ui_child_wait exit_code=$($info.LastTaskResult) manifest_present=$([bool](Test-Path -LiteralPath $manifestPath -PathType Leaf))")
            $childResultPath = Join-Path $runDirectory 'child-result.json'
            $childUnavailable = $false
            if ($info.LastTaskResult -eq 3 -and (Test-Path -LiteralPath $childResultPath -PathType Leaf)) {
                try {
                    Assert-ChildResultContract -Path $childResultPath -ExpectedRunId $runId
                    $childUnavailable = $true
                } catch {
                    $childUnavailable = $false
                }
            }
            $StableFailure = if ($childUnavailable) { 'ui_session_unavailable' } else { 'ui_acceptance_child_failed' }
        } else {
            Assert-ManifestContract `
                -Path $manifestPath `
                -ExpectedRunId $runId `
                -ExpectedSessionId $sessionId `
                -ExpectedAppHost $canonicalAppHost `
                -RunDirectory $runDirectory
        }
    }
} catch {
    if (-not $StableFailure) {
        $StableFailure = if ($_.Exception.Message -cmatch '^ui_[a-z0-9_]+$') {
            $_.Exception.Message
        } else { 'ui_acceptance_unhandled_exception' }
    }
    Write-UiDiagnostic $_ $StableFailure $script:DiagnosticStage $runDirectory
} finally {
    if ($CreatedTask) {
        try {
            $current = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            $exact = $current.Description -ceq $ExpectedTaskDescription -and
                $current.Principal.UserId -ieq $AdministratorUser -and
                $current.Principal.LogonType -eq 'InteractiveToken' -and
                $current.Principal.RunLevel -eq 'Highest' -and
                @($current.Actions).Count -eq 1 -and
                $current.Actions[0].Execute -ieq $PowerShellPath -and
                $current.Actions[0].Arguments -ceq $ExpectedActionArguments -and
                $current.Settings.ExecutionTimeLimit -eq $ExpectedExecutionTimeLimit
            if ($exact) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            } else {
                $StableFailure = 'ui_acceptance_state_uncertain'
            }
        } catch {
            Write-UiDiagnostic $_ 'ui_acceptance_state_uncertain' 'ui_controller_cleanup_task' $runDirectory
            $StableFailure = 'ui_acceptance_state_uncertain'
        }
    }
}

if ($StableFailure) {
    Fail-Stable -Code $StableFailure -ExitCode 1
}

[Console]::Out.WriteLine('ui_acceptance_pass')
exit 0
