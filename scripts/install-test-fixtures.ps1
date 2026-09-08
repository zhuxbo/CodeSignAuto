[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Cleanup')]
    [string]$RepoPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Cleanup')]
    [string]$RunDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [string]$DotnetPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$DotnetPublisherSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [ValidateLength(1, 1024)]
    [string]$WindowsSystemPublisherSha256Map,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$GenerateNativeFixtures,

    [Parameter(ParameterSetName = 'Install')]
    [string]$MakeCatPath,

    [Parameter(ParameterSetName = 'Install')]
    [string]$MakeCatPublisherSha256,

    [Parameter(ParameterSetName = 'Install')]
    [string]$CscPath,

    [Parameter(ParameterSetName = 'Install')]
    [string]$CscPublisherSha256,

    [Parameter(ParameterSetName = 'Install')]
    [string]$SystemDriverPath,

    [Parameter(ParameterSetName = 'Install')]
    [string]$SystemDriverPublisherSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Cleanup')]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RunId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Cleanup')]
    [switch]$Cleanup,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(60, 600)]
    [int]$TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$dotnetGuard = $null
$taskkillGuard = $null
$taskkillSnapshot = $null
$canonicalTaskkill = $null
$FixtureRootCreated = $false
$FixtureDirectoryForFailure = $null
$FixtureDirectoryIdentity = $null
$FixtureOwnerMarkerHash = $null
$FixtureSentinelPath = $null
$FixtureSentinelIdentity = $null
$FixtureSentinelHash = $null
$FixtureToolGuards = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$windowsSystemPublishers = $null

function Fail-Stable {
    param([Parameter(Mandatory = $true)][string]$Code, [int]$ExitCode = 1)

    [Console]::Out.WriteLine($Code)
    exit $ExitCode
}

function Get-CanonicalExistingPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Container', 'Leaf')][string]$Kind
    )

    if ($Path -notmatch '^[A-Za-z]:\\' -or
        -not [string]::Equals([System.IO.Path]::GetFullPath($Path), $Path, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Path.IndexOfAny([char[]]"`r`n`0") -ge 0) {
        throw 'acceptance_fixture_path_invalid'
    }

    $item = Get-Item -LiteralPath $Path -Force
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'acceptance_fixture_path_invalid'
        }
        $cursor = $cursor.Parent
    }

    if (($Kind -eq 'Container' -and -not $item.PSIsContainer) -or
        ($Kind -eq 'Leaf' -and $item.PSIsContainer)) {
        throw 'acceptance_fixture_path_invalid'
    }

    return $item.FullName
}

function Test-PathUnder {
    param([string]$Path, [string]$Root)

    return $Path.StartsWith(
        $Root.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)
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
        $account = [System.Security.Principal.NTAccount]::new('NT SERVICE', 'TrustedInstaller')
        $trusted.Add([System.Security.Principal.SecurityIdentifier]$account.Translate(
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
        $sid = [System.Security.Principal.SecurityIdentifier]$rule.IdentityReference
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            @($trusted | Where-Object { $_ -eq $sid }).Count -eq 0 -and
            ($rule.FileSystemRights -band $dangerous) -ne 0) {
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
        throw 'acceptance_fixture_dotnet_invalid'
    }
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
    $identity = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($Path, $false)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    return [CodeSignAuto.Acceptance.Contracts.ExecutableTrustSnapshot]::new(
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

function Add-FixtureToolGuard {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$TrustedRoots,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherSha256
    )

    $canonical = Get-CanonicalExistingPath -Path $Path -Kind Leaf
    if ($script:FixtureToolGuards.ContainsKey($canonical)) {
        throw 'acceptance_native_fixture_tool_invalid'
    }
    $stream = [System.IO.FileStream]::new(
        $canonical,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $snapshot = Get-ExecutableTrustSnapshot $canonical $TrustedRoots
        [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
            $snapshot,
            $snapshot,
            $TrustedRoots,
            [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
            $ExpectedPublisherSha256)
        $script:FixtureToolGuards.Add($canonical, [pscustomobject]@{
                Stream = $stream
                Snapshot = $snapshot
                TrustedRoots = @($TrustedRoots)
                ExpectedPublisherSha256 = $ExpectedPublisherSha256
            })
        return $canonical
    } catch {
        $stream.Dispose()
        throw
    }
}

function Assert-FixtureToolGuardUnchanged {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not $script:FixtureToolGuards.ContainsKey($Path)) {
        throw 'acceptance_fixture_executable_untrusted'
    }
    $guard = $script:FixtureToolGuards[$Path]
    [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
        $guard.Snapshot,
        (Get-ExecutableTrustSnapshot $Path ([string[]]$guard.TrustedRoots)),
        [string[]]$guard.TrustedRoots,
        [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
        [string]$guard.ExpectedPublisherSha256)
}

function Close-FixtureToolGuards {
    foreach ($path in @($script:FixtureToolGuards.Keys)) {
        $guard = $script:FixtureToolGuards[$path]
        try {
            Assert-FixtureToolGuardUnchanged $path
        } finally {
            $guard.Stream.Dispose()
            $script:FixtureToolGuards.Remove($path) | Out-Null
        }
    }
}

function Get-UniqueMakeCatPath {
    param([string]$OverridePath)

    if (-not [string]::IsNullOrWhiteSpace($OverridePath)) {
        return Get-CanonicalExistingPath -Path $OverridePath -Kind Leaf
    }
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $kitBin = Get-CanonicalExistingPath -Path (Join-Path $programFilesX86 'Windows Kits\10\bin') -Kind Container
    $candidates = @(Get-ChildItem -LiteralPath $kitBin -Filter 'makecat.exe' -File -Recurse -ErrorAction Stop |
        Where-Object { $_.FullName -match '\\x64\\makecat\.exe$' } |
        ForEach-Object { Get-CanonicalExistingPath -Path $_.FullName -Kind Leaf } |
        Select-Object -Unique)
    if ($candidates.Count -ne 1) { throw 'acceptance_native_fixture_tool_pending' }
    return [string]$candidates[0]
}

function Get-DefaultCscPath {
    param([string]$OverridePath, [string]$CanonicalSystemRoot)

    if (-not [string]::IsNullOrWhiteSpace($OverridePath)) {
        return Get-CanonicalExistingPath -Path $OverridePath -Kind Leaf
    }
    return Get-CanonicalExistingPath `
        -Path (Join-Path $CanonicalSystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe') `
        -Kind Leaf
}

function Get-DefaultSystemDriverPath {
    param([string]$OverridePath, [string]$CanonicalSystemRoot)

    if (-not [string]::IsNullOrWhiteSpace($OverridePath)) {
        return Get-CanonicalExistingPath -Path $OverridePath -Kind Leaf
    }
    return Get-CanonicalExistingPath `
        -Path (Join-Path $CanonicalSystemRoot 'System32\drivers\disk.sys') `
        -Kind Leaf
}

function Initialize-AcceptanceContracts {
    param([Parameter(Mandatory = $true)][string]$CanonicalRepo)

    if ('CodeSignAuto.Acceptance.Contracts.AcceptanceModePolicy' -as [type]) {
        throw 'acceptance_fixture_contract_invalid'
    }

    $sourcePath = Join-Path $CanonicalRepo 'scripts\AcceptanceContracts.cs'
    $canonicalSource = Get-CanonicalExistingPath -Path $sourcePath -Kind Leaf
    if (-not (Test-PathUnder -Path $canonicalSource -Root $CanonicalRepo)) {
        throw 'acceptance_fixture_contract_invalid'
    }

    $bytes = [System.IO.File]::ReadAllBytes($canonicalSource)
    if ($bytes.Length -lt 1024 -or $bytes.Length -gt 262144) {
        throw 'acceptance_fixture_contract_invalid'
    }
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $source = $encoding.GetString($bytes)
    Add-Type `
        -TypeDefinition $source `
        -Language CSharp `
        -ReferencedAssemblies @('System.dll', 'System.Core.dll', 'System.Net.Http.dll', 'System.Xml.dll') `
        -ErrorAction Stop
    if (-not ('CodeSignAuto.Acceptance.Contracts.AcceptanceModePolicy' -as [type])) {
        throw 'acceptance_fixture_contract_invalid'
    }

    $strictJsonPath = Get-CanonicalExistingPath `
        -Path (Join-Path $CanonicalRepo 'scripts\UiAcceptanceStrictJson.cs') `
        -Kind Leaf
    $strictJsonBytes = [System.IO.File]::ReadAllBytes($strictJsonPath)
    if ($strictJsonBytes.Length -lt 1024 -or $strictJsonBytes.Length -gt 262144) {
        throw 'acceptance_fixture_contract_invalid'
    }
    Add-Type `
        -TypeDefinition $encoding.GetString($strictJsonBytes) `
        -Language CSharp `
        -ErrorAction Stop
    if (-not ('CodeSignAuto.UiAcceptance.StrictJson.Preflight' -as [type])) {
        throw 'acceptance_fixture_contract_invalid'
    }
}

function ConvertFrom-StrictJson {
    param([Parameter(Mandatory = $true)][string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json) -or $Json.Length -gt 1048576) {
        throw 'acceptance_fixture_manifest_invalid'
    }
    [CodeSignAuto.UiAcceptance.StrictJson.Preflight]::ValidateObject($Json, 24, 1048576)
    $value = $Json | ConvertFrom-Json
    if ($null -eq $value -or $value -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'acceptance_fixture_manifest_invalid'
    }
    return $value
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    if ($Value -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'acceptance_fixture_manifest_invalid'
    }
    $actual = @($Value.PSObject.Properties.Name)
    [CodeSignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact($Expected, $actual)
}

function New-CreateNewBytes {
    param([string]$Path, [byte[]]$Bytes)

    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function New-CreateNewText {
    param([string]$Path, [string]$Text)

    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    New-CreateNewBytes -Path $Path -Bytes $encoding.GetBytes($Text)
}

function Add-Ascii {
    param([System.IO.MemoryStream]$Stream, [string]$Text)

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Text)
    $Stream.Write($bytes, 0, $bytes.Length)
}

function New-TwoPagePdfBytes {
    $objects = @(
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /CropBox [0 0 612 792] /Resources << /Font << /F1 7 0 R >> >> /Contents 5 0 R >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /CropBox [0 0 612 792] /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>',
        "<< /Length 38 >>`nstream`nBT /F1 12 Tf 72 720 Td (Page 1) Tj ET`nendstream",
        "<< /Length 38 >>`nstream`nBT /F1 12 Tf 72 720 Td (Page 2) Tj ET`nendstream",
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
    )

    $stream = [System.IO.MemoryStream]::new()
    try {
        Add-Ascii -Stream $stream -Text "%PDF-1.7`n%SSA`n"
        $offsets = New-Object System.Collections.Generic.List[long]
        for ($index = 0; $index -lt $objects.Count; $index++) {
            $offsets.Add($stream.Position)
            Add-Ascii -Stream $stream -Text ("{0} 0 obj`n{1}`nendobj`n" -f ($index + 1), $objects[$index])
        }

        $xref = $stream.Position
        Add-Ascii -Stream $stream -Text ("xref`n0 {0}`n0000000000 65535 f `n" -f ($objects.Count + 1))
        foreach ($offset in $offsets) {
            Add-Ascii -Stream $stream -Text (("{0:0000000000} 00000 n `n" -f $offset))
        }
        Add-Ascii -Stream $stream -Text (
            "trailer`n<< /Size {0} /Root 1 0 R >>`nstartxref`n{1}`n%%EOF`n" -f ($objects.Count + 1), $xref)
        return $stream.ToArray()
    } finally {
        $stream.Dispose()
    }
}

function Invoke-BoundedProcess {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [int]$Timeout,
        [string]$WorkingDirectory
    )

    $isDotnet = $null -ne $script:dotnetGuard -and
        [string]::Equals($Executable, $script:dotnetGuard.Name, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $isDotnet -and -not $script:FixtureToolGuards.ContainsKey($Executable)) {
        throw 'acceptance_fixture_executable_untrusted'
    }
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $start.WorkingDirectory = Get-CanonicalExistingPath -Path $WorkingDirectory -Kind Container
    }
    $start.Arguments = (@($Arguments | ForEach-Object {
        if ($_.IndexOfAny([char[]]"`r`n`0`"") -ge 0 -or $_.EndsWith('\', [System.StringComparison]::Ordinal)) {
            throw 'acceptance_fixture_process_argument_invalid'
        }
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' ')

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw 'acceptance_fixture_build_failed'
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Timeout * 1000)) {
            if ($null -eq $script:taskkillGuard -or $null -eq $script:taskkillSnapshot) {
                throw 'acceptance_fixture_executable_untrusted'
            }
            $taskkillAfter = Get-ExecutableTrustSnapshot `
                $script:canonicalTaskkill `
                @((Get-CanonicalExistingPath -Path $env:SystemRoot -Kind Container))
            [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
                $script:taskkillSnapshot,
                $taskkillAfter,
                @((Get-CanonicalExistingPath -Path $env:SystemRoot -Kind Container)),
                [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
                ($script:windowsSystemPublishers.ResolveExpectedPublisherSha256(
                    $script:canonicalTaskkill)))
            $killer = [System.Diagnostics.Process]::Start($script:canonicalTaskkill, "/PID $($process.Id) /T /F")
            if ($null -ne $killer) {
                $killer.WaitForExit(10000) | Out-Null
                $killer.Dispose()
            }
            $taskkillAfter = Get-ExecutableTrustSnapshot `
                $script:canonicalTaskkill `
                @((Get-CanonicalExistingPath -Path $env:SystemRoot -Kind Container))
            [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
                $script:taskkillSnapshot,
                $taskkillAfter,
                @((Get-CanonicalExistingPath -Path $env:SystemRoot -Kind Container)),
                [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
                ($script:windowsSystemPublishers.ResolveExpectedPublisherSha256(
                    $script:canonicalTaskkill)))
            $process.WaitForExit(10000) | Out-Null
            throw 'acceptance_fixture_build_timeout'
        }
        [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($stdout, $stderr), 10000) | Out-Null
        if ($process.ExitCode -ne 0) {
            throw 'acceptance_fixture_build_failed'
        }
    } finally {
        $process.Dispose()
    }
}

function Copy-CreateNewFile {
    param([string]$Source, [string]$Destination)

    $input = [System.IO.File]::Open(
        $Source,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $output = [System.IO.FileStream]::new(
            $Destination,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        try {
            $input.CopyTo($output)
            $output.Flush($true)
        } finally { $output.Dispose() }
    } finally { $input.Dispose() }
}

function New-MinimalMsiFixture {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) { throw 'acceptance_fixture_collision' }
    $installer = $null
    $database = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($Path, 3)
        $queries = @(
            'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)',
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'CodeSignAuto Native Fixture')",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{$([guid]::NewGuid().ToString().ToUpperInvariant())}')",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '1.0.0')",
            "INSERT INTO `Property` (`Property`, `Value`) VALUES ('Manufacturer', 'CodeSignAuto Acceptance')"
        )
        foreach ($query in $queries) {
            $view = $null
            try {
                $view = $database.OpenView($query)
                $view.Execute()
            } finally {
                if ($null -ne $view) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
            }
        }
        $database.Commit()
    } catch {
        throw 'acceptance_native_fixture_build_failed'
    } finally {
        if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
        if ($null -ne $installer) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-Item -LiteralPath $Path).Length -lt 512) {
        throw 'acceptance_native_fixture_build_failed'
    }
}

function New-NativeFixtureSet {
    param(
        [string]$FixtureDirectory,
        [string]$CanonicalMakeCat,
        [string]$CanonicalCsc,
        [string]$CanonicalDriver,
        [int]$Timeout
    )

    $nativeBuild = Join-Path $FixtureDirectory '.native-build'
    [System.IO.Directory]::CreateDirectory($nativeBuild) | Out-Null
    try {
        $source = Join-Path $nativeBuild 'native-fixture.cs'
        New-CreateNewText $source 'public static class CodeSignAutoNativeFixture { public static int Value { get { return 20; } } }'
        $dll = Join-Path $FixtureDirectory 'native-fixture.dll'
        Assert-FixtureToolGuardUnchanged $CanonicalCsc
        Invoke-BoundedProcess `
            -Executable $CanonicalCsc `
            -Arguments @('/nologo', '/target:library', '/optimize+', '/debug-', "/out:$dll", $source) `
            -Timeout $Timeout `
            -WorkingDirectory $nativeBuild
        Assert-FixtureToolGuardUnchanged $CanonicalCsc
        $dllBytes = [System.IO.File]::ReadAllBytes($dll)
        if ($dllBytes.Length -lt 1024 -or $dllBytes[0] -ne 0x4D -or $dllBytes[1] -ne 0x5A -or
            (Get-AuthenticodeSignature -LiteralPath $dll).Status -ne 'NotSigned') {
            throw 'acceptance_native_fixture_build_failed'
        }

        $cdf = Join-Path $nativeBuild 'native-fixture.cdf'
        New-CreateNewText $cdf (@(
                '[CatalogHeader]',
                'Name=native-fixture.cat',
                'PublicVersion=0x00000001',
                'EncodingType=0x00010001',
                'CATATTR1=0x10010001:OSAttr:2:10.0',
                '[CatalogFiles]',
                "<hash>native-fixture.dll=$dll"
            ) -join "`r`n")
        Assert-FixtureToolGuardUnchanged $CanonicalMakeCat
        Invoke-BoundedProcess `
            -Executable $CanonicalMakeCat `
            -Arguments @('/v', $cdf) `
            -Timeout $Timeout `
            -WorkingDirectory $nativeBuild
        Assert-FixtureToolGuardUnchanged $CanonicalMakeCat
        $builtCat = Get-CanonicalExistingPath -Path (Join-Path $nativeBuild 'native-fixture.cat') -Kind Leaf
        $cat = Join-Path $FixtureDirectory 'native-fixture.cat'
        Copy-CreateNewFile $builtCat $cat
        if ((Get-Item -LiteralPath $cat).Length -lt 512 -or
            (Get-AuthenticodeSignature -LiteralPath $cat).Status -ne 'NotSigned') {
            throw 'acceptance_native_fixture_build_failed'
        }

        $driverHash = (Get-FileHash -LiteralPath $CanonicalDriver -Algorithm SHA256).Hash
        Assert-FixtureToolGuardUnchanged $CanonicalDriver
        $sys = Join-Path $FixtureDirectory 'native-fixture.sys'
        Copy-CreateNewFile $CanonicalDriver $sys
        Assert-FixtureToolGuardUnchanged $CanonicalDriver
        if ((Get-FileHash -LiteralPath $CanonicalDriver -Algorithm SHA256).Hash -cne $driverHash -or
            (Get-FileHash -LiteralPath $sys -Algorithm SHA256).Hash -cne $driverHash -or
            (Get-AuthenticodeSignature -LiteralPath $sys).Status -ne 'Valid') {
            throw 'acceptance_native_fixture_build_failed'
        }

        New-MinimalMsiFixture (Join-Path $FixtureDirectory 'native-fixture.msi')
        if ((Get-AuthenticodeSignature -LiteralPath (Join-Path $FixtureDirectory 'native-fixture.msi')).Status -ne 'NotSigned') {
            throw 'acceptance_native_fixture_build_failed'
        }
    } finally {
        if (Test-Path -LiteralPath $nativeBuild -PathType Container) {
            $buildItem = Get-Item -LiteralPath $nativeBuild -Force
            if (($buildItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'acceptance_fixture_cleanup_uncertain'
            }
            Remove-Item -LiteralPath $nativeBuild -Recurse -Force
        }
    }
}

function Get-FixtureEntry {
    param(
        [string]$FixtureDirectory,
        [string]$RelativePath,
        [ValidateSet('ordinary', 'hardlink', 'reparse')][string]$Kind,
        [bool]$CleanupEntry
    )

    $path = Join-Path $FixtureDirectory $RelativePath
    $item = Get-Item -LiteralPath $path -Force
    $reparse = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    if (($Kind -eq 'reparse') -ne $reparse -or $item.PSIsContainer) {
        throw 'acceptance_fixture_manifest_invalid'
    }
    $identity = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($path, $false)
    $sha = if ($Kind -eq 'reparse') { $null } else { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    return [ordered]@{
        relativePath = $RelativePath
        kind = $Kind
        sha256 = $sha
        identity = $identity.Identity
        linkCount = [int]$identity.LinkCount
        cleanup = $CleanupEntry
    }
}

function Assert-RunOwner {
    param([string]$CanonicalRun, [string]$ExpectedRunId)

    if (-not [string]::Equals([System.IO.Path]::GetFileName($CanonicalRun), $ExpectedRunId, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals(
            (Get-Content -LiteralPath (Join-Path $CanonicalRun 'owner.txt') -Raw),
            $ExpectedRunId,
            [System.StringComparison]::Ordinal)) {
        throw 'acceptance_fixture_owner_invalid'
    }
}

function Invoke-FixtureFailureCleanup {
    if ($null -ne $script:dotnetGuard) {
        try { $script:dotnetGuard.Dispose() } finally { $script:dotnetGuard = $null }
    }
    if ($null -ne $script:taskkillGuard) {
        try { $script:taskkillGuard.Dispose() } finally { $script:taskkillGuard = $null }
    }
    foreach ($path in @($script:FixtureToolGuards.Keys)) {
        try { $script:FixtureToolGuards[$path].Stream.Dispose() } finally {
            $script:FixtureToolGuards.Remove($path) | Out-Null
        }
    }

    if ($script:FixtureRootCreated) {
        if ([string]::IsNullOrWhiteSpace($script:FixtureDirectoryForFailure) -or
            -not (Test-Path -LiteralPath $script:FixtureDirectoryForFailure -PathType Container)) {
            throw 'acceptance_fixture_cleanup_uncertain'
        }
        $rootItem = Get-Item -LiteralPath $script:FixtureDirectoryForFailure -Force
        $rootIdentity = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read(
            $script:FixtureDirectoryForFailure,
            $true)
        if ([string]::IsNullOrWhiteSpace($script:FixtureDirectoryIdentity)) {
            $script:FixtureDirectoryIdentity = $rootIdentity.Identity
        }
        $marker = Join-Path $script:FixtureDirectoryForFailure 'fixture-owner.txt'
        if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $rootIdentity.Identity -cne $script:FixtureDirectoryIdentity) {
            throw 'acceptance_fixture_cleanup_uncertain'
        }
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            $actualMarkerHash = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
            if ([string]::IsNullOrWhiteSpace($script:FixtureOwnerMarkerHash)) {
                $script:FixtureOwnerMarkerHash = $actualMarkerHash
            }
            if ((Get-Content -LiteralPath $marker -Raw) -cne $RunId -or
                $actualMarkerHash -cne $script:FixtureOwnerMarkerHash) {
                throw 'acceptance_fixture_cleanup_uncertain'
            }
        } elseif (@(Get-ChildItem -LiteralPath $script:FixtureDirectoryForFailure -Force).Count -ne 0) {
            throw 'acceptance_fixture_cleanup_uncertain'
        }
        foreach ($link in @(Get-ChildItem -LiteralPath $script:FixtureDirectoryForFailure -Force -Recurse |
                Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 })) {
            if (-not (Test-PathUnder -Path $link.FullName -Root $script:FixtureDirectoryForFailure)) {
                throw 'acceptance_fixture_cleanup_uncertain'
            }
            Remove-Item -LiteralPath $link.FullName -Force
        }
        Remove-Item -LiteralPath $script:FixtureDirectoryForFailure -Recurse -Force
        if (Test-Path -LiteralPath $script:FixtureDirectoryForFailure) {
            throw 'acceptance_fixture_cleanup_uncertain'
        }
    }

    if ($null -ne $script:FixtureSentinelPath) {
        if (-not (Test-Path -LiteralPath $script:FixtureSentinelPath -PathType Leaf)) { return }
        $sentinelCurrent = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read(
            $script:FixtureSentinelPath,
            $false)
        $sentinelCurrentHash = (Get-FileHash -LiteralPath $script:FixtureSentinelPath -Algorithm SHA256).Hash
        if ([string]::IsNullOrWhiteSpace($script:FixtureSentinelIdentity)) {
            $script:FixtureSentinelIdentity = $sentinelCurrent.Identity
        }
        if ([string]::IsNullOrWhiteSpace($script:FixtureSentinelHash)) {
            $script:FixtureSentinelHash = $sentinelCurrentHash
        }
        if ($sentinelCurrent.Identity -cne $script:FixtureSentinelIdentity -or
            $sentinelCurrentHash -cne $script:FixtureSentinelHash -or
            -not [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::DeleteOrdinaryFileIfExact(
                $script:FixtureSentinelPath,
                $script:FixtureSentinelIdentity,
                $script:FixtureSentinelHash) -or
            (Test-Path -LiteralPath $script:FixtureSentinelPath)) {
            throw 'acceptance_fixture_cleanup_uncertain'
        }
    }
}

function Invoke-FixtureCleanup {
    param([string]$CanonicalRun, [string]$ExpectedRunId)

    $fixtureDirectory = Get-CanonicalExistingPath -Path (Join-Path $CanonicalRun 'fixtures') -Kind Container
    $manifestPath = Get-CanonicalExistingPath -Path (Join-Path $fixtureDirectory 'fixture-manifest.json') -Kind Leaf
    $manifest = ConvertFrom-StrictJson (Get-Content -LiteralPath $manifestPath -Raw)
    Assert-ExactProperties $manifest @(
        'schemaVersion', 'runId', 'pdfPageCount', 'pdfSecondPageCropBox',
        'visibleSignatureBox', 'entries', 'sentinelFileName', 'sentinelIdentity', 'sentinelSha256')
    if ($manifest.schemaVersion -isnot [int] -or $manifest.schemaVersion -ne 2 -or
        $manifest.runId -isnot [string] -or $manifest.runId -cne $ExpectedRunId -or
        $manifest.pdfPageCount -isnot [int] -or $manifest.pdfPageCount -ne 2 -or
        $manifest.pdfSecondPageCropBox -isnot [System.Array] -or @($manifest.pdfSecondPageCropBox).Count -ne 4 -or
        (@($manifest.pdfSecondPageCropBox) -join ',') -cne '0,0,612,792' -or
        $manifest.visibleSignatureBox -isnot [System.Array] -or @($manifest.visibleSignatureBox).Count -ne 4 -or
        (@($manifest.visibleSignatureBox) -join ',') -cne '200,642,548,680' -or
        $manifest.entries -isnot [System.Array] -or
        $manifest.sentinelFileName -isnot [string] -or
        $manifest.sentinelFileName -cne 'fixture-external-sentinel.bin' -or
        $manifest.sentinelIdentity -isnot [string] -or
        $manifest.sentinelIdentity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{8}:[0-9A-F]{8}$' -or
        $manifest.sentinelSha256 -isnot [string] -or $manifest.sentinelSha256 -cnotmatch '^[0-9A-F]{64}$') {
        throw 'acceptance_fixture_manifest_invalid'
    }

    $entries = @($manifest.entries)
    $baseRelativePaths = @(
        'corrupt.pdf', 'fake.exe', 'hardlink-alias.bin', 'hardlink-source.bin',
        'path-swap-a.bin', 'path-swap-b.bin', 'reparse-link.bin', 'reparse-target.bin',
        'two-page.pdf', 'unsigned-x64.exe', 'wrong-extension.pdf')
    $nativeRelativePaths = @(
        'native-fixture.msi', 'native-fixture.cat', 'native-fixture.sys', 'native-fixture.dll')
    if ($entries.Count -ne $baseRelativePaths.Count -and
        $entries.Count -ne ($baseRelativePaths.Count + $nativeRelativePaths.Count)) {
        throw 'acceptance_fixture_manifest_invalid'
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in $entries) {
        Assert-ExactProperties $entry @('relativePath', 'kind', 'sha256', 'identity', 'linkCount', 'cleanup')
        if ($entry.relativePath -isnot [string] -or
            $entry.relativePath -cnotmatch '^[a-z0-9.-]{1,80}$' -or
            -not $seen.Add([string]$entry.relativePath) -or
            $entry.kind -isnot [string] -or $entry.kind -cnotmatch '^(ordinary|hardlink|reparse)$' -or
            $entry.identity -isnot [string] -or $entry.identity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{8}:[0-9A-F]{8}$' -or
            $entry.linkCount -isnot [int] -or $entry.linkCount -lt 1 -or $entry.linkCount -gt 2 -or
            $entry.cleanup -isnot [bool] -or
            ($entry.kind -ceq 'reparse' -and $null -ne $entry.sha256) -or
            ($entry.kind -cne 'reparse' -and
                ($entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '^[0-9A-F]{64}$'))) {
            throw 'acceptance_fixture_manifest_invalid'
        }
    }

    if (@($entries | Where-Object { $_.cleanup -ne $true }).Count -ne 0) {
        throw 'acceptance_fixture_manifest_invalid'
    }
    [CodeSignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact(
        $(if ($entries.Count -eq $baseRelativePaths.Count) {
            $baseRelativePaths
        } else {
            $baseRelativePaths + $nativeRelativePaths
        }),
        @($entries | ForEach-Object { $_.relativePath }))

    $sentinelPath = Get-CanonicalExistingPath `
        -Path (Join-Path $CanonicalRun ([string]$manifest.sentinelFileName)) `
        -Kind Leaf
    if (Test-PathUnder -Path $sentinelPath -Root $fixtureDirectory) {
        throw 'acceptance_fixture_manifest_invalid'
    }
    $sentinelIdentity = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($sentinelPath, $false)
    if ($sentinelIdentity.Identity -cne [string]$manifest.sentinelIdentity -or
        $sentinelIdentity.LinkCount -ne 1 -or
        (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash -cne [string]$manifest.sentinelSha256) {
        throw 'acceptance_fixture_cleanup_uncertain'
    }
    [CodeSignAuto.Acceptance.Contracts.SentinelLayoutPolicy]::Validate(
        $fixtureDirectory,
        $sentinelPath,
        [string]$manifest.sentinelIdentity,
        $sentinelIdentity.Identity,
        ([string]$manifest.sentinelSha256).ToLowerInvariant(),
        (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash.ToLowerInvariant())

    $actualNames = @(Get-ChildItem -LiteralPath $fixtureDirectory -Force | ForEach-Object { $_.Name })
    $expectedNames = @($entries | ForEach-Object { $_.relativePath }) + @('fixture-manifest.json', 'fixture-owner.txt')
    [CodeSignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact($expectedNames, $actualNames)

    # Validate the complete batch before deleting the first entry.
    foreach ($entry in $entries) {
        $path = Join-Path $fixtureDirectory ([string]$entry.relativePath)
        $item = Get-Item -LiteralPath $path -Force
        $identity = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($path, $false)
        $isReparse = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        if ($item.PSIsContainer -or $identity.Identity -cne [string]$entry.identity -or
            [int]$identity.LinkCount -ne [int]$entry.linkCount -or
            $isReparse -ne ($entry.kind -ceq 'reparse') -or
            ($entry.kind -cne 'reparse' -and
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string]$entry.sha256)) {
            throw 'acceptance_fixture_cleanup_uncertain'
        }
    }

    $hardlinks = @($entries | Where-Object { $_.cleanup -eq $true -and $_.kind -eq 'hardlink' })
    if ($hardlinks.Count -ne 2 -or $hardlinks[0].identity -cne $hardlinks[1].identity -or
        $hardlinks[0].sha256 -cne $hardlinks[1].sha256 -or
        $hardlinks[0].linkCount -ne 2 -or $hardlinks[1].linkCount -ne 2) {
        throw 'acceptance_fixture_cleanup_uncertain'
    }

    foreach ($entry in @($entries | Where-Object { $_.cleanup -eq $true -and $_.kind -eq 'reparse' })) {
        $path = Join-Path $fixtureDirectory ([string]$entry.relativePath)
        Remove-Item -LiteralPath $path -Force
    }
    foreach ($entry in @($entries | Where-Object { $_.cleanup -eq $true -and $_.kind -eq 'ordinary' })) {
        $path = Join-Path $fixtureDirectory ([string]$entry.relativePath)
        Remove-Item -LiteralPath $path -Force
    }
    foreach ($entry in $hardlinks) {
        Remove-Item -LiteralPath (Join-Path $fixtureDirectory ([string]$entry.relativePath)) -Force
    }

    if ((Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash -cne [string]$manifest.sentinelSha256 -or
        $sentinelIdentity.Identity -cne [string]$manifest.sentinelIdentity -or $sentinelIdentity.LinkCount -ne 1) {
        throw 'acceptance_fixture_cleanup_uncertain'
    }
    [CodeSignAuto.Acceptance.Contracts.SentinelLayoutPolicy]::Validate(
        $fixtureDirectory,
        $sentinelPath,
        [string]$manifest.sentinelIdentity,
        $sentinelIdentity.Identity,
        ([string]$manifest.sentinelSha256).ToLowerInvariant(),
        (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash.ToLowerInvariant())
    [CodeSignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact(
        @('fixture-manifest.json', 'fixture-owner.txt'),
        @(Get-ChildItem -LiteralPath $fixtureDirectory -Force | ForEach-Object { $_.Name }))

    [Console]::Out.WriteLine('acceptance_fixture_cleanup_pass')
}

try {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        Fail-Stable -Code 'acceptance_windows_required' -ExitCode 2
    }

    $canonicalRun = Get-CanonicalExistingPath -Path $RunDirectory -Kind Container
    Assert-RunOwner -CanonicalRun $canonicalRun -ExpectedRunId $RunId

    $canonicalRepoForContracts = Get-CanonicalExistingPath -Path $RepoPath -Kind Container
    Assert-TrustedRootAcl $canonicalRepoForContracts
    Initialize-AcceptanceContracts -CanonicalRepo $canonicalRepoForContracts

    if ($Cleanup) {
        Invoke-FixtureCleanup -CanonicalRun $canonicalRun -ExpectedRunId $RunId
        exit 0
    }

    $script:windowsSystemPublishers =
        [CodeSignAuto.Acceptance.Contracts.WindowsSystemPublisherMapPolicy]::Parse(
            $WindowsSystemPublisherSha256Map)

    $canonicalDotnet = Get-CanonicalExistingPath -Path $DotnetPath -Kind Leaf
    $canonicalProgramFiles = Get-CanonicalExistingPath -Path $env:ProgramFiles -Kind Container
    $canonicalSystemRoot = Get-CanonicalExistingPath -Path $env:SystemRoot -Kind Container
    $script:canonicalTaskkill = Get-CanonicalExistingPath `
        -Path (Join-Path $canonicalSystemRoot 'System32\taskkill.exe') `
        -Kind Leaf
    if (-not [string]::Equals([System.IO.Path]::GetFileName($canonicalDotnet), 'dotnet.exe', [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::IsWithinTrustedRoot(
            $canonicalDotnet, @($canonicalRepoForContracts, $canonicalProgramFiles))) {
        throw 'acceptance_fixture_dotnet_invalid'
    }
    $script:dotnetGuard = [System.IO.FileStream]::new(
        $canonicalDotnet,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $dotnetSnapshot = Get-ExecutableTrustSnapshot `
        $canonicalDotnet `
        @($canonicalRepoForContracts, $canonicalProgramFiles)
    [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
        $dotnetSnapshot,
        $dotnetSnapshot,
        @($canonicalRepoForContracts, $canonicalProgramFiles),
        [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
        $DotnetPublisherSha256)
    $script:taskkillGuard = [System.IO.FileStream]::new(
        $script:canonicalTaskkill,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $script:taskkillSnapshot = Get-ExecutableTrustSnapshot `
        $script:canonicalTaskkill `
        @($canonicalSystemRoot)
    [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
        $script:taskkillSnapshot,
        $script:taskkillSnapshot,
        @($canonicalSystemRoot),
        [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
        ($script:windowsSystemPublishers.ResolveExpectedPublisherSha256(
            $script:canonicalTaskkill)))

    $canonicalMakeCat = $null
    $canonicalCsc = $null
    $canonicalDriver = $null
    if ($GenerateNativeFixtures) {
        [CodeSignAuto.Acceptance.Contracts.NativeFixtureSourcePolicy]::ValidateToolPublisherHashes(
            [CodeSignAuto.Acceptance.Contracts.NativeFixtureSourceMode]::AutoGenerated,
            $MakeCatPublisherSha256,
            $CscPublisherSha256,
            $SystemDriverPublisherSha256)
        $canonicalProgramFilesX86 = Get-CanonicalExistingPath `
            -Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)) `
            -Kind Container
        Assert-TrustedRootAcl $canonicalProgramFilesX86
        $resolvedMakeCat = Get-UniqueMakeCatPath $MakeCatPath
        $resolvedCsc = Get-DefaultCscPath $CscPath $canonicalSystemRoot
        $resolvedDriver = Get-DefaultSystemDriverPath $SystemDriverPath $canonicalSystemRoot
        if ([System.IO.Path]::GetFileName($resolvedMakeCat) -ine 'makecat.exe' -or
            [System.IO.Path]::GetFileName($resolvedCsc) -ine 'csc.exe' -or
            [System.IO.Path]::GetExtension($resolvedDriver) -ine '.sys') {
            throw 'acceptance_native_fixture_tool_invalid'
        }
        $canonicalMakeCat = Add-FixtureToolGuard `
            $resolvedMakeCat `
            @($canonicalProgramFilesX86) `
            $MakeCatPublisherSha256
        $canonicalCsc = Add-FixtureToolGuard `
            $resolvedCsc `
            @($canonicalSystemRoot) `
            $CscPublisherSha256
        $canonicalDriver = Add-FixtureToolGuard `
            $resolvedDriver `
            @($canonicalSystemRoot) `
            $SystemDriverPublisherSha256
    }

    $fixtureDirectory = Join-Path $canonicalRun 'fixtures'
    if (Test-Path -LiteralPath $fixtureDirectory) {
        throw 'acceptance_fixture_collision'
    }
    [System.IO.Directory]::CreateDirectory($fixtureDirectory) | Out-Null
    $script:FixtureRootCreated = $true
    $script:FixtureDirectoryForFailure = $fixtureDirectory
    $script:FixtureDirectoryIdentity = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read(
        $fixtureDirectory,
        $true).Identity
    $ownerMarker = Join-Path $fixtureDirectory 'fixture-owner.txt'
    New-CreateNewText -Path $ownerMarker -Text $RunId
    $script:FixtureOwnerMarkerHash = (Get-FileHash -LiteralPath $ownerMarker -Algorithm SHA256).Hash

    $sentinelPath = Join-Path $canonicalRun 'fixture-external-sentinel.bin'
    if (Test-Path -LiteralPath $sentinelPath) { throw 'acceptance_fixture_collision' }
    $script:FixtureSentinelPath = $sentinelPath
    New-CreateNewText -Path $sentinelPath -Text 'SSA preserved sentinel'
    $sentinelIdentity = [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::Read($sentinelPath, $false)
    $script:FixtureSentinelIdentity = $sentinelIdentity.Identity
    $script:FixtureSentinelHash = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash

    $buildDirectory = Join-Path $fixtureDirectory '.build'
    [System.IO.Directory]::CreateDirectory($buildDirectory) | Out-Null
    try {
        $project = Get-CanonicalExistingPath `
            -Path (Join-Path $canonicalRepoForContracts 'tests\CodeSignAuto.Agent.Tests\Fixtures\UnsignedHello\UnsignedHello.csproj') `
            -Kind Leaf
        Invoke-BoundedProcess `
            -Executable $canonicalDotnet `
            -Arguments @(
                'publish', $project, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'false',
                '--no-restore', '-p:UseAppHost=true', '-p:DebugType=None', '-p:DebugSymbols=false',
                '-m:1', '-nodeReuse:false', '-p:UseSharedCompilation=false', '-o', $buildDirectory) `
            -Timeout $TimeoutSeconds
        $dotnetAfter = Get-ExecutableTrustSnapshot `
            $canonicalDotnet `
            @($canonicalRepoForContracts, $canonicalProgramFiles)
        [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
            $dotnetSnapshot,
            $dotnetAfter,
            @($canonicalRepoForContracts, $canonicalProgramFiles),
            [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
            $DotnetPublisherSha256)
        $taskkillAfter = Get-ExecutableTrustSnapshot `
            $script:canonicalTaskkill `
            @($canonicalSystemRoot)
        [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
            $script:taskkillSnapshot,
            $taskkillAfter,
            @($canonicalSystemRoot),
            [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
            ($script:windowsSystemPublishers.ResolveExpectedPublisherSha256(
                $script:canonicalTaskkill)))
        $script:dotnetGuard.Dispose()
        $script:dotnetGuard = $null
        $builtExe = Get-CanonicalExistingPath -Path (Join-Path $buildDirectory 'UnsignedHello.exe') -Kind Leaf
        $unsignedPath = Join-Path $fixtureDirectory 'unsigned-x64.exe'
        $inputStream = [System.IO.File]::Open($builtExe, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $outputStream = [System.IO.FileStream]::new($unsignedPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $inputStream.CopyTo($outputStream)
                $outputStream.Flush($true)
            } finally {
                $outputStream.Dispose()
            }
        } finally {
            $inputStream.Dispose()
        }
    } finally {
        if (Test-Path -LiteralPath $buildDirectory -PathType Container) {
            if ((Get-Item -LiteralPath $buildDirectory -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw 'acceptance_fixture_cleanup_uncertain'
            }
            Remove-Item -LiteralPath $buildDirectory -Recurse -Force
        }
    }

    $unsignedBytes = [System.IO.File]::ReadAllBytes((Join-Path $fixtureDirectory 'unsigned-x64.exe'))
    if ($unsignedBytes.Length -lt 1024 -or $unsignedBytes[0] -ne 0x4D -or $unsignedBytes[1] -ne 0x5A -or
        (Get-AuthenticodeSignature -LiteralPath (Join-Path $fixtureDirectory 'unsigned-x64.exe')).Status -ne 'NotSigned') {
        throw 'acceptance_fixture_pe_invalid'
    }

    New-CreateNewBytes -Path (Join-Path $fixtureDirectory 'two-page.pdf') -Bytes (New-TwoPagePdfBytes)
    New-CreateNewText -Path (Join-Path $fixtureDirectory 'corrupt.pdf') -Text '%PDF-1.7 corrupt no xref'
    New-CreateNewText -Path (Join-Path $fixtureDirectory 'fake.exe') -Text 'MZ-not-a-portable-executable'
    New-CreateNewBytes -Path (Join-Path $fixtureDirectory 'wrong-extension.pdf') -Bytes $unsignedBytes
    New-CreateNewText -Path (Join-Path $fixtureDirectory 'hardlink-source.bin') -Text 'SSA hardlink fixture'
    [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::CreateHardLink(
        (Join-Path $fixtureDirectory 'hardlink-alias.bin'),
        (Join-Path $fixtureDirectory 'hardlink-source.bin'))
    New-CreateNewText -Path (Join-Path $fixtureDirectory 'reparse-target.bin') -Text 'SSA reparse sentinel'
    [CodeSignAuto.Acceptance.Contracts.WindowsFileIdentity]::CreateFileSymbolicLink(
        (Join-Path $fixtureDirectory 'reparse-link.bin'),
        (Join-Path $fixtureDirectory 'reparse-target.bin'))
    New-CreateNewText -Path (Join-Path $fixtureDirectory 'path-swap-a.bin') -Text 'SSA path swap A'
    New-CreateNewText -Path (Join-Path $fixtureDirectory 'path-swap-b.bin') -Text 'SSA path swap B'
    if ($GenerateNativeFixtures) {
        New-NativeFixtureSet `
            $fixtureDirectory `
            $canonicalMakeCat `
            $canonicalCsc `
            $canonicalDriver `
            $TimeoutSeconds
        Close-FixtureToolGuards
    }
    $taskkillAfter = Get-ExecutableTrustSnapshot `
        $script:canonicalTaskkill `
        @($canonicalSystemRoot)
    [CodeSignAuto.Acceptance.Contracts.TrustedExecutablePolicy]::Validate(
        $script:taskkillSnapshot,
        $taskkillAfter,
        @($canonicalSystemRoot),
        [CodeSignAuto.Acceptance.Contracts.ExecutableTrustKind]::PlatformPublisher,
        ($script:windowsSystemPublishers.ResolveExpectedPublisherSha256(
            $script:canonicalTaskkill)))
    $script:taskkillGuard.Dispose()
    $script:taskkillGuard = $null
    $entries = @(
        Get-FixtureEntry $fixtureDirectory 'corrupt.pdf' 'ordinary' $true
        Get-FixtureEntry $fixtureDirectory 'fake.exe' 'ordinary' $true
        Get-FixtureEntry $fixtureDirectory 'hardlink-alias.bin' 'hardlink' $true
        Get-FixtureEntry $fixtureDirectory 'hardlink-source.bin' 'hardlink' $true
        Get-FixtureEntry $fixtureDirectory 'path-swap-a.bin' 'ordinary' $true
        Get-FixtureEntry $fixtureDirectory 'path-swap-b.bin' 'ordinary' $true
        Get-FixtureEntry $fixtureDirectory 'reparse-link.bin' 'reparse' $true
        Get-FixtureEntry $fixtureDirectory 'reparse-target.bin' 'ordinary' $true
        Get-FixtureEntry $fixtureDirectory 'two-page.pdf' 'ordinary' $true
        Get-FixtureEntry $fixtureDirectory 'unsigned-x64.exe' 'ordinary' $true
        Get-FixtureEntry $fixtureDirectory 'wrong-extension.pdf' 'ordinary' $true
    )
    if ($GenerateNativeFixtures) {
        $entries += @(
            Get-FixtureEntry $fixtureDirectory 'native-fixture.msi' 'ordinary' $true
            Get-FixtureEntry $fixtureDirectory 'native-fixture.cat' 'ordinary' $true
            Get-FixtureEntry $fixtureDirectory 'native-fixture.sys' 'ordinary' $true
            Get-FixtureEntry $fixtureDirectory 'native-fixture.dll' 'ordinary' $true
        )
    }
    if (@($entries | Where-Object { $_.kind -eq 'hardlink' -and $_.linkCount -ne 2 }).Count -ne 0) {
        throw 'acceptance_fixture_hardlink_failed'
    }

    $manifest = [ordered]@{
        schemaVersion = 2
        runId = $RunId
        pdfPageCount = 2
        pdfSecondPageCropBox = @(0, 0, 612, 792)
        visibleSignatureBox = @(200, 642, 548, 680)
        entries = $entries
        sentinelFileName = 'fixture-external-sentinel.bin'
        sentinelIdentity = $script:FixtureSentinelIdentity
        sentinelSha256 = $script:FixtureSentinelHash
    } | ConvertTo-Json -Compress -Depth 6
    New-CreateNewText -Path (Join-Path $fixtureDirectory 'fixture-manifest.json') -Text $manifest

    $actual = @(Get-ChildItem -LiteralPath $fixtureDirectory -Force | ForEach-Object { $_.Name })
    $expected = @($entries | ForEach-Object { $_.relativePath }) + @('fixture-manifest.json', 'fixture-owner.txt')
    [CodeSignAuto.Acceptance.Contracts.ArtifactSetPolicy]::ValidateExact($expected, $actual)
    [Console]::Out.WriteLine('acceptance_fixtures_ready')
    exit 0
} catch {
    $failure = 'acceptance_fixture_failed'
    try { Invoke-FixtureFailureCleanup } catch { $failure = 'acceptance_fixture_cleanup_uncertain' }
    Fail-Stable -Code $failure -ExitCode 1
}
