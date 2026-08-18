[CmdletBinding()]
param(
    [Parameter()]
    [string]$ManifestPath,

    [Parameter()]
    [string]$ReleaseMediaRoot,

    [Parameter()]
    [switch]$VerifyMediaOnly
)

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $PSScriptRoot 'runtime-prerequisites.json'
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:SecureDownloadDirectory = $null
$releasePublisherCertificateSha256 = '__SIMPLYSIGNAUTO_PUBLISHER_CERTIFICATE_SHA256__'
$releaseNativeTypeBase64 = 'dXNpbmcgU3lzdGVtOyB1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7IHVzaW5nIE1pY3Jvc29mdC5XaW4zMi5TYWZlSGFuZGxlczsgbmFtZXNwYWNlIFNpbXBseVNpZ25BdXRvLlJlbGVhc2UgeyBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuU2VxdWVudGlhbCldIHB1YmxpYyBzdHJ1Y3QgRmlsZUluZm9ybWF0aW9uIHsgcHVibGljIHVpbnQgRmlsZUF0dHJpYnV0ZXM7IHB1YmxpYyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuQ29tVHlwZXMuRklMRVRJTUUgQ3JlYXRpb25UaW1lOyBwdWJsaWMgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzLkZJTEVUSU1FIExhc3RBY2Nlc3NUaW1lOyBwdWJsaWMgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzLkZJTEVUSU1FIExhc3RXcml0ZVRpbWU7IHB1YmxpYyB1aW50IFZvbHVtZVNlcmlhbE51bWJlcjsgcHVibGljIHVpbnQgRmlsZVNpemVIaWdoOyBwdWJsaWMgdWludCBGaWxlU2l6ZUxvdzsgcHVibGljIHVpbnQgbk51bWJlck9mTGlua3M7IHB1YmxpYyB1aW50IEZpbGVJbmRleEhpZ2g7IHB1YmxpYyB1aW50IEZpbGVJbmRleExvdzsgfSBwdWJsaWMgc3RhdGljIGNsYXNzIE5hdGl2ZU1ldGhvZHMgeyBbRGxsSW1wb3J0KCJrZXJuZWwzMi5kbGwiLCBTZXRMYXN0RXJyb3I9dHJ1ZSldIFtyZXR1cm46IE1hcnNoYWxBcyhVbm1hbmFnZWRUeXBlLkJvb2wpXSBwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIEdldEZpbGVJbmZvcm1hdGlvbkJ5SGFuZGxlKFNhZmVGaWxlSGFuZGxlIGhhbmRsZSwgb3V0IEZpbGVJbmZvcm1hdGlvbiBpbmZvcm1hdGlvbik7IH0gfQ=='

function Stop-PrerequisiteCheck {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This internal helper throws a stable failure and changes no external state.')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase,

        [Parameter(Mandatory = $true)]
        [string]$Code
    )

    throw [System.InvalidOperationException]::new("$Phase|$Code")
}

function Write-PrerequisiteStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase,

        [Parameter(Mandatory = $true)]
        [string]$Code
    )

    [Console]::Out.WriteLine("phase=$Phase code=$Code")
}

function Get-ReleaseCertificateSha256 {
    param([Parameter(Mandatory = $true)]$Certificate)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Test-ReleaseSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherCertificateSha256
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        Stop-PrerequisiteCheck 'media' 'signature_invalid'
    }
    $rawData = $signature.SignerCertificate.RawData
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $actual = ([BitConverter]::ToString($sha256.ComputeHash($rawData))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
    if ($actual -cne $ExpectedPublisherCertificateSha256) {
        Stop-PrerequisiteCheck 'media' 'publisher_identity_mismatch'
    }
    return $signature
}

function Test-SingleFileLink {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $information = New-Object SimplySignAuto.Release.FileInformation
        if (-not [SimplySignAuto.Release.NativeMethods]::GetFileInformationByHandle(
                $stream.SafeFileHandle,
                [ref]$information) -or
            $information.nNumberOfLinks -ne 1) {
            Stop-PrerequisiteCheck 'media' 'link_invalid'
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-ReleaseRelativePathSet {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][object[]]$Files
    )

    return @(
        $Files |
            ForEach-Object {
                $_.FullName.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/')
            } |
            Sort-Object
    )
}

function Test-ReleaseMedia {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'Release media is the established singular term for one closed payload set.')]
    param([Parameter(Mandatory = $true)][string]$Root)

    if ($releasePublisherCertificateSha256 -cnotmatch '^[0-9a-f]{64}$') {
        Stop-PrerequisiteCheck 'media' 'publisher_identity_invalid'
    }
    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $canonicalRoot -PathType Container)) {
        Stop-PrerequisiteCheck 'media' 'media_missing'
    }
    $rootItem = Get-Item -LiteralPath $canonicalRoot -Force
    $ancestor = $rootItem
    while ($null -ne $ancestor) {
        if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-PrerequisiteCheck 'media' 'link_invalid'
        }
        $ancestor = $ancestor.Parent
    }

    if ($null -eq ('SimplySignAuto.Release.NativeMethods' -as [type])) {
        $nativeSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($releaseNativeTypeBase64))
        Add-Type -TypeDefinition $nativeSource -ErrorAction Stop
    }

    $rootPrefix = $canonicalRoot + '\'
    $items = @(Get-ChildItem -LiteralPath $canonicalRoot -Force -Recurse -ErrorAction Stop)
    foreach ($item in $items) {
        $canonicalItem = [IO.Path]::GetFullPath($item.FullName)
        if (-not $canonicalItem.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-PrerequisiteCheck 'media' 'path_invalid'
        }
        if (-not $item.PSIsContainer) {
            Test-SingleFileLink -Path $canonicalItem
        }
    }

    $catalogPath = Join-Path $canonicalRoot 'release-files.cat'
    $scriptPath = Join-Path $canonicalRoot 'install-prerequisites.ps1'
    $applicationPath = Join-Path $canonicalRoot 'SimplySignAuto.exe'
    foreach ($required in @($catalogPath, $scriptPath, $applicationPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            Stop-PrerequisiteCheck 'media' 'media_missing'
        }
    }
    if (-not [IO.Path]::GetFullPath($PSCommandPath).Equals(
            [IO.Path]::GetFullPath($scriptPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        Stop-PrerequisiteCheck 'media' 'path_invalid'
    }

    $catalogSignature = Test-ReleaseSignature `
        -Path $catalogPath `
        -ExpectedPublisherCertificateSha256 $releasePublisherCertificateSha256
    $applicationSignature = Test-ReleaseSignature `
        -Path $applicationPath `
        -ExpectedPublisherCertificateSha256 $releasePublisherCertificateSha256
    if ((Get-ReleaseCertificateSha256 $catalogSignature.SignerCertificate) -cne
            (Get-ReleaseCertificateSha256 $applicationSignature.SignerCertificate)) {
        Stop-PrerequisiteCheck 'media' 'publisher_identity_mismatch'
    }

    $catalogInformation = Test-FileCatalog `
        -Detailed `
        -Path $canonicalRoot `
        -CatalogFilePath $catalogPath `
        -FilesToSkip @('release-files.cat', 'SimplySignAuto.exe') `
        -ErrorAction Stop
    $payloadFiles = @($items | Where-Object {
        -not $_.PSIsContainer -and
        $_.FullName -cne $catalogPath -and
        $_.FullName -cne $applicationPath
    })
    $expectedPaths = @(Get-ReleaseRelativePathSet -Root $canonicalRoot -Files $payloadFiles)
    $catalogPaths = @($catalogInformation.CatalogItems.Keys | ForEach-Object { $_.Replace('\', '/') } | Sort-Object)
    $testedPaths = @($catalogInformation.PathItems.Keys | ForEach-Object { $_.Replace('\', '/') } | Sort-Object)
    if ([string]$catalogInformation.Status -cne 'Valid' -or
        [string]$catalogInformation.HashAlgorithm -cne 'SHA256' -or
        $null -eq $catalogInformation.Signature -or
        $catalogInformation.Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        (Get-ReleaseCertificateSha256 $catalogInformation.Signature.SignerCertificate) -cne $releasePublisherCertificateSha256 -or
        @(Compare-Object -ReferenceObject $expectedPaths -DifferenceObject $catalogPaths -CaseSensitive).Count -ne 0 -or
        @(Compare-Object -ReferenceObject $expectedPaths -DifferenceObject $testedPaths -CaseSensitive).Count -ne 0) {
        Stop-PrerequisiteCheck 'media' 'catalog_invalid'
    }
}

function Test-ProcessElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ElevatedReleaseInstall {
    param([Parameter(Mandatory = $true)][string]$Root)

    $systemPowerShell = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) (
        'WindowsPowerShell\v1.0\powershell.exe')
    if (-not (Test-Path -LiteralPath $systemPowerShell -PathType Leaf)) {
        Stop-PrerequisiteCheck 'media' 'powershell_missing'
    }
    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $PSCommandPath + '"'),
        '-ReleaseMediaRoot', ('"' + $Root + '"'))
    $process = Start-Process `
        -FilePath $systemPowerShell `
        -ArgumentList $arguments `
        -Verb RunAs `
        -Wait `
        -PassThru
    return [int]$process.ExitCode
}

function Move-JsonWhitespace {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [ref]$Index
    )

    while ($Index.Value -lt $Text.Length -and [char]::IsWhiteSpace($Text[$Index.Value])) {
        $Index.Value++
    }
}

function Get-JsonStringToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [ref]$Index
    )

    if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -cne '"') {
        throw [System.FormatException]::new('json_string_expected')
    }

    $Index.Value++
    $builder = New-Object System.Text.StringBuilder
    while ($Index.Value -lt $Text.Length) {
        $character = $Text[$Index.Value]
        $Index.Value++
        if ($character -ceq '"') {
            return $builder.ToString()
        }

        if ($character -cne '\') {
            if ([int]$character -lt 0x20) {
                throw [System.FormatException]::new('json_control_character')
            }

            [void]$builder.Append($character)
            continue
        }

        if ($Index.Value -ge $Text.Length) {
            throw [System.FormatException]::new('json_escape_invalid')
        }

        $escape = $Text[$Index.Value]
        $Index.Value++
        switch -CaseSensitive ($escape) {
            '"' { [void]$builder.Append('"') }
            '\' { [void]$builder.Append('\') }
            '/' { [void]$builder.Append('/') }
            'b' { [void]$builder.Append([char]0x08) }
            'f' { [void]$builder.Append([char]0x0c) }
            'n' { [void]$builder.Append([char]0x0a) }
            'r' { [void]$builder.Append([char]0x0d) }
            't' { [void]$builder.Append([char]0x09) }
            'u' {
                if ($Index.Value + 4 -gt $Text.Length) {
                    throw [System.FormatException]::new('json_unicode_escape_invalid')
                }

                $hex = $Text.Substring($Index.Value, 4)
                if ($hex -cnotmatch '^[0-9A-Fa-f]{4}$') {
                    throw [System.FormatException]::new('json_unicode_escape_invalid')
                }

                [void]$builder.Append([char][Convert]::ToInt32($hex, 16))
                $Index.Value += 4
            }
            default { throw [System.FormatException]::new('json_escape_invalid') }
        }
    }

    throw [System.FormatException]::new('json_string_unterminated')
}

function Get-JsonValueToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [ref]$Index
    )

    Move-JsonWhitespace $Text $Index
    if ($Index.Value -ge $Text.Length) {
        throw [System.FormatException]::new('json_value_expected')
    }

    $character = $Text[$Index.Value]
    if ($character -ceq '{') {
        $Index.Value++
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        Move-JsonWhitespace $Text $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -ceq '}') {
            $Index.Value++
            return
        }

        while ($Index.Value -lt $Text.Length) {
            Move-JsonWhitespace $Text $Index
            $name = Get-JsonStringToken $Text $Index
            if (-not $names.Add($name)) {
                throw [System.FormatException]::new('json_duplicate_property')
            }

            Move-JsonWhitespace $Text $Index
            if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -cne ':') {
                throw [System.FormatException]::new('json_colon_expected')
            }

            $Index.Value++
            Get-JsonValueToken $Text $Index
            Move-JsonWhitespace $Text $Index
            if ($Index.Value -ge $Text.Length) {
                throw [System.FormatException]::new('json_object_unterminated')
            }

            if ($Text[$Index.Value] -ceq '}') {
                $Index.Value++
                return
            }

            if ($Text[$Index.Value] -cne ',') {
                throw [System.FormatException]::new('json_comma_expected')
            }

            $Index.Value++
        }

        throw [System.FormatException]::new('json_object_unterminated')
    }

    if ($character -ceq '[') {
        $Index.Value++
        Move-JsonWhitespace $Text $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -ceq ']') {
            $Index.Value++
            return
        }

        while ($Index.Value -lt $Text.Length) {
            Get-JsonValueToken $Text $Index
            Move-JsonWhitespace $Text $Index
            if ($Index.Value -ge $Text.Length) {
                throw [System.FormatException]::new('json_array_unterminated')
            }

            if ($Text[$Index.Value] -ceq ']') {
                $Index.Value++
                return
            }

            if ($Text[$Index.Value] -cne ',') {
                throw [System.FormatException]::new('json_comma_expected')
            }

            $Index.Value++
        }

        throw [System.FormatException]::new('json_array_unterminated')
    }

    if ($character -ceq '"') {
        [void](Get-JsonStringToken $Text $Index)
        return
    }

    $start = $Index.Value
    while ($Index.Value -lt $Text.Length) {
        $current = $Text[$Index.Value]
        if ([char]::IsWhiteSpace($current) -or $current -ceq ',' -or $current -ceq ']' -or $current -ceq '}') {
            break
        }

        $Index.Value++
    }

    if ($Index.Value -eq $start) {
        throw [System.FormatException]::new('json_primitive_invalid')
    }
}

function ConvertFrom-StrictJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Json
    )

    $index = 0
    Get-JsonValueToken $Json ([ref]$index)
    Move-JsonWhitespace $Json ([ref]$index)
    if ($index -ne $Json.Length) {
        throw [System.FormatException]::new('json_trailing_content')
    }

    return ConvertFrom-Json -InputObject $Json -ErrorAction Stop
}

function Test-ExactProperties {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The helper validates the complete property-name set of one JSON object.')]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Expected
    )

    if ($null -eq $Value -or $Value -is [System.Array] -or $Value -is [string]) {
        throw [System.FormatException]::new('json_object_expected')
    }

    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $sortedExpected = @($Expected | Sort-Object)
    if ($actual.Count -ne $sortedExpected.Count) {
        throw [System.FormatException]::new('json_properties_invalid')
    }

    for ($index = 0; $index -lt $actual.Count; $index++) {
        if ($actual[$index] -cne $sortedExpected[$index]) {
            throw [System.FormatException]::new('json_properties_invalid')
        }
    }
}

function Get-StrictUtf8File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    return [System.IO.File]::ReadAllText($Path, $encoding)
}

function Get-RuntimeManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $json = Get-StrictUtf8File $Path
        $manifest = ConvertFrom-StrictJson $json
        Test-ExactProperties $manifest @(
            'schemaVersion',
            'architecture',
            'minimumMajor',
            'rollForward',
            'releaseMetadataUrl',
            'maximumMetadataBytes',
            'maximumInstallerBytes',
            'approvedHosts',
            'allowedSignerSubjects',
            'runtimes'
        )

        if ($manifest.schemaVersion -isnot [int] -or $manifest.schemaVersion -ne 1 -or
            $manifest.architecture -cne 'x64' -or
            $manifest.minimumMajor -isnot [int] -or $manifest.minimumMajor -ne 10 -or
            $manifest.rollForward -cne 'Major' -or
            $manifest.releaseMetadataUrl -cne 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json' -or
            $manifest.maximumMetadataBytes -isnot [int] -or $manifest.maximumMetadataBytes -ne 2097152 -or
            $manifest.maximumInstallerBytes -isnot [int] -or $manifest.maximumInstallerBytes -ne 134217728) {
            throw [System.FormatException]::new('manifest_value_invalid')
        }

        $hosts = @($manifest.approvedHosts)
        if ($hosts.Count -ne 1 -or $hosts[0] -cne 'builds.dotnet.microsoft.com') {
            throw [System.FormatException]::new('manifest_hosts_invalid')
        }

        $subjects = @($manifest.allowedSignerSubjects)
        if ($subjects.Count -ne 1 -or
            $subjects[0] -cne 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US') {
            throw [System.FormatException]::new('manifest_signers_invalid')
        }

        $runtimes = @($manifest.runtimes)
        if ($runtimes.Count -ne 2) {
            throw [System.FormatException]::new('manifest_runtimes_invalid')
        }

        $expectedRuntimes = @{
            'Microsoft.WindowsDesktop.App' = @('windowsdesktop', 'windowsdesktop-runtime-win-x64.exe')
            'Microsoft.AspNetCore.App' = @('aspnetcore-runtime', 'aspnetcore-runtime-win-x64.exe')
        }
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($runtime in $runtimes) {
            Test-ExactProperties $runtime @('name', 'metadataProperty', 'installerName')
            $name = [string]$runtime.name
            if (-not $expectedRuntimes.ContainsKey($name) -or -not $seen.Add($name)) {
                throw [System.FormatException]::new('manifest_runtime_invalid')
            }

            $expected = $expectedRuntimes[$name]
            if ($runtime.metadataProperty -cne $expected[0] -or $runtime.installerName -cne $expected[1]) {
                throw [System.FormatException]::new('manifest_runtime_invalid')
            }
        }

        return $manifest
    }
    catch {
        Stop-PrerequisiteCheck 'manifest' 'manifest_invalid'
    }
}

function Test-PlainFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return -not $item.PSIsContainer -and
            (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0)
    }
    catch {
        return $false
    }
}

function Get-MachineSnapshot {
    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $installationType = [string](Get-ItemPropertyValue -LiteralPath `
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -Name InstallationType `
            -ErrorAction Stop)
        $principal = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent())
        return [pscustomobject]@{
            is64BitOperatingSystem = [Environment]::Is64BitOperatingSystem
            is64BitProcess = [Environment]::Is64BitProcess
            productType = [int]$operatingSystem.ProductType
            operatingSystemSku = [uint32]$operatingSystem.OperatingSystemSKU
            buildNumber = [string]$operatingSystem.BuildNumber
            installationType = $installationType
            domainRole = [int]$computerSystem.DomainRole
            elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            simplySignDesktopExists = Test-PlainFile 'C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe'
            pkcs11Exists = Test-PlainFile 'C:\Windows\System32\SimplySignPKCS.dll'
            lookupFailure = $false
        }
    }
    catch {
        Stop-PrerequisiteCheck 'preflight' 'machine_lookup_failed'
    }
}

function Test-SupportedMachine {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Machine
    )

    try {
        if ([bool]$Machine.lookupFailure) {
            Stop-PrerequisiteCheck 'preflight' 'machine_lookup_failed'
        }

        if (-not [bool]$Machine.is64BitOperatingSystem -or -not [bool]$Machine.is64BitProcess) {
            Stop-PrerequisiteCheck 'preflight' 'architecture_unsupported'
        }

        $domainRole = [int]$Machine.domainRole
        if ($domainRole -lt 0 -or $domainRole -gt 5) {
            Stop-PrerequisiteCheck 'preflight' 'machine_lookup_failed'
        }

        if ($domainRole -eq 4 -or $domainRole -eq 5) {
            Stop-PrerequisiteCheck 'preflight' 'domain_controller_unsupported'
        }

        if (-not [bool]$Machine.elevated) {
            Stop-PrerequisiteCheck 'preflight' 'elevation_required'
        }

        $build = 0
        if (-not [int]::TryParse([string]$Machine.buildNumber, [ref]$build)) {
            Stop-PrerequisiteCheck 'preflight' 'machine_lookup_failed'
        }

        $operatingSystemSku = [uint32]0
        if (-not [uint32]::TryParse([string]$Machine.operatingSystemSku, [ref]$operatingSystemSku)) {
            Stop-PrerequisiteCheck 'preflight' 'machine_lookup_failed'
        }

        $productType = [int]$Machine.productType
        $installationType = [string]$Machine.installationType
        if ($productType -eq 1) {
            if ($installationType -cne 'Client') {
                Stop-PrerequisiteCheck 'preflight' 'os_unsupported'
            }

            $enterpriseLtscSkus = @(125, 126, 129, 130)
            $iotEnterpriseLtscSkus = @(191, 207)
            $windows10 =
                ($build -in @(14393, 17763) -and $operatingSystemSku -in $enterpriseLtscSkus) -or
                ($build -eq 19044 -and $operatingSystemSku -in ($enterpriseLtscSkus + $iotEnterpriseLtscSkus))

            $enterpriseSkus = @(4, 27, 72, 84, 140, 141, 171, 172, 175)
            $windows11Skus = @(
                4, 27, 48, 49, 72, 84, 98, 99, 100, 101, 121, 122,
                125, 126, 129, 130, 138, 139, 140, 141, 161, 162, 164,
                165, 171, 172, 175, 188, 191, 202, 203, 207)
            $windows11 =
                ($build -eq 22631 -and $operatingSystemSku -in $enterpriseSkus) -or
                ($build -in @(26100, 26200, 28000) -and $operatingSystemSku -in $windows11Skus)
            if (-not $windows10 -and -not $windows11) {
                Stop-PrerequisiteCheck 'preflight' 'os_unsupported'
            }
        }
        elseif ($productType -eq 3) {
            if ($installationType -cne 'Server') {
                Stop-PrerequisiteCheck 'preflight' 'desktop_experience_required'
            }

            $supportedServer = $operatingSystemSku -in @(7, 8) -and $build -in @(17763, 20348, 26100)
            if (-not $supportedServer) {
                Stop-PrerequisiteCheck 'preflight' 'os_unsupported'
            }
        }
        else {
            Stop-PrerequisiteCheck 'preflight' 'os_unsupported'
        }

        if (-not [bool]$Machine.simplySignDesktopExists) {
            Stop-PrerequisiteCheck 'preflight' 'simplysign_desktop_missing'
        }

        if (-not [bool]$Machine.pkcs11Exists) {
            Stop-PrerequisiteCheck 'preflight' 'simplysign_pkcs11_missing'
        }
    }
    catch {
        if ($_.Exception.Message -match '^[a-z_]+\|[a-z0-9_]+$') {
            throw
        }

        Stop-PrerequisiteCheck 'preflight' 'machine_lookup_failed'
    }
}

function Get-InstalledRuntimeVersions {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The return value is the complete installed version set for one runtime.')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuntimeName
    )

    try {
        $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        if ([string]::IsNullOrWhiteSpace($programFiles)) {
            Stop-PrerequisiteCheck 'detection' 'runtime_lookup_failed'
        }

        $runtimeRoot = Join-Path (Join-Path $programFiles 'dotnet\shared') $RuntimeName
        if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) {
            return @()
        }

        $rootItem = Get-Item -LiteralPath $runtimeRoot -Force -ErrorAction Stop
        if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-PrerequisiteCheck 'detection' 'runtime_lookup_failed'
        }

        return @(Get-ChildItem -LiteralPath $runtimeRoot -Directory -Force -ErrorAction Stop |
            Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 } |
            ForEach-Object { $_.Name })
    }
    catch {
        if ($_.Exception.Message -match '^[a-z_]+\|[a-z0-9_]+$') {
            throw
        }

        Stop-PrerequisiteCheck 'detection' 'runtime_lookup_failed'
    }
}

function Test-CompatibleStableRuntime {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Versions,

        [Parameter(Mandatory = $true)]
        [int]$MinimumMajor
    )

    foreach ($version in $Versions) {
        $major = 0
        if ($version -cmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -and
            [int]::TryParse($Matches[1], [ref]$major) -and $major -ge $MinimumMajor) {
            return $true
        }
    }

    return $false
}

function Get-MissingRuntimes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The return value is the complete set of missing required runtimes.')]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest
    )

    $missing = New-Object System.Collections.Generic.List[object]
    foreach ($runtime in @($Manifest.runtimes)) {
        $versions = @(Get-InstalledRuntimeVersions ([string]$runtime.name))
        if (-not (Test-CompatibleStableRuntime $versions ([int]$Manifest.minimumMajor))) {
            [void]$missing.Add($runtime)
        }
    }

    return $missing.ToArray()
}

function Test-ApprovedHttpsUri {
    param(
        [Parameter(Mandatory = $true)]
        [Uri]$Uri,

        [Parameter(Mandatory = $true)]
        [string[]]$ApprovedHosts
    )

    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -cne 'https' -or $Uri.Port -ne 443 -or
        -not [string]::IsNullOrEmpty($Uri.UserInfo) -or [string]::IsNullOrWhiteSpace($Uri.DnsSafeHost)) {
        return $false
    }

    foreach ($hostName in $ApprovedHosts) {
        if ([string]::Equals($Uri.DnsSafeHost, $hostName, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Invoke-HttpDownload {
    param(
        [Parameter(Mandatory = $true)]
        [Uri]$Uri,

        [Parameter(Mandatory = $true)]
        [long]$MaximumBytes,

        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [string[]]$ApprovedHosts
    )

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Stop-PrerequisiteCheck 'download' 'download_failed'
    }

    $totalTimeoutMilliseconds = 120000
    $downloadWatch = [Diagnostics.Stopwatch]::StartNew()
    $current = $Uri
    for ($redirectCount = 0; $redirectCount -le 3; $redirectCount++) {
        $remainingTotal = $totalTimeoutMilliseconds - [long]$downloadWatch.ElapsedMilliseconds
        if ($remainingTotal -le 0) {
            Stop-PrerequisiteCheck 'download' 'download_timeout'
        }

        $requestTimeout = [int][Math]::Min(30000, $remainingTotal)
        if (-not (Test-ApprovedHttpsUri $current $ApprovedHosts)) {
            Stop-PrerequisiteCheck 'download' 'redirect_rejected'
        }

        $request = [System.Net.HttpWebRequest]::CreateHttp($current)
        $request.Method = 'GET'
        $request.AllowAutoRedirect = $false
        $request.Timeout = $requestTimeout
        $request.ReadWriteTimeout = $requestTimeout
        $request.UseDefaultCredentials = $false
        $request.Credentials = $null
        $request.PreAuthenticate = $false
        $request.Proxy = $null
        $request.UserAgent = 'SimplySignAuto-Prerequisite/1'
        $response = $null
        try {
            $response = [System.Net.HttpWebResponse]$request.GetResponse()
            $status = [int]$response.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                if ($redirectCount -eq 3 -or [string]::IsNullOrWhiteSpace($response.Headers['Location'])) {
                    Stop-PrerequisiteCheck 'download' 'redirect_rejected'
                }

                try {
                    $next = New-Object Uri($current, $response.Headers['Location'])
                }
                catch {
                    Stop-PrerequisiteCheck 'download' 'redirect_rejected'
                }

                if (-not (Test-ApprovedHttpsUri $next $ApprovedHosts)) {
                    Stop-PrerequisiteCheck 'download' 'redirect_rejected'
                }

                $current = $next
                continue
            }

            if ($status -ne 200) {
                Stop-PrerequisiteCheck 'download' 'download_failed'
            }

            if ($response.ContentLength -gt $MaximumBytes) {
                Stop-PrerequisiteCheck 'download' 'download_too_large'
            }

            $inputStream = $null
            $outputStream = $null
            $memoryStream = $null
            try {
                $inputStream = $response.GetResponseStream()
                if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
                    $memoryStream = New-Object System.IO.MemoryStream
                    $outputStream = $memoryStream
                }
                else {
                    $outputStream = New-Object System.IO.FileStream(
                        $DestinationPath,
                        [System.IO.FileMode]::CreateNew,
                        [System.IO.FileAccess]::Write,
                        [System.IO.FileShare]::None)
                }

                $buffer = New-Object byte[] 81920
                $total = [long]0
                while ($true) {
                    $remainingTotal = $totalTimeoutMilliseconds - [long]$downloadWatch.ElapsedMilliseconds
                    if ($remainingTotal -le 0) {
                        Stop-PrerequisiteCheck 'download' 'download_timeout'
                    }

                    $remainingMilliseconds = [int][Math]::Min(30000, $remainingTotal)
                    if ($inputStream.CanTimeout) {
                        $inputStream.ReadTimeout = $remainingMilliseconds
                    }
                    $read = $inputStream.Read($buffer, 0, $buffer.Length)
                    if ($downloadWatch.ElapsedMilliseconds -ge $totalTimeoutMilliseconds) {
                        Stop-PrerequisiteCheck 'download' 'download_timeout'
                    }
                    if ($read -le 0) {
                        break
                    }

                    $total += $read
                    if ($total -gt $MaximumBytes) {
                        Stop-PrerequisiteCheck 'download' 'download_too_large'
                    }

                    $outputStream.Write($buffer, 0, $read)
                }

                if ($null -ne $memoryStream) {
                    return $memoryStream.ToArray()
                }

                return
            }
            finally {
                if ($null -ne $outputStream) { $outputStream.Dispose() }
                if ($null -ne $inputStream) { $inputStream.Dispose() }
                if ($null -ne $memoryStream) { $memoryStream.Dispose() }
            }
        }
        catch {
            if ($_.Exception.Message -match '^[a-z_]+\|[a-z0-9_]+$') {
                throw
            }

            $exception = $_.Exception
            while ($null -ne $exception) {
                if (($exception -is [System.Net.WebException] -and
                        $exception.Status -eq [System.Net.WebExceptionStatus]::Timeout) -or
                    ($exception -is [System.Net.Sockets.SocketException] -and
                        $exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut)) {
                    Stop-PrerequisiteCheck 'download' 'download_timeout'
                }
                $exception = $exception.InnerException
            }
            if ($downloadWatch.ElapsedMilliseconds -ge $totalTimeoutMilliseconds) {
                Stop-PrerequisiteCheck 'download' 'download_timeout'
            }

            Stop-PrerequisiteCheck 'download' 'download_failed'
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
        }
    }

    Stop-PrerequisiteCheck 'download' 'redirect_rejected'
}

function Invoke-BoundedDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [long]$MaximumBytes,

        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [string[]]$ApprovedHosts
    )

    try {
        $uri = [Uri]$Url
    }
    catch {
        Stop-PrerequisiteCheck 'download' 'download_url_invalid'
    }

    if (-not (Test-ApprovedHttpsUri $uri $ApprovedHosts)) {
        Stop-PrerequisiteCheck 'download' 'download_url_invalid'
    }

    return Invoke-HttpDownload $uri $MaximumBytes $DestinationPath $ApprovedHosts
}

function Get-InstallerSelections {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The metadata operation resolves one selection for every missing runtime.')]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$MetadataBytes,

        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [object[]]$MissingRuntimes
    )

    try {
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $metadataJson = $encoding.GetString($MetadataBytes)
        $metadata = ConvertFrom-StrictJson $metadataJson
        $channelProperty = $metadata.PSObject.Properties['channel-version']
        $releasesProperty = $metadata.PSObject.Properties['releases']
        if ($null -eq $channelProperty -or $channelProperty.Value -cne '10.0' -or
            $null -eq $releasesProperty) {
            Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
        }

        $stable = @($releasesProperty.Value | Where-Object {
            $property = $_.PSObject.Properties['release-version']
            $null -ne $property -and [string]$property.Value -cmatch '^10\.0\.(0|[1-9][0-9]*)$'
        } | Sort-Object {
            [Version]([string]$_.PSObject.Properties['release-version'].Value)
        } -Descending)
        if ($stable.Count -eq 0) {
            Stop-PrerequisiteCheck 'metadata' 'stable_release_missing'
        }

        $release = $stable[0]
        $releaseVersion = [string]$release.PSObject.Properties['release-version'].Value
        $selections = New-Object System.Collections.Generic.List[object]
        foreach ($runtime in $MissingRuntimes) {
            $componentProperty = $release.PSObject.Properties[[string]$runtime.metadataProperty]
            if ($null -eq $componentProperty) {
                Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
            }

            $component = $componentProperty.Value
            $versionProperty = $component.PSObject.Properties['version']
            $filesProperty = $component.PSObject.Properties['files']
            if ($null -eq $versionProperty -or $versionProperty.Value -cne $releaseVersion -or
                $null -eq $filesProperty) {
                Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
            }

            $files = @($filesProperty.Value | Where-Object {
                $name = $_.PSObject.Properties['name']
                $rid = $_.PSObject.Properties['rid']
                $null -ne $name -and $name.Value -ceq $runtime.installerName -and
                    $null -ne $rid -and $rid.Value -ceq 'win-x64'
            })
            if ($files.Count -ne 1) {
                Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
            }

            $file = $files[0]
            $urlProperty = $file.PSObject.Properties['url']
            $hashProperty = $file.PSObject.Properties['hash']
            if ($null -eq $urlProperty -or $null -eq $hashProperty -or
                [string]$hashProperty.Value -cnotmatch '^[0-9A-Fa-f]{128}$') {
                Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
            }

            $uri = $null
            try {
                $uri = [Uri]([string]$urlProperty.Value)
            }
            catch {
                Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
            }
            if ($null -eq $uri -or -not (Test-ApprovedHttpsUri $uri @($Manifest.approvedHosts))) {
                Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
            }

            $expectedPath = if ($runtime.metadataProperty -ceq 'windowsdesktop') {
                "/dotnet/WindowsDesktop/$releaseVersion/windowsdesktop-runtime-$releaseVersion-win-x64.exe"
            }
            else {
                "/dotnet/aspnetcore/Runtime/$releaseVersion/aspnetcore-runtime-$releaseVersion-win-x64.exe"
            }
            if ($uri.AbsolutePath -cne $expectedPath -or -not [string]::IsNullOrEmpty($uri.Query) -or
                -not [string]::IsNullOrEmpty($uri.Fragment)) {
                Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
            }

            [void]$selections.Add([pscustomobject]@{
                Runtime = $runtime
                ReleaseVersion = $releaseVersion
                Url = $uri.AbsoluteUri
                Hash = ([string]$hashProperty.Value).ToLowerInvariant()
            })
        }

        return $selections.ToArray()
    }
    catch {
        if ($_.Exception.Message -match '^[a-z_]+\|[a-z0-9_]+$') {
            throw
        }

        Stop-PrerequisiteCheck 'metadata' 'metadata_invalid'
    }
}

function New-SecureDownloadDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'The checker requires a non-interactive private temp directory and always cleans it.')]
    param()

    try {
        $tempRoot = 'C:\Windows\Temp'
        $rootItem = Get-Item -LiteralPath $tempRoot -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or
            ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw [System.Security.SecurityException]::new('temp_root_invalid')
        }

        $path = Join-Path $tempRoot ('SimplySignAuto-Prerequisite-' + [Guid]::NewGuid().ToString('N'))
        [void][System.IO.Directory]::CreateDirectory($path)
        $administrators = New-Object Security.Principal.SecurityIdentifier(
            [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
            $null)
        $system = New-Object Security.Principal.SecurityIdentifier(
            [Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null)
        $security = New-Object Security.AccessControl.DirectorySecurity
        $security.SetAccessRuleProtection($true, $false)
        $security.SetOwner($administrators)
        foreach ($identity in @($administrators, $system)) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $identity,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            [void]$security.AddAccessRule($rule)
        }

        Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop
        $actual = Get-Acl -LiteralPath $path -ErrorAction Stop
        if (-not $actual.AreAccessRulesProtected) {
            throw [System.Security.SecurityException]::new('acl_not_protected')
        }

        $allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        [void]$allowed.Add($administrators.Value)
        [void]$allowed.Add($system.Value)
        $actualIdentities = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($access in @($actual.Access)) {
            $sid = $access.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if (-not $allowed.Contains($sid) -or
                $access.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                (($access.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                    [Security.AccessControl.FileSystemRights]::FullControl)) {
                throw [System.Security.SecurityException]::new('acl_invalid')
            }
            [void]$actualIdentities.Add($sid)
        }

        $owner = $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if (-not $allowed.Contains($owner) -or $actualIdentities.Count -ne 2 -or
            -not $actualIdentities.Contains($administrators.Value) -or
            -not $actualIdentities.Contains($system.Value)) {
            throw [System.Security.SecurityException]::new('acl_invalid')
        }

        return $path
    }
    catch {
        Stop-PrerequisiteCheck 'download' 'secure_temp_failed'
    }
}

function Test-InstallerSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Manifest
    )

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate -or
            @($Manifest.allowedSignerSubjects) -cnotcontains $signature.SignerCertificate.Subject) {
            Stop-PrerequisiteCheck 'signature' 'signature_invalid'
        }
    }
    catch {
        if ($_.Exception.Message -match '^[a-z_]+\|[a-z0-9_]+$') { throw }
        Stop-PrerequisiteCheck 'signature' 'signature_invalid'
    }
}

function Stop-ProcessTree {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Timeout containment must terminate the exact child tree without an interactive prompt.')]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $taskKill = 'C:\Windows\System32\taskkill.exe'
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $taskKill
    $start.Arguments = "/PID $ProcessId /T /F"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $killer = New-Object System.Diagnostics.Process
    $killer.StartInfo = $start
    try {
        if (-not $killer.Start()) {
            return $false
        }
        $stdout = $killer.StandardOutput.ReadToEndAsync()
        $stderr = $killer.StandardError.ReadToEndAsync()
        if (-not $killer.WaitForExit(30000)) {
            return $false
        }
        [void]$stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        return $killer.ExitCode -eq 0
    }
    finally {
        $killer.Dispose()
    }
}

function Invoke-InstallerProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $process = Start-Process -FilePath $Path `
            -ArgumentList @('/install', '/passive', '/norestart') `
            -Wait:$false `
            -PassThru `
            -ErrorAction Stop
        if (-not $process.WaitForExit(900000)) {
            $terminated = Stop-ProcessTree $process.Id
            if (-not $terminated -or -not $process.WaitForExit(30000)) {
                Stop-PrerequisiteCheck 'install' 'process_cleanup_failed'
            }

            Stop-PrerequisiteCheck 'install' 'install_timeout'
        }

        return $process.ExitCode
    }
    catch {
        if ($_.Exception.Message -match '^[a-z_]+\|[a-z0-9_]+$') { throw }
        Stop-PrerequisiteCheck 'install' 'install_failed'
    }
}

function Test-StrictVersionOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    if ($Output -cnotmatch '^(?<core>(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))(?:-(?<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+(?<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\r?\n?$') {
        return $false
    }

    $prerelease = if ($Matches.ContainsKey('prerelease')) {
        [string]$Matches['prerelease']
    }
    else {
        [string]::Empty
    }
    if (-not [string]::IsNullOrEmpty($prerelease)) {
        foreach ($identifier in $prerelease.Split('.')) {
            if ($identifier -cmatch '^[0-9]+$' -and $identifier.Length -gt 1 -and $identifier[0] -ceq '0') {
                return $false
            }
        }
    }

    return $true
}

function Invoke-PrerequisiteProbe {
    $executable = Join-Path $PSScriptRoot 'SimplySignAuto.exe'
    if (-not (Test-PlainFile $executable)) {
        Stop-PrerequisiteCheck 'probe' 'probe_executable_missing'
    }

    try {
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = $executable
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Arguments = '--version'
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $start
        if (-not $process.Start()) {
            Stop-PrerequisiteCheck 'probe' 'probe_failed'
        }

        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $terminated = Stop-ProcessTree $process.Id
            if (-not $terminated -or -not $process.WaitForExit(30000)) {
                Stop-PrerequisiteCheck 'probe' 'process_cleanup_failed'
            }

            Stop-PrerequisiteCheck 'probe' 'probe_timeout'
        }

        $output = $stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            Stop-PrerequisiteCheck 'probe' 'probe_failed'
        }
    }
    catch {
        if ($_.Exception.Message -match '^[a-z_]+\|[a-z0-9_]+$') { throw }
        Stop-PrerequisiteCheck 'probe' 'probe_failed'
    }

    if (-not (Test-StrictVersionOutput $output)) {
        Stop-PrerequisiteCheck 'probe' 'probe_output_invalid'
    }
}

function Clear-DownloadDirectory {
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Directory]::Exists($Path)) {
        return
    }

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            [System.IO.Directory]::Delete($Path, $false)
        }
        else {
            [System.IO.Directory]::Delete($Path, $true)
        }
    }
    catch {
        Stop-PrerequisiteCheck 'cleanup' 'cleanup_failed'
    }
}

function Invoke-PrerequisiteCheck {
    $manifest = Get-RuntimeManifest $ManifestPath
    Write-PrerequisiteStatus 'manifest' 'ready'

    $machine = Get-MachineSnapshot
    Test-SupportedMachine $machine
    Write-PrerequisiteStatus 'preflight' 'ready'

    $missing = @(Get-MissingRuntimes $manifest)
    if ($missing.Count -eq 0) {
        Write-PrerequisiteStatus 'detection' 'ready'
        Invoke-PrerequisiteProbe
        Write-PrerequisiteStatus 'probe' 'ready'
        Write-PrerequisiteStatus 'complete' 'ready'
        return 0
    }

    Write-PrerequisiteStatus 'detection' 'install_required'
    $metadataBytes = Invoke-BoundedDownload `
        ([string]$manifest.releaseMetadataUrl) `
        ([long]$manifest.maximumMetadataBytes) `
        $null `
        @($manifest.approvedHosts)
    Write-PrerequisiteStatus 'download' 'ready'
    $selections = @(Get-InstallerSelections $metadataBytes $manifest $missing)
    Write-PrerequisiteStatus 'metadata' 'ready'

    $script:SecureDownloadDirectory = New-SecureDownloadDirectory
    foreach ($selection in $selections) {
        $filePath = Join-Path $script:SecureDownloadDirectory ([string]$selection.Runtime.installerName)
        Invoke-BoundedDownload `
            ([string]$selection.Url) `
            ([long]$manifest.maximumInstallerBytes) `
            $filePath `
            @($manifest.approvedHosts)
        Write-PrerequisiteStatus 'download' 'ready'

        $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA512 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($actualHash -cne [string]$selection.Hash) {
            Stop-PrerequisiteCheck 'download' 'hash_mismatch'
        }

        Test-InstallerSignature $filePath $manifest
        Write-PrerequisiteStatus 'signature' 'ready'
        $exitCode = Invoke-InstallerProcess $filePath
        if ($exitCode -eq 3010) {
            Write-PrerequisiteStatus 'install' 'restart_required'
            return 3010
        }

        if ($exitCode -eq 1602) {
            Stop-PrerequisiteCheck 'install' 'install_cancelled'
        }

        if ($exitCode -ne 0) {
            Stop-PrerequisiteCheck 'install' 'install_failed'
        }

        Write-PrerequisiteStatus 'install' 'ready'
    }

    if (@(Get-MissingRuntimes $manifest).Count -ne 0) {
        Stop-PrerequisiteCheck 'detection' 'runtime_missing_after_install'
    }

    Write-PrerequisiteStatus 'detection' 'ready'
    Invoke-PrerequisiteProbe
    Write-PrerequisiteStatus 'probe' 'ready'
    Write-PrerequisiteStatus 'complete' 'ready'
    return 0
}

$result = 1
try {
    if ($VerifyMediaOnly -and [string]::IsNullOrWhiteSpace($ReleaseMediaRoot)) {
        Stop-PrerequisiteCheck 'media' 'media_missing'
    }
    if (-not [string]::IsNullOrWhiteSpace($ReleaseMediaRoot)) {
        Test-ReleaseMedia -Root $ReleaseMediaRoot
        Write-PrerequisiteStatus 'media' 'ready'
    }

    if ($VerifyMediaOnly) {
        $result = 0
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ReleaseMediaRoot) -and -not (Test-ProcessElevated)) {
        $result = Invoke-ElevatedReleaseInstall -Root ([IO.Path]::GetFullPath($ReleaseMediaRoot))
    }
    else {
        $result = Invoke-PrerequisiteCheck
        if ($result -eq 0 -and -not [string]::IsNullOrWhiteSpace($ReleaseMediaRoot)) {
            $applicationPath = Join-Path ([IO.Path]::GetFullPath($ReleaseMediaRoot)) 'SimplySignAuto.exe'
            & $applicationPath setup | ForEach-Object { [Console]::Out.WriteLine($_) }
            $result = $LASTEXITCODE
        }
    }
}
catch {
    $message = [string]$_.Exception.Message
    if ($message -cmatch '^(?<phase>[a-z_]+)\|(?<code>[a-z0-9_]+)$') {
        Write-PrerequisiteStatus $Matches.phase $Matches.code
    }
    else {
        Write-PrerequisiteStatus 'internal' 'unexpected_failure'
    }
    $result = 1
}
finally {
    try {
        Clear-DownloadDirectory $script:SecureDownloadDirectory
    }
    catch {
        if ($result -eq 0) {
            Write-PrerequisiteStatus 'cleanup' 'cleanup_failed'
            $result = 1
        }
    }
}

exit $result
