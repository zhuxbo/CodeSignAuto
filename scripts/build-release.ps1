[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$SemVerPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$SbomCreatedUtc = '1980-01-01T00:00:00Z'
$ReleaseNativeTypeBase64 = 'dXNpbmcgU3lzdGVtOyB1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7IHVzaW5nIE1pY3Jvc29mdC5XaW4zMi5TYWZlSGFuZGxlczsgbmFtZXNwYWNlIENvZGVTaWduQXV0by5SZWxlYXNlIHsgW1N0cnVjdExheW91dChMYXlvdXRLaW5kLlNlcXVlbnRpYWwpXSBwdWJsaWMgc3RydWN0IEZpbGVJbmZvcm1hdGlvbiB7IHB1YmxpYyB1aW50IEZpbGVBdHRyaWJ1dGVzOyBwdWJsaWMgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzLkZJTEVUSU1FIENyZWF0aW9uVGltZTsgcHVibGljIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5Db21UeXBlcy5GSUxFVElNRSBMYXN0QWNjZXNzVGltZTsgcHVibGljIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5Db21UeXBlcy5GSUxFVElNRSBMYXN0V3JpdGVUaW1lOyBwdWJsaWMgdWludCBWb2x1bWVTZXJpYWxOdW1iZXI7IHB1YmxpYyB1aW50IEZpbGVTaXplSGlnaDsgcHVibGljIHVpbnQgRmlsZVNpemVMb3c7IHB1YmxpYyB1aW50IG5OdW1iZXJPZkxpbmtzOyBwdWJsaWMgdWludCBGaWxlSW5kZXhIaWdoOyBwdWJsaWMgdWludCBGaWxlSW5kZXhMb3c7IH0gcHVibGljIHN0YXRpYyBjbGFzcyBOYXRpdmVNZXRob2RzIHsgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIiwgU2V0TGFzdEVycm9yPXRydWUpXSBbcmV0dXJuOiBNYXJzaGFsQXMoVW5tYW5hZ2VkVHlwZS5Cb29sKV0gcHVibGljIHN0YXRpYyBleHRlcm4gYm9vbCBHZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZShTYWZlRmlsZUhhbmRsZSBoYW5kbGUsIG91dCBGaWxlSW5mb3JtYXRpb24gaW5mb3JtYXRpb24pOyB9IH0='
$SigningClientScript = Join-Path $PSScriptRoot 'sign-via-simplysign.ps1'
. $SigningClientScript
$PdfReleaseDecisionScript = Join-Path $PSScriptRoot 'get-pdf-release-decision.ps1'
. $PdfReleaseDecisionScript

function Fail-Release {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'This established private helper name is retained to avoid a broad release-script refactor.')]
    param([Parameter(Mandatory = $true)][string]$Code)

    throw $Code
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $FilePath @ArgumentList | ForEach-Object { [Console]::Out.WriteLine($_) }
        if ($LASTEXITCODE -ne 0) {
            Fail-Release 'release_command_failed'
        }
    } finally {
        Pop-Location
    }
}

function Get-RequiredTrxCounter {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlElement]$Counters,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $attribute = $Counters.Attributes[$Name]
    $value = 0
    if ($null -eq $attribute -or
        -not [int]::TryParse(
            $attribute.Value,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$value) -or
        $value -lt 0) {
        Fail-Release 'release_test_result_invalid'
    }
    return $value
}

function Read-ReleaseTestResult {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        ((Get-Item -LiteralPath $Path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Release 'release_test_result_missing'
    }

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    $document = [System.Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    try {
        $document.Load($reader)
    } catch {
        Fail-Release 'release_test_result_invalid'
    } finally {
        $reader.Dispose()
    }

    $trxNamespace = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
    $namespaces = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespaces.AddNamespace('trx', $trxNamespace)
    $roots = $document.SelectNodes('/trx:TestRun', $namespaces)
    if ($null -eq $roots -or $roots.Count -ne 1) {
        Fail-Release 'release_test_result_invalid'
    }
    $summaries = $roots.Item(0).SelectNodes('trx:ResultSummary', $namespaces)
    if ($null -eq $summaries -or $summaries.Count -ne 1) {
        Fail-Release 'release_test_result_invalid'
    }
    $counterNodes = $summaries.Item(0).SelectNodes('trx:Counters', $namespaces)
    if ($null -eq $counterNodes -or $counterNodes.Count -ne 1) {
        Fail-Release 'release_test_result_invalid'
    }
    $counters = $counterNodes.Item(0)

    $values = [ordered]@{}
    foreach ($name in @('total', 'executed', 'passed', 'failed', 'error', 'aborted', 'timeout')) {
        $values[$name] = Get-RequiredTrxCounter -Counters $counters -Name $name
    }
    if ($values.total -le 0 -or
        $values.executed -le 0 -or
        $values.executed -gt $values.total -or
        $values.passed -ne $values.executed -or
        $values.failed -ne 0 -or
        $values.error -ne 0 -or
        $values.aborted -ne 0 -or
        $values.timeout -ne 0) {
        Fail-Release 'release_test_result_failed'
    }

    return [pscustomobject]$values
}

function Invoke-ReleaseTestSuite {
    param(
        [Parameter(Mandatory = $true)][string]$Dotnet,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ResultsRoot
    )

    $projects = [ordered]@{
        'CodeSignAuto.Core.Tests' = 'tests/CodeSignAuto.Core.Tests/CodeSignAuto.Core.Tests.csproj'
        'CodeSignAuto.Protocol.Tests' = 'tests/CodeSignAuto.Protocol.Tests/CodeSignAuto.Protocol.Tests.csproj'
        'CodeSignAuto.Service.Tests' = 'tests/CodeSignAuto.Service.Tests/CodeSignAuto.Service.Tests.csproj'
        'CodeSignAuto.Agent.Tests' = 'tests/CodeSignAuto.Agent.Tests/CodeSignAuto.Agent.Tests.csproj'
        'CodeSignAuto.UI.Tests' = 'tests/CodeSignAuto.UI.Tests/CodeSignAuto.UI.Tests.csproj'
        'CodeSignAuto.EndToEnd.Tests' = 'tests/CodeSignAuto.EndToEnd.Tests/CodeSignAuto.EndToEnd.Tests.csproj'
    }
    if (Test-Path -LiteralPath $ResultsRoot) {
        Assert-PlainDirectory -Path $ResultsRoot
        if (@(Get-ChildItem -LiteralPath $ResultsRoot -Force).Count -ne 0) {
            Fail-Release 'release_test_results_not_empty'
        }
    } else {
        [System.IO.Directory]::CreateDirectory($ResultsRoot) | Out-Null
    }

    foreach ($entry in $projects.GetEnumerator()) {
        $project = Join-Path $RepoRoot $entry.Value
        if (-not (Test-Path -LiteralPath $project -PathType Leaf) -or
            ((Get-Item -LiteralPath $project -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Release 'release_test_project_missing'
        }
        $trxName = $entry.Key + '.trx'
        Push-Location -LiteralPath $RepoRoot
        try {
            & $Dotnet @(
                'test', $project, '-c', 'Release', '--no-restore',
                '--logger', "trx;LogFileName=$trxName",
                '--results-directory', $ResultsRoot,
                '-m:1', '-nodeReuse:false')
            $commandExitCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }

        $null = Read-ReleaseTestResult -Path (Join-Path $ResultsRoot $trxName)
        if ($commandExitCode -ne 0) {
            Fail-Release 'release_test_command_failed'
        }
    }

    $expected = @($projects.Keys | ForEach-Object { $_ + '.trx' } | Sort-Object)
    $actual = @(
        Get-ChildItem -LiteralPath $ResultsRoot -File -Filter '*.trx' |
            ForEach-Object { $_.Name } |
            Sort-Object
    )
    if (@(Compare-Object -ReferenceObject $expected -DifferenceObject $actual -CaseSensitive).Count -ne 0) {
        Fail-Release 'release_test_project_closure_mismatch'
    }
}

function Assert-PlainDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Release 'release_path_invalid'
    }
}

function Assert-ReleaseTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    Assert-PlainDirectory -Path $canonicalRoot
    if ($null -eq ('CodeSignAuto.Release.NativeMethods' -as [type])) {
        $nativeSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ReleaseNativeTypeBase64))
        Add-Type -TypeDefinition $nativeSource -ErrorAction Stop
    }

    $rootPrefix = $canonicalRoot + '\'
    foreach ($item in @(Get-ChildItem -LiteralPath $canonicalRoot -Force -Recurse)) {
        $canonicalItem = [IO.Path]::GetFullPath($item.FullName)
        if (-not $canonicalItem.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Release 'release_package_path_invalid'
        }
        if ($item.PSIsContainer) {
            continue
        }

        $stream = [IO.File]::Open(
            $canonicalItem,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $information = New-Object CodeSignAuto.Release.FileInformation
            if (-not [CodeSignAuto.Release.NativeMethods]::GetFileInformationByHandle(
                    $stream.SafeFileHandle,
                    [ref]$information) -or
                $information.nNumberOfLinks -ne 1) {
                Fail-Release 'release_package_link_invalid'
            }
        }
        finally {
            $stream.Dispose()
        }
    }
}

function Get-LowerSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CertificateSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$RawData)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($RawData))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Write-PdfExtensionManifest {
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$ProductVersion,
        [Parameter(Mandatory = $true)][string]$HelperVersion,
        [Parameter(Mandatory = $true)][long]$HelperLength,
        [Parameter(Mandatory = $true)][string]$HelperSha256,
        [Parameter(Mandatory = $true)][string]$PublisherCertificateSha256
    )

    $manifest = [ordered]@{
        schemaVersion = 1
        productVersion = $ProductVersion
        helperVersion = $HelperVersion
        helperLength = $HelperLength
        helperSha256 = $HelperSha256
        publisherCertificateSha256 = $PublisherCertificateSha256
    }
    Write-Utf8File -Path $OutputPath -Content (($manifest | ConvertTo-Json -Depth 3) + "`n")
}

function Write-SetupPayloadMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$PayloadPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('main', 'pdf-extension')]
        [string]$ProductKind,
        [Parameter(Mandatory = $true)][string]$PublisherCertificateSha256
    )

    $payload = Get-Item -LiteralPath $PayloadPath -Force
    if ($payload.PSIsContainer -or
        ($payload.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $payload.Length -le 0) {
        Fail-Release 'release_setup_payload_invalid'
    }
    $metadata = [ordered]@{
        schemaVersion = 1
        productKind = $ProductKind
        productVersion = $Version
        payloadLength = [long]$payload.Length
        payloadSha256 = Get-LowerSha256 -Path $payload.FullName
        publisherCertificateSha256 = $PublisherCertificateSha256
    }
    Write-Utf8File -Path $OutputPath -Content (($metadata | ConvertTo-Json -Depth 3) + "`n")
}

function Get-FileManifest {
    param([Parameter(Mandatory = $true)][string]$Root)

    return @(
        Get-ChildItem -LiteralPath $Root -Recurse -File |
            Sort-Object FullName |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/')
                    length = $_.Length
                    sha256 = Get-LowerSha256 -Path $_.FullName
                }
            }
    )
}

function Assert-PublishPayloadPolicy {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$RelativePaths)

    $allowed = @(
        'CodeSignAuto.exe'
        'e_sqlite3.dll'
        'CodeSignAuto.runtimeconfig.json'
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $RelativePaths) {
        if ([string]::IsNullOrWhiteSpace($path) -or
            -not ($allowed -ccontains $path) -or
            -not $seen.Add($path)) {
            Fail-Release 'release_publish_payload_forbidden'
        }
    }
    foreach ($required in @('CodeSignAuto.exe', 'e_sqlite3.dll')) {
        if (-not ($RelativePaths -ccontains $required)) {
            Fail-Release 'release_publish_payload_missing'
        }
    }
}

function Assert-ReleasePackageFileSet {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ExpectedFiles
    )

    Assert-ReleaseTree -Root $Root
    $expected = @($ExpectedFiles | Sort-Object)
    if (@($expected | Select-Object -Unique).Count -ne $expected.Count) {
        Fail-Release 'release_package_file_set_mismatch'
    }
    $actual = @(
        Get-ChildItem -LiteralPath $Root -Recurse -File |
            ForEach-Object {
                $_.FullName.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/')
            } |
            Sort-Object
    )
    if (@(Compare-Object -ReferenceObject $expected -DifferenceObject $actual -CaseSensitive).Count -ne 0) {
        Fail-Release 'release_package_file_set_mismatch'
    }
}

function Copy-PublishPayload {
    param(
        [Parameter(Mandatory = $true)][string]$PublishRoot,
        [Parameter(Mandatory = $true)][string]$PackageRoot
    )

    Assert-ReleaseTree -Root $PublishRoot
    $files = @(Get-ChildItem -LiteralPath $PublishRoot -Recurse -File -Force | Sort-Object FullName)
    $relativePaths = @(
        $files | ForEach-Object {
            $_.FullName.Substring($PublishRoot.Length).TrimStart('\', '/').Replace('\', '/')
        }
    )
    Assert-PublishPayloadPolicy -RelativePaths $relativePaths
    [System.IO.Directory]::CreateDirectory($PackageRoot) | Out-Null
    Assert-PlainDirectory -Path $PackageRoot
    $copied = New-Object System.Collections.Generic.List[string]
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($PublishRoot.Length).TrimStart('\', '/').Replace('\', '/')
        $destination = Join-Path $PackageRoot $relative
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($destination)) | Out-Null
        [System.IO.File]::Copy($file.FullName, $destination, $false)
        $copied.Add($relative)
    }
    return $copied.ToArray()
}

function Get-ManagedAssemblyHashes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The established private function returns a set of hashes and is retained for compatibility.')]
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $bundleInputRoot = Join-Path $RepoRoot 'src/CodeSignAuto.App/bin/Release/net10.0-windows/win-x64'
    if (-not (Test-Path -LiteralPath $bundleInputRoot -PathType Container) -or
        ((Get-Item -LiteralPath $bundleInputRoot -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Release 'release_managed_output_missing'
    }

    $projects = @(
        'CodeSignAuto.Core'
        'CodeSignAuto.Protocol'
        'CodeSignAuto.Agent'
        'CodeSignAuto.Service'
        'CodeSignAuto'
    )
    $hashes = [ordered]@{}
    foreach ($project in $projects) {
        $candidate = Join-Path $bundleInputRoot ($project + '.dll')
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
            ((Get-Item -LiteralPath $candidate -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Release 'release_managed_output_missing'
        }
        $hashes[$project] = Get-LowerSha256 -Path $candidate
    }
    return $hashes
}

function Copy-ReleaseSource {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    [System.IO.Directory]::CreateDirectory($DestinationRoot) | Out-Null
    foreach ($name in @('Directory.Build.props', 'Directory.Packages.props')) {
        [System.IO.File]::Copy(
            (Join-Path $RepoRoot $name),
            (Join-Path $DestinationRoot $name),
            $false)
    }
    $sourceRoot = Join-Path $RepoRoot 'src'
    foreach ($directory in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Directory -Force)) {
        if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Release 'release_source_reparse'
        }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Force)) {
        $relative = $file.FullName.Substring($RepoRoot.Length).TrimStart('\', '/')
        if ($relative -match '(^|[\\/])(bin|obj)([\\/]|$)') {
            continue
        }
        $destination = Join-Path $DestinationRoot $relative
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($destination)) | Out-Null
        [System.IO.File]::Copy($file.FullName, $destination, $false)
    }
}

function Get-LockedPackageVersions {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The established private function returns a version map and is retained for compatibility.')]
    param([Parameter(Mandatory = $true)][string]$Root)

    $versions = [ordered]@{}
    foreach ($lockPath in @(Get-ChildItem -LiteralPath (Join-Path $Root 'src') -Recurse -File -Filter 'packages.lock.json')) {
        $lock = Get-Content -LiteralPath $lockPath.FullName -Raw | ConvertFrom-Json
        foreach ($framework in $lock.dependencies.PSObject.Properties) {
            foreach ($dependency in $framework.Value.PSObject.Properties) {
                $resolved = $dependency.Value.PSObject.Properties['resolved']
                if ($null -eq $resolved) {
                    continue
                }
                $key = $dependency.Name.ToLowerInvariant()
                $value = [string]$resolved.Value
                if ($versions.Contains($key) -and $versions[$key] -ne $value) {
                    Fail-Release 'release_lock_inconsistent'
                }
                $versions[$key] = $value
            }
        }
    }
    return $versions
}

function Get-ReleasePackageLockPaths {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The established private function returns the complete lock-file path set.')]
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $sourceRoot = Join-Path $RepoRoot 'src'
    Assert-PlainDirectory -Path $sourceRoot
    return @(
        Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Filter 'packages.lock.json' |
            Sort-Object FullName |
            ForEach-Object { $_.FullName }
    )
}

function Assert-RidLockPreservesVersions {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseSingularNouns',
        '',
        Justification = 'The established private assertion compares the full set of package versions.')]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$RidSourceRoot
    )

    $baseline = Get-LockedPackageVersions -Root $RepoRoot
    $rid = Get-LockedPackageVersions -Root $RidSourceRoot
    foreach ($name in $baseline.Keys) {
        if (-not $rid.Contains($name) -or $rid[$name] -ne $baseline[$name]) {
            Fail-Release 'release_lock_version_changed'
        }
    }
}

function Invoke-ReleaseCandidate {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RidSourceRoot,
        [Parameter(Mandatory = $true)][string]$BuildRoot,
        [Parameter(Mandatory = $true)][string]$Dotnet
    )

    $candidateRoot = Join-Path $BuildRoot $Name
    [System.IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    $publishRoot = Join-Path $candidateRoot 'publish'
    [System.IO.Directory]::CreateDirectory($publishRoot) | Out-Null

    Invoke-Checked -FilePath $Dotnet -WorkingDirectory $RidSourceRoot -ArgumentList @(
        'publish', 'src/CodeSignAuto.App/CodeSignAuto.App.csproj',
        '-c', 'Release',
        '-r', 'win-x64',
        '--self-contained', 'false',
        '--no-restore',
        '-m:1',
        '-nodeReuse:false',
        '-p:PublishSingleFile=true',
        '-p:EnableCompressionInSingleFile=false',
        '-p:EnableSingleFileAnalyzer=false',
        '-p:PublishReadyToRun=false',
        '-p:PublishTrimmed=false',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        '-p:Deterministic=true',
        "-p:Version=$Version",
        '-o', $publishRoot
    )

    $application = Join-Path $publishRoot 'CodeSignAuto.exe'
    if (-not (Test-Path -LiteralPath $application -PathType Leaf)) {
        Fail-Release 'release_application_missing'
    }

    return [pscustomobject]@{
        Name = $Name
        Root = $candidateRoot
        PublishRoot = $publishRoot
        Application = $application
        Files = @(Get-FileManifest -Root $publishRoot)
        Managed = Get-ManagedAssemblyHashes -RepoRoot $RidSourceRoot
    }
}

function Assert-Reproducibility {
    param(
        [Parameter(Mandatory = $true)]$First,
        [Parameter(Mandatory = $true)]$Second,
        [Parameter(Mandatory = $true)][string]$ReportPath
    )

    $firstPaths = @($First.Files | ForEach-Object { $_.path })
    $secondPaths = @($Second.Files | ForEach-Object { $_.path })
    if ((ConvertTo-Json $firstPaths -Compress) -ne (ConvertTo-Json $secondPaths -Compress)) {
        Fail-Release 'release_file_manifest_mismatch'
    }

    $firstManagedNames = @($First.Managed.Keys | Sort-Object)
    $secondManagedNames = @($Second.Managed.Keys | Sort-Object)
    if ((ConvertTo-Json $firstManagedNames -Compress) -ne (ConvertTo-Json $secondManagedNames -Compress)) {
        Fail-Release 'release_managed_hash_mismatch'
    }
    foreach ($name in $First.Managed.Keys) {
        if ($First.Managed[$name] -ne $Second.Managed[$name]) {
            Fail-Release 'release_managed_hash_mismatch'
        }
    }

    for ($index = 0; $index -lt $First.Files.Count; $index++) {
        if ($First.Files[$index].sha256 -ne $Second.Files[$index].sha256 -or
            $First.Files[$index].length -ne $Second.Files[$index].length) {
            Fail-Release 'release_file_hash_mismatch'
        }
    }

    $report = [ordered]@{
        schemaVersion = 1
        releaseVersion = $Version
        fileSetMatched = $true
        byteForByteMatched = $true
        managedAssembliesMatched = $true
        publishFilesMatched = $true
        note = 'Both unsigned framework-dependent publish candidates matched byte for byte.'
    }
    Write-Utf8File -Path $ReportPath -Content (($report | ConvertTo-Json -Depth 5) + "`n")
}

function Write-SpdxSbom {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $packages = [ordered]@{}
    foreach ($lockPath in @(Get-ReleasePackageLockPaths -RepoRoot $RepoRoot)) {
        $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
        foreach ($framework in $lock.dependencies.PSObject.Properties) {
            foreach ($dependency in $framework.Value.PSObject.Properties) {
                $typeProperty = $dependency.Value.PSObject.Properties['type']
                $resolvedProperty = $dependency.Value.PSObject.Properties['resolved']
                if ($null -ne $typeProperty -and
                    $typeProperty.Value -ne 'Project' -and
                    $null -ne $resolvedProperty) {
                    $packages[('nuget:' + $dependency.Name.ToLowerInvariant())] = [ordered]@{
                        name = $dependency.Name
                        version = [string]$resolvedProperty.Value
                        supplier = 'NOASSERTION'
                        downloadLocation = 'NOASSERTION'
                        filesAnalyzed = $false
                        licenseConcluded = 'NOASSERTION'
                        licenseDeclared = if ($dependency.Name -eq 'PdfPig') { 'Apache-2.0' } else { 'NOASSERTION' }
                        SPDXID = 'SPDXRef-NuGet-' + ($dependency.Name -replace '[^A-Za-z0-9.-]', '-')
                    }
                }
            }
        }
    }

    $sortedPackages = @(
        $packages.Keys | Sort-Object | ForEach-Object {
            $package = $packages[$_]
            [ordered]@{
                name = $package.name
                versionInfo = $package.version
                supplier = $package.supplier
                downloadLocation = $package.downloadLocation
                filesAnalyzed = $package.filesAnalyzed
                licenseConcluded = $package.licenseConcluded
                licenseDeclared = $package.licenseDeclared
                SPDXID = $package.SPDXID
            }
        }
    )

    $document = [ordered]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = "CodeSignAuto-$Version-win-x64"
        documentNamespace = "https://codesignauto.invalid/spdx/$Version/win-x64"
        creationInfo = [ordered]@{
            created = $SbomCreatedUtc
            creators = @('Tool: scripts/build-release.ps1')
        }
        packages = @(
            [ordered]@{
                name = 'CodeSignAuto'
                versionInfo = $Version
                supplier = 'NOASSERTION'
                downloadLocation = 'NOASSERTION'
                filesAnalyzed = $false
                licenseConcluded = 'NOASSERTION'
                licenseDeclared = 'NOASSERTION'
                SPDXID = 'SPDXRef-Package-CodeSignAuto'
            }
        ) + $sortedPackages
    }
    Write-Utf8File -Path $OutputPath -Content (($document | ConvertTo-Json -Depth 7) + "`n")
}

function New-DeterministicZip {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This private deterministic archive writer only targets the validated release output path.')]
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    Add-Type -AssemblyName System.IO.Compression
    $partPath = $DestinationPath + '.' + [Guid]::NewGuid().ToString('N') + '.part'
    $output = [System.IO.FileStream]::new(
        $partPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $output,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $true)
        try {
            foreach ($file in @(Get-ChildItem -LiteralPath $SourceRoot -Recurse -File | Sort-Object FullName)) {
                $relative = $file.FullName.Substring($SourceRoot.Length).TrimStart('\', '/').Replace('\', '/')
                $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $entryStream = $entry.Open()
                $inputStream = [System.IO.File]::OpenRead($file.FullName)
                try {
                    $inputStream.CopyTo($entryStream)
                } finally {
                    $inputStream.Dispose()
                    $entryStream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
        $output.Flush($true)
    } finally {
        $output.Dispose()
    }

    if (Test-Path -LiteralPath $DestinationPath) {
        [System.IO.File]::Delete($DestinationPath)
    }
    [System.IO.File]::Move($partPath, $DestinationPath)
}

function Invoke-ReleaseArtifactSign {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SigningBaseUrl,
        [Parameter(Mandatory = $true)][string]$SigningBearerToken,
        [Parameter(Mandatory = $true)][string]$SigningCertificateSerial,
        [Parameter(Mandatory = $true)][string]$IdempotencyPrefix,
        [Parameter(Mandatory = $true)][TimeSpan]$SigningTimeout
    )

    $signedPath = Join-Path `
        ([System.IO.Path]::GetDirectoryName($Path)) `
        ([System.IO.Path]::GetFileNameWithoutExtension($Path) + '.' +
            [Guid]::NewGuid().ToString('N') + '.signed' +
            [System.IO.Path]::GetExtension($Path))
    try {
        $null = Invoke-SimplySignArtifact `
            -InputPath $Path `
            -OutputPath $signedPath `
            -BaseUrl $SigningBaseUrl `
            -BearerToken $SigningBearerToken `
            -CertificateSerialNumber $SigningCertificateSerial `
            -IdempotencyPrefix $IdempotencyPrefix `
            -Timeout $SigningTimeout
        $signature = Get-AuthenticodeSignature -LiteralPath $signedPath
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate -or
            $null -eq $signature.TimeStamperCertificate -or
            (ConvertTo-CanonicalCertificateSerial -Value $signature.SignerCertificate.SerialNumber) -cne
                $SigningCertificateSerial) {
            Fail-Release 'release_artifact_signature_invalid'
        }
        Move-SimplySignArtifactIntoPlace -SignedPath $signedPath -DestinationPath $Path
        return $signature
    }
    finally {
        if (Test-Path -LiteralPath $signedPath -PathType Leaf) {
            [System.IO.File]::Delete($signedPath)
        }
    }
}

function Publish-SetupArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Dotnet,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$SetupProject,
        [Parameter(Mandatory = $true)][string]$BuildRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseRoot,
        [Parameter(Mandatory = $true)][string]$PublishName,
        [Parameter(Mandatory = $true)][string]$ArtifactName,
        [Parameter(Mandatory = $true)][string]$PayloadPath,
        [Parameter(Mandatory = $true)][string]$MetadataPath,
        [Parameter(Mandatory = $true)][string]$SigningBaseUrl,
        [Parameter(Mandatory = $true)][string]$SigningBearerToken,
        [Parameter(Mandatory = $true)][string]$SigningCertificateSerial,
        [Parameter(Mandatory = $true)][TimeSpan]$SigningTimeout
    )

    $publishRoot = Join-Path $BuildRoot ("setup-publish-" + $PublishName)
    Invoke-Checked -FilePath $Dotnet -WorkingDirectory $WorkingDirectory -ArgumentList @(
        'publish', $SetupProject,
        '-c', 'Release',
        '-r', 'win-x64',
        '--self-contained', 'false',
        '--no-restore',
        '-m:1',
        '-nodeReuse:false',
        '-p:PublishSingleFile=true',
        '-p:EnableCompressionInSingleFile=false',
        '-p:EnableSingleFileAnalyzer=false',
        '-p:PublishReadyToRun=false',
        '-p:PublishTrimmed=false',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        '-p:Deterministic=true',
        "-p:Version=$Version",
        "-p:SetupPayloadPath=$PayloadPath",
        "-p:SetupMetadataPath=$MetadataPath",
        '-o', $publishRoot)
    $builtSetupPath = Join-Path $publishRoot 'CodeSignAutoSetup.exe'
    if (-not (Test-Path -LiteralPath $builtSetupPath -PathType Leaf) -or
        ((Get-Item -LiteralPath $builtSetupPath -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Release 'release_setup_missing'
    }

    $artifactPath = Join-Path $ReleaseRoot $ArtifactName
    $partPath = $artifactPath + '.' + [Guid]::NewGuid().ToString('N') + '.part.exe'
    try {
        [System.IO.File]::Copy($builtSetupPath, $partPath, $false)
        $null = Invoke-ReleaseArtifactSign `
            -Path $partPath `
            -SigningBaseUrl $SigningBaseUrl `
            -SigningBearerToken $SigningBearerToken `
            -SigningCertificateSerial $SigningCertificateSerial `
            -IdempotencyPrefix ("release-$PublishName-setup") `
            -SigningTimeout $SigningTimeout
        [System.IO.File]::Move($partPath, $artifactPath)
    } finally {
        if (Test-Path -LiteralPath $partPath -PathType Leaf) {
            [System.IO.File]::Delete($partPath)
        }
    }

    return $artifactPath
}

function Invoke-BuildReleaseMain {
param(
    [Parameter(Mandatory = $true)][string]$Version
)
if ($Version -notmatch $SemVerPattern) {
    Fail-Release 'release_version_invalid'
}
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    Fail-Release 'release_windows_required'
}

$SigningBaseUrl = [Environment]::GetEnvironmentVariable(
    'SIMPLYSIGN_SIGNING_BASE_URL',
    [EnvironmentVariableTarget]::Process)
$SigningBearerToken = [Environment]::GetEnvironmentVariable(
    'SIMPLYSIGN_SIGNING_BEARER_TOKEN',
    [EnvironmentVariableTarget]::Process)
$SigningCertificateSerial = [Environment]::GetEnvironmentVariable(
    'SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL',
    [EnvironmentVariableTarget]::Process)
$signingUri = $null
try {
    $SigningCertificateSerial = ConvertTo-CanonicalCertificateSerial `
        -Value $SigningCertificateSerial
}
catch {
    Fail-Release 'release_signing_parameters_invalid'
}
if (-not [Uri]::TryCreate($SigningBaseUrl, [UriKind]::Absolute, [ref]$signingUri) -or
    ($signingUri.Scheme -cne 'http' -and $signingUri.Scheme -cne 'https') -or
    -not [string]::IsNullOrEmpty($signingUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($signingUri.Query) -or
    -not [string]::IsNullOrEmpty($signingUri.Fragment) -or
    [string]::IsNullOrWhiteSpace($SigningBearerToken) -or
    $SigningBearerToken.IndexOfAny([char[]]@("`r", "`n", [char]0)) -ge 0) {
    Fail-Release 'release_signing_parameters_invalid'
}
$SigningTimeout = [TimeSpan]::FromMinutes(10)

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Assert-PlainDirectory -Path $RepoRoot
$Dotnet = (Get-Command dotnet -CommandType Application -ErrorAction Stop).Path
$Solution = Join-Path $RepoRoot 'CodeSignAuto.sln'
$ArtifactsRoot = Join-Path $RepoRoot 'artifacts'
$BuildBase = Join-Path $ArtifactsRoot 'build'
$BuildRoot = Join-Path $BuildBase $Version
$ReleaseRoot = Join-Path $ArtifactsRoot 'release'

[System.IO.Directory]::CreateDirectory($ArtifactsRoot) | Out-Null
Assert-PlainDirectory -Path $ArtifactsRoot
[System.IO.Directory]::CreateDirectory($BuildBase) | Out-Null
Assert-PlainDirectory -Path $BuildBase
if (Test-Path -LiteralPath $ReleaseRoot) {
    Assert-PlainDirectory -Path $ReleaseRoot
    Remove-Item -LiteralPath $ReleaseRoot -Recurse -Force
}
[System.IO.Directory]::CreateDirectory($ReleaseRoot) | Out-Null
if (-not $BuildRoot.StartsWith($BuildBase + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([System.IO.Path]::GetDirectoryName($BuildRoot), $BuildBase, [StringComparison]::OrdinalIgnoreCase)) {
    Fail-Release 'release_path_invalid'
}
if (Test-Path -LiteralPath $BuildRoot) {
    Assert-PlainDirectory -Path $BuildRoot
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}
[System.IO.Directory]::CreateDirectory($BuildRoot) | Out-Null
$pdfReleaseDecision = Get-PdfReleaseDecision -RepositoryRoot $RepoRoot -Version $Version
Write-PdfReleaseDecision `
    -Decision $pdfReleaseDecision `
    -OutputPath (Join-Path $BuildRoot 'pdf-release-decision.json')

Invoke-Checked -FilePath $Dotnet -WorkingDirectory $RepoRoot -ArgumentList @('restore', $Solution, '--locked-mode', '-m:1', '-nodeReuse:false')
Invoke-ReleaseTestSuite -Dotnet $Dotnet -RepoRoot $RepoRoot -ResultsRoot (Join-Path $BuildRoot 'test-results')

$ridSourceRoot = Join-Path $BuildRoot 'rid-source'
Copy-ReleaseSource -RepoRoot $RepoRoot -DestinationRoot $ridSourceRoot
$ridAppProject = Join-Path $ridSourceRoot 'src/CodeSignAuto.App/CodeSignAuto.App.csproj'
Invoke-Checked -FilePath $Dotnet -WorkingDirectory $ridSourceRoot -ArgumentList @(
    'restore', $ridAppProject, '--force-evaluate', '-r', 'win-x64',
    '-p:NuGetAudit=false', '-m:1', '-nodeReuse:false')
Assert-RidLockPreservesVersions -RepoRoot $RepoRoot -RidSourceRoot $ridSourceRoot
Invoke-Checked -FilePath $Dotnet -WorkingDirectory $ridSourceRoot -ArgumentList @(
    'restore', $ridAppProject, '--locked-mode', '-r', 'win-x64',
    '-p:NuGetAudit=false', '-m:1', '-nodeReuse:false')

$first = Invoke-ReleaseCandidate -Name 'first' -RidSourceRoot $ridSourceRoot -BuildRoot $BuildRoot -Dotnet $Dotnet
$second = Invoke-ReleaseCandidate -Name 'second' -RidSourceRoot $ridSourceRoot -BuildRoot $BuildRoot -Dotnet $Dotnet
$reproducibility = Join-Path $BuildRoot 'reproducibility.json'
Assert-Reproducibility -First $first -Second $second -ReportPath $reproducibility
$expectedPublishFiles = @('CodeSignAuto.exe', 'e_sqlite3.dll')
if (@($first.Files | Where-Object { $_.path -ceq 'CodeSignAuto.runtimeconfig.json' }).Count -eq 1) {
    $expectedPublishFiles += 'CodeSignAuto.runtimeconfig.json'
}

$pdfHelperRoot = Join-Path $RepoRoot 'tools/pdf-signer'
$uv = (Get-Command uv -CommandType Application -ErrorAction Stop).Path
Invoke-Checked -FilePath $uv -WorkingDirectory $pdfHelperRoot -ArgumentList @('sync', '--frozen')
Invoke-Checked -FilePath $uv -WorkingDirectory $pdfHelperRoot -ArgumentList @('run', 'pytest', '-q')
Invoke-Checked -FilePath $uv -WorkingDirectory $pdfHelperRoot -ArgumentList @('run', 'ruff', 'check', '.')
Invoke-Checked -FilePath $uv -WorkingDirectory $pdfHelperRoot -ArgumentList @(
    'run', 'pyinstaller', '--clean', '--noconfirm', 'pdf-signer.spec')
$builtPdfHelperPath = Join-Path $pdfHelperRoot 'dist/CodeSignAutoPdfSigner.exe'
if (-not (Test-Path -LiteralPath $builtPdfHelperPath -PathType Leaf)) {
    Fail-Release 'release_pdf_helper_missing'
}
$builtPdfHelper = Get-Item -LiteralPath $builtPdfHelperPath -Force
if (($builtPdfHelper.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $builtPdfHelper.Length -le 0) {
    Fail-Release 'release_pdf_helper_invalid'
}
$frozenHelperEnvironmentName = 'SIMPLYSIGN_FROZEN_HELPER_PATH'
$previousFrozenHelperPath = [Environment]::GetEnvironmentVariable(
    $frozenHelperEnvironmentName,
    [EnvironmentVariableTarget]::Process)
try {
    [Environment]::SetEnvironmentVariable(
        $frozenHelperEnvironmentName,
        $builtPdfHelperPath,
        [EnvironmentVariableTarget]::Process)
    Invoke-Checked -FilePath $uv -WorkingDirectory $pdfHelperRoot -ArgumentList @(
        'run', 'pytest', '-q', 'tests/test_sign_command.py', '-k',
        'frozen_executable_validates_real_pades_and_probe_surface')
} finally {
    [Environment]::SetEnvironmentVariable(
        $frozenHelperEnvironmentName,
        $previousFrozenHelperPath,
        [EnvironmentVariableTarget]::Process)
}
[string[]]$pdfHelperVersionOutput = @(& $builtPdfHelperPath '--version' 2>&1)
if ($LASTEXITCODE -ne 0 -or
    $pdfHelperVersionOutput.Count -ne 1 -or
    $pdfHelperVersionOutput[0] -notmatch $SemVerPattern) {
    Fail-Release 'release_pdf_helper_version_invalid'
}
$pdfHelperVersion = $pdfHelperVersionOutput[0]
if ($pdfReleaseDecision.releasePdf -and $pdfHelperVersion -cne $Version) {
    Fail-Release 'release_pdf_helper_version_mismatch'
}

$packageRoot = Join-Path $BuildRoot ("CodeSignAuto-$Version-win-x64")
[System.IO.Directory]::CreateDirectory($packageRoot) | Out-Null
$null = Copy-PublishPayload -PublishRoot $first.PublishRoot -PackageRoot $packageRoot
[System.IO.File]::Copy((Join-Path $RepoRoot 'packaging/agent.example.json'), (Join-Path $packageRoot 'agent.example.json'), $false)
[System.IO.File]::Copy((Join-Path $RepoRoot 'packaging/service.example.json'), (Join-Path $packageRoot 'service.example.json'), $false)
[System.IO.File]::Copy((Join-Path $RepoRoot 'packaging/README.txt'), (Join-Path $packageRoot 'README.txt'), $false)
[System.IO.File]::Copy((Join-Path $RepoRoot 'README.md'), (Join-Path $packageRoot 'OPERATIONS.md'), $false)
[System.IO.File]::Copy(
    (Join-Path $RepoRoot 'packaging/install-prerequisites.ps1'),
    (Join-Path $packageRoot 'install-prerequisites.ps1'),
    $false)
[System.IO.File]::Copy(
    (Join-Path $RepoRoot 'packaging/runtime-prerequisites.json'),
    (Join-Path $packageRoot 'runtime-prerequisites.json'),
    $false)
[System.IO.File]::Copy(
    (Join-Path $RepoRoot 'LICENSE'),
    (Join-Path $packageRoot 'LICENSE.txt'),
    $false)
[System.IO.File]::Copy(
    (Join-Path $RepoRoot 'THIRD-PARTY-NOTICES.txt'),
    (Join-Path $packageRoot 'THIRD-PARTY-NOTICES.txt'),
    $false)
[System.IO.File]::Copy($reproducibility, (Join-Path $packageRoot 'reproducibility.json'), $false)
Write-SpdxSbom -RepoRoot $RepoRoot -OutputPath (Join-Path $packageRoot 'sbom.spdx.json')

$expectedPackageFiles = @(
    $expectedPublishFiles
    'agent.example.json'
    'service.example.json'
    'README.txt'
    'OPERATIONS.md'
    'install-prerequisites.ps1'
    'runtime-prerequisites.json'
    'LICENSE.txt'
    'THIRD-PARTY-NOTICES.txt'
    'reproducibility.json'
    'sbom.spdx.json'
) | Sort-Object
Assert-ReleasePackageFileSet -Root $packageRoot -ExpectedFiles $expectedPackageFiles

$releaseSigningScript = Join-Path $RepoRoot 'scripts/sign-release-media.ps1'
$windowsPowerShell = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Path
Invoke-Checked -FilePath $windowsPowerShell -WorkingDirectory $RepoRoot -ArgumentList @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'RemoteSigned',
    '-File', $releaseSigningScript,
    '-PackageRoot', $packageRoot)
$expectedSignedPackageFiles = @($expectedPackageFiles + 'release-files.cat') | Sort-Object
Assert-ReleasePackageFileSet -Root $packageRoot -ExpectedFiles $expectedSignedPackageFiles
$mainApplicationSignature = Get-AuthenticodeSignature -LiteralPath (
    Join-Path $packageRoot 'CodeSignAuto.exe')
if ($mainApplicationSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    $null -eq $mainApplicationSignature.SignerCertificate -or
    $null -eq $mainApplicationSignature.TimeStamperCertificate -or
    (ConvertTo-CanonicalCertificateSerial -Value $mainApplicationSignature.SignerCertificate.SerialNumber) -cne
        $SigningCertificateSerial) {
    Fail-Release 'release_application_signature_invalid'
}
$publisherCertificateSha256 = Get-CertificateSha256 `
    -RawData $mainApplicationSignature.SignerCertificate.RawData
Invoke-Checked -FilePath $windowsPowerShell -WorkingDirectory $RepoRoot -ArgumentList @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $packageRoot 'install-prerequisites.ps1'),
    '-ReleaseMediaRoot', $packageRoot,
    '-VerifyMediaOnly')
Assert-ReleasePackageFileSet -Root $packageRoot -ExpectedFiles $expectedSignedPackageFiles

$mainPayloadZipPath = Join-Path $BuildRoot ("CodeSignAuto-$Version-win-x64.internal.zip")
New-DeterministicZip -SourceRoot $packageRoot -DestinationPath $mainPayloadZipPath
$mainSetupMetadataPath = Join-Path $BuildRoot 'setup-main-metadata.json'
Write-SetupPayloadMetadata `
    -PayloadPath $mainPayloadZipPath `
    -OutputPath $mainSetupMetadataPath `
    -ProductKind 'main' `
    -PublisherCertificateSha256 $publisherCertificateSha256

$ridSetupProject = Join-Path $ridSourceRoot 'src/CodeSignAuto.Setup/CodeSignAuto.Setup.csproj'
Invoke-Checked -FilePath $Dotnet -WorkingDirectory $ridSourceRoot -ArgumentList @(
    'restore', $ridSetupProject, '--force-evaluate', '-r', 'win-x64',
    '-p:NuGetAudit=false', '-m:1', '-nodeReuse:false')
$setupArtifactPath = Publish-SetupArtifact `
    -Dotnet $Dotnet `
    -WorkingDirectory $ridSourceRoot `
    -SetupProject $ridSetupProject `
    -BuildRoot $BuildRoot `
    -ReleaseRoot $ReleaseRoot `
    -PublishName 'main' `
    -ArtifactName ("CodeSignAutoSetup-$Version-win-x64.exe") `
    -PayloadPath $mainPayloadZipPath `
    -MetadataPath $mainSetupMetadataPath `
    -SigningBaseUrl $SigningBaseUrl `
    -SigningBearerToken $SigningBearerToken `
    -SigningCertificateSerial $SigningCertificateSerial `
    -SigningTimeout $SigningTimeout

$finalArtifactPaths = @($setupArtifactPath)
$pdfSetupArtifactPath = $null
if ($pdfReleaseDecision.releasePdf) {
    $pdfHelperArtifactPath = Join-Path $BuildRoot 'CodeSignAutoPdfSigner.exe'
    [System.IO.File]::Copy($builtPdfHelperPath, $pdfHelperArtifactPath, $false)
    $pdfHelperSignature = Invoke-ReleaseArtifactSign `
        -Path $pdfHelperArtifactPath `
        -SigningBaseUrl $SigningBaseUrl `
        -SigningBearerToken $SigningBearerToken `
        -SigningCertificateSerial $SigningCertificateSerial `
        -IdempotencyPrefix 'release-pdf-helper' `
        -SigningTimeout $SigningTimeout
    if ((Get-CertificateSha256 -RawData $pdfHelperSignature.SignerCertificate.RawData) -cne
        $publisherCertificateSha256) {
        Fail-Release 'release_pdf_helper_signature_invalid'
    }
    $pdfHelperArtifact = Get-Item -LiteralPath $pdfHelperArtifactPath -Force
    $pdfHelperSha256 = Get-LowerSha256 -Path $pdfHelperArtifactPath

    $pdfPackageRoot = Join-Path $BuildRoot ("CodeSignAutoPdfSupport-$Version-win-x64")
    [System.IO.Directory]::CreateDirectory($pdfPackageRoot) | Out-Null
    [System.IO.File]::Copy(
        $pdfHelperArtifactPath,
        (Join-Path $pdfPackageRoot 'CodeSignAutoPdfSigner.exe'),
        $false)
    [System.IO.File]::Copy(
        (Join-Path $RepoRoot 'LICENSE'),
        (Join-Path $pdfPackageRoot 'LICENSE.txt'),
        $false)
    [System.IO.File]::Copy(
        (Join-Path $RepoRoot 'THIRD-PARTY-NOTICES.txt'),
        (Join-Path $pdfPackageRoot 'THIRD-PARTY-NOTICES.txt'),
        $false)
    Write-PdfExtensionManifest `
        -OutputPath (Join-Path $pdfPackageRoot 'extension.json') `
        -ProductVersion $Version `
        -HelperVersion $pdfHelperVersion `
        -HelperLength $pdfHelperArtifact.Length `
        -HelperSha256 $pdfHelperSha256 `
        -PublisherCertificateSha256 $publisherCertificateSha256
    Assert-ReleasePackageFileSet `
        -Root $pdfPackageRoot `
        -ExpectedFiles @(
            'extension.json',
            'LICENSE.txt',
            'CodeSignAutoPdfSigner.exe',
            'THIRD-PARTY-NOTICES.txt')
    $pdfPayloadZipPath = Join-Path $BuildRoot (
        "CodeSignAutoPdfSupport-$Version-win-x64.internal.zip")
    New-DeterministicZip -SourceRoot $pdfPackageRoot -DestinationPath $pdfPayloadZipPath
    $pdfSetupMetadataPath = Join-Path $BuildRoot 'setup-pdf-metadata.json'
    Write-SetupPayloadMetadata `
        -PayloadPath $pdfPayloadZipPath `
        -OutputPath $pdfSetupMetadataPath `
        -ProductKind 'pdf-extension' `
        -PublisherCertificateSha256 $publisherCertificateSha256

    $pdfSetupArtifactPath = Publish-SetupArtifact `
        -Dotnet $Dotnet `
        -WorkingDirectory $ridSourceRoot `
        -SetupProject $ridSetupProject `
        -BuildRoot $BuildRoot `
        -ReleaseRoot $ReleaseRoot `
        -PublishName 'pdf' `
        -ArtifactName ("CodeSignAutoPdfSetup-$Version-win-x64.exe") `
        -PayloadPath $pdfPayloadZipPath `
        -MetadataPath $pdfSetupMetadataPath `
        -SigningBaseUrl $SigningBaseUrl `
        -SigningBearerToken $SigningBearerToken `
        -SigningCertificateSerial $SigningCertificateSerial `
        -SigningTimeout $SigningTimeout
    $finalArtifactPaths += $pdfSetupArtifactPath
}

foreach ($finalArtifactPath in $finalArtifactPaths) {
    $finalSignature = Get-AuthenticodeSignature -LiteralPath $finalArtifactPath
    if ($finalSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $finalSignature.SignerCertificate -or
        $null -eq $finalSignature.TimeStamperCertificate -or
        (ConvertTo-CanonicalCertificateSerial -Value $finalSignature.SignerCertificate.SerialNumber) -cne
            $SigningCertificateSerial -or
        (Get-CertificateSha256 -RawData $finalSignature.SignerCertificate.RawData) -cne
            $publisherCertificateSha256) {
        Fail-Release 'release_setup_signature_invalid'
    }
}

$expectedReleaseFiles = @($finalArtifactPaths | ForEach-Object {
    [System.IO.Path]::GetFileName($_)
}) | Sort-Object
Assert-ReleasePackageFileSet -Root $ReleaseRoot -ExpectedFiles $expectedReleaseFiles

$releaseSummary = "release_ok version=$Version setup_sha256=$(Get-LowerSha256 -Path $setupArtifactPath) pdf_release=$($pdfReleaseDecision.releasePdf.ToString().ToLowerInvariant()) reason=$($pdfReleaseDecision.reason)"
if ($pdfReleaseDecision.releasePdf) {
    $releaseSummary += " pdf_setup_sha256=$(Get-LowerSha256 -Path $pdfSetupArtifactPath)"
}
[Console]::Out.WriteLine($releaseSummary)
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-BuildReleaseMain -Version $Version
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
    exit 0
}
