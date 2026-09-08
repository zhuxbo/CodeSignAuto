[CmdletBinding()]
param(
    [string]$PackageRoot,

    [string]$BaseUrl,

    [string]$BearerToken,

    [string]$CertificateSerialNumber,

    [TimeSpan]$SigningTimeout = [TimeSpan]::FromMinutes(10)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$publisherPlaceholder = '__CODESIGNAUTO_PUBLISHER_CERTIFICATE_SHA256__'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$releaseNativeTypeBase64 = 'dXNpbmcgU3lzdGVtOyB1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7IHVzaW5nIE1pY3Jvc29mdC5XaW4zMi5TYWZlSGFuZGxlczsgbmFtZXNwYWNlIENvZGVTaWduQXV0by5SZWxlYXNlIHsgW1N0cnVjdExheW91dChMYXlvdXRLaW5kLlNlcXVlbnRpYWwpXSBwdWJsaWMgc3RydWN0IEZpbGVJbmZvcm1hdGlvbiB7IHB1YmxpYyB1aW50IEZpbGVBdHRyaWJ1dGVzOyBwdWJsaWMgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzLkZJTEVUSU1FIENyZWF0aW9uVGltZTsgcHVibGljIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5Db21UeXBlcy5GSUxFVElNRSBMYXN0QWNjZXNzVGltZTsgcHVibGljIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5Db21UeXBlcy5GSUxFVElNRSBMYXN0V3JpdGVUaW1lOyBwdWJsaWMgdWludCBWb2x1bWVTZXJpYWxOdW1iZXI7IHB1YmxpYyB1aW50IEZpbGVTaXplSGlnaDsgcHVibGljIHVpbnQgRmlsZVNpemVMb3c7IHB1YmxpYyB1aW50IG5OdW1iZXJPZkxpbmtzOyBwdWJsaWMgdWludCBGaWxlSW5kZXhIaWdoOyBwdWJsaWMgdWludCBGaWxlSW5kZXhMb3c7IH0gcHVibGljIHN0YXRpYyBjbGFzcyBOYXRpdmVNZXRob2RzIHsgW0RsbEltcG9ydCgia2VybmVsMzIuZGxsIiwgU2V0TGFzdEVycm9yPXRydWUpXSBbcmV0dXJuOiBNYXJzaGFsQXMoVW5tYW5hZ2VkVHlwZS5Cb29sKV0gcHVibGljIHN0YXRpYyBleHRlcm4gYm9vbCBHZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZShTYWZlRmlsZUhhbmRsZSBoYW5kbGUsIG91dCBGaWxlSW5mb3JtYXRpb24gaW5mb3JtYXRpb24pOyB9IH0='
$signingClientScript = Join-Path $PSScriptRoot 'sign-via-simplysign.ps1'
. $signingClientScript

function Stop-ReleaseSigning {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This helper only throws a stable failure code and changes no external state.')]
    param([Parameter(Mandatory = $true)][string]$Code)

    throw $Code
}

function Get-CanonicalPlainPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Leaf', 'Container')][string]$Kind
    )

    $canonical = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $canonical -PathType $Kind)) {
        Stop-ReleaseSigning 'release_signing_path_missing'
    }
    $item = Get-Item -LiteralPath $canonical -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Stop-ReleaseSigning 'release_signing_path_invalid'
    }
    return $canonical
}

function Get-CertificateSha256 {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Assert-PayloadTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    if ($null -eq ('CodeSignAuto.Release.NativeMethods' -as [type])) {
        $nativeSource = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($releaseNativeTypeBase64))
        Add-Type -TypeDefinition $nativeSource -ErrorAction Stop
    }
    $prefix = $Root.TrimEnd('\') + '\'
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force -Recurse)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $item.FullName.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            Stop-ReleaseSigning 'release_signing_payload_invalid'
        }
        if ($item.PSIsContainer) {
            continue
        }
        $stream = [IO.File]::Open(
            $item.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $information = New-Object CodeSignAuto.Release.FileInformation
            if (-not [CodeSignAuto.Release.NativeMethods]::GetFileInformationByHandle(
                    $stream.SafeFileHandle,
                    [ref]$information) -or
                $information.nNumberOfLinks -ne 1) {
                Stop-ReleaseSigning 'release_signing_payload_invalid'
            }
        }
        finally {
            $stream.Dispose()
        }
    }
}

function Write-PublisherIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$PublisherCertificateSha256
    )

    $content = [System.IO.File]::ReadAllText($Path)
    $placeholderCount = ([regex]::Matches($content, [regex]::Escape($publisherPlaceholder))).Count
    if ($placeholderCount -ne 1) {
        Stop-ReleaseSigning 'release_publisher_placeholder_invalid'
    }
    $content = $content.Replace($publisherPlaceholder, $PublisherCertificateSha256)
    [System.IO.File]::WriteAllText($Path, $content, $utf8NoBom)
}

function Assert-RemoteSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedCertificateSerialNumber
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $null -eq $signature.TimeStamperCertificate -or
        (ConvertTo-CanonicalCertificateSerial -Value $signature.SignerCertificate.SerialNumber) -cne
            (ConvertTo-CanonicalCertificateSerial -Value $ExpectedCertificateSerialNumber)) {
        Stop-ReleaseSigning 'release_authenticode_verify_failed'
    }
    return $signature
}

function Invoke-RemoteArtifactSignInPlace {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$BearerToken,
        [Parameter(Mandatory = $true)][string]$CertificateSerialNumber,
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
            -BaseUrl $BaseUrl `
            -BearerToken $BearerToken `
            -CertificateSerialNumber $CertificateSerialNumber `
            -IdempotencyPrefix $IdempotencyPrefix `
            -Timeout $SigningTimeout
        $signature = Assert-RemoteSignature `
            -Path $signedPath `
            -ExpectedCertificateSerialNumber $CertificateSerialNumber
        Move-SimplySignArtifactIntoPlace -SignedPath $signedPath -DestinationPath $Path
        return $signature
    }
    finally {
        if (Test-Path -LiteralPath $signedPath -PathType Leaf) {
            [System.IO.File]::Delete($signedPath)
        }
    }
}

function Invoke-SignReleaseMediaMain {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$BearerToken,
        [Parameter(Mandatory = $true)][string]$CertificateSerialNumber,
        [Parameter(Mandatory = $true)][TimeSpan]$SigningTimeout
    )

    $PackageRoot = Get-CanonicalPlainPath -Path $PackageRoot -Kind Container
    Assert-PayloadTree -Root $PackageRoot

    $applicationPath = Get-CanonicalPlainPath -Path (Join-Path $PackageRoot 'CodeSignAuto.exe') -Kind Leaf
    $prerequisiteScriptPath = Get-CanonicalPlainPath -Path (Join-Path $PackageRoot 'install-prerequisites.ps1') -Kind Leaf
    $catalogPath = Join-Path $PackageRoot 'release-files.cat'
    if (Test-Path -LiteralPath $catalogPath) {
        Stop-ReleaseSigning 'release_catalog_already_exists'
    }

    $applicationSignature = Invoke-RemoteArtifactSignInPlace `
        -Path $applicationPath `
        -BaseUrl $BaseUrl `
        -BearerToken $BearerToken `
        -CertificateSerialNumber $CertificateSerialNumber `
        -IdempotencyPrefix 'release-main-app' `
        -SigningTimeout $SigningTimeout
    $publisherCertificateSha256 = Get-CertificateSha256 `
        -Certificate $applicationSignature.SignerCertificate
    Write-PublisherIdentity -Path $prerequisiteScriptPath -PublisherCertificateSha256 $publisherCertificateSha256

    $temporaryCatalogPath = Join-Path ([System.IO.Path]::GetDirectoryName($PackageRoot)) (
        'release-files.' + [Guid]::NewGuid().ToString('N') + '.cat')
    try {
        $null = New-FileCatalog -Path $PackageRoot -CatalogFilePath $temporaryCatalogPath -CatalogVersion 2.0
        $null = Invoke-RemoteArtifactSignInPlace `
            -Path $temporaryCatalogPath `
            -BaseUrl $BaseUrl `
            -BearerToken $BearerToken `
            -CertificateSerialNumber $CertificateSerialNumber `
            -IdempotencyPrefix 'release-main-catalog' `
            -SigningTimeout $SigningTimeout
        $catalogInformation = Test-FileCatalog -Path $PackageRoot -CatalogFilePath $temporaryCatalogPath -Detailed
        $expectedPaths = @(
            Get-ChildItem -LiteralPath $PackageRoot -Recurse -File -Force |
                ForEach-Object {
                    $_.FullName.Substring($PackageRoot.Length).TrimStart('\', '/').Replace('\', '/')
                } |
                Sort-Object
        )
        $catalogPaths = @($catalogInformation.CatalogItems.Keys | ForEach-Object { $_.Replace('\', '/') } | Sort-Object)
        $testedPaths = @($catalogInformation.PathItems.Keys | ForEach-Object { $_.Replace('\', '/') } | Sort-Object)
        if ([string]$catalogInformation.Status -cne 'Valid' -or
            $catalogInformation.HashAlgorithm -cne 'SHA256' -or
            $null -eq $catalogInformation.Signature -or
            $catalogInformation.Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
            $null -eq $catalogInformation.Signature.TimeStamperCertificate -or
            (ConvertTo-CanonicalCertificateSerial -Value $catalogInformation.Signature.SignerCertificate.SerialNumber) -cne
                (ConvertTo-CanonicalCertificateSerial -Value $CertificateSerialNumber) -or
            (Get-CertificateSha256 -Certificate $catalogInformation.Signature.SignerCertificate) -cne $publisherCertificateSha256 -or
            @(Compare-Object -ReferenceObject $expectedPaths -DifferenceObject $catalogPaths -CaseSensitive).Count -ne 0 -or
            @(Compare-Object -ReferenceObject $expectedPaths -DifferenceObject $testedPaths -CaseSensitive).Count -ne 0) {
            Stop-ReleaseSigning 'release_catalog_verify_failed'
        }
        [System.IO.File]::Move($temporaryCatalogPath, $catalogPath)
    } finally {
        if (Test-Path -LiteralPath $temporaryCatalogPath) {
            [System.IO.File]::Delete($temporaryCatalogPath)
        }
    }

    return $publisherCertificateSha256
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
            $BaseUrl = [Environment]::GetEnvironmentVariable(
                'SIMPLYSIGN_SIGNING_BASE_URL',
                [EnvironmentVariableTarget]::Process)
        }
        if ([string]::IsNullOrWhiteSpace($BearerToken)) {
            $BearerToken = [Environment]::GetEnvironmentVariable(
                'SIMPLYSIGN_SIGNING_BEARER_TOKEN',
                [EnvironmentVariableTarget]::Process)
        }
        if ([string]::IsNullOrWhiteSpace($CertificateSerialNumber)) {
            $CertificateSerialNumber = [Environment]::GetEnvironmentVariable(
                'SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL',
                [EnvironmentVariableTarget]::Process)
        }
        if ([string]::IsNullOrWhiteSpace($PackageRoot) -or
            [string]::IsNullOrWhiteSpace($BaseUrl) -or
            [string]::IsNullOrWhiteSpace($BearerToken) -or
            [string]::IsNullOrWhiteSpace($CertificateSerialNumber)) {
            Stop-ReleaseSigning 'release_signing_parameters_invalid'
        }
        Invoke-SignReleaseMediaMain `
            -PackageRoot $PackageRoot `
            -BaseUrl $BaseUrl `
            -BearerToken $BearerToken `
            -CertificateSerialNumber $CertificateSerialNumber `
            -SigningTimeout $SigningTimeout | Out-Null
        [Console]::Out.WriteLine('release_signing_ok')
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
    exit 0
}
