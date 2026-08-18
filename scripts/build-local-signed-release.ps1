[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$SigningBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$BearerTokenPath,

    [Parameter(Mandatory = $true)]
    [string]$SigningReferencePath,

    [string]$DotnetRoot,

    [string]$UvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-CanonicalLeafPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not [System.IO.Path]::IsPathRooted($Path)) {
        throw 'local_release_path_invalid'
    }

    $pathRoot = [System.IO.Path]::GetPathRoot($Path)
    if ([string]::IsNullOrWhiteSpace($pathRoot) -or
        ($pathRoot.Length -eq 2 -and $pathRoot[1] -eq ':')) {
        throw 'local_release_path_invalid'
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw 'local_release_path_missing'
    }

    $item = Get-Item -LiteralPath $fullPath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'local_release_path_invalid'
    }

    return $item.FullName
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'local_release_windows_required'
}

$baseUri = $null
if (-not [Uri]::TryCreate($SigningBaseUrl, [UriKind]::Absolute, [ref]$baseUri) -or
    ($baseUri.Scheme -cne 'http' -and $baseUri.Scheme -cne 'https') -or
    -not [string]::IsNullOrEmpty($baseUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($baseUri.Query) -or
    -not [string]::IsNullOrEmpty($baseUri.Fragment)) {
    throw 'local_release_signing_url_invalid'
}

$buildScriptPath = Get-CanonicalLeafPath -Path (Join-Path $PSScriptRoot 'build-release.ps1')
$tokenPath = Get-CanonicalLeafPath -Path $BearerTokenPath
$referencePath = Get-CanonicalLeafPath -Path $SigningReferencePath
$bearerToken = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($bearerToken) -or
    $bearerToken.IndexOfAny([char[]]@("`r", "`n", [char]0)) -ge 0) {
    throw 'local_release_token_invalid'
}

$referenceSignature = Get-AuthenticodeSignature -LiteralPath $referencePath
if ($referenceSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    $null -eq $referenceSignature.SignerCertificate) {
    throw 'local_release_signer_invalid'
}

$pathEntries = [System.Collections.Generic.List[string]]::new()
if (-not [string]::IsNullOrWhiteSpace($DotnetRoot)) {
    $canonicalDotnet = Get-CanonicalLeafPath -Path (Join-Path $DotnetRoot 'dotnet.exe')
    $pathEntries.Add([System.IO.Path]::GetDirectoryName($canonicalDotnet))
}
if (-not [string]::IsNullOrWhiteSpace($UvPath)) {
    $canonicalUv = Get-CanonicalLeafPath -Path $UvPath
    $pathEntries.Add([System.IO.Path]::GetDirectoryName($canonicalUv))
}

$windowsPowerShell = Get-CanonicalLeafPath -Path (
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
$previousPath = $env:PATH
$previousDotnetRoot = $env:DOTNET_ROOT
$previousBaseUrl = $env:SIMPLYSIGN_SIGNING_BASE_URL
$previousBearer = $env:SIMPLYSIGN_SIGNING_BEARER_TOKEN
$previousSerial = $env:SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL
try {
    if ($pathEntries.Count -gt 0) {
        $env:PATH = [string]::Join(';', @($pathEntries) + @($previousPath))
    }
    if (-not [string]::IsNullOrWhiteSpace($DotnetRoot)) {
        $env:DOTNET_ROOT = [System.IO.Path]::GetFullPath($DotnetRoot)
    }
    $env:SIMPLYSIGN_SIGNING_BASE_URL = $baseUri.AbsoluteUri.TrimEnd('/')
    $env:SIMPLYSIGN_SIGNING_BEARER_TOKEN = $bearerToken
    $env:SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL = $referenceSignature.SignerCertificate.SerialNumber

    [Console]::Out.WriteLine("local_release_preflight_ok version=$Version")
    & $windowsPowerShell `
        -NoLogo `
        -NoProfile `
        -NonInteractive `
        -ExecutionPolicy Bypass `
        -File $buildScriptPath `
        -Version $Version
    if ($LASTEXITCODE -ne 0) {
        throw "local_release_build_failed:$LASTEXITCODE"
    }
}
finally {
    $env:PATH = $previousPath
    $env:DOTNET_ROOT = $previousDotnetRoot
    $env:SIMPLYSIGN_SIGNING_BASE_URL = $previousBaseUrl
    $env:SIMPLYSIGN_SIGNING_BEARER_TOKEN = $previousBearer
    $env:SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL = $previousSerial
    $bearerToken = $null
}
