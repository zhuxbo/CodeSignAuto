[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ReleaseRoot,

    [Parameter(Mandatory = $true)]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$semVerPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if ($Version -cnotmatch $semVerPattern) {
    throw 'release_notes_version_invalid'
}

$canonicalReleaseRoot = [IO.Path]::GetFullPath($ReleaseRoot).TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $canonicalReleaseRoot -PathType Container)) {
    throw 'release_notes_root_missing'
}
$rootItem = Get-Item -LiteralPath $canonicalReleaseRoot -Force
if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'release_notes_root_invalid'
}

$expectedNames = @(
    "SimplySignAutoPdfSetup-$Version-win-x64.exe",
    "SimplySignAutoSetup-$Version-win-x64.exe"
)
$actualEntries = @(Get-ChildItem -LiteralPath $canonicalReleaseRoot -Force)
if ($actualEntries.Count -ne 2 -or
    @($actualEntries | Where-Object {
        $_.PSIsContainer -or
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -ne 0 -or
    @(Compare-Object $expectedNames @($actualEntries.Name) -CaseSensitive).Count -ne 0) {
    throw 'release_notes_asset_closure_invalid'
}
$entries = @($expectedNames | ForEach-Object {
    Get-Item -LiteralPath (Join-Path $canonicalReleaseRoot $_) -Force
})

$canonicalOutputPath = [IO.Path]::GetFullPath($OutputPath)
$releasePrefix = $canonicalReleaseRoot + [IO.Path]::DirectorySeparatorChar
if ($canonicalOutputPath.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $canonicalOutputPath)) {
    throw 'release_notes_output_invalid'
}
$outputDirectory = [IO.Path]::GetDirectoryName($canonicalOutputPath)
if ([string]::IsNullOrWhiteSpace($outputDirectory) -or
    -not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    throw 'release_notes_output_invalid'
}

$lines = [Collections.Generic.List[string]]::new()
$heading = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('IyMg5a6J6KOF5YyF'))
$emDash = [char]0x2014
$lines.Add($heading)
$lines.Add('')
foreach ($entry in $entries) {
    $hash = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $lines.Add("- ``$($entry.Name)`` $emDash $($entry.Length) bytes $emDash SHA-256 ``$hash``")
}
$content = [string]::Join("`r`n", $lines) + "`r`n"
[IO.File]::WriteAllText($canonicalOutputPath, $content, [Text.UTF8Encoding]::new($false))
