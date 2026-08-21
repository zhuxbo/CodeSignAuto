[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ReleaseRoot,

    [Parameter(Mandatory = $true)]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [string] $DecisionPath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$semVerPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if ($Version -cnotmatch $semVerPattern) {
    throw 'release_notes_version_invalid'
}
$tagPattern = '^v' + $semVerPattern.Substring(1)

$canonicalReleaseRoot = [IO.Path]::GetFullPath($ReleaseRoot).TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $canonicalReleaseRoot -PathType Container)) {
    throw 'release_notes_root_missing'
}
$rootItem = Get-Item -LiteralPath $canonicalReleaseRoot -Force
if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'release_notes_root_invalid'
}

$canonicalDecisionPath = [IO.Path]::GetFullPath($DecisionPath)
if (-not (Test-Path -LiteralPath $canonicalDecisionPath -PathType Leaf)) {
    throw 'release_notes_decision_missing'
}
$decisionItem = Get-Item -LiteralPath $canonicalDecisionPath -Force
if (($decisionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'release_notes_decision_invalid'
}
try {
    $decision = Get-Content -LiteralPath $canonicalDecisionPath -Raw | ConvertFrom-Json
} catch {
    throw 'release_notes_decision_invalid'
}
$decisionProperties = @($decision.PSObject.Properties.Name | Sort-Object)
$expectedDecisionProperties = @(
    'baselineTag',
    'changedPaths',
    'reason',
    'releasePdf',
    'schemaVersion',
    'version'
) | Sort-Object
if (@(Compare-Object $expectedDecisionProperties $decisionProperties -CaseSensitive).Count -ne 0 -or
    $decision.schemaVersion -ne 1 -or
    $decision.version -cne $Version -or
    $decision.releasePdf -isnot [bool] -or
    $null -eq $decision.changedPaths) {
    throw 'release_notes_decision_invalid'
}
if ($decision.releasePdf) {
    if (($decision.reason -cne 'first_release' -and $decision.reason -cne 'pdf_inputs_changed') -or
        ($decision.reason -ceq 'first_release' -and $null -ne $decision.baselineTag) -or
        ($decision.reason -ceq 'pdf_inputs_changed' -and
            ($decision.baselineTag -isnot [string] -or
             $decision.baselineTag -cnotmatch $tagPattern))) {
        throw 'release_notes_decision_invalid'
    }
} elseif ($decision.reason -cne 'pdf_inputs_unchanged' -or
    $decision.baselineTag -isnot [string] -or
    $decision.baselineTag -cnotmatch $tagPattern -or
    @($decision.changedPaths).Count -ne 0) {
    throw 'release_notes_decision_invalid'
}

$expectedNames = @("SimplySignAutoSetup-$Version-win-x64.exe")
if ($decision.releasePdf) {
    $expectedNames = @("SimplySignAutoPdfSetup-$Version-win-x64.exe") + $expectedNames
}
$actualEntries = @(Get-ChildItem -LiteralPath $canonicalReleaseRoot -Force)
if ($actualEntries.Count -ne $expectedNames.Count -or
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
if (-not $decision.releasePdf) {
    $lines.Add('')
    $skipTemplate = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String(
            'UERGIOaJqeWxle+8muebuOWvuSBgezB9YCDmsqHmnInmnInmlYjovpPlhaXlj5jmm7TvvIzmnKzniYjmnKzmnKrlj5HluIPmlrDnmoQgUERGIOWuieijheWMheOAgg=='))
    $lines.Add([string]::Format($skipTemplate, $decision.baselineTag))
}
$content = [string]::Join("`r`n", $lines) + "`r`n"
[IO.File]::WriteAllText($canonicalOutputPath, $content, [Text.UTF8Encoding]::new($false))
