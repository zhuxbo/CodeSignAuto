[CmdletBinding()]
param(
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Invoke-GitOutput {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $lines = @(& git -C $script:root @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "release_git_failed:$($Arguments[0])"
    }

    return @($lines | ForEach-Object { [string]$_ })
}

function Test-ForbiddenRepositoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = $Path.Replace('\', '/').Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $false
    }

    return $normalized -match '(^|/)(\.superpowers|artifacts|bin|obj|TestResults|\.venv|__pycache__|\.pytest_cache|\.ruff_cache|dist|build)(/|$)' -or
        $normalized -match '(^|/)\.DS_Store$' -or
        $normalized -match '(^|/)\._[^/]+$' -or
        $normalized -match '(^|/)__MACOSX(/|$)' -or
        $normalized -match '(^|/)\.env(?:\.|$)' -or
        $normalized -match '(^|/)(install-token\.txt|id_rsa|id_ed25519)$' -or
        $normalized -match '\.(pfx|p12|pem|key|snk|secrets\.json|user|suo)$'
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}

$root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw 'release_repository_missing'
}

$inside = @(Invoke-GitOutput -Arguments @('rev-parse', '--is-inside-work-tree'))
if ($inside.Count -ne 1 -or $inside[0] -cne 'true') {
    throw 'release_repository_invalid'
}

$shallow = @(Invoke-GitOutput -Arguments @('rev-parse', '--is-shallow-repository'))
if ($shallow.Count -ne 1 -or $shallow[0] -cne 'false') {
    throw 'release_history_incomplete'
}

$status = @(Invoke-GitOutput -Arguments @('status', '--porcelain=v1', '--untracked-files=all'))
if ($status.Count -ne 0) {
    throw 'release_worktree_dirty'
}

$null = Invoke-GitOutput -Arguments @('diff', '--check')
$null = Invoke-GitOutput -Arguments @('diff', '--cached', '--check')

$tracked = @(Invoke-GitOutput -Arguments @('ls-files'))
$forbiddenTracked = @($tracked | Where-Object { Test-ForbiddenRepositoryPath -Path $_ })
if ($forbiddenTracked.Count -ne 0) {
    throw "release_tracked_path_forbidden:$($forbiddenTracked[0])"
}

$historyPaths = @(Invoke-GitOutput -Arguments @(
    '-c',
    'core.quotepath=false',
    'log',
    '--all',
    '--format=',
    '--name-only'))
$forbiddenHistory = @($historyPaths |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Where-Object { Test-ForbiddenRepositoryPath -Path $_ } |
    Select-Object -Unique)
if ($forbiddenHistory.Count -ne 0) {
    throw "release_history_path_forbidden:$($forbiddenHistory[0])"
}

$historyMessages = @(Invoke-GitOutput -Arguments @('log', '--all', '--format=%B'))
$forbiddenHistoryMessage = @($historyMessages | Where-Object {
        $_ -match '(?i)(^|[^a-z0-9])task[ _-]?[0-9]+([^a-z0-9]|$)' -or
        $_ -match '(?i)red[- /]?green' -or
        $_ -match '(?i)\.superpowers[\\/]'
    } | Select-Object -First 1)
if ($forbiddenHistoryMessage.Count -ne 0) {
    throw 'release_history_message_forbidden'
}

$maximumTrackedBytes = 10MB
foreach ($relativePath in $tracked) {
    $fullPath = Join-Path $root $relativePath
    if ((Test-Path -LiteralPath $fullPath -PathType Leaf) -and
        (Get-Item -LiteralPath $fullPath -Force).Length -gt $maximumTrackedBytes) {
        throw "release_tracked_file_too_large:$relativePath"
    }
}

$requiredFiles = @(
    'LICENSE',
    'README.md',
    'THIRD-PARTY-NOTICES.txt',
    'docs/API.md',
    'scripts/build-release.ps1',
    'scripts/get-pdf-release-decision.ps1',
    'scripts/pre-release-check.ps1',
    '.github/workflows/release.yml',
    'AGENTS.md',
    '.agents/skills/CodeSignAuto-release/SKILL.md'
)
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf)) {
        throw "release_required_file_missing:$relativePath"
    }
}

$textExtensions = @(
    '.cs', '.json', '.md', '.props', '.ps1', '.py', '.targets', '.txt',
    '.toml', '.xaml', '.xml', '.yaml', '.yml')
foreach ($relativePath in $tracked) {
    if ($textExtensions -notcontains [IO.Path]::GetExtension($relativePath)) {
        continue
    }

    $text = [IO.File]::ReadAllText((Join-Path $root $relativePath))
    if ($text -match '(?i)(^|[^a-z0-9])task[ _-]?[0-9]+([^a-z0-9]|$)' -or
        $text -match '(?i)red[- /]?green' -or
        $text -match '(?i)\.superpowers[\\/][^\r\n`"'']+\.(md|txt)') {
        throw "release_process_reference_forbidden:$relativePath"
    }
}

$ignoredProbes = @(
    '.superpowers/pre-release-probe',
    'artifacts/pre-release-probe',
    '.DS_Store',
    '._',
    '__MACOSX/pre-release-probe',
    'pre-release-probe.pfx'
)
foreach ($probe in $ignoredProbes) {
    & git -C $root check-ignore -q -- $probe
    if ($LASTEXITCODE -ne 0) {
        throw "release_ignore_rule_missing:$probe"
    }
}

[Console]::Out.WriteLine(
    "pre_release_check_ok tracked=$($tracked.Count) historyPaths=$($historyPaths.Count)")
