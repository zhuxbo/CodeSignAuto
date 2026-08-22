[CmdletBinding()]
param(
    [Alias('RepositoryRoot')]
    [string]$DecisionRepositoryRoot,

    [Alias('Version')]
    [string]$DecisionVersion,

    [Alias('OutputPath')]
    [string]$DecisionOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PdfReleaseSemVerPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
$PdfReleaseInputPaths = @(
    'tools/pdf-signer/pdf-signer.spec',
    'tools/pdf-signer/pyproject.toml',
    'tools/pdf-signer/simplysign_pdf_signer.py',
    'tools/pdf-signer/simplysign_pdf_validator.py',
    'tools/pdf-signer/uv.lock',
    'scripts/build-release.ps1',
    'src/SimplySignAuto.Setup',
    'Directory.Build.props',
    'Directory.Packages.props',
    'global.json',
    'LICENSE',
    'THIRD-PARTY-NOTICES.txt'
)

function Fail-PdfReleaseDecision {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseApprovedVerbs',
        '',
        Justification = 'The private helper returns stable release gate error codes.')]
    param([Parameter(Mandatory = $true)][string]$Code)

    throw $Code
}

function Invoke-PdfReleaseGit {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [int[]]$AllowedExitCodes = @(0)
    )

    [string[]]$output = @(& $Git -C $Root @ArgumentList 2>&1)
    $exitCode = $LASTEXITCODE
    if ($AllowedExitCodes -notcontains $exitCode) {
        Fail-PdfReleaseDecision 'pdf_release_git_failed'
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = @($output)
    }
}

function Get-PdfReleaseDecision {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Version
    )

    if ($Version -cnotmatch $PdfReleaseSemVerPattern) {
        Fail-PdfReleaseDecision 'pdf_release_version_invalid'
    }
    if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        Fail-PdfReleaseDecision 'pdf_release_repository_invalid'
    }
    $root = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        Fail-PdfReleaseDecision 'pdf_release_repository_invalid'
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-PdfReleaseDecision 'pdf_release_repository_invalid'
    }

    $gitCommands = @(Get-Command git.exe -CommandType Application -ErrorAction Stop)
    if ($gitCommands.Count -eq 0 -or
        [string]::IsNullOrWhiteSpace([string]$gitCommands[0].Path)) {
        Fail-PdfReleaseDecision 'pdf_release_git_failed'
    }
    $git = [string]$gitCommands[0].Path
    $insideWorkTree = Invoke-PdfReleaseGit `
        -Git $git `
        -Root $root `
        -ArgumentList @('rev-parse', '--is-inside-work-tree')
    if ($insideWorkTree.Lines.Count -ne 1 -or $insideWorkTree.Lines[0] -cne 'true') {
        Fail-PdfReleaseDecision 'pdf_release_repository_invalid'
    }
    $shallow = Invoke-PdfReleaseGit `
        -Git $git `
        -Root $root `
        -ArgumentList @('rev-parse', '--is-shallow-repository')
    if ($shallow.Lines.Count -ne 1 -or $shallow.Lines[0] -cne 'false') {
        Fail-PdfReleaseDecision 'pdf_release_history_incomplete'
    }
    $head = Invoke-PdfReleaseGit `
        -Git $git `
        -Root $root `
        -ArgumentList @('rev-parse', '--verify', 'HEAD^{commit}')
    if ($head.Lines.Count -ne 1 -or $head.Lines[0] -cnotmatch '^[0-9a-f]{40,64}$') {
        Fail-PdfReleaseDecision 'pdf_release_history_invalid'
    }
    $headCommit = $head.Lines[0]

    $worktree = Invoke-PdfReleaseGit `
        -Git $git `
        -Root $root `
        -ArgumentList (@('status', '--porcelain=v1', '--untracked-files=all', '--') + $PdfReleaseInputPaths)
    if ($worktree.Lines.Count -ne 0) {
        Fail-PdfReleaseDecision 'pdf_release_worktree_dirty'
    }

    $tags = Invoke-PdfReleaseGit `
        -Git $git `
        -Root $root `
        -ArgumentList @('tag', '--merged', 'HEAD', '--list', 'v*')
    $candidates = [System.Collections.Generic.List[object]]::new()
    $currentTag = "v$Version"
    foreach ($tag in $tags.Lines) {
        if ($tag -cnotmatch "^v$($PdfReleaseSemVerPattern.Trim('^', '$'))$") {
            continue
        }
        $tagCommitResult = Invoke-PdfReleaseGit `
            -Git $git `
            -Root $root `
            -ArgumentList @('rev-parse', '--verify', "$tag^{commit}")
        if ($tagCommitResult.Lines.Count -ne 1) {
            Fail-PdfReleaseDecision 'pdf_release_history_invalid'
        }
        $tagCommit = $tagCommitResult.Lines[0]
        if ($tag -ceq $currentTag) {
            if ($tagCommit -cne $headCommit) {
                Fail-PdfReleaseDecision 'pdf_release_current_tag_invalid'
            }
            continue
        }
        $distanceResult = Invoke-PdfReleaseGit `
            -Git $git `
            -Root $root `
            -ArgumentList @('rev-list', '--count', "$tag..HEAD")
        $distance = 0
        if ($distanceResult.Lines.Count -ne 1 -or
            -not [int]::TryParse($distanceResult.Lines[0], [ref]$distance) -or
            $distance -lt 0) {
            Fail-PdfReleaseDecision 'pdf_release_history_invalid'
        }
        $candidates.Add([pscustomobject]@{ Tag = $tag; Distance = $distance })
    }

    if ($candidates.Count -eq 0) {
        return [pscustomobject][ordered]@{
            schemaVersion = 1
            version = $Version
            releasePdf = $true
            reason = 'first_release'
            baselineTag = $null
            changedPaths = @()
        }
    }

    $nearestDistance = ($candidates | Measure-Object -Property Distance -Minimum).Minimum
    $nearest = @($candidates | Where-Object { $_.Distance -eq $nearestDistance })
    if ($nearest.Count -ne 1) {
        Fail-PdfReleaseDecision 'pdf_release_baseline_ambiguous'
    }
    $baselineTag = $nearest[0].Tag
    $diff = Invoke-PdfReleaseGit `
        -Git $git `
        -Root $root `
        -ArgumentList (@('diff', '--quiet', '--no-ext-diff', $baselineTag, 'HEAD', '--') + $PdfReleaseInputPaths) `
        -AllowedExitCodes @(0, 1)
    if ($diff.ExitCode -eq 0) {
        return [pscustomobject][ordered]@{
            schemaVersion = 1
            version = $Version
            releasePdf = $false
            reason = 'pdf_inputs_unchanged'
            baselineTag = $baselineTag
            changedPaths = @()
        }
    }

    $changed = Invoke-PdfReleaseGit `
        -Git $git `
        -Root $root `
        -ArgumentList (@(
            'diff', '--name-only', '--diff-filter=ACDMRTUXB', '--no-ext-diff',
            $baselineTag, 'HEAD', '--') + $PdfReleaseInputPaths)
    $changedPaths = @($changed.Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    if ($changedPaths.Count -eq 0) {
        Fail-PdfReleaseDecision 'pdf_release_diff_invalid'
    }
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        version = $Version
        releasePdf = $true
        reason = 'pdf_inputs_changed'
        baselineTag = $baselineTag
        changedPaths = $changedPaths
    }
}

function Write-PdfReleaseDecision {
    param(
        [Parameter(Mandatory = $true)][object]$Decision,
        [string]$OutputPath
    )

    $json = $Decision | ConvertTo-Json -Depth 4 -Compress
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        [Console]::Out.WriteLine($json)
        return
    }
    $canonicalOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = [System.IO.Path]::GetDirectoryName($canonicalOutputPath)
    if ([string]::IsNullOrWhiteSpace($outputDirectory) -or
        -not (Test-Path -LiteralPath $outputDirectory -PathType Container) -or
        (Test-Path -LiteralPath $canonicalOutputPath)) {
        Fail-PdfReleaseDecision 'pdf_release_output_invalid'
    }
    [System.IO.File]::WriteAllText(
        $canonicalOutputPath,
        $json + "`r`n",
        [System.Text.UTF8Encoding]::new($false))
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $decision = Get-PdfReleaseDecision `
            -RepositoryRoot $DecisionRepositoryRoot `
            -Version $DecisionVersion
        Write-PdfReleaseDecision -Decision $decision -OutputPath $DecisionOutputPath
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
    exit 0
}
