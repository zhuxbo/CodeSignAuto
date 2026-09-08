[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ExistingUser', 'ProvisionUser', 'RepairUser')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,20}$')]
    [string]$UserName,

    [string]$AppPath = (Join-Path $PSScriptRoot '..\CodeSignAuto.exe')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'windows_required'
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath),
        '-Mode', $Mode,
        '-UserName', $UserName,
        '-AppPath', ('"{0}"' -f (Resolve-Path -LiteralPath $AppPath).Path)
    )
    $elevated = Start-Process `
        -FilePath 'powershell.exe' `
        -Verb RunAs `
        -ArgumentList $arguments `
        -Wait `
        -PassThru
    exit $elevated.ExitCode
}

$resolvedApp = (Resolve-Path -LiteralPath $AppPath).Path
$nativeMode = switch ($Mode) {
    'ExistingUser' { 'existing-user' }
    'ProvisionUser' { 'provision-user' }
    'RepairUser' { 'repair-user' }
}
& $resolvedApp 'provision-agent-user' '--mode' $nativeMode '--user' $UserName
exit $LASTEXITCODE
