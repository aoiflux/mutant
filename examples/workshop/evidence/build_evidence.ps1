# Build the QUILLDROP evidence corpus (Windows / PowerShell).
#
#   .\examples\workshop\evidence\build_evidence.ps1
#
# Run from the repository root. Requires fsagen on PATH:
#   go install github.com/aoiflux/fsagen@latest
#
# Prefer NTFS: Mark-of-the-Web and the alternate data stream are NTFS features,
# and beat 3 reads both. Add a Defender exclusion for the output folder first,
# and keep it outside Windows Search indexing.

$ErrorActionPreference = 'Stop'

$Seed     = 88412
$Here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Playbook = Join-Path $Here 'quilldrop.playbook.yaml'
$Root     = Join-Path (Split-Path -Parent $Here) 'case'
$Bodyfile = Join-Path (Split-Path -Parent $Here) 'case_quilldrop.body'

if (-not (Get-Command fsagen -ErrorAction SilentlyContinue)) {
    Write-Host 'fsagen not found on PATH.' -ForegroundColor Red
    Write-Host '  go install github.com/aoiflux/fsagen@latest'
    exit 1
}

if (Test-Path $Root) {
    Write-Host "removing previous corpus: $Root"
    Remove-Item -Recurse -Force $Root
}

Write-Host "generating corpus (seed $Seed)..." -ForegroundColor Cyan
fsagen --seed $Seed --playbook $Playbook `
       --timeline $Bodyfile --timeline-format bodyfile --timeline-source modelled `
       $Root

$files = Get-ChildItem -Recurse -File $Root
$bytes = ($files | Measure-Object -Property Length -Sum).Sum
$rows  = (Get-Content $Bodyfile).Count

Write-Host ''
Write-Host 'evidence ready' -ForegroundColor Green
Write-Host "  corpus   : $Root"
Write-Host "  files    : $($files.Count)"
Write-Host "  bytes    : $bytes"
Write-Host "  bodyfile : $Bodyfile ($rows rows)"
Write-Host ''
Write-Host 'Now run the first step:' -ForegroundColor Yellow
Write-Host '  .\examples\workshop\run.ps1 01_scene'
