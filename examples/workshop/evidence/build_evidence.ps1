# Build the QUILLDROP evidence corpus (Windows / PowerShell).
#
#   .\examples\workshop\evidence\build_evidence.ps1
#
# Run from the repository root. Requires fsagen on PATH, at this exact version
# -- @latest became v0.2.0 on 2026-10-02 and the playbook is written for v0.1.0:
#   go install github.com/aoiflux/fsagen@v0.1.0
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
    Write-Host '  go install github.com/aoiflux/fsagen@v0.1.0'
    exit 1
}

if (Test-Path $Root) {
    Write-Host "removing previous corpus: $Root"
    Remove-Item -Recurse -Force $Root
}

Write-Host "generating corpus (seed $Seed)..." -ForegroundColor Cyan
# --on-unsupported=skip is a no-op on NTFS, where nothing here is unsupported.
# On any other volume it is the difference between a corpus and no corpus at
# all; every skip is recorded in $Root.fsagen/run-manifest.json.
fsagen --seed $Seed --playbook $Playbook --on-unsupported=skip `
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
# Beat 6 asks whether any file's mtime precedes its crtime. Ask the timeline the
# same question: NTFS answers yes, and a volume without crtime answers no for
# every row, which would cost the beat its finding with no other sign.
$backdated = @(Get-Content $Bodyfile | Where-Object {
    $f = $_ -split '\|'
    $f.Count -ge 11 -and [int64]$f[8] -lt [int64]$f[10]
}).Count
if ($backdated -eq 0) {
    Write-Host ''
    Write-Host 'NOTE: no row in this timeline has a modification time earlier' -ForegroundColor Yellow
    Write-Host "      than its creation time, so beat 6's 'older than its own" -ForegroundColor Yellow
    Write-Host "      birth' finding will not fire here. It needs crtime, which" -ForegroundColor Yellow
    Write-Host '      is NTFS. The pre-built corpus keeps it.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Now run the first step:' -ForegroundColor Yellow
Write-Host '  .\examples\workshop\run.ps1 01_scene'
