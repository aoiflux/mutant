# Build the QUILLDROP evidence corpus (Windows / PowerShell).
#
#   .\examples\workshop\evidence\build_evidence.ps1
#
# Run from the repository root. Requires fsagen on PATH:
#   go install github.com/aoiflux/fsagen@latest
#
# Prefer an NTFS volume: Mark-of-the-Web and the alternate data stream are NTFS
# features, and two of the workshop's findings live in them.

$ErrorActionPreference = 'Stop'

$Seed     = 88412
$Here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Playbook = Join-Path $Here 'quilldrop.playbook.yaml'
$Root     = Join-Path $Here 'case_quilldrop'
$Bodyfile = Join-Path $Here 'case_quilldrop.body'
$CsvTl    = Join-Path $Here 'case_quilldrop.csv'

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
fsagen --seed $Seed --playbook $Playbook --timeline $Bodyfile $Root

# A second pass for the CSV timeline. --timeline alone regenerates from the
# existing corpus, so this costs nothing and does not disturb the artifacts.
Write-Host 'generating CSV timeline...' -ForegroundColor Cyan
fsagen --timeline $CsvTl $Root

$files = Get-ChildItem -Recurse -File $Root
$bytes = ($files | Measure-Object -Property Length -Sum).Sum

Write-Host ''
Write-Host 'evidence ready' -ForegroundColor Green
Write-Host "  corpus   : $Root"
Write-Host "  files    : $($files.Count)"
Write-Host "  bytes    : $bytes"
Write-Host "  bodyfile : $Bodyfile"
Write-Host "  csv      : $CsvTl"
Write-Host ''
Write-Host 'Now run the first tool:' -ForegroundColor Yellow
Write-Host '  mutant run examples/workshop/07_dropzone.mut -pwd workshop'
