<#
.SYNOPSIS
  Measures test coverage per package, both ways, and prints the table.

.DESCRIPTION
  Unit coverage credits a package only for its own tests; cross-package
  coverage (-coverpkg=./...) credits it for every test in the module that runs
  its code. Both go into the release review's test-coverage report. This is a
  measurement, not a gate. Nothing is written into the working tree.

.PARAMETER Go
  The go command to run, e.g. go1.26.6.

.PARAMETER OutDir
  Where the profiles and the table go. Defaults to a fresh temporary directory.
#>
Param(
    [string]$Go = "go",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
if ($OutDir -eq "") {
    $OutDir = Join-Path ([IO.Path]::GetTempPath()) ("mutant-coverage-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
New-Item -ItemType Directory -Force $OutDir | Out-Null

$saved = $env:CGO_ENABLED
$env:CGO_ENABLED = "0"
try {
    & $Go test ./... -count=1 -covermode=atomic "-coverprofile=$OutDir/unit.out" *> "$OutDir/unit.log"
    if ($LASTEXITCODE -ne 0) { Write-Warning "some tests failed; coverage still measured (see $OutDir/unit.log)" }
    & $Go test ./... -count=1 -covermode=atomic "-coverpkg=./..." "-coverprofile=$OutDir/cross.out" *> "$OutDir/cross.log"
    if ($LASTEXITCODE -ne 0) { Write-Warning "some tests failed under -coverpkg; coverage still measured (see $OutDir/cross.log)" }
} finally {
    $env:CGO_ENABLED = $saved
}

& $Go run ./cmd/covreport -unit "$OutDir/unit.out" -cross "$OutDir/cross.out" -o "$OutDir/coverage.md"
Write-Host "`nProfiles and table in $OutDir"
