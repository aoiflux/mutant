<#
.SYNOPSIS
  Runs every check a Mutant release has to pass, and prints one PASS/FAIL table.

.DESCRIPTION
  This is the release gate. The project runs no CI, so these are the checks a
  contributor runs before handing a change over and the owner runs before
  tagging. Nothing here is read from the environment: every choice is a
  parameter, and the script writes nothing into the working tree -- builds,
  logs and scratch copies go under -LogDir.

  The expected Go toolchain is read from go.mod, not written here, so moving
  the pin is one edit.

.PARAMETER Go
  The go command to run. The pinned toolchain is installed beside newer ones
  with golang.org/dl, e.g. -Go go1.26.2.

.PARAMETER FuzzTime
  How long to fuzz each target (a Go duration such as 30s or 10m). Empty runs
  the seed corpora only, which plain `go test` already does.

.PARAMETER Quick
  Skip the slow steps: the race detector, the cross-compiles and the example
  sweep.

.PARAMETER Vuln
  Also run govulncheck (downloads it; does not touch go.mod).

.PARAMETER LogDir
  Where logs and build outputs go. Defaults to a fresh temporary directory.
#>
Param(
    [string]$Go = "go",
    [string]$FuzzTime = "",
    [switch]$Quick,
    [switch]$Vuln,
    [string]$LogDir = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if ($LogDir -eq "") {
    $LogDir = Join-Path ([IO.Path]::GetTempPath()) ("mutant-release-gate-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
# The gofmt step writes an LF copy of every Go file under -LogDir. Inside the
# repository those copies are packages of the module: go test ./... would
# compile them beside the real ones and every tree-walking guard would count
# them twice, so the gate would fail for a reason that is nowhere in the code.
$logFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogDir).TrimEnd('\', '/')
$rootFull = (Get-Item -LiteralPath $repoRoot).FullName.TrimEnd('\', '/')
$pathCase = if ($IsWindows -or $PSVersionTable.PSEdition -eq "Desktop") { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
if ($logFull.Equals($rootFull, $pathCase) -or $logFull.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, $pathCase)) {
    Write-Host "release_gate: -LogDir $LogDir is inside the repository ($rootFull). The gate writes Go files there, which go test ./... would take for part of the module; pick a directory outside it." -ForegroundColor Red
    exit 2
}
New-Item -ItemType Directory -Force $LogDir | Out-Null

# The six release targets, the same list scripts/build.ps1 builds.
$targets = @(
    @{ GoOS = "windows"; GoArch = "amd64" }, @{ GoOS = "windows"; GoArch = "arm64" },
    @{ GoOS = "linux"; GoArch = "amd64" }, @{ GoOS = "linux"; GoArch = "arm64" },
    @{ GoOS = "darwin"; GoArch = "amd64" }, @{ GoOS = "darwin"; GoArch = "arm64" }
)

# Packages whose tests exercise goroutines; the race detector needs cgo for the
# test binary only, never for anything shipped.
$racePackages = @("./vm/...", "./builtin/...", "./serve/...", "./security/...", "./object/...",
    "./runtime/...", "./repl/...", "./dap/...", "./sema/...", "./lsp/...", "./cli/...")

$results = New-Object System.Collections.Generic.List[object]

function Invoke-Step {
    Param([string]$Name, [scriptblock]$Body)
    $log = Join-Path $LogDir (($Name -replace '[^A-Za-z0-9]+', '_') + ".log")
    $started = Get-Date
    Write-Host "==> $Name" -ForegroundColor Cyan
    $status = "PASS"
    $note = ""
    try {
        $outcome = & $Body $log
        if ($outcome -is [string] -and $outcome -ne "") { $note = $outcome }
        if ($note -like "SKIP*") { $status = "SKIP" }
    } catch {
        $status = "FAIL"
        $note = $_.Exception.Message
    }
    $seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    $results.Add([pscustomobject]@{ Step = $Name; Status = $status; Seconds = $seconds; Note = $note; Log = $log })
    $color = @{ PASS = "Green"; FAIL = "Red"; SKIP = "Yellow" }[$status]
    Write-Host "    $status ($seconds s) $note" -ForegroundColor $color
}

# Run a native command with the given environment for that command only,
# appending its output to the step log; throw on a non-zero exit.
function Invoke-Logged {
    Param([string]$Log, [hashtable]$Env = @{}, [string]$Exe, [string[]]$Arguments)
    $saved = @{}
    foreach ($k in $Env.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $Env[$k]) }
    try {
        "`n> $Exe $($Arguments -join ' ')" | Out-File -Append -Encoding utf8 $Log
        $ErrorActionPreference = "Continue"
        & $Exe @Arguments *>> $Log
        $code = $LASTEXITCODE
    } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    }
    if ($code -ne 0) { throw "$Exe $($Arguments -join ' ') exited $code (see $Log)" }
}

$goModVersion = (Select-String -Path go.mod -Pattern '^go\s+(\S+)').Matches[0].Groups[1].Value
$version = (Select-String -Path global/const.go -Pattern 'const Version = "([^"]+)"').Matches[0].Groups[1].Value
Write-Host "Mutant $version release gate; go.mod pins go $goModVersion; logs in $LogDir`n"

Invoke-Step "toolchain is the pinned one" {
    Param($log)
    $got = (& $Go env GOVERSION).Trim()
    if ($got -ne "go$goModVersion") {
        throw "go.mod pins go $goModVersion but $Go is $got; install it with ``go install golang.org/dl/go$goModVersion@latest`` and pass -Go go$goModVersion"
    }
}

Invoke-Step "gofmt (on LF copies)" {
    Param($log)
    # The working copy is checked out with per-file CRLF, and gofmt reports every
    # CRLF file; formatting is judged on the content git stores, which is LF.
    # Untracked files git does not ignore are included: they are the ones a
    # change is about to add.
    $copy = Join-Path $LogDir "gofmt-lf"
    $files = git ls-files --cached --others --exclude-standard '*.go'
    foreach ($f in $files) {
        $dest = Join-Path $copy $f
        New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
        [IO.File]::WriteAllText($dest, [IO.File]::ReadAllText((Join-Path $repoRoot $f)).Replace("`r`n", "`n"))
    }
    $gofmt = Join-Path (& $Go env GOROOT).Trim() "bin/gofmt"
    $unformatted = & $gofmt -l $copy
    $unformatted | Out-File -Encoding utf8 $log
    if ($unformatted) { throw "$(@($unformatted).Count) file(s) not gofmt-clean (see $log)" }
}

foreach ($os in "linux", "windows", "darwin") {
    Invoke-Step "go vet ($os)" {
        Param($log)
        Invoke-Logged -Log $log -Env @{ GOOS = $os; GOARCH = "amd64"; CGO_ENABLED = "0" } -Exe $Go -Arguments @("vet", "./...")
    }
}

if ($Quick) {
    $results.Add([pscustomobject]@{ Step = "cross-compile"; Status = "SKIP"; Seconds = 0; Note = "SKIP: -Quick"; Log = "" })
} else {
    Invoke-Step "cross-compile (6 targets x mutant+mlsp, wasm)" {
        Param($log)
        $out = Join-Path $LogDir "bin"
        foreach ($t in $targets) {
            $suffix = if ($t.GoOS -eq "windows") { ".exe" } else { "" }
            $envs = @{ GOOS = $t.GoOS; GOARCH = $t.GoArch; CGO_ENABLED = "0" }
            Invoke-Logged -Log $log -Env $envs -Exe $Go -Arguments @("build", "-trimpath", "-o", (Join-Path $out "mutant-$($t.GoOS)-$($t.GoArch)$suffix"), ".")
            Invoke-Logged -Log $log -Env $envs -Exe $Go -Arguments @("build", "-trimpath", "-o", (Join-Path $out "mlsp-$($t.GoOS)-$($t.GoArch)$suffix"), "./lsp/cmd/mlsp")
        }
        Invoke-Logged -Log $log -Env @{ GOOS = "js"; GOARCH = "wasm"; CGO_ENABLED = "0" } -Exe $Go -Arguments @("build", "-o", (Join-Path $out "mutant_repl.wasm"), "./cmd/replwasm")
    }
}

Invoke-Step "go test ./..." {
    Param($log)
    Invoke-Logged -Log $log -Env @{ CGO_ENABLED = "0" } -Exe $Go -Arguments @("test", "./...", "-count=1")
}

if ($Quick) {
    $results.Add([pscustomobject]@{ Step = "race detector"; Status = "SKIP"; Seconds = 0; Note = "SKIP: -Quick"; Log = "" })
} else {
    Invoke-Step "race detector (test binaries only)" {
        Param($log)
        if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) { return "SKIP: no gcc on PATH; the race detector needs cgo" }
        Invoke-Logged -Log $log -Env @{ CGO_ENABLED = "1" } -Exe $Go -Arguments (@("test", "-race", "-count=1", "-timeout", "45m") + $racePackages)
    }
}

Invoke-Step "fuzz targets" {
    Param($log)
    if ($FuzzTime -eq "") { return "SKIP: seed corpora ran in go test; pass -FuzzTime to fuzz" }
    $listLog = Join-Path $LogDir "fuzz_listing.log"
    Invoke-Logged -Log $listLog -Env @{ CGO_ENABLED = "0" } -Exe $Go -Arguments @("test", "-list", '^Fuzz', "./...")
    $listing = Get-Content $listLog
    $pending = @()
    $ran = 0
    foreach ($line in $listing) {
        if ($line -match '^Fuzz\w+$') { $pending += $line; continue }
        if ($line -match '^ok\s+(\S+)') {
            foreach ($target in $pending) {
                Invoke-Logged -Log $log -Env @{ CGO_ENABLED = "0" } -Exe $Go -Arguments @("test", "-run", '^$', "-fuzz", "^$target`$", "-fuzztime", $FuzzTime, $Matches[1])
                $ran++
            }
            $pending = @()
        }
    }
    if ($ran -eq 0) { return "SKIP: no fuzz targets" }
    return "$ran target(s), $FuzzTime each"
}

Invoke-Step "generated docs are current" {
    Param($log)
    Invoke-Logged -Log $log -Env @{ CGO_ENABLED = "0" } -Exe $Go -Arguments @("run", "./cmd/gendocs", "-check")
}

if ($Quick) {
    $results.Add([pscustomobject]@{ Step = "example sweep"; Status = "SKIP"; Seconds = 0; Note = "SKIP: -Quick"; Log = "" })
} else {
    # The sweep runs the binary a release ships -- this toolchain, no cgo --
    # not one it would otherwise build with whatever go is first on the PATH.
    Invoke-Step "example sweep (golden output, levels 0,5,10)" {
        Param($log)
        $bin = Join-Path $LogDir "bin/sweep/mutant.exe"
        Invoke-Logged -Log $log -Env @{ CGO_ENABLED = "0" } -Exe $Go -Arguments @("build", "-trimpath", "-o", $bin, ".")
        Invoke-Logged -Log $log -Env @{ CGO_ENABLED = "0" } -Exe $Go -Arguments @("run", "./cmd/sweep", "--levels", "0,5,10", "--golden", "--mutant", $bin)
        $summary = Select-String -Path $log -Pattern 'printed exactly what' | Select-Object -Last 1
        if ($summary) { return $summary.Line.Trim() }
    }
}

Invoke-Step "go mod verify / tidy" {
    Param($log)
    Invoke-Logged -Log $log -Exe $Go -Arguments @("mod", "verify")
    Invoke-Logged -Log $log -Exe $Go -Arguments @("mod", "tidy", "-diff")
}

Invoke-Step "CHANGELOG date matches the tag" {
    Param($log)
    $tag = "v$version"
    $tagDate = (git for-each-ref --format='%(creatordate:short)' "refs/tags/$tag").Trim()
    if ($tagDate -eq "") { return "SKIP: $tag is not tagged yet" }
    $heading = (Select-String -Path CHANGELOG.md -Pattern "^## \[$([regex]::Escape($version))\](.*)$").Matches
    if ($heading.Count -eq 0) { throw "CHANGELOG.md has no [$version] heading" }
    $stated = [regex]::Match($heading[0].Groups[1].Value, '\d{4}-\d{2}-\d{2}').Value
    if ($stated -ne $tagDate) { throw "CHANGELOG.md dates $version '$stated'; the tag $tag was made $tagDate" }
}

if ($Vuln) {
    Invoke-Step "govulncheck" {
        Param($log)
        Invoke-Logged -Log $log -Env @{ CGO_ENABLED = "0" } -Exe $Go -Arguments @("run", "golang.org/x/vuln/cmd/govulncheck@latest", "./...")
    }
}

Write-Host ""
$results | Format-Table Step, Status, Seconds, Note -AutoSize -Wrap | Out-String -Width 200 | Write-Host
$failed = @($results | Where-Object Status -eq "FAIL").Count
if ($failed -gt 0) {
    Write-Host "$failed step(s) failed. Logs: $LogDir" -ForegroundColor Red
    exit 1
}
Write-Host "Release gate passed. Logs: $LogDir" -ForegroundColor Green
exit 0
