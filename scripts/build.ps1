Param(
    [string]$OutputDir = "dist",
    [string]$AssetsOut = "releaseassets",
    [string]$FinalName = "mutant",
    [switch]$HostOnly,
    [switch]$WasmRepl,
    [string]$WasmOutDir = "examples/wasm-repl"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$targets = @(
    @{ GoOS = "windows"; GoArch = "amd64"; ExeSuffix = ".exe" },
    @{ GoOS = "windows"; GoArch = "arm64"; ExeSuffix = ".exe" },
    @{ GoOS = "linux"; GoArch = "amd64"; ExeSuffix = "" },
    @{ GoOS = "linux"; GoArch = "arm64"; ExeSuffix = "" },
    @{ GoOS = "darwin"; GoArch = "amd64"; ExeSuffix = "" },
    @{ GoOS = "darwin"; GoArch = "arm64"; ExeSuffix = "" }
)

$totalSteps = if ($WasmRepl) { 4 } else { 3 }
$step = 0
$goBuildArgs = @("-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid=")

function Show-Step {
    Param(
        [string]$Message,
        [string]$Status = "Running"
    )

    $percent = [int](($step / $totalSteps) * 100)
    Write-Progress -Activity "Mutant Full Build" -Status $Status -PercentComplete $percent -CurrentOperation $Message
    Write-Host "[$step/$totalSteps] $Message" -ForegroundColor Cyan
}

function Start-Step {
    Param([string]$Message)
    $script:step += 1
    Show-Step -Message $Message
}

function Invoke-Checked {
    Param(
        [string]$What,
        [scriptblock]$Command
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE"
    }
}

function Assert-ReleaseAssetsDataClean {
    $dataDir = Join-Path $repoRoot "$AssetsOut\data"
    if (-not (Test-Path $dataDir)) {
        throw "Required assets data directory not found: $dataDir"
    }

    $entries = Get-ChildItem -Force $dataDir
    $placeholder = $entries | Where-Object { $_.Name -eq "placeholder.bin" }
    $unexpected = $entries | Where-Object { $_.Name -ne "placeholder.bin" }

    if ($unexpected.Count -gt 0) {
        foreach ($entry in $unexpected) {
            Remove-Item -Force -Recurse $entry.FullName
        }

        Write-Host "    Pruned $dataDir to placeholder.bin only." -ForegroundColor Yellow
    }

    if (-not $placeholder) {
        throw "Expected '$dataDir' to contain placeholder.bin before build actions, but it is missing."
    }
}

function Resolve-WasmExecPath {
    Param([string]$GoRoot)

    $candidates = @(
        (Join-Path $GoRoot "lib/wasm/wasm_exec.js"),
        (Join-Path $GoRoot "misc/wasm/wasm_exec.js")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "wasm_exec.js not found under '$GoRoot/lib/wasm' or '$GoRoot/misc/wasm'"
}

Assert-ReleaseAssetsDataClean

New-Item -ItemType Directory -Path (Join-Path $repoRoot $OutputDir) -Force | Out-Null

$exeSuffix = if ($IsWindows) { ".exe" } else { "" }
$bootstrapPath = Join-Path $repoRoot (Join-Path $OutputDir ("mutant-bootstrap" + $exeSuffix))

$hostInfo = & go env GOHOSTOS GOHOSTARCH
if ($LASTEXITCODE -ne 0 -or -not $hostInfo -or $hostInfo.Count -lt 2) {
    throw "Failed to detect Go host target via 'go env GOHOSTOS GOHOSTARCH'"
}
$goHostOS = $hostInfo[0].Trim()
$goHostArch = $hostInfo[1].Trim()

if ($HostOnly) {
    $targets = $targets | Where-Object { $_.GoOS -eq $goHostOS -and $_.GoArch -eq $goHostArch }
    if (-not $targets -or $targets.Count -eq 0) {
        throw "No host-matching target found for $goHostOS/$goHostArch"
    }
}

Push-Location $repoRoot
try {
    Start-Step "Compile Go bootstrap binary"
    Invoke-Checked -What "Go bootstrap build" -Command {
        go build @goBuildArgs -o $bootstrapPath .
    }
    Write-Host "    Bootstrap binary: $bootstrapPath" -ForegroundColor DarkGray

    Start-Step "Generate embedded release assets"
    Invoke-Checked -What "Release asset generation" -Command {
        & $bootstrapPath gen --release-assets -out $AssetsOut
    }
    Write-Host "    Assets directory: $(Join-Path $repoRoot $AssetsOut)" -ForegroundColor DarkGray

    Start-Step "Recompile final Go binaries with release assets"
    $oldCGOEnabled = $env:CGO_ENABLED
    $oldGoos = $env:GOOS
    $oldGoarch = $env:GOARCH
    $oldCC = $env:CC

    try {
        $env:CGO_ENABLED = "0"

        foreach ($target in $targets) {
            $targetLabel = "$($target.GoOS)/$($target.GoArch)"

            $env:GOOS = $target.GoOS
            $env:GOARCH = $target.GoArch
            $env:CC = $oldCC

            $targetName = "$FinalName-$($target.GoOS)-$($target.GoArch)$($target.ExeSuffix)"
            $finalPath = Join-Path $repoRoot (Join-Path $OutputDir $targetName)

            Write-Host "    Go => $targetLabel" -ForegroundColor DarkGray
            Invoke-Checked -What "Go final build for $targetLabel" -Command {
                go build @goBuildArgs -o $finalPath .
            }
            Write-Host "      binary: $finalPath" -ForegroundColor DarkGray
        }
    }
    finally {
        $env:CGO_ENABLED = $oldCGOEnabled
        $env:GOOS = $oldGoos
        $env:GOARCH = $oldGoarch
        $env:CC = $oldCC
    }

    if ($WasmRepl) {
        Start-Step "Build browser REPL wasm artifacts"
        $wasmOutPath = Join-Path $repoRoot $WasmOutDir
        New-Item -ItemType Directory -Path $wasmOutPath -Force | Out-Null

        $goRoot = (& go env GOROOT).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($goRoot)) {
            throw "Failed to resolve GOROOT for wasm artifact setup"
        }

        $wasmExecPath = Resolve-WasmExecPath -GoRoot $goRoot
        Copy-Item $wasmExecPath (Join-Path $wasmOutPath "wasm_exec.js") -Force

        $oldGoos = $env:GOOS
        $oldGoarch = $env:GOARCH
        try {
            $env:GOOS = "js"
            $env:GOARCH = "wasm"
            $env:CGO_ENABLED = "0"

            $wasmPath = Join-Path $wasmOutPath "mutant_repl.wasm"
            Invoke-Checked -What "WASM browser REPL build" -Command {
                go build @goBuildArgs -o $wasmPath ./cmd/replwasm
            }
            Write-Host "    wasm: $wasmPath" -ForegroundColor DarkGray
            Write-Host "    wasm_exec.js: $(Join-Path $wasmOutPath "wasm_exec.js")" -ForegroundColor DarkGray
        }
        finally {
            $env:GOOS = $oldGoos
            $env:GOARCH = $oldGoarch
        }
    }

    Write-Progress -Activity "Mutant Full Build" -Status "Done" -PercentComplete 100 -Completed
    Write-Host "Build complete." -ForegroundColor Green
    Write-Host "  Final binaries in: $(Join-Path $repoRoot $OutputDir)" -ForegroundColor Green

    Remove-Item $bootstrapPath;
    Write-Host "Cleaned Bootstrap Bin" -ForegroundColor Blue;
}
finally {
    Pop-Location
}
