Param(
    [string]$OutputDir = "dist",
    [string]$FinalName = "mlsp",
    [switch]$HostOnly
)

$ErrorActionPreference = "Stop"

$lspRoot = $PSScriptRoot
$mainPackage = "./cmd/mlsp"
$targets = @(
    @{ GoOS = "windows"; GoArch = "amd64"; ExeSuffix = ".exe" },
    @{ GoOS = "windows"; GoArch = "arm64"; ExeSuffix = ".exe" },
    @{ GoOS = "linux"; GoArch = "amd64"; ExeSuffix = "" },
    @{ GoOS = "linux"; GoArch = "arm64"; ExeSuffix = "" },
    @{ GoOS = "darwin"; GoArch = "amd64"; ExeSuffix = "" },
    @{ GoOS = "darwin"; GoArch = "arm64"; ExeSuffix = "" }
)

$goBuildArgs = @("-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid=")

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

$outputPath = Join-Path $lspRoot $OutputDir
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

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

Push-Location $lspRoot
try {
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

            $binaryName = "$FinalName-$($target.GoOS)-$($target.GoArch)$($target.ExeSuffix)"
            $binaryPath = Join-Path $outputPath $binaryName

            Write-Host "Building $targetLabel -> $binaryPath" -ForegroundColor Cyan
            Invoke-Checked -What "LSP build for $targetLabel" -Command {
                go build @goBuildArgs -o $binaryPath $mainPackage
            }
        }
    }
    finally {
        $env:CGO_ENABLED = $oldCGOEnabled
        $env:GOOS = $oldGoos
        $env:GOARCH = $oldGoarch
        $env:CC = $oldCC
    }

    Write-Host "LSP build complete." -ForegroundColor Green
    Write-Host "  Output directory: $outputPath" -ForegroundColor Green
}
finally {
    Pop-Location
}
