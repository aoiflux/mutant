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

# SHA256SUMS is written in the format `sha256sum -c` reads, so whoever downloads
# a binary can verify it with a tool they already have and nothing from this
# project: lowercase hex, two spaces, the file's bare name, LF line endings and
# no BOM -- the reader is as likely to be Linux as Windows. Names are bare and
# the file sits beside what it covers, so checking is
# `cd <dir>; sha256sum -c SHA256SUMS`.
function Write-Sha256Sums {
    Param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    # Ordinal sort, to match `LC_ALL=C sort` in the shell scripts: the same
    # build has to write the same file whichever script cut it.
    $ordered = $Names | Sort-Object -CaseSensitive
    $lines = foreach ($name in $ordered) {
        $path = Join-Path $Directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Cannot checksum a file the build did not produce: $path"
        }

        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower()
        "$hash  $name"
    }

    $sumsPath = Join-Path $Directory "SHA256SUMS"
    [System.IO.File]::WriteAllText(
        $sumsPath,
        (($lines -join "`n") + "`n"),
        (New-Object System.Text.UTF8Encoding $false))

    # No return value: every caller wants the file, not the path, and a bare
    # `return` in PowerShell puts the string on the pipeline where it surfaces as
    # a stray line of build output.
    Write-Host "    checksums: $sumsPath" -ForegroundColor DarkGray
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

    $binaryNames = @()
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
            $binaryNames += $binaryName
        }
    }
    finally {
        $env:CGO_ENABLED = $oldCGOEnabled
        $env:GOOS = $oldGoos
        $env:GOARCH = $oldGoarch
        $env:CC = $oldCC
    }

    Write-Sha256Sums -Directory $outputPath -Names $binaryNames

    Write-Host "LSP build complete." -ForegroundColor Green
    Write-Host "  Output directory: $outputPath" -ForegroundColor Green
    Write-Host "  Verify with: cd `"$outputPath`"; sha256sum -c SHA256SUMS" -ForegroundColor Green
}
finally {
    Pop-Location
}
