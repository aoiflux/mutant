Param(
    [string]$ExtensionDir = "mutant-vscode-extension",
    [string]$VsixOutDir = "dist/vscode-extension",
    [string]$VsixFileName = "mutant-language-tools.vsix",
    [switch]$Publish
)

$ErrorActionPreference = "Stop"

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

$repoRoot = Split-Path -Parent $PSScriptRoot
$lspBuildScript = Join-Path $repoRoot "lsp/build.ps1"
$extensionPath = Join-Path $repoRoot $ExtensionDir
$vsixOutPath = Join-Path $repoRoot $VsixOutDir
$vsixPath = Join-Path $vsixOutPath $VsixFileName

if (-not (Test-Path $lspBuildScript)) {
    throw "LSP build script not found: $lspBuildScript"
}

if (-not (Test-Path $extensionPath)) {
    throw "Extension directory not found: $extensionPath"
}

Write-Host "[1/3] Build LSP binaries for all supported platforms" -ForegroundColor Cyan
Invoke-Checked -What "LSP multi-platform build" -Command {
    & $lspBuildScript
}

Push-Location $extensionPath
try {
    if (-not (Test-Path (Join-Path $extensionPath "node_modules"))) {
        Write-Host "Installing extension dependencies" -ForegroundColor Cyan
        Invoke-Checked -What "npm install" -Command {
            npm install
        }
    }

    # Staging is a separate step: vscode:prepublish compiles only, so that
    # package-targets.mjs can stage a single per-target binary without vsce
    # re-staging all six behind it. This wrapper builds the universal VSIX, so
    # it stages every binary.
    Write-Host "[2/3] Stage LSP binaries and compile the extension" -ForegroundColor Cyan
    Invoke-Checked -What "Stage LSP binaries" -Command {
        npm run prepare:lsp-bins
    }
    Invoke-Checked -What "Extension prepublish" -Command {
        npm run vscode:prepublish
    }

    New-Item -ItemType Directory -Path $vsixOutPath -Force | Out-Null

    $vsce = Get-Command vsce -ErrorAction SilentlyContinue
    if ($vsce) {
        if ($Publish) {
            Write-Host "[3/3] Publish extension using vsce" -ForegroundColor Cyan
            Invoke-Checked -What "vsce publish" -Command {
                vsce publish --allow-missing-repository
            }
        }
        else {
            Write-Host "[3/3] Package VSIX using vsce" -ForegroundColor Cyan
            Invoke-Checked -What "vsce package" -Command {
                vsce package --allow-missing-repository --out $vsixPath
            }
            Write-Host "VSIX created: $vsixPath" -ForegroundColor Green
            Write-Sha256Sums -Directory $vsixOutPath -Names @($VsixFileName)
        }
    }
    else {
        $npx = Get-Command npx -ErrorAction SilentlyContinue
        if (-not $npx) {
            throw "Neither 'vsce' nor 'npx' was found on PATH. Install Node.js tooling first."
        }

        if ($Publish) {
            Write-Host "[3/3] Publish extension using npx @vscode/vsce" -ForegroundColor Cyan
            Invoke-Checked -What "npx @vscode/vsce publish" -Command {
                npx --yes @vscode/vsce publish --allow-missing-repository
            }
        }
        else {
            Write-Host "[3/3] Package VSIX using npx @vscode/vsce" -ForegroundColor Cyan
            Invoke-Checked -What "npx @vscode/vsce package" -Command {
                npx --yes @vscode/vsce package --allow-missing-repository --out $vsixPath
            }
            Write-Host "VSIX created: $vsixPath" -ForegroundColor Green
            Write-Sha256Sums -Directory $vsixOutPath -Names @($VsixFileName)
        }
    }
}
finally {
    Pop-Location
}

if ($Publish) {
    Write-Host "Publish flow complete." -ForegroundColor Green
}
else {
    Write-Host "Package flow complete." -ForegroundColor Green
}
