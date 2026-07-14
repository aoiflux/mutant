Param(
    [string]$ExtensionDir = "mutant-vscode-extension",
    [string]$VsixOutDir = "dist/vscode-extension",
    [string]$VsixFileName = "mutant-language-tools.vsix",
    [switch]$Publish
)

$ErrorActionPreference = "Stop"

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

    Write-Host "[2/3] Run extension prepublish (stages binaries and compiles)" -ForegroundColor Cyan
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
