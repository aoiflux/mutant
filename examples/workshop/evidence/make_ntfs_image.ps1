# Build a REAL NTFS volume containing REAL timestomped files, so the workshop
# can demonstrate $STANDARD_INFORMATION vs $FILE_NAME detection on genuine
# NTFS metadata rather than on a simulation.
#
#   RUN THIS ONCE, ON THE FACILITATOR'S MACHINE, IN AN ELEVATED POWERSHELL.
#   Students never need admin: they get the exported $MFT file.
#
#   .\examples\workshop\evidence\make_ntfs_image.ps1
#
# Why this is worth the trouble
# -----------------------------
# NTFS stores every file's timestamps twice. $STANDARD_INFORMATION (SI) is what
# the ordinary Win32 SetFileTime API writes -- and what PowerShell writes when
# you assign to .CreationTime. $FILE_NAME (FN) is written by the kernel when the
# directory entry is created, and there is no supported user-mode call that
# changes it.
#
# So the three lines below that backdate a file are a REAL timestomp, performed
# by the same API every timestomping tool uses. Afterwards SI says 2024 and FN
# still says today -- which is exactly the contradiction 09_revenant.mut hunts,
# recorded in real NTFS structures on a real volume.
#
# Bonus: .NET DateTime values parsed from a whole-second string carry a zero
# 100-nanosecond fraction, so these files also trip the "all SI times land on a
# whole second" tell. Two independent detections from three lines of setup.

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$Here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Corpus   = Join-Path $Here 'case_quilldrop'
$Vhd      = Join-Path $Here 'quilldrop_ntfs.vhd'
$Letter   = 'Q'
$SizeMB   = 256
$FakeTime = [datetime]::ParseExact('2024-01-05 08:00:00','yyyy-MM-dd HH:mm:ss',$null)

# Files to backdate, relative to the corpus root. These are the implant's.
$Stomp = @(
  'Users\r.mehta\Downloads\Invoice_MRD-88412.pdf.exe',
  'Users\r.mehta\AppData\Roaming\MeridianSync\svchost.exe',
  'Users\r.mehta\AppData\Roaming\MeridianSync\config.dat',
  'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\MeridianSync.cmd'
)

if (-not (Test-Path $Corpus)) {
    Write-Host "No corpus at $Corpus - run build_evidence.ps1 first." -ForegroundColor Red
    exit 1
}
if (Test-Path $Vhd) { Remove-Item -Force $Vhd }

# --- create + attach + format, via diskpart (no Hyper-V module required) -----
$script = @"
create vdisk file="$Vhd" maximum=$SizeMB type=fixed
select vdisk file="$Vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=QUILLDROP
assign letter=$Letter
"@
$scriptPath = Join-Path $env:TEMP 'quilldrop_diskpart.txt'
Set-Content -Path $scriptPath -Value $script -Encoding ASCII

Write-Host "creating and mounting a ${SizeMB}MB NTFS volume as ${Letter}:..." -ForegroundColor Cyan
diskpart /s $scriptPath | Out-Null
Start-Sleep -Seconds 2

$Root = "${Letter}:\"
if (-not (Test-Path $Root)) { Write-Host "volume did not mount" -ForegroundColor Red; exit 1 }

# --- populate ----------------------------------------------------------------
Write-Host 'copying the corpus onto the volume...' -ForegroundColor Cyan
Copy-Item -Recurse -Force (Join-Path $Corpus '*') $Root

# --- the actual timestomp ----------------------------------------------------
# This writes $STANDARD_INFORMATION only. $FILE_NAME keeps the real birth time,
# set by the kernel during the Copy-Item above, moments ago.
Write-Host 'timestomping the implant files (SI only)...' -ForegroundColor Yellow
foreach ($rel in $Stomp) {
    $p = Join-Path $Root $rel
    if (-not (Test-Path $p)) { Write-Host "  skip (not present): $rel"; continue }
    $f = Get-Item $p
    $f.CreationTime   = $FakeTime
    $f.LastWriteTime  = $FakeTime
    $f.LastAccessTime = $FakeTime
    Write-Host "  stomped: $rel"
}

# --- export the $MFT while the volume is still mounted -----------------------
# export_mft.mut reads the boot sector, computes where the $MFT starts, and
# copies it out. Nothing in it is NTFS-specific magic; it is five integer reads.
Write-Host ''
Write-Host 'exporting the $MFT with mutant...' -ForegroundColor Cyan
$repo = Resolve-Path (Join-Path $Here '..\..\..')
Push-Location $repo
try {
    & .\mutant.exe run examples\workshop\evidence\export_mft.mut --password-stdin < $null 2>&1 | Out-Null
    Write-Host '  (if that prompted for a password, run the two commands by hand:)'
    Write-Host '    mutant run examples/workshop/evidence/export_mft.mut'
    Write-Host '    mutant     examples/workshop/evidence/export_mft.mu'
} finally { Pop-Location }

Write-Host ''
Write-Host "Volume ${Letter}: is still mounted so you can run export_mft by hand." -ForegroundColor Green
Write-Host 'When you are done:'
Write-Host "  diskpart /s - then: select vdisk file=`"$Vhd`" / detach vdisk"
Write-Host ''
Write-Host 'Then ship examples/workshop/evidence/case_quilldrop.mft with the workshop'
Write-Host 'and set MFT_PATH in 09_revenant.mut to it. Students need no admin.'
Write-Host ''
Write-Host 'Facilitator shortcut, no VHD at all: in an elevated shell set'
Write-Host '  MFT_PATH = "\\.\C:"'
Write-Host 'and 09_revenant.mut parses your own live Master File Table.'
