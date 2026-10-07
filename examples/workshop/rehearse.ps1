<#
.SYNOPSIS
  Rehearse the whole QUILLDROP workshop, unattended (Windows).

.DESCRIPTION
  RUN_SHEET_2H.md tells the instructor to prepare alone before the room
  arrives. This runs all ten beats in order, times each one and says whether it
  did what the run sheet promises, so a beat that cannot work on this machine is
  found the evening before rather than in front of attendees.

  Run it from the repository root: every beat names its evidence with
  repository-relative paths. This is the twin of rehearse.sh.

  It behaves differently depending on what is on disk, because the ten .golden
  files describe the empty case and not the solved one:

    no corpus   the ten beats each print one "missing" line and exit cleanly.
                That is exactly what the .golden files record, so every beat is
                compared against its golden byte for byte.
    corpus      the goldens no longer apply. A beat passes if it exits zero,
                prints its own QUILLDROP header and prints no "missing" line,
                and the three machine-dependent findings are reported by name.

  Only stdout is compared with the golden, because only stdout is what the
  program prints. `mutant --dev` with no password also writes a one-line notice
  about the development key to stderr, and on a host the sandbox detector flags
  it writes a warning per stage as well. cmd/sweep never sees either -- it
  passes a password, so the notice does not fire -- which is why the goldens do
  not carry them and why reading both streams as one would report all ten beats
  as broken. Everything on stderr is still read, and summarised at the end.

  A failing beat does not stop the run. The point is to see all ten.

  Exit codes. 0 every beat that ran matched its golden. 1 a beat failed or
  differed. 2 it could not start -- wrong directory, or no mutant. 3 the beats
  ran but no golden could be compared, because the goldens and the tree
  describe different worlds. 3 is deliberately not 0: a run that checked
  nothing is not a run that found nothing wrong.

.PARAMETER Mutant
  The mutant command to rehearse with. Defaults to whatever is on PATH; pass
  .\mutant.exe to rehearse a build you just made.

.PARAMETER Keep
  Leave the compiled .mu files beside their sources. By default the ones this
  run created are removed again and ones that were already there are left.

.PARAMETER Beat
  Rehearse one beat. -Beat 3, -Beat 03, -Beat lies and -Beat 06_lies all name
  one.
#>
Param(
    [string]$Mutant = "mutant",
    [switch]$Keep,
    [string]$Beat = ""
)

$beats = @("01_scene", "02_lure", "03_download", "04_binary", "05_timeline",
    "06_lies", "07_inventory", "08_rules", "09_verdict", "10_seal")
$ws = "examples/workshop"
$caseDir = "$ws/case"
$body = "$ws/case_quilldrop.body"

if ($Beat -match '^[1-9]$') { $Beat = "0$Beat" }

if (-not (Test-Path go.mod) -or -not (Test-Path "$ws/run.ps1")) {
    Write-Host "rehearse: run this from the repository root."
    Write-Host "  the beats name their evidence as $ws/case/..., so the working"
    Write-Host "  directory decides whether they find anything."
    exit 2
}

# Start-Process needs a path it can launch and a working directory of its own:
# PowerShell's current location is not the process's, so it is passed below.
$mutantPath = $null
$resolved = Get-Command $Mutant -ErrorAction SilentlyContinue
if ($resolved) {
    $mutantPath = $resolved.Source
} elseif (Test-Path -LiteralPath $Mutant) {
    $mutantPath = (Resolve-Path -LiteralPath $Mutant).Path
}
if (-not $mutantPath) {
    Write-Host "rehearse: $Mutant not found on PATH."
    Write-Host "  build it with: go build -o mutant.exe ."
    Write-Host "  then: .\examples\workshop\rehearse.ps1 -Mutant .\mutant.exe"
    exit 2
}
$repoRoot = (Get-Location).Path

# The same shape sweep.NormalizeOutput gives a golden, which is what wrote
# these ten -- CRLF to LF, no trailing blanks on any line, and exactly one
# newline at the end. Without the last of those every beat reads as different,
# because a program's output ends in a newline and the golden holds the text
# without it. The scratch-root and host-error rewrites that function also does
# are not needed here: this runs in the repository itself, and in guard mode no
# beat prints a host error.
function Get-NormalizedText {
    Param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return "`n" }
    $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n")
    $lines = @()
    foreach ($line in ($text -split "`n")) { $lines += ($line -replace '[ \t]+$', '') }
    return (($lines -join "`n").TrimEnd("`n")) + "`n"
}

# Start-Process is used rather than the call operator because this needs stdout
# and stderr apart, and the exit code: `&` merges a native command's streams
# into one pipeline, which is exactly what makes a golden comparison wrong here.
function Invoke-Captured {
    Param([string[]]$Arguments, [string]$OutFile, [string]$ErrFile)
    $p = Start-Process -FilePath $mutantPath -ArgumentList $Arguments `
        -WorkingDirectory $repoRoot -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $OutFile -RedirectStandardError $ErrFile
    return $p.ExitCode
}

Write-Host "QUILLDROP rehearsal"
Write-Host "  mutant   : $mutantPath"
$versionOut = Join-Path ([IO.Path]::GetTempPath()) ("quilldrop-version-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
$null = Invoke-Captured -Arguments @("--version") -OutFile "$versionOut.out" -ErrFile "$versionOut.err"
$version = (Get-Content "$versionOut.out" -ErrorAction SilentlyContinue | Select-Object -First 1)
Remove-Item -LiteralPath "$versionOut.out", "$versionOut.err" -Force -ErrorAction SilentlyContinue
Write-Host "  version  : $version"
if ($version -notlike "*2.5.0*") {
    Write-Host "             note: the story targets v2.5.0, which is what attendees"
    Write-Host "             will have downloaded. A newer build runs it fine; this is"
    Write-Host "             only a reminder that you are not rehearsing their binary."
}

# Which evidence paths exist decides what each beat can do: beats 1, 2, 3, 4, 7
# and 9 need the corpus, beats 5, 6 and 8 need the timeline, and beat 10 needs
# the handover beat 9 writes. Reporting the two inputs separately beats one
# yes/no answer, because a half-built corpus is the confusing case.
$haveCase = Test-Path -LiteralPath $caseDir
$haveBody = Test-Path -LiteralPath $body
if ($haveCase -or $haveBody) { $mode = "case" } else { $mode = "guard" }

# Whether the goldens can be compared is a separate question from whether the
# corpus is there, and it is read off the goldens rather than assumed. Today all
# ten hold the single line lib/quilldrop.mut prints when the evidence is absent.
# The workshop readiness report's item 2 will replace them with real output from
# a pre-built corpus, and on that day the two worlds swap: comparing is right
# when the corpus is present and wrong when it is not. Deciding from the corpus
# alone would mean this script quietly stopped comparing anything on the day the
# goldens became worth comparing.
$emptyGoldens = 0
foreach ($b in $beats) {
    $g = "$ws/$b.golden"
    if ((Test-Path -LiteralPath $g) -and ([IO.File]::ReadAllText($g) -like "*- see examples/workshop/README.md*")) {
        $emptyGoldens++
    }
}
if ($emptyGoldens -eq 10) { $goldenWorld = "empty" }
elseif ($emptyGoldens -eq 0) { $goldenWorld = "case" }
else { $goldenWorld = "mixed" }
$compare = ($goldenWorld -eq "empty" -and $mode -eq "guard") -or ($goldenWorld -eq "case" -and $mode -eq "case")

Write-Host ""
if ($mode -eq "guard") {
    Write-Host "  evidence : none, $caseDir and $body are both absent"
} else {
    Write-Host "  evidence : present"
}
if ($goldenWorld -eq "empty") {
    Write-Host "  goldens  : record the empty case ($emptyGoldens of 10 hold the `"missing`" line)"
} elseif ($goldenWorld -eq "case") {
    Write-Host "  goldens  : record real output ($emptyGoldens of 10 hold the `"missing`" line)"
} else {
    Write-Host "  goldens  : are mixed ($emptyGoldens of 10 hold the `"missing`" line)"
}
if ($goldenWorld -eq "mixed") {
    Write-Host "             MIXED, which no single state of the tree produces. Some goldens"
    Write-Host "             were regenerated and some were not; regenerate them all with"
    Write-Host "             go run ./cmd/sweep --update-golden before trusting this run."
}
if ($compare) {
    Write-Host "  mode     : COMPARE. Each beat is checked against its .golden byte for"
    Write-Host "             byte, which is what the readiness report asks for: the diff"
    Write-Host "             must be empty."
} elseif ($mode -eq "guard") {
    Write-Host "  mode     : NO CORPUS. The goldens record real output, so every beat will"
    Write-Host "             print its `"missing`" line instead and nothing can be compared."
    Write-Host "             Build the corpus and run this again:"
    Write-Host "               go install github.com/aoiflux/fsagen@v0.1.0"
    Write-Host "               .\examples\workshop\evidence\build_evidence.ps1"
} else {
    Write-Host "  mode     : CASE. The goldens record the empty case, so they are not"
    Write-Host "             compared here. A beat passes if it exits 0, prints its"
    Write-Host "             QUILLDROP header and prints no `"missing`" line."
}
if ($mode -eq "guard") {
    if ($compare) {
        Write-Host ""
        Write-Host "             This tests the guard in lib/quilldrop.mut, not the case. To"
        Write-Host "             rehearse the case itself, build the corpus first:"
        Write-Host "               go install github.com/aoiflux/fsagen@v0.1.0"
        Write-Host "               .\examples\workshop\evidence\build_evidence.ps1"
    }
} else {
    if ($haveCase) {
        $files = (Get-ChildItem -LiteralPath $caseDir -Recurse -File -ErrorAction SilentlyContinue).Count
        Write-Host "  corpus   : $caseDir, $files files (the run sheet says 98)"
        if ($files -ne 98) {
            Write-Host "             MISMATCH. Check evidence/README.md before teaching this."
        }
    } else {
        Write-Host "  corpus   : MISSING $caseDir, so beats 1, 2, 3, 4, 7 and 9 report missing"
    }
    if ($haveBody) {
        $rows = (Get-Content -LiteralPath $body).Count
        Write-Host "  timeline : $body, $rows rows (the run sheet says 131)"
        if ($rows -ne 131) {
            Write-Host "             MISMATCH. Check evidence/README.md before teaching this."
        }
    } else {
        Write-Host "  timeline : MISSING $body, so beats 5, 6 and 8 report missing"
    }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("quilldrop-rehearse-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$summary = New-Object System.Collections.Generic.List[string]
$failed = 0
$ran = 0
$sandbox = 0
$runTotal = 0.0
$stdoutOf = @{}

Write-Host ""
Write-Host "----------------------------------------------------------------------"
foreach ($b in $beats) {
    if ($Beat -ne "" -and $b -ne $Beat -and $b.Split("_")[0] -ne $Beat -and $b.Substring($b.IndexOf("_") + 1) -ne $Beat) {
        continue
    }
    $ran++
    Write-Host ("{0,-14} " -f $b) -NoNewline
    $watch = [Diagnostics.Stopwatch]::StartNew()

    $genRc = Invoke-Captured -Arguments @("gen", "--src", "$ws/$b.mut", "--dev") `
        -OutFile "$tmp/$b.gen.out" -ErrFile "$tmp/$b.gen.err"
    if ($genRc -ne 0) {
        $watch.Stop()
        $elapsed = [math]::Round($watch.Elapsed.TotalSeconds, 1)
        Write-Host "COMPILE (${elapsed}s) mutant gen refused the source"
        Get-Content "$tmp/$b.gen.out", "$tmp/$b.gen.err" -ErrorAction SilentlyContinue |
            Select-Object -First 20 | ForEach-Object { Write-Host "    $_" }
        $summary.Add(("{0,-14} {1,-8} {2,5}s  {3}" -f $b, "COMPILE", $elapsed, "mutant gen refused the source"))
        $failed++
        continue
    }

    $rc = Invoke-Captured -Arguments @("$ws/$b.mu", "--dev") -OutFile "$tmp/$b.out" -ErrFile "$tmp/$b.err"
    $watch.Stop()
    $elapsed = [math]::Round($watch.Elapsed.TotalSeconds, 1)
    $runTotal += $watch.Elapsed.TotalSeconds

    $outText = Get-NormalizedText "$tmp/$b.out"
    $stdoutOf[$b] = $outText
    $lines = ($outText.TrimEnd("`n") -split "`n").Count

    # The two stderr lines that are a property of how this script invokes
    # mutant rather than of the beat: the development-key notice, and one
    # sandbox warning per stage where the host looks like an analysis machine.
    # Anything else on stderr is the beat's own and is shown.
    $errLines = @(Get-Content "$tmp/$b.err" -ErrorAction SilentlyContinue)
    if ($errLines | Where-Object { $_ -match 'event=sandbox_detected' }) { $sandbox++ }
    $otherErr = @($errLines | Where-Object {
            $_ -notmatch '^\[dev\] ' -and $_ -notmatch '^\[security\] event=sandbox_detected ' -and $_ -ne ""
        })

    $status = "OK"
    $note = ""
    if ($rc -ne 0) {
        $status = "FAIL"
        $note = "exited $rc"
    } elseif ($compare) {
        $want = Get-NormalizedText "$ws/$b.golden"
        if ($outText -ceq $want) {
            $note = "matches $b.golden"
        } else {
            $status = "DIFF"
            $note = "differs from $b.golden"
        }
    } else {
        if ($outText -notmatch 'QUILLDROP') {
            $status = "FAIL"
            $note = "printed no QUILLDROP header"
        } elseif ($outText -match '(?m)^  missing ') {
            $status = "GUARD"
            $note = "the guard fired, so evidence this beat needs is not there"
        } else {
            $note = "$lines lines"
        }
    }

    if ($status -eq "FAIL" -or $status -eq "DIFF") { $failed++ }
    Write-Host "$status (${elapsed}s) $note"
    if ($status -eq "DIFF") {
        $want = Get-NormalizedText "$ws/$b.golden"
        Compare-Object ($want.TrimEnd("`n") -split "`n") ($outText.TrimEnd("`n") -split "`n") |
            Select-Object -First 20 | ForEach-Object {
                if ($_.SideIndicator -eq "=>") { Write-Host "    + $($_.InputObject)" }
                else { Write-Host "    - $($_.InputObject)" }
            }
    } elseif ($status -eq "FAIL") {
        ($outText.TrimEnd("`n") -split "`n") | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" }
    }
    if ($otherErr.Count -gt 0) {
        Write-Host "    unexpected on stderr:"
        $otherErr | Select-Object -First 10 | ForEach-Object { Write-Host "      $_" }
    }
    $summary.Add(("{0,-14} {1,-8} {2,5}s  {3}" -f $b, $status, $elapsed, $note))
}
Write-Host "----------------------------------------------------------------------"

# The three findings the run sheet promises that depend on the volume rather
# than on the code. Each is read out of what the beat actually printed, so this
# is right on NTFS, on ReFS, on a network share and under WSL, without guessing
# from the operating system.
if ($mode -eq "case") {
    Write-Host ""
    Write-Host "The findings that depend on this machine:"
    if ($stdoutOf.ContainsKey("03_download")) {
        if ($stdoutOf["03_download"] -match 'HostUrl=') {
            Write-Host "  beat 3  the Zone.Identifier stream is there, so the download host"
            Write-Host "          corroborates the email from beat 2. The twist lands."
        } else {
            Write-Host "  beat 3  no Zone.Identifier: this volume has no named streams, so the"
            Write-Host "          third answer reports nothing. The run sheet calls that the"
            Write-Host "          honest answer, so say it rather than skipping the beat."
        }
    }
    if ($stdoutOf.ContainsKey("06_lies")) {
        if ($stdoutOf["06_lies"] -match 'older than its own birth') {
            Write-Host "  beat 6  a file is modified before it was born. The central finding fires."
        } else {
            Write-Host "  beat 6  nothing is older than its own birth. This volume kept no"
            Write-Host "          creation times, so beat 6's central finding cannot fire."
            Write-Host "          Generate on NTFS, or hand out the pre-built corpus"
            Write-Host "          (evidence/README.md, `"Where the pre-built corpus comes from`")."
        }
    }
    if ($stdoutOf.ContainsKey("08_rules")) {
        if ($stdoutOf["08_rules"] -match 'fields no event carried') {
            Write-Host "  beat 8  the unmatched-fields line is there, which is the beat's point:"
            Write-Host "          the critical rule never ran, so it did not clear the host."
        } else {
            Write-Host "  beat 8  no unmatched-fields line, and that line is beat 8's twist."
            Write-Host "          Check that quilldrop.sigma.yaml reached sigma_scan."
        }
    }
}

if ($sandbox -gt 0) {
    Write-Host ""
    Write-Host "This host looks like an analysis sandbox to mutant ($sandbox of the beats"
    Write-Host "warned). --dev downgrades that to a warning, which is why they ran. An"
    Write-Host "attendee who drops --dev here is halted instead, so rehearse where you"
    Write-Host "will teach, and teach from PowerShell or cmd, as README.md says."
}

Write-Host ""
Write-Host "Summary"
foreach ($line in $summary) { Write-Host "  $line" }
Write-Host ""
$total = [math]::Round($runTotal, 1)
Write-Host "  machine time: ${total}s across the beats that ran. That is compile and"
Write-Host "  run only. RUN_SHEET_2H.md allocates ten minutes a beat for asking the"
Write-Host "  question, writing the file and reading the output, which is teaching time"
Write-Host "  and is not measured here."

# A .mu is build output: mutant gen rewrites one in about a second from a
# committed source, and *.mu is gitignored. All ten go, not only the ones this
# run made -- preserving whatever happened to be there already meant the litter
# from one interrupted run stayed for every later run to step around, and made
# the count printed below depend on history rather than on the tree. -Keep is
# for when you want to inspect a compiled beat afterwards.
if (-not $Keep) {
    $removed = 0
    foreach ($b in $beats) {
        if (Test-Path -LiteralPath "$ws/$b.mu") {
            Remove-Item -LiteralPath "$ws/$b.mu" -Force
            $removed++
        }
    }
    if ($removed -gt 0) {
        Write-Host "  removed $removed compiled .mu file(s); -Keep leaves them in place"
    }
}
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($failed -gt 0) {
    Write-Host "$failed beat(s) did not do what this mode expects. Not ready to teach."
    exit 1
}
# "All ten" is only true of a whole run: -Beat names one, and saying ten of it
# would be the kind of claim this script exists to stop someone making.
if ($ran -eq 10) { $which = "All ten beats" } else { $which = "$ran of ten beats (-Beat)" }
if ($compare -and $mode -eq "guard") {
    Write-Host "$which printed what the golden records. The guard works, and the case"
    Write-Host "itself is untested until you build the corpus and run this again."
    exit 0
} elseif ($compare) {
    Write-Host "$which matched its golden with the corpus in place. The diff is empty,"
    Write-Host "which is what the readiness report asks of a rehearsal."
    exit 0
} else {
    Write-Host "$which ran, and nothing was compared with a golden -- see the mode line"
    Write-Host "above for why. Read the machine-dependent findings before teaching, and"
    Write-Host "treat this as unverified rather than passed."
    exit 3
}
