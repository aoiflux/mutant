package policy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The release gate exists to check the binary a release ships, and a release
// ships with CGO_ENABLED=0. A go command that leaves cgo unset takes the host's
// default instead: on a host with a C compiler it builds something no release
// is, and on a host with a compiler but no C headers it fails before it checks
// anything. Only the race detector needs cgo, and only for its test binaries.

// gateCompilingCommands are the go subcommands that compile code, so cgo
// decides what they build.
var gateCompilingCommands = regexp.MustCompile(`^(build|run|test|vet|install)$`)

// TestEveryGateGoCommandChoosesCgo: in both gate scripts, every go command that
// compiles says CGO_ENABLED=0 on its own line -- CGO_ENABLED=1 for the race
// detector -- and the example sweep runs a binary the gate built, not one the
// sweep builds with whatever go is first on the PATH.
func TestEveryGateGoCommandChoosesCgo(t *testing.T) {
	bashCommand := regexp.MustCompile(`"\$GO" (\w+)`)
	checked := 0
	for n, line := range gateScriptLines(t, "scripts/release_gate.sh") {
		for _, m := range bashCommand.FindAllStringSubmatch(line, -1) {
			if !gateCompilingCommands.MatchString(m[1]) {
				continue
			}
			checked++
			want := gateCgoWant(line)
			if !strings.Contains(line, "CGO_ENABLED="+want) {
				t.Errorf("scripts/release_gate.sh:%d runs go %s without CGO_ENABLED=%s: %s", n+1, m[1], want, strings.TrimSpace(line))
			}
		}
	}

	psLines := gateScriptLines(t, "scripts/release_gate.ps1")
	psInvoke := regexp.MustCompile(`-Exe \$Go -Arguments \(?@\("(\w+)"`)
	psDirect := regexp.MustCompile(`& \$Go (\w+)`)
	psEnvs := regexp.MustCompile(`\$envs = @\{[^}]*CGO_ENABLED = "0"`)
	envsSetsCgo := false
	for _, line := range psLines {
		envsSetsCgo = envsSetsCgo || psEnvs.MatchString(line)
	}
	for n, line := range psLines {
		if m := psDirect.FindStringSubmatch(line); m != nil && gateCompilingCommands.MatchString(m[1]) {
			t.Errorf("scripts/release_gate.ps1:%d calls go %s directly, so it cannot set cgo for that command alone; use Invoke-Logged -Env: %s", n+1, m[1], strings.TrimSpace(line))
		}
		m := psInvoke.FindStringSubmatch(line)
		if m == nil || !gateCompilingCommands.MatchString(m[1]) {
			continue
		}
		checked++
		want := gateCgoWant(line)
		switch {
		case strings.Contains(line, `CGO_ENABLED = "`+want+`"`):
		case want == "0" && strings.Contains(line, "-Env $envs") && envsSetsCgo:
		default:
			t.Errorf("scripts/release_gate.ps1:%d runs go %s without CGO_ENABLED = %q: %s", n+1, m[1], want, strings.TrimSpace(line))
		}
	}
	if checked == 0 {
		t.Fatal("found no go commands in the gate scripts; the patterns no longer match them")
	}

	for _, script := range []string{"scripts/release_gate.sh", "scripts/release_gate.ps1"} {
		swept := false
		for n, line := range gateScriptLines(t, script) {
			if !strings.Contains(line, "./cmd/sweep") {
				continue
			}
			swept = true
			if !strings.Contains(line, "--mutant") {
				t.Errorf("%s:%d runs the sweep without --mutant, so the sweep builds its own binary with the go on the PATH: %s", script, n+1, strings.TrimSpace(line))
			}
		}
		if !swept {
			t.Errorf("%s no longer runs ./cmd/sweep; update this test if the step moved", script)
		}
	}
}

// TestShellScriptsAreCommittedExecutable: CONTRIBUTING tells a Linux or macOS
// contributor to run scripts/release_gate.sh, which a checkout can only do if git
// recorded the script as executable. A Windows checkout never notices a missing
// bit (core.filemode is off there), so the index is the only place to check it.
//
// Every tracked .sh, not only the ones under scripts/. Reading `-- scripts` alone
// is what let lsp/build.sh stay 100644 while its own usage line and three
// documentation sites invoke it as ./lsp/build.sh, which is exactly the failure
// M26-TEST-005 fixed for the four scripts under scripts/ (M26-TEST-012).
//
// There is no allowlist for scripts documented to be run through `sh`, although
// the row proposed one. The executable bit is never WRONG on such a script, while
// a missing bit is a documented failure, so an exemption buys nothing and a
// hand-maintained list of them is the shape M26-TEST-009 is about. Deriving the
// list from how the documentation invokes each script was tried and misclassified
// three of the seven tracked scripts, so it is not a rule that can be always
// correct.
func TestShellScriptsAreCommittedExecutable(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "--stage", "--", "*.sh")
	cmd.Dir = repositoryRoot
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("not a git checkout (%v); the executable bit lives in git's index", err)
	}
	scripts := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		// <mode> <blob> <stage>\t<path>
		meta, path, ok := strings.Cut(line, "\t")
		if !ok || !strings.HasSuffix(path, ".sh") {
			continue
		}
		scripts++
		if mode, _, _ := strings.Cut(meta, " "); mode != "100755" {
			t.Errorf("%s is recorded as mode %s; a checkout cannot run it (git update-index --chmod=+x %s)", path, mode, path)
		}
	}
	if scripts == 0 {
		t.Fatal("git lists no tracked shell scripts; the pattern no longer matches them")
	}
}

// TestGateRefusesALogDirInsideTheRepository: the gate writes an LF copy of every
// Go file under its log directory for gofmt to read. Inside the repository those
// copies are packages of the module, so go test ./... compiles them beside the
// real ones and every tree-walking guard counts them twice -- the gate fails for
// a reason that is nowhere in the code. Each host runs its own twin of the gate,
// so each host checks that twin refuses such a directory before creating it.
func TestGateRefusesALogDirInsideTheRepository(t *testing.T) {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(root, "policy", "gate-logdir-probe-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { os.RemoveAll(logDir) })

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		pwsh, err := exec.LookPath("pwsh")
		if err != nil {
			t.Skipf("pwsh is not on the PATH (%v); scripts/release_gate.ps1 needs it", err)
		}
		cmd = exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", filepath.Join(root, "scripts", "release_gate.ps1"),
			"-Go", "go-the-refusal-never-runs", "-Quick", "-LogDir", logDir)
	} else {
		bash, err := exec.LookPath("bash")
		if err != nil {
			t.Skipf("bash is not on the PATH (%v); scripts/release_gate.sh needs it", err)
		}
		cmd = exec.Command(bash, filepath.Join(root, "scripts", "release_gate.sh"),
			"--go", "go-the-refusal-never-runs", "--quick", "--log-dir", logDir)
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("the gate with a log directory inside the repository ended with %v, want exit status 2:\n%s", err, out)
	}
	if !strings.Contains(string(out), "inside the repository") {
		t.Errorf("the refusal does not say why:\n%s", out)
	}
	if _, err := os.Stat(logDir); !os.IsNotExist(err) {
		t.Errorf("the gate created %s before refusing it", logDir)
	}
}

// TestFullGateRunsGovulncheck: a vulnerability the code can reach blocks a
// release, so a full gate runs govulncheck without being asked. Only a quick
// run skips it, and only when --vuln / -Vuln does not ask for it anyway. A
// gate where the step hides behind an opt-in switch passes every release it
// was meant to stop.
func TestFullGateRunsGovulncheck(t *testing.T) {
	for _, gate := range []struct{ script, guard string }{
		{"scripts/release_gate.sh", `if [ "$QUICK" -eq 1 ] && [ "$VULN" -eq 0 ]; then`},
		{"scripts/release_gate.ps1", `if ($Quick -and -not $Vuln) {`},
	} {
		lines := gateScriptLines(t, gate.script)
		guarded, runs := false, false
		for _, line := range lines {
			guarded = guarded || strings.Contains(line, gate.guard)
			runs = runs || strings.Contains(line, "golang.org/x/vuln/cmd/govulncheck")
		}
		if !runs {
			t.Errorf("%s no longer runs govulncheck", gate.script)
		}
		if !guarded {
			t.Errorf("%s does not skip govulncheck with exactly %q, so a full gate may not run it; update this test if the step moved", gate.script, gate.guard)
		}
	}
}

// TestFullGateFailsWhenTheRaceDetectorCannotRun: the race detector is the only
// step that needs a C compiler, and a host without one used to record the step
// as skipped -- which does not fail the gate, so the run ended in "Release gate
// passed" over no race coverage at all. A full gate fails instead. --quick and
// -Quick are the one place a skip is the agreed answer, and they record one
// without consulting gcc, so the fix must not take that away either
// (M26-TEST-004).
func TestFullGateFailsWhenTheRaceDetectorCannotRun(t *testing.T) {
	for _, gate := range []struct{ script, quickSkip, fails string }{
		{"scripts/release_gate.sh", `"race detector" SKIP)  SKIP: --quick`, "return 1"},
		{"scripts/release_gate.ps1", `Step = "race detector"; Status = "SKIP"`, "throw"},
	} {
		quick, checked := false, false
		for n, line := range gateScriptLines(t, gate.script) {
			if strings.Contains(line, gate.quickSkip) {
				quick = true
			}
			if !strings.Contains(line, "gcc") || !strings.Contains(line, "cgo") {
				continue
			}
			checked = true
			if strings.Contains(line, "SKIP") {
				t.Errorf("%s:%d records a skip when gcc is missing, so a full gate reports success having never run the race detector: %s", gate.script, n+1, strings.TrimSpace(line))
			}
			if !strings.Contains(line, gate.fails) {
				t.Errorf("%s:%d notices that gcc is missing but does not %s, so the step does not fail: %s", gate.script, n+1, gate.fails, strings.TrimSpace(line))
			}
		}
		if !checked {
			t.Errorf("%s no longer decides what to do when gcc is missing; the race step needs cgo, so something must. Update this test if the check moved off one line", gate.script)
		}
		if !quick {
			t.Errorf("%s does not record the race detector as skipped with %q, so a quick run may now fail where a skip is the agreed answer", gate.script, gate.quickSkip)
		}
	}
}

// goModFloors are the lowest versions go.mod may name. Each was raised to clear
// vulnerabilities govulncheck found reachable (or, for x/crypto, required) on
// the version before it, so going back under one reintroduces them.
var goModFloors = []struct{ directive, version string }{
	{"go", "1.26.6"},                  // 18 reachable standard-library issues in 1.26.2
	{"golang.org/x/crypto", "0.56.0"}, // ssh denial of service fixed in v0.56.0
}

// TestGoModStaysAboveItsVulnerabilityFloors: moving the toolchain or a module
// back is a one-line go.mod edit that no other test notices.
func TestGoModStaysAboveItsVulnerabilityFloors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]string{}
	for line := range strings.SplitSeq(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(fields) >= 2 {
			named[fields[0]] = strings.TrimPrefix(fields[1], "v")
		}
	}
	for _, floor := range goModFloors {
		got, ok := named[floor.directive]
		if !ok {
			t.Errorf("go.mod no longer names %s; update goModFloors if it was dropped on purpose", floor.directive)
			continue
		}
		if versionLess(got, floor.version) {
			t.Errorf("go.mod names %s %s, below the floor %s that cleared its known vulnerabilities", floor.directive, got, floor.version)
		}
	}
}

// versionLess compares dotted numeric versions such as 1.26.6 and 0.56.0; a
// pre-release or build suffix is ignored, which is conservative here.
func versionLess(a, b string) bool {
	if i := strings.IndexAny(a, "-+"); i >= 0 {
		a = a[:i]
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// TestGateGofmtStepHonoursGofmtsExitStatus: both twins used to decide the gofmt
// step on gofmt -l's STDOUT alone. gofmt reports a file it cannot PARSE on stderr,
// exits non-zero and prints nothing on stdout, so a Go file with a syntax error
// made the step report PASS -- and three committed files are compiled by no other
// step than cross-compile, which --quick skips, so for them this was the only
// check there was (M26-TEST-010).
//
// The bash twin also wrote its result with `echo ... >"$log"`, which truncated the
// step log after step() had already appended gofmt's stderr to it, erasing the one
// record of what gofmt objected to. So the guard is for both: the status is read,
// and the log is appended to rather than replaced.
func TestGateGofmtStepHonoursGofmtsExitStatus(t *testing.T) {
	for _, tc := range []struct {
		script string
		status string
	}{
		{"scripts/release_gate.sh", "status"},
		{"scripts/release_gate.ps1", "LASTEXITCODE"},
	} {
		step, from := gateGofmtStep(t, tc.script)
		if !strings.Contains(step, tc.status) {
			t.Errorf("%s: the gofmt step (from line %d) never reads %s, so a file gofmt "+
				"cannot parse passes the step: it prints nothing on stdout and says so only "+
				"in its exit status", tc.script, from, tc.status)
		}
		if strings.Contains(tc.script, ".sh") && gateTruncatesLog.MatchString(gateStripComments(step)) {
			t.Errorf("%s: the gofmt step (from line %d) truncates its log with a single >, "+
				"which erases the stderr step() has already written there; append with >>", tc.script, from)
		}
	}
}

// TestGateLFCopyKeepsAStrayCarriageReturn: the bash twin built its LF copies with
// `tr -d` over every CR, not only the CR of a CRLF pair, so a blob git stores with
// CR CR LF came out clean -- the shape M26-TEST-001 found in lexer.go. The
// PowerShell twin replaces only CRLF and flagged the same bytes, so the two twins
// disagreed about one tree (M26-TEST-010).
func TestGateLFCopyKeepsAStrayCarriageReturn(t *testing.T) {
	step, from := gateGofmtStep(t, "scripts/release_gate.sh")
	// A raw string: in a double-quoted Go literal \\r is one carriage return
	// byte, and the needle then matches nothing at all. The first version of this
	// guard was written that way and passed on the pre-fix script.
	if strings.Contains(gateStripComments(step), `tr -d '\r'`) {
		t.Errorf("scripts/release_gate.sh: the gofmt step (from line %d) strips CRs with "+
			"tr -d, which deletes every CR and not only the CR of a CRLF pair, so a file "+
			"stored with CR CR LF reads as clean here while the PowerShell twin flags it", from)
	}
	ps, psFrom := gateGofmtStep(t, "scripts/release_gate.ps1")
	if !strings.Contains(ps, `Replace("`+"`"+`r`+"`"+`n", "`+"`"+`n")`) {
		t.Errorf("scripts/release_gate.ps1: the gofmt step (from line %d) no longer "+
			"replaces CRLF specifically; replacing every CR would pass a blob stored with "+
			"CR CR LF", psFrom)
	}
}

// TestGofmtReportsAnUnparseableFileOnlyThroughItsExitStatus pins the fact the step
// above now depends on. If a future gofmt ever names an unparseable file on stdout,
// the reasoning in that step is no longer the reason it is written that way, and
// this test is where that shows up.
func TestGofmtReportsAnUnparseableFileOnlyThroughItsExitStatus(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte("package p\nfunc (\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	cmd := exec.Command(gofmtPath(t), "-l", dir)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("gofmt -l exited 0 on a file it cannot parse")
	}
	if got := strings.TrimSpace(stdout.String()); got != "" {
		t.Errorf("gofmt -l named the unparseable file on stdout (%q); the gate step's "+
			"exit-status check is written because it does not", got)
	}
	if !strings.Contains(stderr.String(), "bad.go") {
		t.Errorf("gofmt -l did not name the unparseable file on stderr either: %q", stderr.String())
	}
}

// TestGofmtFlagsAFileWithAStrayCarriageReturn pins the other half: keeping the CR
// of a CRLF pair is enough for gofmt to catch a blob stored with CR CR LF, which
// is why the copy step strips one CR rather than all of them.
func TestGofmtFlagsAFileWithAStrayCarriageReturn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stray.go"), []byte("package p\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(gofmtPath(t), "-l", dir).Output()
	if err != nil {
		t.Fatalf("gofmt -l failed on a parseable file: %v", err)
	}
	if !strings.Contains(string(out), "stray.go") {
		t.Error("gofmt -l did not flag a file carrying a stray CR, so leaving that CR in " +
			"the LF copy would no longer catch a blob stored with CR CR LF")
	}
}

// gateTruncatesLog matches a single > redirect to the step log and not the >> that
// appends to it, which a plain substring test cannot tell apart: >>"$log" contains
// >"$log". The step log is written to by step() before the step runs, so a single
// > throws away what is already there.
var gateTruncatesLog = regexp.MustCompile(`(^|[^>])>"\$log"`)

// gateStripComments drops whole-line comments from a shell or PowerShell fragment.
// Without it a guard reads the comment that explains why the code no longer does
// the thing, and reports the explanation as the defect -- which is what the first
// version of the two guards above did.
func gateStripComments(fragment string) string {
	var kept []string
	for _, line := range strings.Split(fragment, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// gateGofmtStep returns the gofmt step of one twin as one string, with the line it
// starts on, so a guard reads the step rather than the whole script.
func gateGofmtStep(t *testing.T, rel string) (string, int) {
	t.Helper()
	lines := gateScriptLines(t, rel)
	start, end := -1, len(lines)
	for n, line := range lines {
		if start < 0 {
			if strings.HasPrefix(line, "gofmt_lf()") || strings.Contains(line, `Invoke-Step "gofmt`) {
				start = n
			}
			continue
		}
		if line == "}" {
			end = n + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s: found no gofmt step; this guard no longer knows where to look", rel)
	}
	return strings.Join(lines[start:end], "\n"), start + 1
}

// gofmtPath is the gofmt of the toolchain running the test, which is the one the
// gate uses: it reads GOROOT from the same go command rather than trusting PATH.
func gofmtPath(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skipf("no go command to ask for GOROOT (%v)", err)
	}
	path := filepath.Join(strings.TrimSpace(string(out)), "bin", "gofmt")
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no gofmt at %s (%v)", path, err)
	}
	return path
}

// gateCgoWant is the CGO_ENABLED value a gate command line must set.
func gateCgoWant(line string) string {
	if strings.Contains(line, "-race") {
		return "1"
	}
	return "0"
}

func gateScriptLines(t *testing.T, rel string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}
