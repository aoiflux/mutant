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
func TestShellScriptsAreCommittedExecutable(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "--stage", "--", "scripts")
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
		t.Fatal("git lists no shell scripts under scripts/; the pattern no longer matches them")
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
