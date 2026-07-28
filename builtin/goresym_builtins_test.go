package builtin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mutant/object"
)

// buildGoProbe compiles a tiny Go program to a temp binary so the go_* builtins
// have a reliable, current-toolchain target. Skips if the go toolchain is absent.
func buildGoProbe(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available; skipping GoReSym integration test")
	}
	dir := t.TempDir()
	src := "package main\n\nimport \"fmt\"\n\nfunc probeMarker() { fmt.Println(\"probe\") }\n\nfunc main() { probeMarker() }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatalf("write probe source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gsymprobe\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatalf("write probe go.mod: %v", err)
	}
	out := filepath.Join(dir, "probe.exe")
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build of probe failed (skipping): %v\n%s", err, combined)
	}
	return out
}

func TestGoReSymOnGoBinary(t *testing.T) {
	probe := buildGoProbe(t)

	// go_buildinfo
	biPayload, errObj := unwrapPair(t, GoBuildInfo(stringObj(probe)))
	if errObj != nil {
		t.Fatalf("go_buildinfo error: %s", errObj.Inspect())
	}
	bi := biPayload.(*object.Hash)
	gv := bi.Pairs[(&object.String{Value: "go_version"}).HashKey()].Value.(*object.String).Value
	if !strings.HasPrefix(gv, "go1.") {
		t.Fatalf("unexpected go_version: %q", gv)
	}
	if _, ok := bi.Pairs[(&object.String{Value: "settings"}).HashKey()].Value.(*object.Hash); !ok {
		t.Fatal("go_buildinfo settings should be a HASH")
	}

	// go_build_id — may be empty on some builds; tolerate error, require STRING on success.
	idPayload, errObj := unwrapPair(t, GoBuildID(stringObj(probe)))
	if errObj == nil {
		if _, ok := idPayload.(*object.String); !ok {
			t.Fatalf("go_build_id payload type: %T", idPayload)
		}
	} else {
		t.Logf("go_build_id returned error (tolerated): %s", errObj.Message)
	}

	// go_symbols — the flagship: recover functions from the pclntab.
	symPayload, errObj := unwrapPair(t, GoSymbols(stringObj(probe)))
	if errObj != nil {
		t.Fatalf("go_symbols error: %s", errObj.Inspect())
	}
	sym := symPayload.(*object.Hash)
	count := sym.Pairs[(&object.String{Value: "function_count"}).HashKey()].Value.(*object.Integer).Value
	if count < 100 {
		t.Fatalf("expected many recovered functions, got %d", count)
	}
	funcs := sym.Pairs[(&object.String{Value: "functions"}).HashKey()].Value.(*object.Array)

	// The real function names must be recovered (the whole point on a stripped binary).
	foundMain := false
	for _, el := range funcs.Elements {
		h := el.(*object.Hash)
		if h.Pairs[(&object.String{Value: "name"}).HashKey()].Value.(*object.String).Value == "main.main" {
			foundMain = true
			break
		}
	}
	if !foundMain {
		t.Fatal("go_symbols did not recover main.main")
	}

	// "user" mode is a subset of "all".
	userPayload, errObj := unwrapPair(t, GoSymbols(stringObj(probe), stringObj("user")))
	if errObj != nil {
		t.Fatalf("go_symbols user error: %s", errObj.Inspect())
	}
	userFuncs := userPayload.(*object.Hash).Pairs[(&object.String{Value: "functions"}).HashKey()].Value.(*object.Array)
	if len(userFuncs.Elements) == 0 || len(userFuncs.Elements) > len(funcs.Elements) {
		t.Fatalf("user-mode functions invalid: %d of %d", len(userFuncs.Elements), len(funcs.Elements))
	}
	t.Logf("recovered %d functions (%d user)", count, len(userFuncs.Elements))
}

func TestGoReSymErrorsOnNonGoFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "notgo.txt")
	if err := os.WriteFile(tmp, []byte("just some text, not a binary"), 0644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, errObj := unwrapPair(t, GoBuildInfo(stringObj(tmp))); errObj == nil {
		t.Fatal("go_buildinfo should error on a non-Go file")
	}
	if _, errObj := unwrapPair(t, GoSymbols(stringObj(tmp))); errObj == nil {
		t.Fatal("go_symbols should error on a non-Go file")
	}
	if _, errObj := unwrapPair(t, GoSymbols(stringObj(tmp), stringObj("bogus"))); errObj == nil {
		t.Fatal("go_symbols should reject an invalid mode")
	}
}
