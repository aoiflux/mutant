package builtin

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestNTAndLMHash(t *testing.T) {
	// Canonical NTLM test vectors.
	if got := strResult(t, NTHash(stringObj("password"))); got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatalf("nt_hash(password) = %q", got)
	}
	if got := strResult(t, LMHash(stringObj("password"))); got != "e52cac67419a9a224a3b108f3fa6cb6d" {
		t.Fatalf("lm_hash(password) = %q", got)
	}
	// LM is case-insensitive.
	if strResult(t, LMHash(stringObj("PASSWORD"))) != strResult(t, LMHash(stringObj("password"))) {
		t.Fatal("lm_hash should be case-insensitive")
	}
	// Empty-password LM hash is the well-known blank value.
	if got := strResult(t, LMHash(stringObj(""))); got != "aad3b435b51404eeaad3b435b51404ee" {
		t.Fatalf("lm_hash(empty) = %q", got)
	}
	// arg errors.
	if _, ok := NTHash().(*object.Error); !ok {
		t.Fatal("nt_hash with no args should error")
	}
}

func TestComputeImphash(t *testing.T) {
	libs := []imphashLib{
		{dll: "KERNEL32.dll", funcs: []imphashFunc{{name: "CreateFileA"}, {ordinal: 12, byOrdinal: true}}},
		{dll: "WS2_32.DLL", funcs: []imphashFunc{{name: "socket"}}},
	}
	// dll/ocx/sys extensions stripped, everything lowercased, ordinals -> ord<N>.
	expected := md5.Sum([]byte("kernel32.createfilea,kernel32.ord12,ws2_32.socket"))
	if got := computeImphash(libs); got != hex.EncodeToString(expected[:]) {
		t.Fatalf("computeImphash = %q, want %q", got, hex.EncodeToString(expected[:]))
	}
	// empty -> md5 of empty string.
	if got := computeImphash(nil); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("computeImphash(nil) = %q", got)
	}
}

func TestImphashOnWindowsPE(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module peprobe\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	out := filepath.Join(dir, "probe.exe")
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("windows PE build failed (skipping): %v\n%s", err, combined)
	}

	payload, errObj := unwrapPair(t, Imphash(stringObj(out)))
	if errObj != nil {
		t.Fatalf("imphash error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	imphash := h.Pairs[(&object.String{Value: "imphash"}).HashKey()].Value.(*object.String).Value
	if len(imphash) != 32 {
		t.Fatalf("imphash should be a 32-char md5, got %q", imphash)
	}
	if h.Pairs[(&object.String{Value: "import_count"}).HashKey()].Value.(*object.Integer).Value < 1 {
		t.Fatal("a Go Windows PE should have imports")
	}
	// Deterministic: same file -> same imphash.
	payload2, _ := unwrapPair(t, Imphash(stringObj(out)))
	if payload2.(*object.Hash).Pairs[(&object.String{Value: "imphash"}).HashKey()].Value.(*object.String).Value != imphash {
		t.Fatal("imphash should be stable for the same file")
	}

	// A non-PE errors.
	if _, errObj := unwrapPair(t, Imphash(stringObj(filepath.Join(dir, "main.go")))); errObj == nil {
		t.Fatal("imphash of a non-PE file should error")
	}
}
