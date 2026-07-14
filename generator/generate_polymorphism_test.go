package generator

import (
	"mutant/global"
	"mutant/runner"
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePolymorphismSeedUsesProvidedSeed(t *testing.T) {
	got := resolvePolymorphismSeed(12345)
	if got != 12345 {
		t.Fatalf("expected provided seed 12345, got %d", got)
	}
}

func TestResolvePolymorphismSeedUsesTimestampWhenMissing(t *testing.T) {
	got := resolvePolymorphismSeed(0)
	if got == 0 {
		t.Fatalf("expected non-zero timestamp seed when seed is omitted")
	}
}

func TestGenerateCompiledMacroProgramRuns(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "macro_example.mut")
	dst := filepath.Join(tempDir, "macro_example")
	password := "macro-test-pass"

	program := `let emit_literal = macro() { quote(7); }; emit_literal();`
	if err := os.WriteFile(src, []byte(program), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err, errType, parseErrors := Generate(src, dst, "", "", false, password, 0, 0, nil); err != nil {
		t.Fatalf("generate failed: type=%s err=%v parseErrors=%v", errType, err, parseErrors)
	}

	compiledPath := dst + global.MutantByteCodeCompiledFileExtension
	if err, errType := runner.Run(compiledPath, password, false, false); err != nil {
		t.Fatalf("compiled macro run failed: type=%s err=%v", errType, err)
	}
}
