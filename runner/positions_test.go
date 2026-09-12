package runner

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/generator"
	"mutant/object"
)

// A .mu produced by the ordinary compile path carries source positions all the
// way through encode, compress, encrypt and back.
//
// This is the whole L-3 pipeline in one test. Every stage in between has its own
// coverage; what this catches is a stage that quietly drops a field it does not
// know about -- which is how the container has broken before.
func TestGeneratedProgramCarriesPositionsThroughTheContainer(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "prog.mut")
	source := "let half = fn(x) {\n\treturn x / 2;\n};\nputln(half(10));\n"
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	const password = "correct horse battery"
	dst := filepath.Join(dir, "prog")
	if err, _, _ := generator.Generate(src, dst, "", "", false, password, 0, 0, nil, nil); err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := os.ReadFile(dst + ".mu")
	if err != nil {
		t.Fatal(err)
	}

	bytecode, err := decode(data, password)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if bytecode.SourceFile != src {
		t.Errorf("SourceFile = %q, want %q", bytecode.SourceFile, src)
	}
	if bytecode.LineTable.Empty() {
		t.Error("the main stream lost its line table in the container")
	}

	var found bool
	for _, constant := range bytecode.Constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		found = true
		if fn.Name != "half" {
			t.Errorf("function name = %q, want %q", fn.Name, "half")
		}
		if fn.LineTable.Empty() {
			t.Errorf("function %q lost its line table in the container", fn.Name)
		}
	}
	if !found {
		t.Fatal("no compiled function survived decoding")
	}
}

// The default compile mutates -- `mutant prog.mut` runs at polymorphic level 5 --
// so the positions that reach the container are ones the engine remapped, not
// the ones the compiler emitted. They still have to point at the right lines.
func TestPositionsSurviveTheDefaultMutationLevel(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "prog.mut")
	source := "let boom = fn() {\n\treturn 1 / 0;\n};\nboom();\n"
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	const password = "correct horse battery"
	dst := filepath.Join(dir, "prog")
	if err, _, _ := generator.Generate(src, dst, "", "", false, password, 5, 99, nil, nil); err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := os.ReadFile(dst + ".mu")
	if err != nil {
		t.Fatal(err)
	}

	bytecode, err := decode(data, password)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bytecode.LineTable.Empty() {
		t.Fatal("a mutated program reached the container with no line table")
	}

	for _, constant := range bytecode.Constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok || fn.Name != "boom" {
			continue
		}

		// The body is line 2. The function's own stream is short, so every
		// position it reports must be inside the function.
		for ip := 0; ip < len(fn.Instructions); ip++ {
			line, _, ok := fn.LineTable.At(ip)
			if !ok {
				continue
			}
			if line != 2 {
				t.Errorf("ip %d in boom resolves to line %d, want 2", ip, line)
			}
		}
		return
	}
	t.Fatal("the mutated program has no function named boom")
}
