package sweep

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A golden file is a claim about what a program prints. One with no program
// beside it claims something about nothing, and one beside a program a sweep
// never runs to completion is never checked -- both are the stale-list failure
// this package exists to prevent, so both fail here without running anything.
func TestEveryGoldenBelongsToARunnableProgram(t *testing.T) {
	checked := 0
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "node_modules" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, GoldenExtension) {
			return nil
		}
		checked++
		program := strings.TrimSuffix(path, GoldenExtension) + ".mut"
		source, err := os.ReadFile(program)
		if err != nil {
			t.Errorf("%s has no program beside it (%s)", filepath.ToSlash(path), filepath.ToSlash(program))
			return nil
		}
		marker, err := ParseMarker(string(source))
		if err != nil {
			t.Errorf("%s: %v", filepath.ToSlash(program), err)
			return nil
		}
		if marker.Mode != ModeRun {
			t.Errorf("%s records output for a program marked %s, which a sweep never runs to completion",
				filepath.ToSlash(path), marker.Mode)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d golden files", checked)
}

func TestNormalizeOutput(t *testing.T) {
	root := `C:\Temp\mutant-sweep-123`
	cases := []struct{ in, want string }{
		{"a\r\nb\r\n", "a\nb\n"},
		{"a  \nb\t\n\n\n", "a\nb\n"},
		{"wrote " + root + `\examples\out.json` + "\n", "wrote <SCRATCH>\\examples\\out.json\n"},
		{"wrote C:/Temp/mutant-sweep-123/examples/out.json\n", "wrote <SCRATCH>/examples/out.json\n"},
		{"", "\n"},
	}
	for _, c := range cases {
		if got := NormalizeOutput(c.in, root); got != c.want {
			t.Errorf("NormalizeOutput(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGoldenPath(t *testing.T) {
	if got := GoldenPath("examples/basics/hello.mut"); got != "examples/basics/hello.golden" {
		t.Errorf("GoldenPath = %q", got)
	}
}
