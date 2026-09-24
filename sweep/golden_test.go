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
		// The same honest error, as Windows and as Linux print it.
		{
			`ERROR:bin_strings: open README.md: The system cannot find the file specified. at examples\binary\b.mut:5:24 context=builtin.strings`,
			"ERROR:bin_strings: open README.md: no such file or directory at examples/binary/b.mut:5:24 context=builtin.strings\n",
		},
		{
			"ERROR:bin_strings: open README.md: no such file or directory at examples/binary/b.mut:5:24 context=builtin.strings",
			"ERROR:bin_strings: open README.md: no such file or directory at examples/binary/b.mut:5:24 context=builtin.strings\n",
		},
		{
			"dial tcp 127.0.0.1:9: connectex: No connection could be made because the target machine actively refused it.",
			"dial tcp 127.0.0.1:9: connect: connection refused\n",
		},
		{`at C:\Temp\mutant-sweep-123\examples\x.mut:1:2`, "at <SCRATCH>/examples/x.mut:1:2\n"},
		// Paths an example prints as data are the example's output, not the host's.
		{`entry: C:\Users\alice\Startup\evil.lnk`, "entry: C:\\Users\\alice\\Startup\\evil.lnk\n"},
		{`key not found: HKCU\Software\Run at examples\r.mut:10:23`, "key not found: HKCU\\Software\\Run at examples/r.mut:10:23\n"},
		{`copied C:\Windows\Temp\at x.mut to Q:\x.mut:1`, "copied C:\\Windows\\Temp\\at x.mut to Q:\\x.mut:1\n"},
	}
	for _, c := range cases {
		got := NormalizeOutput(c.in, root)
		if got != c.want {
			t.Errorf("NormalizeOutput(%q) = %q, want %q", c.in, got, c.want)
		}
		// A golden is stored normalized and normalized again when read, so
		// normalizing twice must change nothing.
		if again := NormalizeOutput(got, ""); again != got {
			t.Errorf("NormalizeOutput is not idempotent on %q: %q", got, again)
		}
	}
}

func TestGoldenPath(t *testing.T) {
	if got := GoldenPath("examples/basics/hello.mut"); got != "examples/basics/hello.golden" {
		t.Errorf("GoldenPath = %q", got)
	}
}
