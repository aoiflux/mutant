package sweep

import (
	"path/filepath"
	"strings"
)

// GoldenExtension names the file beside an example that records what the
// example prints. A sweep run with --golden compares against it, which is what
// turns "the examples ran" into "the examples printed what their documentation
// says they print".
const GoldenExtension = ".golden"

// ScratchPlaceholder stands in for the throwaway directory a sweep runs in, so
// an example that prints a path it wrote to still has one recorded output.
const ScratchPlaceholder = "<SCRATCH>"

// GoldenPath is the golden file for a program: the same name with the source
// extension replaced.
func GoldenPath(program string) string {
	return strings.TrimSuffix(program, filepath.Ext(program)) + GoldenExtension
}

// NormalizeOutput makes one run's stdout comparable with another host's: LF
// line endings, no trailing whitespace on any line or at the end, and the
// scratch directory -- in either slash direction -- replaced by
// ScratchPlaceholder. Nothing else is rewritten; an example whose output
// carries a timestamp is not reproducible, and the sweep measures that rather
// than papering over it.
func NormalizeOutput(output, scratchRoot string) string {
	output = strings.ReplaceAll(output, "\r\n", "\n")
	if scratchRoot != "" {
		for _, form := range []string{scratchRoot, filepath.ToSlash(scratchRoot), strings.ReplaceAll(scratchRoot, `\`, `\\`)} {
			output = strings.ReplaceAll(output, form, ScratchPlaceholder)
		}
	}
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}
