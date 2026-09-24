package sweep

import (
	"path/filepath"
	"regexp"
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

// hostErrorTexts maps the words Windows gives a system error to the words
// Linux and macOS give the same error. Go reports a syscall error in the
// host's language, so an example that honestly prints "no such file" prints
// different bytes on each OS; recording one spelling is what lets a golden
// recorded on one host check a run on another. Only errors a golden records
// are listed.
var hostErrorTexts = []struct{ windows, posix string }{
	{"The system cannot find the file specified.", "no such file or directory"},
	{"The system cannot find the path specified.", "no such file or directory"},
	{"connectex: No connection could be made because the target machine actively refused it.", "connect: connection refused"},
}

// sourcePosition matches the position a runtime error names, as in
// "at examples\basics\x.mut:3:7", whose separators are the host's.
var sourcePosition = regexp.MustCompile(`\bat ([^\s:]+\.mut):(\d+):(\d+)`)

// NormalizeOutput makes one run's stdout comparable with another host's: LF
// line endings, no trailing whitespace on any line or at the end, and the
// scratch directory -- in either slash direction -- replaced by
// ScratchPlaceholder. Beyond that it rewrites only what differs by host and not
// by program: the separators in the source position a runtime error names, and
// the system-error texts Windows words differently (hostErrorTexts). A path an
// example prints as data is left alone. An example whose output carries a
// timestamp is still not reproducible, and the sweep measures that rather than
// papering over it.
func NormalizeOutput(output, scratchRoot string) string {
	output = strings.ReplaceAll(output, "\r\n", "\n")
	if scratchRoot != "" {
		// The slash form is spelled out rather than taken from filepath.ToSlash,
		// which does nothing on a host whose separator is already a slash: the
		// rewrite has to be the same wherever the sweep, or its test, runs.
		for _, form := range []string{scratchRoot, strings.ReplaceAll(scratchRoot, `\`, "/"), strings.ReplaceAll(scratchRoot, `\`, `\\`)} {
			output = strings.ReplaceAll(output, form, ScratchPlaceholder)
		}
	}
	output = sourcePosition.ReplaceAllStringFunc(output, func(position string) string {
		return strings.ReplaceAll(position, `\`, "/")
	})
	for _, text := range hostErrorTexts {
		output = strings.ReplaceAll(output, text.windows, text.posix)
	}
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}
