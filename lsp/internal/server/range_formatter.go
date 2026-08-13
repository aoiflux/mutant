package server

import (
	"strings"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// maxDiffLines caps the LCS table. Beyond this the quadratic table costs more
// memory than the feature is worth, so the whole changed region becomes a
// single hunk instead. Correctness is unaffected — only edit granularity.
const maxDiffLines = 2000

// lineHunk is a contiguous run of original lines to be replaced.
// startLine is inclusive and endLine exclusive, both 0-based.
type lineHunk struct {
	startLine int
	endLine   int
	newLines  []string
}

// rangeFormattingEdits formats the whole document and returns only the edits
// that fall entirely inside the requested line span.
//
// Mutant's formatter is a whole-program AST printer — a fragment cannot be
// parsed and printed on its own — so range formatting is expressed as
// "format everything, then keep the changes the user asked for". A hunk that
// straddles the selection boundary is dropped rather than partially applied,
// so range formatting never edits a line outside the selection.
func rangeFormattingEdits(original, formatted string, selection lsp.Range) []lsp.TextEdit {
	if original == formatted {
		return nil
	}

	originalLines := splitLines(original)
	formattedLines := splitLines(formatted)

	edits := make([]lsp.TextEdit, 0, 4)
	for _, hunk := range diffLines(originalLines, formattedLines) {
		if !hunkWithinSelection(hunk, selection) {
			continue
		}
		edits = append(edits, lsp.TextEdit{
			Range:   hunkRange(hunk, originalLines),
			NewText: strings.Join(hunk.newLines, ""),
		})
	}

	if len(edits) == 0 {
		return nil
	}
	return edits
}

// hunkWithinSelection reports whether every line the hunk rewrites lies in
// the requested span. A pure insertion (startLine == endLine) is accepted
// when its anchor line is inside the span.
func hunkWithinSelection(hunk lineHunk, selection lsp.Range) bool {
	start := int(selection.Start.Line)
	end := int(selection.End.Line)

	if hunk.startLine == hunk.endLine {
		return hunk.startLine >= start && hunk.startLine <= end+1
	}
	return hunk.startLine >= start && hunk.endLine-1 <= end
}

func hunkRange(hunk lineHunk, originalLines []string) lsp.Range {
	return lsp.Range{
		Start: linePosition(hunk.startLine, originalLines),
		End:   linePosition(hunk.endLine, originalLines),
	}
}

// linePosition maps a line index to the position at its first character.
// An index one past the end maps to the very end of the document, which is
// how a hunk that runs to EOF is expressed.
func linePosition(line int, lines []string) lsp.Position {
	if line < len(lines) {
		return lsp.Position{Line: lsp.UInteger(line), Character: 0}
	}
	if len(lines) == 0 {
		return lsp.Position{Line: 0, Character: 0}
	}

	last := lines[len(lines)-1]
	if strings.HasSuffix(last, "\n") {
		return lsp.Position{Line: lsp.UInteger(len(lines)), Character: 0}
	}
	return lsp.Position{Line: lsp.UInteger(len(lines) - 1), Character: lsp.UInteger(len([]rune(last)))}
}

// splitLines splits text into lines that keep their trailing newline, so
// concatenating the result reproduces the input exactly. Line endings are
// normalised first because the formatter always emits "\n".
func splitLines(text string) []string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	if normalized == "" {
		return nil
	}

	lines := make([]string, 0, strings.Count(normalized, "\n")+1)
	for {
		idx := strings.IndexByte(normalized, '\n')
		if idx < 0 {
			lines = append(lines, normalized)
			return lines
		}
		lines = append(lines, normalized[:idx+1])
		normalized = normalized[idx+1:]
		if normalized == "" {
			return lines
		}
	}
}

// diffLines produces the hunks that turn a into b.
//
// Common prefix and suffix are trimmed first, which reduces the usual
// formatting change — a handful of reindented lines — to a tiny middle
// section before the quadratic LCS ever runs.
func diffLines(a, b []string) []lineHunk {
	prefix := commonPrefixLen(a, b)
	suffix := commonSuffixLen(a[prefix:], b[prefix:])

	midA := a[prefix : len(a)-suffix]
	midB := b[prefix : len(b)-suffix]

	if len(midA) == 0 && len(midB) == 0 {
		return nil
	}

	// Too large to diff precisely: replace the whole changed region at once.
	if len(midA) > maxDiffLines || len(midB) > maxDiffLines {
		return []lineHunk{{startLine: prefix, endLine: prefix + len(midA), newLines: midB}}
	}

	return lcsHunks(midA, midB, prefix)
}

// lcsHunks diffs two line slices via a longest-common-subsequence table and
// groups the differing regions into hunks. offset shifts the reported line
// numbers back into the original document's coordinates.
func lcsHunks(a, b []string, offset int) []lineHunk {
	n, m := len(a), len(b)

	table := make([][]int, n+1)
	for i := range table {
		table[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
				continue
			}
			if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}

	hunks := make([]lineHunk, 0, 4)
	var pending *lineHunk

	flush := func() {
		if pending != nil {
			hunks = append(hunks, *pending)
			pending = nil
		}
	}
	extend := func(startLine int, consumed int, added []string) {
		if pending == nil {
			pending = &lineHunk{startLine: startLine, endLine: startLine}
		}
		pending.endLine += consumed
		pending.newLines = append(pending.newLines, added...)
	}

	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			flush()
			i++
			j++
		case table[i+1][j] > table[i][j+1]:
			// Line a[i] is not in the LCS: delete it.
			extend(offset+i, 1, nil)
			i++
		case table[i][j+1] > table[i+1][j]:
			// Line b[j] is not in the LCS: insert it.
			extend(offset+i, 0, b[j:j+1])
			j++
		default:
			// Neither dropping a[i] nor adding b[j] improves the match, so
			// the two lines correspond: emit a standalone one-line
			// replacement. This is the common case when formatting only
			// respaces or reindents lines, and keeping such hunks separate
			// is what lets range formatting act on a single selected line
			// instead of one document-sized hunk.
			flush()
			hunks = append(hunks, lineHunk{
				startLine: offset + i,
				endLine:   offset + i + 1,
				newLines:  []string{b[j]},
			})
			i++
			j++
		}
	}
	for i < n {
		extend(offset+i, 1, nil)
		i++
	}
	if j < m {
		extend(offset+i, 0, b[j:])
	}
	flush()

	return hunks
}

func commonPrefixLen(a, b []string) int {
	limit := min(len(a), len(b))
	i := 0
	for i < limit && a[i] == b[i] {
		i++
	}
	return i
}

func commonSuffixLen(a, b []string) int {
	limit := min(len(a), len(b))
	i := 0
	for i < limit && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	return i
}
