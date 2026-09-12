package ast

// Shift moves both endpoints of r down by lines lines and forward by offset
// bytes. An endpoint with no recorded position is left alone.
func (r Range) Shift(lines, offset int) Range {
	r.Start = r.Start.Shift(lines, offset)
	r.End = r.End.Shift(lines, offset)
	return r
}

// ShiftPositions rebases every position this program records onto a source
// blob in which the program's own text begins lines lines and offset bytes in.
//
// Linking compiles several modules as one concatenated source, so positions
// captured against an individual file are wrong the moment that file is not
// the first one in the blob. Rebasing them here, before compilation, means the
// compiler, the macro expander and the VM all keep reading a single coordinate
// system and none of them needs to learn what a module is.
//
// All three side-tables move together. Skipping any one of them produces the
// worst kind of wrong: NodePositions alone would leave the formatter pinning
// comments to the wrong statements, and leaving MacroExpansions behind would
// make the macro table -- the thing a traceback consults precisely when the
// authored line is not where the bug is -- point into another file.
//
// Shifting by zero is a no-op, so the entry module can be run through this
// unconditionally rather than special-cased.
func (p *Program) ShiftPositions(lines, offset int) {
	if p == nil || (lines == 0 && offset == 0) {
		return
	}

	for node, rng := range p.NodePositions {
		p.NodePositions[node] = rng.Shift(lines, offset)
	}

	for i := range p.Comments {
		p.Comments[i].Start = p.Comments[i].Start.Shift(lines, offset)
		p.Comments[i].End = p.Comments[i].End.Shift(lines, offset)
	}

	for node, origin := range p.MacroExpansions {
		p.MacroExpansions[node] = MacroOrigin{
			Call:       origin.Call.Shift(lines, offset),
			Definition: origin.Definition.Shift(lines, offset),
		}
	}
}
