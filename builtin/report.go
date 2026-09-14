package builtin

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"

	"mutant/object"
)

// --- reporting ---
//
// An investigation ends in a report, not a stdout dump. This file builds one as
// a value and renders it three ways.
//
// The report is a plain hash, so it can be encoded as JSON, diffed against
// yesterday's, or written by hand; the builders never mutate what they are
// given, they return a new document. Nothing here touches the filesystem.
//
// What makes reporting different from every other emitter in the tree is who
// opens the output. A STIX bundle is read by a machine; a report is read by a
// person, in a browser, on the workstation they are doing the examination from.
// And nearly every string in it came from the evidence -- a filename, a registry
// value, a URL out of a phishing mail -- which is to say it was written by the
// subject of the investigation. Rendered into markup without escaping, it is
// the attack's second stage.
//
// So the model holds values and nothing else. Text becomes markup in exactly
// one place per format, and each format is escaped for the thing that actually
// goes wrong in it:
//
//   - HTML is the security boundary. Every string is escaped, and the renderer
//     never turns evidence text into a link: a report that makes the attacker's
//     URL clickable is a report that can be clicked.
//   - Markdown is structural. A pipe or a newline inside a table cell silently
//     breaks the row, and a line-leading "#" in a paragraph becomes a heading,
//     so the report reads wrong and nothing says it did.
//   - CSV is formula injection. A cell that begins "=", "+", "-" or "@" is
//     executed by a spreadsheet when the file is opened.
//
// The second rule comes from F-1: a renderer that skips a block it does not
// understand produces a report that looks complete and is missing a finding.
// `report_render` validates the whole document first and refuses by section and
// block index rather than rendering the part it recognised.

// Block kinds. A hand-written report uses these names too, so they are the
// contract rather than an implementation detail.
const (
	reportBlockText  = "text"
	reportBlockList  = "list"
	reportBlockTable = "table"
)

const (
	reportDefaultLevel = 2
	reportMaxLevel     = 6
)

var reportNewOptions = []string{"subtitle", "examiner", "case_id", "generated"}

// ReportNew starts a report: report_new(title, opts?) -> (report, err).
func ReportNew(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	title, errObj := requireStringArg("report_new", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(title) == "" {
		return resultAndError(nil, newError("report_new: a report needs a title; it is the one line that says what was examined"))
	}
	opts, errObj := formatOptionsArg("report_new", args, 2, reportNewOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	values := map[string]object.Object{
		"title":    stringObj(title),
		"sections": &object.Array{Elements: []object.Object{}},
	}
	for _, key := range []string{"subtitle", "examiner", "case_id"} {
		text, errObj := opts.str(key, "")
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		if text != "" {
			values[key] = stringObj(text)
		}
	}

	// The one field that cannot be derived from the document is when it was
	// written, so it is an option rather than only a clock read. Pin it and two
	// renders of one investigation are the same bytes, which is what makes a
	// report diffable against the last one.
	stamp, errObj := opts.str("generated", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	generated := time.Now().UTC().Format(time.RFC3339)
	if stamp != "" {
		at, err := time.Parse(time.RFC3339, stamp)
		if err != nil {
			return resultAndError(nil, newError("report_new: option %q must be an RFC 3339 timestamp: %s", "generated", err.Error()))
		}
		generated = at.UTC().Format(time.RFC3339)
	}
	values["generated"] = stringObj(generated)

	return resultAndError(makeHashObject(values), nil)
}

var reportSectionOptions = []string{"level"}

// ReportSection opens a section: report_section(report, heading, opts?).
func ReportSection(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	report, errObj := requireHashArg("report_section", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	heading, errObj := requireStringArg("report_section", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg("report_section", args, 3, reportSectionOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	level, errObj := reportLevelOption(opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	sections, errObj := reportSections("report_section", report)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	section := makeHashObject(map[string]object.Object{
		"heading": stringObj(heading),
		"level":   intObj(int64(level)),
		"blocks":  &object.Array{Elements: []object.Object{}},
	})
	return resultAndError(reportWithSections(report, appendObject(sections, section)), nil)
}

// ReportText adds a paragraph: report_text(report, text).
func ReportText(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	report, errObj := requireHashArg("report_text", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	text, errObj := requireStringArg("report_text", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	block := makeHashObject(map[string]object.Object{
		"kind": stringObj(reportBlockText),
		"text": stringObj(text),
	})
	return reportAppend("report_text", report, block)
}

var reportListOptions = []string{"ordered"}

// ReportList adds a list: report_list(report, items, opts?).
func ReportList(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	report, errObj := requireHashArg("report_list", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	items, errObj := requireArrayArg("report_list", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg("report_list", args, 3, reportListOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ordered, errObj := opts.boolean("ordered", false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// Cells and list items are rendered from scalars the same way a CSV field
	// is, so a count that arrived as an INTEGER does not have to be converted
	// at the call site and a nested hash is refused where it was written rather
	// than appearing as a Go value in the middle of a sentence.
	elements := make([]object.Object, 0, len(items.Elements))
	for i, item := range items.Elements {
		text, errObj := csvFieldText("report_list", item, i, 0)
		if errObj != nil {
			return resultAndError(nil, newError("report_list: item %d must be a scalar, got %s", i, item.Type()))
		}
		elements = append(elements, stringObj(text))
	}

	block := makeHashObject(map[string]object.Object{
		"kind":    stringObj(reportBlockList),
		"items":   &object.Array{Elements: elements},
		"ordered": boolObj(ordered),
	})
	return reportAppend("report_list", report, block)
}

var reportTableOptions = []string{"columns", "caption", "header"}

// ReportTable adds a table: report_table(report, rows, opts?).
//
// Rows arrive in either of the shapes csv_stringify takes -- an array of arrays
// written positionally, or an array of hashes written against a column list --
// and go through the same normalization, so a table in a report and the same
// table written straight to CSV cannot disagree about what a cell contains.
func ReportTable(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	report, errObj := requireHashArg("report_table", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	rows, errObj := requireArrayArg("report_table", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg("report_table", args, 3, reportTableOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	columns, columnsGiven, errObj := opts.stringList("columns")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	caption, errObj := opts.str("caption", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if len(rows.Elements) == 0 && !columnsGiven {
		return resultAndError(nil, newError("report_table: a table with no rows and no columns says nothing; pass `columns` to record that the search found nothing, or write a sentence with report_text"))
	}

	records, hasHeader, errObj := csvRecords("report_table", rows, columns, columnsGiven)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	header, errObj := opts.boolean("header", hasHeader || columnsGiven)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// csvRecords prepends the header only for hash rows. Array rows keep their
	// own order and take the column names, if any were given, as a header.
	headings := columns
	if hasHeader {
		headings = records[0]
		records = records[1:]
	}
	if !header {
		headings = nil
	}

	values := map[string]object.Object{
		"kind":    stringObj(reportBlockTable),
		"columns": stringListObj(headings),
		"rows":    reportRowsObj(records),
	}
	if caption != "" {
		values["caption"] = stringObj(caption)
	}
	return reportAppend("report_table", report, makeHashObject(values))
}

var reportRenderOptions = []string{"fragment", "table", "delimiter", "formula_guard"}

// ReportRender renders a report: report_render(report, format, opts?).
func ReportRender(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	reportHash, errObj := requireHashArg("report_render", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	format, errObj := requireStringArg("report_render", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg("report_render", args, 3, reportRenderOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	doc, errObj := readReport(reportHash)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "html":
		fragment, errObj := opts.boolean("fragment", false)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		return resultAndError(stringObj(renderReportHTML(doc, fragment)), nil)
	case "markdown", "md":
		return resultAndError(stringObj(renderReportMarkdown(doc)), nil)
	case "csv":
		text, errObj := renderReportCSV(doc, opts)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		return resultAndError(stringObj(text), nil)
	default:
		return resultAndError(nil, newError("report_render: unknown format %q (accepted: html, markdown, csv)", format))
	}
}

// --- building on an existing document ---

// reportAppend returns a copy of the report with one block added to its last
// section.
//
// The spine is copied and the blocks are shared. A block is never mutated once
// it is built, so the old report cannot see the new one's additions, and a
// table of a hundred thousand rows is not copied again by every call that
// follows it.
func reportAppend(op string, report *object.Hash, block *object.Hash) object.Object {
	sections, errObj := reportSections(op, report)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// A report often opens with a paragraph before the first heading, so blocks
	// written before any section land in a lead section that renders without
	// one rather than being refused.
	if len(sections) == 0 {
		sections = []object.Object{makeHashObject(map[string]object.Object{
			"heading": stringObj(""),
			"level":   intObj(reportDefaultLevel),
			"blocks":  &object.Array{Elements: []object.Object{}},
		})}
	}

	last, ok := sections[len(sections)-1].(*object.Hash)
	if !ok {
		return resultAndError(nil, newError("%s: section %d is %s, not a HASH", op, len(sections)-1, sections[len(sections)-1].Type()))
	}
	blocks, ok := hashValueByKey(last, "blocks").(*object.Array)
	if !ok {
		return resultAndError(nil, newError("%s: section %d has no `blocks` array", op, len(sections)-1))
	}

	updated := hashWith(last, "blocks", &object.Array{Elements: appendObject(blocks.Elements, block)})
	spine := make([]object.Object, len(sections))
	copy(spine, sections)
	spine[len(spine)-1] = updated

	return resultAndError(reportWithSections(report, spine), nil)
}

func reportSections(op string, report *object.Hash) ([]object.Object, *object.Error) {
	value := hashValueByKey(report, "sections")
	if value == nil {
		return nil, newError("%s: this is not a report; it has no `sections` (start one with report_new)", op)
	}
	sections, ok := value.(*object.Array)
	if !ok {
		return nil, newError("%s: `sections` must be an ARRAY, got %s", op, value.Type())
	}
	return sections.Elements, nil
}

func reportWithSections(report *object.Hash, sections []object.Object) *object.Hash {
	return hashWith(report, "sections", &object.Array{Elements: sections})
}

func reportLevelOption(opts *formatOptions) (int, *object.Error) {
	value, ok := opts.pairs["level"]
	if !ok {
		return reportDefaultLevel, nil
	}
	level, ok := value.(*object.Integer)
	if !ok {
		return 0, newError("%s: option %q must be INTEGER, got %s", opts.op, "level", value.Type())
	}
	if level.Value < 1 || level.Value > reportMaxLevel {
		return 0, newError("%s: option %q must be between 1 and %d, got %d", opts.op, "level", reportMaxLevel, level.Value)
	}
	return int(level.Value), nil
}

// hashWith copies a hash with one key replaced. The companion to makeHashObject
// for the builders here, which are all "the same document plus one thing".
func hashWith(hash *object.Hash, key string, value object.Object) *object.Hash {
	pairs := make(map[object.HashKey]object.HashPair, len(hash.Pairs)+1)
	for k, pair := range hash.Pairs {
		pairs[k] = pair
	}
	keyObj := &object.String{Value: key}
	pairs[keyObj.HashKey()] = object.HashPair{Key: keyObj, Value: value}
	return &object.Hash{Pairs: pairs}
}

func appendObject(elements []object.Object, value object.Object) []object.Object {
	out := make([]object.Object, 0, len(elements)+1)
	out = append(out, elements...)
	return append(out, value)
}

// stringListObj keeps the order it was given, unlike stringArrayObj, which
// sorts. A table's columns are in the order the examiner put them.
func stringListObj(values []string) *object.Array {
	elements := make([]object.Object, 0, len(values))
	for _, value := range values {
		elements = append(elements, stringObj(value))
	}
	return &object.Array{Elements: elements}
}

func reportRowsObj(records [][]string) *object.Array {
	rows := make([]object.Object, 0, len(records))
	for _, record := range records {
		rows = append(rows, stringListObj(record))
	}
	return &object.Array{Elements: rows}
}

// --- reading a document back ---

type reportDoc struct {
	title     string
	subtitle  string
	examiner  string
	caseID    string
	generated string
	sections  []reportDocSection
}

type reportDocSection struct {
	heading string
	level   int
	blocks  []reportDocBlock
}

type reportDocBlock struct {
	kind    string
	text    string
	items   []string
	ordered bool
	columns []string
	rows    [][]string
	caption string
}

// readReport validates the whole document before anything is rendered.
//
// It is written against the hash rather than against what the builders happen
// to produce, because a report can be written by hand or reloaded from JSON,
// and because the alternative -- rendering the blocks it recognises and
// stepping over the rest -- produces a report that looks complete and is
// missing a finding. Every refusal names the section and block it came from.
func readReport(hash *object.Hash) (*reportDoc, *object.Error) {
	doc := &reportDoc{}

	title, errObj := reportString(hash, "title", "report_render", true)
	if errObj != nil {
		return nil, errObj
	}
	doc.title = title

	for _, key := range []string{"subtitle", "examiner", "case_id", "generated"} {
		value, errObj := reportString(hash, key, "report_render", false)
		if errObj != nil {
			return nil, errObj
		}
		switch key {
		case "subtitle":
			doc.subtitle = value
		case "examiner":
			doc.examiner = value
		case "case_id":
			doc.caseID = value
		case "generated":
			doc.generated = value
		}
	}

	sections, errObj := reportSections("report_render", hash)
	if errObj != nil {
		return nil, errObj
	}
	for i, element := range sections {
		section, ok := element.(*object.Hash)
		if !ok {
			return nil, newError("report_render: section %d is %s, not a HASH", i, element.Type())
		}
		read, errObj := readReportSection(section, i)
		if errObj != nil {
			return nil, errObj
		}
		doc.sections = append(doc.sections, *read)
	}
	return doc, nil
}

func readReportSection(section *object.Hash, index int) (*reportDocSection, *object.Error) {
	where := fmt.Sprintf("section %d", index)

	heading, errObj := reportString(section, "heading", "report_render", false)
	if errObj != nil {
		return nil, errObj
	}
	out := &reportDocSection{heading: heading, level: reportDefaultLevel}

	if value := hashValueByKey(section, "level"); value != nil {
		level, ok := value.(*object.Integer)
		if !ok {
			return nil, newError("report_render: %s: `level` must be INTEGER, got %s", where, value.Type())
		}
		if level.Value < 1 || level.Value > reportMaxLevel {
			return nil, newError("report_render: %s: `level` must be between 1 and %d, got %d", where, reportMaxLevel, level.Value)
		}
		out.level = int(level.Value)
	}

	blocksValue := hashValueByKey(section, "blocks")
	if blocksValue == nil {
		return nil, newError("report_render: %s has no `blocks` array", where)
	}
	blocks, ok := blocksValue.(*object.Array)
	if !ok {
		return nil, newError("report_render: %s: `blocks` must be an ARRAY, got %s", where, blocksValue.Type())
	}

	for i, element := range blocks.Elements {
		block, ok := element.(*object.Hash)
		if !ok {
			return nil, newError("report_render: %s, block %d is %s, not a HASH", where, i, element.Type())
		}
		read, errObj := readReportBlock(block, where, i)
		if errObj != nil {
			return nil, errObj
		}
		out.blocks = append(out.blocks, *read)
	}
	return out, nil
}

func readReportBlock(block *object.Hash, where string, index int) (*reportDocBlock, *object.Error) {
	at := fmt.Sprintf("%s, block %d", where, index)

	kindValue := hashValueByKey(block, "kind")
	if kindValue == nil {
		return nil, newError("report_render: %s has no `kind` (one of %s, %s, %s)", at, reportBlockText, reportBlockList, reportBlockTable)
	}
	kind, ok := kindValue.(*object.String)
	if !ok {
		return nil, newError("report_render: %s: `kind` must be STRING, got %s", at, kindValue.Type())
	}
	out := &reportDocBlock{kind: kind.Value}

	switch kind.Value {
	case reportBlockText:
		value := hashValueByKey(block, "text")
		if value == nil {
			return nil, newError("report_render: %s is a %s block with no `text`", at, reportBlockText)
		}
		text, ok := value.(*object.String)
		if !ok {
			return nil, newError("report_render: %s: `text` must be STRING, got %s", at, value.Type())
		}
		out.text = text.Value

	case reportBlockList:
		items, errObj := reportStringList(block, "items", at)
		if errObj != nil {
			return nil, errObj
		}
		out.items = items
		if value := hashValueByKey(block, "ordered"); value != nil {
			ordered, ok := value.(*object.Boolean)
			if !ok {
				return nil, newError("report_render: %s: `ordered` must be BOOLEAN, got %s", at, value.Type())
			}
			out.ordered = ordered.Value
		}

	case reportBlockTable:
		columns, errObj := reportStringList(block, "columns", at)
		if errObj != nil {
			return nil, errObj
		}
		out.columns = columns

		rowsValue := hashValueByKey(block, "rows")
		if rowsValue == nil {
			return nil, newError("report_render: %s has no `rows` array", at)
		}
		rows, ok := rowsValue.(*object.Array)
		if !ok {
			return nil, newError("report_render: %s: `rows` must be an ARRAY, got %s", at, rowsValue.Type())
		}
		for i, element := range rows.Elements {
			row, ok := element.(*object.Array)
			if !ok {
				return nil, newError("report_render: %s, row %d is %s, not an ARRAY", at, i, element.Type())
			}
			cells := make([]string, 0, len(row.Elements))
			for j, cell := range row.Elements {
				text, errObj := csvFieldText("report_render", cell, i, j)
				if errObj != nil {
					return nil, newError("report_render: %s, row %d column %d is %s; a table cell must be a scalar", at, i, j, cell.Type())
				}
				cells = append(cells, text)
			}
			out.rows = append(out.rows, cells)
		}

		if value := hashValueByKey(block, "caption"); value != nil {
			caption, ok := value.(*object.String)
			if !ok {
				return nil, newError("report_render: %s: `caption` must be STRING, got %s", at, value.Type())
			}
			out.caption = caption.Value
		}

	default:
		return nil, newError("report_render: %s has kind %q, which nothing renders (one of %s, %s, %s)", at, kind.Value, reportBlockText, reportBlockList, reportBlockTable)
	}
	return out, nil
}

func reportString(hash *object.Hash, key, op string, required bool) (string, *object.Error) {
	value := hashValueByKey(hash, key)
	if value == nil {
		if required {
			return "", newError("%s: this is not a report; it has no %q", op, key)
		}
		return "", nil
	}
	text, ok := value.(*object.String)
	if !ok {
		return "", newError("%s: %q must be STRING, got %s", op, key, value.Type())
	}
	return text.Value, nil
}

func reportStringList(hash *object.Hash, key, at string) ([]string, *object.Error) {
	value := hashValueByKey(hash, key)
	if value == nil {
		return nil, nil
	}
	list, ok := value.(*object.Array)
	if !ok {
		return nil, newError("report_render: %s: %q must be an ARRAY, got %s", at, key, value.Type())
	}
	out := make([]string, 0, len(list.Elements))
	for i, element := range list.Elements {
		text, ok := element.(*object.String)
		if !ok {
			return nil, newError("report_render: %s: %q element %d is %s, not a STRING", at, key, i, element.Type())
		}
		out = append(out, text.Value)
	}
	return out, nil
}

// --- HTML ---

// reportStylesheet is inlined rather than linked, and there is no font, script
// or image in the document at all. A report that fetches anything tells whoever
// serves it that the examiner opened it, and when -- from the examiner's own
// machine, on a case they may not want to announce.
const reportStylesheet = `:root { color-scheme: light dark; }
body { margin: 0 auto; padding: 2rem 1.25rem; max-width: 54rem;
  font: 16px/1.6 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
h1 { font-size: 1.75rem; margin: 0 0 .25rem; }
.subtitle { margin: 0 0 1rem; font-size: 1.1rem; opacity: .75; }
.meta { margin: 0 0 2rem; padding: .75rem 1rem; border-left: 3px solid currentColor;
  opacity: .8; font-size: .9rem; }
.meta div { display: flex; gap: .5rem; }
.meta dt { min-width: 6rem; font-weight: 600; }
.meta dd { margin: 0; }
section { margin: 2rem 0; }
.t { white-space: pre-wrap; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .9rem; }
caption { text-align: left; font-weight: 600; padding-bottom: .5rem; }
th, td { border: 1px solid; border-color: color-mix(in srgb, currentColor 25%, transparent);
  padding: .35rem .6rem; text-align: left; vertical-align: top; word-break: break-word; }
th { background: color-mix(in srgb, currentColor 8%, transparent); }
.empty { opacity: .6; font-style: italic; }`

func renderReportHTML(doc *reportDoc, fragment bool) string {
	var out bytes.Buffer

	if !fragment {
		out.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
		out.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
		fmt.Fprintf(&out, "<title>%s</title>\n", reportHTML(doc.title))
		fmt.Fprintf(&out, "<style>\n%s\n</style>\n</head>\n<body>\n", reportStylesheet)
	}

	fmt.Fprintf(&out, "<h1>%s</h1>\n", reportHTML(doc.title))
	if doc.subtitle != "" {
		fmt.Fprintf(&out, "<p class=\"subtitle\">%s</p>\n", reportHTML(doc.subtitle))
	}

	meta := [][2]string{{"Examiner", doc.examiner}, {"Case", doc.caseID}, {"Generated", doc.generated}}
	if reportHasMeta(meta) {
		out.WriteString("<dl class=\"meta\">\n")
		for _, entry := range meta {
			if entry[1] == "" {
				continue
			}
			fmt.Fprintf(&out, "<div><dt>%s</dt><dd>%s</dd></div>\n", reportHTML(entry[0]), reportHTML(entry[1]))
		}
		out.WriteString("</dl>\n")
	}

	for _, section := range doc.sections {
		out.WriteString("<section>\n")
		if section.heading != "" {
			fmt.Fprintf(&out, "<h%d>%s</h%d>\n", section.level, reportHTML(section.heading), section.level)
		}
		for _, block := range section.blocks {
			renderHTMLBlock(&out, block)
		}
		out.WriteString("</section>\n")
	}

	if !fragment {
		out.WriteString("</body>\n</html>\n")
	}
	return out.String()
}

func renderHTMLBlock(out *bytes.Buffer, block reportDocBlock) {
	switch block.kind {
	case reportBlockText:
		// The paragraph keeps the line breaks the evidence had, through CSS
		// rather than through <br> tags: no markup at all is generated from the
		// text, so there is nothing for a crafted value to reach.
		fmt.Fprintf(out, "<p class=\"t\">%s</p>\n", reportHTML(block.text))

	case reportBlockList:
		tag := "ul"
		if block.ordered {
			tag = "ol"
		}
		fmt.Fprintf(out, "<%s>\n", tag)
		for _, item := range block.items {
			fmt.Fprintf(out, "<li>%s</li>\n", reportHTML(item))
		}
		fmt.Fprintf(out, "</%s>\n", tag)

	case reportBlockTable:
		out.WriteString("<table>\n")
		if block.caption != "" {
			fmt.Fprintf(out, "<caption>%s</caption>\n", reportHTML(block.caption))
		}
		if len(block.columns) > 0 {
			out.WriteString("<thead>\n<tr>")
			for _, column := range block.columns {
				fmt.Fprintf(out, "<th>%s</th>", reportHTML(column))
			}
			out.WriteString("</tr>\n</thead>\n")
		}
		out.WriteString("<tbody>\n")
		if len(block.rows) == 0 {
			width := len(block.columns)
			if width == 0 {
				width = 1
			}
			fmt.Fprintf(out, "<tr><td class=\"empty\" colspan=\"%d\">no rows</td></tr>\n", width)
		}
		for _, row := range block.rows {
			out.WriteString("<tr>")
			for _, cell := range row {
				fmt.Fprintf(out, "<td>%s</td>", reportHTML(cell))
			}
			out.WriteString("</tr>\n")
		}
		out.WriteString("</tbody>\n</table>\n")
	}
}

// reportHTML is the single place a string becomes HTML.
//
// html.EscapeString covers the five characters that matter -- & < > " ' -- which
// is enough precisely because nothing here ever puts evidence text anywhere but
// in element content and never builds an attribute, a URL or a script from it.
// The moment something wants a link out of a value, this stops being sufficient
// and the value stops being safe, which is why the renderer does not make one.
func reportHTML(text string) string { return html.EscapeString(text) }

func reportHasMeta(meta [][2]string) bool {
	for _, entry := range meta {
		if entry[1] != "" {
			return true
		}
	}
	return false
}

// --- Markdown ---

func renderReportMarkdown(doc *reportDoc) string {
	var out bytes.Buffer

	fmt.Fprintf(&out, "# %s\n", markdownText(doc.title))
	if doc.subtitle != "" {
		fmt.Fprintf(&out, "\n%s\n", markdownText(doc.subtitle))
	}

	meta := [][2]string{{"Examiner", doc.examiner}, {"Case", doc.caseID}, {"Generated", doc.generated}}
	if reportHasMeta(meta) {
		out.WriteString("\n")
		for _, entry := range meta {
			if entry[1] == "" {
				continue
			}
			fmt.Fprintf(&out, "**%s:** %s  \n", entry[0], markdownText(entry[1]))
		}
	}

	for _, section := range doc.sections {
		if section.heading != "" {
			fmt.Fprintf(&out, "\n%s %s\n", strings.Repeat("#", section.level), markdownText(section.heading))
		}
		for _, block := range section.blocks {
			renderMarkdownBlock(&out, block)
		}
	}
	return out.String()
}

func renderMarkdownBlock(out *bytes.Buffer, block reportDocBlock) {
	out.WriteString("\n")
	switch block.kind {
	case reportBlockText:
		// A newline inside a paragraph is a hard break rather than something
		// Markdown may fold away, so the shape the examiner wrote survives.
		fmt.Fprintf(out, "%s\n", strings.ReplaceAll(markdownText(block.text), "\n", "\\\n"))

	case reportBlockList:
		for i, item := range block.items {
			marker := "-"
			if block.ordered {
				marker = strconv.Itoa(i+1) + "."
			}
			fmt.Fprintf(out, "%s %s\n", marker, markdownCell(item))
		}

	case reportBlockTable:
		if block.caption != "" {
			fmt.Fprintf(out, "**%s**\n\n", markdownText(block.caption))
		}
		width := len(block.columns)
		for _, row := range block.rows {
			if len(row) > width {
				width = len(row)
			}
		}
		if width == 0 {
			width = 1
		}
		header := make([]string, width)
		for i := range header {
			if i < len(block.columns) {
				header[i] = markdownCell(block.columns[i])
			}
		}
		fmt.Fprintf(out, "| %s |\n", strings.Join(header, " | "))
		fmt.Fprintf(out, "|%s\n", strings.Repeat(" --- |", width))
		for _, row := range block.rows {
			cells := make([]string, width)
			for i := range cells {
				if i < len(row) {
					cells[i] = markdownCell(row[i])
				}
			}
			fmt.Fprintf(out, "| %s |\n", strings.Join(cells, " | "))
		}
	}
}

// markdownInline escapes the characters that open inline markup or an entity.
//
// Markdown is escaped for structure, not for safety: a filename with an
// asterisk in it should read as a filename, and one with a "<" in it should not
// reach a downstream converter as a tag. That last part is the reason "<" and
// "&" are in here, but it is a courtesy rather than a boundary -- a Markdown
// report is safe to *read*, and report_render(report, "html") is what to use
// when the output is going to be looked at in a browser.
var markdownInline = strings.NewReplacer(
	`\`, `\\`,
	"`", "\\`",
	`*`, `\*`,
	`_`, `\_`,
	`[`, `\[`,
	`]`, `\]`,
	`<`, `\<`,
	`&`, `\&`,
)

// markdownBlockStarters are the characters that, at the start of a line, turn a
// paragraph into something else.
const markdownBlockStarters = "#>-+=|"

func markdownText(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		escaped := markdownInline.Replace(line)
		trimmed := strings.TrimLeft(escaped, " \t")
		indent := escaped[:len(escaped)-len(trimmed)]
		switch {
		case trimmed == "":
		case strings.ContainsRune(markdownBlockStarters, rune(trimmed[0])):
			escaped = indent + `\` + trimmed
		case markdownOrderedPrefix(trimmed):
			escaped = indent + `\` + trimmed
		}
		lines[i] = escaped
	}
	return strings.Join(lines, "\n")
}

// markdownOrderedPrefix reports whether a line begins with digits followed by
// "." or ")", which Markdown reads as the start of a numbered list. A finding
// that begins "4. exe deleted" is a sentence, not item four.
func markdownOrderedPrefix(line string) bool {
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	return i > 0 && i < len(line) && (line[i] == '.' || line[i] == ')')
}

// markdownCell escapes for a table cell, where the structure breaks differently:
// an unescaped pipe ends the cell and a newline ends the row, so a value
// carrying either would silently shift every column after it. A cell cannot
// hold a line break at all, so one becomes a space.
func markdownCell(text string) string {
	cell := markdownInline.Replace(text)
	cell = strings.ReplaceAll(cell, "|", `\|`)
	cell = strings.ReplaceAll(cell, "\r\n", " ")
	cell = strings.ReplaceAll(cell, "\n", " ")
	cell = strings.ReplaceAll(cell, "\r", " ")
	return cell
}

// --- CSV ---

func renderReportCSV(doc *reportDoc, opts *formatOptions) (string, *object.Error) {
	tables, labels := reportTables(doc)
	if len(tables) == 0 {
		return "", newError("report_render: csv carries rows and this report has none; render it as html or markdown")
	}

	chosen := 0
	if value, ok := opts.pairs["table"]; ok {
		index, errObj := reportChooseTable(value, tables, labels)
		if errObj != nil {
			return "", errObj
		}
		chosen = index
	} else if len(tables) > 1 {
		return "", newError("report_render: this report has %d tables and a CSV file holds one; name it with {\"table\": n} or its caption -- %s",
			len(tables), strings.Join(labels, "; "))
	}

	delimiter, errObj := opts.str("delimiter", ",")
	if errObj != nil {
		return "", errObj
	}
	comma, errObj := singleRune("report_render", "delimiter", delimiter)
	if errObj != nil {
		return "", errObj
	}
	guard, errObj := opts.boolean("formula_guard", true)
	if errObj != nil {
		return "", errObj
	}

	table := tables[chosen]
	records := make([][]string, 0, len(table.rows)+1)
	if len(table.columns) > 0 {
		records = append(records, csvGuardRecord(table.columns, guard))
	}
	for _, row := range table.rows {
		records = append(records, csvGuardRecord(row, guard))
	}

	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	writer.Comma = comma
	if err := writer.WriteAll(records); err != nil {
		return "", newError("report_render: %s", err.Error())
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", newError("report_render: %s", err.Error())
	}
	return out.String(), nil
}

func reportTables(doc *reportDoc) ([]reportDocBlock, []string) {
	var (
		tables []reportDocBlock
		labels []string
	)
	for _, section := range doc.sections {
		for _, block := range section.blocks {
			if block.kind != reportBlockTable {
				continue
			}
			label := block.caption
			if label == "" {
				label = section.heading
			}
			if label == "" {
				label = "untitled"
			}
			labels = append(labels, fmt.Sprintf("%d: %s", len(tables), label))
			tables = append(tables, block)
		}
	}
	return tables, labels
}

func reportChooseTable(value object.Object, tables []reportDocBlock, labels []string) (int, *object.Error) {
	switch chooser := value.(type) {
	case *object.Integer:
		if chooser.Value < 0 || chooser.Value >= int64(len(tables)) {
			return 0, newError("report_render: option %q is %d but this report has %d tables -- %s",
				"table", chooser.Value, len(tables), strings.Join(labels, "; "))
		}
		return int(chooser.Value), nil
	case *object.String:
		matched := -1
		for i, table := range tables {
			if table.caption != chooser.Value {
				continue
			}
			if matched >= 0 {
				return 0, newError("report_render: option %q is %q and this report has more than one table with that caption; use its index instead", "table", chooser.Value)
			}
			matched = i
		}
		if matched < 0 {
			return 0, newError("report_render: option %q is %q, which is no table's caption -- %s",
				"table", chooser.Value, strings.Join(labels, "; "))
		}
		return matched, nil
	default:
		return 0, newError("report_render: option %q must be INTEGER or STRING, got %s", "table", value.Type())
	}
}

func csvGuardRecord(record []string, guard bool) []string {
	if !guard {
		return record
	}
	out := make([]string, len(record))
	for i, cell := range record {
		out[i] = csvGuardCell(cell)
	}
	return out
}

// csvGuardCell neutralizes a cell a spreadsheet would run.
//
// Excel and LibreOffice both treat a cell beginning "=", "+", "-", "@", a tab
// or a carriage return as a formula, and evaluate it when the file is opened --
// so a filename recovered from an image is code on the examiner's workstation.
// The mitigation is a leading apostrophe, which spreadsheets strip on display.
//
// A value that is simply a negative number is left alone: "-1" is not a
// formula, and a report whose numbers all gained an apostrophe would be one
// nobody could sort. The guard is switched off with {"formula_guard": false},
// for output that is going to be parsed rather than opened.
func csvGuardCell(cell string) string {
	if cell == "" {
		return cell
	}
	switch cell[0] {
	case '=', '+', '-', '@', '\t', '\r':
	default:
		return cell
	}
	if _, err := strconv.ParseFloat(cell, 64); err == nil {
		return cell
	}
	return "'" + cell
}
