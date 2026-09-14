package builtin

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"mutant/object"

	"github.com/BurntSushi/toml"
	yaml "go.yaml.in/yaml/v3"
	"golang.org/x/text/encoding/charmap"
)

// The text half of B-1: the structured formats evidence actually arrives in
// that are not JSON. CSV/TSV for every SIEM export and triage-tool table, XML
// for Scheduled Tasks and OOXML and Nessus, NDJSON for Zeek and Elastic bulk,
// YAML for Sigma rules, TOML for cloud and tool configuration.
//
// Everything here decodes into the shared bridge in format_native.go, so a
// document's shape in Mutant does not depend on which parser produced it.

// utf8BOM is stripped from the front of any text document before parsing.
//
// This is not pedantry. Excel and PowerShell's Export-Csv both write one, so
// the first column of a real analyst-produced CSV is named "<BOM>Timestamp"
// rather than "Timestamp" unless something removes it -- and a header lookup
// that silently misses is the failure this whole item exists to stop.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

func stripBOM(data []byte) []byte { return bytes.TrimPrefix(data, utf8BOM) }

// formatOptions is the optional trailing options hash these builtins take.
//
// Unknown keys are refused by name. An option hash is the one place a typo
// costs nothing at the call site and changes the result: writing {"headers":
// true} instead of {"header": true} would parse, run, and hand back positional
// arrays with no complaint. Naming the key and listing the accepted ones turns
// that into an error at the moment it is made.
type formatOptions struct {
	op    string
	pairs map[string]object.Object
}

func formatOptionsArg(op string, args []object.Object, pos int, allowed ...string) (*formatOptions, *object.Error) {
	opts := &formatOptions{op: op, pairs: map[string]object.Object{}}
	if len(args) < pos {
		return opts, nil
	}
	hash, errObj := requireHashArg(op, args[pos-1], pos)
	if errObj != nil {
		return nil, errObj
	}
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			return nil, newError("%s: option keys must be STRING, got %s", op, pair.Key.Type())
		}
		known := false
		for _, name := range allowed {
			if name == key.Value {
				known = true
				break
			}
		}
		if !known {
			return nil, newError("%s: unknown option %q (accepted: %s)", op, key.Value, strings.Join(allowed, ", "))
		}
		opts.pairs[key.Value] = pair.Value
	}
	return opts, nil
}

func (o *formatOptions) str(key, def string) (string, *object.Error) {
	value, ok := o.pairs[key]
	if !ok {
		return def, nil
	}
	s, ok := value.(*object.String)
	if !ok {
		return "", newError("%s: option %q must be STRING, got %s", o.op, key, value.Type())
	}
	return s.Value, nil
}

func (o *formatOptions) boolean(key string, def bool) (bool, *object.Error) {
	value, ok := o.pairs[key]
	if !ok {
		return def, nil
	}
	b, ok := value.(*object.Boolean)
	if !ok {
		return false, newError("%s: option %q must be BOOLEAN, got %s", o.op, key, value.Type())
	}
	return b.Value, nil
}

func (o *formatOptions) stringList(key string) ([]string, bool, *object.Error) {
	value, ok := o.pairs[key]
	if !ok {
		return nil, false, nil
	}
	arr, ok := value.(*object.Array)
	if !ok {
		return nil, false, newError("%s: option %q must be ARRAY, got %s", o.op, key, value.Type())
	}
	out := make([]string, 0, len(arr.Elements))
	for i, el := range arr.Elements {
		s, ok := el.(*object.String)
		if !ok {
			return nil, false, newError("%s: option %q element %d must be STRING, got %s", o.op, key, i, el.Type())
		}
		out = append(out, s.Value)
	}
	return out, true, nil
}

// singleRune validates a delimiter or comment option.
func singleRune(op, key, value string) (rune, *object.Error) {
	r, size := utf8.DecodeRuneInString(value)
	if r == utf8.RuneError || size != len(value) || value == "" {
		return 0, newError("%s: option %q must be exactly one character, got %q", op, key, value)
	}
	if r == '"' || r == '\r' || r == '\n' || r == 0xFFFD {
		return 0, newError("%s: option %q cannot be %q", op, key, value)
	}
	return r, nil
}

// --- CSV / TSV ---

// csvExtraKey holds fields a row carries beyond what its header declares.
//
// Ragged rows are refused by encoding/csv's default and are common in real
// exports, so the reader is set to accept them -- but accepting them must not
// mean discarding the surplus. A row with more fields than columns keeps them
// here rather than losing them off the end.
const csvExtraKey = "_extra"

var csvOptionNames = []string{"delimiter", "comment", "header", "trim_space", "lazy_quotes"}

func CsvParse(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	data, errObj := requireBinaryArg("csv_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg("csv_parse", args, 2, csvOptionNames...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	delimiter, errObj := opts.str("delimiter", ",")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	comma, errObj := singleRune("csv_parse", "delimiter", delimiter)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	comment, errObj := opts.str("comment", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	var commentRune rune
	if comment != "" {
		commentRune, errObj = singleRune("csv_parse", "comment", comment)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
	}
	header, errObj := opts.boolean("header", true)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	trimSpace, errObj := opts.boolean("trim_space", false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	lazyQuotes, errObj := opts.boolean("lazy_quotes", false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	reader := csv.NewReader(bytes.NewReader(stripBOM(data)))
	reader.Comma = comma
	reader.Comment = commentRune
	reader.TrimLeadingSpace = trimSpace
	reader.LazyQuotes = lazyQuotes
	// -1 accepts rows whose field count differs from the first row's. Evidence
	// tables are ragged often enough that refusing them would make the builtin
	// useless on the files it exists for; nothing is dropped (see csvExtraKey).
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return resultAndError(nil, newError("csv_parse: %s", err.Error()))
	}
	if !header {
		rows := make([]object.Object, 0, len(records))
		for _, record := range records {
			rows = append(rows, stringArrayLiteral(record))
		}
		return resultAndError(&object.Array{Elements: rows}, nil)
	}
	if len(records) == 0 {
		return resultAndError(&object.Array{Elements: []object.Object{}}, nil)
	}
	return csvHeaderRows(records)
}

// stringArrayLiteral wraps a []string as an ARRAY, preserving order.
//
// Not stringArrayObj, from security_status.go, which sorts -- a CSV row's order
// is its meaning.
func stringArrayLiteral(values []string) *object.Array {
	elements := make([]object.Object, 0, len(values))
	for _, value := range values {
		elements = append(elements, stringObj(value))
	}
	return &object.Array{Elements: elements}
}

// csvHeaderRows turns records into one hash per row, keyed by the first record.
func csvHeaderRows(records [][]string) object.Object {
	columns := records[0]
	seen := make(map[string]int, len(columns))
	for i, name := range columns {
		if name == csvExtraKey {
			return resultAndError(nil, newError("csv_parse: column %d is named %q, which is the key used for fields beyond the header; "+
				"read this file with header: false", i, csvExtraKey))
		}
		// A duplicate column is refused rather than resolved. Either choice --
		// first wins, last wins, rename -- silently answers a question about
		// the analyst's data that only the analyst can answer, and header:
		// false reads the file either way.
		if prev, exists := seen[name]; exists {
			return resultAndError(nil, newError("csv_parse: columns %d and %d are both named %q; "+
				"read this file with header: false to keep both", prev, i, name))
		}
		seen[name] = i
	}

	rows := make([]object.Object, 0, len(records)-1)
	for _, record := range records[1:] {
		pairs := make([]object.HashPair, 0, len(columns)+1)
		for i, name := range columns {
			field := ""
			if i < len(record) {
				field = record[i]
			}
			pairs = append(pairs, object.HashPair{Key: stringObj(name), Value: stringObj(field)})
		}
		if len(record) > len(columns) {
			pairs = append(pairs, object.HashPair{
				Key:   stringObj(csvExtraKey),
				Value: stringArrayLiteral(record[len(columns):]),
			})
		}
		row, err := hashFromPairs(pairs)
		if err != nil {
			return resultAndError(nil, newError("csv_parse: %s", err.Error()))
		}
		rows = append(rows, row)
	}
	return resultAndError(&object.Array{Elements: rows}, nil)
}

var csvStringifyOptionNames = []string{"delimiter", "header", "columns", "crlf"}

func CsvStringify(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	rows, errObj := requireArrayArg("csv_stringify", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	opts, errObj := formatOptionsArg("csv_stringify", args, 2, csvStringifyOptionNames...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	delimiter, errObj := opts.str("delimiter", ",")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	comma, errObj := singleRune("csv_stringify", "delimiter", delimiter)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	columns, columnsGiven, errObj := opts.stringList("columns")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	useCRLF, errObj := opts.boolean("crlf", false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	records, defaultHeader, errObj := csvRecords("csv_stringify", rows, columns, columnsGiven)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	header, errObj := opts.boolean("header", defaultHeader)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if !header && defaultHeader && len(records) > 0 {
		records = records[1:]
	}

	var out bytes.Buffer
	writer := csv.NewWriter(&out)
	writer.Comma = comma
	writer.UseCRLF = useCRLF
	if err := writer.WriteAll(records); err != nil {
		return resultAndError(nil, newError("csv_stringify: %s", err.Error()))
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return resultAndError(nil, newError("csv_stringify: %s", err.Error()))
	}
	return resultAndError(stringObj(out.String()), nil)
}

// csvRecords renders rows as CSV records and reports whether it prepended a
// header. An array of arrays is written positionally and has no header; an
// array of hashes is written against a column list and gets one.
//
// Shared with report_table, so a table in a report and the same table written
// straight to CSV cannot disagree about what a cell contains. It takes the
// caller's name because its refusals point at a line of someone's program.
func csvRecords(op string, rows *object.Array, columns []string, columnsGiven bool) ([][]string, bool, *object.Error) {
	if len(rows.Elements) == 0 {
		if columnsGiven {
			return [][]string{columns}, true, nil
		}
		return nil, false, nil
	}

	switch rows.Elements[0].(type) {
	case *object.Array:
		records := make([][]string, 0, len(rows.Elements))
		for i, element := range rows.Elements {
			row, ok := element.(*object.Array)
			if !ok {
				return nil, false, newError("%s: row 0 is an ARRAY but row %d is %s; a table cannot mix the two", op, i, element.Type())
			}
			record := make([]string, 0, len(row.Elements))
			for j, field := range row.Elements {
				text, errObj := csvFieldText(op, field, i, j)
				if errObj != nil {
					return nil, false, errObj
				}
				record = append(record, text)
			}
			records = append(records, record)
		}
		return records, false, nil

	case *object.Hash:
		if !columnsGiven {
			columns = csvUnionColumns(rows)
		}
		records := make([][]string, 0, len(rows.Elements)+1)
		records = append(records, columns)
		for i, element := range rows.Elements {
			row, ok := element.(*object.Hash)
			if !ok {
				return nil, false, newError("%s: row 0 is a HASH but row %d is %s; a table cannot mix the two", op, i, element.Type())
			}
			lookup := make(map[string]object.Object, len(row.Pairs))
			for _, pair := range row.Pairs {
				key, errText := nativeKeyText(pair.Key)
				if errText != nil {
					return nil, false, newError("%s: row %d: %s", op, i, errText.Error())
				}
				lookup[key] = pair.Value
			}
			record := make([]string, 0, len(columns))
			for j, name := range columns {
				value, present := lookup[name]
				if !present {
					record = append(record, "")
					continue
				}
				text, errObj := csvFieldText(op, value, i, j)
				if errObj != nil {
					return nil, false, errObj
				}
				record = append(record, text)
			}
			records = append(records, record)
		}
		return records, true, nil

	default:
		return nil, false, newError("%s: rows must be ARRAYs or HASHes, got %s", op, rows.Elements[0].Type())
	}
}

// csvUnionColumns is the sorted union of every key across every row, so a row
// that carries a field the first row lacks still gets a column.
func csvUnionColumns(rows *object.Array) []string {
	seen := map[string]struct{}{}
	for _, element := range rows.Elements {
		row, ok := element.(*object.Hash)
		if !ok {
			continue
		}
		for _, pair := range row.Pairs {
			if key, err := nativeKeyText(pair.Key); err == nil {
				seen[key] = struct{}{}
			}
		}
	}
	columns := make([]string, 0, len(seen))
	for name := range seen {
		columns = append(columns, name)
	}
	sort.Strings(columns)
	return columns
}

// csvFieldText renders one cell. CSV is flat, so a nested array or hash is
// refused by position rather than silently rendered as its Inspect form.
func csvFieldText(op string, value object.Object, row, col int) (string, *object.Error) {
	switch v := value.(type) {
	case *object.String:
		return v.Value, nil
	case *object.Null:
		return "", nil
	case *object.Integer, *object.Float, *object.Boolean, *object.Bytes:
		return v.Inspect(), nil
	default:
		return "", newError("%s: row %d column %d is %s; a CSV cell must be a scalar", op, row, col, value.Type())
	}
}

// --- XML ---

const (
	// maxXMLDepth and maxXMLNodes bound a document the same way maxNativeDepth
	// and maxNativeNodes bound a decoded tree. encoding/xml itself has no
	// limit, so without these a few kilobytes of nested open tags is a stack
	// overflow and a long run of empty elements is unbounded allocation.
	maxXMLDepth = 256
	maxXMLNodes = 1 << 21
)

// xmlCharsets are the non-UTF-8 encodings an XML declaration may name that this
// parser will decode.
//
// Go's encoding/xml refuses any encoding it is not taught, and the ones here
// are what actually turns up: Windows tooling writes windows-1252 and older
// scanners write Latin-1. Anything else fails by name rather than by mojibake,
// because a document silently misdecoded is worse than one that will not open.
var xmlCharsets = map[string]*charmap.Charmap{
	"windows-1252": charmap.Windows1252,
	"cp1252":       charmap.Windows1252,
	"iso-8859-1":   charmap.ISO8859_1,
	"latin1":       charmap.ISO8859_1,
	"latin-1":      charmap.ISO8859_1,
	"iso-8859-15":  charmap.ISO8859_15,
	"windows-1251": charmap.Windows1251,
}

func xmlCharsetReader(label string, input io.Reader) (io.Reader, error) {
	normalized := strings.ToLower(strings.TrimSpace(label))
	switch normalized {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return input, nil
	}
	if cm, ok := xmlCharsets[normalized]; ok {
		return cm.NewDecoder().Reader(input), nil
	}
	return nil, fmt.Errorf("unsupported XML encoding %q; convert the document to UTF-8 first", label)
}

func XmlParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg("xml_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	decoder := xml.NewDecoder(bytes.NewReader(stripBOM(data)))
	decoder.CharsetReader = xmlCharsetReader
	// Entity is left nil deliberately. An undeclared entity then fails instead
	// of expanding, which is what closes both the billion-laughs expansion and
	// the external-entity read -- encoding/xml never fetches a SYSTEM
	// identifier, so a DOCTYPE cannot reach the filesystem or the network.
	decoder.Strict = true

	root, err := decodeXMLTree(decoder)
	if err != nil {
		return resultAndError(nil, newError("xml_parse: %s", err.Error()))
	}
	if root == nil {
		return resultAndError(nil, newError("xml_parse: document has no root element"))
	}
	return resultAndError(root, nil)
}

// xmlNode is the intermediate the decoder builds before it becomes a hash.
type xmlNode struct {
	name      string
	namespace string
	attrs     []object.HashPair
	text      strings.Builder
	children  []*xmlNode
}

// decodeXMLTree walks the token stream iteratively rather than recursively, so
// depth is a number this function controls rather than a Go stack it might run
// out of.
func decodeXMLTree(decoder *xml.Decoder) (object.Object, error) {
	var root *xmlNode
	var stack []*xmlNode
	nodes := 0

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch t := token.(type) {
		case xml.StartElement:
			if len(stack) >= maxXMLDepth {
				return nil, fmt.Errorf("element nests deeper than %d levels", maxXMLDepth)
			}
			nodes++
			if nodes > maxXMLNodes {
				return nil, fmt.Errorf("document has more than %d elements", maxXMLNodes)
			}
			node := &xmlNode{name: t.Name.Local, namespace: t.Name.Space}
			for _, attr := range t.Attr {
				node.attrs = append(node.attrs, object.HashPair{
					Key:   stringObj(xmlAttrName(attr.Name)),
					Value: stringObj(attr.Value),
				})
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			} else if root != nil {
				return nil, fmt.Errorf("document has a second root element %q", node.name)
			} else {
				root = node
			}
			stack = append(stack, node)

		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("closing tag %q has no opening tag", t.Name.Local)
			}
			stack = stack[:len(stack)-1]

		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}
		}
		// Comments, processing instructions and directives are skipped: they
		// carry no element structure, and a DOCTYPE in particular is exactly
		// the part of an untrusted document not to act on.
	}

	if len(stack) != 0 {
		return nil, fmt.Errorf("element %q is never closed", stack[len(stack)-1].name)
	}
	if root == nil {
		return nil, nil
	}
	return xmlNodeObject(root)
}

// xmlAttrName qualifies a namespaced attribute as space:local, and leaves a
// plain one alone. An xmlns declaration arrives with the space "xmlns", so it
// is preserved rather than flattened into a bare "xmlns" that would collide.
func xmlAttrName(name xml.Name) string {
	if name.Space == "" {
		return name.Local
	}
	return name.Space + ":" + name.Local
}

func xmlNodeObject(node *xmlNode) (object.Object, error) {
	children := make([]object.Object, 0, len(node.children))
	for _, child := range node.children {
		converted, err := xmlNodeObject(child)
		if err != nil {
			return nil, err
		}
		children = append(children, converted)
	}
	attrs, err := hashFromPairs(node.attrs)
	if err != nil {
		return nil, fmt.Errorf("element %q: %s", node.name, err.Error())
	}
	return makeHashObject(map[string]object.Object{
		"name":      stringObj(node.name),
		"namespace": stringObj(node.namespace),
		"attrs":     attrs,
		"text":      stringObj(strings.TrimSpace(node.text.String())),
		"children":  &object.Array{Elements: children},
	}), nil
}

// XmlFind selects nodes below a parsed element by a slash-separated path.
//
// A tree with no way to query it is a tree nobody reads. The path language is
// deliberately three rules -- a name matches an element, `*` matches any single
// element, `**` matches any number of levels including none -- because the
// alternative was XPath, and a partial XPath that quietly disagrees with a real
// one on a predicate is worse than a small language that does not pretend.
func XmlFind(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	node, errObj := requireHashArg("xml_find", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	path, errObj := requireStringArg("xml_find", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	segments := make([]string, 0, 4)
	for _, segment := range strings.Split(path, "/") {
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	if len(segments) == 0 {
		return resultAndError(nil, newError("xml_find: path %q selects nothing; give at least one element name", path))
	}

	matches := make([]object.Object, 0, 8)
	if err := xmlWalk(node, segments, &matches); err != nil {
		return resultAndError(nil, newError("xml_find: %s", err.Error()))
	}
	return resultAndError(&object.Array{Elements: matches}, nil)
}

func xmlWalk(node *object.Hash, segments []string, out *[]object.Object) error {
	if len(segments) == 0 {
		*out = append(*out, node)
		return nil
	}
	children, err := xmlChildren(node)
	if err != nil {
		return err
	}

	// `**` matches here as well as deeper: it is applied to the current node
	// against the rest of the path, then to every child with itself still in
	// front. That is what makes "**/x" find a direct child named x.
	if segments[0] == "**" {
		if err := xmlWalk(node, segments[1:], out); err != nil {
			return err
		}
		for _, child := range children {
			if err := xmlWalk(child, segments, out); err != nil {
				return err
			}
		}
		return nil
	}

	for _, child := range children {
		name, err := xmlNodeName(child)
		if err != nil {
			return err
		}
		if segments[0] != "*" && segments[0] != name {
			continue
		}
		if err := xmlWalk(child, segments[1:], out); err != nil {
			return err
		}
	}
	return nil
}

func xmlChildren(node *object.Hash) ([]*object.Hash, error) {
	value, ok := hashValue(node, "children")
	if !ok {
		return nil, fmt.Errorf("value is not an element from xml_parse (no \"children\" key)")
	}
	arr, ok := value.(*object.Array)
	if !ok {
		return nil, fmt.Errorf("\"children\" must be an ARRAY, got %s", value.Type())
	}
	children := make([]*object.Hash, 0, len(arr.Elements))
	for _, element := range arr.Elements {
		child, ok := element.(*object.Hash)
		if !ok {
			return nil, fmt.Errorf("child element must be a HASH, got %s", element.Type())
		}
		children = append(children, child)
	}
	return children, nil
}

func xmlNodeName(node *object.Hash) (string, error) {
	value, ok := hashValue(node, "name")
	if !ok {
		return "", fmt.Errorf("value is not an element from xml_parse (no \"name\" key)")
	}
	name, ok := value.(*object.String)
	if !ok {
		return "", fmt.Errorf("\"name\" must be a STRING, got %s", value.Type())
	}
	return name.Value, nil
}

// hashValue reads a string-keyed field out of a hash.
func hashValue(hash *object.Hash, key string) (object.Object, bool) {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}

// --- NDJSON / JSONL ---

// maxNDJSONLine bounds one line of an NDJSON stream. bufio's default 64 KiB is
// far too small for a Zeek or Elastic record; this is generous enough for any
// real one and still refuses a file with no newlines in it at all.
const maxNDJSONLine = 64 << 20

func NdjsonParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg("ndjson_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	scanner := bufio.NewScanner(bytes.NewReader(stripBOM(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), maxNDJSONLine)

	values := make([]object.Object, 0, 64)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		// Blank lines are skipped rather than decoded. Every producer of this
		// format emits a trailing newline, and a stream concatenated from two
		// files has a blank line in the middle of it.
		if text == "" {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		var raw any
		if err := decoder.Decode(&raw); err != nil {
			return resultAndError(nil, newError("ndjson_parse: line %d: %s", line, err.Error()))
		}
		if decoder.More() {
			return resultAndError(nil, newError("ndjson_parse: line %d carries more than one JSON value", line))
		}
		value, err := jsonValueToObject(raw)
		if err != nil {
			return resultAndError(nil, newError("ndjson_parse: line %d: %s", line, err.Error()))
		}
		values = append(values, value)
	}
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return resultAndError(nil, newError("ndjson_parse: line %d is longer than %d bytes; this is probably not a newline-delimited stream", line+1, maxNDJSONLine))
		}
		return resultAndError(nil, newError("ndjson_parse: %s", err.Error()))
	}
	return resultAndError(&object.Array{Elements: values}, nil)
}

func NdjsonStringify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	values, errObj := requireArrayArg("ndjson_stringify", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var out strings.Builder
	for i, element := range values.Elements {
		value, err := objectToJSONValue(element)
		if err != nil {
			return resultAndError(nil, newError("ndjson_stringify: element %d: %s", i, err.Error()))
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return resultAndError(nil, newError("ndjson_stringify: element %d: %s", i, err.Error()))
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return resultAndError(stringObj(out.String()), nil)
}

// --- YAML ---

func YamlParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg("yaml_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var raw any
	if err := yaml.Unmarshal(stripBOM(data), &raw); err != nil {
		return resultAndError(nil, newError("yaml_parse: %s", err.Error()))
	}
	value, err := nativeToObject(raw)
	if err != nil {
		return resultAndError(nil, newError("yaml_parse: %s", err.Error()))
	}
	return resultAndError(value, nil)
}

// YamlParseAll decodes every document in a stream.
//
// This is not a convenience over yaml_parse. A Sigma ruleset ships as one file
// of `---`-separated rules, and yaml_parse on such a file returns only the
// first -- silently, which is the shape of bug this item exists to remove.
func YamlParseAll(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg("yaml_parse_all", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(stripBOM(data)))
	documents := make([]object.Object, 0, 8)
	for index := 0; ; index++ {
		var raw any
		err := decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			return resultAndError(nil, newError("yaml_parse_all: document %d: %s", index, err.Error()))
		}
		value, convErr := nativeToObject(raw)
		if convErr != nil {
			return resultAndError(nil, newError("yaml_parse_all: document %d: %s", index, convErr.Error()))
		}
		documents = append(documents, value)
	}
	return resultAndError(&object.Array{Elements: documents}, nil)
}

func YamlStringify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	// YAML has a binary tag, but a buffer written as !!binary base64 round-trips
	// to a buffer only through a decoder configured to expect one. Hex keeps
	// yaml_stringify agreeing with Inspect and json_stringify, and
	// string_to_bytes(s, "hex") converts it back.
	value, err := objectToNative(args[0], false)
	if err != nil {
		return resultAndError(nil, newError("yaml_stringify: %s", err.Error()))
	}
	encoded, err := yaml.Marshal(value)
	if err != nil {
		return resultAndError(nil, newError("yaml_stringify: %s", err.Error()))
	}
	return resultAndError(stringObj(string(encoded)), nil)
}

// --- TOML ---

func TomlParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	data, errObj := requireBinaryArg("toml_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	var raw map[string]any
	if _, err := toml.Decode(string(stripBOM(data)), &raw); err != nil {
		return resultAndError(nil, newError("toml_parse: %s", err.Error()))
	}
	value, err := nativeToObject(raw)
	if err != nil {
		return resultAndError(nil, newError("toml_parse: %s", err.Error()))
	}
	return resultAndError(value, nil)
}

func TomlStringify(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	switch args[0].(type) {
	case *object.Hash, *object.Struct:
	default:
		return resultAndError(nil, newError("argument 1 to `toml_stringify` must be HASH or STRUCT, got %s "+
			"(a TOML document is a table at the top level)", args[0].Type()))
	}

	value, err := objectToNative(args[0], false)
	if err != nil {
		return resultAndError(nil, newError("toml_stringify: %s", err.Error()))
	}

	var out bytes.Buffer
	if err := encodeTOML(&out, value); err != nil {
		return resultAndError(nil, newError("toml_stringify: %s", err.Error()))
	}
	return resultAndError(stringObj(out.String()), nil)
}

// encodeTOML wraps the encoder because TOML has no null: a nil anywhere in the
// tree makes it panic rather than return, and a panic out of a builtin takes
// the program with it.
func encodeTOML(out *bytes.Buffer, value any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("value cannot be written as TOML (%v); TOML has no null, and every table entry needs a value", r)
		}
	}()
	return toml.NewEncoder(out).Encode(value)
}
