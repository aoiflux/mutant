package builtin

import "strings"

// ParamKind names a value type a builtin parameter accepts. The values are
// deliberately the object type names the language already shows users through
// `type_of` (INTEGER, STRING, ARRAY, ...) so a diagnostic can say "expects
// STRING, got INTEGER" in the same words the runtime does.
//
// ParamBytes names the byte-buffer type. Before it existed, a "bytes" parameter
// had to declare ParamString and explain itself in prose, because a buffer and a
// string were the same value to the language. Both kinds are still declared
// together on every position that reads a buffer -- the whole family accepts
// either representation, and a position that refused STRING would flag working
// programs.
type ParamKind string

const (
	// ParamAny records that a parameter genuinely accepts any value — a
	// verified fact, distinct from a parameter whose kinds are simply not
	// declared yet (an empty set). Consumers must never type-check against it.
	ParamAny    ParamKind = "ANY"
	ParamInt    ParamKind = "INTEGER"
	ParamFloat  ParamKind = "FLOAT"
	ParamString ParamKind = "STRING"
	ParamBytes  ParamKind = "BYTES"
	ParamBool   ParamKind = "BOOLEAN"
	ParamArray  ParamKind = "ARRAY"
	ParamHash   ParamKind = "HASH"
	ParamFn     ParamKind = "FUNCTION"
	ParamNull   ParamKind = "NULL"
	// ParamStruct and ParamEnum name the two user-declared value types.
	//
	// They arrived late because nothing needed them: the parameters that accept
	// them all read a field or a tag off the value, and the rest of the standard
	// library never sees one. Their absence was the reason fifteen positions
	// stayed undeclared — a parameter documented as "a hash or struct" could
	// only be described by half its contract, and declaring the half would have
	// flagged the struct calls that work.
	//
	// ParamEnum is spelled ENUM_VALUE rather than ENUM because that is what
	// `type_of` returns and what the runtime's own errors say ("node type must
	// be INTEGER or ENUM_VALUE"). The kind names exist to let a diagnostic speak
	// the language's words, so they follow the language rather than tidiness.
	ParamStruct ParamKind = "STRUCT"
	ParamEnum   ParamKind = "ENUM_VALUE"
	// ParamError names the error type. It arrived with error(), the first
	// builtin whose *success* value is an error rather than whose failure is.
	//
	// Every other builtin that yields an error yields it in the second half of
	// a pair, which BuiltinReturnDoc.Text renders as the literal "ERROR"
	// without needing a kind for it. A bare ERROR return had no way to be
	// spelled at all, and "ANY" would have been a lie in the one place the
	// contract has an exact answer.
	ParamError ParamKind = "ERROR"
)

// BuiltinParamDoc is the exported view of one builtin parameter.
//
// Name keeps the decorated spelling used in the signature (`topic?`,
// `...values`) because hover and signature help render it directly; Optional
// and Variadic carry the same information in structured form, derived from that
// spelling so the two can never disagree.
//
// Kinds is the set of value types the parameter accepts — a union, because
// plenty of builtins take more than one (`len` accepts STRING, ARRAY, or HASH).
// An empty set means the parameter's types have not been declared yet and it
// must not be type-checked; that is what keeps the argument-type diagnostic
// free of false positives as coverage grows.
type BuiltinParamDoc struct {
	Name     string
	Doc      string
	Kinds    []ParamKind
	Optional bool
	Variadic bool

	// Elem is the set of kinds an ARRAY parameter's elements may be, for the
	// builtins that check them — str_join rejects a non-STRING element, sum and
	// avg reject a non-numeric one. It is a union for the same reason Kinds is:
	// "an array of numbers" is INTEGER or FLOAT, not one of them. Empty means
	// the elements are unconstrained, or simply not declared yet, and are never
	// checked.
	Elem []ParamKind
}

// AcceptsElement reports whether an ARRAY parameter admits an element of the
// given kind. It is true for every kind when no element contract is declared.
func (p BuiltinParamDoc) AcceptsElement(kind ParamKind) bool {
	if len(p.Elem) == 0 {
		return true
	}
	for _, allowed := range p.Elem {
		if allowed == ParamAny || allowed == kind {
			return true
		}
	}
	return false
}

// ElemText names an ARRAY parameter's element kinds the way KindsText names its
// own — "STRING", or "INTEGER|FLOAT" for a union — and "" when unconstrained.
func (p BuiltinParamDoc) ElemText() string {
	if len(p.Elem) == 0 {
		return ""
	}
	parts := make([]string, 0, len(p.Elem))
	for _, kind := range p.Elem {
		parts = append(parts, string(kind))
	}
	return strings.Join(parts, "|")
}

// AcceptsAnyKind reports whether the parameter must be left unchecked: either
// its kinds are undeclared, or it is declared to accept anything.
func (p BuiltinParamDoc) AcceptsAnyKind() bool {
	if len(p.Kinds) == 0 {
		return true
	}
	for _, kind := range p.Kinds {
		if kind == ParamAny {
			return true
		}
	}
	return false
}

// Accepts reports whether a value of the given kind satisfies the parameter.
// It is true for any kind when the parameter is unchecked.
func (p BuiltinParamDoc) Accepts(kind ParamKind) bool {
	if p.AcceptsAnyKind() {
		return true
	}
	for _, allowed := range p.Kinds {
		if allowed == kind {
			return true
		}
	}
	return false
}

// BuiltinReturnDoc is the exported view of what a builtin yields.
//
// Kinds is the set of value types the *success* value can have, in the same
// vocabulary the parameter contracts use. Pair records the shape: true when the
// builtin follows the (value, err) convention and returns a MULTI_VALUE whose
// second element carries the error, false when it returns a bare value and
// signals failure with an ERROR in its place.
//
// That distinction is the one this type exists for. Mutant's standard library is
// split almost two to one between the two shapes, and which binding of
// `let a, b = f()` receives the error depends entirely on which shape f has —
// something no signature or summary said before.
//
// Fields names the keys of a returned HASH (or of the hashes in a returned
// ARRAY) for the builtins that always build the same shape. It is empty when the
// builtin builds more than one shape, or one this could not read, so an empty
// list means "not stated" and never "no fields".
type BuiltinReturnDoc struct {
	Kinds  []ParamKind
	Elem   []ParamKind
	Fields []string
	Doc    string
	Pair   bool
}

// KindsText names the success value's kinds the way BuiltinParamDoc.KindsText
// names a parameter's — "STRING", or "INTEGER|FLOAT" for a union. An undeclared
// or ANY return renders as "ANY", because unlike a parameter (where "no
// constraint" means "do not check"), a return always has *some* answer to give
// the reader.
func (r BuiltinReturnDoc) KindsText() string {
	if len(r.Kinds) == 0 {
		return string(ParamAny)
	}
	parts := make([]string, 0, len(r.Kinds))
	for _, kind := range r.Kinds {
		parts = append(parts, string(kind))
	}
	return strings.Join(parts, "|")
}

// Text renders the whole return type as it appears in a signature: the success
// kinds for a bare builtin, and the pair for a (value, err) one.
func (r BuiltinReturnDoc) Text() string {
	if len(r.Elem) == 1 && len(r.Kinds) == 1 && r.Kinds[0] == ParamArray {
		if r.Pair {
			return "([]" + string(r.Elem[0]) + ", ERROR)"
		}
		return "[]" + string(r.Elem[0])
	}
	if r.Pair {
		return "(" + r.KindsText() + ", ERROR)"
	}
	return r.KindsText()
}

// builtinReturnDoc is the internal, hand-authored form of a return contract.
//
// Leave kinds nil only for a builtin whose result genuinely has no single type;
// prefer an explicit ParamAny, which records that as a verified fact the same
// way it does for a parameter.
type builtinReturnDoc struct {
	kinds  []ParamKind
	elem   []ParamKind
	fields []string
	doc    string
	pair   bool
}

// ret builds a return contract for a builtin that yields a bare value.
func ret(doc string, kinds ...ParamKind) builtinReturnDoc {
	return builtinReturnDoc{kinds: kinds, doc: doc}
}

// pairRet builds a return contract for a builtin that follows the (value, err)
// convention, where the error lands in the *second* binding.
func pairRet(doc string, kinds ...ParamKind) builtinReturnDoc {
	return builtinReturnDoc{kinds: kinds, doc: doc, pair: true}
}

// withFields records the keys a returned HASH always carries, or the keys of the
// hashes in a returned ARRAY.
func (r builtinReturnDoc) withFields(fields ...string) builtinReturnDoc {
	r.fields = fields
	return r
}

// ofElem records the element kind of a returned ARRAY.
func (r builtinReturnDoc) ofElem(elem ...ParamKind) builtinReturnDoc {
	r.elem = elem
	return r
}

type builtinFamilyDoc struct {
	prefix  string
	summary string
}

type builtinDoc struct {
	signature string
	summary   string
	params    []builtinParamDoc
	// returns is the contract for the value the builtin yields. Like the
	// parameter contracts it is read off the implementation rather than
	// inferred from the summary, and return_conformance_test.go asks the
	// implementations to back it.
	returns builtinReturnDoc
	// platforms lists the GOOS values on which the builtin actually works. An
	// empty/nil slice means "all platforms" (the common case). The LSP reads this
	// to warn when a program calls a builtin unsupported on the host OS.
	platforms []string
	// platformNote is a soft, human-readable caveat surfaced in hover (not a hard
	// availability gate) — e.g. a builtin that works everywhere but whose behavior
	// differs per OS, or one path of which is platform-specific.
	platformNote string
	// stability is the promise the builtin's name and shape carry. Empty means
	// StabilityStable, so the field is written only where the answer is not the
	// default and 400-odd entries stay unchanged.
	stability Stability
	// replacement names what to use instead, and is meaningful only alongside
	// StabilityDeprecated. It is the "<replacement>" half of the
	// `deprecated:<replacement>` spelling, kept as its own field so a consumer
	// need not parse the tier string. TestDeprecatedBuiltinsNameTheirReplacement
	// requires it.
	replacement string
}

// builtinParamDoc is the internal, hand-authored form of one parameter.
//
// name keeps the signature's spelling (`topic?`, `...values`); optional and
// variadic are derived from it at export time rather than stored, so there is
// nothing to keep in sync. kinds is the union of accepted value types — leave
// it nil until the parameter has been verified against the builtin's
// implementation, because an undeclared parameter is simply never checked.
type builtinParamDoc struct {
	name  string
	doc   string
	kinds []ParamKind
	// elem is the set of kinds an ARRAY parameter's elements may be, declared
	// only for the builtins that actually check them. Like kinds, it is a union
	// and an empty one means "never checked".
	elem []ParamKind
}

// Stability is the promise a builtin's name and shape carry. It became
// expressible only once bytecode stopped addressing builtins by registry
// ordinal: while an ordinal was baked into every artifact, nothing could be
// renamed or retired, so every builtin was permanent whether or not that was
// intended.
type Stability string

const (
	// StabilityStable is the default and the unwritten value: the name, the
	// arguments and the shape of the result will not change under a program
	// already written against them.
	StabilityStable Stability = "stable"

	// StabilityExperimental marks a builtin whose contract is still moving. It
	// works, and it may be renamed or reshaped in a minor release. Editors show
	// the tier; nothing refuses to compile it.
	StabilityExperimental Stability = "experimental"

	// StabilityDeprecated marks a builtin kept only so existing programs keep
	// working. It names its replacement, and calling it earns a diagnostic
	// rather than a failure -- the whole point of keeping it is that old code
	// still runs.
	StabilityDeprecated Stability = "deprecated"
)

// StabilityOf reports the tier a builtin declares, and whether the builtin has a
// teaching doc to declare one at all. An undocumented builtin reports
// StabilityStable: absent evidence of a promise being withdrawn, an editor
// should say nothing.
func StabilityOf(name string) (Stability, bool) {
	doc, ok := builtinDocs[name]
	if !ok {
		return StabilityStable, false
	}
	if doc.stability == "" {
		return StabilityStable, true
	}
	return doc.stability, true
}

// DeprecatedBy returns the builtin that replaces a deprecated one. The bool is
// false for anything not deprecated, so a caller can use it as the whole test.
func DeprecatedBy(name string) (string, bool) {
	doc, ok := builtinDocs[name]
	if !ok || doc.stability != StabilityDeprecated {
		return "", false
	}
	return doc.replacement, true
}

// hashableKinds is the set of kinds that implement object.Hashable, and so the
// only kinds a hash key may be — see hashableKey in collections_builtins.go,
// which rejects everything else with "must be a hashable type".
var hashableKinds = []ParamKind{ParamString, ParamInt, ParamFloat, ParamBool}

// param builds one parameter contract: the spelling used in the signature, the
// prose shown in hover, and the set of value kinds the builtin accepts there.
//
// Pass no kinds when the parameter has not been verified against the builtin's
// implementation yet — an undeclared parameter is simply never type-checked.
// Pass ParamAny to record the verified fact that it accepts anything.
func param(name, doc string, kinds ...ParamKind) builtinParamDoc {
	return builtinParamDoc{name: name, doc: doc, kinds: kinds}
}

// arrayParam builds an ARRAY parameter that additionally records what its
// elements may be.
//
// Declare element kinds only where the builtin genuinely rejects other ones —
// str_join's "element %d is %s", sum's "element %d must be numeric". Most array
// parameters are polymorphic (reverse, slice, unique) and must be left bare, or
// the element check would flag working code.
func arrayParam(name, doc string, elem ...ParamKind) builtinParamDoc {
	return builtinParamDoc{name: name, doc: doc, kinds: []ParamKind{ParamArray}, elem: elem}
}

// The twelve bytes_read_* / bytes_write_* builtins are generated from two
// helpers in builtin/bytes.go and share one argument shape apiece. Spelling
// that shape once keeps the twelve entries from drifting apart.

func bytesReadParams() []builtinParamDoc {
	return []builtinParamDoc{
		param("data", "Source buffer.", ParamString, ParamBytes),
		param("offset", "Offset to read from.", ParamInt),
	}
}

func bytesWriteParams() []builtinParamDoc {
	return []builtinParamDoc{
		param("data", "Buffer to write into; a modified copy is returned, in the same representation.", ParamString, ParamBytes),
		param("offset", "Offset to write at.", ParamInt),
		param("value", "Unsigned integer to encode; must fit the field width.", ParamInt),
	}
}

// cursorParam is the cursor argument the bytes_cursor_* builtins share — a HASH
// carrying `data` and `offset`, as built by bytes_cursor_new and validated by
// requireBytesCursor.
func cursorParam() builtinParamDoc {
	return param("cursor", "Cursor hash from bytes_cursor_new, with `data` and `offset` fields.", ParamHash)
}

var builtinDocs = map[string]builtinDoc{
	BuiltinNameLen: {
		signature: "len(value)",
		// Verified against builtin/len.go: the switch accepts Array, String,
		// Bytes and Hash. A buffer's length is its byte count.
		summary: "Returns the length of a string, buffer, array, or hash.",
		params:  []builtinParamDoc{param("value", "String, buffer, array, or hash to measure.", ParamString, ParamBytes, ParamArray, ParamHash)},
		returns: ret("the length of a string, buffer, array, or hash", ParamInt)},
	BuiltinNameHelp: {signature: "help(topic?, mode?)", summary: "Returns help text: an overview, a topic (keywords/builtins/examples/docs), or details for a specific builtin name.", params: []builtinParamDoc{param("topic?", "Optional topic or builtin name.", ParamString), param("mode?", "Optional rendering mode.", ParamString)}, returns: ret("the rendered help text", ParamString)},
	// putln takes no arity check at all and prints each argument separated by a
	// space (builtin/putln.go) — the `putln(value)` spelling it carried before
	// contradicted the 400+ multi-argument calls in examples/.
	BuiltinNamePutln: {signature: "putln(...values)", summary: "Prints values separated by spaces, followed by a newline.", params: []builtinParamDoc{param("...values", "Values to print; any type is accepted.", ParamAny)}, returns: ret("null; the values are written to standard output", ParamNull)},
	BuiltinNamePutf: {
		signature: "putf(format, ...values)",
		summary:   "Formats and prints values using a format string.",
		// Unlike str_format, putf does not require a STRING format: it calls
		// Inspect() on whatever it is given (builtin/putf.go).
		params: []builtinParamDoc{
			param("format", "Printf-style format string; any value is accepted and inspected.", ParamAny),
			param("...values", "Values interpolated into format; any type is accepted.", ParamAny),
		},
		returns: ret("null; the formatted text is written to standard output", ParamNull)},
	BuiltinNameGets:  {signature: "gets()", summary: "Reads a full line of input from stdin and returns it as a STRING (newline trimmed). Use to_int/to_float/parse_int to convert.", returns: ret("the line read from standard input, without its newline", ParamString)},
	BuiltinNameFirst: {signature: "first(array)", summary: "Returns the first element of an array.", params: []builtinParamDoc{param("array", "Source array.", ParamArray)}, returns: ret("the first element, or null when the array is empty", ParamAny)},
	BuiltinNameLast:  {signature: "last(array)", summary: "Returns the last element of an array.", params: []builtinParamDoc{param("array", "Source array.", ParamArray)}, returns: ret("the last element, or null when the array is empty", ParamAny)},
	BuiltinNameRest:  {signature: "rest(array)", summary: "Returns a new array without the first element.", params: []builtinParamDoc{param("array", "Source array.", ParamArray)}, returns: ret("a new array without the first element", ParamArray)},
	BuiltinNamePush:  {signature: "push(array, value)", summary: "Returns a new array with value appended.", params: []builtinParamDoc{param("array", "Source array.", ParamArray), param("value", "Element to append; any type is accepted.", ParamAny)}, returns: ret("a new array with value appended", ParamArray)},
	BuiltinNamePop:   {signature: "pop(array)", summary: "Returns a new array without the last element.", params: []builtinParamDoc{param("array", "Source array.", ParamArray)}, returns: ret("a new array without the last element", ParamArray)},
	// Every fs_* path is asserted to *object.String in builtin/fs.go. Payloads
	// go through requireBinaryArg and accept either representation, so a buffer
	// can be written straight back out without a conversion in between.
	BuiltinNameFsRead: {
		signature: "fs_read(path)", summary: "Reads file contents from disk.",
		params:  []builtinParamDoc{param("path", "Path to file.", ParamString)},
		returns: pairRet("the file's bytes", ParamString)},
	BuiltinNameFsReadBytes: {
		signature: "fs_read_bytes(path)", summary: "Reads file contents from disk as a BYTES buffer. Use this rather than fs_read whenever the file is not known to be text.",
		params:  []builtinParamDoc{param("path", "Path to file.", ParamString)},
		returns: pairRet("the file's bytes", ParamBytes)},
	BuiltinNameFsWrite: {
		signature: "fs_write(path, data)", summary: "Writes data to a file, replacing existing contents.",
		params: []builtinParamDoc{
			param("path", "Path to file.", ParamString),
			param("data", "Text or buffer payload.", ParamString, ParamBytes),
		},
		returns: pairRet("true once the file has been written", ParamBool)},
	BuiltinNameFsAppend: {
		signature: "fs_append(path, data)", summary: "Appends data to the end of a file.",
		params: []builtinParamDoc{
			param("path", "Path to file.", ParamString),
			param("data", "Text or buffer payload.", ParamString, ParamBytes),
		},
		returns: pairRet("true once the data has been appended", ParamBool)},
	BuiltinNameFsExists: {
		signature: "fs_exists(path)", summary: "Returns whether a file or directory exists.",
		params:  []builtinParamDoc{param("path", "Path to check.", ParamString)},
		returns: pairRet("whether a file or directory exists", ParamBool)},
	BuiltinNameHttpGet:     {signature: "http_get(url)", summary: "Performs an HTTP GET request.", params: []builtinParamDoc{param("url", "Absolute request URL.", ParamString)}, returns: pairRet("the response status, headers, and body", ParamHash).withFields("body", "error", "headers", "status")},
	BuiltinNameHttpPost:    {signature: "http_post(url, body, contentType?)", summary: "Performs an HTTP POST request. contentType defaults to application/octet-stream when omitted.", params: []builtinParamDoc{param("url", "Absolute request URL.", ParamString), param("body", "Request body: STRING sent as-is, HASH or STRUCT encoded as JSON.", ParamString, ParamHash, ParamStruct), param("contentType?", "Optional Content-Type header (default application/octet-stream).", ParamString)}, returns: pairRet("the response status, headers, and body", ParamHash).withFields("body", "error", "headers", "status")},
	BuiltinNameHttpRequest: {signature: "http_request(method, url, body, headers)", summary: "Performs an HTTP request with a body and a headers hash. All four arguments are required; the timeout is a fixed 30s (not configurable).", params: []builtinParamDoc{param("method", "HTTP verb (GET/POST/etc).", ParamString), param("url", "Absolute request URL.", ParamString), param("body", "Request body: STRING sent as-is, HASH or STRUCT encoded as JSON.", ParamString, ParamHash, ParamStruct), param("headers", "Request headers as a hash or struct.", ParamHash, ParamStruct)}, returns: pairRet("the response status, headers, and body", ParamHash).withFields("body", "error", "headers", "status")},
	BuiltinNameJsonParse: {
		signature: "json_parse(text)", summary: "Parses JSON text into Mutant values.",
		params:  []builtinParamDoc{param("text", "JSON string input.", ParamString)},
		returns: pairRet("the decoded value: a scalar, array, or hash, depending on the JSON", ParamAny)},
	// objectToJSONValue (builtin/json.go) handles scalars, null, arrays, and
	// hashes and errors on anything else — functions included — so the union
	// below is every kind it can serialize.
	BuiltinNameJsonStringify: {
		signature: "json_stringify(value)", summary: "Serializes Mutant values into JSON text.",
		// A buffer serialises as its hex, matching Inspect. JSON has no binary
		// type, and erroring on any structure containing one would make a
		// buffer unusable in exactly the reports this language exists to write.
		params: []builtinParamDoc{param("value", "Value to serialize: a scalar, buffer, null, array, or hash with string keys.",
			ParamString, ParamBytes, ParamInt, ParamFloat, ParamBool, ParamNull, ParamArray, ParamHash)},
		returns: pairRet("the JSON text", ParamString)},
	// The formats that are not JSON (B-1). Every one of these decodes through
	// the shared bridge in builtin/format_native.go, so a buffer, a timestamp and
	// a big integer render identically no matter which format they arrived in.
	// The parse side accepts BYTES or STRING because evidence reaches a program
	// either way -- fs_read_bytes and zip_read_bytes hand back buffers, fs_read
	// hands back text -- and neither should need a conversion first.
	BuiltinNameCsvParse: {
		signature: "csv_parse(data, options?)",
		summary:   "Parses CSV/TSV into an array of hashes keyed by the header row. options: delimiter (default \",\"), comment, header (default true), trim_space, lazy_quotes. A UTF-8 BOM is stripped, duplicate column names are refused rather than silently resolved, and fields beyond the header land in an _extra array. With header:false each row is an array of strings instead.",
		params: []builtinParamDoc{
			param("data", "CSV/TSV text or buffer.", ParamBytes, ParamString),
			param("options?", "Parse options: delimiter, comment, header, trim_space, lazy_quotes. Unknown keys are refused by name.", ParamHash),
		},
		returns: pairRet("the rows: hashes keyed by header name, or arrays of strings when header is false", ParamArray).ofElem(ParamHash, ParamArray)},
	BuiltinNameCsvStringify: {
		signature: "csv_stringify(rows, options?)",
		summary:   "Serializes an array of hashes (or arrays) as CSV/TSV. options: delimiter, header (default true), columns (explicit column order), crlf. Without an explicit columns list the header is the sorted union of every row's keys, so a row missing a key writes an empty field rather than shifting the others.",
		params: []builtinParamDoc{
			arrayParam("rows", "Rows to write: hashes keyed by column name, or arrays of values.", ParamHash, ParamArray),
			param("options?", "Write options: delimiter, header, columns, crlf. Unknown keys are refused by name.", ParamHash),
		},
		returns: pairRet("the CSV text", ParamString)},
	BuiltinNameXmlParse: {
		signature: "xml_parse(data)",
		summary:   "Parses XML into a node tree: {name, namespace, attrs, text, children}. Comments, processing instructions and directives are skipped, undeclared entities fail rather than expand (closing billion-laughs and XXE), and windows-1252/iso-8859-1/-15/windows-1251 documents are decoded by their declared charset -- an unrecognised charset fails by name rather than being misdecoded.",
		params:    []builtinParamDoc{param("data", "XML text or buffer.", ParamBytes, ParamString)},
		returns:   pairRet("the root element", ParamHash).withFields("attrs", "children", "name", "namespace", "text")},
	BuiltinNameXmlFind: {
		signature: "xml_find(node, selector)",
		summary:   "Selects descendants of a parsed element by a slash-separated path. Three rules, not XPath: a name matches an element, * matches any single level, ** matches any number of levels including none (so \"**/Task\" also finds a direct child).",
		params: []builtinParamDoc{
			param("node", "A node from xml_parse or a previous xml_find.", ParamHash),
			// Named "selector", not "path": webrepl's browser-safe filter reads a
			// parameter called "path" as a filesystem path and would exclude this
			// builtin from the browser REPL, which reads no files at all.
			param("selector", "Slash-separated selector, e.g. \"Triggers/*\" or \"**/Command\".", ParamString),
		},
		returns: pairRet("the matching nodes, in document order", ParamArray).ofElem(ParamHash).withFields("attrs", "children", "name", "namespace", "text")},
	BuiltinNameNdjsonParse: {
		signature: "ndjson_parse(data)",
		summary:   "Parses newline-delimited JSON (NDJSON/JSONL) -- the wire format of Zeek, Elastic bulk and OCSF streams. Blank lines are skipped; a malformed line fails with its line number rather than silently truncating the stream.",
		params:    []builtinParamDoc{param("data", "NDJSON text or buffer.", ParamBytes, ParamString)},
		returns:   pairRet("one decoded value per line", ParamArray).ofElem(ParamAny)},
	BuiltinNameNdjsonStringify: {
		signature: "ndjson_stringify(values)",
		summary:   "Serializes an array as newline-delimited JSON, one value per line, with a trailing newline so the output concatenates with another stream.",
		params:    []builtinParamDoc{arrayParam("values", "Values to write, one per line.", ParamAny)},
		returns:   pairRet("the NDJSON text", ParamString)},
	BuiltinNameYamlParse: {
		signature: "yaml_parse(data)",
		summary:   "Parses the first YAML document -- Sigma rules, CI config, cloud manifests. A file of ----separated documents needs yaml_parse_all, which is why this one exists as a pair.",
		params:    []builtinParamDoc{param("data", "YAML text or buffer.", ParamBytes, ParamString)},
		returns:   pairRet("the decoded document", ParamAny)},
	BuiltinNameYamlParseAll: {
		signature: "yaml_parse_all(data)",
		summary:   "Parses every document in a multi-document YAML stream. A Sigma ruleset is one file of ----separated documents, and yaml_parse would return only the first, silently.",
		params:    []builtinParamDoc{param("data", "YAML text or buffer.", ParamBytes, ParamString)},
		returns:   pairRet("one decoded value per document, in file order", ParamArray).ofElem(ParamAny)},
	BuiltinNameYamlStringify: {
		signature: "yaml_stringify(value)",
		summary:   "Serializes a Mutant value as YAML. A buffer is written as hex, matching Inspect and json_stringify; string_to_bytes(s, \"hex\") converts it back.",
		params: []builtinParamDoc{param("value", "Value to serialize: a scalar, buffer, null, array, hash, or struct.",
			ParamString, ParamBytes, ParamInt, ParamFloat, ParamBool, ParamNull, ParamArray, ParamHash, ParamStruct)},
		returns: pairRet("the YAML text", ParamString)},
	BuiltinNameTomlParse: {
		signature: "toml_parse(data)",
		summary:   "Parses TOML into a hash. TOML datetimes become RFC 3339 strings, so they sort against every other timestamp the language produces.",
		params:    []builtinParamDoc{param("data", "TOML text or buffer.", ParamBytes, ParamString)},
		returns:   pairRet("the decoded table", ParamHash)},
	BuiltinNameTomlStringify: {
		signature: "toml_stringify(value)",
		summary:   "Serializes a hash or struct as TOML. The top level must be a table -- TOML has no other document shape -- and a buffer is written as hex, matching yaml_stringify.",
		params:    []builtinParamDoc{param("value", "Table to serialize.", ParamHash, ParamStruct)},
		returns:   pairRet("the TOML text", ParamString)},
	BuiltinNameCborParse: {
		signature: "cbor_parse(data)",
		summary:   "Parses CBOR -- COSE, WebAuthn, IoT telemetry. Byte strings decode to buffers, not text; tagged items are preserved as {_cbor_tag, value} rather than dropped; integer map keys are supported (COSE labels them that way); duplicate keys are refused. Nesting is capped at 64 levels.",
		params:    []builtinParamDoc{param("data", "CBOR bytes.", ParamBytes, ParamString)},
		returns:   pairRet("the decoded value", ParamAny)},
	BuiltinNameCborEncode: {
		signature: "cbor_encode(value)",
		summary:   "Serializes a Mutant value as canonical CBOR: map keys are sorted and integers use their shortest form, so hash_sha256(cbor_encode(v)) is a stable identifier for v. A buffer encodes as a CBOR byte string.",
		params: []builtinParamDoc{param("value", "Value to encode: a scalar, buffer, null, array, hash, or struct.",
			ParamString, ParamBytes, ParamInt, ParamFloat, ParamBool, ParamNull, ParamArray, ParamHash, ParamStruct)},
		returns: pairRet("the encoded bytes", ParamBytes)},
	BuiltinNameMsgpackParse: {
		signature: "msgpack_parse(data)",
		summary:   "Parses MessagePack -- agent check-ins, queue payloads, Fluentd forward traffic. Binary values decode to buffers, not text. Input carrying more than one value is reported rather than ignored: a blob that decodes and keeps going is either a stream or not what it was thought to be.",
		params:    []builtinParamDoc{param("data", "MessagePack bytes.", ParamBytes, ParamString)},
		returns:   pairRet("the decoded value", ParamAny)},
	BuiltinNameMsgpackEncode: {
		signature: "msgpack_encode(value)",
		summary:   "Serializes a Mutant value as MessagePack with sorted map keys and compact integers, so the output is deterministic for a given value.",
		params: []builtinParamDoc{param("value", "Value to encode: a scalar, buffer, null, array, hash, or struct.",
			ParamString, ParamBytes, ParamInt, ParamFloat, ParamBool, ParamNull, ParamArray, ParamHash, ParamStruct)},
		returns: pairRet("the encoded bytes", ParamBytes)},
	BuiltinNameProtobufParse: {
		signature: "protobuf_parse(data)",
		summary:   "Walks protobuf wire format without a .proto -- the situation an analyst holding a gRPC capture is actually in. Each field reports {field, wire_type, offset} plus every reading its bytes admit: a varint as itself, as zigzag and as bool; a length-delimited field as bytes, plus text and message when those parse. Naming the ambiguity is the honest thing a schemaless reader can do.",
		params:    []builtinParamDoc{param("data", "Protobuf-encoded bytes.", ParamBytes, ParamString)},
		returns:   pairRet("one hash per field, in wire order", ParamArray).ofElem(ParamHash).withFields("field", "offset", "wire_type")},
	BuiltinNameDerParse: {
		signature: "der_parse(data)",
		summary:   "Walks DER/ASN.1 structurally, without a schema -- what x509_parse and pem_decode already need internally, and what a certificate extension or a Kerberos ticket needs when no ASN.1 module is at hand. Each node reports {offset, header_len, length, class, tag, constructed, tag_name}, constructed nodes carry children, and primitives carry raw value bytes plus a decoded rendering for universal types (OIDs dotted, big INTEGERs as decimal text rather than truncated, times as RFC 3339). BER indefinite length is refused by name.",
		params:    []builtinParamDoc{param("data", "DER-encoded bytes.", ParamBytes, ParamString)},
		returns:   pairRet("the top-level nodes, each a tree", ParamArray).ofElem(ParamHash).withFields("class", "constructed", "header_len", "length", "offset", "tag", "tag_name")},
	BuiltinNameLuaRunString: {signature: "lua_run_string(code)", summary: "Runs a Lua script from a string.", returns: pairRet("the script's result, or the error it raised", ParamHash).withFields("error", "ok", "result", "schema_version"), params: []builtinParamDoc{param("code", "Lua source to run.", ParamString)}},
	BuiltinNameLuaRunFile:   {signature: "lua_run_file(path)", summary: "Runs a Lua script from a file.", returns: pairRet("the script's result, or the error it raised", ParamHash).withFields("error", "ok", "result", "schema_version"), params: []builtinParamDoc{param("path", "Path to the Lua script.", ParamString)}},
	BuiltinNameLuaRunHttp:   {signature: "lua_run_http(url)", summary: "Fetches and runs a Lua script from an HTTP endpoint in a restricted sandbox (no io, no os.execute/exit/remove; only safe base/math/string/table/os-time libraries).", returns: pairRet("the script's result, or the error it raised", ParamHash).withFields("error", "ok", "result", "schema_version"), params: []builtinParamDoc{param("url", "URL the script is fetched from.", ParamString)}},
	// Parameter kinds below are verified against builtin/strings_builtins.go:
	// the whole family routes through requireStringArg/requireIntArg, so every
	// parameter is strictly typed. str_format is the one exception — its
	// variadic tail formats any value (the default branch calls Inspect()).
	BuiltinNameStrUpper:      {signature: "str_upper(s)", summary: "Returns s with all letters upper-cased.", params: []builtinParamDoc{param("s", "Source string.", ParamString)}, returns: ret("s with all letters upper-cased", ParamString)},
	BuiltinNameStrLower:      {signature: "str_lower(s)", summary: "Returns s with all letters lower-cased.", params: []builtinParamDoc{param("s", "Source string.", ParamString)}, returns: ret("s with all letters lower-cased", ParamString)},
	BuiltinNameStrTrim:       {signature: "str_trim(s)", summary: "Returns s with leading and trailing whitespace removed.", params: []builtinParamDoc{param("s", "Source string.", ParamString)}, returns: ret("s with leading and trailing whitespace removed", ParamString)},
	BuiltinNameStrTrimLeft:   {signature: "str_trim_left(s, cutset)", summary: "Trims any leading characters in cutset from s.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("cutset", "Characters to trim from the left.", ParamString)}, returns: ret("s with the leading cutset characters removed", ParamString)},
	BuiltinNameStrTrimRight:  {signature: "str_trim_right(s, cutset)", summary: "Trims any trailing characters in cutset from s.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("cutset", "Characters to trim from the right.", ParamString)}, returns: ret("s with the trailing cutset characters removed", ParamString)},
	BuiltinNameStrTrimPrefix: {signature: "str_trim_prefix(s, prefix)", summary: "Removes prefix from s if present.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("prefix", "Prefix to remove.", ParamString)}, returns: ret("s without prefix, or s unchanged when it did not start with prefix", ParamString)},
	BuiltinNameStrTrimSuffix: {signature: "str_trim_suffix(s, suffix)", summary: "Removes suffix from s if present.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("suffix", "Suffix to remove.", ParamString)}, returns: ret("s without suffix, or s unchanged when it did not end with suffix", ParamString)},
	BuiltinNameStrStartsWith: {signature: "str_starts_with(s, prefix)", summary: "Returns whether s begins with prefix.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("prefix", "Prefix to test for.", ParamString)}, returns: ret("whether s begins with prefix", ParamBool)},
	BuiltinNameStrEndsWith:   {signature: "str_ends_with(s, suffix)", summary: "Returns whether s ends with suffix.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("suffix", "Suffix to test for.", ParamString)}, returns: ret("whether s ends with suffix", ParamBool)},
	BuiltinNameStrJoin:       {signature: "str_join(array, sep)", summary: "Joins an array of strings with sep (inverse of text_split).", params: []builtinParamDoc{arrayParam("array", "Array of STRING elements to join; a non-string element is an error.", ParamString), param("sep", "Separator placed between elements.", ParamString)}, returns: ret("the elements joined by sep", ParamString)},
	BuiltinNameStrRepeat:     {signature: "str_repeat(s, n)", summary: "Returns s repeated n times.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("n", "Repeat count; must be non-negative.", ParamInt)}, returns: ret("s repeated n times", ParamString)},
	BuiltinNameStrPadLeft:    {signature: "str_pad_left(s, width, pad)", summary: "Left-pads s with pad until it reaches width runes.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("width", "Target width in runes.", ParamInt), param("pad", "Padding string; must be non-empty.", ParamString)}, returns: ret("s left-padded to width runes", ParamString)},
	BuiltinNameStrPadRight:   {signature: "str_pad_right(s, width, pad)", summary: "Right-pads s with pad until it reaches width runes.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("width", "Target width in runes.", ParamInt), param("pad", "Padding string; must be non-empty.", ParamString)}, returns: ret("s right-padded to width runes", ParamString)},
	BuiltinNameStrReverse:    {signature: "str_reverse(s)", summary: "Returns s reversed (rune-aware).", params: []builtinParamDoc{param("s", "Source string.", ParamString)}, returns: ret("s reversed (rune-aware)", ParamString)},
	BuiltinNameStrSubstr:     {signature: "str_substr(s, start, length)", summary: "Returns length runes of s starting at rune index start (clamped to bounds).", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("start", "Starting rune index; must be non-negative.", ParamInt), param("length", "Number of runes to take; must be non-negative.", ParamInt)}, returns: ret("length runes of s starting at rune index start (clamped to bounds)", ParamString)},
	BuiltinNameStrCharAt:     {signature: "str_char_at(s, index)", summary: "Returns the rune at index as a string.", params: []builtinParamDoc{param("s", "Source string.", ParamString), param("index", "Rune index; must be within the string.", ParamInt)}, returns: ret("the rune at index as a string", ParamString)},
	BuiltinNameStrFormat:     {signature: "str_format(format, ...values)", summary: "Returns a printf-style formatted string (like putf but returns instead of printing).", params: []builtinParamDoc{param("format", "Printf-style format string.", ParamString), param("...values", "Values interpolated into format; any type is accepted.", ParamAny)}, returns: ret("a printf-style formatted string (like putf but returns instead of printing)", ParamString)},
	BuiltinNameStrTitle:      {signature: "str_title(s)", summary: "Upper-cases the first letter of each word in s.", params: []builtinParamDoc{param("s", "Source string.", ParamString)}, returns: ret("s with the first letter of each word upper-cased", ParamString)},
	// generic: hashing & IDs
	// Every digest builtin funnels through hashOneString → requireStringArg, so
	// they all take exactly one STRING. Byte buffers are STRING values in
	// Mutant, so hashing bytes needs no separate kind.
	BuiltinNameHashMD5: {
		signature: "hash_md5(s)", summary: "Returns the lowercase hex MD5 digest of s.",
		params:  []builtinParamDoc{param("s", "Text or buffer to digest.", ParamString, ParamBytes)},
		returns: ret("the lowercase hex MD5 digest of s", ParamString)},
	BuiltinNameHashSHA1: {
		signature: "hash_sha1(s)", summary: "Returns the lowercase hex SHA-1 digest of s.",
		params:  []builtinParamDoc{param("s", "Text or buffer to digest.", ParamString, ParamBytes)},
		returns: ret("the lowercase hex SHA-1 digest of s", ParamString)},
	BuiltinNameHashSHA256: {
		signature: "hash_sha256(s)", summary: "Returns the lowercase hex SHA-256 digest of s.",
		params:  []builtinParamDoc{param("s", "Text or buffer to digest.", ParamString, ParamBytes)},
		returns: ret("the lowercase hex SHA-256 digest of s", ParamString)},
	BuiltinNameHashSHA512: {
		signature: "hash_sha512(s)", summary: "Returns the lowercase hex SHA-512 digest of s.",
		params:  []builtinParamDoc{param("s", "Text or buffer to digest.", ParamString, ParamBytes)},
		returns: ret("the lowercase hex SHA-512 digest of s", ParamString)},
	BuiltinNameHashCRC32: {
		signature: "hash_crc32(s)", summary: "Returns the CRC-32 (IEEE) checksum of s as 8 hex chars.",
		params:  []builtinParamDoc{param("s", "Text or buffer to checksum.", ParamString, ParamBytes)},
		returns: ret("the CRC-32 (IEEE) checksum of s as 8 hex chars", ParamString)},
	BuiltinNameHashBlake2: {
		signature: "hash_blake2(s)", summary: "Returns the lowercase hex BLAKE2b-256 digest of s.",
		params:  []builtinParamDoc{param("s", "Text or buffer to digest.", ParamString, ParamBytes)},
		returns: ret("the lowercase hex BLAKE2b-256 digest of s", ParamString)},
	BuiltinNameHMAC: {
		signature: "hmac(key, message, algo)", summary: "Returns the hex HMAC of message under key. algo is md5/sha1/sha256/sha512.",
		params: []builtinParamDoc{
			param("key", "Secret key; text or buffer.", ParamString, ParamBytes),
			param("message", "Message to authenticate; text or buffer.", ParamString, ParamBytes),
			param("algo", "Hash algorithm: md5/sha1/sha256/sha512.", ParamString),
		},
		returns: ret("the hex HMAC of message under key", ParamString)},
	BuiltinNameUUIDv4: {signature: "uuid_v4()", summary: "Returns a random (v4) UUID string.", returns: ret("a random (v4) UUID string", ParamString)},
	BuiltinNameUUIDv7: {signature: "uuid_v7()", summary: "Returns a time-ordered (v7) UUID string.", returns: ret("a time-ordered (v7) UUID string", ParamString)},
	BuiltinNameRandomHex: {
		signature: "random_hex(n)", summary: "Returns n cryptographically-random bytes as a 2n-char hex string.",
		params:  []builtinParamDoc{param("n", "Number of random bytes.", ParamInt)},
		returns: ret("n cryptographically-random bytes as a 2n-char hex string", ParamString)},
	BuiltinNameNanoID: {
		signature: "nanoid(n)", summary: "Returns a URL-safe random identifier of length n.",
		params:  []builtinParamDoc{param("n", "Identifier length in characters.", ParamInt)},
		returns: ret("a URL-safe random identifier of length n", ParamString)},
	// generic: math
	// The math builtins take their operands through requireNumericArg, which
	// accepts INTEGER and FLOAT and rejects everything else
	// (builtin/math_builtins.go). rand_int / rand_bytes are the exceptions:
	// they require whole INTEGERs.
	BuiltinNameAbs: {
		signature: "abs(x)", summary: "Absolute value (preserves INTEGER/FLOAT type).",
		params:  []builtinParamDoc{param("x", "Number to take the magnitude of.", ParamInt, ParamFloat)},
		returns: ret("the absolute value, INTEGER for an integer argument and FLOAT for a float one", ParamInt, ParamFloat)},
	// The leading `value` is not decoration: min/max reject a zero-argument
	// call, and `...values` alone would read as "zero or more".
	BuiltinNameMin: {
		signature: "min(value, ...values)", summary: "Returns the smallest of the numeric arguments (original type preserved).",
		params: []builtinParamDoc{
			param("value", "First number to compare.", ParamInt, ParamFloat),
			param("...values", "Further numbers to compare.", ParamInt, ParamFloat),
		},
		returns: ret("the smallest argument, keeping its own numeric type", ParamInt, ParamFloat)},
	BuiltinNameMax: {
		signature: "max(value, ...values)", summary: "Returns the largest of the numeric arguments (original type preserved).",
		params: []builtinParamDoc{
			param("value", "First number to compare.", ParamInt, ParamFloat),
			param("...values", "Further numbers to compare.", ParamInt, ParamFloat),
		},
		returns: ret("the largest argument, keeping its own numeric type", ParamInt, ParamFloat)},
	BuiltinNameClamp: {
		signature: "clamp(x, lo, hi)", summary: "Constrains x to the range [lo, hi].",
		params: []builtinParamDoc{
			param("x", "Number to constrain.", ParamInt, ParamFloat),
			param("lo", "Lower bound; must not exceed hi.", ParamInt, ParamFloat),
			param("hi", "Upper bound.", ParamInt, ParamFloat),
		},
		returns: ret("x constrained to [lo, hi], keeping its own numeric type", ParamInt, ParamFloat)},
	BuiltinNamePow: {
		signature: "pow(x, y)", summary: "Returns x raised to the power y (FLOAT).",
		params: []builtinParamDoc{
			param("x", "Base.", ParamInt, ParamFloat),
			param("y", "Exponent.", ParamInt, ParamFloat),
		},
		returns: ret("x raised to the power y (FLOAT)", ParamFloat)},
	BuiltinNameSqrt: {
		signature: "sqrt(x)", summary: "Returns the square root of x (FLOAT); errors on negative x.",
		params:  []builtinParamDoc{param("x", "Non-negative number.", ParamInt, ParamFloat)},
		returns: ret("the square root of x (FLOAT); errors on negative x", ParamFloat)},
	BuiltinNameMod: {
		signature: "mod(a, b)", summary: "Returns a modulo b; errors on b=0. Integer mod when both are INTEGER.",
		params: []builtinParamDoc{
			param("a", "Dividend.", ParamInt, ParamFloat),
			param("b", "Divisor; must not be zero.", ParamInt, ParamFloat),
		},
		returns: ret("a modulo b; errors on b=0", ParamInt, ParamFloat)},
	BuiltinNameFloor: {
		signature: "floor(x)", summary: "Largest integer <= x (INTEGER).",
		params:  []builtinParamDoc{param("x", "Number to round down.", ParamInt, ParamFloat)},
		returns: ret("the largest integer less than or equal to x", ParamInt)},
	BuiltinNameCeil: {
		signature: "ceil(x)", summary: "Smallest integer >= x (INTEGER).",
		params:  []builtinParamDoc{param("x", "Number to round up.", ParamInt, ParamFloat)},
		returns: ret("the smallest integer greater than or equal to x", ParamInt)},
	BuiltinNameRound: {
		signature: "round(x)", summary: "Nearest integer to x (INTEGER).",
		params:  []builtinParamDoc{param("x", "Number to round.", ParamInt, ParamFloat)},
		returns: ret("the integer nearest to x", ParamInt)},
	// Both reject a non-numeric element through requireNumericArg
	// (math_builtins.go, "element %d must be numeric"), so their elements are
	// INTEGER or FLOAT.
	BuiltinNameSum: {
		signature: "sum(array)", summary: "Sum of a numeric array (INTEGER if all elements are integers).",
		params:  []builtinParamDoc{arrayParam("array", "Array whose elements are all numbers.", ParamInt, ParamFloat)},
		returns: ret("the total, INTEGER when every element is an integer and FLOAT otherwise", ParamInt, ParamFloat)},
	BuiltinNameAvg: {
		signature: "avg(array)", summary: "Arithmetic mean of a numeric array (FLOAT); errors on empty.",
		params:  []builtinParamDoc{arrayParam("array", "Non-empty array whose elements are all numbers.", ParamInt, ParamFloat)},
		returns: ret("the arithmetic mean of the array's elements", ParamFloat)},
	BuiltinNameRand: {signature: "rand()", summary: "Returns a random FLOAT in [0, 1).", returns: ret("a random FLOAT in [0, 1)", ParamFloat)},
	BuiltinNameRandInt: {
		signature: "rand_int(lo, hi)", summary: "Returns a random INTEGER in [lo, hi).",
		params: []builtinParamDoc{
			param("lo", "Inclusive lower bound.", ParamInt),
			param("hi", "Exclusive upper bound; must be greater than lo.", ParamInt),
		},
		returns: ret("a random INTEGER in [lo, hi)", ParamInt)},
	BuiltinNameRandBytes: {
		signature: "rand_bytes(n)", summary: "Returns n cryptographically-random bytes (as a byte string).",
		params:  []builtinParamDoc{param("n", "Number of random bytes.", ParamInt)},
		returns: ret("n cryptographically-random bytes (as a byte string)", ParamString)},
	BuiltinNameMathPi: {signature: "math_pi()", summary: "Returns the constant pi.", returns: ret("the constant pi", ParamFloat)},
	BuiltinNameMathE:  {signature: "math_e()", summary: "Returns the constant e.", returns: ret("the constant e", ParamFloat)},
	// generic: encoding (decoders return (value, err))
	// The codecs all take one STRING (encOneString / requireStringArg in
	// builtin/encoding_builtins.go). Encoded bytes are STRING values too, so
	// the decoders' inputs are STRING as well.
	BuiltinNameBase64Encode:        {signature: "base64_encode(s)", summary: "Standard base64-encodes s.", params: []builtinParamDoc{param("s", "Text or buffer to encode.", ParamString, ParamBytes)}, returns: ret("the standard base64 text", ParamString)},
	BuiltinNameBase64Decode:        {signature: "base64_decode(s)", summary: "Decodes standard base64; returns (bytes, err).", params: []builtinParamDoc{param("s", "Standard base64 text.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameBase64URLEncode:     {signature: "base64url_encode(s)", summary: "URL-safe base64-encodes s.", params: []builtinParamDoc{param("s", "Text or buffer to encode.", ParamString, ParamBytes)}, returns: ret("the URL-safe base64 text", ParamString)},
	BuiltinNameBase64URLDecode:     {signature: "base64url_decode(s)", summary: "Decodes URL-safe base64; returns (bytes, err).", params: []builtinParamDoc{param("s", "URL-safe base64 text.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameBase32Encode:        {signature: "base32_encode(s)", summary: "Standard base32-encodes s.", params: []builtinParamDoc{param("s", "Text or buffer to encode.", ParamString, ParamBytes)}, returns: ret("the standard base32 text", ParamString)},
	BuiltinNameBase32Decode:        {signature: "base32_decode(s)", summary: "Decodes standard base32; returns (bytes, err).", params: []builtinParamDoc{param("s", "Standard base32 text.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameHexEncode:           {signature: "hex_encode(s)", summary: "Hex-encodes a byte string to lowercase hex.", params: []builtinParamDoc{param("s", "Text or buffer to encode.", ParamString, ParamBytes)}, returns: ret("the lowercase hex text", ParamString)},
	BuiltinNameBase64DecodeBytes:   {signature: "base64_decode_bytes(s)", summary: "Decodes standard base64 into a BYTES buffer; returns (bytes, err).", params: []builtinParamDoc{param("s", "Standard base64 text.", ParamString)}, returns: pairRet("the decoded bytes", ParamBytes)},
	BuiltinNameHexDecodeBytes:      {signature: "hex_decode_bytes(s)", summary: "Decodes a hex string into a BYTES buffer; returns (bytes, err).", params: []builtinParamDoc{param("s", "Hex text to decode.", ParamString)}, returns: pairRet("the decoded bytes", ParamBytes)},
	BuiltinNameGunzipBytes:         {signature: "gunzip_bytes(s, max_bytes?)", summary: "Gzip-decompresses s into a BYTES buffer; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise.", params: []builtinParamDoc{param("s", "Gzip-compressed data.", ParamString, ParamBytes), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit.", ParamInt)}, returns: pairRet("the decompressed bytes", ParamBytes)},
	BuiltinNameZlibDecompressBytes: {signature: "zlib_decompress_bytes(s, max_bytes?)", summary: "Zlib-decompresses s into a BYTES buffer; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise.", params: []builtinParamDoc{param("s", "Zlib-compressed data.", ParamString, ParamBytes), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit.", ParamInt)}, returns: pairRet("the decompressed bytes", ParamBytes)},
	BuiltinNameHexDecode:           {signature: "hex_decode(s)", summary: "Decodes a hex string to bytes; returns (bytes, err).", params: []builtinParamDoc{param("s", "Hex text to decode.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameURLEncode:           {signature: "url_encode(s)", summary: "URL query-escapes s.", params: []builtinParamDoc{param("s", "Text to escape.", ParamString)}, returns: ret("the query-escaped text", ParamString)},
	BuiltinNameURLDecode:           {signature: "url_decode(s)", summary: "URL query-unescapes s; returns (value, err).", params: []builtinParamDoc{param("s", "Escaped text to unescape.", ParamString)}, returns: pairRet("the unescaped text", ParamString)},
	BuiltinNameGzip:                {signature: "gzip(s)", summary: "Gzip-compresses s (returns a byte string).", params: []builtinParamDoc{param("s", "Text or buffer to compress.", ParamString, ParamBytes)}, returns: ret("the compressed bytes", ParamString)},
	BuiltinNameGunzip:              {signature: "gunzip(s, max_bytes?)", summary: "Gzip-decompresses s; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise.", params: []builtinParamDoc{param("s", "Gzip-compressed data.", ParamString, ParamBytes), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit.", ParamInt)}, returns: pairRet("the decompressed bytes", ParamString)},
	BuiltinNameZlibCompress:        {signature: "zlib_compress(s)", summary: "Zlib-compresses s (returns a byte string).", params: []builtinParamDoc{param("s", "Text or buffer to compress.", ParamString, ParamBytes)}, returns: ret("the compressed bytes", ParamString)},
	BuiltinNameZlibDecompress:      {signature: "zlib_decompress(s, max_bytes?)", summary: "Zlib-decompresses s; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise.", params: []builtinParamDoc{param("s", "Zlib-compressed data.", ParamString, ParamBytes), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit.", ParamInt)}, returns: pairRet("the decompressed bytes", ParamString)},
	BuiltinNameToBase: {
		signature: "to_base(n, base)", summary: "Formats integer n in the given base (2–36).",
		params: []builtinParamDoc{
			param("n", "Integer to format.", ParamInt),
			param("base", "Radix between 2 and 36.", ParamInt),
		},
		returns: ret("n written in the given base", ParamString)},
	BuiltinNameFromBase: {
		signature: "from_base(s, base)", summary: "Parses s as an integer in the given base (2–36); returns (int, err).",
		params: []builtinParamDoc{
			param("s", "Digits to parse.", ParamString),
			param("base", "Radix between 2 and 36.", ParamInt),
		},
		returns: pairRet("the integer s denotes in the given base", ParamInt)},
	// generic: type conversion & introspection
	//
	// The to_* conversions switch on the concrete object type and error on
	// anything outside their case list (builtin/convert_builtins.go), so their
	// accepted sets are exact. to_string is the exception: its default branch
	// falls back to Inspect(), so it genuinely accepts every value.
	BuiltinNameToInt: {
		signature: "to_int(v)", summary: "Converts a number/bool/string to INTEGER; returns (int, err).",
		params:  []builtinParamDoc{param("v", "Value to convert; numbers, booleans, and numeric strings are accepted.", ParamInt, ParamFloat, ParamBool, ParamString)},
		returns: pairRet("the integer value", ParamInt)},
	BuiltinNameToFloat: {
		signature: "to_float(v)", summary: "Converts a number/bool/string to FLOAT; returns (float, err).",
		params:  []builtinParamDoc{param("v", "Value to convert; numbers, booleans, and numeric strings are accepted.", ParamInt, ParamFloat, ParamBool, ParamString)},
		returns: pairRet("the floating-point value", ParamFloat)},
	BuiltinNameToString: {
		signature: "to_string(v)", summary: "Converts any value to its STRING representation.",
		params:  []builtinParamDoc{param("v", "Value to render; any type is accepted.", ParamAny)},
		returns: ret("the value's string representation", ParamString)},
	BuiltinNameToBool: {
		signature: "to_bool(v)", summary: "Converts a bool/number/string to BOOLEAN; returns (bool, err).",
		params:  []builtinParamDoc{param("v", "Value to convert; booleans, numbers, and \"true\"/\"false\" strings are accepted.", ParamBool, ParamInt, ParamFloat, ParamString)},
		returns: pairRet("the boolean value", ParamBool)},
	BuiltinNameParseInt: {
		signature: "parse_int(s, base)", summary: "Parses s as an integer in base (0 auto-detects); returns (int, err).",
		params: []builtinParamDoc{
			param("s", "Text to parse.", ParamString),
			param("base", "Radix: 0 to auto-detect, otherwise 2 to 36.", ParamInt),
		},
		returns: pairRet("the integer s denotes", ParamInt)},
	BuiltinNameParseFloat: {
		signature: "parse_float(s)", summary: "Parses s as a float; returns (float, err).",
		params:  []builtinParamDoc{param("s", "Text to parse.", ParamString)},
		returns: pairRet("the floating-point number s denotes", ParamFloat)},
	BuiltinNameTypeOf: {
		signature: "type_of(v)", summary: "Returns the object type name of v (e.g. INTEGER, STRING, ARRAY).",
		params:  []builtinParamDoc{param("v", "Value to inspect; any type is accepted.", ParamAny)},
		returns: ret("the object type name of v (e", ParamString)},
	BuiltinNameIsNull: {
		signature: "is_null(v)", summary: "Returns whether v is NULL.",
		params:  []builtinParamDoc{param("v", "Value to test; any type is accepted.", ParamAny)},
		returns: ret("whether v is NULL", ParamBool)},
	BuiltinNameError: {
		signature: "error(message, context?, related?)", summary: "Constructs an error value carrying a message, an origin, and any related facts. Single-return: it cannot fail.",
		params: []builtinParamDoc{
			param("message", "What went wrong.", ParamString),
			param("context?", "Where it went wrong; defaults to \"user\".", ParamString),
			param("related?", "Facts to carry along, keyed by STRING. Values keep their types.", ParamHash),
		},
		returns: ret("an error carrying message, context and related, stamped with the call position", ParamError)},
	// generic: time & date (epoch seconds; Go reference layout, e.g. \"2006-01-02 15:04:05\")
	BuiltinNameTimeNow:  {signature: "time_now()", summary: "Returns the current UTC time as a hash {unix, iso, year, month, day, hour, minute, second}.", returns: ret("the current UTC time, broken into fields", ParamHash).withFields("day", "hour", "iso", "minute", "month", "second", "unix", "year")},
	BuiltinNameTimeUnix: {signature: "time_unix()", summary: "Returns the current Unix time in seconds.", returns: ret("the current Unix time in seconds", ParamInt)},
	// Unix timestamps are whole seconds: requireIntArg, not requireNumericArg.
	BuiltinNameTimeFormat: {
		signature: "time_format(unix, layout)", summary: "Formats a Unix timestamp (UTC) using a Go reference layout.",
		params: []builtinParamDoc{
			param("unix", "Unix timestamp in seconds.", ParamInt),
			param("layout", "Go reference layout, e.g. \"2006-01-02 15:04:05\".", ParamString),
		},
		returns: ret("the formatted timestamp", ParamString)},
	BuiltinNameTimeParse: {
		signature: "time_parse(value, layout)", summary: "Parses value with a Go reference layout; returns (unixSeconds, err).",
		params: []builtinParamDoc{
			param("value", "Timestamp text to parse.", ParamString),
			param("layout", "Go reference layout the value is written in.", ParamString),
		},
		returns: pairRet("the parsed time as Unix seconds", ParamInt)},
	BuiltinNameTimeDiff: {
		signature: "time_diff(a, b)", summary: "Returns a - b in seconds (both Unix timestamps).",
		params: []builtinParamDoc{
			param("a", "Later Unix timestamp in seconds.", ParamInt),
			param("b", "Earlier Unix timestamp in seconds.", ParamInt),
		},
		returns: ret("a - b in seconds (both Unix timestamps)", ParamInt)},
	BuiltinNameTimeAdd: {
		signature: "time_add(unix, seconds)", summary: "Returns the Unix timestamp shifted by seconds.",
		params: []builtinParamDoc{
			param("unix", "Unix timestamp in seconds.", ParamInt),
			param("seconds", "Offset in seconds; may be negative.", ParamInt),
		},
		returns: ret("the Unix timestamp shifted by seconds", ParamInt)},
	// generic: collections (array + hash operations; return new values, never mutate)
	//
	// The array operations all run their first argument through
	// requireArrayArg and the hash operations through requireHashArg, so ARRAY
	// and HASH here are exact. Element and key/value parameters compared with
	// objectsEqual accept anything.
	BuiltinNameSort: {
		signature: "sort(array)", summary: "Returns a sorted copy of an array (all numbers or all strings).",
		params:  []builtinParamDoc{param("array", "Array of numbers or array of strings.", ParamArray)},
		returns: ret("a sorted copy of an array (all numbers or all strings)", ParamArray)},
	BuiltinNameReverseArray: {
		signature: "reverse(array)", summary: "Returns a reversed copy of an array.",
		params:  []builtinParamDoc{param("array", "Array to reverse.", ParamArray)},
		returns: ret("a reversed copy of an array", ParamArray)},
	BuiltinNameContains: {
		signature: "contains(array, value)", summary: "Returns whether array contains value (by value equality).",
		params: []builtinParamDoc{
			param("array", "Array to search.", ParamArray),
			param("value", "Value to look for; any type is accepted.", ParamAny),
		},
		returns: ret("whether array contains value (by value equality)", ParamBool)},
	BuiltinNameIndexOf: {
		signature: "index_of(array, value)", summary: "Returns the first index of value in array, or -1.",
		params: []builtinParamDoc{
			param("array", "Array to search.", ParamArray),
			param("value", "Value to look for; any type is accepted.", ParamAny),
		},
		returns: ret("the first index of value in array, or -1", ParamInt)},
	BuiltinNameSlice: {
		signature: "slice(array, start, end)", summary: "Returns the sub-array array[start:end] (bounds-clamped).",
		params: []builtinParamDoc{
			param("array", "Array to slice.", ParamArray),
			param("start", "Start index, inclusive.", ParamInt),
			param("end", "End index, exclusive.", ParamInt),
		},
		returns: ret("the sub-array array[start:end] (bounds-clamped)", ParamArray)},
	BuiltinNameConcat: {
		signature: "concat(a, b)", summary: "Returns a new array with the elements of a followed by b.",
		params: []builtinParamDoc{
			param("a", "First array.", ParamArray),
			param("b", "Second array.", ParamArray),
		},
		returns: ret("a new array with the elements of a followed by b", ParamArray)},
	BuiltinNameFlatten: {
		signature: "flatten(array)", summary: "Flattens one level of nested arrays.",
		params:  []builtinParamDoc{param("array", "Array whose nested arrays are spliced in.", ParamArray)},
		returns: ret("a new array with one level of nesting removed", ParamArray)},
	BuiltinNameUnique: {
		signature: "unique(array)", summary: "Returns a new array with duplicate values removed (order preserved).",
		params:  []builtinParamDoc{param("array", "Array to de-duplicate.", ParamArray)},
		returns: ret("a new array with duplicate values removed (order preserved)", ParamArray)},
	BuiltinNameRange: {
		signature: "range(start, end, step?)", summary: "Returns an array of integers from start (inclusive) to end (exclusive); step defaults to 1.",
		params: []builtinParamDoc{
			param("start", "First value, inclusive.", ParamInt),
			param("end", "Stop value, exclusive.", ParamInt),
			param("step?", "Increment; defaults to 1 and must not be zero.", ParamInt),
		},
		returns: ret("an array of integers from start (inclusive) to end (exclusive); step defaults to 1", ParamArray).ofElem(ParamInt)},
	BuiltinNameZip: {
		signature: "zip(a, b)", summary: "Returns an array of [a[i], b[i]] pairs up to the shorter length.",
		params: []builtinParamDoc{
			param("a", "First array.", ParamArray),
			param("b", "Second array.", ParamArray),
		},
		returns: ret("an array of [a[i], b[i]] pairs up to the shorter length", ParamArray)},
	// map/filter/reduce/each/sort_by are intercepted by the executor rather
	// than run as ordinary builtins; both the VM (vm/higher_order.go) and the
	// evaluator (evaluator/higher_order.go) require an ARRAY and a callable.
	// The callback's own arity stays prose — it is not modelled here.
	BuiltinNameMap: {
		signature: "map(array, fn)", summary: "Returns a new array of fn applied to each element. fn takes (element) or (element, index).",
		params: []builtinParamDoc{
			param("array", "Array to transform.", ParamArray),
			param("fn", "Function called per element: (element) or (element, index).", ParamFn),
		},
		returns: ret("a new array holding the callback's result for each element", ParamArray)},
	BuiltinNameFilter: {
		signature: "filter(array, fn)", summary: "Returns a new array of the elements for which fn is truthy. fn takes (element) or (element, index).",
		params: []builtinParamDoc{
			param("array", "Array to filter.", ParamArray),
			param("fn", "Predicate called per element: (element) or (element, index).", ParamFn),
		},
		returns: ret("a new array of the elements the callback accepted", ParamArray)},
	BuiltinNameReduce: {
		signature: "reduce(array, fn, initial)", summary: "Folds the array to a single value: fn(accumulator, element) starting from initial.",
		params: []builtinParamDoc{
			param("array", "Array to fold.", ParamArray),
			param("fn", "Reducer called as (accumulator, element).", ParamFn),
			param("initial", "Starting accumulator; any type is accepted.", ParamAny),
		},
		returns: ret("the final accumulator value", ParamAny)},
	BuiltinNameEach: {
		signature: "each(array, fn)", summary: "Calls fn for each element for its side effects and returns null. fn takes (element) or (element, index).",
		params: []builtinParamDoc{
			param("array", "Array to iterate.", ParamArray),
			param("fn", "Function called per element: (element) or (element, index).", ParamFn),
		},
		returns: ret("null; each is called for its side effects", ParamNull)},
	BuiltinNamePMap: {
		signature: "pmap(array, fn, workers?)", summary: "Like map, but applies fn to elements concurrently and returns results in the original order. fn takes (element) or (element, index). Each worker runs on its own VM with a snapshot of globals, so fn should be self-contained: it cannot write back to a global.",
		params: []builtinParamDoc{
			param("array", "Array to transform.", ParamArray),
			param("fn", "Function called per element: (element) or (element, index).", ParamFn),
			param("workers?", "Maximum concurrent workers; defaults to the CPU count, capped by the array length.", ParamInt),
		},
		returns: ret("a new array holding the callback's result for each element, in the input's order", ParamArray)},
	BuiltinNamePEach: {
		signature: "peach(array, fn, workers?)", summary: "Like each, but calls fn on elements concurrently for their side effects and returns null. fn takes (element) or (element, index). Each worker runs on its own VM with a snapshot of globals, so fn should report through a shared store (cache_*/db_*) rather than by assigning to a global.",
		params: []builtinParamDoc{
			param("array", "Array to iterate.", ParamArray),
			param("fn", "Function called per element: (element) or (element, index).", ParamFn),
			param("workers?", "Maximum concurrent workers; defaults to the CPU count, capped by the array length.", ParamInt),
		},
		returns: ret("null; peach is called for its side effects", ParamNull)},
	BuiltinNameSpawn: {
		signature: "spawn(fn, arg?)", summary: "Runs fn on its own VM alongside the rest of the program and returns a task handle to collect it with. fn takes no arguments, or one if arg is given. The task sees a snapshot of globals taken at the spawn, so it should report back through its return value or a channel rather than by assigning to a global.",
		params: []builtinParamDoc{
			param("fn", "Function to run concurrently: () or (arg).", ParamFn),
			param("arg?", "Value passed to fn; any type is accepted.", ParamAny),
		},
		returns: pairRet("a task handle; collect it with task_wait", ParamInt)},
	BuiltinNameTaskWait: {
		signature: "task_wait(handle, timeoutMs?)", summary: "Waits for a spawned task and returns the value its function returned. Whatever stopped the task arrives in the error slot. Without a timeout it waits indefinitely; running out of time is reported as an error and leaves the task collectable. Collecting a task releases its handle, so wait for it once.",
		params: []builtinParamDoc{
			param("handle", "Task handle from spawn.", ParamInt),
			param("timeoutMs?", "How long to wait, in milliseconds; omit to wait indefinitely.", ParamInt),
		},
		returns: pairRet("the value the task's function returned", ParamAny)},
	BuiltinNameTaskDone: {
		signature: "task_done(handle)", summary: "Reports whether a spawned task has finished, without waiting for it.",
		params: []builtinParamDoc{
			param("handle", "Task handle from spawn.", ParamInt),
		},
		returns: pairRet("true once the task has finished", ParamBool)},
	BuiltinNameChanNew: {
		signature: "chan_new(capacity?)", summary: "Creates a channel for passing values between concurrently running code and returns its handle. Capacity 0 (the default) is unbuffered, so a send waits for a receive; a positive capacity lets that many values queue first. At most 1024 channels may be open at once; close each one with chan_close when you are done with it.",
		params: []builtinParamDoc{
			param("capacity?", "How many values may queue before a send waits; 0 for unbuffered.", ParamInt),
		},
		returns: pairRet("a channel handle; close it with chan_close, which is what releases it", ParamInt)},
	BuiltinNameChanSend: {
		signature: "chan_send(handle, value, timeoutMs?)", summary: "Puts a value on a channel, waiting for a receiver if the channel is full. Returns true once the value is handed over and false if the timeout ran out first; sending on a closed channel is an error.",
		params: []builtinParamDoc{
			param("handle", "Channel handle from chan_new.", ParamInt),
			param("value", "Value to send; any type is accepted.", ParamAny),
			param("timeoutMs?", "How long to wait, in milliseconds; 0 to give up immediately, omit to wait indefinitely.", ParamInt),
		},
		returns: pairRet("true if the value was sent, false if the timeout ran out", ParamBool)},
	BuiltinNameChanRecv: {
		signature: "chan_recv(handle, timeoutMs?)", summary: "Takes the next value off a channel, waiting for one if the channel is empty. Returns {ok, value, closed, timeout}; check ok before reading value, since null is itself a sendable value. Values already queued are delivered even after the channel is closed.",
		params: []builtinParamDoc{
			param("handle", "Channel handle from chan_new.", ParamInt),
			param("timeoutMs?", "How long to wait, in milliseconds; 0 to give up immediately, omit to wait indefinitely.", ParamInt),
		},
		returns: pairRet("whether a value arrived, the value itself, and whether the channel is closed or the wait timed out", ParamHash).withFields("ok", "value", "closed", "timeout")},
	BuiltinNameChanTryRecv: {
		signature: "chan_try_recv(handle)", summary: "Takes a value off a channel only if one is already waiting, and never blocks. Returns the same {ok, value, closed, timeout} shape as chan_recv.",
		params: []builtinParamDoc{
			param("handle", "Channel handle from chan_new.", ParamInt),
		},
		returns: pairRet("whether a value was waiting, the value itself, and whether the channel is closed", ParamHash).withFields("ok", "value", "closed", "timeout")},
	BuiltinNameChanClose: {
		signature: "chan_close(handle)", summary: "Closes a channel, waking every waiting sender and receiver. Returns true when this call did the closing and false when the channel was already closed. Receivers can still drain values that were already queued; the handle is reclaimed once enough other channels have been closed after it, after which it reports as unknown.",
		params: []builtinParamDoc{
			param("handle", "Channel handle from chan_new.", ParamInt),
		},
		returns: pairRet("true if this call closed the channel, false if it was already closed", ParamBool)},
	BuiltinNameSortBy: {
		signature: "sort_by(array, fn)", summary: "Returns a new array stably sorted by the key fn returns for each element (INTEGER/FLOAT/STRING keys).",
		params: []builtinParamDoc{
			param("array", "Array to sort.", ParamArray),
			param("fn", "Key function called per element: (element) or (element, index).", ParamFn),
		},
		returns: ret("a new array sorted by the callback's key", ParamArray)},
	BuiltinNameWithResource: {
		signature: "with_resource(resource, closer, fn)", summary: "Calls fn with a resource an open call returned and always closes it afterwards -- whether fn returns a value, returns an error, or fails outright. closer is the name of a closing builtin (\"ntfs_close\") or a function taking the resource. If the open itself failed, fn never runs and the open's error comes back unchanged, so wrapping an existing call in with_resource does not change what the program sees. Returns (value, err): value is what fn returned, and err is the first failure among the open, an error fn returned, and the close. When fn and the close both fail, fn's error is the one returned and the close's is attached to it as related[\"close_error\"].",
		params: []builtinParamDoc{
			param("resource", "What an open call returned: a (handle, err) pair, or the handle itself.", ParamAny),
			param("closer", "Name of the builtin that closes the resource, or a function taking it.", ParamString, ParamFn),
			param("fn", "Function called with the resource: (resource).", ParamFn),
		},
		returns: pairRet("what fn returned, and the first failure among the open, fn and the close", ParamAny)},

	// Testing. Every one of these records what it saw in the run that is
	// executing and is therefore only meaningful under `mutant test`; each also
	// RETURNS its verdict, so a failure is a value the program can read the way
	// it reads every other failure in this language.
	BuiltinNameTest: {
		signature: "test(name, fn)", summary: "Runs fn as a named test and records whether it passed. Tests run where they are written, in order; a test declared inside another is a subtest of it. A runtime error inside fn fails that test and the file keeps going.",
		params: []builtinParamDoc{
			param("name", "What this test is called, as it will be reported.", ParamString),
			param("fn", "The test body, taking no parameters.", ParamFn),
		},
		returns: ret("true when the test and everything nested inside it passed", ParamBool)},
	BuiltinNameBeforeEach: {
		signature: "before_each(fn)", summary: "Registers fn to run before each test declared after this call, at this nesting level and inside it. A failure in fn fails the test it was preparing.",
		params:  []builtinParamDoc{param("fn", "Setup function, taking no parameters.", ParamFn)},
		returns: ret("null; the function is recorded for later tests", ParamNull)},
	BuiltinNameAfterEach: {
		signature: "after_each(fn)", summary: "Registers fn to run after each test declared after this call, at this nesting level and inside it. It runs whether the test passed, failed, or ended in an error.",
		params:  []builtinParamDoc{param("fn", "Teardown function, taking no parameters.", ParamFn)},
		returns: ret("null; the function is recorded for later tests", ParamNull)},
	BuiltinNameAssert: {
		signature: "assert(condition, message?)", summary: "Fails the current test unless condition is truthy.",
		params: []builtinParamDoc{
			param("condition", "Value that must be truthy; any type is accepted.", ParamAny),
			param("message?", "What the check was for, shown with the failure.", ParamString),
		},
		returns: ret("true when the assertion held; an error naming what was seen when it did not", ParamBool)},
	BuiltinNameAssertEq: {
		signature: "assert_eq(got, want, message?)", summary: "Fails the current test unless got equals want. Scalars compare by value; arrays, hashes and structs compare by their rendered form, so key order does not matter.",
		params: []builtinParamDoc{
			param("got", "The value produced; any type is accepted.", ParamAny),
			param("want", "The value expected; any type is accepted.", ParamAny),
			param("message?", "What the check was for, shown with the failure.", ParamString),
		},
		returns: ret("true when the two are equal; an error showing both when they are not", ParamBool)},
	BuiltinNameAssertNe: {
		signature: "assert_ne(got, unwanted, message?)", summary: "Fails the current test when got equals unwanted, compared the way assert_eq compares.",
		params: []builtinParamDoc{
			param("got", "The value produced; any type is accepted.", ParamAny),
			param("unwanted", "The value it must not be; any type is accepted.", ParamAny),
			param("message?", "What the check was for, shown with the failure.", ParamString),
		},
		returns: ret("true when the two differ; an error showing the value when they do not", ParamBool)},
	BuiltinNameAssertContains: {
		signature: "assert_contains(container, value, message?)", summary: "Fails the current test unless container holds value: a substring of a string, an element of an array, or a key of a hash.",
		params: []builtinParamDoc{
			param("container", "String, array or hash to look in.", ParamString, ParamArray, ParamHash),
			param("value", "Substring, element or key to look for.", ParamAny),
			param("message?", "What the check was for, shown with the failure.", ParamString),
		},
		returns: ret("true when the value was found; an error naming both when it was not", ParamBool)},
	BuiltinNameAssertErr: {
		signature: "assert_err(value, substring?)", summary: "Fails the current test unless value is an error, optionally requiring its message to contain substring. This is what the second binding of a (value, err) call is checked with.",
		params: []builtinParamDoc{
			param("value", "The value expected to be an error; any type is accepted.", ParamAny),
			param("substring?", "Text the error message must contain.", ParamString),
		},
		returns: ret("true when the value was the expected error; an error describing the mismatch when it was not", ParamBool)},
	BuiltinNameAssertOk: {
		signature: "assert_ok(value, message?)", summary: "Fails the current test when value is an error, quoting the error's own message. This is the check to put on the second binding of a (value, err) call that is expected to succeed.",
		params: []builtinParamDoc{
			param("value", "The value expected not to be an error; any type is accepted.", ParamAny),
			param("message?", "What the check was for, shown with the failure.", ParamString),
		},
		returns: ret("true when the value was not an error; an error quoting it when it was", ParamBool)},
	BuiltinNameFail: {
		signature: "fail(message)", summary: "Fails the current test unconditionally with the given message. For the branch a test should never reach.",
		params:  []builtinParamDoc{param("message", "Why the test failed.", ParamString)},
		returns: ret("an error carrying the message; the failure is recorded either way", ParamError)},

	// Chain of custody (F-1). Nothing in this family records anything until
	// `case_open` is called, so the hooks these rely on -- in every evidence
	// opener and every handle resolver -- cost a program that does not open a
	// case exactly one atomic load.
	BuiltinNameCaseOpen: {
		signature: "case_open(id, examiner, options?)",
		summary:   "Opens a chain-of-custody session. From here until `case_close`, every evidence opener records its source into the case manifest and every builtin that reads through an evidence handle is counted against that source. Only one case may be open at a time.",
		params: []builtinParamDoc{
			param("id", "The case identifier this investigation is filed under.", ParamString),
			param("examiner", "Who is conducting it. A manifest nobody signed for is not a chain of custody, so this may not be empty.", ParamString),
			param("options?", "`{\"hash\": \"sha256\"}` digests each source as it is opened. The default is `\"none\"`, because the alternative is `raw_open` silently reading half a terabyte before it returns a handle; a manifest then states which it was. Also accepts `\"md5\"` and `\"sha1\"`.", ParamHash),
		},
		returns: pairRet("the opened case", ParamHash).withFields("examiner", "hash_policy", "id", "opened_at", "status")},
	BuiltinNameCaseNote: {
		signature: "case_note(text, data?)",
		summary:   "Records an examiner's note in the case timeline, with an optional value alongside it. The timeline holds what the analyst did -- opens, notes, verifications, the close -- and never grows with what the program read.",
		params: []builtinParamDoc{
			param("text", "What happened, in the examiner's words.", ParamString),
			param("data?", "Any value to record with the note; it is stored as written.", ParamAny),
		},
		returns: pairRet("the recorded entry", ParamHash).withFields("at", "elapsed_ms", "event", "status", "text")},
	BuiltinNameCaseEvidence: {
		signature: "case_evidence(path, options?)",
		summary:   "Brings a file under custody that no evidence opener will touch -- a carved file, an export, a hash list handed over with the drive. Registers its size, modification time and, under the case's hash policy, its digest.",
		params: []builtinParamDoc{
			param("path", "The file to place under custody.", ParamString),
			param("options?", "`{\"hash\": \"sha256\"}` digests this one file even in a case opened without a hash policy, because an examiner who names a single file is willing to wait for it.", ParamHash),
		},
		returns: pairRet("the evidence record", ParamHash).withFields("elapsed_ms", "hash", "hash_algo", "hashed", "mod_time", "on_disk", "opens", "path", "registered_at", "size", "touches")},
	BuiltinNameCaseVerify: {
		signature: "case_verify()",
		summary:   "Re-measures every source under custody and reports what moved. A case opened with a hash policy compares digests; one opened without compares size and modification time. Each source says which basis was used, so a weaker check is never mistaken for a stronger one.",
		returns:   pairRet("the drift report", ParamHash).withFields("changed", "checked", "missing", "not_on_disk", "sources", "unchanged")},
	BuiltinNameCaseManifest: {
		signature: "case_manifest()",
		summary:   "Returns the case manifest as it stands: the case and examiner, the tool build, every evidence source with its size and digest, every builtin that touched each source with a count, the timeline, and the security telemetry for the run. Readable while the case is open and after it closes.",
		returns:   pairRet("the case manifest", ParamHash).withFields("audit", "case", "classification", "evidence", "integrity", "program", "seal", "security_telemetry", "timeline", "tool")},
	BuiltinNameCaseWrite: {
		signature: "case_write(path, options?)",
		summary:   "Writes the manifest to disk as a signed JSON document. The seal carries a SHA-256 over every field except itself and an Ed25519 signature over the same bytes, from the local key pair Mutant already maintains; the public key travels in the document, so `case_manifest_verify` needs nothing but the file.",
		params: []builtinParamDoc{
			param("path", "Where to write the manifest.", ParamString),
			param("options?", "`{\"sign\": false}` writes the hash but no signature, for a machine with no key store. The document then says `\"signed\": false` rather than looking signed.", ParamHash),
		},
		returns: pairRet("what was written", ParamHash).withFields("bytes", "manifest_hash", "path", "signed", "status")},
	BuiltinNameCaseManifestVerify: {
		signature: "case_manifest_verify(path)",
		summary:   "Checks a written manifest: that its contents still hash to the value in its seal, and that the signature over them holds. A function of the file alone -- it needs neither the case that produced it nor any key the reader does not already hold.",
		params:    []builtinParamDoc{param("path", "The manifest to check.", ParamString)},
		returns: pairRet("the verification result", ParamHash).withFields(
			"case_id", "computed_hash", "examiner", "hash_matches", "manifest_hash", "path",
			"signature_detail", "signature_valid", "signed")},
	BuiltinNameCaseReport: {
		signature: "case_report(opts?)",
		summary:   "Renders the open case as a report value, in the shape report_new builds: the case header, the evidence with its digests, what each builtin touched and how often, the timeline, the integrity statement and the security counters. It is read from the manifest rather than from the session, so the report and the manifest cannot disagree about what was examined; and it is a value, so an examiner's conclusions can be added with report_section and report_text before anything is rendered.",
		params:    []builtinParamDoc{param("opts?", "Optional {title, subtitle, generated}. title defaults to \"Case <id>\"; generated is RFC 3339 and defaults to now, and pinning it makes two renders of one case the same bytes.", ParamHash)},
		returns:   pairRet("the case as a report", ParamHash).withFields("case_id", "examiner", "generated", "sections", "title")},
	BuiltinNameCaseBundle: {
		signature: "case_bundle(dir, opts?)",
		summary:   "Writes the handover: manifest.json, report.html, report.md and a SHA256SUMS any sha256sum can check. The reports are written first and the manifest records what they hashed to, so the seal over the manifest -- a SHA-256 over every other field, signed with the local key pair -- covers the reports too: edit a byte of report.html and it no longer matches the case it claims to be from. The binding runs one way on purpose; a report quoting the manifest's hash would be quoting a document that had not been written yet. Returns (result, err).",
		params: []builtinParamDoc{
			param("dir", "The directory to write into; created if it does not exist.", ParamString),
			param("opts?", "Optional {title, subtitle, generated, sign}. The first three are case_report's; sign:false writes the hash but no signature, for a machine with no key store.", ParamHash),
		},
		returns: pairRet("what the bundle contains", ParamHash).withFields("checksums", "dir", "files", "manifest", "manifest_hash", "signed", "status")},
	BuiltinNameCaseClose: {
		signature: "case_close()",
		summary:   "Closes the case and returns its final manifest. After this, evidence openers stop recording.",
		returns:   pairRet("the final manifest", ParamHash).withFields("audit", "case", "evidence", "integrity", "program", "seal", "security_telemetry", "timeline", "tool")},
	BuiltinNameCaseKeyCreate: {
		signature: "case_key_create(path, options?)",
		summary:   "Mints the case key a classified record is sealed under and writes it to a file that must not already exist. The passphrase is asked for at the terminal and never appears in an argument: key material in program text is key material a traceback can print, and a Go string holding a secret cannot be wiped. Refuses an existing path, because writing a key over a key makes every record sealed under the old one unopenable.",
		params: []builtinParamDoc{
			param("path", "Where to write the key file. Keep it out of the directory `case_bundle` writes: the key is the one thing that must not travel with the handover.", ParamString),
			param("options?", "`{\"case_id\": \"IR-2026-0031\"}` names the case the key belongs to, defaulting to the open case. `{\"sign\": false}` writes the file with no Ed25519 signature, for a machine with no key store.", ParamHash),
		},
		returns: pairRet("what was minted", ParamHash).withFields("case_id", "case_uid", "fingerprint", "generation", "kdf", "key_id", "path", "signature_detail", "signed", "status")},
	BuiltinNameCaseKeyOpen: {
		signature: "case_key_open(path, options?)",
		summary:   "Unwraps a case key and holds it for the life of the open case. Returns no handle and has no closer: the key's lifetime is the case's, and `case_close` zeroes it. Refuses a key whose case id is not the open case's, and refuses a second key while one is open.",
		params: []builtinParamDoc{
			param("path", "The key file `case_key_create` wrote.", ParamString),
			param("options?", "`{\"generation\": 2}` opens an earlier generation, for a record sealed before the key was rotated. Defaults to the file's current generation.", ParamHash),
		},
		returns: pairRet("what was opened", ParamHash).withFields("case_id", "case_uid", "fingerprint", "generation", "key_id", "path", "signature_detail", "signature_valid", "signed", "status")},
	BuiltinNameCaseKeyRotate: {
		signature: "case_key_rotate(path, options)",
		summary:   "Changes the passphrase, or mints a new case key. `mode` is required and has no default because the two do different things. Neither reaches a disclosure already issued: a grant is bytes in someone else's hands, and rotation is not revocation.",
		params: []builtinParamDoc{
			param("path", "The key file to rotate.", ParamString),
			param("options", "`{\"mode\": \"passphrase\"}` rewraps every generation under a new passphrase and a new salt, leaving every case key byte-identical so no record is touched. `{\"mode\": \"case_key\"}` appends a new generation and makes it current, leaving earlier ones in place so records sealed under them still open.", ParamHash),
		},
		returns: pairRet("what the rotation did", ParamHash).withFields("case_id", "fingerprint", "generation", "key_id", "mode", "path", "previous_fingerprint", "previous_generation", "records_rewrapped", "signature_detail", "signed", "status")},
	BuiltinNameCaseKeyFingerprint: {
		signature: "case_key_fingerprint(path)",
		summary:   "Reads what a key file says about itself, with no passphrase and no unwrapping. `authenticated` is always false and says so: without the passphrase the file's own MAC cannot be checked, so every field returned is a claim. The signature narrows that to a claim by the holder of a signing key, which is better and is not proof.",
		params: []builtinParamDoc{
			param("path", "The key file to read.", ParamString),
		},
		returns: pairRet("what the file claims", ParamHash).withFields("authenticated", "case_id", "case_uid", "current", "generations", "path", "previous_file_mac", "signature_detail", "signature_valid", "signed", "status")},
	BuiltinNameClassDefine: {
		signature: "class_define(label, options?)",
		summary:   "Declares one classification label and returns the tag its segments will carry. Labels are declared before use so that a typo is an error rather than a new secret class nobody recognises. The tag is keyed to the case key, so two investigations that both declare \"restricted\" produce different tags and neither can be linked to the other.",
		params: []builtinParamDoc{
			param("label", "The label as it should read in a report. Normalised to NFC, trimmed, internal spacing collapsed and lowercased before tagging, so `Restricted` and ` restricted ` are one class; a control or formatting character is refused.", ParamString),
			param("options?", "`{\"description\": \"...\"}` is prose for the manifest and is never part of the tag.", ParamHash),
		},
		returns: pairRet("the declared label", ParamHash).withFields("canonical", "description", "index", "label", "status", "tag")},
	BuiltinNameClassList: {
		signature: "class_list()",
		summary:   "Returns the classification scheme in force, in declaration order. Answers with the same keys whether or not a case is open, so a program branches on a field rather than on an error: `open` says a case is open, `tagged` says a case key is open, which is what makes a tag possible at all. The order is presentation order and carries no authority; nothing here enforces a lattice.",
		returns:   pairRet("the scheme in force", ParamHash).withFields("case_id", "classes", "count", "open", "tagged")},
	BuiltinNameRecordClassifyRange: {
		signature: "record_classify_range(offset, length, label)",
		summary:   "Describes one run of bytes and the class it carries, resolving the label to the tag its segments will actually be bound to. It is a builtin rather than a hash you write out so that a label which was never declared is refused at the line that named it, rather than at the seal -- by which point a program has usually built a list and lost track of which entry was wrong. Ranges do not have to be given in order and must not overlap: which label wins where two ranges disagree is a legal question, not one this tool may answer for you. Returns (range, err).",
		params: []builtinParamDoc{
			param("offset", "Where the run starts in the plaintext.", ParamInt),
			param("length", "How many bytes it covers. A range of zero bytes classifies nothing and is refused.", ParamInt),
			param("label", "A label already declared with `class_define`.", ParamString),
		},
		returns: pairRet("the range and the tag it carries", ParamHash).withFields("class", "label", "length", "offset")},
	BuiltinNameRecordSeal: {
		signature: "record_seal(source, record, ranges, options)",
		summary:   "Encrypts a file into a `.mrec` at the classification boundaries it was given. The `default` option is required and names the class every byte no range covers will carry: there is no implicit unclassified, because a record with an unlabelled remainder discloses that remainder to everyone who is disclosed anything, and \"the examiner decided this is open\" and \"the examiner did not think about this\" are different statements. Each span splits into segments of at most segment_size, and a segment never straddles a span, so a segment key can never open bytes of two classifications. Range boundaries and lengths are public by construction -- a redaction nobody can see is a redaction nobody can challenge -- and `record_seal_quantised` is the answer where a short secret must not advertise its length. The destination must not already exist. Returns (record, err).",
		params: []builtinParamDoc{
			param("source", "The file to seal. An empty file is refused: sealing nothing protects nothing, since a record's length is public anyway.", ParamString),
			param("record", "Where to write the `.mrec`. Refused if it already exists, because the record it would replace may be the only copy of what it held.", ParamString),
			param("ranges", "An array of `record_classify_range` results. May be empty, in which case the whole record carries the default class.", ParamArray),
			param("options", "`{\"default\": \"open\"}` is required. `{\"sign\": false}` writes no Ed25519 signature, for a machine with no key store. `{\"segment_size\": 65536}` sets the disclosure granularity. `{\"source\": \"...\"}` is a note about provenance and is never checked.", ParamHash),
		},
		returns: pairRet("what was sealed", ParamHash).withFields("case_key_id", "case_uid", "file_length", "generation", "key_created_for_this_run", "path", "plaintext_length", "public_key", "quantised_extra", "quantum", "record_uid", "segment_size", "segments", "segments_root", "signed", "spans")},
	BuiltinNameRecordSealQuantised: {
		signature: "record_seal_quantised(source, record, ranges, options)",
		summary:   "Seals with span boundaries rounded OUTWARD to a quantum, so that a four-byte secret is indistinguishable from anything else inside its rounded span. `rounds_to` is required and names the one class rounding may grow, because every byte a range grows over stops carrying the class it had and starts carrying that range's -- and whether that withholds those bytes or releases them depends on which of the two classes is the more sensitive, which nothing here knows: a class is a label and a tag, and nothing orders them. With default `restricted` and a four-byte `open` passage, rounding to sixteen releases twelve bytes nobody cleared, so a range whose class is not the one named is sealed at the boundary it was given rather than rounded. `quantised_extra` is how many bytes changed class, and `rounds_to` comes back beside it because a count with no direction cannot be read. Everything else matches `record_seal`. Returns (record, err).",
		params: []builtinParamDoc{
			param("source", "The file to seal.", ParamString),
			param("record", "Where to write the `.mrec`. Refused if it already exists.", ParamString),
			param("ranges", "An array of `record_classify_range` results.", ParamArray),
			param("options", "`quantum`, `default` and `rounds_to` are all required; `sign`, `segment_size` and `source` are as for `record_seal`.", ParamHash),
		},
		returns: pairRet("what was sealed, and which class the rounding grew", ParamHash).withFields("case_key_id", "case_uid", "file_length", "generation", "key_created_for_this_run", "path", "plaintext_length", "public_key", "quantised_extra", "quantum", "record_uid", "rounds_to", "segment_size", "segments", "segments_root", "signed", "spans")},
	BuiltinNameRecordOpen: {
		signature: "record_open(path)",
		summary:   "Opens a record for reading and returns a handle. Needs the case key the record was sealed under: the record key is wrapped under it, and a record sealed by another case is refused by its case uid before any unwrapping is attempted. The handle it returns can only ever open -- there is no path from here to sealing, which is what stops a program re-sealing a position and putting two plaintexts under one keystream. Record handles are their own space and are not ledger or database handles. Close it with `record_close`. Returns (record, err).",
		params: []builtinParamDoc{
			param("path", "The `.mrec` to open.", ParamString),
		},
		returns: pairRet("the handle and what the record says about itself", ParamHash).withFields("case_uid", "generation", "handle", "key_created_for_this_run", "path", "plaintext_length", "record_uid", "segment_size", "segments", "signature_note", "signature_valid", "signed")},
	BuiltinNameRecordLayout: {
		signature: "record_layout(record)",
		summary:   "Reports the record's public structure -- every span, every segment, where each one sits and which class it carries -- and reads no plaintext to do it. `boundaries_are_public` is returned as a field rather than left to a document, because a reader of a layout is exactly the reader who might otherwise conclude the opposite: offsets and lengths are visible to everyone holding the record, with no key at all. Returns (layout, err).",
		params: []builtinParamDoc{
			param("record", "Handle from record_open.", ParamInt),
		},
		returns: pairRet("the public structure", ParamHash).withFields("boundaries_are_public", "plaintext_length", "record_uid", "segment_size", "segments", "spans")},
	BuiltinNameRecordRead: {
		signature: "record_read(record, offset, length)",
		summary:   "Returns a span of plaintext, or refuses and names the segments that stood in the way. It is an error and not a short read: a caller who wrote `record_read(r, 0, n)` believes they are getting n bytes of evidence, and a buffer with zeros where the withheld spans were would look exactly like evidence and not be it. Use `record_read_partial` for the bytes that are readable, which returns the holes as data instead. The result is BYTES and never a STRING, because a Go string cannot be zeroed and the runtime copies one at will. Returns (bytes, err).",
		params: []builtinParamDoc{
			param("record", "Handle from record_open.", ParamInt),
			param("offset", "Where to start in the plaintext.", ParamInt),
			param("length", "How many bytes to read. Running past the end of the record is refused.", ParamInt),
		},
		returns: pairRet("the plaintext span", ParamBytes)},
	BuiltinNameRecordReadPartial: {
		signature: "record_read_partial(record, offset, length)",
		summary:   "Returns what is readable plus exactly what is not. The unreadable spans are zero-filled rather than removed, so offsets still line up with the record's own numbering -- the same reason the format refuses to pad, since a recipient who cannot place their fragments at their true positions cannot reconstruct the document they were given. `holes_are_zero_filled` is a field because zeros are also a thing evidence contains. `length` and `withheld` are both reported so a caller does not have to subtract. Returns (result, err).",
		params: []builtinParamDoc{
			param("record", "Handle from record_open.", ParamInt),
			param("offset", "Where to start in the plaintext.", ParamInt),
			param("length", "How many bytes to attempt.", ParamInt),
		},
		returns: pairRet("the bytes, and the spans that are missing from them", ParamHash).withFields("bytes", "complete", "holes", "holes_are_zero_filled", "length", "withheld")},
	BuiltinNameRecordVerify: {
		signature: "record_verify(path)",
		summary:   "Checks a record holding no key at all, which is the property the whole format is arranged around: a recipient who was granted nothing can still establish that the file they hold is the file that was sealed. It rebuilds every segment descriptor from the public header, recomputes every segment digest from the stored ciphertext, folds the root and checks the signature. `signed` and `signature_valid` are two bits and never one, because an unsigned record is a normal record written on a machine with no key store and a forged one is not. `does_not_prove` is a returned field and not a footnote: a signature authenticates the document, not the names in it. Returns (result, err).",
		params: []builtinParamDoc{
			param("path", "The `.mrec` to check. No case key is needed and none is used.", ParamString),
		},
		returns: pairRet("what the record is, and what checking it did not establish", ParamHash).withFields("case_key_id", "case_uid", "created", "does_not_prove", "examiner", "generation", "key_created_for_this_run", "path", "plaintext_length", "public_key", "quantised_extra", "quantum", "record_uid", "rounds_to", "segments", "segments_root", "signature_note", "signature_valid", "signed", "spans", "verified_without_key")},
	BuiltinNameRecordProveSegment: {
		signature: "record_prove_segment(record, index)",
		summary:   "Cites one segment in a form a third party can check against the copy they hold: which segment, at which offset, under which class, with which digest, folding into which signed root. It is deliberately not a Merkle inclusion proof -- a tree buys a compact path to the root, and compactness is worth having only when the verifier does not have the data, but a disclosure hands over a record byte-identical to the one under custody, so every recipient already holds every segment and can recompute the whole fold. The root is recomputed from the bytes on disk rather than read from the footer, so `root_matches` is about the file and not about what the file says of itself. `content_free` is true: nothing here reveals plaintext. Returns (citation, err).",
		params: []builtinParamDoc{
			param("record", "Handle from record_open.", ParamInt),
			param("index", "The segment to cite, numbered from 0. `record_layout` lists them.", ParamInt),
		},
		returns: pairRet("the citation, and what it does not establish", ParamHash).withFields("class", "content_free", "digest", "does_not_prove", "length", "offset", "proves", "record_uid", "root_matches", "segment", "segments_root", "signature_valid", "signed")},
	BuiltinNameRecordClose: {
		signature: "record_close(record)",
		summary:   "Closes a record handle, zeroing its key schedule and releasing the file. The handle comes from record_open and is not a ledger or database handle; the three handle spaces are separate so that no builtin of one family can resolve a handle of another.",
		params: []builtinParamDoc{
			param("record", "Handle from record_open.", ParamInt),
		},
		returns: pairRet("true once the handle has been closed", ParamBool)},
	BuiltinNameAuditHead: {
		signature: "audit_head()",
		summary:   "Returns the head of the security audit chain: the SHA-256 commitment to every security event this run recorded, in order. The counters in `case_manifest` say how many times a check tripped; the chain says in what order and at which stage, which is the question a counter cannot be asked afterwards. The head covers every event ever recorded even when older entries have been dropped from memory, so `entries` and `retained` are different numbers and both are reported.",
		returns: pairRet("the state of the audit chain", ParamHash).withFields(
			"chain_complete", "dropped", "entries", "first_retained_seq", "head", "recording", "retained", "status")},
	BuiltinNameAuditWrite: {
		signature: "audit_write(path)",
		summary:   "Writes the audit chain to disk as JSON: every retained entry with its sequence number, timestamp, event, stage, the hash of the entry before it and its own hash. The file is read back and hashed after writing, so a document that is not what was written is an error rather than a digest nobody can reproduce. When a case is open the write is recorded in its timeline, the same way a report is. The log carries no signature of its own -- what ties it to a run is that its head matches the one sealed into that run's manifest.",
		params:    []builtinParamDoc{param("path", "Where to write the log.", ParamString)},
		returns: pairRet("what was written", ParamHash).withFields(
			"bytes", "chain_complete", "dropped", "entries", "head", "path", "retained", "sha256", "status")},
	BuiltinNameAuditVerify: {
		signature: "audit_verify(path, head?)",
		summary:   "Re-walks a written audit log, recomputing every link and the timestamp each entry displays against the one its hash covers, and stops at the first entry that disagrees. Pass the head from the case manifest as the second argument to check the log against a value its own writer did not choose: `anchored` says whether a head was supplied and `anchor_matches` whether it agreed, because a log checked only against the head stored inside it has been checked against itself. A log whose entries were dropped for the memory cap begins at `first_retained_seq`, and the `prev` of that first entry is a claim rather than something the document can check.",
		params: []builtinParamDoc{
			param("path", "The log to check.", ParamString),
			param("head?", "The head to check the log against, from the `audit` block of the case manifest. Omitted, the log is checked only for internal consistency and says so in `anchored`.", ParamString),
		},
		returns: pairRet("the verification result", ParamHash).withFields(
			"anchor_matches", "anchored", "broken_at", "chain_complete", "computed_head", "detail", "does_not_cover", "dropped", "entries", "head", "head_matches", "links_checked", "links_intact", "path", "status")},

	BuiltinNameKeys: {
		signature: "keys(hash)", summary: "Returns the hash keys as an array (sorted for determinism).",
		params:  []builtinParamDoc{param("hash", "Hash to read keys from.", ParamHash)},
		returns: ret("the hash keys as an array (sorted for determinism)", ParamArray)},
	BuiltinNameValues: {
		signature: "values(hash)", summary: "Returns the hash values as an array (ordered by sorted key).",
		params:  []builtinParamDoc{param("hash", "Hash to read values from.", ParamHash)},
		returns: ret("the hash values as an array (ordered by sorted key)", ParamArray)},
	BuiltinNameEntries: {
		signature: "entries(hash)", summary: "Returns the hash as an array of [key, value] pairs (sorted by key).",
		params:  []builtinParamDoc{param("hash", "Hash to enumerate.", ParamHash)},
		returns: ret("the hash as an array of [key, value] pairs (sorted by key)", ParamArray)},
	BuiltinNameHasKey: {
		signature: "has_key(hash, key)", summary: "Returns whether hash contains key.",
		params: []builtinParamDoc{
			param("hash", "Hash to test.", ParamHash),
			param("key", "Hashable key: string, integer, float, or boolean.", hashableKinds...),
		},
		returns: ret("whether hash contains key", ParamBool)},
	BuiltinNameGet: {
		signature: "get(hash, key, default)", summary: "Returns hash[key], or default when the key is absent.",
		params: []builtinParamDoc{
			param("hash", "Hash to read from.", ParamHash),
			param("key", "Hashable key: string, integer, float, or boolean.", hashableKinds...),
			param("default", "Value returned when the key is absent; any type is accepted.", ParamAny),
		},
		returns: ret("the value stored under key, or the supplied default when the key is absent", ParamAny)},
	BuiltinNameSet: {
		signature: "set(hash, key, value)", summary: "Returns a new hash with key set to value (original unchanged).",
		params: []builtinParamDoc{
			param("hash", "Hash to copy.", ParamHash),
			param("key", "Hashable key: string, integer, float, or boolean.", hashableKinds...),
			param("value", "Value to store; any type is accepted.", ParamAny),
		},
		returns: ret("a new hash with key set to value (original unchanged)", ParamHash)},
	BuiltinNameMerge: {
		signature: "merge(a, b)", summary: "Returns a new hash combining a and b (b wins on key conflicts).",
		params: []builtinParamDoc{
			param("a", "Base hash.", ParamHash),
			param("b", "Overriding hash.", ParamHash),
		},
		returns: ret("a new hash combining a and b (b wins on key conflicts)", ParamHash)},
	BuiltinNameDelete: {
		signature: "delete(hash, key)", summary: "Returns a new hash with key removed.",
		params: []builtinParamDoc{
			param("hash", "Hash to copy.", ParamHash),
			param("key", "Hashable key: string, integer, float, or boolean.", hashableKinds...),
		},
		returns: ret("a new hash with key removed", ParamHash)},
	// security: Go binary analysis (GoReSym) — parses PE/ELF/Mach-O Go binaries
	BuiltinNameGoBuildInfo: {signature: "go_buildinfo(path)", summary: "Extracts Go build info from a binary: go_version, module path, main module, dependencies (path/version/sum), and build settings (GOOS/GOARCH/vcs.*). Returns (info, err).", params: []builtinParamDoc{param("path", "Path to a Go-compiled binary (PE/ELF/Mach-O).", ParamString)}, returns: pairRet("the Go version, module path, and dependency list", ParamHash)},
	BuiltinNameGoBuildID:   {signature: "go_build_id(path)", summary: "Extracts the Go build ID from a binary. Returns (build_id, err).", params: []builtinParamDoc{param("path", "Path to a Go-compiled binary.", ParamString)}, returns: pairRet("the Go build ID", ParamString)},
	BuiltinNameGoSymbols:   {signature: "go_symbols(path, mode?)", summary: "Recovers function symbols from a Go binary via the pclntab — works even on STRIPPED binaries. Returns {go_version, arch, os, pclntab_va, function_count, user_function_count, std_function_count, functions:[{name, package, start, end, stdlib}]}. mode is \"all\" (default), \"user\", or \"std\". Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Go-compiled binary.", ParamString), param("mode?", "Filter: all/user/std (default all).", ParamString)}, returns: pairRet("the function symbols recovered from the pclntab", ParamHash)},
	BuiltinNameGoTypes:     {signature: "go_types(path)", summary: "Recovers type and interface definitions from a Go binary via GoReSym typelink/itablink parsing, including reconstructed Go source for structs/interfaces where possible. Returns {go_version, type_count, itab_count, types:[{va, name, kind, reconstructed}], itabs:[...]}. Type recovery needs a parseable moduledata; GoReSym v1.7.1 supports it up to ~Go 1.24 and returns an honest error on newer toolchains. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Go-compiled binary.", ParamString)}, returns: pairRet("the type and interface definitions recovered from the binary", ParamHash)},
	BuiltinNameBinIsGo:     {signature: "bin_is_go(path)", summary: "Quick check whether a binary was produced by the Go toolchain, using three signals (build info blob, Go build ID, and a parseable pclntab — the one that survives stripping). Returns {is_go, go_version, has_buildinfo, has_build_id, has_pclntab}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a binary (PE/ELF/Mach-O).", ParamString)}, returns: pairRet("whether the binary is Go, and which signals said so", ParamHash).withFields("go_version", "has_build_id", "has_buildinfo", "has_pclntab", "is_go")},
	// security: IOC / network intelligence
	BuiltinNameDefang:        {signature: "defang(ioc)", summary: "Defangs an indicator for safe display (http->hxxp, .->[.], @->[at]).", returns: ret("the defanged indicator, safe to display", ParamString), params: []builtinParamDoc{param("ioc", "Indicator to defang for safe display.", ParamString)}},
	BuiltinNameRefang:        {signature: "refang(ioc)", summary: "Reverses common defang encodings ([.]/(.)/[dot]->., hxxp->http, [at]->@).", returns: ret("the original indicator, with defang encodings undone", ParamString), params: []builtinParamDoc{param("ioc", "Defanged indicator to restore.", ParamString)}},
	BuiltinNameIPIsPrivate:   {signature: "ip_is_private(ip)", summary: "Returns whether an IP is private/loopback/link-local (RFC1918 etc.).", returns: ret("whether an IP is private/loopback/link-local (RFC1918 etc", ParamBool), params: []builtinParamDoc{param("ip", "IPv4 or IPv6 address.", ParamString)}},
	BuiltinNameIPInCIDR:      {signature: "ip_in_cidr(ip, cidr)", summary: "Returns whether an IP falls within a CIDR range.", params: []builtinParamDoc{param("ip", "IPv4 or IPv6 address.", ParamString), param("cidr", "CIDR network, e.g. 10.0.0.0/8.", ParamString)}, returns: ret("whether an IP falls within a CIDR range", ParamBool)},
	BuiltinNameCIDRHosts:     {signature: "cidr_hosts(cidr)", summary: "Returns all addresses in a CIDR range (capped; errors if >20 host bits).", returns: ret("all addresses in a CIDR range (capped; errors if >20 host bits)", ParamArray).ofElem(ParamString), params: []builtinParamDoc{param("cidr", "CIDR range, e.g. \"10.0.0.0/28\".", ParamString)}},
	BuiltinNameIPVersion:     {signature: "ip_version(ip)", summary: "Returns 4, 6, or 0 (invalid) for an IP address.", returns: ret("4, 6, or 0 (invalid) for an IP address", ParamInt), params: []builtinParamDoc{param("ip", "IP address to classify.", ParamString)}},
	BuiltinNameIPToInt:       {signature: "ip_to_int(ip)", summary: "Converts an IPv4 address to its 32-bit integer form.", returns: ret("the address as a 32-bit integer", ParamInt), params: []builtinParamDoc{param("ip", "IPv4 address in dotted-quad form.", ParamString)}},
	BuiltinNameIntToIP:       {signature: "int_to_ip(n)", summary: "Converts a 32-bit integer to an IPv4 dotted-quad string.", returns: ret("the dotted-quad address", ParamString), params: []builtinParamDoc{param("n", "32-bit integer form of an IPv4 address.", ParamInt)}},
	BuiltinNameDomainExtract: {signature: "domain_extract(url)", summary: "Extracts the lowercased hostname from a URL or host string.", returns: ret("the lowercased hostname", ParamString), params: []builtinParamDoc{param("url", "URL or bare host to take the hostname from.", ParamString)}},
	BuiltinNameTLDExtract:    {signature: "tld_extract(domain)", summary: "Returns {domain, etld1, suffix} using the public suffix list.", returns: ret("{domain, etld1, suffix} using the public suffix list", ParamString, ParamHash), params: []builtinParamDoc{param("domain", "Domain name to split against the public suffix list.", ParamString)}},
	BuiltinNameIsValidDomain: {signature: "is_valid_domain(s)", summary: "Returns whether s is a syntactically valid domain name.", returns: ret("whether s is a syntactically valid domain name", ParamBool), params: []builtinParamDoc{param("s", "Candidate domain name.", ParamString)}},
	BuiltinNameExtractIOCs:   {signature: "extract_iocs(text)", summary: "Extracts IOCs from text (refanged first): {ipv4, urls, domains, emails, md5, sha1, sha256}, each unique and sorted.", returns: ret("the indicators found, grouped by type", ParamHash).withFields("domains", "emails", "ipv4", "md5", "sha1", "sha256", "urls"), params: []builtinParamDoc{param("text", "Text to scan; it is refanged before matching.", ParamString)}},
	// forensic: hash sets (known-file filtering, NSRL-style)
	BuiltinNameHashsetLoad:     {signature: "hashset_load(path)", summary: "Loads a file of hashes (one per line, or CSV/NSRL where the hash is the first field) into an in-memory set. Skips headers/comments/non-hex. Returns {handle, count}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a hash list (md5/sha1/sha256 hex).", ParamString)}, returns: pairRet("a handle for the loaded set, and how many hashes it holds", ParamHash).withFields("count", "handle")},
	BuiltinNameHashsetContains: {signature: "hashset_contains(handle, hash)", summary: "Returns whether a hash is in a loaded set (case-insensitive). Returns (bool, err).", params: []builtinParamDoc{param("handle", "Handle from hashset_load.", ParamString), param("hash", "Hex hash to look up.", ParamString)}, returns: pairRet("whether a hash is in a loaded set (case-insensitive)", ParamBool)},
	BuiltinNameHashsetClose:    {signature: "hashset_close(handle)", summary: "Frees a loaded hash set. Returns (bool, err).", returns: pairRet("true once the set has been freed", ParamBool), params: []builtinParamDoc{param("handle", "Handle from hashset_load.", ParamString)}},
	// forensic: timeline
	BuiltinNameTimestampNormalize: {signature: "timestamp_normalize(value, format?)", summary: "Normalizes a timestamp to {unix, unix_ms, iso, format}. Formats: unix (s/ms/us/ns), filetime (Windows), webkit/chrome, dos (packed 32-bit), iso (RFC3339 string). Default \"auto\" detects unix magnitude or parses an ISO string. Returns (result, err).", params: []builtinParamDoc{param("value", "INTEGER epoch/packed value, or ISO STRING.", ParamInt, ParamString), param("format?", "One of auto/unix/unix_ms/unix_us/unix_ns/filetime/webkit/dos/iso.", ParamString)}, returns: pairRet("the timestamp expressed in every supported form", ParamHash).withFields("format", "iso", "unix", "unix_ms")},
	BuiltinNameTimelineSort:       {signature: "timeline_sort(events, field?)", summary: "Returns events (array of hashes) sorted ascending by a numeric timestamp field (default \"ts\"); events missing the field sort last. Stable.", returns: ret("events (array of hashes) sorted ascending by a numeric timestamp field (default \"ts\"); events missing the field sort last", ParamArray), params: []builtinParamDoc{param("events", "Array of event hashes to sort.", ParamArray), param("field?", "Timestamp field to sort on; defaults to the common timestamp key.", ParamString)}},
	BuiltinNameTimelineMerge:      {signature: "timeline_merge(sources, field?)", summary: "Flattens an array of event arrays into one supertimeline sorted by a numeric timestamp field (default \"ts\").", returns: ret("one array of events, sorted by the timestamp field", ParamArray), params: []builtinParamDoc{param("sources", "Array of event arrays to flatten into one timeline.", ParamArray), param("field?", "Timestamp field to sort on; defaults to the common timestamp key.", ParamString)}},
	BuiltinNameBodyfileParse:      {signature: "bodyfile_parse(path)", summary: "Parses a Sleuth Kit bodyfile (MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime) into an array of entry hashes. Returns (entries, err).", params: []builtinParamDoc{param("path", "Path to a TSK bodyfile.", ParamString)}, returns: pairRet("one hash per bodyfile row", ParamArray).ofElem(ParamHash).withFields("atime", "crtime", "ctime", "gid", "inode", "md5", "mode", "mtime", "name", "size", "uid")},
	BuiltinNamePlistParse:         {signature: "plist_parse(path)", summary: "Parses an Apple property list (binary bplist00 or XML) into a Mutant value: dict->hash, array->array, string/integer/real/bool as scalars; dates and data become strings. Returns (value, err).", params: []builtinParamDoc{param("path", "Path to a .plist file (binary or XML).", ParamString)}, returns: pairRet("the decoded value: a scalar, array, or hash, depending on the plist", ParamAny)},
	BuiltinNameHiveOpen:           {signature: "hive_open(path)", summary: "Opens a real Windows registry hive (regf binary format — SOFTWARE/SYSTEM/NTUSER.DAT, etc.) and returns {handle, path}. Distinct from the JSON-fixture reg_* family. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a registry hive file.", ParamString)}, returns: pairRet("a handle for the other hive_ builtins; release it with hive_close", ParamHash).withFields("handle", "path")},
	BuiltinNameHiveClose:          {signature: "hive_close(handle)", summary: "Closes a hive handle. Returns (bool, err).", returns: pairRet("true once the handle has been released", ParamBool), params: []builtinParamDoc{param("handle", "Handle from hive_open.", ParamString)}},
	BuiltinNameHiveKeyInfo:        {signature: "hive_key_info(handle, keypath?)", summary: "Returns {name, last_write, last_write_iso, subkey_count, value_count} for a key (keypath is backslash-separated under the root; default root). Returns (result, err).", returns: pairRet("the key's metadata, including its last-write time and child counts", ParamHash).withFields("last_write", "last_write_iso", "name", "subkey_count", "value_count"), params: []builtinParamDoc{param("handle", "Handle from hive_open.", ParamString), param("keypath?", "Key path under the opened root, backslash-separated; defaults to the root.", ParamString)}},
	BuiltinNameHiveListKeys:       {signature: "hive_list_keys(handle, keypath?)", summary: "Returns the subkey names under a key (default root) as an array. Returns (array, err).", returns: pairRet("the subkey names under a key (default root) as an array", ParamArray).ofElem(ParamString), params: []builtinParamDoc{param("handle", "Handle from hive_open.", ParamString), param("keypath?", "Key path under the opened root, backslash-separated; defaults to the root.", ParamString)}},
	BuiltinNameHiveListValues:     {signature: "hive_list_values(handle, keypath?)", summary: "Returns a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. Returns (array, err).", returns: pairRet("one hash per value, with its type and decoded data (REG_SZ/DWORD/QWORD/MULTI_SZ decoded, binary as hex plus a data_bytes buffer)", ParamArray).ofElem(ParamHash).withFields("data", "data_bytes", "name", "type"), params: []builtinParamDoc{param("handle", "Handle from hive_open.", ParamString), param("keypath?", "Key path under the opened root, backslash-separated; defaults to the root.", ParamString)}},
	BuiltinNameHiveGetValue:       {signature: "hive_get_value(handle, keypath, name)", summary: "Returns {name, type, data} for a single value under keypath. Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. Returns (result, err).", returns: pairRet("the value stored under name, with its registry type, and data_bytes when that value is binary", ParamHash).withFields("data", "data_bytes", "name", "type"), params: []builtinParamDoc{param("handle", "Handle from hive_open.", ParamString), param("keypath", "Key path holding the value, backslash-separated under the opened root.", ParamString), param("name", "Value name to read; \"\" reads the key's default value.", ParamString)}},
	BuiltinNameShimcacheParse:     {signature: "shimcache_parse(path)", summary: "Decodes the Windows AppCompatCache (shimcache) — program execution/presence evidence. Accepts a SYSTEM hive file (locates the value) or a raw AppCompatCache blob. Supports Win8/Win8.1/Win10 (10ts/00ts). Returns {version, count, entries:[{position, path, last_modified, last_modified_iso}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "SYSTEM hive file or raw AppCompatCache blob.", ParamString)}, returns: pairRet("the parsed AppCompatCache entries", ParamHash)},
	BuiltinNameAmcacheParse:       {signature: "amcache_parse(path)", summary: "Parses an Amcache.hve hive (program execution/presence evidence) into {format, count, entries:[{key, path, name, sha1, publisher, version, product, size, last_write}]}. Supports the modern InventoryApplicationFile and legacy Root\\File layouts. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to an Amcache.hve hive file.", ParamString)}, returns: pairRet("the parsed Amcache entries", ParamHash)},
	BuiltinNamePrefetchParse:      {signature: "prefetch_parse(path)", summary: "Decodes a Windows Prefetch (.pf) file — program execution evidence. Transparently decompresses the Win10/11 MAM (Xpress-Huffman) container and parses the SCCA format for XP (v17), Vista/7 (v23), Win8.1 (v26), and Win10/11 (v30/v31). Returns {version, executable, prefetch_hash, run_count, run_times[], files_loaded[], file_count, volumes:[{device_path, serial, created, created_iso}], compressed}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .pf prefetch file (compressed or raw SCCA).", ParamString)}, returns: pairRet("the execution evidence the .pf file records", ParamHash).withFields("created", "created_iso", "device_path", "serial")},
	BuiltinNameMftParse:           {signature: "mft_parse(path)", summary: "Parses an NTFS Master File Table into a per-record timeline. Auto-detects a standalone $MFT file (FILE-signature record stream, e.g. KAPE/FTK/icat) vs a full NTFS volume image. Each entry has $STANDARD_INFORMATION (si_*) and $FILE_NAME (fn_*) MAC times as unix seconds, a sub-second nanosecond fraction (si_*_ns/fn_*_ns, 0-999999999, at NTFS 100 ns resolution — a whole-second/zero fraction is a timestomping tell), and an RFC3339Nano iso string; plus reconstructed path, size, sequence, and hard-link count. The record size is read from the first record header rather than assumed, and skipped counts records that would not parse. Returns {source_type, record_size, count, skipped, entries:[{record, parent_record, in_use, is_directory, name, path, size, allocated_size, sequence, hard_links, file_attributes, si_*, si_*_ns, fn_*, fn_*_ns}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a standalone $MFT file or an NTFS volume image.", ParamString)}, returns: pairRet("the parsed $MFT records", ParamHash).withFields("count", "entries", "record_size", "skipped", "source_type")},
	BuiltinNameEvtxParse:          {signature: "evtx_parse(path)", summary: "Parses a Windows Event Log (.evtx). Walks every chunk and decodes each record's BinXML (templates + substitutions) into the fully-expanded event tree, plus summary fields per record. Returns {source, chunk_count, count, records:[{record_id, timestamp, timestamp_iso, event_id, event_record_id, level, channel, computer, provider, event}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .evtx Windows Event Log file.", ParamString)}, returns: pairRet("the decoded event records", ParamHash).withFields("chunk_count", "count", "records", "source")},
	BuiltinNameEvtxParseBytes:     {signature: "evtx_parse_bytes(path)", summary: "Parses a Windows Event Log (.evtx) exactly as evtx_parse does, except that binary event values (EVTX BinaryType) come back as BYTES buffers instead of hex strings. Everything else -- the record tree, the summary fields, the return shape -- is identical. Use this when an event carries a binary payload you intend to read rather than print. Returns {source, chunk_count, count, records:[{record_id, timestamp, timestamp_iso, event_id, event_record_id, level, channel, computer, provider, event}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .evtx Windows Event Log file.", ParamString)}, returns: pairRet("the decoded event records, with binary values as BYTES", ParamHash).withFields("chunk_count", "count", "records", "source")},
	BuiltinNameJumplistParse:      {signature: "jumplist_parse(path)", summary: "Parses a Windows Jump List (recent/pinned destinations). Auto-detects *.automaticDestinations-ms (OLE compound file: numbered shell-link streams + a DestList MRU/metadata stream) and *.customDestinations-ms (concatenated shell links). Each entry merges DestList metadata (last_access, pinned, hostname) with the embedded shell-link target. Returns {type, format_version, entry_count, pinned_count, entries:[{stream_id, target, arguments, working_dir, name, last_access, last_access_iso, pinned, hostname}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .automaticDestinations-ms or .customDestinations-ms jump list.", ParamString)}, returns: pairRet("the parsed Jump List destinations", ParamHash).withFields("entries", "entry_count", "format_version", "pinned_count", "type")},
	BuiltinNameSyslogParse:        {signature: "syslog_parse(path)", summary: "Parses a Unix syslog file into structured entries, auto-detecting RFC 5424 (IETF, ISO-8601) and RFC 3164 (BSD) per line; unmatched lines are kept as raw messages. RFC 3164 lines omit the year, so the current year is assumed. Each entry has a `ts` unix field for timeline_merge/timeline_sort. Returns {count, entries:[{format, priority, facility, severity, timestamp, ts, host, app_name, pid, msgid, structured_data, message}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a syslog text file (RFC 3164 or RFC 5424).", ParamString)}, returns: pairRet("the parsed syslog entries", ParamHash).withFields("count", "entries")},
	BuiltinNameSqliteQuery:        {signature: "sqlite_query(path, sql, params?)", summary: "Runs a read-only SQL query against a SQLite database, pure-Go (no cgo). The database (+ any -wal/-shm sidecars) is copied to a temp file first, so the original is never modified or lock-contended — safe for forensic DBs held open by a running app. Optional params is an ARRAY of bind values for a parameterized query. Returns {columns, row_count, truncated, rows:[{col: value}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a SQLite database file.", ParamString), param("sql", "SQL query to run.", ParamString), param("params?", "Optional ARRAY of bind parameters.", ParamArray)}, returns: pairRet("the query's columns and rows", ParamHash).withFields("columns", "row_count", "rows", "truncated")},
	BuiltinNameSqliteQueryBytes:   {signature: "sqlite_query_bytes(path, sql, params?)", summary: "Runs a read-only SQL query exactly as sqlite_query does, except that BLOB columns come back as BYTES buffers. sqlite_query asks whether a BLOB happens to be valid UTF-8 and returns a string if so and hex if not, so one column's type varies row by row with its content; here a BLOB is a buffer whatever it holds. Other column types are unchanged: INTEGER is an INT, TEXT a STRING, NULL a NULL. Returns {columns, row_count, truncated, rows:[{col: value}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a SQLite database file.", ParamString), param("sql", "SQL query to run.", ParamString), param("params?", "Optional ARRAY of bind parameters.", ParamArray)}, returns: pairRet("the query's columns and rows, with BLOBs as BYTES", ParamHash).withFields("columns", "row_count", "rows", "truncated")},
	BuiltinNameBrowserHistory:     {signature: "browser_history(path)", summary: "Parses a Chromium (History) or Firefox (places.sqlite) history database into normalized visit entries, auto-detecting the schema and converting timestamps to unix. Returns {browser, count, entries:[{url, title, visit_count, last_visit, last_visit_iso, browser}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Chromium History or Firefox places.sqlite database.", ParamString)}, returns: pairRet("the normalized visit entries", ParamHash)},
	BuiltinNameBrowserCookies:     {signature: "browser_cookies(path)", summary: "Parses a Chromium (Cookies) or Firefox (cookies.sqlite) cookie database. Chromium cookie values are OS-encrypted; such rows are reported with encrypted=true and an empty value (decryption needs OS keys). Returns {browser, count, entries:[{host, name, value, path, expires, expires_iso, secure, http_only, encrypted, browser}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Chromium Cookies or Firefox cookies.sqlite database.", ParamString)}, returns: pairRet("the parsed cookie records", ParamHash)},
	BuiltinNameBrowserDownloads:   {signature: "browser_downloads(path)", summary: "Parses download records from a Chromium (History downloads table) or Firefox (places.sqlite moz_annos) database; Firefox support is best-effort (destination file URI). Returns {browser, count, entries:[{url, target_path, bytes_total, bytes_received, start_time, end_time, state, mime_type, browser}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Chromium History or Firefox places.sqlite database.", ParamString)}, returns: pairRet("the parsed download records", ParamHash)},
	BuiltinNameFsDeleted:          {signature: "fs_deleted(path)", summary: "Enumerates deleted files from an NTFS $MFT (a standalone $MFT file or a full volume image, auto-detected). A record is deleted when its in-use flag is clear but its metadata still parses. Small files with a resident $DATA attribute are fully recovered, as hex (resident_data) and as a buffer (resident_data_bytes) carrying the same bytes; larger non-resident files report metadata only. SI/FN times include unix seconds, a sub-second nanosecond fraction (si_*_ns/fn_*_ns), and an RFC3339Nano iso string. Returns {source_type, deleted_count, skipped, entries:[{record, name, path, size, is_directory, has_data, resident, recoverable, resident_data, resident_data_bytes, si_*, si_*_ns, fn_*, fn_*_ns}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a standalone $MFT file or an NTFS volume image.", ParamString)}, returns: pairRet("the recovered deleted entries and how many were skipped", ParamHash).withFields("deleted_count", "entries", "skipped", "source_type")},
	BuiltinNameLnkParse:           {signature: "lnk_parse(path)", summary: "Parses a Windows shell link (.lnk): header (attributes, creation/access/write FILETIME->unix), decoded LinkFlags, LinkInfo local_base_path (target), and StringData (name, relative_path, working_dir, arguments, icon_location). Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .lnk shell link file.", ParamString)}, returns: pairRet("the shell link's header, target, and tracker fields", ParamHash)},
	BuiltinNameEventsFrom:         {signature: "events_from(artifact, kind_or_mapping)", summary: "Normalizes a parsed artifact into interchange events: one event per timestamp the artifact records, in a fixed vocabulary the ECS/OCSF/Timesketch emitters are written against. The second argument names a built-in source kind (event_kinds() lists them) or is a mapping hash {kind, category, action, entries, message, times:[{field, desc, format?, ns_field?, array?}], fields:{envelope: source}} describing an artifact this tree does not know. Unknown fields are omitted rather than emitted empty, a zero timestamp yields no event, and `extra` carries the source entry verbatim so normalizing loses nothing. Accepts a parser's (result, err) pair directly. Returns (events, err).", params: []builtinParamDoc{param("artifact", "A parser's result hash (its entries/records array is found for you) or an array of entries.", ParamHash, ParamArray), param("kind_or_mapping", "A source kind from event_kinds(), or a mapping hash describing the artifact.", ParamString, ParamHash)}, returns: pairRet("one event per timestamp the artifact records", ParamArray).ofElem(ParamHash).withFields("category", "extra", "iso", "kind", "ts", "ts_desc", "ts_ms")},
	BuiltinNameEventKinds:         {signature: "event_kinds()", summary: "Lists the artifact kinds events_from understands, each with the envelope category and action it maps to, the key its entries live under, the timestamps it reads and what each one means, and the envelope fields it fills.", returns: ret("one descriptor per supported source kind, ordered by kind", ParamArray).ofElem(ParamHash).withFields("action", "category", "entries_key", "fields", "kind", "times")},
	BuiltinNameEcsEvent:           {signature: "ecs_event(event, opts?)", summary: "Renders events_from() events as Elastic Common Schema documents: one ECS document, or one per event when given a whole timeline. Maps the envelope onto @timestamp, event.*, host/user, file.*, process.*, source/destination.*, url.full and registry.path; keeps the severity word in log.level beside a syslog-scale event.severity; and carries what ECS does not define under a `mutant` namespace -- including ts_desc, without which the four documents an $MFT record produces are the same document four times, and the verbatim source entry in mutant.extra. A field the artifact did not record is omitted rather than emitted empty. A category ECS has no honest home for, log among them, leaves event.category out rather than filing the document under the wrong one. Returns (document(s), err).", params: []builtinParamDoc{param("event", "An events_from() event, or an array of them.", ParamHash, ParamArray), param("opts?", "Optional {host, user, tags, extra, version}. host and user fill in what an artifact structurally cannot record; extra:false leaves the verbatim source entry out; version sets ecs.version (default 8.11.0).", ParamHash)}, returns: pairRet("an ECS document, or one per event when given an array", ParamHash, ParamArray)},
	BuiltinNameOcsfEvent:          {signature: "ocsf_event(event, opts?)", summary: "Renders events_from() events as OCSF 1.1 events: one event, or one per event when given a whole timeline. The class comes from the envelope category -- file to 1001 File System Activity, web to 6001, network to 4001, authentication to 3002 -- and anything with no honest fit, execution and registry included, stays on the Base Event 0/0 rather than borrowing a class someone else's detection rule fires on. activity_id is read from what the timestamp records, so a creation time becomes Create and an access time becomes Read; the severity word maps straight onto severity_id, which is why the envelope carries a word. What OCSF has no home for -- the kind, the timestamp description, the verbatim source entry -- goes in `unmapped`, the field OCSF keeps for exactly that. Returns (event(s), err).", params: []builtinParamDoc{param("event", "An events_from() event, or an array of them.", ParamHash, ParamArray), param("opts?", "Optional {host, user, tags, extra, version}. host and user fill in what an artifact structurally cannot record; extra:false leaves the verbatim source entry out; version sets metadata.version (default 1.1.0).", ParamHash)}, returns: pairRet("an OCSF event, or one per event when given an array", ParamHash, ParamArray)},
	BuiltinNameTimesketchEvent:    {signature: "timesketch_event(event, opts?)", summary: "Renders events_from() events as Timesketch/plaso records, ready for ndjson_stringify: one record, or one per event when given a whole timeline. Fills all three fields Timesketch requires -- message, datetime, timestamp_desc -- and never leaves one empty, because a record missing any of them is dropped on ingest rather than flagged. `timestamp` counts plaso microseconds. `data_type` is the plaso string its analyzers key off (mft to fs:stat:ntfs, prefetch to windows:prefetch:execution, the browser kinds by which browser the entry came out of); a kind with no plaso equivalent gets mutant:<kind>:event rather than borrowing one an analyzer would then run over and report on. Returns (record(s), err).", params: []builtinParamDoc{param("event", "An events_from() event, or an array of them.", ParamHash, ParamArray), param("opts?", "Optional {host, user, tags, extra, data_type}. host and user fill in what an artifact structurally cannot record; tags becomes Timesketch's tag list; extra:false leaves the verbatim source entry out; data_type overrides the plaso type.", ParamHash)}, returns: pairRet("a Timesketch record, or one per event when given an array", ParamHash, ParamArray)},
	BuiltinNameStixBundle:         {signature: "stix_bundle(iocs, opts?)", summary: "Renders indicators as a STIX 2.1 bundle, taking extract_iocs() output directly. ipv4 and ipv6 become ipv4-addr and ipv6-addr observables, domains become domain-name, urls url, emails email-addr, and each md5/sha1/sha256 digest becomes a file observable carrying that one algorithm -- three digests of one file are three observables, because nothing in a list of digests says they describe the same file. Every id is a UUIDv5 over the object's ID contributing properties under the namespace STIX fixes for the purpose, so the same indicator is the same object wherever it is seen and a re-run over the same evidence is the same bundle byte for byte. `indicators: true` adds an Indicator beside each observable, typed `unknown` rather than `malicious-activity`: extraction found the value, it did not conclude anything about it. A key no indicator type claims is an error, and so is a value that is not what its key says -- a 40-character digest under sha256 would become an observable nothing else can match. A bundle with no indicators in it has no `objects` key, because an empty STIX list property must be left out. Returns (bundle, err).", params: []builtinParamDoc{param("iocs", "Indicators grouped by type, as extract_iocs returns: {ipv4, ipv6, domains, urls, emails, md5, sha1, sha256}. Each value is a STRING or an ARRAY of STRING.", ParamHash), param("opts?", "Optional {indicators, created, tags}. indicators:true adds Indicator objects; created stamps them (RFC 3339, default now) and pinning it makes even those byte-identical between runs; tags becomes each Indicator's labels, and needs indicators:true, since a STIX observable has no labels property.", ParamHash)}, returns: pairRet("a STIX 2.1 bundle", ParamHash).withFields("id", "objects", "type")},
	BuiltinNameStixPattern:        {signature: "stix_pattern(type, value)", summary: "Renders the STIX pattern that matches one indicator: stix_pattern(\"sha256\", digest) gives [file:hashes.'SHA-256' = '...']. Takes the same type names stix_bundle accepts (ipv4, ipv6, domains, urls, emails, md5, sha1, sha256, and their singular spellings), normalizes and checks the value the same way, and escapes it for the pattern. Returns (pattern, err).", params: []builtinParamDoc{param("type", "Indicator type: ipv4, ipv6, domains, urls, emails, md5, sha1 or sha256.", ParamString), param("value", "The indicator itself.", ParamString)}, returns: pairRet("a STIX pattern string", ParamString)},
	BuiltinNameReportNew: {
		signature: "report_new(title, opts?)",
		summary:   "Starts a report. The report is a plain hash -- title, generated, and a sections array -- so it can be JSON-encoded, diffed against yesterday's, or written by hand; every builder here returns a new document rather than changing the one it was given. `generated` defaults to now and is the only field that cannot be derived from the document, so pinning it makes two renders of one investigation the same bytes. Returns (report, err).",
		params: []builtinParamDoc{
			param("title", "What was examined. A report without one is refused.", ParamString),
			param("opts?", "Optional {subtitle, examiner, case_id, generated}. generated is RFC 3339 and defaults to now; pin it for byte-identical output.", ParamHash),
		},
		returns: pairRet("a new report", ParamHash).withFields("generated", "sections", "title")},
	BuiltinNameReportSection: {
		signature: "report_section(report, heading, opts?)",
		summary:   "Opens a section. Everything added afterwards lands in it, until the next one. Returns (report, err).",
		params: []builtinParamDoc{
			param("report", "The report so far.", ParamHash),
			param("heading", "The section heading.", ParamString),
			param("opts?", "Optional {level}: the heading depth, 1 to 6, default 2. The title is always the level above.", ParamHash),
		},
		returns: pairRet("the report with the section opened", ParamHash).withFields("generated", "sections", "title")},
	BuiltinNameReportText: {
		signature: "report_text(report, text)",
		summary:   "Adds a paragraph. Line breaks inside it survive every format. A paragraph written before the first report_section lands in a lead section that renders without a heading, because a report usually opens with a summary. Returns (report, err).",
		params: []builtinParamDoc{
			param("report", "The report so far.", ParamHash),
			param("text", "The paragraph. Rendered as text in every format -- nothing in it is ever interpreted as markup.", ParamString),
		},
		returns: pairRet("the report with the paragraph added", ParamHash).withFields("generated", "sections", "title")},
	BuiltinNameReportList: {
		signature: "report_list(report, items, opts?)",
		summary:   "Adds a bulleted list, or a numbered one with {\"ordered\": true}. Items are scalars, rendered the way a CSV cell is, so a count that arrived as an INTEGER needs no conversion. Returns (report, err).",
		params: []builtinParamDoc{
			param("report", "The report so far.", ParamHash),
			param("items", "The list items: STRING, INTEGER, FLOAT, BOOLEAN or NULL. A nested hash is refused here rather than appearing mid-sentence in the output.", ParamArray),
			param("opts?", "Optional {ordered}: true numbers the list. Default false.", ParamHash),
		},
		returns: pairRet("the report with the list added", ParamHash).withFields("generated", "sections", "title")},
	BuiltinNameReportTable: {
		signature: "report_table(report, rows, opts?)",
		summary:   "Adds a table. Rows arrive in either shape csv_stringify takes -- an array of arrays written positionally, or an array of hashes written against a column list -- and go through the same normalization, so a table in a report and the same table written straight to CSV cannot disagree about what a cell contains. A table with no rows and no columns is refused: pass `columns` to record that a search found nothing. Returns (report, err).",
		params: []builtinParamDoc{
			param("report", "The report so far.", ParamHash),
			param("rows", "An ARRAY of ARRAYs, or an ARRAY of HASHes. Cells are scalars.", ParamArray),
			param("opts?", "Optional {columns, caption, header}. columns names and orders the fields, and for hash rows selects them; header:false drops the header row.", ParamHash),
		},
		returns: pairRet("the report with the table added", ParamHash).withFields("generated", "sections", "title")},
	BuiltinNameReportRender: {
		signature: "report_render(report, format, opts?)",
		summary:   "Renders a report as \"html\", \"markdown\" or \"csv\". The whole document is validated first and a block nothing renders is an error naming its section and index, because a renderer that steps over what it does not understand produces a report that looks complete and is missing a finding. HTML is the format to hand to a person: every string is escaped, the stylesheet is inlined, there is no script, font or image, and evidence text is never turned into a link -- a report that makes the attacker's URL clickable is a report that can be clicked. Markdown is escaped for structure, so a pipe in a filename cannot shift a table column. CSV carries one table, and guards the cells a spreadsheet would execute. Returns (text, err).",
		params: []builtinParamDoc{
			param("report", "The report to render.", ParamHash),
			param("format", "\"html\", \"markdown\" (or \"md\"), or \"csv\".", ParamString),
			param("opts?", "html: {fragment} omits the document wrapper. csv: {table} names which table by index or caption -- required when there is more than one, since a CSV file holds one; {delimiter}; {formula_guard} false writes cells beginning = + - @ unaltered, for output that will be parsed rather than opened in a spreadsheet.", ParamHash),
		},
		returns: pairRet("the rendered report", ParamString)},
	BuiltinNameReportWrite: {
		signature: "report_write(report, path, opts?)",
		summary:   "Renders a report and writes it to disk, returning what the file turned out to be: {path, bytes, format, sha256}. The format comes from the path's extension -- .html, .htm, .md, .markdown, .csv -- or from {\"format\": ...} for a path whose name says nothing. The digest is read back off the disk and checked against the document that was meant to be there, so a short write or a full disk is a refusal rather than a hash of something nobody can reproduce. When a case is open the write becomes a timeline entry carrying the path and the digest, which is the whole of the link between an investigation and the documents it produced. Returns (result, err).",
		params: []builtinParamDoc{
			param("report", "The report to write.", ParamHash),
			param("path", "Where to write it. The file is created 0600.", ParamString),
			param("opts?", "Optional {format} plus every report_render option: {fragment} for html, {table}, {delimiter} and {formula_guard} for csv.", ParamHash),
		},
		returns: pairRet("what was written", ParamHash).withFields("bytes", "format", "path", "sha256")},
	BuiltinNameMactime: {signature: "mactime(entries)", summary: "Builds a chronological MAC-time timeline from bodyfile_parse entries: one row per distinct time with a MACB flag string (m/a/c/b, \".\" where absent), sorted by ts then name (ts field composes with timeline_merge).", returns: ret("one row per distinct timestamp, in chronological order", ParamArray).ofElem(ParamHash).withFields("gid", "inode", "iso", "macb", "md5", "mode", "name", "size", "ts", "uid"), params: []builtinParamDoc{param("entries", "Entries from bodyfile_parse.", ParamArray)}},
	// security: fingerprinting
	BuiltinNameImphash: {signature: "imphash(pe_path)", summary: "Computes the PE import hash (pefile/Mandiant algorithm) for malware clustering. Returns {imphash, import_count, dll_count}. Note: ordinal-only imports are rendered as ord<N>, so results may differ from VT for ws2_32/oleaut32 ordinal imports. Returns (result, err).", params: []builtinParamDoc{param("pe_path", "Path to a PE (Windows) binary.", ParamString)}, returns: pairRet("the PE import hash and the counts it was computed over", ParamHash).withFields("dll_count", "imphash", "import_count")},
	BuiltinNameNTHash:  {signature: "nt_hash(password)", summary: "Returns the NTLM NT hash (MD4 of the UTF-16LE password) as hex. For authorized credential testing/CTF use.", returns: ret("the NTLM NT hash (MD4 of the UTF-16LE password) as hex", ParamString), params: []builtinParamDoc{param("password", "Password to hash.", ParamString)}},
	BuiltinNameLMHash:  {signature: "lm_hash(password)", summary: "Returns the legacy LM hash (DES-based; case-insensitive, max 14 chars) as hex. Empty password -> aad3b435b51404eeaad3b435b51404ee.", returns: ret("the legacy LM hash (DES-based; case-insensitive, max 14 chars) as hex", ParamString), params: []builtinParamDoc{param("password", "Password to hash.", ParamString)}},
	BuiltinNameJA3:     {signature: "ja3(client_hello)", summary: "Computes the JA3 TLS-client fingerprint from a ClientHello (raw bytes, with or without the TLS record layer). Hashes version,ciphers,extensions,curves,point_formats with GREASE (RFC 8701) removed. Returns {ja3, ja3_hash (md5), tls_version, ciphers[], extensions[], curves[], point_formats[]}. Returns (result, err).", params: []builtinParamDoc{param("client_hello", "Raw bytes of a TLS ClientHello (optionally wrapped in its record layer).", ParamString)}, returns: pairRet("the JA3 string and its MD5 hash, plus the fields they were built from", ParamHash).withFields("ciphers", "curves", "extensions", "ja3", "ja3_hash", "point_formats", "tls_version")},
	// security: crypto
	BuiltinNameX509Parse:       {signature: "x509_parse(pem_or_der)", summary: "Parses an X.509 certificate (PEM or DER). Returns {subject, issuer, serial, not_before, not_after, is_ca, version, dns_names, ip_addresses, email_addresses, key_algorithm, signature_algorithm, sha1, sha256}. Returns (cert, err).", params: []builtinParamDoc{param("pem_or_der", "Certificate bytes in PEM or DER form.", ParamString)}, returns: pairRet("the certificate's subject, issuer, validity window, and fingerprints", ParamHash).withFields("dns_names", "email_addresses", "ip_addresses", "is_ca", "issuer", "key_algorithm", "not_after", "not_before", "serial", "sha1", "sha256", "signature_algorithm", "subject", "version")},
	BuiltinNameJWTDecode:       {signature: "jwt_decode(token)", summary: "Decodes a JWT's header and claims WITHOUT verifying the signature (verified is always false). Returns {header, claims, algorithm, signature_present, verified}. Returns (result, err).", params: []builtinParamDoc{param("token", "Compact JWT string (header.payload.signature).", ParamString)}, returns: pairRet("the token's header and claims; the signature is never verified", ParamHash).withFields("algorithm", "claims", "header", "signature_present", "verified")},
	BuiltinNameAESEncrypt:      {signature: "aes_encrypt(key, plaintext)", summary: "AES-GCM encrypts plaintext. key must be 16/24/32 bytes. A random nonce is prepended to the output. Returns (ciphertext, err).", params: []builtinParamDoc{param("key", "16/24/32-byte key (AES-128/192/256).", ParamString), param("plaintext", "Text or buffer to encrypt.", ParamString, ParamBytes)}, returns: pairRet("the ciphertext, with the random nonce prepended", ParamString)},
	BuiltinNameAESDecryptBytes: {signature: "aes_decrypt_bytes(key, ciphertext)", summary: "AES-GCM decrypts into a BYTES buffer. Recovered plaintext is binary until something proves otherwise, and a buffer is also the form the VM can wipe. Returns (plaintext, err).", params: []builtinParamDoc{param("key", "16/24/32-byte key.", ParamString), param("ciphertext", "Nonce-prefixed AES-GCM ciphertext.", ParamString, ParamBytes)}, returns: pairRet("the recovered plaintext", ParamBytes)},
	BuiltinNameAESDecrypt:      {signature: "aes_decrypt(key, ciphertext)", summary: "AES-GCM decrypts ciphertext produced by aes_encrypt (nonce-prefixed). Returns (plaintext, err); errors on wrong key or tampering.", params: []builtinParamDoc{param("key", "16/24/32-byte key.", ParamString), param("ciphertext", "Nonce-prefixed AES-GCM ciphertext.", ParamString)}, returns: pairRet("the recovered plaintext", ParamString)},
	BuiltinNamePEMDecode:       {signature: "pem_decode(s)", summary: "Decodes the first PEM block. Returns {type, headers, der_hex, size, remaining_bytes}. Returns (result, err).", returns: pairRet("the first PEM block, with its DER body hex-encoded", ParamHash).withFields("der_hex", "headers", "remaining_bytes", "size", "type"), params: []builtinParamDoc{param("s", "PEM text to decode.", ParamString)}},
	BuiltinNameTextContains: {
		signature: "text_contains(haystack, needle)", summary: "Returns whether a string contains a substring.",
		params: []builtinParamDoc{
			param("haystack", "String to search in.", ParamString),
			param("needle", "Substring to search for.", ParamString),
		},
		returns: ret("whether a string contains a substring", ParamBool)},
	BuiltinNameTextIndex: {
		signature: "text_index(haystack, needle)", summary: "Returns the first index of substring occurrence, or -1.",
		params: []builtinParamDoc{
			param("haystack", "String to search in.", ParamString),
			param("needle", "Substring to search for.", ParamString),
		},
		returns: ret("the first index of substring occurrence, or -1", ParamInt)},
	BuiltinNameTextCount: {
		signature: "text_count(haystack, needle)", summary: "Counts non-overlapping substring occurrences.",
		params: []builtinParamDoc{
			param("haystack", "String to search in.", ParamString),
			param("needle", "Substring to count.", ParamString),
		},
		returns: ret("the number of non-overlapping occurrences", ParamInt)},
	BuiltinNameTextSplit: {
		signature: "text_split(text, sep)", summary: "Splits text by separator and returns an array of parts.",
		params: []builtinParamDoc{
			param("text", "String to split.", ParamString),
			param("sep", "Separator to split on.", ParamString),
		},
		returns: ret("the parts between separators", ParamArray).ofElem(ParamString)},
	// TextReplace accepts 3 or 4 arguments (builtin/text_matching.go); the
	// signature previously omitted the optional replacement count.
	BuiltinNameTextReplace: {
		signature: "text_replace(text, old, new, count?)", summary: "Replaces substring occurrences in text; count limits how many (all by default).",
		params: []builtinParamDoc{
			param("text", "String to rewrite.", ParamString),
			param("old", "Substring to replace.", ParamString),
			param("new", "Replacement substring.", ParamString),
			param("count?", "Maximum replacements; all occurrences when omitted.", ParamInt),
		},
		returns: ret("text with the matched occurrences replaced", ParamString)},
	BuiltinNameTextLevenshtein: {
		signature: "text_levenshtein(left, right)",
		summary:   "Computes Levenshtein edit distance between two strings.",
		params: []builtinParamDoc{
			param("left", "First string to compare.", ParamString),
			param("right", "Second string to compare.", ParamString),
		},
		returns: ret("the edit distance in single-character operations", ParamInt)},
	BuiltinNameTextSimilarity: {
		signature: "text_similarity(left, right)",
		summary:   "Computes normalized Levenshtein similarity between two strings.",
		params: []builtinParamDoc{
			param("left", "First string to compare.", ParamString),
			param("right", "Second string to compare.", ParamString),
		},
		returns: ret("a similarity score from 0.0 (unrelated) to 1.0 (identical)", ParamFloat)},
	BuiltinNameTextFuzzyFind: {
		signature: "text_fuzzy_find(query, candidates, maxDistance?)",
		summary:   "Finds the closest fuzzy match in an array of candidate strings.",
		params: []builtinParamDoc{
			param("query", "String to match against the candidates.", ParamString),
			arrayParam("candidates", "Array of candidate strings.", ParamString),
			param("maxDistance?", "Largest edit distance still considered a match.", ParamInt),
		},
		returns: ret("the closest candidate and how close it was", ParamHash).withFields("distance", "found", "index", "match")},
	BuiltinNameTextJaroWinkler: {
		signature: "text_jaro_winkler(left, right)",
		summary:   "Computes Jaro-Winkler string similarity score.",
		params: []builtinParamDoc{
			param("left", "First string to compare.", ParamString),
			param("right", "Second string to compare.", ParamString),
		},
		returns: ret("a Jaro-Winkler score from 0.0 (unrelated) to 1.0 (identical)", ParamFloat)},
	// Every regex builtin takes its pattern and input through
	// regexPatternAndInput, which requires two STRINGs (builtin/regex.go).
	BuiltinNameRegexMatch: {
		signature: "regex_match(pattern, input)", summary: "Returns whether regex pattern matches input.",
		params: []builtinParamDoc{
			param("pattern", "Regular expression pattern.", ParamString),
			param("input", "Input string to test.", ParamString),
		},
		returns: pairRet("whether regex pattern matches input", ParamBool)},
	BuiltinNameRegexFind: {
		signature: "regex_find(pattern, input)", summary: "Finds the first regex match in input.",
		params: []builtinParamDoc{
			param("pattern", "Regular expression pattern.", ParamString),
			param("input", "Input string to search.", ParamString),
		},
		returns: pairRet("the first match, or null when the pattern does not match", ParamString, ParamNull)},
	BuiltinNameRegexFindAll: {
		signature: "regex_find_all(pattern, input, limit?)",
		summary:   "Finds all regex matches with optional result limit.",
		params: []builtinParamDoc{
			param("pattern", "Regular expression pattern.", ParamString),
			param("input", "Input string to search.", ParamString),
			param("limit?", "Maximum matches to return; all matches when omitted.", ParamInt),
		},
		returns: pairRet("every match, in the order found", ParamArray).ofElem(ParamString)},
	BuiltinNameRegexReplace: {
		signature: "regex_replace(pattern, input, replacement)",
		summary:   "Replaces all regex matches in input with replacement text.",
		params: []builtinParamDoc{
			param("pattern", "Regular expression pattern.", ParamString),
			param("input", "Input string to transform.", ParamString),
			param("replacement", "Replacement text for each match.", ParamString),
		},
		returns: pairRet("input with every match replaced", ParamString)},
	BuiltinNameRegexCaptureGroups: {
		signature: "regex_capture_groups(pattern, input)",
		summary:   "Returns full regex capture array (full match plus groups).",
		params: []builtinParamDoc{
			param("pattern", "Regular expression pattern with capture groups.", ParamString),
			param("input", "Input string to match against.", ParamString),
		},
		returns: pairRet("full regex capture array (full match plus groups)", ParamArray).ofElem(ParamString)},
	BuiltinNamePolicyLoad: {
		signature: "policy_load(name, source)",
		summary:   "Loads a policy module by name from source text or config hash.",
		returns:   pairRet("the loaded policy's name, package, and query set", ParamHash).withFields("allow_query", "eval_query", "loaded", "name", "package", "rules_query"), params: []builtinParamDoc{param("name", "Name the policy is registered under; must not be empty.", ParamString), param("source", "Rego module source, or a config hash describing it.", ParamHash, ParamString)}},
	BuiltinNamePolicyEval: {
		signature: "policy_eval(policy, input)",
		summary:   "Evaluates a loaded policy and returns decision details.",
		params: []builtinParamDoc{
			param("policy", "Policy name or handle.", ParamHash, ParamString),
			param("input", "Input data evaluated by the policy.", ParamHash),
		},
		returns: pairRet("the decision and the details behind it", ParamHash)},
	BuiltinNamePolicyAllow: {
		signature: "policy_allow(policy, input)",
		summary:   "Evaluates and returns allow/deny boolean for a policy.",
		returns:   pairRet("whether the policy's allow rule holds for input", ParamBool), params: []builtinParamDoc{param("policy", "Policy name loaded with policy_load, or the module source itself.", ParamHash, ParamString), param("input", "Input document the allow rule is evaluated against.", ParamHash)}},
	BuiltinNamePolicyRules: {
		signature: "policy_rules(policy)",
		summary:   "Returns rule metadata exported by a loaded policy.",
		returns:   pairRet("the policy's rule set, in whatever shape the query yields", ParamAny), params: []builtinParamDoc{param("policy", "Policy name loaded with policy_load, or the module source itself.", ParamHash, ParamString)}},
	BuiltinNamePolicyTrace: {
		signature: "policy_trace(policy, input)",
		summary:   "Runs policy evaluation with trace output for debugging rule flow.",
		params: []builtinParamDoc{
			param("policy", "Policy name or handle.", ParamHash, ParamString),
			param("input", "Input data evaluated by the policy.", ParamHash),
		},
		returns: pairRet("the evaluation trace, in whatever shape the query yields", ParamAny)},
	BuiltinNameCacheOpen: {
		signature: "cache_open(name)",
		summary:   "Opens or creates a named in-memory cache store.",
		params:    []builtinParamDoc{param("name", "Cache namespace identifier.", ParamString)},
		returns:   pairRet("the cache's name and whether this call created it", ParamHash).withFields("created", "name", "opened")},
	BuiltinNameCachePut: {
		signature: "cache_put(name, key, value, ttlSeconds?)",
		summary:   "Stores a value in a named cache key with optional TTL.",
		params: []builtinParamDoc{
			param("name", "Cache namespace identifier.", ParamString),
			param("key", "Cache key string.", ParamString),
			param("value", "Value to store; any type is accepted.", ParamAny),
			param("ttlSeconds?", "Optional expiration in seconds (0 for no expiry).", ParamInt),
		},
		returns: pairRet("true once the value has been stored", ParamBool)},
	BuiltinNameCacheGet: {
		signature: "cache_get(name, key)",
		summary:   "Reads a value from cache and returns found/value fields.",
		params: []builtinParamDoc{
			param("name", "Cache namespace identifier.", ParamString),
			param("key", "Cache key string.", ParamString),
		},
		returns: pairRet("the stored value, and whether the key was present at all", ParamHash).withFields("found", "value")},
	BuiltinNameCacheDelete: {
		signature: "cache_delete(name, key)",
		summary:   "Deletes a key from cache and returns whether it existed.",
		returns:   pairRet("whether the key existed before it was removed", ParamBool), params: []builtinParamDoc{param("name", "Cache namespace holding the key.", ParamString), param("key", "Key to remove.", ParamString)}},
	BuiltinNameCacheKeys: {
		signature: "cache_keys(name)",
		summary:   "Lists sorted cache keys for a cache namespace.",
		returns:   pairRet("the cache's keys, sorted", ParamArray).ofElem(ParamString), params: []builtinParamDoc{param("name", "Cache namespace to list.", ParamString)}},
	BuiltinNameCacheStats: {
		signature: "cache_stats(name)",
		summary:   "Returns cache counters such as hits, misses, puts, deletes, and expires.",
		params:    []builtinParamDoc{param("name", "Cache namespace identifier.", ParamString)},
		returns:   pairRet("cache counters such as hits, misses, puts, deletes, and expires", ParamHash).withFields("clears", "deletes", "expires", "hits", "items", "misses", "name", "puts")},
	BuiltinNameCacheClear: {
		signature: "cache_clear(name)",
		summary:   "Clears all entries and resets relevant cache state.",
		returns:   pairRet("the number of entries removed", ParamInt), params: []builtinParamDoc{param("name", "Cache namespace to empty.", ParamString)}},
	BuiltinNameProcessList: {signature: "process_list()", summary: "Lists running processes (pid, ppid, name) natively on Windows, Linux, and macOS.", returns: pairRet("one hash per running process", ParamArray).ofElem(ParamHash).withFields("name", "pid", "ppid")},
	BuiltinNameProcessTree: {
		signature: "process_tree(rootPid?)",
		summary:   "Returns descendant processes for a root pid (default current process). Cross-platform, using real parent PIDs on every OS.",
		params:    []builtinParamDoc{param("rootPid?", "Optional root process ID; defaults to current process.", ParamInt)},
		returns:   pairRet("descendant processes for a root pid (default current process)", ParamHash)},
	BuiltinNameProcessOpenFiles: {
		signature: "process_open_files(pid?)",
		summary:   "Lists open file paths for a process (cross-platform; may require privileges for other processes).",
		params:    []builtinParamDoc{param("pid?", "Optional process ID; defaults to current process.", ParamInt)},
		returns:   pairRet("the open file paths", ParamArray).ofElem(ParamString)},
	BuiltinNameProcessThreads: {
		signature: "process_threads(pid?)",
		summary:   "Returns {pid, count, tids} for a process. The thread count is cross-platform; tids are populated where the OS exposes them (e.g. Linux).",
		params:    []builtinParamDoc{param("pid?", "Optional process ID; defaults to current process.", ParamInt)},
		returns:   pairRet("the process's thread IDs, and how many there are", ParamHash).withFields("count", "pid", "tids")},
	BuiltinNameProcessModules: {
		signature: "process_modules(pid?)",
		summary:   "Lists loaded module/library paths for a process (memory maps on Linux, Toolhelp32 on Windows; fails honestly on platforms without a backend, e.g. macOS).",
		params:    []builtinParamDoc{param("pid?", "Optional process ID; defaults to current process.", ParamInt)},
		platforms: []string{"windows", "linux"},
		returns:   pairRet("the loaded module paths", ParamArray).ofElem(ParamString)},
	BuiltinNameProcessHash: {
		signature: "process_hash(pid?)",
		summary:   "Computes SHA-256 hash metadata for a process executable.",
		params:    []builtinParamDoc{param("pid?", "Optional process ID; defaults to current process.", ParamInt)},
		returns:   pairRet("the executable's SHA-256 digest and size", ParamHash).withFields("path", "pid", "sha256", "size")},
	BuiltinNameProcessMemoryScan: {
		signature: "process_memory_scan(pid, pattern)",
		summary:   "Scans a process's readable memory for a byte pattern and returns {pid, pattern, matched, truncated, addresses}. Real scan on Linux (/proc/self/mem) and Windows (VirtualQuery+ReadProcessMemory); self process only for now; honest error on macOS.",
		params: []builtinParamDoc{
			param("pid", "Target process ID (must be the current process for now).", ParamInt),
			param("pattern", "Non-empty byte pattern to search for.", ParamString),
		},
		platforms: []string{"windows", "linux"},
		returns:   pairRet("the addresses at which the pattern matched", ParamHash).withFields("addresses", "matched", "pattern", "pid", "truncated")},
	BuiltinNameProcessEnv: {
		signature: "process_env(pid?)",
		summary:   "Returns environment variables for a process (cross-platform; other processes may require privileges).",
		params:    []builtinParamDoc{param("pid?", "Optional process ID; defaults to current process.", ParamInt)},
		returns:   pairRet("environment variables for a process (cross-platform; other processes may require privileges)", ParamHash)},
	BuiltinNameProcessKill: {
		signature: "process_kill(pid, signal?)",
		summary:   "Sends a signal to a process (default SIGKILL semantics).",
		params: []builtinParamDoc{
			param("pid", "Target process ID.", ParamInt),
			param("signal?", "Optional integer signal number.", ParamInt),
		},
		platformNote: "On Windows only SIGKILL semantics are honored; other signal numbers are ignored.",
		returns:      pairRet("true once the signal has been delivered", ParamBool)},
	BuiltinNameExecString: {
		signature: "exec_string(command, shell?)",
		summary:   "Executes a shell command string via security-guarded command execution.",
		params: []builtinParamDoc{
			param("command", "Command text to execute.", ParamString),
			param("shell?", "Optional shell executable (defaults to powershell).", ParamString),
		},
		returns: pairRet("the command's output streams, exit code, and timeout status", ParamHash).withFields("error", "exit_code", "ok", "schema_version", "stderr", "stdout", "timed_out")},
	BuiltinNameCmdBuilder: {
		signature: "cmd_builder(shell?)",
		summary:   "Creates a command builder object for step-wise command composition.",
		params:    []builtinParamDoc{param("shell?", "Optional shell executable (defaults to powershell).", ParamString)},
		returns:   pairRet("a fresh command builder", ParamHash).withFields("lines", "shell")},
	BuiltinNameCmdAdd: {
		signature: "cmd_add(builder, arg)",
		summary:   "Appends an argument to a command builder.",
		params: []builtinParamDoc{
			param("builder", "Builder hash returned by cmd_builder/cmd_add.", ParamHash),
			param("arg", "Command line text appended as a new line.", ParamString),
		},
		returns: pairRet("the builder, with the argument appended", ParamHash).withFields("lines", "shell")},
	BuiltinNameCmdRun: {
		signature: "cmd_run(builder)",
		summary:   "Executes a composed command and returns run output metadata.",
		params:    []builtinParamDoc{param("builder", "Builder hash containing shell and command lines.", ParamHash)},
		returns:   pairRet("the command's output streams, exit code, and timeout status", ParamHash).withFields("error", "exit_code", "ok", "schema_version", "stderr", "stdout", "timed_out")},
	BuiltinNameFsDelete: {
		signature: "fs_delete(path)", summary: "Deletes a file from disk.",
		params:  []builtinParamDoc{param("path", "Path to the file to delete.", ParamString)},
		returns: pairRet("true once the file has been deleted", ParamBool)},
	BuiltinNameFsStat: {
		signature: "fs_stat(path)", summary: "Returns file metadata such as size and timestamps.",
		params:  []builtinParamDoc{param("path", "Path to inspect.", ParamString)},
		returns: pairRet("file metadata such as size and timestamps", ParamHash).withFields("is_dir", "mod_time", "name", "size")},
	BuiltinNameFsList: {
		signature: "fs_list(path)", summary: "Lists directory entries for a path.",
		params:  []builtinParamDoc{param("path", "Directory to list.", ParamString)},
		returns: pairRet("one hash per directory entry", ParamArray).ofElem(ParamHash).withFields("is_dir", "name", "size")},
	BuiltinNameFsMkdir: {
		signature: "fs_mkdir(path)", summary: "Creates a directory path.",
		params:  []builtinParamDoc{param("path", "Directory path to create.", ParamString)},
		returns: pairRet("true once the directory exists", ParamBool)},
	BuiltinNameFsCopy: {
		signature: "fs_copy(src, dst)", summary: "Copies a file from source path to destination path.",
		params: []builtinParamDoc{
			param("src", "Source file path.", ParamString),
			param("dst", "Destination file path.", ParamString),
		},
		returns: pairRet("true once the file has been copied", ParamBool)},
	BuiltinNameFsMove: {
		signature: "fs_move(src, dst)", summary: "Moves or renames a file or directory.",
		params: []builtinParamDoc{
			param("src", "Source path.", ParamString),
			param("dst", "Destination path.", ParamString),
		},
		returns: pairRet("true once the file has been moved", ParamBool)},
	// Both of these carry a second, optional parameter the signature used to
	// omit — fs_forensics.go accepts `len(args) == 1 || len(args) == 2`. The
	// arity conformance probe caught it; without the fix the lint would flag
	// every correct two-argument call.
	BuiltinNameFsHash: {
		signature: "fs_hash(path, algo?)",
		summary:   "Computes hash digests for a file.",
		params: []builtinParamDoc{
			param("path", "Path of the file to hash.", ParamString),
			param("algo?", "Digest algorithm: `md5`, `sha1`, or `sha256` (the default).", ParamString),
		},
		returns: pairRet("the requested digest and the file's size", ParamHash).withFields("algo", "bytes", "hash", "path", "size", "status")},
	BuiltinNameFsWalk: {
		signature: "fs_walk(root, maxDepth?)",
		summary:   "Walks a directory tree and returns discovered paths.",
		params: []builtinParamDoc{
			param("root", "Directory to walk.", ParamString),
			param("maxDepth?", "Maximum depth below root; omit or pass a negative value for unlimited.", ParamInt),
		},
		returns: pairRet("one hash per path found in the tree", ParamArray).ofElem(ParamHash).withFields("depth", "is_dir", "mod_time", "name", "path", "size")},
	BuiltinNameFsMetadata: {
		signature: "fs_metadata(path)",
		summary:   "Returns detailed filesystem metadata for a path.",
		returns:   pairRet("detailed filesystem metadata for a path", ParamHash).withFields("extension", "is_dir", "is_read_only", "mod_time", "mode", "name", "path", "perm_octal", "size"), params: []builtinParamDoc{param("path", "Path to the file or directory.", ParamString)}},
	BuiltinNameFsMagic: {
		signature: "fs_magic(path)",
		summary:   "Infers file type/magic from a file's header against a ~40-signature database (executables PE/ELF/Mach-O, images, archives, documents, SQLite/registry/EVTX/pcap, media, and forensic artifacts like lnk/prefetch). Returns {path, type, mime, signature}.",
		returns:   pairRet("the inferred file type and the signature that matched", ParamHash).withFields("mime", "path", "signature", "type"), params: []builtinParamDoc{param("path", "Path to the file to identify.", ParamString)}},
	BuiltinNameFsExtractStrings: {
		signature: "fs_extract_strings(path, minLen?)",
		summary:   "Extracts printable strings from a file.",
		params: []builtinParamDoc{
			param("path", "Path to source file.", ParamString),
			param("minLen?", "Optional minimum string length (default 4).", ParamInt),
		},
		returns: pairRet("the printable strings found in the file", ParamArray).ofElem(ParamString)},
	BuiltinNameFsDiff: {
		signature: "fs_diff(leftPath, rightPath)",
		summary:   "Compares two files (not directories) and reports differences.",
		returns:   pairRet("how the two files compare, including the first differing offset", ParamHash).withFields("equal", "first_diff_offset", "path_a", "path_b", "sha256_a", "sha256_b", "size_a", "size_b"), params: []builtinParamDoc{param("leftPath", "Path to the first file; directories are not accepted.", ParamString), param("rightPath", "Path to the second file; directories are not accepted.", ParamString)}},
	BuiltinNameFsCarve: {
		signature: "fs_carve(path, type)",
		summary:   "Scans a file for a known artifact signature and returns the byte offsets where it starts. It reports offsets only; it does not extract (carve out) the artifact bytes or determine their length.",
		params: []builtinParamDoc{
			param("path", "Path to source file.", ParamString),
			param("type", "Signature type name from the shared database (e.g. pe/elf/macho64/png/jpeg/gif/zip/gzip/7z/rar/pdf/ole/sqlite/regf/evtx/gzip/mp3/mp4); an unsupported name errors with the full list.", ParamString),
		},
		returns: pairRet("one hash per carved artifact, giving its offset and type", ParamArray).ofElem(ParamHash).withFields("offset", "type")},
	BuiltinNameFsEntropy: {
		signature: "fs_entropy(path)",
		summary:   "Computes file entropy for packed/encrypted artifact detection.",
		returns:   pairRet("the file's Shannon entropy and its size in bytes", ParamHash).withFields("bytes", "entropy", "path"), params: []builtinParamDoc{param("path", "Path to the file to measure.", ParamString)}},
	BuiltinNameBinPeParse: {
		signature: "bin_pe_parse(path)",
		summary:   "Parses PE headers and returns core binary metadata.",
		params:    []builtinParamDoc{param("path", "Path to PE file.", ParamString)},
		returns:   pairRet("the PE header fields", ParamHash).withFields("characteristics", "format", "machine", "num_sections", "path", "timestamp")},
	BuiltinNameBinElfParse: {
		signature: "bin_elf_parse(path)",
		summary:   "Parses ELF headers and returns core binary metadata.",
		returns:   pairRet("the ELF header fields", ParamHash).withFields("class", "data", "entry", "format", "machine", "num_sections", "path", "type"), params: []builtinParamDoc{param("path", "Path to the ELF binary.", ParamString)}},
	BuiltinNameBinMachoParse: {
		signature: "bin_macho_parse(path)",
		summary:   "Parses a Mach-O binary (macOS/iOS). Handles thin and fat/universal images. For a thin binary returns {format, fat, magic, cpu, type, flags, num_sections, num_commands, imported_libraries}; for a fat binary returns {format, fat, num_arches, architectures:[{cpu, type, offset, size, align}]}. Returns (result, err).",
		params:    []builtinParamDoc{param("path", "Path to a Mach-O binary.", ParamString)},
		returns:   pairRet("the Mach-O header fields; a fat image reports each architecture", ParamHash)},
	BuiltinNameBinDwarfParse: {
		signature: "bin_dwarf_parse(path)",
		summary:   "Parses DWARF metadata and reports compile unit information.",
		returns:   pairRet("the DWARF compile-unit information", ParamHash).withFields("compile_units", "format", "path"), params: []builtinParamDoc{param("path", "Path to the binary.", ParamString)}},
	BuiltinNameBinStrings: {
		signature: "bin_strings(path, minLen?)",
		summary:   "Extracts printable strings from a binary.",
		returns:   pairRet("the printable strings found in the binary", ParamArray).ofElem(ParamString), params: []builtinParamDoc{param("path", "Path to the binary to scan.", ParamString), param("minLen?", "Shortest run of printable bytes to report; defaults to 4.", ParamInt)}},
	BuiltinNameBinEntropy: {
		signature: "bin_entropy(path)",
		summary:   "Computes binary entropy signal.",
		returns:   pairRet("the binary's Shannon entropy and its size in bytes", ParamHash).withFields("bytes", "entropy", "path"), params: []builtinParamDoc{param("path", "Path to the binary to measure.", ParamString)}},
	BuiltinNameBinYaraScan: {
		signature: "bin_yara_scan(path, rules, caseInsensitive?)",
		summary:   "Literal multi-string scan of a file (NOT a real YARA engine — that needs cgo). Reports every offset of each rule string. Case-sensitive unless caseInsensitive is true. Returns {engine, matched, total_hits, hits:[{rule, count, offsets}]}.",
		// Verified against binary_analysis.go: STRING path, ARRAY of STRING
		// rules ("must contain STRING rules. element %d got %s"), optional
		// BOOLEAN flag.
		params: []builtinParamDoc{
			param("path", "Path to the file to scan.", ParamString),
			arrayParam("rules", "Array of literal STRING patterns.", ParamString),
			param("caseInsensitive?", "Optional BOOLEAN; default false (case-sensitive).", ParamBool),
		},
		returns: pairRet("every offset at which one of the literal strings matched", ParamHash)},
	BuiltinNameBinImports: {
		signature: "bin_imports(path)",
		summary:   "Returns imported symbols/libraries from a binary.",
		returns:   pairRet("the imported symbols", ParamHash).withFields("format", "imports", "path"), params: []builtinParamDoc{param("path", "Path to the binary.", ParamString)}},
	BuiltinNameBinSections: {
		signature: "bin_sections(path)",
		summary:   "Returns binary section table information.",
		returns:   pairRet("one hash per section", ParamHash), params: []builtinParamDoc{param("path", "Path to the binary.", ParamString)}},
	BuiltinNameNetSynScan:     {stability: StabilityDeprecated, replacement: BuiltinNameNetConnectScan, signature: "net_syn_scan(host, startPort, endPort, timeoutMs)", summary: "DEPRECATED alias of net_connect_scan. This is a full TCP connect scan, not a half-open SYN scan; use net_connect_scan.", params: []builtinParamDoc{param("host", "Target host.", ParamString), param("startPort", "First port (inclusive).", ParamInt), param("endPort", "Last port (inclusive).", ParamInt), param("timeoutMs", "Per-port connect timeout in ms.", ParamInt)}, returns: pairRet("which ports answered, and how long the scan took", ParamHash).withFields("duration_ms", "end_port", "host", "open_ports", "scanned", "start_port")},
	BuiltinNameNetConnectScan: {signature: "net_connect_scan(host, startPort, endPort, timeoutMs)", summary: "Scans a TCP port range on a host using full connect() probes (net.Dial). Pure-Go and unprivileged; not a half-open SYN scan (which needs raw sockets/privileges).", params: []builtinParamDoc{param("host", "Target host.", ParamString), param("startPort", "First port (inclusive).", ParamInt), param("endPort", "Last port (inclusive).", ParamInt), param("timeoutMs", "Per-port connect timeout in ms.", ParamInt)}, returns: pairRet("which ports answered, and how long the scan took", ParamHash).withFields("duration_ms", "end_port", "host", "open_ports", "scanned", "start_port")},
	BuiltinNameNetUdpScan:     {signature: "net_udp_scan(host, startPort, endPort, timeoutMs)", summary: "Scans a UDP port range on a host.", params: []builtinParamDoc{param("host", "Target host.", ParamString), param("startPort", "First port (inclusive).", ParamInt), param("endPort", "Last port (inclusive).", ParamInt), param("timeoutMs", "Per-port timeout in ms.", ParamInt)}, returns: pairRet("which ports responded, and how long the scan took", ParamHash).withFields("duration_ms", "end_port", "host", "responsive_ports", "scanned", "start_port")},
	BuiltinNameNetBanner:      {signature: "net_banner(address, timeoutMs)", summary: "Collects service banner text from a network endpoint.", params: []builtinParamDoc{param("address", "host:port endpoint.", ParamString), param("timeoutMs", "Read timeout in ms.", ParamInt)}, returns: pairRet("the banner text the service sent", ParamHash).withFields("banner", "error", "ok")},
	BuiltinNameNetTlsFingerprint: {
		signature: "net_tls_fingerprint(address, timeoutMs)",
		summary:   "Collects TLS certificate and handshake fingerprint metadata.",
		params: []builtinParamDoc{
			param("address", "Host:port endpoint for TLS connection.", ParamString),
			param("timeoutMs", "Dial timeout in milliseconds.", ParamInt),
		},
		returns: pairRet("the certificate and handshake metadata", ParamHash)},
	BuiltinNameNetDnsQuery: {
		signature: "net_dns_query(name, qtype)",
		summary:   "Queries DNS records for a hostname.",
		params: []builtinParamDoc{
			param("name", "DNS name or reverse-lookup value.", ParamString),
			param("qtype", "Query type: A, AAAA, IP, CNAME, MX, TXT, NS, or PTR.", ParamString),
		},
		returns: pairRet("the records found; a STRING for a single-value record type", ParamString, ParamArray)},
	BuiltinNameNetPcapAnalyze: {
		signature: "net_pcap_analyze(path)",
		summary:   "Analyzes PCAP captures and returns flow/session signals.",
		returns:   pairRet("the flow and session signals found in the capture", ParamHash), params: []builtinParamDoc{param("path", "Path to the capture file.", ParamString)}},
	BuiltinNameNetCaptureRaw: {
		signature: "net_capture_raw(pcap_path)",
		summary:   "Reads raw packets from an offline pcap file into a per-packet listing (live interface capture needs cgo/raw sockets and is unavailable; net_pcap_analyze gives the flow summary, this gives the packets). Returns {file, link_type, count, truncated, packets:[{index, ts, timestamp, length, src, dst, protocol, sport, dport}]}. Returns (result, err).",
		params:    []builtinParamDoc{param("pcap_path", "Path to an offline pcap capture file.", ParamString)},
		returns:   pairRet("the packets read from the capture file", ParamHash)},
	BuiltinNameNetFlowReconstruct: {
		signature: "net_flow_reconstruct(packets)",
		summary:   "Reconstructs higher-level flows from packet records.",
		params:    []builtinParamDoc{param("packets", "Array of packet hashes with src/dst/ports/protocol/bytes fields.", ParamArray)},
		returns:   pairRet("one hash per reconstructed flow", ParamArray).ofElem(ParamHash).withFields("bytes", "dport", "dst", "packets", "proto", "sport", "src")},
	BuiltinNameNetOsFingerprint: {
		signature: "net_os_fingerprint(pcap_path)",
		summary:   "Passively fingerprints OS families from TCP SYN/SYN-ACK packets in an offline pcap (p0f-style heuristic over TTL, DF, window, and TCP options). Identifies an OS family, not a definitive OS; runs offline with no privileges.",
		params: []builtinParamDoc{
			param("pcap_path", "Path to a pcap file to analyze.", ParamString),
		},
		returns: pairRet("the OS families inferred from the capture", ParamHash)},
	BuiltinNameRegOpen: {
		signature:    "reg_open(source)",
		summary:      "Opens a registry data source (polymorphic) and returns {handle, path, source_type, status}. Dispatch: a regf hive file (SOFTWARE/SYSTEM/NTUSER.DAT, …) -> real hive parse; a hive-JSON file -> JSON; otherwise a live Windows registry path (e.g. HKLM\\SOFTWARE\\...) -> live registry (Windows only). Returns (result, err).",
		params:       []builtinParamDoc{param("source", "regf hive file, hive-JSON file, or live registry key path (HKLM/HKCU/HKCR/HKU/HKCC).", ParamString)},
		platformNote: "The live-registry path (HKLM\\..., HKCU\\..., etc.) is Windows-only; captured hive files and hive-JSON inputs are parsed on all platforms.",
		returns:      pairRet("a handle for the other reg_ builtins, and which source type it opened", ParamHash).withFields("handle", "path", "source_type", "status")},
	BuiltinNameRegEnumKeys: {
		signature: "reg_enum_keys(handle, keyPath?)",
		summary:   "Enumerates subkeys under a key. For hive/live sources keyPath is relative to the opened key (default root); for JSON it is the absolute path. Returns (array, err).",
		params: []builtinParamDoc{
			param("handle", "Handle returned by reg_open.", ParamString),
			param("keyPath?", "Subkey path (default: the opened key/root).", ParamString),
		},
		returns: pairRet("the subkey names under the key", ParamArray).ofElem(ParamString)},
	BuiltinNameRegEnumValues: {
		signature: "reg_enum_values(handle, keyPath?)",
		summary:   "Enumerates a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. A JSON source never reports one, having no binary type to transcribe. Works across JSON/hive-file/live sources. Returns (array, err).",
		params: []builtinParamDoc{
			param("handle", "Handle returned by reg_open.", ParamString),
			param("keyPath?", "Key path (default: the opened key/root).", ParamString),
		},
		returns: pairRet("one hash per value, with its type and decoded data, plus data_bytes on binary values", ParamArray).ofElem(ParamHash).withFields("data", "data_bytes", "name", "type")},
	BuiltinNameRegGetValue: {
		signature: "reg_get_value(handle, keyPath, valueName)",
		summary:   "Reads a specific registry value with type metadata, across JSON/hive-file/live sources. Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. A JSON source never reports one, having no binary type to transcribe. Returns (result, err).",
		params: []builtinParamDoc{
			param("handle", "Handle returned by reg_open.", ParamString),
			param("keyPath", "Key path that contains the value.", ParamString),
			param("valueName", "Registry value name to fetch.", ParamString),
		},
		returns: pairRet("the value, with its registry type, and data_bytes when that value is binary", ParamHash).withFields("data", "data_bytes", "name", "type")},
	BuiltinNameRegDeletedKeys: {
		signature: "reg_deleted_keys(handle)",
		summary:   "Lists deleted-key entries. Populated only for the JSON source (its deleted_keys field); empty for real hive files and live registry (no unallocated-cell carving).",
		returns:   pairRet("the deleted-key entries, empty for sources that do not record them", ParamArray), params: []builtinParamDoc{param("handle", "Handle from reg_open.", ParamString)}},
	BuiltinNameRegTimeline: {
		signature: "reg_timeline(handle)",
		summary:   "Returns timeline entries. Populated only for the JSON source (its timeline field); empty for real hive files and live registry.",
		params:    []builtinParamDoc{param("handle", "Handle returned by reg_open.", ParamString)},
		returns:   pairRet("timeline entries", ParamArray)},
	BuiltinNameEmailParse: {
		signature: "email_parse(raw)",
		summary:   "Parses a raw email message into headers, body parts, and attachments.",
		params:    []builtinParamDoc{param("raw", "RFC822-style raw email text.", ParamString)},
		returns:   pairRet("the message's headers, body parts, and attachments", ParamHash)},
	BuiltinNameEmailHeaders: {
		signature: "email_headers(raw)",
		summary:   "Parses and returns message headers from raw email input.",
		params:    []builtinParamDoc{param("raw", "RFC822-style raw email text.", ParamString)},
		returns:   pairRet("the message headers", ParamHash)},
	BuiltinNameEmailAttachments: {
		signature: "email_attachments(raw)",
		summary:   "Extracts attachment metadata/content details from raw email input.",
		params:    []builtinParamDoc{param("raw", "RFC822-style raw email text.", ParamString)},
		returns:   pairRet("one hash per attachment", ParamArray).ofElem(ParamHash).withFields("filename", "mime", "sha256", "size")},
	BuiltinNameEmailSpfDkim: {
		signature: "email_spf_dkim(raw)",
		summary:   "Cryptographically verifies DKIM signatures (public key via DNS) and reports SPF/DMARC. SPF is reported as recorded by the receiving MTA; DMARC combines the reported result with DKIM alignment.",
		params:    []builtinParamDoc{param("raw", "RFC822-style raw email text.", ParamString)},
		returns:   pairRet("the SPF, DKIM, and DMARC verdicts", ParamHash)},
	BuiltinNameEmailUrls: {
		signature: "email_urls(raw)",
		summary:   "Extracts and normalizes URLs from email headers and body.",
		params:    []builtinParamDoc{param("raw", "RFC822-style raw email text.", ParamString)},
		returns:   pairRet("one hash per URL found in the message", ParamArray).ofElem(ParamHash).withFields("host", "scheme", "url")},
	BuiltinNameMemMap: {
		signature: "mem_map(path)",
		summary:   "Splits a memory dump into fixed-size (4 KiB) segments, each with measured entropy and printable-byte ratio. A raw dump carries no page-protection metadata, so no readable/writable/executable flags are reported.",
		returns:   pairRet("one hash per 4 KiB segment, with its entropy and printable ratio", ParamArray).ofElem(ParamHash).withFields("entropy", "offset", "printable_ratio", "size"), params: []builtinParamDoc{param("path", "Path to the memory image.", ParamString)}},
	BuiltinNameMemRead: {
		signature: "mem_read(path, offset, size)",
		summary:   "Reads a byte range from a memory image.",
		params: []builtinParamDoc{
			param("path", "Path to memory image or dump file.", ParamString),
			param("offset", "Starting offset in bytes.", ParamInt),
			param("size", "Number of bytes to read.", ParamInt),
		},
		returns: pairRet("the bytes at the requested range, hex-encoded", ParamHash).withFields("hex", "offset", "size")},
	BuiltinNameMemReadBytes: {
		signature: "mem_read_bytes(path, offset, size)",
		summary:   "Reads a byte range from a memory image as a BYTES buffer. Unlike mem_read it returns the buffer itself rather than a hash: the offset is the one you asked for, and a short read at end-of-image is simply a shorter length. Prefer this whenever the range is going to be parsed rather than printed.",
		params: []builtinParamDoc{
			param("path", "Path to memory image or dump file.", ParamString),
			param("offset", "Starting offset in bytes.", ParamInt),
			param("size", "Number of bytes to read.", ParamInt),
		},
		returns: pairRet("the bytes at the requested range", ParamBytes)},
	BuiltinNameMemScan: {
		signature: "mem_scan(path, pattern)",
		summary:   "Scans a memory image for a string/byte pattern.",
		params: []builtinParamDoc{
			param("path", "Path to memory image or dump file.", ParamString),
			param("pattern", "String pattern to search for.", ParamString),
		},
		returns: pairRet("every offset at which the pattern matched", ParamHash).withFields("count", "offsets", "pattern")},
	BuiltinNameMemStrings: {
		signature: "mem_strings(path, minLen?)",
		summary:   "Extracts printable strings from memory image data.",
		params: []builtinParamDoc{
			param("path", "Path to memory image or dump file.", ParamString),
			param("minLen?", "Optional minimum string length (default 4).", ParamInt),
		},
		returns: pairRet("the printable strings found in the image", ParamArray).ofElem(ParamString)},
	BuiltinNameMemFindPe: {
		signature: "mem_find_pe(path)",
		summary:   "Finds PE headers in a memory image: carves each MZ marker and confirms real PEs by following e_lfanew to \"PE\\0\\0\". Returns {candidates, confirmed, headers:[{mz_offset, confirmed, pe_offset, machine}]}.",
		returns:   pairRet("the PE headers found, split into candidates and confirmed ones", ParamHash).withFields("candidates", "confirmed", "headers"), params: []builtinParamDoc{param("path", "Path to the memory image.", ParamString)}},
	BuiltinNameMemFindShellcode: {
		signature: "mem_find_shellcode(path)",
		summary:   "Scans a memory dump file for common shellcode byte signatures.",
		params:    []builtinParamDoc{param("path", "Path to memory image or dump file.", ParamString)},
		returns:   pairRet("one hash per shellcode signature hit, with its offset", ParamArray).ofElem(ParamHash).withFields("offset", "signature")},
	BuiltinNameDetectPersistence: {
		signature: "detect_persistence(facts)",
		summary:   "Detects persistence indicators from host evidence facts.",
		params:    []builtinParamDoc{param("facts", "Hash containing autorun/startup/task evidence.", ParamHash)},
		returns:   pairRet("the persistence indicators found", ParamHash)},
	BuiltinNameDetectInjection: {
		signature: "detect_injection(facts)",
		summary:   "Scores probable code injection in a memory image using multiple PE headers plus weighted shellcode signatures (GetPC via fnstenv/call-pop, PEB walks, NOP sleds); returns score and matched_signatures.",
		params:    []builtinParamDoc{param("facts", "Hash containing evidence such as mem_path.", ParamHash)},
		returns:   pairRet("an injection score and the signals behind it", ParamHash)},
	BuiltinNameDetectNetworkBeacon: {
		signature: "detect_network_beacon(flows)",
		summary:   "Detects C2 beaconing by analyzing inter-arrival interval regularity (low coefficient of variation) and optional transfer-size consistency per destination; each flow may carry ts (epoch/RFC3339) and bytes. Returns per-dst score, interval_cv, and confidence.",
		params:    []builtinParamDoc{param("flows", "Array of flow hashes with a dst, and optional ts and bytes fields.", ParamArray)},
		returns:   pairRet("a beaconing verdict and the interval statistics behind it", ParamHash)},
	BuiltinNameDetectPrivEsc: {
		signature: "detect_priv_esc(facts)",
		summary:   "Detects potential privilege-escalation indicators from host facts.",
		params:    []builtinParamDoc{param("facts", "Hash of privilege-related evidence and boolean checks.", ParamHash)},
		returns:   pairRet("a privilege-escalation score and the signals behind it", ParamHash).withFields("detected", "score", "signals")},
	BuiltinNameDetectSuspiciousFiles: {
		signature: "detect_suspicious_files(paths)",
		summary:   "Flags suspicious files via entropy tiers (high/very-high), executable magic under a document extension (extension_mismatch), and disguised double extensions (e.g. invoice.pdf.exe).",
		params:    []builtinParamDoc{param("paths", "Array of filesystem paths to inspect.", ParamArray)},
		returns:   pairRet("the files flagged, and why each was flagged", ParamHash)},
	BuiltinNameSigmaParse: {
		signature: "sigma_parse(rule)",
		summary:   "Compiles one Sigma detection rule from YAML. The rule is validated rather than accepted: a condition naming a search identifier the detection block does not define, an `all of filter*` that matches no identifier, a modifier this engine does not implement, a rule collection, `timeframe`, `near` and aggregation pipes are all errors. That is deliberate -- a rule this engine cannot evaluate has to fail where you can see it, because a detection that silently never fires reads as coverage on a report and is a blind spot in the evidence. Supported value modifiers: contains, startswith, endswith, all, cased, re (with i/m/s), base64, base64offset, utf16/utf16le/utf16be/wide, windash, cidr, lt/lte/gt/gte, exists, fieldref. The returned hash carries the detection block verbatim, so it is a rule and not a description of one: sigma_match and sigma_scan take it straight back. Returns (rule, err).",
		params:    []builtinParamDoc{param("rule", "One Sigma rule as YAML text.", ParamString, ParamBytes)},
		returns:   pairRet("the compiled rule, with the fields it reads and the search identifiers it defines", ParamHash).withFields("author", "condition", "description", "detection", "falsepositives", "fields", "id", "level", "logsource", "references", "searches", "status", "tags", "title")},
	BuiltinNameSigmaParseAll: {
		signature: "sigma_parse_all(ruleset)",
		summary:   "Compiles every rule in a multi-document YAML ruleset, which is the shape a Sigma ruleset ships in. One rule that does not compile fails the call rather than being dropped quietly: a ruleset that loads 43 of its 44 rules is a ruleset you believe covers something it does not. Returns (rules, err).",
		params:    []builtinParamDoc{param("ruleset", "A multi-document YAML ruleset.", ParamString, ParamBytes)},
		returns:   pairRet("one compiled rule per document, in file order", ParamArray).ofElem(ParamHash).withFields("author", "condition", "description", "detection", "falsepositives", "fields", "id", "level", "logsource", "references", "searches", "status", "tags", "title")},
	BuiltinNameSigmaMatch: {
		signature: "sigma_match(rule, event)",
		summary:   "Asks one rule about one event. A field named in the rule is looked up on the event and then inside `extra`, where events_from() keeps the source entry verbatim, so a rule written in a source's own taxonomy -- Image, CommandLine, EventID -- runs against a normalized Mutant event with no field-mapping file in between. String comparison is case-insensitive unless |cased, values carry Sigma's * and ? wildcards, and a field holding a list matches when any element does. `fields_missing` names the fields the rule read and this event did not carry: a rule that did not match because the field was never there is a different answer from a rule that looked and disagreed, and only one of them means clean. Accepts the rule as YAML text or as a sigma_parse hash; the hash is recompiled on every call, which is the cost sigma_scan exists to avoid. Returns (result, err).",
		params:    []builtinParamDoc{param("rule", "A Sigma rule as YAML text, or the hash sigma_parse returned.", ParamString, ParamHash), param("event", "One event -- an events_from() event, or any hash.", ParamHash)},
		returns:   pairRet("whether the rule matched, which searches held, and what it could not find", ParamHash).withFields("condition", "fields_missing", "fields_read", "id", "level", "matched", "searches", "tags", "title")},
	BuiltinNameSigmaScan: {
		signature: "sigma_scan(rules, events)",
		summary:   "Runs a ruleset over a timeline, compiling each rule once and then walking the events. Every hit records which rule fired, which of its searches held, and the event itself, so a hit is reviewable without a second lookup. `unmatched_fields` names the fields no event in the whole scan carried, which is the honest answer to whether the ruleset had anything to look at: a rule reading Image against a timeline that has no Image field did not clear the host, it never ran. Returns (report, err).",
		params:    []builtinParamDoc{param("rules", "A ruleset as YAML text, a sigma_parse hash, or an array of either.", ParamString, ParamHash, ParamArray), param("events", "An events_from() timeline, or a single event.", ParamArray, ParamHash)},
		returns:   pairRet("what matched, counted per level and per rule", ParamHash).withFields("by_level", "by_rule", "events", "hits", "matched", "rules", "unmatched_fields")},
	BuiltinNameNetResolve:    {signature: "net_resolve(host)", summary: "Resolves a host name to network addresses.", returns: pairRet("the addresses the host resolves to", ParamArray).ofElem(ParamString), params: []builtinParamDoc{param("host", "Host name to resolve.", ParamString)}},
	BuiltinNameNetDial:       {signature: "net_dial(address, timeoutMs)", summary: "Connectivity probe: dials address, immediately closes, and returns {ok, latency_ms, error}. Does not return a usable connection (use net_connect for that).", params: []builtinParamDoc{param("address", "host:port endpoint.", ParamString), param("timeoutMs", "Dial timeout in ms.", ParamInt)}, returns: pairRet("whether the address answered, and how long it took", ParamHash).withFields("error", "latency_ms", "ok")},
	BuiltinNameDbOpen:        {signature: "db_open()", summary: "Creates an in-memory graph database handle.", returns: pairRet("a handle for the other db_ builtins; close it with db_close", ParamInt)},
	BuiltinNameDbOpenDisk: {signature: "db_open_disk(path, opts?)", summary: "Opens or creates a disk-backed graph database. opts is an optional {memory_budget, discover_memory_budget, verify_on_open} hash: memory_budget caps what the store holds, in bytes, and is a whole-store figure rather than a whole-process one, so leave room for the program using it; discover_memory_budget:true derives that cap from the cgroup or Job Object limit the process is already under, and an explicit memory_budget always wins over it; verify_on_open:true checks the property indexes against the records before the handle is returned. An unknown option key is an error rather than ignored. Note that compacting a store with this build rewrites it in a newer on-disk format that older mutant builds cannot open; reading is unaffected.", params: []builtinParamDoc{param("path", "Database file path.", ParamString), param("opts?", "Optional {memory_budget, discover_memory_budget, verify_on_open}.", ParamHash)}, returns: pairRet("a handle for the other db_ builtins; close it with db_close", ParamInt)},
	BuiltinNameDbClose:       {signature: "db_close(db)", summary: "Closes a graph database handle and flushes pending state.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt)}, returns: pairRet("true once the handle has been closed and pending state flushed", ParamBool)},
	BuiltinNameDbAddNode:     {signature: "db_add_node(db, nodeType?)", summary: "Adds a DATA node and returns its ID. nodeType is an optional integer/enum node type (0–127; 0 is the DATA type used when omitted). Property hashes are not supported.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("nodeType?", "Optional integer/enum node type (0–127).", ParamInt, ParamEnum)}, returns: pairRet("the new node's ID", ParamInt)},
	BuiltinNameDbAddEdge:     {signature: "db_add_edge(db, from, to, edgeType?)", summary: "Adds an edge between two node IDs. edgeType is an optional integer/enum edge type. Edge property hashes are not supported.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("from", "Source node ID.", ParamInt), param("to", "Destination node ID.", ParamInt), param("edgeType?", "Optional integer/enum edge type.", ParamInt, ParamEnum)}, returns: pairRet("the new edge's ID", ParamInt)},
	BuiltinNameDbAddArtifact: {signature: "db_add_artifact(db, type, attrs?)", summary: "Adds a forensic artifact node. type is a STRING; attrs is an optional properties hash that is indexed.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("type", "Artifact type string.", ParamString), param("attrs?", "Optional attributes hash (indexed).", ParamHash)}, returns: pairRet("the new artifact node", ParamHash)},
	BuiltinNameDbAddRelation: {signature: "db_add_relation(db, from, to, relation)", summary: "Adds a named relation edge between two entity IDs. All four arguments are required; property hashes are not supported.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("from", "Source entity ID.", ParamInt), param("to", "Destination entity ID.", ParamInt), param("relation", "Relation type string.", ParamString)}, returns: pairRet("the new relation edge", ParamHash)},
	BuiltinNameDbIndexProp:   {signature: "db_index_prop(db, nodeID, key, value)", summary: "Indexes a property (key=value) on a node. All four arguments are required.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("nodeID", "Node ID to index.", ParamInt), param("key", "Property key.", ParamString), param("value", "Property value.", ParamString)}, returns: pairRet("true once the property has been indexed", ParamBool)},
	BuiltinNameDbQueryNodes:  {signature: "db_query_nodes(db, nodeType?)", summary: "Returns node IDs, optionally filtered to a single node type (integer/enum).", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("nodeType?", "Optional integer/enum node type filter.", ParamInt, ParamEnum)}, returns: pairRet("node IDs, optionally filtered to a single node type (integer/enum)", ParamArray).ofElem(ParamInt)},
	// db_query delegates straight to DbQueryNodes, which requires an INTEGER
	// handle (db.go); the handle kind is not visible in db_query's own body.
	BuiltinNameDbQuery:        {signature: "db_query(db)", summary: "Returns all DATA-type node IDs (an alias for db_query_nodes with no type filter). There is no query-expression language.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt)}, returns: pairRet("all DATA-type node IDs (an alias for db_query_nodes with no type filter)", ParamArray).ofElem(ParamInt)},
	BuiltinNameDbBfs:          {signature: "db_bfs(db, origin, depth, direction)", summary: "Breadth-first traversal from origin up to depth. direction is \"in\", \"out\", or \"both\". All four arguments are required.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("origin", "Origin node ID.", ParamInt), param("depth", "Maximum traversal depth.", ParamInt), param("direction", "Edge direction: \"in\", \"out\", or \"both\".", ParamString)}, returns: pairRet("the nodes and edges the traversal reached", ParamHash).withFields("edges", "nodes")},
	BuiltinNameDbShortestPath: {signature: "db_shortest_path(db, from, to)", summary: "Computes shortest path between two graph nodes.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt), param("from", "Source node ID.", ParamInt), param("to", "Destination node ID.", ParamInt)}, returns: pairRet("the node IDs along the shortest path, empty when none exists", ParamArray).ofElem(ParamInt)},
	BuiltinNameDbTimeline:     {signature: "db_timeline(db)", summary: "Returns chronological timeline events recorded in the graph. Takes only the handle (no options argument).", params: []builtinParamDoc{param("db", "Database handle.", ParamInt)}, returns: pairRet("chronological timeline events recorded in the graph", ParamArray)},
	BuiltinNameDbStats:        {signature: "db_stats(db)", summary: "Returns graph database statistics: {nodes, edges, has_storage}. Disk-backed handles also report delta_records, csr_records, deleted_nodes, deleted_edges, wal_bytes, commit_seq and last_compact — growing delta_records/wal_bytes means the store is overdue for compaction.", params: []builtinParamDoc{param("db", "Database handle.", ParamInt)}, returns: pairRet("graph database statistics: {nodes, edges, has_storage}", ParamHash)},
	BuiltinNameDbCompact: {signature: "db_compact(db)", summary: "Merges a disk-backed store's pending writes into its image and truncates the write-ahead log, which is what gives the memory back. Everything written since the last compaction stays resident and is replayed at every open, so a store that is never compacted grows in memory and open time with no error to signal it -- db_stats' delta_records and wal_bytes are the figures that say it is due. Compacting an in-memory handle is a no-op and reports has_storage false. Note that compacting with this build rewrites the store in a newer on-disk format that older mutant builds cannot open. Returns (report, err).", params: []builtinParamDoc{param("db", "Database handle.", ParamInt)}, returns: pairRet("what the compaction moved: {has_storage, delta_records_before, delta_records_after}", ParamHash).withFields("delta_records_after", "delta_records_before", "has_storage")},
	// The ledger family. Its own alignment group, which is also why the
	// comment is here: these entries joined the section above otherwise, and
	// gofmt would have rewritten the two db_ rows that have been formatted
	// their own way since long before this family existed.
	BuiltinNameLedgerOpen:    {signature: "ledger_open(path, actor)", summary: "Opens or creates a forensic ledger: a graphene store in a fixed strict posture -- every commit signed, a log containing an unsigned commit refused on replay, the image verified before it loads, the redaction ledger on, and retention keeping every retired WAL segment. There is no options hash, because each of those is a decision about what the resulting document may claim and a script that can turn signing off is a script whose store cannot be relied on to have had it on. actor is the examiner's asserted name: it is recorded, never authenticated, and actor_id is that name hashed into the 64-bit field graphene attributes commits with. Signing uses the local Mutant key pair; key_created_for_this_run is true when this process had to generate it, which means every signature under it is by a key younger than the case. role_grants is always false and stays that way on purpose -- filling graphene's grant ledger would manufacture the look of an authorisation model behind a typed-in name -- so ledger_custody keeps reporting that gap. Writes a mutant.ledger marker into the directory, and db_open_disk refuses any directory carrying one. Returns (info, err).", params: []builtinParamDoc{param("path", "Ledger directory path.", ParamString), param("actor", "The examiner's asserted name. Recorded, never authenticated.", ParamString)}, returns: pairRet("the handle and the posture it was opened under", ParamHash).withFields("actor", "actor_id", "audit_log", "created", "handle", "key_created_for_this_run", "key_id", "path", "public_key", "redaction_ledger", "retained_segments", "role_grants", "signed_commits_required", "verified_on_open")},
	BuiltinNameLedgerClose:   {signature: "ledger_close(ledger)", summary: "Closes a ledger handle and flushes pending state. The handle comes from ledger_open and is not a db_ handle; the two handle spaces are separate so that no db_ builtin can write into a ledger.", params: []builtinParamDoc{param("ledger", "Handle from ledger_open.", ParamInt)}, returns: pairRet("true once the handle has been closed and pending state flushed", ParamBool)},
	BuiltinNameLedgerStats:   {signature: "ledger_stats(ledger)", summary: "Reports what a ledger holds and what it commits to: node and edge counts, the delta/WAL figures that say a compaction is due, the retained segment count, the audit and redaction entry counts, and the snapshot roots. compacted is false on a ledger that has never been compacted, and the four root fields are empty strings rather than an error -- a store whose contents are still entirely in the log has no roots, which is a state rather than a failure, and nothing in it can be proved to anybody until it does. The handle comes from ledger_open and is not a db_ handle; the two handle spaces are separate so that no db_ builtin can write into a ledger. Returns (stats, err).", params: []builtinParamDoc{param("ledger", "Handle from ledger_open.", ParamInt)}, returns: pairRet("what the ledger holds and what it commits to", ParamHash).withFields("actor", "actor_id", "audit_entries", "body_version", "commit_seq", "compacted", "delta_records", "edges", "last_compact", "nodes", "path", "prev_root", "redactions", "retained_segments", "snapshot_root", "tombstone_root", "wal_bytes")},
	BuiltinNameLedgerCompact: {signature: "ledger_compact(ledger)", summary: "Merges the ledger's delta layer into a new signed image and returns the snapshot roots it produced. This is the operation that makes a ledger provable: an entity written but never compacted is live and in no snapshot, so there is nothing for an inclusion proof to resolve against. Under this family's retention the compaction keeps every retired WAL segment, where the engine default would discard the log here along with every commit's actor, timestamp and signature -- retained_segments is how a manifest shows the retention took effect rather than merely being configured. The handle comes from ledger_open and is not a db_ handle; the two handle spaces are separate so that no db_ builtin can write into a ledger. Reads and rewrites the whole store, so it costs O(store size) rather than a seek. Returns (report, err).", params: []builtinParamDoc{param("ledger", "Handle from ledger_open.", ParamInt)}, returns: pairRet("what the compaction moved, and the roots it produced", ParamHash).withFields("audit_entries", "body_version", "compacted", "delta_records_after", "delta_records_before", "prev_root", "redactions", "retained_segments", "snapshot_root", "tombstone_root")},
	BuiltinNameLedgerAddNode: {signature: "ledger_add_node(ledger, props, nodeType?)", summary: "Writes one node into the ledger, attributed to the opening actor and signed as part of its commit. nodeType is an optional integer/enum node type (0-127; 0 is the DATA type used when omitted). Properties are written twice from one map, to the entity's own blob and to the property index, because they are different storage and only the blob is what a later property redaction removes: an entity written with index entries alone -- which is what db_add_artifact and db_index_prop write -- makes ledger_redact_metadata refuse with \"carries no properties to redact\" while the values stay queryable in the index. redactable reports whether this entity can ever be property-redacted, which is decided here at write time and not visible again until somebody tries. Values must be STRING or BYTES: the index matches exact bytes, so a rendering Mutant chose for a number would be searchable only by a caller who guessed the same one. The handle comes from ledger_open and is not a db_ handle; the two handle spaces are separate so that no db_ builtin can write into a ledger. Returns (info, err).", params: []builtinParamDoc{param("ledger", "Handle from ledger_open.", ParamInt), param("props", "Properties, written to both the blob and the index. STRING or BYTES values.", ParamHash), param("nodeType?", "Optional integer/enum node type (0-127).", ParamInt, ParamEnum)}, returns: pairRet("the new node and whether it can ever be property-redacted", ParamHash).withFields("id", "property_bytes", "property_count", "redactable")},
	BuiltinNameLedgerAddEdge: {signature: "ledger_add_edge(ledger, from, to, props, edgeType?)", summary: "Writes one edge between two node IDs into the ledger, attributed to the opening actor and signed as part of its commit. edgeType is an optional integer/enum edge type. Properties are written twice from one map, to the entity's own blob and to the property index, because they are different storage and only the blob is what a later property redaction removes: an entity written with index entries alone -- which is what db_add_artifact and db_index_prop write -- makes ledger_redact_metadata refuse with \"carries no properties to redact\" while the values stay queryable in the index. redactable reports whether this entity can ever be property-redacted, which is decided here at write time and not visible again until somebody tries. Values must be STRING or BYTES: the index matches exact bytes, so a rendering Mutant chose for a number would be searchable only by a caller who guessed the same one. The handle comes from ledger_open and is not a db_ handle; the two handle spaces are separate so that no db_ builtin can write into a ledger. Returns (info, err).", params: []builtinParamDoc{param("ledger", "Handle from ledger_open.", ParamInt), param("from", "Source node ID.", ParamInt), param("to", "Destination node ID.", ParamInt), param("props", "Properties, written to both the blob and the index. STRING or BYTES values.", ParamHash), param("edgeType?", "Optional integer/enum edge type.", ParamInt, ParamEnum)}, returns: pairRet("the new edge and whether it can ever be property-redacted", ParamHash).withFields("id", "property_bytes", "property_count", "redactable")},
	// The proof half of the family, written long-form. A multi-line entry ends
	// gofmt's alignment run, which is what keeps the six single-line entries
	// above at the width they were given when they were the whole family.
	BuiltinNameLedgerProveNode: {
		signature: "ledger_prove_node(ledger, node)", summary: "Builds and exports a Merkle inclusion proof that one node was in the ledger's current compacted snapshot, and returns it as BYTES ready for fs_write. A proof is what lets somebody who does not have the ledger check a claim about one entity: it carries that entity's leaf, the sibling hashes and the component roots, and nothing about any other entity. It deliberately does not carry a root the verifier should trust -- snapshot_root comes back beside it so the examiner can retain or publish that value out of band, because ledger_verify_proof takes the root as an argument and a proof checked against the root inside itself proves nothing. Proofs are bound to a snapshot: one exported now verifies against the root named here forever, does not verify against the root a later compaction produces, and a fresh proof for the same unchanged entity is different bytes -- so exporting proofs without retaining the roots beside them produces files nobody can check. Refuses with three messages where graphene has one: a ledger never compacted, a node that is live but was written after the last compaction, and a node this ledger does not have. The last two are the same error underneath and have opposite fixes. There is no ledger_prove_edge -- graphene can prove an edge removed but not present. Returns (proof, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID to prove.", ParamInt),
		},
		returns: pairRet("the proof bytes and the roots they resolve against", ParamHash).withFields("body_version", "edge_root", "index_root", "kind", "leaf_bytes", "leaf_index", "node_id", "node_root", "prev_root", "proof", "proof_bytes", "siblings", "snapshot_root", "subject", "tombstone_root", "tree_size")},
	BuiltinNameLedgerVerifyProof: {
		signature: "ledger_verify_proof(proof, snapshotRoot)", summary: "Checks an exported proof against a snapshot root the caller supplies. Needs no ledger, no store and no directory: the bytes and the root are enough, which is the property proofs exist for. snapshotRoot is a required 64-character hex argument and there is no form of this call that reads the root out of the proof -- whoever wrote a proof file supplied both the evidence and the roots it claims, so checking one against the other is circular. An empty root is refused, and so is an all-zero one, which is what an empty value looks like once something has padded it and which graphene records as \"this snapshot has no roots\" rather than as a root. A file that is not a readable proof comes back as an error; a readable proof that is not true comes back as a value with verified false and a reason, because a corrupt download and a forgery call for different responses. checked_against and stated_snapshot_root are always both present so a reader can see which root the verdict was reached against. Verifies all three proof kinds: node inclusion, redaction and property redaction. Returns (result, err).",
		params: []builtinParamDoc{
			param("proof", "Proof bytes from ledger_prove_node, or read back from a proof file.", ParamString, ParamBytes),
			param("snapshotRoot", "The snapshot root, as 64 hex characters, obtained independently of the proof.", ParamString),
		},
		returns: pairRet("the verdict, and both roots it was reached between", ParamHash).withFields("checked_against", "edge_id", "kind", "leaf_bytes", "leaf_index", "node_id", "proof_bytes", "reason", "siblings", "stated_body_version", "stated_edge_root", "stated_index_root", "stated_node_root", "stated_prev_root", "stated_snapshot_root", "stated_tombstone_root", "subject", "tree_size", "verified")},
	BuiltinNameLedgerProofDescribe: {
		signature: "ledger_proof_describe(proof)", summary: "Decodes an exported proof and reports what it says about itself, checking none of it. Every root field is prefixed stated_ because this builtin is given no root and verifies nothing: those values are the file's own account of itself, and a proof file can state whatever roots its author chose. There is deliberately no verified field, which would be read as a verdict of false rather than as the absence of one. Decoding is not a weaker form of verifying -- a byte flipped inside a proof's roots region still decodes cleanly and then fails verification -- so a proof this describes is still a proof that may be false. ledger_verify_proof is the one that reaches a verdict, and it takes a root. Returns (claims, err).",
		params: []builtinParamDoc{
			param("proof", "Proof bytes from ledger_prove_node, or read back from a proof file.", ParamString, ParamBytes),
		},
		returns: pairRet("what the proof states about itself, none of it checked", ParamHash).withFields("edge_id", "kind", "leaf_bytes", "leaf_index", "node_id", "proof_bytes", "siblings", "stated_body_version", "stated_edge_root", "stated_index_root", "stated_node_root", "stated_prev_root", "stated_snapshot_root", "stated_tombstone_root", "subject", "tree_size")},
	BuiltinNameLedgerRootExport: {
		signature: "ledger_root_export(ledger)", summary: "Returns the ledger's current snapshot roots: the value an examiner retains or publishes so a proof can later be checked against a root the proof's author did not supply. All six component roots come back together because the snapshot root binds them and ledger_verify_chain needs the set rather than the one number. Unlike ledger_stats, which reports \"never compacted\" as a state with empty root strings, this refuses on a ledger with no snapshot: its job is to produce a value that will be retained, and an empty one retained now is an empty one quoted later in a manifest as though it were a root. Returns (roots, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
		},
		returns: pairRet("the roots worth retaining outside the store", ParamHash).withFields("actor", "actor_id", "body_version", "edge_root", "index_root", "node_root", "path", "prev_root", "snapshot_root", "tombstone_root")},
	BuiltinNameLedgerVerifyChain: {
		signature: "ledger_verify_chain(earlier, later)", summary: "Checks that a later retained snapshot names an earlier one as its predecessor, given two hashes from ledger_root_export. This is what separates a store's history from a collection of internally consistent files: a substituted snapshot can be perfectly coherent on its own, but it cannot claim a predecessor it never had. Both arguments must carry all six component roots and body_version; a missing one is refused rather than read as zero, because a zero component would fail the snapshot root's own binding check and report the chain as broken when what was broken was the argument. A snapshot does not chain to itself. Two well-formed root sets that do not link come back as chained false with a reason, not as an error. Returns (result, err).",
		params: []builtinParamDoc{
			param("earlier", "The earlier snapshot, as returned by ledger_root_export.", ParamHash),
			param("later", "The later snapshot, as returned by ledger_root_export.", ParamHash),
		},
		returns: pairRet("whether the later snapshot names the earlier one", ParamHash).withFields("chained", "earlier_snapshot_root", "later_prev_root", "later_snapshot_root", "reason")},
	BuiltinNameLedgerCustody: {
		signature: "ledger_custody(ledger, node)", summary: "Accounts for one entity across every history the ledger keeps -- the compacted snapshot and the entity's place in it, the attestation over that snapshot, the retired WAL segments, the audit log, the redaction ledger and the grant ledger -- and reports what could not be accounted for. Returns gaps, never a verdict: \"not verified\" is useless to somebody holding evidence, where \"the segment chain is intact but nothing attested the current snapshot\" says what to do next. Each gap carries its layer, whether the chain is broken or was never established, graphene's own detail verbatim, and a remedy in this language -- three of graphene's six details end by naming an option to set, two of which ledger_open already sets and whose real answer is ledger_compact. source says which of the two wrote each line. There is deliberately no complete field: graphene's Complete() is false whenever any gap exists, and this posture records no role grants by decision, so it would read false on every ledger Mutant can open. Unlike ledger_prove_node this does not refuse an id the store never held -- \"nothing was found to account for\" is an account, and comes back as live false. Every check here compares the store to itself, so the external gap is always present; ledger_custody_anchored and ledger_verify_anchor are what close it. One gap is this tool's own rather than graphene's: a redacted entity still sits, as written, in the retired write-ahead segments this ledger keeps so that attribution survives compaction, which a library cannot know and a directory being handed over must not hide. Returns (report, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID to account for.", ParamInt),
		},
		returns: pairRet("what was walked and what could not be accounted for", ParamHash).withFields("anchored", "attest_actor_id", "attestation_verified", "attested", "audit_entries_walked", "broken", "checked_against", "compactions_recorded", "delta_records", "gap_count", "gaps", "grants_walked", "in_snapshot", "live", "node_id", "redacted", "redactions_walked", "removal_provable", "segments_checked", "snapshot_root")},
	BuiltinNameLedgerCustodyAnchored: {
		signature: "ledger_custody_anchored(ledger, node, snapshotRoot)", summary: "ledger_custody with the snapshot additionally checked against a root the caller retained outside this machine. The only form that can tell \"internally consistent\" from \"not tampered with\", because it is the only one comparing the store against something an adversary holding the signing key could not change. snapshotRoot is a required 64-character hex argument, from ledger_root_export at the time it was retained; an empty root and an all-zero one are both refused here rather than passed through, because graphene reports a root mismatch as a broken chain and an examiner who supplied zeroes would be told the image had been tampered with. A separate builtin rather than a nullable third argument on ledger_custody, so that going without a retained root is visible in the source instead of being expressed by a value that happens to be empty. Returns (report, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID to account for.", ParamInt),
			param("snapshotRoot", "The snapshot root as 64 hex characters, retained outside this machine.", ParamString),
		},
		returns: pairRet("what was walked, and how it compared to the retained root", ParamHash).withFields("anchored", "attest_actor_id", "attestation_verified", "attested", "audit_entries_walked", "broken", "checked_against", "compactions_recorded", "delta_records", "gap_count", "gaps", "grants_walked", "in_snapshot", "live", "node_id", "redacted", "redactions_walked", "removal_provable", "segments_checked", "snapshot_root")},
	BuiltinNameLedgerCheckpoint: {
		signature: "ledger_checkpoint(ledger)", summary: "Binds every history's head into one digest and records it in the ledger's local checkpoint chain. The digest is the value to publish; everything else in the result is what it commits to -- the snapshot root, the attestation id, the segment, audit, redaction and grant heads, and a count of each, so a truncation shows up as more than a changed hash. Anchoring the snapshot root alone leaves the others free, and an adversary who rewrites only the audit log changes no snapshot root. witnessed always comes back false and is not computed: this call publishes nothing, and the field is there so a manifest assembled from this hash cannot claim otherwise by omission. Recording is a promise to publish -- a checkpoint whose digest never reaches an external witness is reported by ledger_verify_anchor as a fatal finding. The digest cannot be looked at before it is recorded, because a checkpoint is stamped with the time of capture before it is hashed and two captures of an unchanged ledger produce two different digests. delta_records is the count of records written since the last compaction: a checkpoint binds the snapshot, and an uncompacted write moves none of the six heads, so those records are covered by no checkpoint however many are published. Returns (checkpoint, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
		},
		returns: pairRet("the digest to publish and the heads it binds", ParamHash).withFields("actor", "actor_id", "at", "attestation_id", "audit_count", "audit_head", "delta_records", "digest", "grant_count", "grant_head", "prev", "redaction_count", "redaction_head", "segment_count", "segment_head", "seq", "snapshot_root", "unix", "witnessed")},
	BuiltinNameLedgerCheckpointHistory: {
		signature: "ledger_checkpoint_history(ledger)", summary: "Returns this ledger's local checkpoint chain, oldest first, with each entry's digest, the heads it bound and the counts beside them. chain_intact is a weak check and is not the interesting one: it recomputes each digest from its contents and each link from its predecessor, which catches a clumsy edit and nothing else, because anyone who rewrites the chain forward passes it. That is precisely why the digests are published and why ledger_verify_anchor exists. A ledger that has never checkpointed returns count 0 and chain_intact true, which is the honest reading of an empty chain rather than a fault. Returns (history, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
		},
		returns: pairRet("the local checkpoint chain and a weak check over it", ParamHash).withFields("chain_intact", "checkpoints", "count", "reason")},
	BuiltinNameLedgerVerifyAnchor: {
		signature: "ledger_verify_anchor(ledger, witnessed)", summary: "Checks this ledger's checkpoint chain against what an external witness says it holds -- the one check in this family that is not the store vouching for itself. Mutant ships no anchor transport and graphene ships none either: what makes an anchor an anchor is being beyond the reach of whoever can rewrite the store, and that property comes from where it lives, not from code. So the witness is an argument, exactly as the snapshot root is in ledger_verify_proof. witnessed is an ARRAY of hashes carrying digest (64 hex) and unix (INTEGER seconds, as time_unix returns), with an optional ref -- a timestamp-token serial, a transaction hash, a URL, a page number. The time is required because it is the only part of a witness record this store could not have written itself. The check runs both ways and both are fatal: a local checkpoint the witness never saw means the local chain was rewritten, and a witnessed digest with no local checkpoint means the local record was destroyed, which is otherwise indistinguishable from innocence and strictly easier to perform. An empty witness list is a legitimate argument, not an error -- it says nothing was ever published, and every local checkpoint becomes a finding. current_matches_last is about the six heads a checkpoint binds and not about the ledger's contents: an uncompacted write moves none of them, so a ledger with records in flight is confirmed by the witness while those records are covered by nothing, which is what delta_records and its gap report. Returns (audit, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("witnessed", "What the external witness holds: an array of hashes with digest and unix, and optionally ref.", ParamArray),
		},
		returns: pairRet("how the local chain compared to what was witnessed", ParamHash).withFields("broken", "checkpoints", "current_matches_last", "delta_records", "gap_count", "gaps", "last_anchored_at", "last_anchored_digest", "last_anchored_seq", "last_anchored_snapshot_root", "last_anchored_unix", "matched", "published", "witnessed")},
	BuiltinNameLedgerVerifyStore: {
		signature: "ledger_verify_store(path)", summary: "Recomputes a compacted image's Merkle roots from the records the file actually holds and compares them to the roots the file carries. A different question from the image's own digest: the digest asks whether these bytes are what was written, and this asks whether the roots describe the records in the same file. An adversary who edits a record and recomputes the digest defeats the first and not this -- and if they recompute the roots too, the snapshot root changes, which is what a root retained elsewhere detects. Takes a path rather than a handle, because the party who most needs it is the one holding a copy of a store and no reason to trust the process that wrote it; it runs on an open ledger as well. The path may be the ledger directory or the image file. A directory holding no image is refused as a mistake about which path was passed, not reported as a failed check. Returns (result, err).",
		params: []builtinParamDoc{
			param("path", "Ledger directory, or the compacted image file itself.", ParamString),
		},
		returns: pairRet("whether the roots describe the records in the same file", ParamHash).withFields("path", "reason", "roots_match")},
	BuiltinNameLedgerRedactNode: {
		signature: "ledger_redact_node(ledger, node, reason)", summary: "Destroys an entity and every edge touching it, and records who did it, when, under which key and why. The difference between this and db_delete_node is the record: a deletion after a compaction is indistinguishable from evidence that was never ingested, which makes lawful redaction and evidence destruction the same operation. This keeps the fact, the actor, the reason, the shape of what went and the version hash identifying it, and destroys only the content. Cascades: every incident edge goes too, each with its own version hash in the record, so a removal taken as collateral can still be identified. Call ledger_redaction_impact first -- it reports the cascade before anything is destroyed, and the hashes it returns are the ones the record will carry. The reason is required, is written to the redaction ledger and again to the audit log, and neither is redactable -- so a reason repeating a value this call is about to destroy is refused rather than recorded. Whitespace is not a reason either, which graphene accepts and this does not. provable comes back false and is not computed: a redaction is bound into the image by the next compaction and this call is always before it. retained_segments counts the retired write-ahead segments this ledger keeps: a segment is an immutable record of the commits it carries, so it still holds this entity as originally written, and a redaction rewrites the live graph and the next compacted image but never a segment. Redacting before the first compaction does not avoid it, because the compaction that makes a redaction permanent is the same operation that rotates the live log into a segment. ledger_open keeps every segment so that each commit's actor, timestamp and signature survive compaction, and the same bytes carry both -- attribution and erasure want the same bytes, and this family reports the trade rather than resolving it. Returns (redaction, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID to destroy.", ParamInt),
			param("reason", "Why, in the examiner's own words. Required, and must not name what is being destroyed.", ParamString),
		},
		returns: pairRet("the ledger record of what was destroyed", ParamHash).withFields("actor", "actor_id", "at", "cascade_count", "cascaded_edges", "cascaded_hashes", "edge_id", "hash", "key_id", "node_id", "prev", "prior_properties_hash", "provable", "reason", "retained_segment_bytes", "retained_segments", "scope", "seq", "signed", "surviving_hash", "unix", "version_hash")},
	BuiltinNameLedgerRedactNodeProperties: {
		signature: "ledger_redact_node_properties(ledger, node, reason)", summary: "Destroys an entity's properties and keeps the entity: its ID, its labels and every edge touching it survive, so the graph's shape is intact and the entity remains available as a subject of provenance. This is the lawful-erasure case, and removing a whole node to erase one field destroys evidence that was never in scope. All of an entity's properties or none of them -- there is no per-key form, because the property blob is one value and the index purge is unconditional, so an entity with one sensitive field and four innocuous ones loses all five. Write the sensitive field on an entity of its own if it may have to go separately, which is a decision taken at ingest rather than here. The index entries go with the blob, unconditionally, or the destroyed values would stay queryable. The reason is required, is written to the redaction ledger and again to the audit log, and neither is redactable -- so a reason repeating a value this call is about to destroy is refused rather than recorded. Whitespace is not a reason either, which graphene accepts and this does not. The record keeps the version hash the entity had before and the hash it has after, plus a separated hash of the destroyed blob, which is what makes ledger_prove_property_redaction content-free. provable comes back false: until the next compaction the image still holds the entity as it was and records no removal. retained_segments counts the retired write-ahead segments this ledger keeps: a segment is an immutable record of the commits it carries, so it still holds this entity as originally written, and a redaction rewrites the live graph and the next compacted image but never a segment. Redacting before the first compaction does not avoid it, because the compaction that makes a redaction permanent is the same operation that rotates the live log into a segment. ledger_open keeps every segment so that each commit's actor, timestamp and signature survive compaction, and the same bytes carry both -- attribution and erasure want the same bytes, and this family reports the trade rather than resolving it. Returns (redaction, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID whose properties to destroy.", ParamInt),
			param("reason", "Why, in the examiner's own words. Required, and must not name what is being destroyed.", ParamString),
		},
		returns: pairRet("the ledger record of what was destroyed", ParamHash).withFields("actor", "actor_id", "at", "cascade_count", "cascaded_edges", "cascaded_hashes", "edge_id", "hash", "key_id", "node_id", "prev", "prior_properties_hash", "provable", "reason", "retained_segment_bytes", "retained_segments", "scope", "seq", "signed", "surviving_hash", "unix", "version_hash")},
	BuiltinNameLedgerRedactEdge: {
		signature: "ledger_redact_edge(ledger, edge, reason)", summary: "Destroys one relationship and leaves both endpoints, recording who did it and why. A node redaction takes every incident edge with it, which is usually more than the decision called for; this removes the single relationship that was actually in scope. Edge ids and node ids are different namespaces that look alike, so this refuses a node id no differently from any other number it cannot find -- an edge redaction performed against a node id would remove a relationship nobody named. The reason is required, is written to the redaction ledger and again to the audit log, and neither is redactable -- so a reason repeating a value this call is about to destroy is refused rather than recorded. Whitespace is not a reason either, which graphene accepts and this does not. provable comes back false until the next compaction binds a tombstone for the edge into the snapshot root. retained_segments counts the retired write-ahead segments this ledger keeps: a segment is an immutable record of the commits it carries, so it still holds this entity as originally written, and a redaction rewrites the live graph and the next compacted image but never a segment. Redacting before the first compaction does not avoid it, because the compaction that makes a redaction permanent is the same operation that rotates the live log into a segment. ledger_open keeps every segment so that each commit's actor, timestamp and signature survive compaction, and the same bytes carry both -- attribution and erasure want the same bytes, and this family reports the trade rather than resolving it. Returns (redaction, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("edge", "Edge ID to destroy.", ParamInt),
			param("reason", "Why, in the examiner's own words. Required, and must not name what is being destroyed.", ParamString),
		},
		returns: pairRet("the ledger record of what was destroyed", ParamHash).withFields("actor", "actor_id", "at", "cascade_count", "cascaded_edges", "cascaded_hashes", "edge_id", "hash", "key_id", "node_id", "prev", "prior_properties_hash", "provable", "reason", "retained_segment_bytes", "retained_segments", "scope", "seq", "signed", "surviving_hash", "unix", "version_hash")},
	BuiltinNameLedgerRedactEdgeProperties: {
		signature: "ledger_redact_edge_properties(ledger, edge, reason)", summary: "Destroys a relationship's properties and keeps the relationship -- endpoints, labels and weight survive, so the graph's shape is untouched and only the data the order was about goes. The edge counterpart of ledger_redact_node_properties, and the same all-or-nothing rule applies: the property blob is one value and the index purge is unconditional. The reason is required, is written to the redaction ledger and again to the audit log, and neither is redactable -- so a reason repeating a value this call is about to destroy is refused rather than recorded. Whitespace is not a reason either, which graphene accepts and this does not. The record keeps the edge's version hash before and after plus the separated hash of the destroyed blob. There is no proof builtin for this scope: graphene can prove an edge removed but never prove what an edge still in the image used to carry, so ledger_prove_edge_redaction proves the removal and the property claim rests on the ledger record. provable comes back false until the next compaction. retained_segments counts the retired write-ahead segments this ledger keeps: a segment is an immutable record of the commits it carries, so it still holds this entity as originally written, and a redaction rewrites the live graph and the next compacted image but never a segment. Redacting before the first compaction does not avoid it, because the compaction that makes a redaction permanent is the same operation that rotates the live log into a segment. ledger_open keeps every segment so that each commit's actor, timestamp and signature survive compaction, and the same bytes carry both -- attribution and erasure want the same bytes, and this family reports the trade rather than resolving it. Returns (redaction, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("edge", "Edge ID whose properties to destroy.", ParamInt),
			param("reason", "Why, in the examiner's own words. Required, and must not name what is being destroyed.", ParamString),
		},
		returns: pairRet("the ledger record of what was destroyed", ParamHash).withFields("actor", "actor_id", "at", "cascade_count", "cascaded_edges", "cascaded_hashes", "edge_id", "hash", "key_id", "node_id", "prev", "prior_properties_hash", "provable", "reason", "retained_segment_bytes", "retained_segments", "scope", "seq", "signed", "surviving_hash", "unix", "version_hash")},
	BuiltinNameLedgerRedactionImpact: {
		signature: "ledger_redaction_impact(ledger, node)", summary: "Reports what redacting a node would remove, without removing anything. The point of a preview is to be available while refusing is still possible: a hub node takes an evidentiary subgraph with it, and cascade_count is the number an examiner should see before signing the order rather than after. cascaded_edges and cascaded_hashes are parallel lists in graphene's own order, and the hashes are computed here rather than at deletion time -- so a manifest can record the exact set this preview showed, and a recipient can check that it is the set the redaction record describes. There is no exceeds_policy field: this posture sets no cascade limit, because a limit Mutant invented would refuse a lawful order for a number nobody chose, and a field that is false on every ledger reads as a check that passed. The preview is the limit. Refuses an id the ledger never held, and says so differently for one it held and redacted. Returns (impact, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID to preview.", ParamInt),
		},
		returns: pairRet("what a redaction of this node would remove", ParamHash).withFields("cascade_count", "cascaded_edges", "cascaded_hashes", "node_id", "retained_segment_bytes", "retained_segments", "version_hash")},
	BuiltinNameLedgerRedactions: {
		signature: "ledger_redactions(ledger)", summary: "Returns every redaction this ledger records, oldest first, with the actor, the time, the scope, the reason, the version hash of what was destroyed and the hash chain linking each record to the one before it. The ledger is its own append-only file that compaction never touches, which is why a redaction record outlives the entity it describes. chain_intact recomputes each record's hash from its contents and each link from its predecessor, checking signatures against the keyring this ledger was opened with: it catches an edited or removed record. It does not catch a ledger rewritten forward from the start by whoever holds the signing key -- that is what binding the head into a published checkpoint is for, and an unpublished chain is the store's word about itself. The chain check's explanation is chain_reason rather than reason, because reason is the field beside it and means why a redaction was performed. head is the last record's hash, which is the value to bind or publish. Returns (redactions, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
		},
		returns: pairRet("the redaction ledger and a check over its chain", ParamHash).withFields("chain_intact", "chain_reason", "count", "head", "redactions")},
	BuiltinNameLedgerProveRedaction: {
		signature: "ledger_prove_redaction(ledger, node)", summary: "Builds and exports a Merkle proof that the compacted image records a node as deliberately removed, and returns it as BYTES ready for fs_write. The audience is the one that matters most in an evidentiary exchange: somebody handed a single image and nothing else, to whom a redacted entity is simply absent and indistinguishable from one that never existed. A tombstone is the image's own record that the absence was deliberate, and it is Merkle-rooted into the snapshot root, so a root retained out of band commits to what was taken out of the image as well as what is in it. The proof carries no content, no reason and no actor -- only the scope, the entity, the version hash of what was destroyed, and the ledger sequence and record hash to ask for if the circumstances are needed. Verify it with ledger_verify_proof against a root obtained independently. Refuses with three messages where graphene has one: a ledger never compacted, an entity redacted but not yet compacted, and an entity this ledger never redacted. Returns (proof, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID whose removal to prove.", ParamInt),
		},
		returns: pairRet("the proof bytes and the roots they resolve against", ParamHash).withFields("body_version", "edge_id", "edge_root", "index_root", "kind", "leaf_bytes", "leaf_index", "node_id", "node_root", "prev_root", "proof", "proof_bytes", "redaction_hash", "redaction_seq", "scope", "siblings", "snapshot_root", "subject", "tombstone_root", "tree_size", "version_hash")},
	BuiltinNameLedgerProveEdgeRedaction: {
		signature: "ledger_prove_edge_redaction(ledger, edge)", summary: "Builds and exports a Merkle proof that the compacted image records an edge as deliberately removed. Separate from ledger_prove_redaction because an edge id and a node id are different namespaces: answering \"was 7 redacted?\" without knowing which 7 was meant is how a proof about one thing gets read as a proof about another. Proves an edge removed outright, an edge whose properties were stripped, and an edge cascaded out by a node redaction -- the last is why it exists, because an edge taken as collateral is as absent as one removed deliberately and deserves the same standing. Where an entity has more than one tombstone the most recent is proved, because that is the one describing its present state. Verify with ledger_verify_proof against a root obtained independently. Returns (proof, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("edge", "Edge ID whose removal to prove.", ParamInt),
		},
		returns: pairRet("the proof bytes and the roots they resolve against", ParamHash).withFields("body_version", "edge_id", "edge_root", "index_root", "kind", "leaf_bytes", "leaf_index", "node_id", "node_root", "prev_root", "proof", "proof_bytes", "redaction_hash", "redaction_seq", "scope", "siblings", "snapshot_root", "subject", "tombstone_root", "tree_size", "version_hash")},
	BuiltinNameLedgerProvePropertyRedaction: {
		signature: "ledger_prove_property_redaction(ledger, node)", summary: "Builds and exports a proof that an entity's properties were removed and that nothing else about it changed -- and does it without revealing what was removed. The claim is stronger than \"this entity's version hash changed\" and is checkable by somebody who never sees the content: the entity is in the image with these labels, its properties are now empty, it previously had properties hashing to P, it was otherwise byte-identical, and the removal is recorded under the snapshot root. The prior leaf is reconstructed from the surviving entity's identity plus the destroyed blob's 32-byte digest, so the content appears nowhere in the file. prior_leaf_bytes and surviving_leaf_bytes are equal on a well-formed proof, because the two leaves differ only in their final 32 bytes and that is the entire claim. Refuses an entity removed outright rather than stripped, including one whose properties were stripped and which was later removed -- this proof asserts the entity is still here, which is not true of it. Verify with ledger_verify_proof against a root obtained independently. Returns (proof, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID whose property redaction to prove.", ParamInt),
		},
		returns: pairRet("the content-free proof bytes and the roots they resolve against", ParamHash).withFields("body_version", "edge_root", "index_root", "kind", "leaf_index", "node_id", "node_root", "prev_root", "prior_leaf_bytes", "proof", "proof_bytes", "redaction_hash", "redaction_seq", "removal_leaf_bytes", "siblings", "snapshot_root", "subject", "surviving_leaf_bytes", "tombstone_root", "tree_size", "version_hash")},
	BuiltinNameLedgerNode: {
		signature: "ledger_node(ledger, node)", summary: "Reads one node record back. Until this family had a read side a ledger Mutant opened was write-only: a script could commit attributed evidence and prove it was there, and could not ask what it said. Properties come back as BYTES rather than STRING because that is what the store holds -- ledger_add_node accepts either and commits bytes, so the two are the same blob afterwards and rendering one as text would invent a distinction the ledger does not keep and lose any value that is not valid UTF-8. bytes_to_string is the conversion for a caller who knows what they wrote, and it is that one rather than to_string, which renders BYTES as hex. labels are the offsets that were written, not graphene internal type numbers, so a label read here can be passed straight back to ledger_add_node; a graphene built-in type, which no Mutant builtin can write, comes back negative so it cannot be mistaken for one. An id the ledger does not hold is refused, and the refusal distinguishes an id that was never written from one a redaction removed by reading the redaction ledger first. Returns (node, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID, as returned by ledger_add_node.", ParamInt),
		},
		returns: pairRet("the record as committed", ParamHash).withFields("id", "labels", "properties", "property_bytes", "property_count", "redactable")},
	BuiltinNameLedgerEdge: {
		signature: "ledger_edge(ledger, edge)", summary: "Reads one edge record back, with its endpoints and its weight. weight is graphene's own field and means a similarity score for its SimilarTo type and zero for everything else; it is not a distance, which is why ledger_path takes the reading to make of it as an argument. Properties come back as BYTES for the reason ledger_node gives. An edge a node redaction took as collateral is refused by name, saying which redaction removed it and that it was not the subject of that decision. Returns (edge, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("edge", "Edge ID, as returned by ledger_add_edge.", ParamInt),
		},
		returns: pairRet("the relationship as committed", ParamHash).withFields("dst", "id", "labels", "properties", "property_bytes", "property_count", "redactable", "src", "weight")},
	BuiltinNameLedgerProvenance: {
		signature: "ledger_provenance(ledger, node, maxDepth)", summary: "Walks inbound edges from one entity back towards the evidence it came from, and says why the walk stopped. stopped_at is the field that matters and it is not graphene's: ProvenanceChain documents that a walk which does not reach a root returns the deepest path it found, so a chain cut short by its depth limit comes back the same shape as one that reached the source. This reads the last node's inbound edges afterwards and reports root, depth or cycle; complete is true for exactly one of the three. branch_points is the second thing graphene does not report: a node with two parents has two ancestries and the walk follows one, so every place the chain had a choice is named along with the parents it did not take -- \"this artefact came from that image\" must not be read off a result that had another answer. maxDepth must be positive; graphene substitutes 64 for a non-positive depth, which would be reported here as the limit the caller chose. Every inbound edge type is followed, deliberately: filtering by type adds a fourth reason a walk can stop early and the ids are opaque offsets. The walk runs under this language's fixed traversal budget and a walk that exceeds it is refused rather than truncated. Returns (provenance, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("node", "Node ID to walk back from.", ParamInt),
			param("maxDepth", "Maximum hops to follow; must be positive.", ParamInt),
		},
		returns: pairRet("the chain, why it stopped, and what it did not follow", ParamHash).withFields("branch_point_count", "branch_points", "chain", "complete", "hops", "length", "max_depth", "origin", "root", "stopped_at")},
	BuiltinNameLedgerPath: {
		signature: "ledger_path(ledger, src, dst, costModel)", summary: "Finds the cheapest path between two entities under a named cost model. The model is a name and not a function on purpose. graphene's EdgeCost contract is three obligations -- non-negative, deterministic, cheap -- and a function written in this language satisfies none of them by construction: graphene refuses a negative or NaN cost by edge id, it cannot check determinism, and a probe confirmed that a cost returning a different number each time it is asked about the same edge produces a path with no error that is neither the cheapest nor costed by the number reported beside it. The callback also runs once per incident edge on Dijkstra's inner loop, and builtin/resource.go already records that the VM and the evaluator drive a closure differently, so the same script would cost its evidence differently under the two engines. The three models are hops (every step 1), weight (the edge weight is the distance) and similarity (1 - weight, the reading graphene documents for its SimilarTo type). Two entities that are not connected come back as found false rather than as an error, because \"these are not related\" is a finding and folding it into the error channel would make a script's error branch mean that and \"bad handle\" at once. A src or dst the ledger does not hold is a refusal, and says whether a redaction removed it. Returns (path, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("src", "Node ID to start from.", ParamInt),
			param("dst", "Node ID to reach.", ParamInt),
			param("costModel", "One of: hops, similarity, weight.", ParamString),
		},
		returns: pairRet("the cheapest path under the named model, or found false", ParamHash).withFields("cost", "cost_model", "dst", "edges", "found", "hops", "nodes", "src")},
	BuiltinNameLedgerSubgraph: {
		signature: "ledger_subgraph(ledger, nodeIds)", summary: "Returns the entities named and every relationship among them -- the edges whose two endpoints are both in the set. An id given twice is counted once and reported in duplicates; graphene returns the record once per occurrence, so a list with a repeat in it would otherwise produce a subgraph claiming more entities than were asked about. An id the ledger does not hold refuses the whole call rather than dropping it, because an induced subgraph is the claim that these are all the relationships among these entities, and a missing entity makes that false rather than incomplete -- the refusal names how many were missing and whether a redaction removed the first of them. An empty list is refused too: a subgraph over nothing is a question with no subject, not an empty answer. Returns (subgraph, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("nodeIds", "ARRAY of node IDs to induce the subgraph over.", ParamArray),
		},
		returns: pairRet("the entities and every relationship among them", ParamHash).withFields("duplicates", "edge_count", "edges", "node_count", "nodes", "requested")},
	BuiltinNameLedgerPatterns: {
		signature: "ledger_patterns(ledger, pattern, scope, maxMatches)", summary: "Finds every subgraph matching a shape. pattern is a HASH with nodes (an ARRAY of {\"id\": <position>, \"labels\": [<label>]}) and edges (an ARRAY of {\"src\": <position>, \"dst\": <position>, \"labels\": [<label>]}). scope is an ARRAY of node IDs to search within, or 0 for the whole graph. Every part of the pattern is validated before graphene sees it, and two of those checks are not politeness: an edge naming a pattern node that does not exist panics inside the matcher and takes the process down, and an unlabelled pattern node with no scope is documented inside graphene as unsupported and produces no matches and no error, so a script asking a question graphene cannot answer would be told the answer is none. A node id must equal its position because graphene matches by position and never reads the id, so ids written in another order would match a shape the script did not describe. capped reports that maxMatches was reached, which is a truncation graphene performs and says nothing about. A pattern is 2 to 20 nodes and must have at least one edge. Returns (matches, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("pattern", "HASH with nodes and edges describing the shape to find.", ParamHash),
			param("scope", "ARRAY of node IDs to search within, or 0 for the whole graph.", ParamArray, ParamInt),
			param("maxMatches", "Cap on matches returned; 0 for no cap.", ParamInt),
		},
		returns: pairRet("every subgraph matching the shape, and whether the set was capped", ParamHash).withFields("capped", "count", "matches", "max_matches", "pattern_size", "scope_size", "scoped")},
	BuiltinNameLedgerQueryNodes: {
		signature: "ledger_query_nodes(ledger, query)", summary: "Answers a node query and says which comparison rule answered it. query is a HASH taking types, ids, filters, mode (all or any), order (asc or desc by id), offset and limit; a filter is {\"key\", \"op\", \"value\"} with op one of eq, prefix, contains, gt, gte, lt, lte, between, and between also needs value_upper. comparison is the field this builtin exists for. A key that has not been declared ordered compares range predicates numerically when both sides parse as numbers and byte-wise otherwise; a declared key compares byte-wise throughout. Those are different questions, and over the values 9, 10, 1x, 100, 2 a between of \"2\" and \"100\" returns four records undeclared and none at all declared. So comparison reports which rule ran -- none, numeric-then-bytes, bytes, or mixed when the query's range filters straddle both -- and range_keys names the keys it applies to. limited says a limit was reached, which means there may be more. Returns (result, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("query", "HASH of types, ids, filters, mode, order, offset and limit.", ParamHash),
		},
		returns: pairRet("the matching ids and the rule that compared them", ParamHash).withFields("comparison", "count", "ids", "limit", "limited", "offset", "range_filters", "range_keys")},
	BuiltinNameLedgerExplainQuery: {
		signature: "ledger_explain_query(ledger, query)", summary: "Reports how the planner resolved a query: which index drove it, how many candidates that produced, and how each remaining filter was applied. Takes the same query HASH as ledger_query_nodes. This is diagnostic output and graphene says so plainly -- which index the planner picks may change as its cost model improves, and the results a query returns may not -- so a script must not make an evidentiary decision from a plan. scanned is the reading worth acting on: the driver fell back to examining every entity, which happens when no filter can be served (contains can never be served by any index), when a range names a key that was not declared ordered, and whenever two or more filters are combined with mode any. candidates is what the driving step produced and not the size of the driving set, because a limit can be pushed into the driver, and residual cost is a forecast rather than a measurement; graphene documents both and neither is softened here. Returns (plan, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("query", "The same query HASH ledger_query_nodes takes.", ParamHash),
		},
		returns: pairRet("how the planner resolved the query, as diagnostics", ParamHash).withFields("candidates", "driver", "driver_filters", "driver_key", "plan", "residual_count", "residuals", "results", "scanned")},
	BuiltinNameLedgerDeclareOrdered: {
		signature: "ledger_declare_ordered(ledger, key, target)", summary: "Declares a property key ordered, so range filters and prefix on it are answered by binary search instead of a scan -- and reports what that does to the answers. order_differs is why this returns anything at all. Declaring a key changes how its range predicates compare, from numeric-when-both-sides-parse to byte order, and the two disagree: over 9, 10, 1x, 100, 2 a between of \"2\" and \"100\" goes from four records to none. So the key's existing values are read before the declaration is made and checked for a pair the two rules order differently, which is exact rather than sampled -- the rules can only disagree about two values that both parse as numbers, so sorting those numerically and looking for a byte-order inversion between neighbours finds such a pair if one exists. example carries it. Encode values so byte order matches intent (zero-padded fixed width, or a fixed-width integer encoding) and order_differs comes back false. target is \"node\" or \"edge\": the two index spaces are separate and a key declared on one is not declared on the other. Entries written before the declaration are absorbed, so the change reaches queries already written. Returns (declaration, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("key", "Property key to declare ordered.", ParamString),
			param("target", "\"node\" or \"edge\".", ParamString),
		},
		returns: pairRet("the declaration, and whether it reorders what is already stored", ParamHash).withFields("comparison", "declared", "distinct_values", "example", "key", "order_differs", "target", "was")},
	BuiltinNameLedgerDeclareUnique: {
		signature: "ledger_declare_unique(ledger, key, target)", summary: "Enforces that at most one live entity holds any given value under key, which is what turns an indexed value into a name. Unlike the ordered and composite declarations this is checked against what is already written, so it is a statement about the evidence rather than about the schema: a ledger where two nodes already share a value is refused, and graphene's message names the value and every id holding it. After it is declared, writing a duplicate is refused by ledger_add_node rather than by this call. target is \"node\" or \"edge\". Returns (declaration, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("key", "Property key that must hold at most one entity per value.", ParamString),
			param("target", "\"node\" or \"edge\".", ParamString),
		},
		returns: pairRet("the declaration and the check it passed", ParamHash).withFields("checked", "declared", "key", "target")},
	BuiltinNameLedgerDeclareUniqueEdge: {
		signature: "ledger_declare_unique_edge(ledger, edgeType)", summary: "Enforces that at most one live edge of the given type joins any ordered pair of entities -- the structural counterpart to ledger_declare_unique, which constrains a value rather than a relationship. Like the property form it validates the graph as it stands, so a ledger that already holds two such edges is refused. Enforcement afterwards happens at commit: the second edge is refused by ledger_add_edge, naming the edge that already exists. edgeType is the same 0..127 offset ledger_add_edge takes. Returns (declaration, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("edgeType", "Edge type offset in 0..127, or an enum value.", ParamInt, ParamEnum),
		},
		returns: pairRet("the declaration and where it is enforced", ParamHash).withFields("checked", "declared", "edge_type", "enforced")},
	BuiltinNameLedgerDeclareComposite: {
		signature: "ledger_declare_composite(ledger, keys, target)", summary: "Declares one key tuple, so a conjunction of equality filters over exactly those keys is answered from one posting list rather than by intersecting several. It serves that query and no other: a query naming fewer of the keys, or naming them with any comparison other than equality, is driven some other way, and ledger_explain_query is how to tell which. Unlike a unique declaration this checks nothing about the data and cannot fail on it, and unlike an ordered declaration it changes no comparison rule -- equality is byte equality either way. target is \"node\" or \"edge\". Returns (declaration, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
			param("keys", "ARRAY of STRING property keys forming the tuple.", ParamArray),
			param("target", "\"node\" or \"edge\".", ParamString),
		},
		returns: pairRet("the declaration and what it serves", ParamHash).withFields("declared", "keys", "serves", "target")},
	BuiltinNameLedgerIndexes: {
		signature: "ledger_indexes(ledger)", summary: "Reports every index declaration in force, on both the node and the edge side: the ordered keys, the unique keys, the composite key tuples, and the edge types under a cardinality constraint. Worth reading before a query and not only after one, because ordered_node_keys is what decides whether a range filter compares numerically or byte-wise -- see ledger_declare_ordered for what that costs. Declarations are recorded in the store and survive both a compaction and a reopen, so a ledger handed over carries the schema decisions that shaped whatever was reported from it. Returns (indexes, err).",
		params: []builtinParamDoc{
			param("ledger", "Handle from ledger_open.", ParamInt),
		},
		returns: pairRet("every declaration in force on both sides", ParamHash).withFields("composite_edge_keys", "composite_node_keys", "count", "ordered_edge_keys", "ordered_node_keys", "unique_edge_keys", "unique_edge_types", "unique_node_keys")},
	// A "bytes value" is a BYTES or a STRING: requireBytesStringArg
	// (builtin/bytes.go) accepts both, and the family is shape-preserving --
	// bytes_slice of a BYTES is a BYTES, of a STRING a STRING. Both kinds are
	// declared on every buffer position because refusing STRING would flag every
	// program written before the BYTES type existed.
	//
	// Offsets and widths go through requireNonNegativeOffset /
	// requireIntegerWithinRange, both of which require INTEGER. A cursor is a
	// HASH with `data` and `offset` fields (requireBytesCursor).
	// The two conversions are the seam between text and binary, and they are
	// explicit on purpose: an implicit coercion would put the corruption back
	// exactly where it was. "raw" is byte-for-byte and is the lossless bridge
	// from every producer that predates the BYTES type.
	BuiltinNameStringToBytes: {
		signature: "string_to_bytes(s, encoding)", summary: "Converts text to a BYTES buffer under a named encoding: \"raw\", \"utf8\" (validated), \"latin1\", \"hex\" or \"base64\". Returns (bytes, err).",
		params: []builtinParamDoc{
			param("s", "Text to convert.", ParamString),
			param("encoding", "One of \"raw\", \"utf8\", \"latin1\", \"hex\", \"base64\".", ParamString),
		},
		returns: pairRet("the decoded buffer", ParamBytes)},
	BuiltinNameBytesToString: {
		signature: "bytes_to_string(b, encoding)", summary: "Converts a buffer to text under a named encoding: \"raw\", \"utf8\" (validated), \"latin1\", \"hex\" or \"base64\". Returns (string, err).",
		params: []builtinParamDoc{
			param("b", "Buffer to convert.", ParamString, ParamBytes),
			param("encoding", "One of \"raw\", \"utf8\", \"latin1\", \"hex\", \"base64\".", ParamString),
		},
		returns: pairRet("the encoded text", ParamString)},
	BuiltinNameBytesLen: {
		signature: "bytes_len(data)", summary: "Returns length of a bytes value.",
		params:  []builtinParamDoc{param("data", "Buffer to measure.", ParamString, ParamBytes)},
		returns: pairRet("length of a bytes value", ParamInt)},
	BuiltinNameBytesGet: {
		signature: "bytes_get(data, index)", summary: "Reads one byte at index as integer.",
		params: []builtinParamDoc{
			param("data", "Source buffer.", ParamString, ParamBytes),
			param("index", "Zero-based byte offset.", ParamInt),
		},
		returns: pairRet("the byte at index, as an integer from 0 to 255", ParamInt)},
	BuiltinNameBytesSlice: {
		signature: "bytes_slice(data, start, length)", summary: "Returns a byte sub-slice of the given length starting at start (i.e. data[start:start+length]).",
		params: []builtinParamDoc{
			param("data", "Source buffer.", ParamString, ParamBytes),
			param("start", "Start offset.", ParamInt),
			param("length", "Number of bytes to take.", ParamInt),
		},
		returns: pairRet("a byte sub-slice of the given length starting at start (i", ParamString, ParamBytes)},
	BuiltinNameBytesHex: {
		signature: "bytes_hex(value, width)", summary: "Formats an integer as a zero-padded uppercase hex string with a 0x prefix (e.g. bytes_hex(4660, 8) -> \"0x00001234\"). This formats a number; it does not hex-encode a byte string.",
		params: []builtinParamDoc{
			param("value", "Integer value to format.", ParamInt),
			param("width", "Minimum hex digit width (zero-padded), 1 to 16.", ParamInt),
		},
		returns: pairRet("the zero-padded uppercase hex text, with a 0x prefix", ParamString)},
	// The third parameter is required, not optional: bytes.go reads args[2]
	// after checking `len(args) != 3`. The signature documented only two, so
	// every correct call would have been flagged by the arity lint.
	BuiltinNameBytesCstrAt: {
		signature: "bytes_cstr_at(data, offset, maxLength)", summary: "Reads null-terminated string from bytes at offset.",
		params: []builtinParamDoc{
			param("data", "Source buffer.", ParamString, ParamBytes),
			param("offset", "Offset the string starts at.", ParamInt),
			param("maxLength", "Maximum number of bytes to scan for the terminator.", ParamInt),
		},
		returns: pairRet("the string up to the terminating null byte", ParamString)},
	BuiltinNameBytesCharFromInt: {
		signature: "bytes_char_from_int(value)", summary: "Converts an integer byte value to a single-character string.",
		params:  []builtinParamDoc{param("value", "Byte value between 0 and 255.", ParamInt)},
		returns: pairRet("a one-character string holding that byte", ParamString)},
	BuiltinNameBytesIntFromChar: {
		signature: "bytes_int_from_char(char)", summary: "Converts a single-character string to its integer byte value.",
		params:  []builtinParamDoc{param("char", "Non-empty string; its first byte is used.", ParamString)},
		returns: pairRet("the character's byte value, from 0 to 255", ParamInt)},
	BuiltinNameBytesReadU16Le: {
		signature: "bytes_read_u16_le(data, offset)", summary: "Reads unsigned 16-bit little-endian integer from bytes at offset.",
		params:  bytesReadParams(),
		returns: pairRet("the little-endian unsigned 16-bit integer at offset", ParamInt)},
	BuiltinNameBytesReadU16Be: {
		signature: "bytes_read_u16_be(data, offset)", summary: "Reads unsigned 16-bit big-endian integer from bytes at offset.",
		params:  bytesReadParams(),
		returns: pairRet("the big-endian unsigned 16-bit integer at offset", ParamInt)},
	BuiltinNameBytesReadU32Le: {
		signature: "bytes_read_u32_le(data, offset)", summary: "Reads unsigned 32-bit little-endian integer from bytes at offset.",
		params:  bytesReadParams(),
		returns: pairRet("the little-endian unsigned 32-bit integer at offset", ParamInt)},
	BuiltinNameBytesReadU32Be: {
		signature: "bytes_read_u32_be(data, offset)", summary: "Reads unsigned 32-bit big-endian integer from bytes at offset.",
		params:  bytesReadParams(),
		returns: pairRet("the big-endian unsigned 32-bit integer at offset", ParamInt)},
	BuiltinNameBytesReadU64Le: {
		signature: "bytes_read_u64_le(data, offset)", summary: "Reads unsigned 64-bit little-endian integer from bytes at offset.",
		params:  bytesReadParams(),
		returns: pairRet("the little-endian unsigned 64-bit integer at offset", ParamInt)},
	BuiltinNameBytesReadU64Be: {
		signature: "bytes_read_u64_be(data, offset)", summary: "Reads unsigned 64-bit big-endian integer from bytes at offset.",
		params:  bytesReadParams(),
		returns: pairRet("the big-endian unsigned 64-bit integer at offset", ParamInt)},
	BuiltinNameBytesWriteU16Le: {
		signature: "bytes_write_u16_le(data, offset, value)", summary: "Writes unsigned 16-bit little-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the little-endian unsigned 16-bit integer written at offset", ParamString, ParamBytes)},
	BuiltinNameBytesWriteU16Be: {
		signature: "bytes_write_u16_be(data, offset, value)", summary: "Writes unsigned 16-bit big-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the big-endian unsigned 16-bit integer written at offset", ParamString, ParamBytes)},
	BuiltinNameBytesWriteU32Le: {
		signature: "bytes_write_u32_le(data, offset, value)", summary: "Writes unsigned 32-bit little-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the little-endian unsigned 32-bit integer written at offset", ParamString, ParamBytes)},
	BuiltinNameBytesWriteU32Be: {
		signature: "bytes_write_u32_be(data, offset, value)", summary: "Writes unsigned 32-bit big-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the big-endian unsigned 32-bit integer written at offset", ParamString, ParamBytes)},
	BuiltinNameBytesWriteU64Le: {
		signature: "bytes_write_u64_le(data, offset, value)", summary: "Writes unsigned 64-bit little-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the little-endian unsigned 64-bit integer written at offset", ParamString, ParamBytes)},
	BuiltinNameBytesWriteU64Be: {
		signature: "bytes_write_u64_be(data, offset, value)", summary: "Writes unsigned 64-bit big-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the big-endian unsigned 64-bit integer written at offset", ParamString, ParamBytes)},
	BuiltinNameBytesCursorNew: {
		signature: "bytes_cursor_new(data)", summary: "Creates a cursor for structured byte parsing.",
		params:  []builtinParamDoc{param("data", "Buffer to read through; the cursor keeps its representation.", ParamString, ParamBytes)},
		returns: pairRet("a cursor positioned at the start of data", ParamHash).withFields("data", "offset")},
	BuiltinNameBytesCursorTell: {
		signature: "bytes_cursor_tell(cursor)", summary: "Returns current cursor position.",
		params:  []builtinParamDoc{cursorParam()},
		returns: pairRet("current cursor position", ParamInt)},
	BuiltinNameBytesCursorSeek: {
		signature: "bytes_cursor_seek(cursor, offset)", summary: "Moves cursor to an absolute offset.",
		params: []builtinParamDoc{
			cursorParam(),
			param("offset", "Absolute offset to move to.", ParamInt),
		},
		returns: pairRet("the cursor, repositioned", ParamHash).withFields("data", "offset")},
	BuiltinNameBytesCursorEof: {
		signature: "bytes_cursor_eof(cursor)", summary: "Returns whether cursor is at end-of-buffer.",
		params:  []builtinParamDoc{cursorParam()},
		returns: pairRet("whether cursor is at end-of-buffer", ParamBool)},
	BuiltinNameBytesCursorReadU8: {
		signature: "bytes_cursor_read_u8(cursor)", summary: "Reads one unsigned byte from cursor.",
		params:  []builtinParamDoc{cursorParam()},
		returns: pairRet("the unsigned byte read, and the cursor advanced past it", ParamHash)},
	BuiltinNameBytesCursorReadU16Le: {
		signature: "bytes_cursor_read_u16_le(cursor)",
		summary:   "Reads unsigned 16-bit little-endian integer from cursor.",
		params:    []builtinParamDoc{cursorParam()},
		returns:   pairRet("the little-endian unsigned 16-bit integer read, and the cursor advanced past it", ParamHash)},
	BuiltinNameBytesCursorReadU16Be: {
		signature: "bytes_cursor_read_u16_be(cursor)",
		summary:   "Reads unsigned 16-bit big-endian integer from cursor.",
		params:    []builtinParamDoc{cursorParam()},
		returns:   pairRet("the big-endian unsigned 16-bit integer read, and the cursor advanced past it", ParamHash)},
	BuiltinNameBytesCursorReadU32Le: {
		signature: "bytes_cursor_read_u32_le(cursor)",
		summary:   "Reads unsigned 32-bit little-endian integer from cursor.",
		params:    []builtinParamDoc{cursorParam()},
		returns:   pairRet("the little-endian unsigned 32-bit integer read, and the cursor advanced past it", ParamHash)},
	BuiltinNameBytesCursorReadU32Be: {
		signature: "bytes_cursor_read_u32_be(cursor)",
		summary:   "Reads unsigned 32-bit big-endian integer from cursor.",
		params:    []builtinParamDoc{cursorParam()},
		returns:   pairRet("the big-endian unsigned 32-bit integer read, and the cursor advanced past it", ParamHash)},
	BuiltinNameBytesCursorReadU64Le: {
		signature: "bytes_cursor_read_u64_le(cursor)",
		summary:   "Reads unsigned 64-bit little-endian integer from cursor.",
		params:    []builtinParamDoc{cursorParam()},
		returns:   pairRet("the little-endian unsigned 64-bit integer read, and the cursor advanced past it", ParamHash)},
	BuiltinNameBytesCursorReadU64Be: {
		signature: "bytes_cursor_read_u64_be(cursor)",
		summary:   "Reads unsigned 64-bit big-endian integer from cursor.",
		params:    []builtinParamDoc{cursorParam()},
		returns:   pairRet("the big-endian unsigned 64-bit integer read, and the cursor advanced past it", ParamHash)},
	BuiltinNameSecurityDiagnostics: {signature: "security_diagnostics()", summary: "Returns security diagnostics for the current runtime.", returns: pairRet("security diagnostics for the current runtime", ParamHash)},
	BuiltinNameSandboxStatus:       {signature: "sandbox_status()", summary: "Returns sandbox-detection status information.", returns: pairRet("sandbox-detection status information", ParamHash).withFields("confidence", "detail", "detected", "name")},
	BuiltinNameDebugStatus:         {signature: "debug_status()", summary: "Returns runtime/debugger status information.", returns: pairRet("runtime/debugger status information", ParamHash).withFields("confidence", "detail", "detected", "name")},
	// secure networking (dev-sec)
	BuiltinNameNetConnect: {
		signature: "net_connect(address, timeoutMs)",
		summary:   "Opens a persistent TCP connection and returns a connection handle.",
		params:    []builtinParamDoc{param("address", "host:port endpoint.", ParamString), param("timeoutMs", "Dial timeout in milliseconds.", ParamInt)},
		returns:   pairRet("a connection handle; close it with net_conn_close", ParamInt)},
	BuiltinNameNetTlsConnect: {
		signature: "net_tls_connect(address, timeoutMs, options?)",
		summary:   "Opens a TLS (secure) client connection and returns a connection handle.",
		params: []builtinParamDoc{
			param("address", "host:port endpoint.", ParamString),
			param("timeoutMs", "Dial timeout in milliseconds.", ParamInt),
			param("options?", "Hash or struct: server_name, insecure, alpn, min_version, ca_cert, client_cert, client_key.", ParamHash, ParamStruct),
		},
		returns: pairRet("a connection handle; close it with net_conn_close", ParamInt)},
	BuiltinNameNetConnWrite: {
		signature: "net_conn_write(handle, data, timeout_ms?)",
		summary:   "Writes bytes to a connection and returns the number written. A write deadline (default 30s, or timeout_ms; <=0 blocks forever) prevents a stalled peer from hanging the write.",
		params:    []builtinParamDoc{param("handle", "Connection handle.", ParamInt), param("data", "Bytes to send (STRING).", ParamString), param("timeout_ms?", "Optional write timeout in ms (default 30000; <=0 = block indefinitely).", ParamInt)},
		returns:   pairRet("the number of bytes written", ParamInt)},
	BuiltinNameNetConnRead: {
		signature: "net_conn_read(handle, maxBytes, timeoutMs)",
		summary:   "Reads up to maxBytes from a connection; returns {data, bytes, eof, error} with I/O failures in the error field.",
		params:    []builtinParamDoc{param("handle", "Connection handle.", ParamInt), param("maxBytes", "Maximum bytes to read (1..32 MiB).", ParamInt), param("timeoutMs", "Read timeout in ms (0 = block).", ParamInt)},
		returns:   pairRet("the bytes read, with eof and error reported as fields rather than as an error", ParamHash).withFields("bytes", "data", "eof", "error")},
	BuiltinNameNetConnReadBytes: {
		signature: "net_conn_read_bytes(handle, maxBytes, timeoutMs)",
		summary:   "Reads up to maxBytes from a connection with `data` as a BYTES buffer; otherwise identical to net_conn_read.",
		params:    []builtinParamDoc{param("handle", "Connection handle.", ParamInt), param("maxBytes", "Maximum bytes to read (1..32 MiB).", ParamInt), param("timeoutMs", "Read timeout in ms (0 = block).", ParamInt)},
		returns:   pairRet("the bytes read, with eof and error reported as fields rather than as an error", ParamHash).withFields("bytes", "data", "eof", "error")},
	BuiltinNameNetConnClose: {signature: "net_conn_close(handle)", summary: "Closes a connection and releases its handle.", returns: pairRet("true once the connection has been released", ParamBool), params: []builtinParamDoc{param("handle", "Connection handle to close.", ParamInt)}},
	BuiltinNameNetConnInfo:  {signature: "net_conn_info(handle)", summary: "Returns addressing and negotiated TLS session details for a connection.", returns: pairRet("the connection's local and remote addresses", ParamHash), params: []builtinParamDoc{param("handle", "Connection handle to describe.", ParamInt)}},
	BuiltinNameNetListen:    {signature: "net_listen(address)", summary: "Opens a plain TCP listener and returns a listener handle.", returns: pairRet("a listener handle; close it with net_listen_close", ParamInt), params: []builtinParamDoc{param("address", "Address to bind, e.g. \"127.0.0.1:8080\".", ParamString)}},
	BuiltinNameNetTlsListen: {
		signature: "net_tls_listen(address, certPem, keyPem, options?)",
		summary:   "Opens a TLS-terminating listener from a PEM cert/key pair.",
		params: []builtinParamDoc{
			param("address", "host:port to bind.", ParamString),
			param("certPem", "Server certificate chain (PEM).", ParamString),
			param("keyPem", "Server private key (PEM).", ParamString),
			param("options?", "Hash or struct: alpn, min_version, client_ca (mutual TLS).", ParamHash, ParamStruct),
		},
		returns: pairRet("a listener handle; close it with net_listen_close", ParamInt)},
	BuiltinNameNetAccept:      {signature: "net_accept(listener, timeoutMs)", summary: "Accepts one connection; returns {ok, handle, remote_addr, timeout, error}.", returns: pairRet("the accepted connection's handle and peer address", ParamHash), params: []builtinParamDoc{param("listener", "Listener handle from net_listen or net_tls_listen.", ParamInt), param("timeoutMs", "How long to wait for a connection, in milliseconds.", ParamInt)}},
	BuiltinNameNetListenClose: {signature: "net_listen_close(handle)", summary: "Closes a listener and releases its handle.", returns: pairRet("true once the listener has been released", ParamBool), params: []builtinParamDoc{param("handle", "Listener handle to close.", ParamInt)}},
	BuiltinNameNetServe:       {signature: "net_serve(listener, handler_path, arg?)", summary: "Accept loop that dispatches each connection to a fresh VM running handler_path; handler reads its connection via serve_conn() and shared arg via serve_arg(). Concurrent.", returns: pairRet("null; the call blocks serving connections and only returns on error", ParamNull), params: []builtinParamDoc{param("listener", "Listener handle from net_listen or net_tls_listen.", ParamInt), param("handler_path", "Path to the Mutant program run for each connection.", ParamString), param("arg?", "Value handed to every handler through serve_arg; any type is accepted.", ParamAny)}},
	BuiltinNameNetSpawn:       {signature: "net_spawn(handler_path, arg?)", summary: "Runs handler_path on a new goroutine with no connection (serve_conn()->0) and arg via serve_arg(). For auxiliary workers, e.g. a WebSocket reverse pump.", returns: pairRet("true once the handler goroutine has been started", ParamBool), params: []builtinParamDoc{param("handler_path", "Path to the Mutant program to run.", ParamString), param("arg?", "Value handed to the handler through serve_arg; any type is accepted.", ParamAny)}},
	BuiltinNameServeConn:      {signature: "serve_conn()", summary: "Inside a net_serve handler, returns the connection handle (INTEGER); null otherwise.", returns: pairRet("the handler's connection handle, or null outside a net_serve handler", ParamInt, ParamNull)},
	BuiltinNameServeArg:       {signature: "serve_arg()", summary: "Inside a net_serve handler, returns the shared arg passed to net_serve; null otherwise.", returns: pairRet("the shared arg passed to net_serve, of whatever type it was given, or null outside a handler", ParamAny)},
	BuiltinNameSleepMs:        {signature: "sleep_ms(ms)", summary: "Blocks the current handler for ms milliseconds.", returns: pairRet("true once the delay has elapsed", ParamBool), params: []builtinParamDoc{param("ms", "How long to block, in milliseconds.", ParamInt)}},
	BuiltinNameTimeMs:         {signature: "time_ms()", summary: "Returns the current Unix time in milliseconds.", returns: pairRet("the current Unix time in milliseconds", ParamInt)},
	BuiltinNameWsAcceptKey:    {signature: "ws_accept_key(client_key)", summary: "Computes the Sec-WebSocket-Accept value for an RFC 6455 101 handshake response.", returns: pairRet("the Sec-WebSocket-Accept value for the handshake response", ParamString), params: []builtinParamDoc{param("client_key", "The client's Sec-WebSocket-Key header value.", ParamString)}},
	BuiltinNameWsReadFrame:    {signature: "ws_read_frame(handle, timeoutMs)", summary: "Reads one WebSocket frame (unmasked); returns {fin, opcode, payload, masked, length, is_control}.", returns: pairRet("the frame's payload and its header flags", ParamHash).withFields("fin", "is_control", "length", "masked", "opcode", "payload"), params: []builtinParamDoc{param("handle", "Connection handle to read from.", ParamInt), param("timeoutMs", "Read deadline in milliseconds.", ParamInt)}},
	BuiltinNameWsWriteFrame:   {signature: "ws_write_frame(handle, opcode, payload, mask, timeout_ms?)", summary: "Writes one WebSocket frame; mask=true for client->server, false for server->client. A write deadline (default 30s, or timeout_ms; <=0 blocks forever) prevents a stalled peer from hanging the write.", returns: pairRet("the number of bytes written", ParamInt), params: []builtinParamDoc{param("handle", "Connection handle to write to.", ParamInt), param("opcode", "RFC 6455 opcode: 1 text, 2 binary, 8 close, 9 ping, 10 pong.", ParamInt), param("payload", "Frame payload bytes.", ParamString), param("mask", "True for a client-to-server frame, false for server-to-client.", ParamBool), param("timeout_ms?", "Write deadline in milliseconds; defaults to 30s.", ParamInt)}},
	BuiltinNameNetTlsUpgradeServer: {
		signature: "net_tls_upgrade_server(handle, certPem, keyPem, options?)",
		summary:   "Upgrades an accepted connection to server-side TLS (completes a CONNECT intercept).",
		params: []builtinParamDoc{
			param("handle", "Connection handle to upgrade.", ParamInt),
			param("certPem", "Leaf certificate (PEM), e.g. issued by tls_sign_cert.", ParamString),
			param("keyPem", "Leaf private key (PEM).", ParamString),
			param("options?", "Hash or struct: alpn, min_version, handshake_timeout_ms, client_ca.", ParamHash, ParamStruct),
		},
		returns: pairRet("the negotiated TLS parameters", ParamHash)},
	BuiltinNameNetTlsUpgradeClient: {
		signature: "net_tls_upgrade_client(handle, options?)",
		summary:   "Upgrades an open connection to client-side TLS (STARTTLS / upstream leg).",
		params: []builtinParamDoc{
			param("handle", "Connection handle to upgrade.", ParamInt),
			param("options?", "Hash or struct: server_name, insecure, alpn, min_version, ca_cert, client_cert, client_key, handshake_timeout_ms.", ParamHash, ParamStruct),
		},
		returns: pairRet("the negotiated TLS parameters", ParamHash)},
	BuiltinNameTlsGenerateCa: {
		signature: "tls_generate_ca(options?)",
		summary:   "Creates a self-signed CA certificate and key; returns {cert_pem, key_pem, serial}.",
		params:    []builtinParamDoc{param("options?", "Hash or struct: common_name, organization, days.", ParamHash, ParamStruct)},
		returns:   pairRet("the CA certificate and its private key, both PEM-encoded", ParamHash).withFields("cert_pem", "key_pem", "serial")},
	BuiltinNameTlsGenerateCert: {
		signature: "tls_generate_cert(options?)",
		summary:   "Creates a self-signed leaf/server certificate and key.",
		params:    []builtinParamDoc{param("options?", "Hash or struct: common_name, organization, dns_names, ip_addresses, days.", ParamHash, ParamStruct)},
		returns:   pairRet("the certificate and its private key, both PEM-encoded", ParamHash).withFields("cert_pem", "key_pem", "serial")},
	BuiltinNameTlsSignCert: {
		signature: "tls_sign_cert(caCertPem, caKeyPem, options?)",
		summary:   "Issues a leaf certificate signed by a CA (per-host interception cert).",
		params: []builtinParamDoc{
			param("caCertPem", "CA certificate (PEM).", ParamString),
			param("caKeyPem", "CA private key (PEM).", ParamString),
			param("options?", "Hash or struct: common_name, dns_names, ip_addresses, days.", ParamHash, ParamStruct),
		},
		returns: pairRet("the signed leaf certificate and its private key, both PEM-encoded", ParamHash).withFields("cert_pem", "key_pem", "serial")},
	BuiltinNameHttpParseRequest:         {signature: "http_parse_request(raw)", summary: "Parses a raw HTTP request into {method, url, path, host, proto, query, headers, body}.", returns: pairRet("the request's method, target, headers, and body", ParamHash), params: []builtinParamDoc{param("raw", "Raw HTTP request bytes.", ParamString)}},
	BuiltinNameHttpParseResponse:        {signature: "http_parse_response(raw)", summary: "Parses a raw HTTP response into {status, status_text, proto, headers, body}.", returns: pairRet("the response's status, headers, and body", ParamHash), params: []builtinParamDoc{param("raw", "Raw HTTP response bytes.", ParamString)}},
	BuiltinNameHttpBuildRequest:         {signature: "http_build_request(request)", summary: "Serialises a request hash into HTTP wire bytes.", returns: pairRet("the request serialised to HTTP wire bytes", ParamString), params: []builtinParamDoc{param("request", "Request as a hash or struct, with the fields http_parse_request produces.", ParamHash, ParamStruct)}},
	BuiltinNameHttpBuildResponse:        {signature: "http_build_response(response)", summary: "Serialises a response hash into HTTP wire bytes (adds Content-Length).", returns: pairRet("the response serialised to HTTP wire bytes, with Content-Length added", ParamString), params: []builtinParamDoc{param("response", "Response as a hash or struct, with the fields http_parse_response produces.", ParamHash, ParamStruct)}},
	BuiltinNameHttpConnReadRequest:      {signature: "http_conn_read_request(handle, timeoutMs)", summary: "Reads exactly one HTTP request from a connection handle.", returns: pairRet("the request's method, target, headers, and body", ParamHash), params: []builtinParamDoc{param("handle", "Connection handle from net_connect, net_accept, or a TLS upgrade.", ParamInt), param("timeoutMs", "Read deadline in milliseconds.", ParamInt)}},
	BuiltinNameHttpConnReadResponse:     {signature: "http_conn_read_response(handle, timeoutMs)", summary: "Reads exactly one HTTP response from a connection handle.", returns: pairRet("the response's status, headers, and body", ParamHash), params: []builtinParamDoc{param("handle", "Connection handle from net_connect, net_accept, or a TLS upgrade.", ParamInt), param("timeoutMs", "Read deadline in milliseconds.", ParamInt)}},
	BuiltinNameHttpConnReadRequestHead:  {signature: "http_conn_read_request_head(handle, timeoutMs)", summary: "Reads a request's line+headers without the body (stream it via net_conn_read); adds content_length, chunked.", returns: pairRet("the request line and headers, with the body left on the connection", ParamHash).withFields("chunked", "content_length", "headers", "host", "method", "path", "proto", "query", "url"), params: []builtinParamDoc{param("handle", "Connection handle from net_connect, net_accept, or a TLS upgrade.", ParamInt), param("timeoutMs", "Read deadline in milliseconds.", ParamInt)}},
	BuiltinNameHttpConnReadResponseHead: {signature: "http_conn_read_response_head(handle, timeoutMs)", summary: "Reads a response's status line+headers without the body (stream it via net_conn_read); adds content_length, chunked.", returns: pairRet("the status line and headers, with the body left on the connection", ParamHash).withFields("chunked", "content_length", "headers", "proto", "status", "status_text"), params: []builtinParamDoc{param("handle", "Connection handle from net_connect, net_accept, or a TLS upgrade.", ParamInt), param("timeoutMs", "Read deadline in milliseconds.", ParamInt)}},

	// filesystem parsers — each *_open(image) returns a handle used by the rest.
	BuiltinNameNtfsOpen:          {signature: "ntfs_open(image, offset?, length?)", summary: "Opens an NTFS filesystem image and returns a handle. Returns (result, err). A volume that sits inside a larger image is opened where it lies rather than carved out first: pass the partition hash from table_list_partitions, or an explicit byte offset with an optional length. Every byte offset this handle goes on to report then already includes that start, so it addresses the image file itself and can be compared with a range from the table_ family without adding anything -- adding it twice, or comparing a partition-relative offset against a whole-disk one, mislocates evidence without failing. `bounded` is false when no length was given, which means reads can run past this volume's end into whatever follows it on the disk.", params: []builtinParamDoc{param("image", "Path to an NTFS image/partition, or to the whole disk the volume sits in.", ParamString), param("offset?", "Byte offset at which the volume begins, or a partition hash from table_list_partitions / table_partition_info. Omit when the image is the volume.", ParamInt, ParamHash), param("length?", "Bytes the volume occupies, so reads cannot run past its end. Omit to read to the end of the image. Not accepted alongside a partition hash, which already carries its length.", ParamInt)}, returns: pairRet("a handle for the other ntfs_ builtins; release it with ntfs_close", ParamHash).withFields("bounded", "handle", "path", "status", "volume_length", "volume_offset")},
	BuiltinNameNtfsListFiles:     {signature: "ntfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened NTFS image.", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("dir", "Directory path within the image.", ParamString)}, returns: pairRet("one hash per directory entry, including deleted ones", ParamArray).ofElem(ParamHash).withFields("allocated_size", "deleted", "entry_num", "is_dir", "name", "path", "sequence_num", "size")},
	BuiltinNameNtfsReadFileBytes: {signature: "ntfs_read_file_bytes(handle, path)", summary: "Reads a file from an opened NTFS image as a BYTES buffer. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: ntfs_extract_file streams the file to disk instead, ntfs_hash_file digests it in place, and ntfs_read_file_at returns one window of it.", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "File path within the image.", ParamString)}, returns: pairRet("the file's bytes", ParamBytes)},
	BuiltinNameNtfsReadFile:      {signature: "ntfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened NTFS image. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: ntfs_extract_file streams the file to disk instead, ntfs_hash_file digests it in place, and ntfs_read_file_at returns one window of it.", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "File path within the image.", ParamString)}, returns: pairRet("the file's bytes", ParamString)},
	BuiltinNameNtfsExtractFile:   {signature: "ntfs_extract_file(handle, path, dest)", summary: "Streams a file out of an opened NTFS image and writes it to dest, never holding the whole of it in memory -- which is what makes a file larger than a mutant value, or larger than RAM, extractable at all. The SHA-256 of what was written is computed in the same pass, so nothing has to read the extracted copy back to obtain one. dest must not already exist: two files in an image can share a name, and evidence written over by accident is not recoverable. A copy that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and what was written is the recoverable prefix rather than the file -- so read `truncated` before treating `digest` as the file's digest. Returns (result, err).", returns: pairRet("where the file was written, how much of it was written, and the digest of what was written", ParamHash).withFields("algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path inside the NTFS image.", ParamString), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameNtfsHashFile:      {signature: "ntfs_hash_file(handle, path, algorithm)", summary: "Digests a file inside an opened NTFS image without writing a copy of it anywhere, reading it in fixed chunks so the peak allocation has nothing to do with the size of the file. This is how a file too large to read into a mutant value is still looked up in a hash set. md5 and sha1 are offered because published hash sets are keyed on them, not as security properties. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and the digest covers only the recoverable prefix, so it will not match a hash set entry for the intact file -- which is the honest answer rather than a defect. Returns (result, err).", returns: pairRet("the digest of the file as it lies in the image, and how many bytes went into it", ParamHash).withFields("algorithm", "bytes_hashed", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path inside the NTFS image.", ParamString), param("algorithm", "One of md5, sha1 or sha256. An empty string means sha256.", ParamString)}},
	BuiltinNameNtfsReadFileAt:    {signature: "ntfs_read_file_at(handle, path, offset, length)", summary: "Reads one window of a file inside an opened NTFS image and returns it as a BYTES buffer, so the head of a file far larger than memory is still reachable. length is capped at 32 MiB, which is what the returned value has to fit into; use ntfs_extract_file for the whole of a larger file. An offset at or past the file's recorded size returns an empty buffer, which is how a caller walks off the end. An offset inside the recorded size but past the bytes the library could locate is an error naming both numbers: that is content the volume says exists and the image cannot produce, and a short buffer or a run of zeroes would hide it. The result is short rather than padded when the window runs past what was located. Returns (bytes, err).", returns: pairRet("the bytes in that window, short rather than padded where it runs past the file", ParamBytes), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path inside the NTFS image.", ParamString), param("offset", "Byte offset within the file to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameNtfsMetadata:      {signature: "ntfs_metadata(handle, path)", summary: "Returns metadata for a file/directory in an opened NTFS image, including the $STANDARD_INFORMATION created_at/modified_at/accessed_at/changed_at times and the readability flags (resident, sparse, compressed, encrypted, blocking_error).", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path within the image.", ParamString)}, returns: pairRet("metadata for a file/directory in an opened NTFS image, including the $STANDARD_INFORMATION created_at/modified_at/accessed_at/changed_at times and the readability flags (resident, sparse, compressed, encrypted, blocking_error)", ParamHash).withFields("accessed_at", "blocking_error", "changed_at", "compressed", "created_at", "encrypted", "entry_num", "has_data", "is_dir", "modified_at", "name", "non_resident", "path", "readable", "resident", "size", "sparse")},
	BuiltinNameNtfsVerify:        {signature: "ntfs_verify(handle)", summary: "Checks every MFT record against its update sequence array -- the per-sector mark NTFS writes so that a torn write can be detected. This is the only integrity check NTFS defines: the format carries no checksum over metadata or data, and libntfs exposes no other verifier, so nothing else about the volume can be verified from the volume itself. Records that are unallocated or that the volume marked bad are skipped rather than failed, because a whole-MFT walk meets them constantly and counting them as damage would report every healthy volume as corrupt. Reads the entire MFT, so it costs O(MFT size) rather than a seek. Every check reports `checked` beside `passed`, because a check that never ran says nothing about the volume and one boolean cannot tell \"intact\" from \"nothing to compare against\"; `examined` is the denominator it covered. `verified` is true only when at least one check actually ran and every check that ran passed, so a volume with nothing checkable is never verified -- checks_run is what tells that apart from a failure. `scope` states what the checks did not reach. Returns (result, err).", returns: pairRet("what this volume could be checked for, and what came of each check", ParamHash).withFields("checks", "checks_failed", "checks_passed", "checks_run", "checks_unavailable", "filesystem", "finding_count", "findings", "findings_truncated", "handle", "scope", "status", "verified"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameNtfsDeleted:       {signature: "ntfs_deleted(handle)", summary: "Reports every MFT record whose in-use flag is clear, with the name, timestamps and data runs NTFS left in place. NTFS does not erase a record when a file is unlinked, so this is the one filesystem of the six whose deleted block map is neither zeroed nor guessed: entries report content_state preserved, or resident when the content was small enough to live inside the record itself. What it cannot report is reuse. libntfs exposes no cluster-allocation query, so allocation_checked is false on every entry and the reallocated bit beside it means nobody looked, not that nothing happened. Records that would not parse are counted in unreadable -- a number libntfs itself does not keep -- and complete goes false when there were any, though an unreadable record may equally be a slot never used, one marked BAAD, or one whose fixups failed because it was partly overwritten, and nothing in the library tells those apart. Paths are reconstructed from parent references, so a file whose parent directory is still live gets its full path back. Names surviving in a parent directory index slack after the record itself was reused are not swept here; ntfs_list_files reports those, marked deleted, per directory. Returns (result, err).", returns: pairRet("what this volume still remembers about files it no longer lists", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "examined", "filesystem", "handle", "incomplete_reason", "scope", "sources", "sources_unavailable", "status", "unreadable", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameNtfsCapabilities:  {signature: "ntfs_capabilities(handle)", summary: "Reports what NTFS can record, as distinct from what this volume happens to have recorded. Twenty-two capabilities, twenty-one of them constants of the format and one -- change_journal -- read from this volume, because $UsnJrnl can be enabled, filled, deleted and re-created; libntfs cannot tell a journal that was never enabled from an $Extend directory too damaged to read, so a false there is not proof of absence. This is the fullest of the six: NTFS answers all eighteen questions asked of every filesystem here and adds security descriptors, alternate data streams, encryption and a change journal no other format in this tree has. Every capability reports two bits, not one: a name appears in `capabilities` only where the library declares it, and the questions it does not answer are listed in `unanswered` rather than rendered false -- a missing field and a recorded no are different facts and only one of them is evidence. `source` says whether an answer is a constant of the format or was read from this volume, which is what decides whether it may be cached across volumes; `volume_specific` is that list. Nothing here describes the contents: a true access_times says the record has the field, not that any timestamp on this volume was maintained. Reads no disk. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}, returns: pairRet("what this filesystem can record, which questions its reader does not answer, and which answers came from this volume", ParamHash).withFields("answered", "capabilities", "capability_count", "complete", "core_questions", "filesystem", "handle", "incomplete_reason", "scope", "status", "supported", "unanswered", "unanswered_count", "unsupported", "volume_specific")},
	BuiltinNameNtfsReport:        {signature: "ntfs_report(handle)", summary: "Walks the whole volume once and returns libntfs's own versioned document: every user-space MFT record, deleted and orphaned entries included, with paths reconstructed from $FILE_NAME parent references and each record's data runs as image-absolute offsets. The twelve reserved metadata records are not listed -- $MFT, $LogFile and $Bitmap are absent by design rather than missing. Identity is the MFT entry number with its sequence number, which is the one identity of the six that is both stable and carries a reuse counter, so two readings of a volume can be diffed on something sturdier than a path. Times are the $STANDARD_INFORMATION set, which is the set an anti-forensic tool rewrites; the $FILE_NAME copy most tools leave alone is not in this document, and ntfs_metadata is where the two are compared. A resident stream's bytes live inside the MFT record rather than at any cluster, so its run reports located false. One row per entry in the shape all six *_report builtins share: path, name, type, size, the deleted and fragmented bits, an identity and a parent identity, the four times that mean the same thing on every format, the layout the fragments were derived from, and image-absolute fragments whose offsets are -1 with `located` false wherever a run has no place in the image. Everything this format records that the others do not travels verbatim in each row's `extra`, so normalising loses nothing. `identity_kind` names the addressing and `identity_stable` says whether it survives the slot being reused, read from the same Capabilities *_capabilities reports and carrying `identity_stable_answered` because not every library declares it. `completeness_checked` says whether anything reconciled this listing against the filesystem's own record of what exists; `completeness_proven` means nothing without it. The library's own schema_version, library_version and generated stamp travel with the document. Reads the whole volume, so it costs O(volume) in time and holds its listing in memory rather than streaming it; the listing is capped at 50000 rows with every count beside it honest past the cap. events_from(report, \"fs_report\") turns it into a supertimeline. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}, returns: pairRet("one document describing this volume and every entry the walk reached", ParamHash).withFields("anomalies", "anomalies_available", "anomalies_truncated", "anomaly_count", "complete", "completeness_checked", "completeness_proven", "deleted_count", "directory_count", "end_offset", "file_count", "files", "files_truncated", "filesystem", "fragmented_count", "fragments_available", "generated", "handle", "identity_kind", "identity_stable", "identity_stable_answered", "incomplete_reason", "library_version", "name", "schema_version", "scope", "start_offset", "status", "volume", "warning_codes", "warnings", "warnings_available")},
	BuiltinNameNtfsClose:         {signature: "ntfs_close(handle)", summary: "Closes an NTFS handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameFatOpen:           {signature: "fat_open(image, offset?, length?)", summary: "Opens a FAT filesystem image and returns a handle. Returns (result, err). A volume that sits inside a larger image is opened where it lies rather than carved out first: pass the partition hash from table_list_partitions, or an explicit byte offset with an optional length. Every byte offset this handle goes on to report then already includes that start, so it addresses the image file itself and can be compared with a range from the table_ family without adding anything -- adding it twice, or comparing a partition-relative offset against a whole-disk one, mislocates evidence without failing. `bounded` is false when no length was given, which means reads can run past this volume's end into whatever follows it on the disk.", params: []builtinParamDoc{param("image", "Path to a FAT image/partition, or to the whole disk the volume sits in.", ParamString), param("offset?", "Byte offset at which the volume begins, or a partition hash from table_list_partitions / table_partition_info. Omit when the image is the volume.", ParamInt, ParamHash), param("length?", "Bytes the volume occupies, so reads cannot run past its end. Omit to read to the end of the image. Not accepted alongside a partition hash, which already carries its length.", ParamInt)}, returns: pairRet("a handle for the other fat_ builtins; release it with fat_close", ParamHash).withFields("bounded", "handle", "path", "status", "volume_length", "volume_offset")},
	BuiltinNameFatListFiles:      {signature: "fat_list_files(handle, dir)", summary: "Lists entries under a directory in an opened FAT image.", returns: pairRet("one hash per directory entry, including deleted and recovered ones", ParamArray).ofElem(ParamHash).withFields("accessed_at", "attributes", "cluster_allocated", "created_at", "deleted", "first_cluster", "is_dir", "modified_at", "name", "path", "recovered", "short_name", "size", "virtual"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameFatReadFileBytes:  {signature: "fat_read_file_bytes(handle, path)", summary: "Reads a file from an opened FAT image as a BYTES buffer. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: fat_extract_file streams the file to disk instead, fat_hash_file digests it in place, and fat_read_file_at returns one window of it.", params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString)}, returns: pairRet("the file's bytes", ParamBytes)},
	BuiltinNameFatReadFile:       {signature: "fat_read_file(handle, path)", summary: "Reads a file's bytes from an opened FAT image. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: fat_extract_file streams the file to disk instead, fat_hash_file digests it in place, and fat_read_file_at returns one window of it.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString)}},
	BuiltinNameFatExtractFile:    {signature: "fat_extract_file(handle, path, dest)", summary: "Streams a file out of an opened FAT image and writes it to dest, never holding the whole of it in memory -- which is what makes a file larger than a mutant value, or larger than RAM, extractable at all. The SHA-256 of what was written is computed in the same pass, so nothing has to read the extracted copy back to obtain one. dest must not already exist: two files in an image can share a name, and evidence written over by accident is not recoverable. A copy that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and what was written is the recoverable prefix rather than the file -- so read `truncated` before treating `digest` as the file's digest. Returns (result, err).", returns: pairRet("where the file was written, how much of it was written, and the digest of what was written", ParamHash).withFields("algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameFatHashFile:       {signature: "fat_hash_file(handle, path, algorithm)", summary: "Digests a file inside an opened FAT image without writing a copy of it anywhere, reading it in fixed chunks so the peak allocation has nothing to do with the size of the file. This is how a file too large to read into a mutant value is still looked up in a hash set. md5 and sha1 are offered because published hash sets are keyed on them, not as security properties. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and the digest covers only the recoverable prefix, so it will not match a hash set entry for the intact file -- which is the honest answer rather than a defect. Returns (result, err).", returns: pairRet("the digest of the file as it lies in the image, and how many bytes went into it", ParamHash).withFields("algorithm", "bytes_hashed", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString), param("algorithm", "One of md5, sha1 or sha256. An empty string means sha256.", ParamString)}},
	BuiltinNameFatReadFileAt:     {signature: "fat_read_file_at(handle, path, offset, length)", summary: "Reads one window of a file inside an opened FAT image and returns it as a BYTES buffer, so the head of a file far larger than memory is still reachable. length is capped at 32 MiB, which is what the returned value has to fit into; use fat_extract_file for the whole of a larger file. An offset at or past the file's recorded size returns an empty buffer, which is how a caller walks off the end. An offset inside the recorded size but past the bytes the library could locate is an error naming both numbers: that is content the volume says exists and the image cannot produce, and a short buffer or a run of zeroes would hide it. The result is short rather than padded when the window runs past what was located. Returns (bytes, err).", returns: pairRet("the bytes in that window, short rather than padded where it runs past the file", ParamBytes), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString), param("offset", "Byte offset within the file to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameFatMetadata:       {signature: "fat_metadata(handle, path)", summary: "Returns metadata for a path in an opened FAT image.", returns: pairRet("metadata for a path in an opened FAT image", ParamHash).withFields("accessed_at", "attributes", "bytes_per_sector", "cluster_count", "cluster_size", "created_at", "deleted", "filesystem", "first_cluster", "is_dir", "modified_at", "name", "path", "recovered", "short_name", "size", "virtual", "volume_label"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString)}},
	BuiltinNameFatVerify:         {signature: "fat_verify(handle)", summary: "Compares FAT's two allocation tables against each other, which is the only integrity signal the format has -- FAT carries no checksum anywhere. A volume with a single FAT reports the check unavailable rather than passed, because there is no mirror to compare. libfat counts disagreements as entries are read rather than scanning for them, so this walks the live directory tree first to give the comparison a denominator worth quoting; the data chains of files nothing read and clusters no directory references are not covered. The mismatch count is cumulative for the handle and rises again each time the same bad entry is re-read, so it bounds the number of disagreeing entries from above rather than counting them. Every check reports `checked` beside `passed`, because a check that never ran says nothing about the volume and one boolean cannot tell \"intact\" from \"nothing to compare against\"; `examined` is the denominator it covered. `verified` is true only when at least one check actually ran and every check that ran passed, so a volume with nothing checkable is never verified -- checks_run is what tells that apart from a failure. `scope` states what the checks did not reach. Returns (result, err).", returns: pairRet("what this volume could be checked for, and what came of each check", ParamHash).withFields("checks", "checks_failed", "checks_passed", "checks_run", "checks_unavailable", "filesystem", "finding_count", "findings", "findings_truncated", "handle", "scope", "status", "verified"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString)}},
	BuiltinNameFatDeleted:        {signature: "fat_deleted(handle)", summary: "Reports FAT records marked deleted in a reachable directory, records surviving in the first cluster of a deleted directory, and records swept out of clusters nothing references. Content is located for one cluster and no further: deletion frees the FAT chain, so following it from a deleted entry follows whatever owns those clusters now, and the first cluster is the only location the surviving record itself states. Entries therefore report content_state first_cluster_only with located_bytes counting exactly that, against a size the record still claims -- the two are separate fields because a recorded size is not a count of the bytes that are there. Assuming the rest of the file followed contiguously is a hypothesis and is not taken here. Deletion also overwrites the first character of the short name; where it could not be brute-forced back out of the name checksum libfat substitutes an underscore, and those entries report name_source reconstructed. The sweep examines free clusters only and requires the dot records to agree with the cluster they were found in, so a directory fragment whose start was overwritten is not found. libfat has no warnings channel, so warnings_available is false and a silently skipped cluster leaves no trace. Returns (result, err).", returns: pairRet("what this volume still remembers about files it no longer lists", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "examined", "filesystem", "handle", "incomplete_reason", "scope", "sources", "sources_unavailable", "status", "unreadable", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString)}},
	BuiltinNameFatCapabilities:   {signature: "fat_capabilities(handle)", summary: "Reports what FAT can record, as distinct from what this volume happens to have recorded. Twenty-four capabilities, three of them read from this volume's boot record and all three about what it can be checked or recovered against rather than what it records: a second allocation table to compare, an FSInfo sector to read hints from, and a backup boot sector that may be what let the volume be opened at all. stable_file_identity false is the consequential one -- a directory slot reused after a deletion carries its predecessor's identity exactly, so two readings of a FAT volume cannot be diffed on it. sub_second_timestamps is true of one timestamp only: creation is recorded to 10 milliseconds, modification to 2 seconds and last access to the day, so equal timestamps here are not evidence that nothing changed. Every capability reports two bits, not one: a name appears in `capabilities` only where the library declares it, and the questions it does not answer are listed in `unanswered` rather than rendered false -- a missing field and a recorded no are different facts and only one of them is evidence. `source` says whether an answer is a constant of the format or was read from this volume, which is what decides whether it may be cached across volumes; `volume_specific` is that list. Nothing here describes the contents: a true access_times says the record has the field, not that any timestamp on this volume was maintained. Reads no disk. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString)}, returns: pairRet("what this filesystem can record, which questions its reader does not answer, and which answers came from this volume", ParamHash).withFields("answered", "capabilities", "capability_count", "complete", "core_questions", "filesystem", "handle", "incomplete_reason", "scope", "status", "supported", "unanswered", "unanswered_count", "unsupported", "volume_specific")},
	BuiltinNameFatReport:         {signature: "fat_report(handle)", summary: "Walks the whole volume once and returns libfat's own versioned document: the reachable directory tree with deleted entries reported at the slots they occupy, and deleted directories descended into where their first cluster is still free and still begins with its own dot records. Nothing is assumed -- a deleted entry's FAT chain has been freed, so its layout past the first cluster is absent here rather than guessed, and fat_recover_file_assuming_contiguous is where that hypothesis is asked for by name. The unreferenced-cluster sweep is not run; fat_deleted is where records no directory reaches are looked for. FAT records no metadata-change time, so metadata_changed is empty on every row for a reason fat_capabilities states, and an identity here names a slot rather than a file. A disagreement between the volume's two allocation tables is raised as a warning, since it is a tamper and damage indicator rather than a reporting problem. One row per entry in the shape all six *_report builtins share: path, name, type, size, the deleted and fragmented bits, an identity and a parent identity, the four times that mean the same thing on every format, the layout the fragments were derived from, and image-absolute fragments whose offsets are -1 with `located` false wherever a run has no place in the image. Everything this format records that the others do not travels verbatim in each row's `extra`, so normalising loses nothing. `identity_kind` names the addressing and `identity_stable` says whether it survives the slot being reused, read from the same Capabilities *_capabilities reports and carrying `identity_stable_answered` because not every library declares it. `completeness_checked` says whether anything reconciled this listing against the filesystem's own record of what exists; `completeness_proven` means nothing without it. The library's own schema_version, library_version and generated stamp travel with the document. Reads the whole volume, so it costs O(volume) in time and holds its listing in memory rather than streaming it; the listing is capped at 50000 rows with every count beside it honest past the cap. events_from(report, \"fs_report\") turns it into a supertimeline. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString)}, returns: pairRet("one document describing this volume and every entry the walk reached", ParamHash).withFields("anomalies", "anomalies_available", "anomalies_truncated", "anomaly_count", "complete", "completeness_checked", "completeness_proven", "deleted_count", "directory_count", "end_offset", "file_count", "files", "files_truncated", "filesystem", "fragmented_count", "fragments_available", "generated", "handle", "identity_kind", "identity_stable", "identity_stable_answered", "incomplete_reason", "library_version", "name", "schema_version", "scope", "start_offset", "status", "volume", "warning_codes", "warnings", "warnings_available")},
	BuiltinNameFatClose:          {signature: "fat_close(handle)", summary: "Closes a FAT handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString)}},
	BuiltinNameXfatOpen:          {signature: "xfat_open(image, offset?, length?)", summary: "Opens an exFAT filesystem image and returns a handle. Returns (result, err). A volume that sits inside a larger image is opened where it lies rather than carved out first: pass the partition hash from table_list_partitions, or an explicit byte offset with an optional length. Every byte offset this handle goes on to report then already includes that start, so it addresses the image file itself and can be compared with a range from the table_ family without adding anything -- adding it twice, or comparing a partition-relative offset against a whole-disk one, mislocates evidence without failing. `bounded` is false when no length was given, which means reads can run past this volume's end into whatever follows it on the disk.", params: []builtinParamDoc{param("image", "Path to an exFAT image/partition, or to the whole disk the volume sits in.", ParamString), param("offset?", "Byte offset at which the volume begins, or a partition hash from table_list_partitions / table_partition_info. Omit when the image is the volume.", ParamInt, ParamHash), param("length?", "Bytes the volume occupies, so reads cannot run past its end. Omit to read to the end of the image. Not accepted alongside a partition hash, which already carries its length.", ParamInt)}, returns: pairRet("a handle for the other xfat_ builtins; release it with xfat_close", ParamHash).withFields("bounded", "handle", "path", "status", "volume_length", "volume_offset")},
	BuiltinNameXfatListFiles:     {signature: "xfat_list_files(handle, dir)", summary: "Lists entries under a directory in an opened exFAT image, with created_at/modified_at/accessed_at, per-timestamp *_utc_offset_valid flags, attributes and valid_data_size. A nameless entry is reported as \"(unnamed)\".", returns: pairRet("one hash per directory entry", ParamArray).ofElem(ParamHash), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameXfatReadFileBytes: {signature: "xfat_read_file_bytes(handle, path)", summary: "Reads a file from an opened exFAT image as a BYTES buffer. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: xfat_extract_file streams the file to disk instead, xfat_hash_file digests it in place, and xfat_read_file_at returns one window of it.", params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString)}, returns: pairRet("the file's bytes", ParamBytes)},
	BuiltinNameXfatReadFile:      {signature: "xfat_read_file(handle, path)", summary: "Reads a file's bytes from an opened exFAT image. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: xfat_extract_file streams the file to disk instead, xfat_hash_file digests it in place, and xfat_read_file_at returns one window of it.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString)}},
	BuiltinNameXfatExtractFile:   {signature: "xfat_extract_file(handle, path, dest)", summary: "Streams a file out of an opened exFAT image and writes it to dest, never holding the whole of it in memory -- which is what makes a file larger than a mutant value, or larger than RAM, extractable at all. The SHA-256 of what was written is computed in the same pass, so nothing has to read the extracted copy back to obtain one. dest must not already exist: two files in an image can share a name, and evidence written over by accident is not recoverable. A copy that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and what was written is the recoverable prefix rather than the file -- so read `truncated` before treating `digest` as the file's digest. Returns (result, err).", returns: pairRet("where the file was written, how much of it was written, and the digest of what was written", ParamHash).withFields("algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameXfatHashFile:      {signature: "xfat_hash_file(handle, path, algorithm)", summary: "Digests a file inside an opened exFAT image without writing a copy of it anywhere, reading it in fixed chunks so the peak allocation has nothing to do with the size of the file. This is how a file too large to read into a mutant value is still looked up in a hash set. md5 and sha1 are offered because published hash sets are keyed on them, not as security properties. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and the digest covers only the recoverable prefix, so it will not match a hash set entry for the intact file -- which is the honest answer rather than a defect. Returns (result, err).", returns: pairRet("the digest of the file as it lies in the image, and how many bytes went into it", ParamHash).withFields("algorithm", "bytes_hashed", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString), param("algorithm", "One of md5, sha1 or sha256. An empty string means sha256.", ParamString)}},
	BuiltinNameXfatReadFileAt:    {signature: "xfat_read_file_at(handle, path, offset, length)", summary: "Reads one window of a file inside an opened exFAT image and returns it as a BYTES buffer, so the head of a file far larger than memory is still reachable. length is capped at 32 MiB, which is what the returned value has to fit into; use xfat_extract_file for the whole of a larger file. An offset at or past the file's recorded size returns an empty buffer, which is how a caller walks off the end. An offset inside the recorded size but past the bytes the library could locate is an error naming both numbers: that is content the volume says exists and the image cannot produce, and a short buffer or a run of zeroes would hide it. The result is short rather than padded when the window runs past what was located. Returns (bytes, err).", returns: pairRet("the bytes in that window, short rather than padded where it runs past the file", ParamBytes), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString), param("offset", "Byte offset within the file to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameXfatMetadata:      {signature: "xfat_metadata(handle, path)", summary: "Returns metadata for a path in an opened exFAT image, including created_at/modified_at/accessed_at with *_utc_offset_valid flags, attributes and valid_data_size (the written portion of size; the remainder is slack).", returns: pairRet("metadata for a path in an opened exFAT image, including created_at/modified_at/accessed_at with *_utc_offset_valid flags, attributes and valid_data_size (the written portion of size; the remainder is slack)", ParamHash), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString)}},
	BuiltinNameXfatVerify:        {signature: "xfat_verify(handle)", summary: "Runs exFAT's two independent integrity checks over the live directory tree: each file entry set's recorded checksum against the checksum computed over the set as read, and each name re-hashed through the volume's own up-case table against the hash stored in its stream extension record. Neither subsumes the other -- a name rewritten with the entry set checksum recomputed but the hash left alone passes one and fails the other -- so they are reported as two checks, not one. An entry whose name is a libxfat placeholder rather than a name read off the volume is reported as a finding, because that name is the library's invention and not evidence. Deleted and carved records are not walked, and libxfat reports no warning for a directory it could not read, so examined is the count of entries actually reached rather than a claim about the volume. Every check reports `checked` beside `passed`, because a check that never ran says nothing about the volume and one boolean cannot tell \"intact\" from \"nothing to compare against\"; `examined` is the denominator it covered. `verified` is true only when at least one check actually ran and every check that ran passed, so a volume with nothing checkable is never verified -- checks_run is what tells that apart from a failure. `scope` states what the checks did not reach. Returns (result, err).", returns: pairRet("what this volume could be checked for, and what came of each check", ParamHash).withFields("checks", "checks_failed", "checks_passed", "checks_run", "checks_unavailable", "filesystem", "finding_count", "findings", "findings_truncated", "handle", "scope", "status", "verified"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString)}},
	BuiltinNameXfatDeleted:       {signature: "xfat_deleted(handle)", summary: "Reports exFAT records marked deleted in a reachable directory, records surviving inside a deleted directory, and entry sets carved out of unallocated clusters. exFAT is the one format here that can state a deleted file whole layout as a fact: a stream extension carrying NoFatChain means the volume declared the run contiguous while the file was live and the FAT entries for it were undefined even then, so freeing the chain took nothing away, and those entries report content_state declared_contiguous rather than a guess. Everything else reports first_cluster_only. The carve accepts an entry set only when every secondary record agrees with its primary on allocation state and a stream extension was seen, so a half-overwritten set is dropped rather than reported half-read. A carved entry whose name did not survive is given a placeholder derived from its cluster number and reports name_source synthetic -- it is not a filename and must not be written into a report as one. libxfat is the only library of the six that leaves its reallocation flag false when the bitmap could not be read instead of folding that into a positive, which is what makes allocation_checked meaningful here. Returns (result, err).", returns: pairRet("what this volume still remembers about files it no longer lists", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "examined", "filesystem", "handle", "incomplete_reason", "scope", "sources", "sources_unavailable", "status", "unreadable", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString)}},
	BuiltinNameXfatCapabilities:  {signature: "xfat_capabilities(handle)", summary: "Reports what exFAT can record, as distinct from what this volume happens to have recorded. Twenty-two capabilities, one -- second_fat -- read from this volume's boot record. exFAT is the sibling of FAT that gained an allocation bitmap independent of the table, a valid data length distinguishing written bytes from allocated ones, and a NoFatChain flag declaring contiguity, and that gained no metadata-change time, no owner and no identity surviving reuse. timezone_offsets is the one timestamp question it answers differently from FAT: exFAT stores the offset beside the stamp, so a reading can be anchored to UTC. Every capability reports two bits, not one: a name appears in `capabilities` only where the library declares it, and the questions it does not answer are listed in `unanswered` rather than rendered false -- a missing field and a recorded no are different facts and only one of them is evidence. `source` says whether an answer is a constant of the format or was read from this volume, which is what decides whether it may be cached across volumes; `volume_specific` is that list. Nothing here describes the contents: a true access_times says the record has the field, not that any timestamp on this volume was maintained. Reads no disk. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString)}, returns: pairRet("what this filesystem can record, which questions its reader does not answer, and which answers came from this volume", ParamHash).withFields("answered", "capabilities", "capability_count", "complete", "core_questions", "filesystem", "handle", "incomplete_reason", "scope", "status", "supported", "unanswered", "unanswered_count", "unsupported", "volume_specific")},
	BuiltinNameXfatReport:        {signature: "xfat_report(handle)", summary: "Walks the whole volume once and returns libxfat's own versioned document: the reachable directory tree with deleted entries reported at the slots they occupy, no extent assumed, and each row's entry-set checksum carried as two bits -- checked beside verified -- because the comparison does not happen for a synthetic entry and a verified that nothing checked says nothing. The sweep for records carved out of unallocated space is not run here; xfat_deleted is where those are looked for, with the confidence grading this shape has nowhere to put. Each row carries the valid data length beside the size: the bytes between them are allocated, readable and were never written by this file. exFAT records no metadata-change time, so metadata_changed is empty on every row, and each timestamp says whether the volume actually recorded a UTC offset for it. One row per entry in the shape all six *_report builtins share: path, name, type, size, the deleted and fragmented bits, an identity and a parent identity, the four times that mean the same thing on every format, the layout the fragments were derived from, and image-absolute fragments whose offsets are -1 with `located` false wherever a run has no place in the image. Everything this format records that the others do not travels verbatim in each row's `extra`, so normalising loses nothing. `identity_kind` names the addressing and `identity_stable` says whether it survives the slot being reused, read from the same Capabilities *_capabilities reports and carrying `identity_stable_answered` because not every library declares it. `completeness_checked` says whether anything reconciled this listing against the filesystem's own record of what exists; `completeness_proven` means nothing without it. The library's own schema_version, library_version and generated stamp travel with the document. Reads the whole volume, so it costs O(volume) in time and holds its listing in memory rather than streaming it; the listing is capped at 50000 rows with every count beside it honest past the cap. events_from(report, \"fs_report\") turns it into a supertimeline. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString)}, returns: pairRet("one document describing this volume and every entry the walk reached", ParamHash).withFields("anomalies", "anomalies_available", "anomalies_truncated", "anomaly_count", "complete", "completeness_checked", "completeness_proven", "deleted_count", "directory_count", "end_offset", "file_count", "files", "files_truncated", "filesystem", "fragmented_count", "fragments_available", "generated", "handle", "identity_kind", "identity_stable", "identity_stable_answered", "incomplete_reason", "library_version", "name", "schema_version", "scope", "start_offset", "status", "volume", "warning_codes", "warnings", "warnings_available")},
	BuiltinNameXfatClose:         {signature: "xfat_close(handle)", summary: "Closes an exFAT handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString)}},
	BuiltinNameExtOpen:           {signature: "ext_open(image, offset?, length?)", summary: "Opens an ext2/3/4 filesystem image and returns a handle. Returns (result, err). A volume that sits inside a larger image is opened where it lies rather than carved out first: pass the partition hash from table_list_partitions, or an explicit byte offset with an optional length. Every byte offset this handle goes on to report then already includes that start, so it addresses the image file itself and can be compared with a range from the table_ family without adding anything -- adding it twice, or comparing a partition-relative offset against a whole-disk one, mislocates evidence without failing. `bounded` is false when no length was given, which means reads can run past this volume's end into whatever follows it on the disk.", params: []builtinParamDoc{param("image", "Path to an ext image/partition, or to the whole disk the volume sits in.", ParamString), param("offset?", "Byte offset at which the volume begins, or a partition hash from table_list_partitions / table_partition_info. Omit when the image is the volume.", ParamInt, ParamHash), param("length?", "Bytes the volume occupies, so reads cannot run past its end. Omit to read to the end of the image. Not accepted alongside a partition hash, which already carries its length.", ParamInt)}, returns: pairRet("a handle for the other ext_ builtins; release it with ext_close", ParamHash).withFields("bounded", "handle", "path", "status", "volume_length", "volume_offset")},
	BuiltinNameExtListFiles:      {signature: "ext_list_files(handle, dir)", summary: "Lists entries under a directory in an opened ext image, with created_at/modified_at/accessed_at/changed_at and deleted.", returns: pairRet("one hash per directory entry, including deleted ones", ParamArray).ofElem(ParamHash).withFields("accessed_at", "changed_at", "created_at", "deleted", "inode", "is_dir", "modified_at", "name", "path", "size"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameExtReadFileBytes:  {signature: "ext_read_file_bytes(handle, path)", summary: "Reads a file from an opened ext image as a BYTES buffer. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: ext_extract_file streams the file to disk instead, ext_hash_file digests it in place, and ext_read_file_at returns one window of it.", params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext2/3/4 image.", ParamString)}, returns: pairRet("the file's bytes", ParamBytes)},
	BuiltinNameExtReadFile:       {signature: "ext_read_file(handle, path)", summary: "Reads a file's bytes from an opened ext image. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: ext_extract_file streams the file to disk instead, ext_hash_file digests it in place, and ext_read_file_at returns one window of it.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext2/3/4 image.", ParamString)}},
	BuiltinNameExtExtractFile:    {signature: "ext_extract_file(handle, path, dest)", summary: "Streams a file out of an opened ext image and writes it to dest, never holding the whole of it in memory -- which is what makes a file larger than a mutant value, or larger than RAM, extractable at all. The SHA-256 of what was written is computed in the same pass, so nothing has to read the extracted copy back to obtain one. dest must not already exist: two files in an image can share a name, and evidence written over by accident is not recoverable. A copy that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and what was written is the recoverable prefix rather than the file -- so read `truncated` before treating `digest` as the file's digest. Returns (result, err).", returns: pairRet("where the file was written, how much of it was written, and the digest of what was written", ParamHash).withFields("algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext image.", ParamString), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameExtHashFile:       {signature: "ext_hash_file(handle, path, algorithm)", summary: "Digests a file inside an opened ext image without writing a copy of it anywhere, reading it in fixed chunks so the peak allocation has nothing to do with the size of the file. This is how a file too large to read into a mutant value is still looked up in a hash set. md5 and sha1 are offered because published hash sets are keyed on them, not as security properties. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and the digest covers only the recoverable prefix, so it will not match a hash set entry for the intact file -- which is the honest answer rather than a defect. Returns (result, err).", returns: pairRet("the digest of the file as it lies in the image, and how many bytes went into it", ParamHash).withFields("algorithm", "bytes_hashed", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext image.", ParamString), param("algorithm", "One of md5, sha1 or sha256. An empty string means sha256.", ParamString)}},
	BuiltinNameExtReadFileAt:     {signature: "ext_read_file_at(handle, path, offset, length)", summary: "Reads one window of a file inside an opened ext image and returns it as a BYTES buffer, so the head of a file far larger than memory is still reachable. length is capped at 32 MiB, which is what the returned value has to fit into; use ext_extract_file for the whole of a larger file. An offset at or past the file's recorded size returns an empty buffer, which is how a caller walks off the end. An offset inside the recorded size but past the bytes the library could locate is an error naming both numbers: that is content the volume says exists and the image cannot produce, and a short buffer or a run of zeroes would hide it. The result is short rather than padded when the window runs past what was located. Returns (bytes, err).", returns: pairRet("the bytes in that window, short rather than padded where it runs past the file", ParamBytes), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext image.", ParamString), param("offset", "Byte offset within the file to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameExtMetadata:       {signature: "ext_metadata(handle, path)", summary: "Returns metadata for a path in an opened ext image, including created_at/modified_at/accessed_at/changed_at, deleted, and warnings (where the parser judged the answer may be incomplete).", returns: pairRet("metadata for a path in an opened ext image, including created_at/modified_at/accessed_at/changed_at, deleted, and warnings (where the parser judged the answer may be incomplete)", ParamHash).withFields("accessed_at", "block_size", "changed_at", "created_at", "deleted", "inode", "inodes_count", "is_dir", "kind", "modified_at", "name", "path", "size", "warnings"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext2/3/4 image.", ParamString)}},
	BuiltinNameExtVerify:         {signature: "ext_verify(handle)", summary: "Reports ext's superblock plausibility checks together with the metadata CRC32c comparisons libext made while parsing this handle. The plausibility check is geometry and range sanity -- block and inode sizes, inodes per group, reserved percentage -- and not a checksum, because libext's per-structure CRC verifiers are unexported; a pass means nothing implausible was found, not that the superblock is unmodified. A volume made without RO_COMPAT_METADATA_CSUM reports the checksum check unavailable: it carries no CRCs, so a torn or edited structure on it is not detectable by checksum at all. Checksum coverage is whatever this handle has parsed, which always includes the superblock and the group descriptors and includes inodes and directory blocks only once something has read them, so verifying again after a walk widens it. Every check reports `checked` beside `passed`, because a check that never ran says nothing about the volume and one boolean cannot tell \"intact\" from \"nothing to compare against\"; `examined` is the denominator it covered. `verified` is true only when at least one check actually ran and every check that ran passed, so a volume with nothing checkable is never verified -- checks_run is what tells that apart from a failure. `scope` states what the checks did not reach. Returns (result, err).", returns: pairRet("what this volume could be checked for, and what came of each check", ParamHash).withFields("checks", "checks_failed", "checks_passed", "checks_run", "checks_unavailable", "filesystem", "finding_count", "findings", "findings_truncated", "handle", "scope", "status", "verified"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString)}},
	BuiltinNameExtDeleted:        {signature: "ext_deleted(handle)", summary: "Reports deleted and orphaned inodes from every source libext consults: the inode table, whose slots keep mode, size, owner and times until reused; the legacy orphan list and the ext4 orphan file, which record inodes unlinked while still open and which a clean unmount would otherwise leave no trace of; and directory slack, which keeps the name the inode never held. ext4 zeroes the extent tree on unlink, so content_state is usually none -- the file is fully described and cannot be located -- and an entry that does carry a map reports it as image-absolute runs rather than raw block numbers, because a volume-relative block scaled to bytes looks exactly like an image offset. Two limits worth stating. libext grades a surviving map partial both when a block has been reallocated and when the block bitmap could not be read, so reallocated true may mean nobody could check. And entries on the legacy orphan chain carry no deletion time by design, because ext stores the next-orphan pointer in that field; an empty deleted_at there is not an absence of evidence. Block groups whose inode tables were never initialised are not scanned, since what is in them predates the filesystem. Warnings raised during this scan are reported; ones already on the handle are not. Returns (result, err).", returns: pairRet("what this volume still remembers about files it no longer lists", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "examined", "filesystem", "handle", "incomplete_reason", "scope", "sources", "sources_unavailable", "status", "unreadable", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString)}},
	BuiltinNameExtCapabilities:   {signature: "ext_capabilities(handle)", summary: "Reports what ext can record, as distinct from what this volume happens to have recorded. Twenty-three capabilities, eleven of them read from this volume's superblock -- more than any other filesystem here, and a property of ext rather than of libext, because ext2, ext3 and ext4 are one on-disk format separated by feature flags. creation_times and sub_second_timestamps both follow the inode size, and that single difference is most of what separates an ext2 volume from an ext4 one; an answer cached from one volume is wrong about the next. journaled is true only when the journal is on this volume, so a volume using an external journal device reports false, meaning the journal exists but not here. deleted_entries_survive is not among the questions libext answers, so it comes back unanswered rather than false; ext_deleted is what reports on that. Every capability reports two bits, not one: a name appears in `capabilities` only where the library declares it, and the questions it does not answer are listed in `unanswered` rather than rendered false -- a missing field and a recorded no are different facts and only one of them is evidence. `source` says whether an answer is a constant of the format or was read from this volume, which is what decides whether it may be cached across volumes; `volume_specific` is that list. Nothing here describes the contents: a true access_times says the record has the field, not that any timestamp on this volume was maintained. Reads no disk. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString)}, returns: pairRet("what this filesystem can record, which questions its reader does not answer, and which answers came from this volume", ParamHash).withFields("answered", "capabilities", "capability_count", "complete", "core_questions", "filesystem", "handle", "incomplete_reason", "scope", "status", "supported", "unanswered", "unanswered_count", "unsupported", "volume_specific")},
	BuiltinNameExtReport:         {signature: "ext_report(handle)", summary: "Walks the whole inode table once -- not only what the directory tree reaches -- and returns libext's own versioned document, so an inode nothing names any more is listed with whatever path could be reconstructed for it. ext is the only one of the six formats here that records when a file was deleted, and that stamp is carried as deleted_at rather than folded into the other four; it is also the one timestamp that makes a row a deletion event in a timeline. Identity is the inode number with its generation, which is what tells a file replaced at the same path from one never touched. Fragments describe written data only: a preallocated span reads as zeros through the file interface and may still hold prior contents, which is ext_slack's question rather than this document's. On a volume whose inodes are 128 bytes there is no birth time and no sub-second fraction at all. One row per entry in the shape all six *_report builtins share: path, name, type, size, the deleted and fragmented bits, an identity and a parent identity, the four times that mean the same thing on every format, the layout the fragments were derived from, and image-absolute fragments whose offsets are -1 with `located` false wherever a run has no place in the image. Everything this format records that the others do not travels verbatim in each row's `extra`, so normalising loses nothing. `identity_kind` names the addressing and `identity_stable` says whether it survives the slot being reused, read from the same Capabilities *_capabilities reports and carrying `identity_stable_answered` because not every library declares it. `completeness_checked` says whether anything reconciled this listing against the filesystem's own record of what exists; `completeness_proven` means nothing without it. The library's own schema_version, library_version and generated stamp travel with the document. Reads the whole volume, so it costs O(volume) in time and holds its listing in memory rather than streaming it; the listing is capped at 50000 rows with every count beside it honest past the cap. events_from(report, \"fs_report\") turns it into a supertimeline. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString)}, returns: pairRet("one document describing this volume and every entry the walk reached", ParamHash).withFields("anomalies", "anomalies_available", "anomalies_truncated", "anomaly_count", "complete", "completeness_checked", "completeness_proven", "deleted_count", "directory_count", "end_offset", "file_count", "files", "files_truncated", "filesystem", "fragmented_count", "fragments_available", "generated", "handle", "identity_kind", "identity_stable", "identity_stable_answered", "incomplete_reason", "library_version", "name", "schema_version", "scope", "start_offset", "status", "volume", "warning_codes", "warnings", "warnings_available")},
	BuiltinNameExtClose:          {signature: "ext_close(handle)", summary: "Closes an ext handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString)}},
	BuiltinNameHfsOpen:           {signature: "hfs_open(image, offset?, length?)", summary: "Opens an HFS+ filesystem image and returns a handle. Returns (result, err). A volume that sits inside a larger image is opened where it lies rather than carved out first: pass the partition hash from table_list_partitions, or an explicit byte offset with an optional length. Every byte offset this handle goes on to report then already includes that start, so it addresses the image file itself and can be compared with a range from the table_ family without adding anything -- adding it twice, or comparing a partition-relative offset against a whole-disk one, mislocates evidence without failing. `bounded` is false when no length was given, which means reads can run past this volume's end into whatever follows it on the disk.", params: []builtinParamDoc{param("image", "Path to an HFS+ image/partition, or to the whole disk the volume sits in.", ParamString), param("offset?", "Byte offset at which the volume begins, or a partition hash from table_list_partitions / table_partition_info. Omit when the image is the volume.", ParamInt, ParamHash), param("length?", "Bytes the volume occupies, so reads cannot run past its end. Omit to read to the end of the image. Not accepted alongside a partition hash, which already carries its length.", ParamInt)}, returns: pairRet("a handle for the other hfs_ builtins; release it with hfs_close", ParamHash).withFields("bounded", "handle", "path", "status", "volume_length", "volume_offset")},
	BuiltinNameHfsListFiles:      {signature: "hfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened HFS+ image.", returns: pairRet("one hash per directory entry", ParamArray).ofElem(ParamHash).withFields("cnid", "is_dir", "is_system", "name", "path"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameHfsReadFileBytes:  {signature: "hfs_read_file_bytes(handle, path)", summary: "Reads a file from an opened HFS+ image as a BYTES buffer. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: hfs_extract_file streams the file to disk instead, hfs_hash_file digests it in place, and hfs_read_file_at returns one window of it.", params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString)}, returns: pairRet("the file's bytes", ParamBytes)},
	BuiltinNameHfsReadFile:       {signature: "hfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened HFS+ image. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: hfs_extract_file streams the file to disk instead, hfs_hash_file digests it in place, and hfs_read_file_at returns one window of it.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString)}},
	BuiltinNameHfsExtractFile:    {signature: "hfs_extract_file(handle, path, dest)", summary: "Streams a file out of an opened HFS+ image and writes it to dest, never holding the whole of it in memory -- which is what makes a file larger than a mutant value, or larger than RAM, extractable at all. The SHA-256 of what was written is computed in the same pass, so nothing has to read the extracted copy back to obtain one. dest must not already exist: two files in an image can share a name, and evidence written over by accident is not recoverable. A copy that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and what was written is the recoverable prefix rather than the file -- so read `truncated` before treating `digest` as the file's digest. Returns (result, err).", returns: pairRet("where the file was written, how much of it was written, and the digest of what was written", ParamHash).withFields("algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameHfsHashFile:       {signature: "hfs_hash_file(handle, path, algorithm)", summary: "Digests a file inside an opened HFS+ image without writing a copy of it anywhere, reading it in fixed chunks so the peak allocation has nothing to do with the size of the file. This is how a file too large to read into a mutant value is still looked up in a hash set. md5 and sha1 are offered because published hash sets are keyed on them, not as security properties. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and the digest covers only the recoverable prefix, so it will not match a hash set entry for the intact file -- which is the honest answer rather than a defect. Returns (result, err).", returns: pairRet("the digest of the file as it lies in the image, and how many bytes went into it", ParamHash).withFields("algorithm", "bytes_hashed", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString), param("algorithm", "One of md5, sha1 or sha256. An empty string means sha256.", ParamString)}},
	BuiltinNameHfsReadFileAt:     {signature: "hfs_read_file_at(handle, path, offset, length)", summary: "Reads one window of a file inside an opened HFS+ image and returns it as a BYTES buffer, so the head of a file far larger than memory is still reachable. length is capped at 32 MiB, which is what the returned value has to fit into; use hfs_extract_file for the whole of a larger file. An offset at or past the file's recorded size returns an empty buffer, which is how a caller walks off the end. An offset inside the recorded size but past the bytes the library could locate is an error naming both numbers: that is content the volume says exists and the image cannot produce, and a short buffer or a run of zeroes would hide it. The result is short rather than padded when the window runs past what was located. Returns (bytes, err).", returns: pairRet("the bytes in that window, short rather than padded where it runs past the file", ParamBytes), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString), param("offset", "Byte offset within the file to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameHfsMetadata:       {signature: "hfs_metadata(handle, path)", summary: "Returns metadata for a path in an opened HFS+ image, including created_at/modified_at/accessed_at/changed_at/backup_at, time_source (HFS+ GMT vs classic-HFS local wall clock), compressed, compression_type and resource_fork_size.", returns: pairRet("metadata for a path in an opened HFS+ image, including created_at/modified_at/accessed_at/changed_at/backup_at, time_source (HFS+ GMT vs classic-HFS local wall clock), compressed, compression_type and resource_fork_size", ParamHash).withFields("accessed_at", "backup_at", "block_size", "changed_at", "cnid", "compressed", "compression_type", "created_at", "file_count", "folder_count", "free_blocks", "is_dir", "kind", "modified_at", "name", "path", "resource_fork_size", "size", "time_source", "total_blocks"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString)}},
	BuiltinNameHfsVerify:         {signature: "hfs_verify(handle)", summary: "Reports what an HFS+ volume can be asked, which is less than the other five filesystems. The format records no checksum over metadata or data, so the checksum check is permanently unavailable and no tool can make it otherwise -- an integrity claim about an HFS+ volume has to rest on the image's own digests, which is what ewf_verify checks, rather than on the filesystem. What is checked here is structural: whether each b-tree the volume header names has a header that parses, since a header that does not means the tree beneath it is unreachable. Alongside that are the anomalies libhfs recorded while parsing on this handle, which accumulate as a side effect of whatever was read, so an empty list can mean little was read rather than that nothing was wrong. Every check reports `checked` beside `passed`, because a check that never ran says nothing about the volume and one boolean cannot tell \"intact\" from \"nothing to compare against\"; `examined` is the denominator it covered. `verified` is true only when at least one check actually ran and every check that ran passed, so a volume with nothing checkable is never verified -- checks_run is what tells that apart from a failure. `scope` states what the checks did not reach. Returns (result, err).", returns: pairRet("what this volume could be checked for, and what came of each check", ParamHash).withFields("checks", "checks_failed", "checks_passed", "checks_run", "checks_unavailable", "filesystem", "finding_count", "findings", "findings_truncated", "handle", "scope", "status", "verified"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString)}},
	BuiltinNameHfsDeleted:        {signature: "hfs_deleted(handle)", summary: "Reports HFS+ catalog records recovered from space the volume no longer treats as live: the free tail inside live B-tree nodes, nodes the tree marks free, and catalog nodes carved out of unallocated blocks. All three sources run. The third reads a large part of the image and libhfs leaves it off by default for that reason, but a scan that quietly skipped a source would report the same empty list as one that found nothing. Records still live in the catalog are excluded: a B-tree insert shifts records within a node and leaves the previous bytes behind it, so a live file record routinely appears in slack, and reporting one as a deletion would say a file was removed when it never was. The extent list on a recovered record is the eight inline descriptors only -- libhfs does not consult the extents overflow tree for a deleted record -- so a fragmented file reports located_bytes short of size, and that difference is map that was never read rather than content that is missing. entry_offset is image-absolute only for records carved from unallocated space; the two node-based sources measure from the node instead, and rather than hand back an offset that would seek to unrelated bytes those entries report -1. Returns (result, err).", returns: pairRet("what this volume still remembers about files it no longer lists", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "examined", "filesystem", "handle", "incomplete_reason", "scope", "sources", "sources_unavailable", "status", "unreadable", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString)}},
	BuiltinNameHfsCapabilities:   {signature: "hfs_capabilities(handle)", summary: "Reports what this HFS volume's kind can record. Nine capabilities, every one of them volume state, because \"HFS\" names three formats -- classic HFS, HFS+ and HFSX -- and libhfs decides which it opened before answering anything: classic HFS returns two answers and nothing else, HFS+ reads the attributes file and the journal bit off the volume header, and HFSX reads the catalog B-tree header to learn whether its names compare case-sensitively. This is the shortest set of the six: ten of the eighteen questions asked of every filesystem here go unanswered, creation and modification times among them. HFS has recorded both since 1985, so read that silence as a gap in what libhfs declares rather than as an absence on the volume -- hfs_metadata reports the dates themselves. Every capability reports two bits, not one: a name appears in `capabilities` only where the library declares it, and the questions it does not answer are listed in `unanswered` rather than rendered false -- a missing field and a recorded no are different facts and only one of them is evidence. `source` says whether an answer is a constant of the format or was read from this volume, which is what decides whether it may be cached across volumes; `volume_specific` is that list. Nothing here describes the contents: a true access_times says the record has the field, not that any timestamp on this volume was maintained. Reads no disk. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString)}, returns: pairRet("what this filesystem can record, which questions its reader does not answer, and which answers came from this volume", ParamHash).withFields("answered", "capabilities", "capability_count", "complete", "core_questions", "filesystem", "handle", "incomplete_reason", "scope", "status", "supported", "unanswered", "unanswered_count", "unsupported", "volume_specific")},
	BuiltinNameHfsReport:         {signature: "hfs_report(handle)", summary: "Walks the whole catalog once and returns libhfs's own versioned document: every record on the volume, the filesystem's own metadata included, with no bound on the listing -- a bound would make file_count the cap rather than the number of records the volume holds. This is the one of the six with no per-file layout: libhfs's report carries catalog records and paths and no extents, so fragments_available is false rather than every row claiming a file with no data. metadata_changed is the HFS+ attribute-modification date, which is the field that moves when a record's metadata changes and so is this format's ctime. On a classic HFS volume the stored times are local wall clock with no recorded offset and are read as UTC because there is nothing else to read them as -- each row's time_source says which kind it is, and comparing across the two compares different clocks. The volume's block counts are its header's own claim rather than a count of the allocation bitmap, and a disagreement between the two is itself a finding. One row per entry in the shape all six *_report builtins share: path, name, type, size, the deleted and fragmented bits, an identity and a parent identity, the four times that mean the same thing on every format, the layout the fragments were derived from, and image-absolute fragments whose offsets are -1 with `located` false wherever a run has no place in the image. Everything this format records that the others do not travels verbatim in each row's `extra`, so normalising loses nothing. `identity_kind` names the addressing and `identity_stable` says whether it survives the slot being reused, read from the same Capabilities *_capabilities reports and carrying `identity_stable_answered` because not every library declares it. `completeness_checked` says whether anything reconciled this listing against the filesystem's own record of what exists; `completeness_proven` means nothing without it. The library's own schema_version, library_version and generated stamp travel with the document. Reads the whole volume, so it costs O(volume) in time and holds its listing in memory rather than streaming it; the listing is capped at 50000 rows with every count beside it honest past the cap. events_from(report, \"fs_report\") turns it into a supertimeline. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString)}, returns: pairRet("one document describing this volume and every entry the walk reached", ParamHash).withFields("anomalies", "anomalies_available", "anomalies_truncated", "anomaly_count", "complete", "completeness_checked", "completeness_proven", "deleted_count", "directory_count", "end_offset", "file_count", "files", "files_truncated", "filesystem", "fragmented_count", "fragments_available", "generated", "handle", "identity_kind", "identity_stable", "identity_stable_answered", "incomplete_reason", "library_version", "name", "schema_version", "scope", "start_offset", "status", "volume", "warning_codes", "warnings", "warnings_available")},
	BuiltinNameHfsClose:          {signature: "hfs_close(handle)", summary: "Closes an HFS+ handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString)}},
	BuiltinNameXfsOpen:           {signature: "xfs_open(image, offset?, length?)", summary: "Opens an XFS filesystem image and returns a handle. Returns (result, err). A volume that sits inside a larger image is opened where it lies rather than carved out first: pass the partition hash from table_list_partitions, or an explicit byte offset with an optional length. Every byte offset this handle goes on to report then already includes that start, so it addresses the image file itself and can be compared with a range from the table_ family without adding anything -- adding it twice, or comparing a partition-relative offset against a whole-disk one, mislocates evidence without failing. `bounded` is false when no length was given, which means reads can run past this volume's end into whatever follows it on the disk.", params: []builtinParamDoc{param("image", "Path to an XFS image/partition, or to the whole disk the volume sits in.", ParamString), param("offset?", "Byte offset at which the volume begins, or a partition hash from table_list_partitions / table_partition_info. Omit when the image is the volume.", ParamInt, ParamHash), param("length?", "Bytes the volume occupies, so reads cannot run past its end. Omit to read to the end of the image. Not accepted alongside a partition hash, which already carries its length.", ParamInt)}, returns: pairRet("a handle for the other xfs_ builtins; release it with xfs_close", ParamHash).withFields("bounded", "handle", "path", "status", "volume_length", "volume_offset")},
	BuiltinNameXfsListFiles:      {signature: "xfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened XFS image, with file_type from the directory record. A damaged inode no longer aborts the listing: that entry is reported with inode_error set and size 0.", returns: pairRet("one hash per directory entry", ParamArray).ofElem(ParamHash).withFields("file_type", "inode", "inode_error", "is_dir", "name", "path", "size"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameXfsReadFileBytes:  {signature: "xfs_read_file_bytes(handle, path)", summary: "Reads a file from an opened XFS image as a BYTES buffer. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: xfs_extract_file streams the file to disk instead, xfs_hash_file digests it in place, and xfs_read_file_at returns one window of it.", params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString)}, returns: pairRet("the file's bytes", ParamBytes)},
	BuiltinNameXfsReadFile:       {signature: "xfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened XFS image. It allocates for the file's whole length before reading a byte of it, so it is bounded by what a library will read into memory: xfs_extract_file streams the file to disk instead, xfs_hash_file digests it in place, and xfs_read_file_at returns one window of it.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString)}},
	BuiltinNameXfsExtractFile:    {signature: "xfs_extract_file(handle, path, dest)", summary: "Streams a file out of an opened XFS image and writes it to dest, never holding the whole of it in memory -- which is what makes a file larger than a mutant value, or larger than RAM, extractable at all. The SHA-256 of what was written is computed in the same pass, so nothing has to read the extracted copy back to obtain one. dest must not already exist: two files in an image can share a name, and evidence written over by accident is not recoverable. A copy that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and what was written is the recoverable prefix rather than the file -- so read `truncated` before treating `digest` as the file's digest. Returns (result, err).", returns: pairRet("where the file was written, how much of it was written, and the digest of what was written", ParamHash).withFields("algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameXfsHashFile:       {signature: "xfs_hash_file(handle, path, algorithm)", summary: "Digests a file inside an opened XFS image without writing a copy of it anywhere, reading it in fixed chunks so the peak allocation has nothing to do with the size of the file. This is how a file too large to read into a mutant value is still looked up in a hash set. md5 and sha1 are offered because published hash sets are keyed on them, not as security properties. `size` is the length the volume records and `located_bytes` is how much of it the library could actually find. The two differ on a FAT or exFAT entry whose cluster chain was broken when the file was deleted: the entry still records the original length and only a prefix of it leads anywhere. When they differ `truncated` is true and the digest covers only the recoverable prefix, so it will not match a hash set entry for the intact file -- which is the honest answer rather than a defect. Returns (result, err).", returns: pairRet("the digest of the file as it lies in the image, and how many bytes went into it", ParamHash).withFields("algorithm", "bytes_hashed", "digest", "located_bytes", "path", "size", "truncated"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString), param("algorithm", "One of md5, sha1 or sha256. An empty string means sha256.", ParamString)}},
	BuiltinNameXfsReadFileAt:     {signature: "xfs_read_file_at(handle, path, offset, length)", summary: "Reads one window of a file inside an opened XFS image and returns it as a BYTES buffer, so the head of a file far larger than memory is still reachable. length is capped at 32 MiB, which is what the returned value has to fit into; use xfs_extract_file for the whole of a larger file. An offset at or past the file's recorded size returns an empty buffer, which is how a caller walks off the end. An offset inside the recorded size but past the bytes the library could locate is an error naming both numbers: that is content the volume says exists and the image cannot produce, and a short buffer or a run of zeroes would hide it. The result is short rather than padded when the window runs past what was located. Returns (bytes, err).", returns: pairRet("the bytes in that window, short rather than padded where it runs past the file", ParamBytes), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString), param("offset", "Byte offset within the file to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameXfsMetadata:       {signature: "xfs_metadata(handle, path)", summary: "Returns metadata for a path in an opened XFS image, including created_at/modified_at/accessed_at/changed_at and needs_repair (the filesystem was left inconsistent and its metadata should be treated with suspicion).", returns: pairRet("metadata for a path in an opened XFS image, including created_at/modified_at/accessed_at/changed_at and needs_repair (the filesystem was left inconsistent and its metadata should be treated with suspicion)", ParamHash).withFields("accessed_at", "block_size", "changed_at", "created_at", "format_version", "inode", "inode_size", "is_dir", "modified_at", "name", "needs_repair", "path", "root_inode", "size", "volume_blocks"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString)}},
	BuiltinNameXfsVerify:         {signature: "xfs_verify(handle)", summary: "Checks the XFS superblock's stored CRC32c against the bytes on the volume, and whether the filesystem is marked as needing repair. XFS records metadata CRCs only from v5 onward, so a v4 image reports the CRC check unavailable rather than failed -- superblock_crc_valid would read false on every v4 volume whatever its state, which is why the checked bit carries the meaning here. The needs-repair result is a flag the filesystem set about itself rather than a check of any bytes, so a pass means it never recorded being left inconsistent, not that it is consistent. Anomalies libxfs raised while building the report are carried through as findings with its own severity words normalised onto the three this family uses. Every check reports `checked` beside `passed`, because a check that never ran says nothing about the volume and one boolean cannot tell \"intact\" from \"nothing to compare against\"; `examined` is the denominator it covered. `verified` is true only when at least one check actually ran and every check that ran passed, so a volume with nothing checkable is never verified -- checks_run is what tells that apart from a failure. `scope` states what the checks did not reach. Returns (result, err).", returns: pairRet("what this volume could be checked for, and what came of each check", ParamHash).withFields("checks", "checks_failed", "checks_passed", "checks_run", "checks_unavailable", "filesystem", "finding_count", "findings", "findings_truncated", "handle", "scope", "status", "verified"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}},
	BuiltinNameXfsDeleted:        {signature: "xfs_deleted(handle, path)", summary: "Reports the free slots and carved candidates in one XFS directory data blocks. It takes a path where the other five take only a handle, because libxfs offers no volume-wide sweep and scanning the root instead would be a claim about every directory made from evidence about one. Content is not recoverable through this route and every entry says so with content_state unsupported: XFS clears di_mode when it frees an inode and libxfs refuses to open an unallocated one, with no raw escape hatch, so names come back and bytes do not. xfs_unlinked is the one place XFS yields deleted content. Best-effort parsing is on, so a malformed block is resynchronised past and recorded as an anomaly instead of ending the scan. Short-form directories -- small ones stored inline in the inode -- carry no deleted-entry recovery whatever, and a scan of one reports complete false with the reason rather than an empty list. Truncation is read from the listing rather than from an error, because a cap the caller set returns no error at all. Each entry carries the libxfs confidence grade and the reasons behind it. Returns (result, err).", returns: pairRet("what this directory still remembers about entries it no longer lists", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "examined", "filesystem", "handle", "incomplete_reason", "scope", "sources", "sources_unavailable", "status", "unreadable", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Directory to scan, as an absolute path within the volume.", ParamString)}},
	BuiltinNameXfsUnlinked:       {signature: "xfs_unlinked(handle)", summary: "Follows the allocation groups unlinked inode buckets and reports the inodes on them. This is the only evidence in any of the six filesystems that the filesystem itself asserts rather than something inferred from surviving bytes: an inode reaches a bucket because it was unlinked while a process still held it open, and until that process closes it the inode stays allocated, keeps its generation number and stays fully readable. Content is therefore genuinely recoverable here and the runs reported are live extents rather than a stale map, so entries report content_state preserved with allocation_checked true. What the chain does not carry is a name -- the directory entry is already gone, which is what unlinked means -- so name is empty and name_source is none. A zeroed bucket array is reported once as an anomaly rather than read as sixty-four empty chains. Returns (result, err).", returns: pairRet("the inodes the filesystem itself recorded as unlinked while still open", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "examined", "filesystem", "handle", "incomplete_reason", "scope", "sources", "sources_unavailable", "status", "unreadable", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}},
	BuiltinNameXfsCapabilities:   {signature: "xfs_capabilities(handle)", summary: "Reports what XFS can record, as distinct from what this volume happens to have recorded. Twenty-five capabilities, thirteen constants of the format and twelve read from this superblock, the split falling almost exactly on the v4/v5 line: creation_times and metadata_checksums are both \"is this a v5 filesystem\", and a v4 filesystem has no birth time at all. journaled is true only for an internal log, so a filesystem with an external log device reports false. needs_repair is the one entry here that is not a capability -- it is the superblock's own statement that this filesystem was not cleanly unmounted, quoted where libxfs put it. The format version libxfs also carries in that struct is not repeated here, since xfs_metadata already reports it and the same number in two places invites a reader to wonder which was read. Every capability reports two bits, not one: a name appears in `capabilities` only where the library declares it, and the questions it does not answer are listed in `unanswered` rather than rendered false -- a missing field and a recorded no are different facts and only one of them is evidence. `source` says whether an answer is a constant of the format or was read from this volume, which is what decides whether it may be cached across volumes; `volume_specific` is that list. Nothing here describes the contents: a true access_times says the record has the field, not that any timestamp on this volume was maintained. Reads no disk. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}, returns: pairRet("what this filesystem can record, which questions its reader does not answer, and which answers came from this volume", ParamHash).withFields("answered", "capabilities", "capability_count", "complete", "core_questions", "filesystem", "handle", "incomplete_reason", "scope", "status", "supported", "unanswered", "unanswered_count", "unsupported", "volume_specific")},
	BuiltinNameXfsReport:         {signature: "xfs_report(handle)", summary: "Walks the whole volume once and returns libxfs's own versioned document, with the inode reconciliation turned on. This is the only one of the six that can say its listing is complete: it walks every allocation group's inode b-tree and compares what the directory walk reached against the superblock's counters and the per-group headers -- three independently maintained sources -- and completeness_proven is libxfs's own conclusion from them. It is also what surfaces the inodes that exist and hold data but that no directory walk would ever produce: the unlinked, which are deleted but still open, and the unreferenced, both counted in the volume hash. That costs a second pass over the metadata, which is why libxfs leaves it off; the alternative is a document that cannot say what it missed. Verification is best-effort, so a checksum mismatch is recorded as an anomaly and the walk continues. Carved directory records are not here; xfs_deleted reports those per directory, graded. One row per entry in the shape all six *_report builtins share: path, name, type, size, the deleted and fragmented bits, an identity and a parent identity, the four times that mean the same thing on every format, the layout the fragments were derived from, and image-absolute fragments whose offsets are -1 with `located` false wherever a run has no place in the image. Everything this format records that the others do not travels verbatim in each row's `extra`, so normalising loses nothing. `identity_kind` names the addressing and `identity_stable` says whether it survives the slot being reused, read from the same Capabilities *_capabilities reports and carrying `identity_stable_answered` because not every library declares it. `completeness_checked` says whether anything reconciled this listing against the filesystem's own record of what exists; `completeness_proven` means nothing without it. The library's own schema_version, library_version and generated stamp travel with the document. Reads the whole volume, so it costs O(volume) in time and holds its listing in memory rather than streaming it; the listing is capped at 50000 rows with every count beside it honest past the cap. events_from(report, \"fs_report\") turns it into a supertimeline. Returns (result, err).", params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}, returns: pairRet("one document describing this volume and every entry the walk reached", ParamHash).withFields("anomalies", "anomalies_available", "anomalies_truncated", "anomaly_count", "complete", "completeness_checked", "completeness_proven", "deleted_count", "directory_count", "end_offset", "file_count", "files", "files_truncated", "filesystem", "fragmented_count", "fragments_available", "generated", "handle", "identity_kind", "identity_stable", "identity_stable_answered", "incomplete_reason", "library_version", "name", "schema_version", "scope", "start_offset", "status", "volume", "warning_codes", "warnings", "warnings_available")},
	BuiltinNameXfsClose:          {signature: "xfs_close(handle)", summary: "Closes an XFS handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}},

	// recovering a deleted entry's content: the *_deleted family's other
	// half. Each takes an entry's index in the most recent scan on that
	// handle, because no identifier these six filesystems keep survives
	// deletion uniquely -- a CNID repeats across carved records and a freed
	// first cluster is shared the moment it is reused.
	BuiltinNameNtfsRecoverFile:       {signature: "ntfs_recover_file(handle, index, dest)", summary: "Writes out the content of an entry ntfs_deleted reported. NTFS leaves the run list of a deleted file in place, so this is the one filesystem of the six whose recovery reads the map the filesystem itself wrote rather than a remnant or a guess. A resident value is taken from the parsed MFT record and never re-read from the image: an MFT record carries update-sequence fixups, so the last two bytes of each sector hold the record's sequence number and a resident value crossing a sector boundary read off the disk is quietly two bytes wrong. A compressed or EFS-encrypted $DATA attribute is refused rather than written, because its runs describe compression units or ciphertext and not the file's bytes. allocation_checked comes back false on every entry -- libntfs has no cluster-allocation query -- so reallocated false here means nobody looked. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("index", "The entry's index field, from the most recent  ntfs_deleted on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameFatRecoverFile:        {signature: "fat_recover_file(handle, index, dest)", summary: "Writes out what is locatable of an entry fat_deleted reported. Deletion frees the cluster chain, so for all but a resident-free contiguous case only the first cluster is known and the rest of the FAT now describes whatever was written to those clusters next. What gets written is therefore usually one cluster and `complete` is false; fat_recover_file_assuming_contiguous is the builtin that goes further, and it is a separate one because going further is a hypothesis. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("index", "The entry's index field, from the most recent  fat_deleted on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameFatRecoverContiguous:  {signature: "fat_recover_file_assuming_contiguous(handle, index, dest)", summary: "Recovers a deleted FAT entry as though the clusters after its first one followed it in order. libfat synthesises ceil(size/cluster) clusters from the first and sets its own Assumed flag; `assumed` reports that flag rather than the fact that this builtin was called, so an entry whose chain turned out to be walkable comes back assumed false and identical to fat_recover_file. When `assumed` is true nothing in the filesystem connects these bytes to this file beyond their position, and the assumption is unfalsifiable from inside the volume because the evidence that would test it is the chain deletion freed. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("index", "The entry's index field, from the most recent  fat_deleted on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameXfatRecoverFile:       {signature: "xfat_recover_file(handle, index, dest)", summary: "Writes out what is locatable of an entry xfat_deleted reported. exFAT is the one format here that can report a deleted file's whole layout as a fact: a stream extension that recorded NoFatChain declared the run contiguous while the file was live, and freeing the chain took nothing away, so those entries recover in full with content_state declared_contiguous. Everything else yields the first cluster alone. An entry past its valid-data length carries a caveat: those bytes were allocated to this file and never written by it. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("index", "The entry's index field, from the most recent  xfat_deleted on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameXfatRecoverContiguous: {signature: "xfat_recover_file_assuming_contiguous(handle, index, dest)", summary: "Recovers a deleted exFAT entry as though the clusters after its first one followed it in order, the way fat_recover_file_assuming_contiguous does. An entry that recorded NoFatChain needs no hypothesis -- the volume already stated the layout -- and for those this reports assumed false and returns the same bytes as xfat_recover_file. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("index", "The entry's index field, from the most recent  xfat_deleted on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameExtRecoverFile:        {signature: "ext_recover_file(handle, index, dest)", summary: "Writes out the blocks a deleted ext inode still points at. ext4 zeroes the extent tree on unlink, so most entries report content_state none and are refused here rather than written as an empty file; the ones that survive are ext3-era inodes and files unlinked while still open. The runs come from libext's own DataRuns, because Extent.PhysicalBlock is volume-relative and only that call adds the base offset -- doing the multiplication anywhere else produces a partition-relative offset that looks exactly like an absolute one. A confidence of partial means either that a block has been reallocated or that the block bitmap could not be read, and libext does not distinguish them. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("index", "The entry's index field, from the most recent  ext_deleted on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameHfsRecoverFile:        {signature: "hfs_recover_file(handle, index, dest)", summary: "Writes out the extents of a catalog record hfs_deleted carved out of node slack, a free node or unallocated space. Only the eight extents held in the record itself are used -- anything that overflowed into the extents B-tree is not among them -- and libhfs clamps a corrupt recorded size to what those extents can actually hold, so a short `bytes_written` against `size` is the normal shape of a partial record rather than an error. An entry the library marked overwritten is still written, because refusing would deny an examiner data they may need, but reallocated is true and the caveat says the bytes are most likely a live file's. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("index", "The entry's index field, from the most recent  hfs_deleted on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameXfsRecoverFile:        {signature: "xfs_recover_file(handle, index, dest)", summary: "Writes out an inode from an allocation group's unlinked chain, as xfs_unlinked reported it. This is the only XFS recovery there is and it is the only one in the whole family that is not inference: an inode reaches an unlinked bucket because the filesystem put it there when a file was unlinked while still open, and it is still allocated and still fully readable, so the ordinary inode reader is both available and correct. An entry from xfs_deleted, whose evidence is a directory record and whose inode has had di_mode cleared, reports content_state unsupported and is refused. dest must not already exist: two deleted entries in one image can carry the same name, and evidence written over by accident is not recoverable. A write that fails part way has its partial output removed, because a prefix left under the name of the whole file reads as the whole file. `bytes_written` is split three ways and the split is the finding: `located_bytes` were read from the image, `sparse_bytes` are a hole the filesystem recorded and so are the file's own content, and `unlocated_bytes` are zeros standing in for ranges the library could not place -- never evidence that the file held zeros there. `caveats` states in prose what this recovery does not establish, and a report that quotes the digest without it is quoting a number out of its scope. Returns (result, err).", returns: pairRet("where the recovered bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "index", "is_directory", "located_bytes", "name", "name_source", "path", "record_id", "reallocated", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("index", "The entry's index field, from the most recent  xfs_unlinked on this handle.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},

	// the journals — three subsystems, and the only structure in any of
	// these formats that records the past rather than the present. All
	// three are circular, so `ordering` says whether the entries array is
	// a timeline and `wrap_checked`/`wrapped` say whether the walk crossed
	// the seam where the region was written round. `timestamps_available`
	// is per journal and not per format: USN and JBD2 carry a clock,
	// $LogFile and XLOG carry none at all.
	BuiltinNameNtfsUsnJournal:        {signature: "ntfs_usn_journal(handle)", summary: "Reports the USN change journal, the richest timeline artifact on an NTFS volume: every record carries a wall-clock timestamp, the changed file's MFT reference and sequence number, its parent's, a decoded reason bitmask and, on version 2 and 3 records, the filename. $J is a sparse stream appended to and trimmed from the front rather than overwritten in place, so stream order is the order the changes happened in and `wrapped` is false as a property of the format rather than as a measurement; `lowest_position` and `highest_position` bound the surviving window in USN, which is itself a byte offset into the stream. Version 4 records track extents and carry neither a timestamp nor a name, so they report has_timestamp and has_name false instead of a year-1 date and an empty string that would read as a file with no name. What this cannot see is a journal deleted and recreated -- a classic anti-forensic action -- because the $Max stream holding the journal's identifier, maximum size and lowest valid USN is one libntfs never reads, so a wiped journal looks like a volume with a short history. A record that will not parse is skipped in silence and counted nowhere, and a read error partway through ends the walk with no error at all: warnings_available is false because libntfs has no channel to report either. `present` distinguishes a volume with no change journal from a journal with no records. Returns (result, err).", returns: pairRet("the change journal's surviving records, the window they cover, and what the walk could not see", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "filesystem", "handle", "highest_position", "incomplete_reason", "journal", "journal_bytes", "journal_offset", "lowest_position", "ordering", "present", "scope", "status", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameNtfsLogRecords:        {signature: "ntfs_log_records(handle)", summary: "Reports the $LogFile record stream: the metadata operations NTFS journals so it can replay or undo them after a crash, each with its LSN, its redo and undo operation names, and the clusters it touched. Records come back in the order their pages sit in the file, which is the order they were written only until the log was written round, so `ordering` is physical and `wrapped` reports whether the LSNs go backwards anywhere in it -- where they do, this array is not a timeline and ntfs_log_transactions, which is ordered by LSN, is the one to read. target_attribute is an offset into the open attribute table rather than an attribute: the table is dumped into the log periodically, and where a dump survives target_attribute_type, target_attribute_name and target_record resolve the operation to the stream and the MFT record it touched. Where the log has been written round past the last dump the table comes back empty rather than as an error, attribute_table_entries is zero, and every record's target stays unresolved. $LogFile carries no wall-clock time anywhere, so an ordering by LSN is the only chronology it can support. restart.open_count is a rough count of the times the volume has been mounted. A page whose update-sequence fixups fail is dropped whole, along with the partial record carried into it, with no counter and no error -- and a fixup failure is a torn write, so the pages most worth seeing are the ones that vanish without trace. Returns (result, err).", returns: pairRet("the log's operation records, the geometry that bounds them, and what could not be resolved", ParamHash).withFields("attribute_table_available", "attribute_table_entries", "complete", "entries", "entries_truncated", "entry_count", "filesystem", "handle", "highest_position", "incomplete_reason", "journal", "journal_bytes", "journal_offset", "lowest_position", "ordering", "present", "restart", "scope", "status", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameNtfsLogTransactions:   {signature: "ntfs_log_transactions(handle)", summary: "Groups the $LogFile records into the transactions they belong to, ordered by the LSN each began at. TransactionID is a slot in NTFS's small transaction table and not an identifier -- the same ID belongs to thousands of unrelated transactions over the life of a log -- so a transaction is closed here when its end record appears and the next record carrying that ID starts a new one, which is what keeps this from collapsing a whole log into a handful of pseudo-transactions. `committed` and `forgotten` are two bits and neither is the negation of the other: NTFS ends almost every transaction with ForgetTransaction rather than CommitTransaction, so a log holding tens of thousands of records may contain no commit record at all and committed false across a whole volume is the normal reading rather than evidence that nothing completed. end_state names which of the two was seen. `start_present` reports whether a transaction's earliest surviving record is one that names no previous record of its own -- where it is false the beginning was overwritten by the wrap and first_lsn is merely the oldest surviving part, which the grouping otherwise presents as the beginning. The log carries no wall-clock time, so this is an ordering and not a timeline. Returns (result, err).", returns: pairRet("the transactions the log recorded, how each ended, and which of them are missing their beginning", ParamHash).withFields("attribute_table_available", "attribute_table_entries", "complete", "entries", "entries_truncated", "entry_count", "filesystem", "handle", "highest_position", "incomplete_reason", "journal", "journal_bytes", "journal_offset", "lowest_position", "ordering", "present", "restart", "scope", "status", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameExtJournal:            {signature: "ext_journal(handle)", summary: "Reports the JBD2 journal's transactions, its own superblock and its feature bits. JBD2 journals whole blocks rather than operations, so each descriptor transaction names the filesystem blocks it carries copies of and each commit block carries the time it committed -- a transaction that never committed has no commit block and therefore no time, which has_timestamp says rather than a zero date. The journal is circular and libext reads it linearly from the first block to the last, parsing the superblock's Start and Sequence and then using neither, so where the log has been written round the transactions come back in physical order with stale pre-wrap ones interleaved among new ones; `wrapped` reports whether the sequence numbers go backwards anywhere in that order. Where it is true, `committed` must not be read as a finding: a transaction whose commit block sits at a lower physical block than its descriptor has the commit processed first, matched against nothing and discarded, so one that did commit is reported as one that never did, and this builtin raises commit_state_unreliable to say so. Revoke records are identified and not parsed -- they carry no tags and a block count of zero -- and a revoke is precisely the statement that a journalled copy must not be replayed. No checksum is verified anywhere in this journal. `external` separates a filesystem whose journal is on another device, which is fully journalled with the evidence elsewhere, from one with no journal at all; libext's own status string calls both of them the same thing. Returns (result, err).", returns: pairRet("the journal's transactions, its superblock and features, and why its ordering may not be chronological", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "external", "features", "filesystem", "handle", "highest_position", "incomplete_reason", "journal", "journal_bytes", "journal_inode", "journal_offset", "lowest_position", "ordering", "present", "scope", "status", "status_text", "superblock", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString)}},
	BuiltinNameExtJournalBlockCopies: {signature: "ext_journal_block_copies(handle, fs_block)", summary: "Returns every journalled copy of one filesystem block, each being that block's contents at the moment a transaction was written, with its sha256 and its bytes. This is how a prior state of metadata the live filesystem has since overwritten is recovered -- a group descriptor, a bitmap, a directory block, an inode table block. libext documents the copies as newest first and that holds only while the journal has not been written round, so this walks the journal a second time purely to establish `wrapped`: a prior state quoted as the state immediately before an event is a claim about time, and where the seam is present the ordering it rests on is one the library declined to make. Copies are not checked against revoke records, which libext identifies and does not parse, so a copy here may be one the filesystem had already declared must not be replayed. A tag naming block zero yields a zero-filled buffer with no error, so an all-zero copy is as likely to be a block that was never read as a block that was zeroed. At most 256 copies are returned because each carries a whole filesystem block; entry_count keeps counting past that. Returns (result, err).", returns: pairRet("the journalled copies of one block, their digests and bytes, and whether their order is chronological", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "external", "features", "filesystem", "fs_block", "handle", "highest_position", "incomplete_reason", "journal", "journal_bytes", "journal_inode", "journal_offset", "lowest_position", "ordering", "present", "scope", "status", "status_text", "superblock", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("fs_block", "Filesystem block number to look for copies of.", ParamInt)}},
	BuiltinNameExtInodeVersions:      {signature: "ext_journal_inode_versions(handle, inode)", summary: "Recovers prior on-disk states of one inode from journalled copies of the inode-table block that holds it. This is the one path in this package that can locate an ext4 file the filesystem itself can no longer locate: unlink zeroes the extent tree in the live inode and leaves everything else, which is why the usual deleted ext4 file comes back from ext_deleted fully described and entirely unfindable with content_state none -- and a journalled copy of the same block from before the unlink still carries the tree. Each version reports content_state in the same vocabulary the *_deleted family uses and `runs` as image-absolute byte ranges, so a version reporting preserved can be read with raw_read_at_bytes or written out with ext_recover_journalled_file. The ordering is libext's, newest first only while the journal has not been written round, so version 0 is the most recent surviving copy and not necessarily the state just before the deletion; `wrapped` is checked with a second journal walk for exactly that reason. deleted_at_raw is carried beside deleted_at because ext4 reuses the deletion-time field to hold the next inode number while an inode sits on the legacy orphan list, and that value read as a date is a timestamp somewhere in 1970. Returns (result, err).", returns: pairRet("the prior states of one inode, the byte map each recorded, and whether their order is chronological", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "external", "features", "filesystem", "handle", "highest_position", "incomplete_reason", "inode", "journal", "journal_bytes", "journal_inode", "journal_offset", "lowest_position", "ordering", "present", "scope", "status", "status_text", "superblock", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("inode", "Inode number to recover prior states of.", ParamInt)}},
	BuiltinNameExtRecoverJournalled:  {signature: "ext_recover_journalled_file(handle, inode, version, dest)", summary: "Writes out the blocks a journalled version of an inode points at -- the extent tree ext4's unlink zeroed, read back out of the journal and followed. It takes an inode number and a version index rather than a scan index, because unlike a deleted directory entry this subject has an identifier that survives: the inode number is the inode number, and the version list for it is derived the same way on every call over the same image. What the version index is not is a date, and the result echoes it for that reason -- where the journal has wrapped, libext's newest-first ordering is not newest first, which ext_journal_inode_versions reports. A version recording inline data is refused rather than written empty, because libext reads inline content only through a live inode; a version whose extent tree is already zeroed is refused with the note that an earlier version is where the tree would be. dest must not already exist, and a write that fails part way has its partial output removed. `bytes_written` splits into located_bytes read from the image, sparse_bytes where a recorded hole means the zeros are the content, and unlocated_bytes written only so later offsets land. The standing caveat is that the filesystem reallocated those blocks freely after the unlink and nothing here checks whether they still hold this file's content. Returns (result, err).", returns: pairRet("where the journalled version's bytes were written, how much of the output came from where, and what the recovery does not establish", ParamHash).withFields("algorithm", "allocation_checked", "assumed", "bytes_written", "caveats", "confidence", "content_state", "dest", "digest", "handle", "id_kind", "inode", "is_directory", "located_bytes", "name", "name_source", "path", "reallocated", "record_id", "runs", "size", "size_matched", "sparse_bytes", "status", "unlocated_bytes", "version"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("inode", "Inode number to recover.", ParamInt), param("version", "Index into ext_journal_inode_versions for this inode. Not a date.", ParamInt), param("dest", "Local path to write to. Must not already exist.", ParamString)}},
	BuiltinNameXfsLogRecords:         {signature: "xfs_log_records(handle)", summary: "Reports the XFS log's records, sorted by log sequence number. An LSN is a cycle and a block and the cycle is the number of times the log has been written round, so ordering by it is exact and `wrapped` here reports a fact about the log rather than a hazard in the ordering -- this is the one journal of the three whose own format settles the question. cleared_blocks counts basic blocks holding a cleared record stamp, the well-formed zero-cycle header mkfs.xfs writes across the whole log, which is the difference between a log that has been quiet and one whose records have been overwritten; neither sibling library has anything comparable. checksum_checked and checksum_valid are two bits, and checked is false for four different reasons -- a v4 image, a stored CRC of zero, checksums skipped, or a header shorter than 328 bytes -- so valid means nothing unless checked is true. has_unmount_record false says the image was taken from a running or a crashed system. This goes through libxfs's options form deliberately: the plain call returns only the slice and discards the truncation flag, the cleared-block count, the offsets and every anomaly, so a scan that stopped at a block limit or after eight unreadable blocks would come back looking complete with a nil error. There is no wall-clock time anywhere in an XFS log: it can say what happened and in what order, and can never say when. Returns (result, err).", returns: pairRet("the log's records in sequence order, how much of the log was never written, and what the scan could not read", ParamHash).withFields("cleared_blocks", "complete", "entries", "entries_truncated", "entry_count", "filesystem", "handle", "has_unmount_record", "highest_position", "incomplete_reason", "journal", "journal_bytes", "journal_offset", "lowest_position", "ordering", "present", "scope", "status", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}},
	BuiltinNameXfsLogTransactions:    {signature: "xfs_log_transactions(handle)", summary: "Groups the XFS log's operations into transactions, ordered by the LSN each started at, with the buffers and inodes each touched. item_count is what the transaction header claimed and items_recovered is how many were actually rebuilt: libxfs stops at 65536 items in one transaction without raising an anomaly, so the two numbers disagreeing is the only sign of it. `committed` reports that a commit region was found, and a transaction without one was in flight when the image was captured and never reached the filesystem, which makes it evidence of intent rather than of change -- the strongest thing any of these three journals can say. A LOG_TRANSACTION_RESTARTED anomaly is graded low by libxfs and means a transaction was discarded rather than noted: XFS reuses transaction identifiers aggressively and a second start for a live one replaces the builder, so this builtin raises transaction_replaced beside it. Transactions whose start region was overwritten by the wrap are dropped silently, which makes this a lower bound on what the log recorded. An item's offset is -1 where libxfs reported both ends as zero, because that means the block number was negative rather than that the buffer sits at offset zero, which is the superblock. There is no wall-clock time anywhere in an XFS log. Returns (result, err).", returns: pairRet("the transactions the log recorded, which of them committed, and how many of their items survived", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "filesystem", "handle", "has_unmount_record", "highest_position", "incomplete_reason", "journal", "journal_bytes", "journal_offset", "lowest_position", "ordering", "present", "record_count", "scope", "status", "timestamps_available", "warning_codes", "warnings", "warnings_available", "wrap_checked", "wrapped"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}},

	// slack and unwritten ranges -- the bytes inside a file's allocation
	// that the file never put there. Two classes and they are not one
	// thing: file_slack lies past the recorded size, unwritten lies inside
	// it and was never written. Only four of the six formats record the
	// second boundary at all. classes_unavailable says what the library
	// cannot report for the format; file_slack_checked and
	// unwritten_checked say whether this file got an answer.
	BuiltinNameNtfsSlack:      {signature: "ntfs_slack(handle, path)", summary: "Reports the bytes in an NTFS file's allocation that the file never put there, in two classes that are not the same thing. file_slack is the space between the end of the stream and the end of its last cluster -- the classic slack, and where the cluster's previous occupant survives. unwritten is the space between InitializedSize and RealSize: inside the length the volume records, allocated, readable, and never written by this file, so the filesystem hands back zeros while the clusters themselves still hold what was there before. Every range carries its class, because a valid-data-length gap quoted as slack in a report is a false statement about where the bytes came from. libntfs has no slack API of any kind, so both figures are computed from the non-resident $DATA attribute's AllocatedSize, RealSize and InitializedSize and located through its run list -- including the whole clusters past the end of the stream, which Fragments drops and a file truncated in place still owns. It is refused rather than guessed on a compressed stream, whose runs map compression units rather than stream bytes, and on a sparse one, whose allocated size is smaller than its recorded size so their difference is not a tail. A resident file's content lives inside the MFT record and owns no cluster, so it reports zero; the record's own unused space is record slack, a different artifact, as are alternate data streams. Returns (result, err).", returns: pairRet("the ranges of this file's allocation that hold no file content, and which class each is", ParamHash).withFields("allocated_bytes", "classes", "classes_unavailable", "complete", "file_slack_bytes", "file_slack_checked", "filesystem", "handle", "incomplete_reason", "is_directory", "located_bytes", "name", "path", "range_count", "ranges", "ranges_truncated", "scope", "size", "status", "unlocated_bytes", "unwritten_bytes", "unwritten_checked", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameFatSlack:       {signature: "fat_slack(handle, path)", summary: "Reports the unused tail of a FAT file's last cluster. FAT records no valid-data length, so the unwritten class is reported as unavailable on every file rather than as zero. This does not simply render libfat's SlackRange, because SlackRange returns the same empty result and false from five different situations and only one of them means the file ends on a cluster boundary: a directory, an empty file, a chain that could not be walked, a genuinely aligned file, and a tail that would fall past the end of the volume. The third is the one that matters, and a freed chain looks exactly like it, so the chain is walked here and file_slack_checked is false with file_slack_bytes at -1 when it broke, with a warning naming which way: a reallocated first cluster, a broken chain, a loop, or runs simply shorter than the recorded size. Note what this cannot reach: it addresses a live file by path, and a deleted entry cannot be opened by one, so the slack most worth having needs the scan index ext_deleted's siblings hand out and this does not take it. Directories are outside libfat's slack API altogether and are reported as unchecked rather than as empty, because directory cluster slack is where deleted short and long name records survive. Volume slack, the sectors past the last cluster, is covered by no libfat API. Returns (result, err).", returns: pairRet("the ranges of this file's allocation that hold no file content, and which class each is", ParamHash).withFields("allocated_bytes", "classes", "classes_unavailable", "complete", "file_slack_bytes", "file_slack_checked", "filesystem", "handle", "incomplete_reason", "is_directory", "located_bytes", "name", "path", "range_count", "ranges", "ranges_truncated", "scope", "size", "status", "unlocated_bytes", "unwritten_bytes", "unwritten_checked", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameXfatSlack:      {signature: "xfat_slack(handle, path)", summary: "Reports an exFAT entry's cluster tail and the part of its allocation past ValidDataLength, each range carrying which of the two it is. The unwritten region is a different byte class from slack: it lies inside the recorded size, it is allocated and readable, and it can span several runs because ValidDataLength may be zero on a large allocation -- which is why it is not a flag on the last range. Unlike its FAT sibling libxfat does report directory slack, a divergence its own documentation calls deliberate, because directory cluster slack is where deleted directory records survive. Two library behaviours are corrected here. A tail that SlackRange declines to name is diagnosed rather than rendered as zero. And UnwrittenRanges does not check whether the run walk was truncated before mapping the region, so a short walk silently reports a smaller unwritten region than exists: that case is warned on and the scan marked incomplete, which makes unwritten_bytes a lower bound rather than a total. A deleted entry the volume had recorded as contiguous keeps its layout through deletion, and libxfat would report its slack -- but this addresses an entry by path and a deleted one cannot be opened by path, so that case is not reachable here. Returns (result, err).", returns: pairRet("the ranges of this file's allocation that hold no file content, and which class each is", ParamHash).withFields("allocated_bytes", "classes", "classes_unavailable", "complete", "file_slack_bytes", "file_slack_checked", "filesystem", "handle", "incomplete_reason", "is_directory", "located_bytes", "name", "path", "range_count", "ranges", "ranges_truncated", "scope", "size", "status", "unlocated_bytes", "unwritten_bytes", "unwritten_checked", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path of the file or directory inside the volume.", ParamString)}},
	BuiltinNameExtSlack:       {signature: "ext_slack(handle, path)", summary: "Reports the blocks past the end of an ext file and the preallocated ranges inside it. libext exposes no file-slack API: Extents keeps the whole blocks an inode maps including preallocation past the end of the file, DataRuns trims the same map to the recorded size, and the slack is the difference -- so this is arithmetic on the library's own public output rather than a second copy of its block map. An extent flagged unwritten was allocated and never written to; the part of it inside the recorded size is reported as the unwritten class, and it reads back as zeros through the filesystem while the blocks themselves still hold what was there before. A file whose data is inline in its inode owns no blocks and reports zero of both. A sparse extent has no physical backing and so contributes no location. Directory-record slack -- the deleted names left in the gap a live record's rec_len was extended over -- is a different artifact with its own builtin, ext_dir_slack. Returns (result, err).", returns: pairRet("the ranges of this file's allocation that hold no file content, and which class each is", ParamHash).withFields("allocated_bytes", "classes", "classes_unavailable", "complete", "file_slack_bytes", "file_slack_checked", "filesystem", "handle", "incomplete_reason", "is_directory", "located_bytes", "name", "path", "range_count", "ranges", "ranges_truncated", "scope", "size", "status", "unlocated_bytes", "unwritten_bytes", "unwritten_checked", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameExtDirSlack:    {signature: "ext_dir_slack(handle, path)", summary: "Recovers the directory records surviving in one directory's slack. Unlinking a file does not erase its record: the preceding record's rec_len is extended to swallow it, leaving the old record intact in the gap between where the live entry's name ends and where its rec_len now reaches. On ext4 this is frequently the only surviving evidence that a name existed at all, because unlink also zeroes the inode's extent tree. Each record is reported at two positions -- dir_offset within the directory's own data stream, which is all libext reports, and offset on the image, which this maps through the directory's data runs because nothing in libext does and a finding that cannot be re-read is not one. Every name is a candidate: the record is real, but the inode it names may since have been reused, so it has to be cross-checked against the inode table before it is called a recovered file. Records that duplicate a live entry are kept and flagged through shadows_live rather than dropped -- they are residue from the directory being rewritten and evidence of no deletion, and ext_deleted filters them out where this deliberately does not. Two limits libext does not report: a record whose inode field was cleared, which is the classic ext2 and ext3 unlink marker, is never recovered, and a block with an implausible record length is abandoned from that point on in silence. An inline directory keeps its records in the inode rather than in blocks and libext's scanner reads blocks only, so it is named as such rather than reported as empty. Returns (result, err).", returns: pairRet("the directory records found in this directory's slack, at their position in the stream and on the image", ParamHash).withFields("complete", "entries", "entries_truncated", "entry_count", "filesystem", "handle", "incomplete_reason", "inode", "located", "path", "scope", "shadows_live_count", "status", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path of the directory whose slack is scanned.", ParamString)}},
	BuiltinNameHfsSlack:       {signature: "hfs_slack(handle, path)", summary: "Reports the slack of an HFS+ file's data fork, which libhfs carries on every extent rather than only the last -- the honest shape, because an over-allocated fork has whole extents that are slack from their first byte, and a final range holding no file data at all is a fact about the volume rather than an empty result. HFS+ records no valid-data length, so the unwritten class is unavailable on this format rather than zero. A decmpfs-compressed file's data fork is genuinely empty on disk, its payload living in the resource fork or an extended attribute, so it is reported as unchecked with a warning rather than as a file with no slack; the resource fork is not examined here. An HFS+ directory is a B-tree record rather than an allocation of blocks and so owns no tail. Free space belonging to no file is a different question with its own builtin, hfs_unallocated. Returns (result, err).", returns: pairRet("the ranges of this file's allocation that hold no file content, and which class each is", ParamHash).withFields("allocated_bytes", "classes", "classes_unavailable", "complete", "file_slack_bytes", "file_slack_checked", "filesystem", "handle", "incomplete_reason", "is_directory", "located_bytes", "name", "path", "range_count", "ranges", "ranges_truncated", "scope", "size", "status", "unlocated_bytes", "unwritten_bytes", "unwritten_checked", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameHfsUnallocated: {signature: "hfs_unallocated(handle)", summary: "Walks an HFS+ volume's allocation file and reports every maximal run of blocks belonging to no live file -- the input to carving, and the only free-space traversal available anywhere in these six filesystem libraries: the others offer a per-cluster or per-block query, a raw bitmap, or a count the volume merely claims. free_blocks is counted bit by bit and free_blocks_claimed is what the volume header records, and the two are reported separately because they are different kinds of statement: a mismatch means the volume was not unmounted cleanly or its metadata is inconsistent, so claim_matches is the field to read before anything carved out of this space is relied on. A free block is not a statement that anything was ever written there, nor that what is there now was deleted rather than never used. Blocks still claimed by a file that was deleted are not free and do not appear here, which is what hfs_deleted finds instead. A run whose start block does not resolve to an offset is reported at -1 rather than at zero, which is a real place on the volume. Returns (result, err).", returns: pairRet("the runs of this volume that belong to no live file, counted rather than claimed", ParamHash).withFields("block_size", "claim_matches", "complete", "filesystem", "free_blocks", "free_blocks_claimed", "free_bytes", "handle", "incomplete_reason", "largest_run_bytes", "run_count", "runs", "runs_truncated", "scope", "status", "total_blocks", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString)}},
	BuiltinNameXfsSlack:       {signature: "xfs_slack(handle, path)", summary: "Reports an XFS inode's block tail and its unwritten extents. libxfs offers no last-block-tail API, but DataRuns does not trim its ranges to the inode's size, so the tail is what the runs hold past it. An unwritten extent is preallocated space that was never written: it reads back as zeros through the filesystem and carries a real location all the same, which libxfs says plainly is the point -- the blocks are real, and where they are is exactly what makes them worth examining. A hole is not the same thing and has no location to report. DataRuns discards the anomalies its own block-number conversion raises, so a range whose fsblock did not resolve arrives looking like a range at offset zero; it is detected here by the rule libxfs documents -- neither sparse nor located -- and reported at -1, with the scan marked incomplete. Returns (result, err).", returns: pairRet("the ranges of this file's allocation that hold no file content, and which class each is", ParamHash).withFields("allocated_bytes", "classes", "classes_unavailable", "complete", "file_slack_bytes", "file_slack_checked", "filesystem", "handle", "incomplete_reason", "is_directory", "located_bytes", "name", "path", "range_count", "ranges", "ranges_truncated", "scope", "size", "status", "unlocated_bytes", "unwritten_bytes", "unwritten_checked", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},

	// file forks, labels and descriptors -- content and metadata a path does not name.
	BuiltinNameNtfsStreams:       {signature: "ntfs_streams(handle, path)", summary: "Lists the $DATA streams of one NTFS file or directory: the unnamed stream the path addresses, and every alternate data stream beside it that the path cannot name and a directory listing does not show. An alternate data stream is the oldest hiding place on NTFS and still a working one -- its bytes are addressed only as file:stream, they are not counted in the file's size, and a directory, which has no content of its own, can carry one too, which is warned on because nothing that walks a volume by path will ever reach it. Each stream reports both of its lengths, whether it is resident in the MFT record, and whether libntfs can read it at all -- that last is known before the first byte is asked for, so an encrypted or otherwise blocked stream is named here rather than discovered part-way through an extraction that has already created its destination file. Reading a stream is ntfs_read_stream or ntfs_extract_stream. $EA and $EA_INFORMATION, the extended attributes NTFS inherited from OS/2 and that WSL uses to store its own metadata, are a different attribute type and are not listed here. Returns (result, err).", returns: pairRet("the streams this entry carries, the unnamed one distinguished from the alternates", ParamHash).withFields("alternate_bytes", "alternate_count", "complete", "default_present", "default_size", "filesystem", "handle", "incomplete_reason", "is_directory", "name", "path", "scope", "status", "stream_count", "streams", "streams_truncated", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path of the file or directory inside the volume.", ParamString)}},
	BuiltinNameNtfsReadStream:    {signature: "ntfs_read_stream(handle, path, stream, offset, length)", summary: "Reads one window of a named $DATA stream and returns it as a BYTES buffer. An alternate data stream is usually small and usually the evidence: the Zone.Identifier stream on a downloaded file records the URL it came from and the security zone Windows assigned it, and no amount of reading the file itself will produce either. An empty stream name selects the unnamed stream, which makes this a superset of ntfs_read_file_at; names are matched case-insensitively, as NTFS matches them, and a named stream on a directory opens like any other because a named stream holds content whatever its host entry is. An offset at or past the stream's recorded size returns an empty buffer, which is how a caller walks off the end; an offset inside the recorded size but past what the library could locate is an error naming both numbers rather than a run of zeroes. length is capped at 32 MiB; a stream larger than that is what ntfs_extract_stream is for. Returns (bytes, err).", returns: pairRet("the bytes in that window, short rather than padded where it runs past the stream", ParamBytes), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString), param("stream", "Name of the $DATA stream; empty selects the unnamed stream.", ParamString), param("offset", "Byte offset within the stream to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameNtfsExtractStream: {signature: "ntfs_extract_stream(handle, path, stream, dest)", summary: "Streams one named $DATA stream out of an image onto local disk without ever holding it in memory, computing the SHA-256 of what was written in the same pass. This is the path for an alternate data stream carrying a payload rather than a label -- an executable parked behind a text file's name is the case the technique is known for, and it is reachable no other way, because the stream's bytes are not part of the file the path addresses. dest must not already exist and a copy that fails part way has its partial output removed, the same rule every builtin here follows when it produces a new piece of evidence out of an image. An empty stream name extracts the unnamed stream. What is written is bounded by the bytes libntfs could locate rather than by the length the record claims, and truncated says whether the two differ. Returns (result, err).", returns: pairRet("where the stream was written, how much of it was written, and the digest of what was written", ParamHash).withFields("algorithm", "bytes_written", "dest", "digest", "located_bytes", "path", "size", "stream", "truncated"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString), param("stream", "Name of the $DATA stream; empty selects the unnamed stream.", ParamString), param("dest", "Local path to write to; must not already exist.", ParamString)}},
	BuiltinNameNtfsSecurity:      {signature: "ntfs_security(handle, path)", summary: "Reports the security descriptor governing one NTFS file: its owner, its group, and the entries of its DACL and SACL as they are stored on the volume. It is a reading, not an access decision, and the difference is the reason dacl_present is a field of its own. A descriptor carrying no DACL at all grants everyone full access; a descriptor whose DACL is present and holds no entries denies everyone. Rendered as an empty array those two are the same value and mean opposite things, so both are reported and both raise a warning naming which case it is. No field here answers whether a particular account could open the file: that needs group memberships, privilege assignments and an inheritance walk which a disk image does not contain. source says where the descriptor came from, because the provenance differs -- one stored on the entry itself belongs to this file alone, while one resolved through the entry's security ID is shared with every other file carrying that ID, and a finding about permissions on a single file has to say which it is. SIDs are rendered in S-R-I-S notation and named only where the SID is a well-known one; a domain account SID names nobody without that domain's directory. Returns (result, err).", returns: pairRet("the descriptor governing this file, with presence and emptiness kept apart", ParamHash).withFields("complete", "control", "control_flags", "dacl", "dacl_ace_count", "dacl_present", "dacl_revision", "descriptor_bytes", "descriptor_sha256", "filesystem", "group_known", "group_name", "group_sid", "handle", "incomplete_reason", "owner_known", "owner_name", "owner_sid", "path", "revision", "sacl", "sacl_ace_count", "sacl_present", "scope", "security_id", "source", "status", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameNtfsSecurityIndex: {signature: "ntfs_security_descriptors(handle)", summary: "Reports every security descriptor in the volume's $Secure:$SDS stream, in ascending security ID order -- the whole vocabulary of permissions the volume uses, read once rather than a lookup per file. This is the question worth asking across an image rather than of one file: which descriptors on this volume grant what, and which security IDs carry no DACL at all and so grant everyone full access, each of which is warned on as it is indexed. Each entry carries the SHA-256 of the descriptor bytes as stored, so the same descriptor can be recognised across images without comparing ACE by ACE. It says which descriptors exist, not which files use them: that join runs through the security ID in each entry's $STANDARD_INFORMATION, which ntfs_security reports per file. A descriptor stored directly on an entry, as older volumes and some system files do, is not in $SDS and so is not here. $SDS is append-only and libntfs indexes what it holds, so a descriptor no file still references is reported like any other rather than distinguished as stale. Returns (result, err).", returns: pairRet("every descriptor the volume's $Secure stream holds, by security id", ParamHash).withFields("complete", "descriptor_count", "descriptors", "descriptors_truncated", "filesystem", "handle", "incomplete_reason", "scope", "status", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameNtfsReparse:       {signature: "ntfs_reparse(handle, path)", summary: "Reports one entry's reparse point: the tag that says who owns it, the target where the tag names one, and the tag-specific bytes where it does not. A target is decoded for the three tags that carry one -- symbolic links, mount points, and WSL symlinks, each with a different layout -- and for every other tag, which covers deduplication, cloud placeholders, WOF-compressed files and anything shipped next, the bytes are handed back as hex rather than guessed at. A file with no reparse point is reported as having none rather than as one whose target could not be read: is_reparse_point tells the two apart, and they are different findings. The link is never followed, which is libntfs's behaviour and the right one here -- a directory carrying a reparse point lists its own index, usually empty, rather than the target's, and whether the target exists is not checked because on an image of one volume it frequently cannot be. A third-party tag carries an owner GUID, which is reported, and a data layout defined by whoever wrote the filter driver, which is not interpreted. Returns (result, err).", returns: pairRet("this entry's reparse point, or that it has none", ParamHash).withFields("complete", "data_bytes", "data_hex", "data_truncated", "filesystem", "guid", "handle", "incomplete_reason", "is_reparse_point", "microsoft_owned", "path", "print_name", "relative", "scope", "status", "tag", "tag_name", "target", "target_available", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path of the file or directory inside the volume.", ParamString)}},
	BuiltinNameExtXattrs:         {signature: "ext_xattrs(handle, path)", summary: "Lists one ext inode's extended attributes, read from both of the places ext keeps them. Reading only one is the trap here and libext's own documentation names it: GetXAttrs follows the inode's external attribute block and nothing else, and returns an empty list with no error for an inode that has no such block -- while security.selinux and system.posix_acl_access are small enough on a typical modern system never to need one, so a reader that follows only the block reports a file with SELinux labels and POSIX ACLs as having no attributes at all. Both storages are consulted here and every attribute says which it came from; a name appearing in both is kept twice and warned on, because which one the kernel would return is not recorded on disk. A value large enough that ext4 gives it its own inode is followed by libext and reported like any other, and a failure to follow one arrives as a library warning rather than as an empty value. Values read from the external block carry its position on the image; inline values have no block address and report -1. A volume without the ext_attr feature reports supported false, which is a statement about the filesystem rather than about this inode. Deleted inodes are not reachable: this addresses a live file by path. Returns (result, err).", returns: pairRet("this inode's extended attributes, from both the inline area and the external block", ParamHash).withFields("attribute_count", "attributes", "attributes_truncated", "complete", "filesystem", "handle", "incomplete_reason", "name", "node_id", "node_id_kind", "path", "scope", "status", "storages_checked", "supported", "total_value_bytes", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameXfsXattrs:         {signature: "xfs_xattrs(handle, path)", summary: "Lists one XFS inode's extended attributes, short-form or block-backed, in the order the attribute fork holds them. libxfs performs no deduplication and documents that it does not: two records carrying the same fully-qualified name both come back, which is an inconsistency in the fork rather than a rendering artifact, so duplicates are counted and warned on here instead of being silently collapsed into one. A remote value -- one large enough that XFS gives it its own blocks -- is followed by the library and reported like any other. Values carry no location on this format: libxfs exposes the attribute fork's extents nowhere that a per-value offset can be derived from, so offset is -1 throughout, unlike the ext and HFS+ siblings where it is a real address. Namespaces are the three XFS records: user, trusted and security, which is where SELinux labels live. An inode whose attribute fork is empty reports no attributes and consults no storage, which is an answer rather than a gap. Returns (result, err).", returns: pairRet("this inode's extended attributes, with duplicate records preserved and flagged", ParamHash).withFields("attribute_count", "attributes", "attributes_truncated", "complete", "filesystem", "handle", "incomplete_reason", "name", "node_id", "node_id_kind", "path", "scope", "status", "storages_checked", "supported", "total_value_bytes", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameHfsXattrs:         {signature: "hfs_xattrs(handle, path)", summary: "Lists one HFS+ catalog node's extended attributes, inline or fork-backed, in B-tree key order. com.apple.quarantine, which records that a file was downloaded and by what, and com.apple.metadata:kMDItemWhereFroms, which records where from, both live here. The system attributes com.apple.decmpfs and com.apple.ResourceFork are returned like any other and flagged rather than filtered -- libhfs calls filtering them a policy decision belonging to the caller, and the presence of decmpfs is exactly why that file's data fork reads as empty everywhere else. A fork-backed value carries its position on the image, so a value too large to render is still reachable with raw_read_at_bytes; an inline value lives in the B-tree record itself, has no allocation-block address, and reports -1 rather than a zero that would read as the start of the image. Values are read while they fit the render cap and reported by length and position when they do not, so the size of an attribute never sets the size of an allocation here. Classic HFS has no attributes B-tree at all: supported distinguishes that from an HFS+ node that simply carries none. Returns (result, err).", returns: pairRet("this node's extended attributes, inline and fork-backed, with the system ones flagged", ParamHash).withFields("attribute_count", "attributes", "attributes_truncated", "complete", "filesystem", "handle", "incomplete_reason", "name", "node_id", "node_id_kind", "path", "scope", "status", "storages_checked", "supported", "total_value_bytes", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},
	BuiltinNameHfsResourceFork:   {signature: "hfs_resource_fork(handle, path)", summary: "Reports one HFS+ file's resource fork: its recorded size, and the image ranges holding it. This is the companion to hfs_slack's finding that a compressed file's data fork is empty -- it is where those bytes went. On a decmpfs-compressed file the payload is held either in this fork or, when it is small enough, inline in the com.apple.decmpfs attribute that hfs_xattrs reaches, and the two cases are distinguished rather than merged: holds_compressed_payload is true only when the file is compressed and this fork is not empty. The bytes are never decompressed on the way out, which is libhfs's rule and the right one for evidence -- the compressed payload as stored is the artifact. On an ordinary file the resource fork is the classic Macintosh second fork, carrying icons, and on older material frequently carrying the document itself. A fork whose extents describe more space than its recorded size reports the surplus as slack on the range holding it, because an attribute record carries no block total to trim against. Folders have no fork of either kind. Returns (result, err).", returns: pairRet("where this file's resource fork lives, and whether it holds a compressed payload", ParamHash).withFields("cnid", "complete", "compressed", "compression_type", "data_fork_size", "filesystem", "handle", "holds_compressed_payload", "incomplete_reason", "located_bytes", "name", "path", "present", "range_count", "ranges", "ranges_truncated", "scope", "size", "status", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path of the file inside the volume.", ParamString)}},

	// disk-image parsers — *_read_at caps length at 32 MiB.
	BuiltinNameVhdiOpen:        {signature: "vhdi_open(image)", summary: "Opens a VHD/VHDX disk image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to a VHD/VHDX image.", ParamString)}, returns: pairRet("a handle for the other vhdi_ builtins; release it with vhdi_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameVhdiMetadata:    {signature: "vhdi_metadata(handle)", summary: "Returns VHD/VHDX metadata (format, disk_type, virtual_size, block/sector size, identifiers), the differencing-chain state (needs_parent, chain_complete, chain_depth, parent_resolve_error) and the VHDX log state (is_dirty, has_log, log_replayed).", returns: pairRet("vHD/VHDX metadata (format, disk_type, virtual_size, block/sector size, identifiers), the differencing-chain state (needs_parent, chain_complete, chain_depth, parent_resolve_error) and the VHDX log state (is_dirty, has_log, log_replayed)", ParamHash).withFields("block_size", "chain_complete", "chain_depth", "disk_type", "format", "has_log", "identifier", "is_differencing", "is_dirty", "log_replayed", "needs_parent", "parent_filename", "parent_identifier", "parent_resolve_error", "sector_size", "virtual_size"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString)}},
	BuiltinNameVhdiReadAtBytes: {signature: "vhdi_read_at_bytes(handle, offset, length)", summary: "Reads length bytes at a virtual offset from a VHD/VHDX image as a BYTES buffer (length capped at 32 MiB).", params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}, returns: pairRet("the bytes read, up to the 32 MiB cap", ParamBytes)},
	BuiltinNameVhdiReadAt:      {signature: "vhdi_read_at(handle, offset, length)", summary: "Reads length bytes at a virtual offset from a VHD/VHDX image (length capped at 32 MiB).", returns: pairRet("the bytes read, up to the 32 MiB cap", ParamString), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameVhdiMapOffset:   {signature: "vhdi_map_offset(handle, offset)", summary: "Maps a virtual offset to a backing file offset. Returns {virtual_offset, mapped, file_offset}.", returns: pairRet("where the virtual offset lands in the backing file", ParamHash).withFields("file_offset", "mapped", "virtual_offset"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("offset", "Virtual byte offset to map into the backing file.", ParamInt)}},
	BuiltinNameVhdiClose:       {signature: "vhdi_close(handle)", summary: "Closes a VHD/VHDX handle.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString)}},
	// the sparse and differencing half of VHD/VHDX -- an address space that is
	// mostly absent, spread over a chain of files that is itself evidence.
	BuiltinNameVhdiExtents:        {signature: "vhdi_extents(handle, offset, length)", summary: "Maps a window of a VHD/VHDX virtual address space to the runs that back it, which is how a sparse image is read without moving its absent zeroes through memory. Each extent carries its kind -- mapped, zero, zeroed_by_child or unresolved -- and, for a mapped one, the file it lives in and the offset within it; file_offset is -1 everywhere else, because 0 is a real offset and the library leaves the field at zero for a run that has no place in any file. zero and zeroed_by_child both read back as zeroes and are different facts: the first was never written anywhere in the chain, the second was explicitly cleared by a differencing child, and a deletion that clears its blocks appears only as the second -- so they are counted separately and is_write tells them apart. A range resolving to a parent that is not attached is unresolved and is neither, because the disk that would say is missing. The byte totals cover the whole window even when the extent list is capped. A mapped range means bytes exist there, not that they are live data: an image that never returns written blocks to the free pool keeps them mapped after the guest deleted what was in them, and says so as a warning. Pass 0 and the virtual_size from vhdi_metadata to map the whole device, which on a long differencing chain walks every block of every link. Returns (result, err).", returns: pairRet("the runs that back this window, with a byte total for each kind over the whole of it", ParamHash).withFields("chain_complete", "complete", "extent_count", "extents", "extents_truncated", "handle", "incomplete_reason", "length", "mapped_bytes", "path", "scope", "status", "unresolved_bytes", "virtual_offset", "virtual_size", "warning_codes", "warnings", "warnings_available", "zero_bytes", "zeroed_by_child_bytes"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("offset", "Virtual byte offset the window starts at.", ParamInt), param("length", "How many bytes of the address space to map; use virtual_size from vhdi_metadata for the whole device.", ParamInt)}},
	BuiltinNameVhdiChain:          {signature: "vhdi_chain(handle)", summary: "Names every image file that together constitutes this device, from the disk that was opened outwards to its base, with what produced each link. A differencing disk holds only what was written since its parent, so these files are the device an evidence record has to name -- and they were routinely made by different tools at different times, which is why the creator, the creation time, the footer copy the image was read from and the log replay state are recorded per link rather than flattened into one record. complete is false when a link the device needs was never attached: the chain then stops short of the device, reads into the missing ranges fail rather than returning zeroes, and parent_resolve_error says why. Returns (result, err).", returns: pairRet("the image files this device is made of, outwards from the one that was opened, with the origin of each", ParamHash).withFields("complete", "depth", "handle", "incomplete_reason", "link_count", "links", "needs_parent", "parent_resolve_error", "path", "paths", "scope", "status", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString)}},
	BuiltinNameVhdiChangedExtents: {signature: "vhdi_changed_extents(handle, since_chain_index)", summary: "Reports which ranges of the virtual disk were written by the links nearer the leaf than the named chain index, which is the block-level answer to what a checkpoint changed and needs no filesystem knowledge at all. Chain indices count outwards from the disk that was opened: 0 is that disk and 1 its parent, so 1 is what the leaf alone wrote and 2 is what the leaf and the checkpoint below it wrote together; vhdi_chain lists them. A range a child explicitly cleared counts as written, because clearing is a write and a deletion that zeroes its blocks shows up no other way -- filtering on mapped alone under-reports deletions and does it silently. deletions_expressible is false when a VHD link is among those being reported on: VHD has no block state meaning zero, so a region the guest cleared is recorded as belonging to the parent and reads back as the parent's old contents, and across such a link the deletion is absent from the format rather than merely from this answer. An unresolved range is neither changed nor unchanged and is returned as itself. Returns (result, err).", returns: pairRet("the ranges written by the links in front of the named one, with cleared ranges counted as writes", ParamHash).withFields("chain_complete", "chain_depth", "changed_bytes", "complete", "deletions_expressible", "extent_count", "extents", "extents_truncated", "handle", "incomplete_reason", "mapped_bytes", "path", "scope", "since_chain_index", "since_path", "status", "unresolved_bytes", "warning_codes", "warnings", "warnings_available", "zeroed_by_child_bytes"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("since_chain_index", "Index of the disk in the chain to measure from; 0 is the disk that was opened, and vhdi_chain lists the rest.", ParamInt)}},
	BuiltinNameVhdiChangedSince:   {signature: "vhdi_changed_since(handle, path)", summary: "vhdi_changed_extents addressed by the path of a disk in the chain rather than by its index, which is how a script holding a checkpoint tree asks the question, and the index it resolved to is reported beside the answer. Paths are compared the way the platform's filesystem compares them, so a script does not have to get Windows's case-insensitivity right itself. Naming the disk that was opened yields nothing, because nothing can have been written since the leaf, and that empty answer carries named_disk_is_the_leaf so it is not read as a finding. A path naming no disk in the chain is an error rather than an empty answer. Every boundary of vhdi_changed_extents applies here, deletions_expressible included. Returns (result, err).", returns: pairRet("the ranges written since the named disk was the leaf, with the chain index it resolved to", ParamHash).withFields("chain_complete", "chain_depth", "changed_bytes", "complete", "deletions_expressible", "extent_count", "extents", "extents_truncated", "handle", "incomplete_reason", "mapped_bytes", "path", "scope", "since_chain_index", "since_path", "status", "unresolved_bytes", "warning_codes", "warnings", "warnings_available", "zeroed_by_child_bytes"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("path", "File path of a disk in this chain, as vhdi_chain reports it.", ParamString)}},
	BuiltinNameVhdiProbe:          {signature: "vhdi_probe(image)", summary: "Reads one VHD/VHDX image's headers without opening it: no block allocation table is parsed, no log is replayed and no content is read, which is what makes asking about a terabyte image cheap. It answers what the file says it is, what chain it records, and whether anything about it disagrees with itself -- a checkpoint extension on a disk that is not differencing, an image recording no link identity that no child can ever be matched to, a footer read from a fallback copy because the conformant one could not be. link_identity is reported apart from identifier because they are different fields: a differencing child records its parent's link identity, and conflating the two is what makes a chain fail to join up. The image is registered as evidence, because the program named this file. Returns (result, err).", returns: pairRet("what one image says about itself, read from its headers alone", ParamHash).withFields("complete", "disk_type", "error", "file_size", "footer_recovered", "footer_source", "format", "has_checkpoint_extension", "has_log", "identifier", "incomplete_reason", "is_differencing", "link_identity", "parent_filename", "parent_identifier", "parent_locators", "path", "readable", "role", "scope", "status", "virtual_size", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("image", "Path to a VHD/VHDX image.", ParamString)}},
	BuiltinNameVhdiDiscover:       {signature: "vhdi_discover(dir)", summary: "Reads the headers of every disk image in a directory and builds the parent-to-child tree they record, which is the shape a chain walk cannot see: checkpoints branch, and from a leaf a sibling branch is invisible. Children are joined to parents by recorded identity alone -- matching on virtual size would attach any image of the right size, and matching on a recorded filename would follow a name that may have been reused -- so a child whose parent is not in the directory stays a root and says so. branched is true when the directory holds more than one leaf; which branch a virtual machine is using is recorded in the machine's configuration and not in the disks, so it is not guessed here. Files that could not be probed are kept and named rather than dropped, because an unreadable file in a checkpoint directory may be the link that would have joined two halves of the tree, and files that are not images at all are listed apart so they do not bury the real failures. The images are not registered as evidence: naming a directory is not the same as naming the files an examination read. Returns (result, err).", returns: pairRet("the parent-to-child tree the images in this directory record, with every lineage it forms", ParamHash).withFields("branched", "complete", "dir", "incomplete_reason", "leaf_paths", "lineage_count", "lineages", "node_count", "nodes", "nodes_truncated", "root_paths", "scope", "skipped", "skipped_count", "status", "unreadable", "unreadable_count", "warning_codes", "warnings", "warnings_available"), params: []builtinParamDoc{param("dir", "Directory to scan for .vhd, .vhdx, .avhd and .avhdx images.", ParamString)}},
	// parseEWFSegmentPaths (disk_image_parsers.go) takes either a single path
	// or an array of them, and requires every array element to be a STRING.
	BuiltinNameEwfOpen: {
		signature: "ewf_open(segments, checksum_policy?)",
		summary:   "Opens an EWF/E01 image. Given one segment path, the rest of the set is discovered beside it and all of them are opened -- the extensions run .E01 to .E99 and then continue .EAA rather than .E100, and the path need not be the first segment, so an image named by its .E03 still decodes from its .E01. Given an array of paths, those files are taken as given and nothing is discovered, so a set whose members were gathered from elsewhere still opens. A discovered set with a hole in its numbering is refused rather than opened, because decoding a set that is missing a segment yields an image that is not the one acquired; ewf_segments reports which files are absent, and ewf_open_partial proceeds anyway for triage. checksum_policy decides what an unverifiable chunk table means -- a chunk table maps offsets to compressed chunks, so an unverified one means the decoded bytes may not be the bytes written. The returned segments array names every file the image was decoded from, for the report. Returns (result, err).",
		params: []builtinParamDoc{
			{
				name:  "segments",
				doc:   "Segment file path (the rest of the set is discovered) or an array of paths (taken as given).",
				kinds: []ParamKind{ParamString, ParamArray},
				elem:  []ParamKind{ParamString},
			},
			param("checksum_policy?", "\"warn\" (default: decode and report failures in ewf_metadata's chunk_tables_invalid), \"strict\" (refuse an image with an unverifiable chunk table) or \"ignore\" (suppress checksum accounting, so chunk_tables_invalid reads zero whether or not tables failed -- never the source of an integrity claim). An unknown name is an error.", ParamString),
		},
		returns: pairRet("a handle for the other ewf_ builtins, and the segment files actually opened", ParamHash).withFields("checksum_policy", "handle", "missing_segments", "partial", "segment_count", "segments", "status")},
	BuiltinNameEwfOpenPartial: {
		signature: "ewf_open_partial(segments, checksum_policy?)",
		summary:   "Opens an EWF/E01 segment set that ewf_open refuses: one with a hole in its numbering, one that does not begin at segment 1, or one whose final segment carries no done-section. Such a set decodes only part of the device -- the image still reports the full size its volume section declares, while reads past the supplied data return end-of-file -- so this is for metadata inspection and triage of damaged evidence, never for content that will be hashed or carved. It is a separate builtin rather than a flag because the difference has to be visible at the call site and in the audit trail. The returned partial and missing_segments fields carry the caveat into whatever report is built from them; they are on ewf_open's result too, so a template written against one cannot silently drop them for the other. Otherwise identical to ewf_open. Returns (result, err).",
		params: []builtinParamDoc{
			{
				name:  "segments",
				doc:   "Segment file path (the rest of the set is discovered) or an array of paths (taken as given).",
				kinds: []ParamKind{ParamString, ParamArray},
				elem:  []ParamKind{ParamString},
			},
			param("checksum_policy?", "\"warn\" (default), \"strict\" or \"ignore\", as for ewf_open. An unknown name is an error.", ParamString),
		},
		returns: pairRet("a handle for the other ewf_ builtins, and what the set was missing", ParamHash).withFields("checksum_policy", "handle", "missing_segments", "partial", "segment_count", "segments", "status")},
	BuiltinNameEwfSegments:    {signature: "ewf_segments(path)", summary: "Reports the segment set a path belongs to without opening any of it, so an examiner can record which files an image will be decoded from -- and find out what is missing before paying for a full open. `contiguous` means the numbering has no holes; it does not mean the set is whole, because a set truncated at its end is indistinguishable from a complete one by looking at a directory, and that case is caught only by ewf_metadata's has_done_section on the opened image. When contiguous is false, missing_segments gives the absent segment numbers and missing_files names the files to go and find; segments is empty, because the set was not resolved. A hole is reported rather than raised, since which files are absent is a finding about the evidence and belongs in a report. Returns (result, err).", returns: pairRet("the segment set, and what is absent from it", ParamHash).withFields("contiguous", "missing_files", "missing_segments", "path", "present_count", "segment_count", "segments"), params: []builtinParamDoc{param("path", "Path to any numbered segment of the set; the rest are discovered beside it.", ParamString)}},
	BuiltinNameEwfMetadata:    {signature: "ewf_metadata(handle)", summary: "Returns EWF metadata (version, sectors/chunks, digests, media info, sector_size, compression_method). chunk_tables_invalid counts chunk-table groups that failed both their primary and backup checksum — their data decoded unverified and should be treated as suspect; chunk_tables_recovered, observed_chunk_count and acquisition_error_count report the rest of the integrity picture.", returns: pairRet("eWF metadata (version, sectors/chunks, digests, media info, sector_size, compression_method)", ParamHash).withFields("acquisition_error_count", "bytes_per_sector", "chunk_tables_invalid", "chunk_tables_recovered", "compression_method", "has_done_section", "has_integrity_hash", "has_md5_digest", "has_media", "has_next_section", "has_sha1_digest", "is_encrypted", "major_version", "md5_digest", "minor_version", "number_of_chunks", "number_of_sectors", "observed_chunk_count", "section_count", "sector_size", "sectors_per_chunk", "segment_number", "sha1_digest", "total_logical_bytes"), params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString)}},
	BuiltinNameEwfVerify:      {signature: "ewf_verify(handle)", summary: "Recomputes MD5 and SHA-1 over the whole decoded device and compares them against the digests the acquisition tool stored in the image. This is the strongest self-contained integrity check an EWF image admits, and it is what ewf_metadata's md5_digest and sha1_digest do not do -- those report what the image *claims*, this checks it. `ok` is true only when every stored digest was reproduced and no span failed to decode; an image that stores no digest at all is never ok, because there is nothing to verify against. Spans that fail to decode are zero-filled so hashing can continue and are listed in bad_ranges -- any entry there makes the computed digests meaningless, so read bad_ranges before treating a mismatch as evidence of tampering. Reads the entire image, so it costs O(image size) rather than a seek. Returns (result, err).", returns: pairRet("the verification outcome, with both the stored and the recomputed digests", ParamHash).withFields("bad_ranges", "bytes_hashed", "computed_md5", "computed_sha1", "has_stored_md5", "has_stored_sha1", "md5_match", "ok", "sha1_match", "size", "stored_md5", "stored_sha1"), params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString)}},
	BuiltinNameEwfReadAtBytes: {signature: "ewf_read_at_bytes(handle, offset, length)", summary: "Reads length bytes at an offset from an EWF image as a BYTES buffer (length capped at 32 MiB).", params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}, returns: pairRet("the bytes read, up to the 32 MiB cap", ParamBytes)},
	BuiltinNameEwfReadAt:      {signature: "ewf_read_at(handle, offset, length)", summary: "Reads length bytes at an offset from an EWF image (length capped at 32 MiB).", returns: pairRet("the bytes read, up to the 32 MiB cap", ParamString), params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameEwfClose:       {signature: "ewf_close(handle)", summary: "Closes an EWF handle and its segment files.", returns: pairRet("confirmation that the handle and its segment files have been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString)}},
	BuiltinNameRawOpen:        {signature: "raw_open(image)", summary: "Opens a raw disk image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to a raw (dd) image.", ParamString)}, returns: pairRet("a handle for the other raw_ builtins; release it with raw_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameRawMetadata:    {signature: "raw_metadata(handle)", summary: "Returns {file_size, assumed_sector_size, sector_size_assumed} (raw images carry no real sector-size metadata).", returns: pairRet("the image's size and sector size, which a raw image does not record and so is assumed", ParamHash).withFields("assumed_sector_size", "file_size", "sector_size_assumed"), params: []builtinParamDoc{param("handle", "Handle from raw_open.", ParamString)}},
	BuiltinNameRawReadAtBytes: {signature: "raw_read_at_bytes(handle, offset, length)", summary: "Reads length bytes at an offset from a raw image as a BYTES buffer (length capped at 32 MiB).", params: []builtinParamDoc{param("handle", "Handle from raw_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}, returns: pairRet("the bytes read, up to the 32 MiB cap", ParamBytes)},
	BuiltinNameRawReadAt:      {signature: "raw_read_at(handle, offset, length)", summary: "Reads length bytes at an offset from a raw image (length capped at 32 MiB).", returns: pairRet("the bytes read, up to the 32 MiB cap", ParamString), params: []builtinParamDoc{param("handle", "Handle from raw_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameRawClose:       {signature: "raw_close(handle)", summary: "Closes a raw image handle.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from raw_open.", ParamString)}},

	// partition table parser
	BuiltinNameTableOpen: {
		signature: "table_open(image)",
		summary:   "Opens a disk image and parses its partition table. Each warning carries a stable code -- overlap, out_of_bounds, hybrid_mbr, entry_count_truncated, backup_missing, backup_mismatch, nested -- beside the prose and the LBA it was found at, and warning_codes is the set of them; branch on the code, because the prose is reworded between releases and the code is not. gpt_backup reports the secondary GPT as ok, missing or mismatch, and unknown when the question does not apply -- two copies are written together, so a mismatch means one was rewritten without the other. candidates lists every scheme that parsed cleanly, so ambiguous means this parse picked a winner: table_open_strict refuses to, table_open_as chooses, table_open_all keeps every one. Returns (result, err).",
		params:    []builtinParamDoc{param("image", "Path to a disk image.", ParamString)},
		returns:   pairRet("a handle for the other table_ builtins, plus what the parser found", ParamHash).withFields("ambiguous", "block_size", "candidates", "gpt_backup", "handle", "is_backup", "partition_count", "path", "status", "table_offset", "table_type", "warning_codes", "warnings")},
	BuiltinNameTableOpenAs: {
		signature: "table_open_as(image, scheme)",
		summary:   "Parses the image as one named scheme instead of autodetecting, which is how an examiner records having chosen between candidates rather than accepting a default. Returns what table_open returns. A scheme the parser does not have is refused by name rather than attempted.",
		params:    []builtinParamDoc{param("image", "Path to a disk image.", ParamString), param("scheme", "One of mbr, gpt, bsd, sun, mac.", ParamString)},
		returns:   pairRet("a handle for the other table_ builtins, plus what the parser found", ParamHash).withFields("ambiguous", "block_size", "candidates", "gpt_backup", "handle", "is_backup", "partition_count", "path", "status", "table_offset", "table_type", "warning_codes", "warnings")},
	BuiltinNameTableOpenAll: {
		signature: "table_open_all(image)",
		summary:   "Returns one handle per scheme that parsed cleanly, rather than one winner. A hybrid MBR -- a disk whose protective MBR also carries real records -- is the case that needs it: table_open reports the GPT, and the MBR entries are reachable by no other route. Each handle owns its own descriptor and is released with its own table_close.",
		params:    []builtinParamDoc{param("image", "Path to a disk image.", ParamString)},
		returns:   pairRet("one hash per scheme that parsed, in preference order", ParamArray).ofElem(ParamHash).withFields("ambiguous", "block_size", "candidates", "gpt_backup", "handle", "is_backup", "partition_count", "path", "status", "table_offset", "table_type", "warning_codes", "warnings")},
	BuiltinNameTableOpenStrict: {
		signature: "table_open_strict(image)",
		summary:   "Opens like table_open, but refuses media on which more than one scheme parses cleanly instead of resolving it by preference order. The error names every candidate and the one preference would have returned. Use it where a silent winner is not an acceptable answer.",
		params:    []builtinParamDoc{param("image", "Path to a disk image.", ParamString)},
		returns:   pairRet("a handle for the other table_ builtins, plus what the parser found", ParamHash).withFields("ambiguous", "block_size", "candidates", "gpt_backup", "handle", "is_backup", "partition_count", "path", "status", "table_offset", "table_type", "warning_codes", "warnings")},
	BuiltinNameTableDetect: {
		signature: "table_detect(image)",
		summary:   "Names every partition scheme that parses cleanly, in preference order, and issues no handle. It is the question asked before the decision, so a script that only wants to know what an image is has nothing to release afterwards. The read is still recorded against the open case.",
		params:    []builtinParamDoc{param("image", "Path to a disk image.", ParamString)},
		returns:   pairRet("what parsed, without opening anything", ParamHash).withFields("ambiguous", "candidate_count", "candidates", "path", "table_type")},
	BuiltinNameTableListPartitions: {
		signature: "table_list_partitions(handle)",
		summary:   "Lists partitions with LBA ranges, absolute start_byte/length_byte, type, name, flags, and hex type_code/attributes. Use start_byte rather than start_lba * block_size, which mislocates every partition on a table parsed at a non-zero offset. The listing maps the whole device, not only its volumes: allocated, unallocated, meta and structure decode flags, occupies_space marks the rows that tile the device exactly once, and has_nested marks a slice holding a partition scheme of its own. A script that hands every entry to fat_open is handing it GPT headers and interior gaps.",
		params:    []builtinParamDoc{param("handle", "Handle from table_open.", ParamString)},
		returns:   pairRet("one hash per partition", ParamArray).ofElem(ParamHash).withFields("allocated", "attributes", "end_lba", "flags", "guid_type", "guid_unique", "has_nested", "index", "length_byte", "length_lba", "meta", "name", "nested_type", "occupies_space", "slot_number", "start_byte", "start_lba", "structure", "table_number", "type_code", "type_name", "unallocated")},
	BuiltinNameTablePartitionInfo: {
		signature: "table_partition_info(handle, index)",
		summary:   "Returns details for a single partition by index, including absolute start_byte/length_byte and the decoded allocated/unallocated/meta/structure flags.",
		params:    []builtinParamDoc{param("handle", "Handle from table_open.", ParamString), param("index", "Zero-based partition index.", ParamInt)},
		returns:   pairRet("details for a single partition by index", ParamHash).withFields("allocated", "attributes", "end_lba", "flags", "guid_type", "guid_unique", "has_nested", "index", "length_byte", "length_lba", "meta", "name", "nested_type", "occupies_space", "slot_number", "start_byte", "start_lba", "structure", "table_number", "type_code", "type_name", "unallocated")},
	BuiltinNameTableNested: {
		signature: "table_nested(handle, index)",
		summary:   "Returns the partition scheme found inside one partition -- a BSD disklabel in an MBR 0xA5 slice is the case that occurs in practice. Its partitions carry absolute byte offsets computed by the inner table, which is the only thing that knows whether the label was written with container-relative or disk-absolute addresses. A partition holding no nested scheme is an error rather than an empty listing, since an empty listing reads as a container that held nothing; has_nested on the partition is how to ask first.",
		params:    []builtinParamDoc{param("handle", "Handle from table_open.", ParamString), param("index", "Zero-based index of the partition to look inside.", ParamInt)},
		returns:   pairRet("the nested table and its partitions", ParamHash).withFields("block_size", "index", "partition_count", "partitions", "table_offset", "table_type", "warning_codes", "warnings")},
	BuiltinNameTableClose: {
		signature: "table_close(handle)",
		summary:   "Closes a partition-table handle.",
		params:    []builtinParamDoc{param("handle", "Handle from table_open.", ParamString)},
		returns:   pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status")},

	// archives -- evidence containers, read in place
	BuiltinNameZipOpen: {
		signature: "zip_open(path)",
		summary:   "Opens a zip archive (store/deflate/bzip2/zstd) and returns a handle for the other zip_ builtins. Reads the central directory only, so opening a large collection is cheap. unsafe_path_count reports entries whose names would escape a destination directory on extraction -- an archive that contains one is itself a finding. Release the handle with zip_close.",
		params:    []builtinParamDoc{param("path", "Path to a .zip archive.", ParamString)},
		returns:   pairRet("a handle for the other zip_ builtins, plus what the central directory declares", ParamHash).withFields("comment", "entry_count", "handle", "path", "status", "total_uncompressed", "unsafe_path_count")},
	BuiltinNameZipEntries: {
		signature: "zip_entries(handle)",
		summary:   "Lists an archive's entries without decompressing any of them: name, sizes, compression method, CRC-32, mode, mtime, encryption flag, and unsafe_path.",
		params:    []builtinParamDoc{param("handle", "Handle from zip_open.", ParamString)},
		returns:   pairRet("one hash per entry", ParamArray).ofElem(ParamHash).withFields("comment", "compressed_size", "crc32", "encrypted", "is_dir", "method", "mode", "modified", "name", "size", "unsafe_path")},
	BuiltinNameZipRead: {
		signature: "zip_read(handle, name, max_bytes?)",
		summary:   "Reads one entry by name and returns its contents as text. Refuses to produce more than 1000x the entry's compressed size, capped at 1 GiB, unless max_bytes says otherwise -- the declared uncompressed size is checked first and the limit is enforced again against what actually decompresses, because a decompression bomb lies about its size. Nothing is written to disk.",
		params:    []builtinParamDoc{param("handle", "Handle from zip_open.", ParamString), param("name", "Entry name, as reported by zip_entries.", ParamString), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit of 1000x the compressed size, capped at 1 GiB.", ParamInt)},
		returns:   pairRet("the entry's contents", ParamString)},
	BuiltinNameZipReadBytes: {
		signature: "zip_read_bytes(handle, name, max_bytes?)",
		summary:   "Reads one entry by name into a BYTES buffer. Same limits as zip_read; this is the form to use, since an archive member is binary unless proven otherwise.",
		params:    []builtinParamDoc{param("handle", "Handle from zip_open.", ParamString), param("name", "Entry name, as reported by zip_entries.", ParamString), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit of 1000x the compressed size, capped at 1 GiB.", ParamInt)},
		returns:   pairRet("the entry's contents", ParamBytes)},
	BuiltinNameZipClose: {
		signature: "zip_close(handle)",
		summary:   "Closes a zip handle and the archive file behind it.",
		params:    []builtinParamDoc{param("handle", "Handle from zip_open.", ParamString)},
		returns:   pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status")},
	BuiltinNameTarOpen: {
		signature: "tar_open(path)",
		summary:   "Opens a tar archive -- plain, or wrapped in gzip, bzip2 or zstd, detected by magic rather than by extension -- and returns a handle. Tar has no central directory, so the whole archive is walked once here to learn what it contains; bodies are skipped rather than held. compression names what was detected. Release the handle with tar_close.",
		params:    []builtinParamDoc{param("path", "Path to a .tar, .tar.gz/.tgz, .tar.bz2 or .tar.zst archive.", ParamString)},
		returns:   pairRet("a handle for the other tar_ builtins, plus what the walk found", ParamHash).withFields("compression", "entry_count", "handle", "path", "status", "total_uncompressed", "unsafe_path_count")},
	BuiltinNameTarEntries: {
		signature: "tar_entries(handle)",
		summary:   "Lists an archive's members from the walk tar_open already did: name, size, entry type, link target, POSIX mode/uid/gid/uname/gname, the three timestamps, and unsafe_path -- which covers a link target that escapes as well as a name that does.",
		params:    []builtinParamDoc{param("handle", "Handle from tar_open.", ParamString)},
		returns:   pairRet("one hash per member", ParamArray).ofElem(ParamHash).withFields("accessed", "changed", "gid", "gname", "is_dir", "linkname", "mode", "modified", "name", "size", "type", "uid", "uname", "unsafe_path")},
	BuiltinNameTarRead: {
		signature: "tar_read(handle, name, max_bytes?)",
		summary:   "Reads one member by name and returns its contents as text. Tar has no index, so this walks from the start of the archive: cheap on a plain .tar, but on a compressed one it decompresses everything before the member, which makes reading many members quadratic. Limited to 1 GiB unless max_bytes says otherwise. Nothing is written to disk.",
		params:    []builtinParamDoc{param("handle", "Handle from tar_open.", ParamString), param("name", "Member name, as reported by tar_entries.", ParamString), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit of 1000x the compressed size, capped at 1 GiB.", ParamInt)},
		returns:   pairRet("the member's contents", ParamString)},
	BuiltinNameTarReadBytes: {
		signature: "tar_read_bytes(handle, name, max_bytes?)",
		summary:   "Reads one member by name into a BYTES buffer. Same walk and same limits as tar_read; this is the form to use, since an archive member is binary unless proven otherwise.",
		params:    []builtinParamDoc{param("handle", "Handle from tar_open.", ParamString), param("name", "Member name, as reported by tar_entries.", ParamString), param("max_bytes?", "Maximum bytes to decompress; replaces the default limit of 1000x the compressed size, capped at 1 GiB.", ParamInt)},
		returns:   pairRet("the member's contents", ParamBytes)},
	BuiltinNameTarClose: {
		signature: "tar_close(handle)",
		summary:   "Closes a tar handle and the archive file behind it.",
		params:    []builtinParamDoc{param("handle", "Handle from tar_open.", ParamString)},
		returns:   pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status")},

	// close helpers that lacked docs
	BuiltinNameCacheClose: {signature: "cache_close(name)", summary: "Closes a named cache and frees its entries and backend.", returns: pairRet("confirmation that the cache has been closed", ParamHash).withFields("closed", "name"), params: []builtinParamDoc{param("name", "Cache namespace to close.", ParamString)}},
	BuiltinNameRegClose:   {signature: "reg_close(handle)", summary: "Closes a registry-hive handle opened with reg_open.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from reg_open.", ParamString)}},
}

var builtinFamilyDocs = []builtinFamilyDoc{
	{prefix: "bytes_", summary: "Bytes utility for reading/writing binary data."},
	{prefix: "db_", summary: "Graph database helper for nodes, edges, indexing, or traversal."},
	{prefix: "fs_", summary: "Filesystem helper for reading/writing/managing files and directories."},
	{prefix: "http_", summary: "HTTP helper for network requests."},
	{prefix: "net_", summary: "Network helper for address resolution, sockets, scanning, and capture analysis."},
	{prefix: "tls_", summary: "TLS certificate authority helper for generating and signing X.509 certificates."},
	{prefix: "cmd_", summary: "Command execution helper."},
	{prefix: "exec_", summary: "Execution helper for running script/code strings in controlled contexts."},
	{prefix: "json_", summary: "JSON serialization/parsing helper."},
	{prefix: "lua_", summary: "Lua execution helper."},
	{prefix: "str_", summary: "String manipulation helper (case, trim, pad, join, slice, format)."},
	{prefix: "hash_", summary: "Cryptographic/checksum hashing helper (md5/sha1/sha256/sha512/crc32/blake2)."},
	{prefix: "math_", summary: "Mathematical constant accessor."},
	{prefix: "rand", summary: "Random value generator."},
	{prefix: "uuid_", summary: "UUID generator."},
	{prefix: "time_", summary: "Time and date helper (Unix timestamps, formatting, parsing)."},
	{prefix: "base64", summary: "Base64 encoding/decoding helper."},
	{prefix: "base32", summary: "Base32 encoding/decoding helper."},
	{prefix: "go_", summary: "Go-compiled binary analysis helper (GoReSym): build info, build ID, and symbol recovery from stripped binaries."},
	{prefix: "ip_", summary: "IP address helper (validation, CIDR membership, conversions)."},
	{prefix: "timeline_", summary: "Forensic timeline helper (sort/merge events into a supertimeline)."},
	{prefix: "hashset_", summary: "Known-file hash-set helper (NSRL-style load/lookup for filtering)."},
	{prefix: "hive_", summary: "Real Windows registry hive parser (regf binary format)."},
	{prefix: "text_", summary: "Text analysis and fuzzy matching helper."},
	{prefix: "regex_", summary: "Regular expression matching and extraction helper."},
	{prefix: "policy_", summary: "Policy evaluation and trace helper."},
	{prefix: "cache_", summary: "In-memory cache helper for open/get/put/delete/stats workflows."},
	{prefix: "process_", summary: "Process forensics helper for inspection, memory scanning, and control."},
	{prefix: "bin_", summary: "Binary analysis helper for PE/ELF/DWARF parsing, strings, and entropy/signature workflows."},
	{prefix: "reg_", summary: "Registry forensics helper for hives, keys, values, and timeline analysis."},
	{prefix: "email_", summary: "Email forensics helper for headers, attachments, URLs, and authentication signals."},
	{prefix: "mem_", summary: "Memory forensics helper for maps, scans, strings, and shellcode/PE discovery."},
	{prefix: "detect_", summary: "Detection helper for persistence, injection, beaconing, privilege escalation, and suspicious files."},
	{prefix: "ntfs_", summary: "NTFS filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "fat_", summary: "FAT filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "xfat_", summary: "exFAT filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "ext_", summary: "ext filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "hfs_", summary: "HFS filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "xfs_", summary: "XFS filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "vhdi_", summary: "VHD image parser helper for metadata lookup and offset reads."},
	{prefix: "ewf_", summary: "EWF image parser helper for metadata lookup and offset reads."},
	{prefix: "raw_", summary: "Raw disk image helper for metadata lookup and offset reads."},
	{prefix: "table_", summary: "Partition table parser helper for table and partition metadata."},
}

func TeachingDoc(name string) (string, string, []BuiltinParamDoc, bool) {
	doc, ok := builtinDocs[name]
	if !ok {
		return "", "", nil, false
	}

	return doc.signature, doc.summary, exportParams(doc.params), true
}

// ParamSpecs returns the parameter contracts for a builtin, or false when the
// builtin has no teaching doc.
//
// It is the same data TeachingDoc carries, exposed on its own for callers that
// want only the contracts — notably the language server's argument-type
// diagnostic, which visits every call site in a document and has no use for the
// signature and summary strings.
func ParamSpecs(name string) ([]BuiltinParamDoc, bool) {
	doc, ok := builtinDocs[name]
	if !ok {
		return nil, false
	}
	return exportParams(doc.params), true
}

// ReturnSpec returns the contract for what a builtin yields, or false when the
// builtin has no teaching doc.
func ReturnSpec(name string) (BuiltinReturnDoc, bool) {
	doc, ok := builtinDocs[name]
	if !ok {
		return BuiltinReturnDoc{}, false
	}
	return BuiltinReturnDoc{
		Kinds:  doc.returns.kinds,
		Elem:   doc.returns.elem,
		Fields: doc.returns.fields,
		Doc:    doc.returns.doc,
		Pair:   doc.returns.pair,
	}, true
}

// exportParams converts the internal parameter docs to their exported form,
// deriving Optional and Variadic from the parameter's spelling.
func exportParams(params []builtinParamDoc) []BuiltinParamDoc {
	exported := make([]BuiltinParamDoc, 0, len(params))
	for _, p := range params {
		shape, ok := parseSignatureParam(p.name)
		if !ok {
			// An unparseable spelling loses only the derived flags; the
			// parameter still documents itself. metadata_param_test.go fails on
			// this, so it cannot reach a release.
			shape = SignatureParam{Name: p.name}
		}
		exported = append(exported, BuiltinParamDoc{
			Name:     p.name,
			Doc:      p.doc,
			Kinds:    p.kinds,
			Optional: shape.Optional,
			Variadic: shape.Variadic,
			Elem:     p.elem,
		})
	}
	return exported
}

func TeachingFamilySummary(name string) (string, bool) {
	for _, family := range builtinFamilyDocs {
		if strings.HasPrefix(name, family.prefix) {
			return family.summary, true
		}
	}
	return "", false
}

func HasTeachingCoverage(name string) bool {
	if _, _, _, ok := TeachingDoc(name); ok {
		return true
	}
	_, ok := TeachingFamilySummary(name)
	return ok
}

// PlatformSupport reports the GOOS values a builtin actually works on and a soft
// caveat note, if any. An empty platforms slice means the builtin works on all
// platforms. The LSP uses this to warn when a program targets a builtin that is
// unsupported on the host OS, and surfaces the note in hover.
func PlatformSupport(name string) (platforms []string, note string) {
	doc, ok := builtinDocs[name]
	if !ok {
		return nil, ""
	}
	return doc.platforms, doc.platformNote
}

// UnsupportedOn reports whether the named builtin is known to NOT work on the
// given GOOS. It returns false when the builtin has no platform restriction
// (the common case) or when the builtin is unknown — callers should not warn on
// something they cannot classify.
func UnsupportedOn(name, goos string) bool {
	doc, ok := builtinDocs[name]
	if !ok || len(doc.platforms) == 0 {
		return false
	}
	for _, p := range doc.platforms {
		if p == goos {
			return false
		}
	}
	return true
}

// capabilityCategory maps a builtin-name prefix to a human-readable capability
// category. It is a decorative label surfaced in LSP hover and completion detail
// (e.g. "builtin · filesystem"). Order matters: more specific prefixes must come
// before shorter ones they would otherwise shadow (e.g. random_hex before rand).
type capabilityCategory struct {
	prefix   string
	category string
}

var capabilityCategories = []capabilityCategory{
	// testing. First, because these are short, common words and a later family
	// that wanted one of them would be the one to rename: `assert` claims every
	// assert_* spelling, and none of the five collide with an existing prefix.
	{"assert", "testing"},
	{"test", "testing"},
	{"fail", "testing"},
	{"before_each", "testing"},
	{"after_each", "testing"},
	// networking / http
	{"http_", "http"},
	{"ws_", "network"},
	{"net_", "network"},
	{"tls_", "network"},
	{"ip_", "network intelligence"},
	{"cidr_", "network intelligence"},
	{"domain_", "network intelligence"},
	{"tld_", "network intelligence"},
	{"defang", "network intelligence"},
	{"refang", "network intelligence"},
	{"extract_iocs", "network intelligence"},
	{"is_valid_domain", "network intelligence"},
	// structured data / encoding
	{"json_", "structured data"},
	{"base64", "structured data"},
	{"base32", "structured data"},
	{"hex_", "structured data"},
	{"url_", "structured data"},
	{"gzip", "structured data"},
	{"gunzip", "structured data"},
	{"zlib_", "structured data"},
	{"to_base", "structured data"},
	{"from_base", "structured data"},
	{"to_", "structured data"},
	{"parse_", "structured data"},
	{"plist_", "structured data"},
	// The formats that are not JSON. None of these collide with an earlier
	// prefix: "to_" needs a literal underscore third, so it does not claim
	// "toml_".
	{"csv_", "structured data"},
	{"xml_", "structured data"},
	{"ndjson_", "structured data"},
	{"yaml_", "structured data"},
	{"toml_", "structured data"},
	{"cbor_", "structured data"},
	{"msgpack_", "structured data"},
	{"protobuf_", "structured data"},
	{"der_", "structured data"},
	// concurrency
	{"chan_", "concurrency"},
	{"task_", "concurrency"},
	{"spawn", "concurrency"},
	// graph database
	{"db_", "graph database"},
	// The forensic ledger is the same engine under a posture that cannot be
	// turned off, and its own category because the two are not
	// interchangeable: a db_ handle never resolves here and a ledger
	// directory refuses to open as a graph.
	{"ledger_", "forensic ledger"},
	// runtime integration
	{"lua_", "runtime integration"},
	// command execution
	{"exec_", "command execution"},
	{"cmd_", "command execution"},
	// strings / text
	{"str_", "strings"},
	{"text_", "text analysis"},
	{"regex_", "text analysis"},
	// hashing / ids
	{"hashset_", "hash-set forensics"},
	{"hash_", "hashing"},
	{"hmac", "hashing"},
	{"uuid_", "hashing"},
	{"nanoid", "hashing"},
	{"random_hex", "hashing"},
	{"crc32", "hashing"},
	// math
	{"math_", "math"},
	{"rand", "math"},
	// time / timeline
	{"time_", "time"},
	{"timestamp_", "forensic timeline"},
	{"timeline_", "forensic timeline"},
	{"bodyfile", "forensic timeline"},
	{"mactime", "forensic timeline"},
	// interchange schemas. "event" claims both event_kinds and events_from, and
	// nothing else in the tree begins with it.
	{"event", "schema interchange"},
	{"ecs_", "schema interchange"},
	{"ocsf_", "schema interchange"},
	{"timesketch_", "schema interchange"},
	{"stix_", "schema interchange"},
	// cryptography / fingerprinting
	{"x509_", "cryptography"},
	{"jwt_", "cryptography"},
	{"aes_", "cryptography"},
	{"pem_", "cryptography"},
	{"imphash", "fingerprinting"},
	{"nt_hash", "fingerprinting"},
	{"lm_hash", "fingerprinting"},
	{"ja3", "fingerprinting"},
	// policy / cache / custody. "case_" is listed before "cache_" only for
	// readability -- neither is a prefix of the other, so the order is free.
	{"policy_", "policy"},
	{"report_", "reporting"},
	{"case_", "chain of custody"},
	// class_ files with case_ because a classification label is a property of
	// the case rather than a type in the language. Position is free: of the
	// c-prefixes here (cidr_, csv_, cbor_, chan_, cmd_, crc32, case_, cache_)
	// none is a prefix of class_ and class_ is a prefix of none, so this is
	// adjacency for the reader -- the same reason the comment above gives.
	//
	// There is deliberately NO {"case_key_", ...} entry. CapabilityCategory
	// returns on the first prefix match, so "case_" above already claims all
	// four case_key_ builtins; an entry here would be a second line producing
	// the identical string, and one placed any later would be dead code.
	{"class_", "chain of custody"},
	// record_ is its own category and not "chain of custody". The custody
	// family documents what happened to evidence; this one encrypts it, and a
	// reader looking for what a classification costs should not have to find it
	// inside a section about manifests.
	{"record_", "classified records"},
	// The audit chain is the log behind the manifest's security counters, and
	// an examiner reads it beside the case documents rather than apart from
	// them, so it files under the same heading.
	{"audit_", "chain of custody"},
	{"cache_", "cache"},
	// system / process / memory forensics
	{"process_", "process forensics"},
	{"mem_", "memory forensics"},
	// registry forensics
	{"reg_", "registry forensics"},
	{"hive_", "registry forensics"},
	{"amcache_", "registry forensics"},
	{"shimcache_", "registry forensics"},
	// binary analysis
	{"bin_", "binary analysis"},
	{"go_", "binary analysis"},
	// email
	{"email_", "email forensics"},
	// detection
	{"detect_", "detection"},
	{"sigma_", "detection"},
	// windows execution artifacts
	{"prefetch_", "windows artifacts"},
	{"evtx_", "windows artifacts"},
	{"lnk_", "windows artifacts"},
	{"jumplist_", "windows artifacts"},
	{"syslog_", "unix artifacts"},
	{"browser_", "browser artifacts"},
	{"sqlite_", "browser artifacts"},
	// filesystem
	{"fs_", "filesystem"},
	{"mft_", "filesystem forensics"},
	{"ntfs_", "filesystem forensics"},
	{"fat_", "filesystem forensics"},
	{"xfat_", "filesystem forensics"},
	{"ext_", "filesystem forensics"},
	{"hfs_", "filesystem forensics"},
	{"xfs_", "filesystem forensics"},
	// disk images / partition tables
	{"vhdi_", "disk image forensics"},
	{"ewf_", "disk image forensics"},
	{"raw_", "disk image forensics"},
	{"table_", "disk image forensics"},
	// archives
	{"zip_", "archives"},
	{"tar_", "archives"},
	// bytes
	{"bytes_", "bytes"},
}

// CapabilityCategory returns a human-readable capability category for a builtin
// (e.g. "filesystem", "network", "graph database"), derived from its name. It is
// used by the LSP to enrich hover and completion detail. Unclassified builtins
// (core language primitives, functional collections, etc.) return
// "standard library".
func CapabilityCategory(name string) string {
	for _, c := range capabilityCategories {
		if strings.HasPrefix(name, c.prefix) {
			return c.category
		}
	}
	return "standard library"
}
