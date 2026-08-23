package builtin

import "strings"

// ParamKind names a value type a builtin parameter accepts. The values are
// deliberately the object type names the language already shows users through
// `type_of` (INTEGER, STRING, ARRAY, ...) so a diagnostic can say "expects
// STRING, got INTEGER" in the same words the runtime does.
//
// Note there is no BYTES kind: Mutant represents byte buffers as STRING values
// (see requireBytesStringArg in bytes.go), so a "bytes" parameter declares
// ParamString and explains itself in prose.
type ParamKind string

const (
	// ParamAny records that a parameter genuinely accepts any value — a
	// verified fact, distinct from a parameter whose kinds are simply not
	// declared yet (an empty set). Consumers must never type-check against it.
	ParamAny    ParamKind = "ANY"
	ParamInt    ParamKind = "INTEGER"
	ParamFloat  ParamKind = "FLOAT"
	ParamString ParamKind = "STRING"
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
		param("data", "Source byte string.", ParamString),
		param("offset", "Offset to read from.", ParamInt),
	}
}

func bytesWriteParams() []builtinParamDoc {
	return []builtinParamDoc{
		param("data", "Byte string to write into; a modified copy is returned.", ParamString),
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
		// and Hash. "bytes" is not a separate kind — Mutant carries byte
		// buffers in STRING values.
		summary: "Returns the length of a string, array, hash, or bytes value.",
		params:  []builtinParamDoc{param("value", "String, array, hash, or bytes value to measure.", ParamString, ParamArray, ParamHash)},
		returns: ret("the length of a string, array, hash, or bytes value", ParamInt)},
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
	// Every fs_* argument is asserted to *object.String in builtin/fs.go —
	// paths and payloads alike, since byte payloads travel as STRING values.
	BuiltinNameFsRead: {
		signature: "fs_read(path)", summary: "Reads file contents from disk.",
		params:  []builtinParamDoc{param("path", "Path to file.", ParamString)},
		returns: pairRet("the file's bytes", ParamString)},
	BuiltinNameFsWrite: {
		signature: "fs_write(path, data)", summary: "Writes data to a file, replacing existing contents.",
		params: []builtinParamDoc{
			param("path", "Path to file.", ParamString),
			param("data", "String/bytes payload.", ParamString),
		},
		returns: pairRet("true once the file has been written", ParamBool)},
	BuiltinNameFsAppend: {
		signature: "fs_append(path, data)", summary: "Appends data to the end of a file.",
		params: []builtinParamDoc{
			param("path", "Path to file.", ParamString),
			param("data", "String/bytes payload.", ParamString),
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
		params: []builtinParamDoc{param("value", "Value to serialize: a scalar, null, array, or hash with string keys.",
			ParamString, ParamInt, ParamFloat, ParamBool, ParamNull, ParamArray, ParamHash)},
		returns: pairRet("the JSON text", ParamString)},
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
		params:  []builtinParamDoc{param("s", "String or bytes to digest.", ParamString)},
		returns: ret("the lowercase hex MD5 digest of s", ParamString)},
	BuiltinNameHashSHA1: {
		signature: "hash_sha1(s)", summary: "Returns the lowercase hex SHA-1 digest of s.",
		params:  []builtinParamDoc{param("s", "String or bytes to digest.", ParamString)},
		returns: ret("the lowercase hex SHA-1 digest of s", ParamString)},
	BuiltinNameHashSHA256: {
		signature: "hash_sha256(s)", summary: "Returns the lowercase hex SHA-256 digest of s.",
		params:  []builtinParamDoc{param("s", "String or bytes to digest.", ParamString)},
		returns: ret("the lowercase hex SHA-256 digest of s", ParamString)},
	BuiltinNameHashSHA512: {
		signature: "hash_sha512(s)", summary: "Returns the lowercase hex SHA-512 digest of s.",
		params:  []builtinParamDoc{param("s", "String or bytes to digest.", ParamString)},
		returns: ret("the lowercase hex SHA-512 digest of s", ParamString)},
	BuiltinNameHashCRC32: {
		signature: "hash_crc32(s)", summary: "Returns the CRC-32 (IEEE) checksum of s as 8 hex chars.",
		params:  []builtinParamDoc{param("s", "String or bytes to checksum.", ParamString)},
		returns: ret("the CRC-32 (IEEE) checksum of s as 8 hex chars", ParamString)},
	BuiltinNameHashBlake2: {
		signature: "hash_blake2(s)", summary: "Returns the lowercase hex BLAKE2b-256 digest of s.",
		params:  []builtinParamDoc{param("s", "String or bytes to digest.", ParamString)},
		returns: ret("the lowercase hex BLAKE2b-256 digest of s", ParamString)},
	BuiltinNameHMAC: {
		signature: "hmac(key, message, algo)", summary: "Returns the hex HMAC of message under key. algo is md5/sha1/sha256/sha512.",
		params: []builtinParamDoc{
			param("key", "Secret key.", ParamString),
			param("message", "Message to authenticate.", ParamString),
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
	BuiltinNameBase64Encode:    {signature: "base64_encode(s)", summary: "Standard base64-encodes s.", params: []builtinParamDoc{param("s", "String or bytes to encode.", ParamString)}, returns: ret("the standard base64 text", ParamString)},
	BuiltinNameBase64Decode:    {signature: "base64_decode(s)", summary: "Decodes standard base64; returns (bytes, err).", params: []builtinParamDoc{param("s", "Standard base64 text.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameBase64URLEncode: {signature: "base64url_encode(s)", summary: "URL-safe base64-encodes s.", params: []builtinParamDoc{param("s", "String or bytes to encode.", ParamString)}, returns: ret("the URL-safe base64 text", ParamString)},
	BuiltinNameBase64URLDecode: {signature: "base64url_decode(s)", summary: "Decodes URL-safe base64; returns (bytes, err).", params: []builtinParamDoc{param("s", "URL-safe base64 text.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameBase32Encode:    {signature: "base32_encode(s)", summary: "Standard base32-encodes s.", params: []builtinParamDoc{param("s", "String or bytes to encode.", ParamString)}, returns: ret("the standard base32 text", ParamString)},
	BuiltinNameBase32Decode:    {signature: "base32_decode(s)", summary: "Decodes standard base32; returns (bytes, err).", params: []builtinParamDoc{param("s", "Standard base32 text.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameHexEncode:       {signature: "hex_encode(s)", summary: "Hex-encodes a byte string to lowercase hex.", params: []builtinParamDoc{param("s", "String or bytes to encode.", ParamString)}, returns: ret("the lowercase hex text", ParamString)},
	BuiltinNameHexDecode:       {signature: "hex_decode(s)", summary: "Decodes a hex string to bytes; returns (bytes, err).", params: []builtinParamDoc{param("s", "Hex text to decode.", ParamString)}, returns: pairRet("the decoded bytes", ParamString)},
	BuiltinNameURLEncode:       {signature: "url_encode(s)", summary: "URL query-escapes s.", params: []builtinParamDoc{param("s", "Text to escape.", ParamString)}, returns: ret("the query-escaped text", ParamString)},
	BuiltinNameURLDecode:       {signature: "url_decode(s)", summary: "URL query-unescapes s; returns (value, err).", params: []builtinParamDoc{param("s", "Escaped text to unescape.", ParamString)}, returns: pairRet("the unescaped text", ParamString)},
	BuiltinNameGzip:            {signature: "gzip(s)", summary: "Gzip-compresses s (returns a byte string).", params: []builtinParamDoc{param("s", "String or bytes to compress.", ParamString)}, returns: ret("the compressed bytes", ParamString)},
	BuiltinNameGunzip:          {signature: "gunzip(s)", summary: "Gzip-decompresses s; returns (bytes, err).", params: []builtinParamDoc{param("s", "Gzip-compressed bytes.", ParamString)}, returns: pairRet("the decompressed bytes", ParamString)},
	BuiltinNameZlibCompress:    {signature: "zlib_compress(s)", summary: "Zlib-compresses s (returns a byte string).", params: []builtinParamDoc{param("s", "String or bytes to compress.", ParamString)}, returns: ret("the compressed bytes", ParamString)},
	BuiltinNameZlibDecompress:  {signature: "zlib_decompress(s)", summary: "Zlib-decompresses s; returns (bytes, err).", params: []builtinParamDoc{param("s", "Zlib-compressed bytes.", ParamString)}, returns: pairRet("the decompressed bytes", ParamString)},
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
		signature: "chan_new(capacity?)", summary: "Creates a channel for passing values between concurrently running code and returns its handle. Capacity 0 (the default) is unbuffered, so a send waits for a receive; a positive capacity lets that many values queue first.",
		params: []builtinParamDoc{
			param("capacity?", "How many values may queue before a send waits; 0 for unbuffered.", ParamInt),
		},
		returns: pairRet("a channel handle; close it with chan_close", ParamInt)},
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
		signature: "chan_close(handle)", summary: "Closes a channel, waking every waiting sender and receiver. Returns true when this call did the closing and false when the channel was already closed. Receivers can still drain values that were already queued.",
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
	BuiltinNameHiveListValues:     {signature: "hive_list_values(handle, keypath?)", summary: "Returns a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Returns (array, err).", returns: pairRet("one hash per value, with its type and decoded data (REG_SZ/DWORD/QWORD/MULTI_SZ decoded, binary as hex)", ParamArray).ofElem(ParamHash).withFields("data", "name", "type"), params: []builtinParamDoc{param("handle", "Handle from hive_open.", ParamString), param("keypath?", "Key path under the opened root, backslash-separated; defaults to the root.", ParamString)}},
	BuiltinNameHiveGetValue:       {signature: "hive_get_value(handle, keypath, name)", summary: "Returns {name, type, data} for a single value under keypath. Returns (result, err).", returns: pairRet("the value stored under name, with its registry type", ParamHash).withFields("data", "name", "type"), params: []builtinParamDoc{param("handle", "Handle from hive_open.", ParamString), param("keypath", "Key path holding the value, backslash-separated under the opened root.", ParamString), param("name", "Value name to read; \"\" reads the key's default value.", ParamString)}},
	BuiltinNameShimcacheParse:     {signature: "shimcache_parse(path)", summary: "Decodes the Windows AppCompatCache (shimcache) — program execution/presence evidence. Accepts a SYSTEM hive file (locates the value) or a raw AppCompatCache blob. Supports Win8/Win8.1/Win10 (10ts/00ts). Returns {version, count, entries:[{position, path, last_modified, last_modified_iso}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "SYSTEM hive file or raw AppCompatCache blob.", ParamString)}, returns: pairRet("the parsed AppCompatCache entries", ParamHash)},
	BuiltinNameAmcacheParse:       {signature: "amcache_parse(path)", summary: "Parses an Amcache.hve hive (program execution/presence evidence) into {format, count, entries:[{key, path, name, sha1, publisher, version, product, size, last_write}]}. Supports the modern InventoryApplicationFile and legacy Root\\File layouts. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to an Amcache.hve hive file.", ParamString)}, returns: pairRet("the parsed Amcache entries", ParamHash)},
	BuiltinNamePrefetchParse:      {signature: "prefetch_parse(path)", summary: "Decodes a Windows Prefetch (.pf) file — program execution evidence. Transparently decompresses the Win10/11 MAM (Xpress-Huffman) container and parses the SCCA format for XP (v17), Vista/7 (v23), Win8.1 (v26), and Win10/11 (v30/v31). Returns {version, executable, prefetch_hash, run_count, run_times[], files_loaded[], file_count, volumes:[{device_path, serial, created, created_iso}], compressed}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .pf prefetch file (compressed or raw SCCA).", ParamString)}, returns: pairRet("the execution evidence the .pf file records", ParamHash).withFields("created", "created_iso", "device_path", "serial")},
	BuiltinNameMftParse:           {signature: "mft_parse(path)", summary: "Parses an NTFS Master File Table into a per-record timeline. Auto-detects a standalone $MFT file (FILE-signature record stream, e.g. KAPE/FTK/icat) vs a full NTFS volume image. Each entry has $STANDARD_INFORMATION (si_*) and $FILE_NAME (fn_*) MAC times as unix seconds, a sub-second nanosecond fraction (si_*_ns/fn_*_ns, 0-999999999, at NTFS 100 ns resolution — a whole-second/zero fraction is a timestomping tell), and an RFC3339Nano iso string; plus reconstructed path, size, sequence, and hard-link count. The record size is read from the first record header rather than assumed, and skipped counts records that would not parse. Returns {source_type, record_size, count, skipped, entries:[{record, parent_record, in_use, is_directory, name, path, size, allocated_size, sequence, hard_links, file_attributes, si_*, si_*_ns, fn_*, fn_*_ns}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a standalone $MFT file or an NTFS volume image.", ParamString)}, returns: pairRet("the parsed $MFT records", ParamHash).withFields("count", "entries", "record_size", "skipped", "source_type")},
	BuiltinNameEvtxParse:          {signature: "evtx_parse(path)", summary: "Parses a Windows Event Log (.evtx). Walks every chunk and decodes each record's BinXML (templates + substitutions) into the fully-expanded event tree, plus summary fields per record. Returns {source, chunk_count, count, records:[{record_id, timestamp, timestamp_iso, event_id, event_record_id, level, channel, computer, provider, event}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .evtx Windows Event Log file.", ParamString)}, returns: pairRet("the decoded event records", ParamHash).withFields("chunk_count", "count", "records", "source")},
	BuiltinNameJumplistParse:      {signature: "jumplist_parse(path)", summary: "Parses a Windows Jump List (recent/pinned destinations). Auto-detects *.automaticDestinations-ms (OLE compound file: numbered shell-link streams + a DestList MRU/metadata stream) and *.customDestinations-ms (concatenated shell links). Each entry merges DestList metadata (last_access, pinned, hostname) with the embedded shell-link target. Returns {type, format_version, entry_count, pinned_count, entries:[{stream_id, target, arguments, working_dir, name, last_access, last_access_iso, pinned, hostname}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .automaticDestinations-ms or .customDestinations-ms jump list.", ParamString)}, returns: pairRet("the parsed Jump List destinations", ParamHash).withFields("entries", "entry_count", "format_version", "pinned_count", "type")},
	BuiltinNameSyslogParse:        {signature: "syslog_parse(path)", summary: "Parses a Unix syslog file into structured entries, auto-detecting RFC 5424 (IETF, ISO-8601) and RFC 3164 (BSD) per line; unmatched lines are kept as raw messages. RFC 3164 lines omit the year, so the current year is assumed. Each entry has a `ts` unix field for timeline_merge/timeline_sort. Returns {count, entries:[{format, priority, facility, severity, timestamp, ts, host, app_name, pid, msgid, structured_data, message}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a syslog text file (RFC 3164 or RFC 5424).", ParamString)}, returns: pairRet("the parsed syslog entries", ParamHash).withFields("count", "entries")},
	BuiltinNameSqliteQuery:        {signature: "sqlite_query(path, sql, params?)", summary: "Runs a read-only SQL query against a SQLite database, pure-Go (no cgo). The database (+ any -wal/-shm sidecars) is copied to a temp file first, so the original is never modified or lock-contended — safe for forensic DBs held open by a running app. Optional params is an ARRAY of bind values for a parameterized query. Returns {columns, row_count, truncated, rows:[{col: value}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a SQLite database file.", ParamString), param("sql", "SQL query to run.", ParamString), param("params?", "Optional ARRAY of bind parameters.", ParamArray)}, returns: pairRet("the query's columns and rows", ParamHash).withFields("columns", "row_count", "rows", "truncated")},
	BuiltinNameBrowserHistory:     {signature: "browser_history(path)", summary: "Parses a Chromium (History) or Firefox (places.sqlite) history database into normalized visit entries, auto-detecting the schema and converting timestamps to unix. Returns {browser, count, entries:[{url, title, visit_count, last_visit, last_visit_iso, browser}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Chromium History or Firefox places.sqlite database.", ParamString)}, returns: pairRet("the normalized visit entries", ParamHash)},
	BuiltinNameBrowserCookies:     {signature: "browser_cookies(path)", summary: "Parses a Chromium (Cookies) or Firefox (cookies.sqlite) cookie database. Chromium cookie values are OS-encrypted; such rows are reported with encrypted=true and an empty value (decryption needs OS keys). Returns {browser, count, entries:[{host, name, value, path, expires, expires_iso, secure, http_only, encrypted, browser}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Chromium Cookies or Firefox cookies.sqlite database.", ParamString)}, returns: pairRet("the parsed cookie records", ParamHash)},
	BuiltinNameBrowserDownloads:   {signature: "browser_downloads(path)", summary: "Parses download records from a Chromium (History downloads table) or Firefox (places.sqlite moz_annos) database; Firefox support is best-effort (destination file URI). Returns {browser, count, entries:[{url, target_path, bytes_total, bytes_received, start_time, end_time, state, mime_type, browser}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a Chromium History or Firefox places.sqlite database.", ParamString)}, returns: pairRet("the parsed download records", ParamHash)},
	BuiltinNameFsDeleted:          {signature: "fs_deleted(path)", summary: "Enumerates deleted files from an NTFS $MFT (a standalone $MFT file or a full volume image, auto-detected). A record is deleted when its in-use flag is clear but its metadata still parses. Small files with a resident $DATA attribute are fully recovered (resident_data, hex-encoded); larger non-resident files report metadata only. SI/FN times include unix seconds, a sub-second nanosecond fraction (si_*_ns/fn_*_ns), and an RFC3339Nano iso string. Returns {source_type, deleted_count, skipped, entries:[{record, name, path, size, is_directory, has_data, resident, recoverable, resident_data, si_*, si_*_ns, fn_*, fn_*_ns}]}. Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a standalone $MFT file or an NTFS volume image.", ParamString)}, returns: pairRet("the recovered deleted entries and how many were skipped", ParamHash).withFields("deleted_count", "entries", "skipped", "source_type")},
	BuiltinNameLnkParse:           {signature: "lnk_parse(path)", summary: "Parses a Windows shell link (.lnk): header (attributes, creation/access/write FILETIME->unix), decoded LinkFlags, LinkInfo local_base_path (target), and StringData (name, relative_path, working_dir, arguments, icon_location). Returns (result, err).", params: []builtinParamDoc{param("path", "Path to a .lnk shell link file.", ParamString)}, returns: pairRet("the shell link's header, target, and tracker fields", ParamHash)},
	BuiltinNameMactime:            {signature: "mactime(entries)", summary: "Builds a chronological MAC-time timeline from bodyfile_parse entries: one row per distinct time with a MACB flag string (m/a/c/b, \".\" where absent), sorted by ts then name (ts field composes with timeline_merge).", returns: ret("one row per distinct timestamp, in chronological order", ParamArray).ofElem(ParamHash).withFields("gid", "inode", "iso", "macb", "md5", "mode", "name", "size", "ts", "uid"), params: []builtinParamDoc{param("entries", "Entries from bodyfile_parse.", ParamArray)}},
	// security: fingerprinting
	BuiltinNameImphash: {signature: "imphash(pe_path)", summary: "Computes the PE import hash (pefile/Mandiant algorithm) for malware clustering. Returns {imphash, import_count, dll_count}. Note: ordinal-only imports are rendered as ord<N>, so results may differ from VT for ws2_32/oleaut32 ordinal imports. Returns (result, err).", params: []builtinParamDoc{param("pe_path", "Path to a PE (Windows) binary.", ParamString)}, returns: pairRet("the PE import hash and the counts it was computed over", ParamHash).withFields("dll_count", "imphash", "import_count")},
	BuiltinNameNTHash:  {signature: "nt_hash(password)", summary: "Returns the NTLM NT hash (MD4 of the UTF-16LE password) as hex. For authorized credential testing/CTF use.", returns: ret("the NTLM NT hash (MD4 of the UTF-16LE password) as hex", ParamString), params: []builtinParamDoc{param("password", "Password to hash.", ParamString)}},
	BuiltinNameLMHash:  {signature: "lm_hash(password)", summary: "Returns the legacy LM hash (DES-based; case-insensitive, max 14 chars) as hex. Empty password -> aad3b435b51404eeaad3b435b51404ee.", returns: ret("the legacy LM hash (DES-based; case-insensitive, max 14 chars) as hex", ParamString), params: []builtinParamDoc{param("password", "Password to hash.", ParamString)}},
	BuiltinNameJA3:     {signature: "ja3(client_hello)", summary: "Computes the JA3 TLS-client fingerprint from a ClientHello (raw bytes, with or without the TLS record layer). Hashes version,ciphers,extensions,curves,point_formats with GREASE (RFC 8701) removed. Returns {ja3, ja3_hash (md5), tls_version, ciphers[], extensions[], curves[], point_formats[]}. Returns (result, err).", params: []builtinParamDoc{param("client_hello", "Raw bytes of a TLS ClientHello (optionally wrapped in its record layer).", ParamString)}, returns: pairRet("the JA3 string and its MD5 hash, plus the fields they were built from", ParamHash).withFields("ciphers", "curves", "extensions", "ja3", "ja3_hash", "point_formats", "tls_version")},
	// security: crypto
	BuiltinNameX509Parse:  {signature: "x509_parse(pem_or_der)", summary: "Parses an X.509 certificate (PEM or DER). Returns {subject, issuer, serial, not_before, not_after, is_ca, version, dns_names, ip_addresses, email_addresses, key_algorithm, signature_algorithm, sha1, sha256}. Returns (cert, err).", params: []builtinParamDoc{param("pem_or_der", "Certificate bytes in PEM or DER form.", ParamString)}, returns: pairRet("the certificate's subject, issuer, validity window, and fingerprints", ParamHash).withFields("dns_names", "email_addresses", "ip_addresses", "is_ca", "issuer", "key_algorithm", "not_after", "not_before", "serial", "sha1", "sha256", "signature_algorithm", "subject", "version")},
	BuiltinNameJWTDecode:  {signature: "jwt_decode(token)", summary: "Decodes a JWT's header and claims WITHOUT verifying the signature (verified is always false). Returns {header, claims, algorithm, signature_present, verified}. Returns (result, err).", params: []builtinParamDoc{param("token", "Compact JWT string (header.payload.signature).", ParamString)}, returns: pairRet("the token's header and claims; the signature is never verified", ParamHash).withFields("algorithm", "claims", "header", "signature_present", "verified")},
	BuiltinNameAESEncrypt: {signature: "aes_encrypt(key, plaintext)", summary: "AES-GCM encrypts plaintext. key must be 16/24/32 bytes. A random nonce is prepended to the output. Returns (ciphertext, err).", params: []builtinParamDoc{param("key", "16/24/32-byte key (AES-128/192/256).", ParamString), param("plaintext", "Data to encrypt.", ParamString)}, returns: pairRet("the ciphertext, with the random nonce prepended", ParamString)},
	BuiltinNameAESDecrypt: {signature: "aes_decrypt(key, ciphertext)", summary: "AES-GCM decrypts ciphertext produced by aes_encrypt (nonce-prefixed). Returns (plaintext, err); errors on wrong key or tampering.", params: []builtinParamDoc{param("key", "16/24/32-byte key.", ParamString), param("ciphertext", "Nonce-prefixed AES-GCM ciphertext.", ParamString)}, returns: pairRet("the recovered plaintext", ParamString)},
	BuiltinNamePEMDecode:  {signature: "pem_decode(s)", summary: "Decodes the first PEM block. Returns {type, headers, der_hex, size, remaining_bytes}. Returns (result, err).", returns: pairRet("the first PEM block, with its DER body hex-encoded", ParamHash).withFields("der_hex", "headers", "remaining_bytes", "size", "type"), params: []builtinParamDoc{param("s", "PEM text to decode.", ParamString)}},
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
	BuiltinNameNetSynScan:     {signature: "net_syn_scan(host, startPort, endPort, timeoutMs)", summary: "DEPRECATED alias of net_connect_scan. This is a full TCP connect scan, not a half-open SYN scan; use net_connect_scan.", params: []builtinParamDoc{param("host", "Target host.", ParamString), param("startPort", "First port (inclusive).", ParamInt), param("endPort", "Last port (inclusive).", ParamInt), param("timeoutMs", "Per-port connect timeout in ms.", ParamInt)}, returns: pairRet("which ports answered, and how long the scan took", ParamHash).withFields("duration_ms", "end_port", "host", "open_ports", "scanned", "start_port")},
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
		summary:   "Enumerates a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Works across JSON/hive-file/live sources. Returns (array, err).",
		params: []builtinParamDoc{
			param("handle", "Handle returned by reg_open.", ParamString),
			param("keyPath?", "Key path (default: the opened key/root).", ParamString),
		},
		returns: pairRet("one hash per value, with its type and decoded data", ParamArray).ofElem(ParamHash).withFields("data", "name", "type")},
	BuiltinNameRegGetValue: {
		signature: "reg_get_value(handle, keyPath, valueName)",
		summary:   "Reads a specific registry value with type metadata, across JSON/hive-file/live sources. Returns (result, err).",
		params: []builtinParamDoc{
			param("handle", "Handle returned by reg_open.", ParamString),
			param("keyPath", "Key path that contains the value.", ParamString),
			param("valueName", "Registry value name to fetch.", ParamString),
		},
		returns: pairRet("the value, with its registry type", ParamHash).withFields("data", "name", "type")},
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
		returns:   pairRet("the normalized URLs found in the message", ParamArray).ofElem(ParamString)},
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
	BuiltinNameNetResolve:    {signature: "net_resolve(host)", summary: "Resolves a host name to network addresses.", returns: pairRet("the addresses the host resolves to", ParamArray).ofElem(ParamString), params: []builtinParamDoc{param("host", "Host name to resolve.", ParamString)}},
	BuiltinNameNetDial:       {signature: "net_dial(address, timeoutMs)", summary: "Connectivity probe: dials address, immediately closes, and returns {ok, latency_ms, error}. Does not return a usable connection (use net_connect for that).", params: []builtinParamDoc{param("address", "host:port endpoint.", ParamString), param("timeoutMs", "Dial timeout in ms.", ParamInt)}, returns: pairRet("whether the address answered, and how long it took", ParamHash).withFields("error", "latency_ms", "ok")},
	BuiltinNameDbOpen:        {signature: "db_open()", summary: "Creates an in-memory graph database handle.", returns: pairRet("a handle for the other db_ builtins; close it with db_close", ParamInt)},
	BuiltinNameDbOpenDisk:    {signature: "db_open_disk(path)", summary: "Opens or creates a disk-backed graph database. Note that compacting a store with this build rewrites it in a newer on-disk format that older mutant builds cannot open.", params: []builtinParamDoc{param("path", "Database file path.", ParamString)}, returns: pairRet("a handle for the other db_ builtins; close it with db_close", ParamInt)},
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
	// A "bytes value" is a STRING: requireBytesStringArg (builtin/bytes.go)
	// asserts *object.String and there is no separate byte-buffer object type.
	// Offsets and widths go through requireNonNegativeOffset /
	// requireIntegerWithinRange, both of which require INTEGER. A cursor is a
	// HASH with `data` and `offset` fields (requireBytesCursor).
	BuiltinNameBytesLen: {
		signature: "bytes_len(data)", summary: "Returns length of a bytes value.",
		params:  []builtinParamDoc{param("data", "Byte string to measure.", ParamString)},
		returns: pairRet("length of a bytes value", ParamInt)},
	BuiltinNameBytesGet: {
		signature: "bytes_get(data, index)", summary: "Reads one byte at index as integer.",
		params: []builtinParamDoc{
			param("data", "Source byte string.", ParamString),
			param("index", "Zero-based byte offset.", ParamInt),
		},
		returns: pairRet("the byte at index, as an integer from 0 to 255", ParamInt)},
	BuiltinNameBytesSlice: {
		signature: "bytes_slice(data, start, length)", summary: "Returns a byte sub-slice of the given length starting at start (i.e. data[start:start+length]).",
		params: []builtinParamDoc{
			param("data", "Source byte string.", ParamString),
			param("start", "Start offset.", ParamInt),
			param("length", "Number of bytes to take.", ParamInt),
		},
		returns: pairRet("a byte sub-slice of the given length starting at start (i", ParamString)},
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
			param("data", "Source byte string.", ParamString),
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
		returns: pairRet("a copy of data with the little-endian unsigned 16-bit integer written at offset", ParamString)},
	BuiltinNameBytesWriteU16Be: {
		signature: "bytes_write_u16_be(data, offset, value)", summary: "Writes unsigned 16-bit big-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the big-endian unsigned 16-bit integer written at offset", ParamString)},
	BuiltinNameBytesWriteU32Le: {
		signature: "bytes_write_u32_le(data, offset, value)", summary: "Writes unsigned 32-bit little-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the little-endian unsigned 32-bit integer written at offset", ParamString)},
	BuiltinNameBytesWriteU32Be: {
		signature: "bytes_write_u32_be(data, offset, value)", summary: "Writes unsigned 32-bit big-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the big-endian unsigned 32-bit integer written at offset", ParamString)},
	BuiltinNameBytesWriteU64Le: {
		signature: "bytes_write_u64_le(data, offset, value)", summary: "Writes unsigned 64-bit little-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the little-endian unsigned 64-bit integer written at offset", ParamString)},
	BuiltinNameBytesWriteU64Be: {
		signature: "bytes_write_u64_be(data, offset, value)", summary: "Writes unsigned 64-bit big-endian integer into bytes at offset.",
		params:  bytesWriteParams(),
		returns: pairRet("a copy of data with the big-endian unsigned 64-bit integer written at offset", ParamString)},
	BuiltinNameBytesCursorNew: {
		signature: "bytes_cursor_new(data)", summary: "Creates a cursor for structured byte parsing.",
		params:  []builtinParamDoc{param("data", "Byte string to read through.", ParamString)},
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
	BuiltinNameServeArg:       {signature: "serve_arg()", summary: "Inside a net_serve handler, returns the shared arg passed to net_serve; null otherwise.", returns: pairRet("the shared arg passed to net_serve, or null outside a handler", ParamNull)},
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
	BuiltinNameNtfsOpen:      {signature: "ntfs_open(image)", summary: "Opens an NTFS filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to an NTFS image/partition.", ParamString)}, returns: pairRet("a handle for the other ntfs_ builtins; release it with ntfs_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameNtfsListFiles: {signature: "ntfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened NTFS image.", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("dir", "Directory path within the image.", ParamString)}, returns: pairRet("one hash per directory entry, including deleted ones", ParamArray).ofElem(ParamHash).withFields("allocated_size", "deleted", "entry_num", "is_dir", "name", "path", "sequence_num", "size")},
	BuiltinNameNtfsReadFile:  {signature: "ntfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened NTFS image.", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "File path within the image.", ParamString)}, returns: pairRet("the file's bytes", ParamString)},
	BuiltinNameNtfsMetadata:  {signature: "ntfs_metadata(handle, path)", summary: "Returns metadata for a file/directory in an opened NTFS image, including the $STANDARD_INFORMATION created_at/modified_at/accessed_at/changed_at times and the readability flags (resident, sparse, compressed, encrypted, blocking_error).", params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString), param("path", "Path within the image.", ParamString)}, returns: pairRet("metadata for a file/directory in an opened NTFS image, including the $STANDARD_INFORMATION created_at/modified_at/accessed_at/changed_at times and the readability flags (resident, sparse, compressed, encrypted, blocking_error)", ParamHash).withFields("accessed_at", "blocking_error", "changed_at", "compressed", "created_at", "encrypted", "entry_num", "has_data", "is_dir", "modified_at", "name", "non_resident", "path", "readable", "resident", "size", "sparse")},
	BuiltinNameNtfsClose:     {signature: "ntfs_close(handle)", summary: "Closes an NTFS handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from ntfs_open.", ParamString)}},
	BuiltinNameFatOpen:       {signature: "fat_open(image)", summary: "Opens a FAT filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to a FAT image/partition.", ParamString)}, returns: pairRet("a handle for the other fat_ builtins; release it with fat_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameFatListFiles:  {signature: "fat_list_files(handle, dir)", summary: "Lists entries under a directory in an opened FAT image.", returns: pairRet("one hash per directory entry, including deleted and recovered ones", ParamArray).ofElem(ParamHash).withFields("accessed_at", "attributes", "cluster_allocated", "created_at", "deleted", "first_cluster", "is_dir", "modified_at", "name", "path", "recovered", "short_name", "size", "virtual"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameFatReadFile:   {signature: "fat_read_file(handle, path)", summary: "Reads a file's bytes from an opened FAT image.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString)}},
	BuiltinNameFatMetadata:   {signature: "fat_metadata(handle, path)", summary: "Returns metadata for a path in an opened FAT image.", returns: pairRet("metadata for a path in an opened FAT image", ParamHash).withFields("accessed_at", "attributes", "bytes_per_sector", "cluster_count", "cluster_size", "created_at", "deleted", "filesystem", "first_cluster", "is_dir", "modified_at", "name", "path", "recovered", "short_name", "size", "virtual", "volume_label"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString), param("path", "Path inside the FAT image.", ParamString)}},
	BuiltinNameFatClose:      {signature: "fat_close(handle)", summary: "Closes a FAT handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from fat_open.", ParamString)}},
	BuiltinNameXfatOpen:      {signature: "xfat_open(image)", summary: "Opens an exFAT filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to an exFAT image/partition.", ParamString)}, returns: pairRet("a handle for the other xfat_ builtins; release it with xfat_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameXfatListFiles: {signature: "xfat_list_files(handle, dir)", summary: "Lists entries under a directory in an opened exFAT image, with created_at/modified_at/accessed_at, per-timestamp *_utc_offset_valid flags, attributes and valid_data_size. A nameless entry is reported as \"(unnamed)\".", returns: pairRet("one hash per directory entry", ParamArray).ofElem(ParamHash), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameXfatReadFile:  {signature: "xfat_read_file(handle, path)", summary: "Reads a file's bytes from an opened exFAT image. Content is staged through a temporary file because libxfat extracts to a path, so reads are capped at 32 MiB.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString)}},
	BuiltinNameXfatMetadata:  {signature: "xfat_metadata(handle, path)", summary: "Returns metadata for a path in an opened exFAT image, including created_at/modified_at/accessed_at with *_utc_offset_valid flags, attributes and valid_data_size (the written portion of size; the remainder is slack).", returns: pairRet("metadata for a path in an opened exFAT image, including created_at/modified_at/accessed_at with *_utc_offset_valid flags, attributes and valid_data_size (the written portion of size; the remainder is slack)", ParamHash), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString), param("path", "Path inside the exFAT image.", ParamString)}},
	BuiltinNameXfatClose:     {signature: "xfat_close(handle)", summary: "Closes an exFAT handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from xfat_open.", ParamString)}},
	BuiltinNameExtOpen:       {signature: "ext_open(image)", summary: "Opens an ext2/3/4 filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to an ext image/partition.", ParamString)}, returns: pairRet("a handle for the other ext_ builtins; release it with ext_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameExtListFiles:  {signature: "ext_list_files(handle, dir)", summary: "Lists entries under a directory in an opened ext image, with created_at/modified_at/accessed_at/changed_at and deleted.", returns: pairRet("one hash per directory entry, including deleted ones", ParamArray).ofElem(ParamHash).withFields("accessed_at", "changed_at", "created_at", "deleted", "inode", "is_dir", "modified_at", "name", "path", "size"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameExtReadFile:   {signature: "ext_read_file(handle, path)", summary: "Reads a file's bytes from an opened ext image.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext2/3/4 image.", ParamString)}},
	BuiltinNameExtMetadata:   {signature: "ext_metadata(handle, path)", summary: "Returns metadata for a path in an opened ext image, including created_at/modified_at/accessed_at/changed_at, deleted, and warnings (where the parser judged the answer may be incomplete).", returns: pairRet("metadata for a path in an opened ext image, including created_at/modified_at/accessed_at/changed_at, deleted, and warnings (where the parser judged the answer may be incomplete)", ParamHash).withFields("accessed_at", "block_size", "changed_at", "created_at", "deleted", "inode", "inodes_count", "is_dir", "kind", "modified_at", "name", "path", "size", "warnings"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString), param("path", "Path inside the ext2/3/4 image.", ParamString)}},
	BuiltinNameExtClose:      {signature: "ext_close(handle)", summary: "Closes an ext handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from ext_open.", ParamString)}},
	BuiltinNameHfsOpen:       {signature: "hfs_open(image)", summary: "Opens an HFS+ filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to an HFS+ image/partition.", ParamString)}, returns: pairRet("a handle for the other hfs_ builtins; release it with hfs_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameHfsListFiles:  {signature: "hfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened HFS+ image.", returns: pairRet("one hash per directory entry", ParamArray).ofElem(ParamHash).withFields("cnid", "is_dir", "is_system", "name", "path"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameHfsReadFile:   {signature: "hfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened HFS+ image.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString)}},
	BuiltinNameHfsMetadata:   {signature: "hfs_metadata(handle, path)", summary: "Returns metadata for a path in an opened HFS+ image, including created_at/modified_at/accessed_at/changed_at/backup_at, time_source (HFS+ GMT vs classic-HFS local wall clock), compressed, compression_type and resource_fork_size.", returns: pairRet("metadata for a path in an opened HFS+ image, including created_at/modified_at/accessed_at/changed_at/backup_at, time_source (HFS+ GMT vs classic-HFS local wall clock), compressed, compression_type and resource_fork_size", ParamHash).withFields("accessed_at", "backup_at", "block_size", "changed_at", "cnid", "compressed", "compression_type", "created_at", "file_count", "folder_count", "free_blocks", "is_dir", "kind", "modified_at", "name", "path", "resource_fork_size", "size", "time_source", "total_blocks"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString), param("path", "Path inside the HFS+ image.", ParamString)}},
	BuiltinNameHfsClose:      {signature: "hfs_close(handle)", summary: "Closes an HFS+ handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from hfs_open.", ParamString)}},
	BuiltinNameXfsOpen:       {signature: "xfs_open(image)", summary: "Opens an XFS filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to an XFS image/partition.", ParamString)}, returns: pairRet("a handle for the other xfs_ builtins; release it with xfs_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameXfsListFiles:  {signature: "xfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened XFS image, with file_type from the directory record. A damaged inode no longer aborts the listing: that entry is reported with inode_error set and size 0.", returns: pairRet("one hash per directory entry", ParamArray).ofElem(ParamHash).withFields("file_type", "inode", "inode_error", "is_dir", "name", "path", "size"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("dir", "Directory to list, relative to the image root.", ParamString)}},
	BuiltinNameXfsReadFile:   {signature: "xfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened XFS image.", returns: pairRet("the file's bytes", ParamString), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString)}},
	BuiltinNameXfsMetadata:   {signature: "xfs_metadata(handle, path)", summary: "Returns metadata for a path in an opened XFS image, including created_at/modified_at/accessed_at/changed_at and needs_repair (the filesystem was left inconsistent and its metadata should be treated with suspicion).", returns: pairRet("metadata for a path in an opened XFS image, including created_at/modified_at/accessed_at/changed_at and needs_repair (the filesystem was left inconsistent and its metadata should be treated with suspicion)", ParamHash).withFields("accessed_at", "block_size", "changed_at", "created_at", "format_version", "inode", "inode_size", "is_dir", "modified_at", "name", "needs_repair", "path", "root_inode", "size", "volume_blocks"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString), param("path", "Path inside the XFS image.", ParamString)}},
	BuiltinNameXfsClose:      {signature: "xfs_close(handle)", summary: "Closes an XFS handle and releases its file.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from xfs_open.", ParamString)}},

	// disk-image parsers — *_read_at caps length at 32 MiB.
	BuiltinNameVhdiOpen:      {signature: "vhdi_open(image)", summary: "Opens a VHD/VHDX disk image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to a VHD/VHDX image.", ParamString)}, returns: pairRet("a handle for the other vhdi_ builtins; release it with vhdi_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameVhdiMetadata:  {signature: "vhdi_metadata(handle)", summary: "Returns VHD/VHDX metadata (format, disk_type, virtual_size, block/sector size, identifiers), the differencing-chain state (needs_parent, chain_complete, chain_depth, parent_resolve_error) and the VHDX log state (is_dirty, has_log, log_replayed).", returns: pairRet("vHD/VHDX metadata (format, disk_type, virtual_size, block/sector size, identifiers), the differencing-chain state (needs_parent, chain_complete, chain_depth, parent_resolve_error) and the VHDX log state (is_dirty, has_log, log_replayed)", ParamHash).withFields("block_size", "chain_complete", "chain_depth", "disk_type", "format", "has_log", "identifier", "is_differencing", "is_dirty", "log_replayed", "needs_parent", "parent_filename", "parent_identifier", "parent_resolve_error", "sector_size", "virtual_size"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString)}},
	BuiltinNameVhdiReadAt:    {signature: "vhdi_read_at(handle, offset, length)", summary: "Reads length bytes at a virtual offset from a VHD/VHDX image (length capped at 32 MiB).", returns: pairRet("the bytes read, up to the 32 MiB cap", ParamString), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameVhdiMapOffset: {signature: "vhdi_map_offset(handle, offset)", summary: "Maps a virtual offset to a backing file offset. Returns {virtual_offset, mapped, file_offset}.", returns: pairRet("where the virtual offset lands in the backing file", ParamHash).withFields("file_offset", "mapped", "virtual_offset"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString), param("offset", "Virtual byte offset to map into the backing file.", ParamInt)}},
	BuiltinNameVhdiClose:     {signature: "vhdi_close(handle)", summary: "Closes a VHD/VHDX handle.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from vhdi_open.", ParamString)}},
	// parseEWFSegmentPaths (disk_image_parsers.go) takes either a single path
	// or an array of them, and requires every array element to be a STRING.
	BuiltinNameEwfOpen: {
		signature: "ewf_open(segments)",
		summary:   "Opens an EWF/E01 image (a segment path or an array of segment paths). Returns (result, err).",
		params: []builtinParamDoc{{
			name:  "segments",
			doc:   "Segment file path or array of paths.",
			kinds: []ParamKind{ParamString, ParamArray},
			elem:  []ParamKind{ParamString},
		}},
		returns: pairRet("a handle for the other ewf_ builtins, and the segment count", ParamHash).withFields("handle", "segment_count", "status")},
	BuiltinNameEwfMetadata: {signature: "ewf_metadata(handle)", summary: "Returns EWF metadata (version, sectors/chunks, digests, media info, sector_size, compression_method). chunk_tables_invalid counts chunk-table groups that failed both their primary and backup checksum — their data decoded unverified and should be treated as suspect; chunk_tables_recovered, observed_chunk_count and acquisition_error_count report the rest of the integrity picture.", returns: pairRet("eWF metadata (version, sectors/chunks, digests, media info, sector_size, compression_method)", ParamHash).withFields("acquisition_error_count", "bytes_per_sector", "chunk_tables_invalid", "chunk_tables_recovered", "compression_method", "has_done_section", "has_integrity_hash", "has_md5_digest", "has_media", "has_next_section", "has_sha1_digest", "is_encrypted", "major_version", "md5_digest", "minor_version", "number_of_chunks", "number_of_sectors", "observed_chunk_count", "section_count", "sector_size", "sectors_per_chunk", "segment_number", "sha1_digest", "total_logical_bytes"), params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString)}},
	BuiltinNameEwfReadAt:   {signature: "ewf_read_at(handle, offset, length)", summary: "Reads length bytes at an offset from an EWF image (length capped at 32 MiB).", returns: pairRet("the bytes read, up to the 32 MiB cap", ParamString), params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameEwfClose:    {signature: "ewf_close(handle)", summary: "Closes an EWF handle and its segment files.", returns: pairRet("confirmation that the handle and its segment files have been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from ewf_open.", ParamString)}},
	BuiltinNameRawOpen:     {signature: "raw_open(image)", summary: "Opens a raw disk image and returns a handle. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to a raw (dd) image.", ParamString)}, returns: pairRet("a handle for the other raw_ builtins; release it with raw_close", ParamHash).withFields("handle", "path", "status")},
	BuiltinNameRawMetadata: {signature: "raw_metadata(handle)", summary: "Returns {file_size, assumed_sector_size, sector_size_assumed} (raw images carry no real sector-size metadata).", returns: pairRet("the image's size and sector size, which a raw image does not record and so is assumed", ParamHash).withFields("assumed_sector_size", "file_size", "sector_size_assumed"), params: []builtinParamDoc{param("handle", "Handle from raw_open.", ParamString)}},
	BuiltinNameRawReadAt:   {signature: "raw_read_at(handle, offset, length)", summary: "Reads length bytes at an offset from a raw image (length capped at 32 MiB).", returns: pairRet("the bytes read, up to the 32 MiB cap", ParamString), params: []builtinParamDoc{param("handle", "Handle from raw_open.", ParamString), param("offset", "Byte offset to read from.", ParamInt), param("length", "How many bytes to read; capped at 32 MiB.", ParamInt)}},
	BuiltinNameRawClose:    {signature: "raw_close(handle)", summary: "Closes a raw image handle.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from raw_open.", ParamString)}},

	// partition table parser
	BuiltinNameTableOpen:           {signature: "table_open(image)", summary: "Opens a disk image and parses its partition table(s) (MBR/GPT). warnings reports suspicious-but-parsable findings (out-of-bounds entries, overlapping extents, hybrid MBR, truncated entry counts); candidates lists every scheme that parsed cleanly, so more than one means the media was ambiguous. Returns (result, err).", params: []builtinParamDoc{param("image", "Path to a disk image.", ParamString)}, returns: pairRet("a handle for the other table_ builtins, plus what the parser found", ParamHash).withFields("block_size", "candidates", "handle", "is_backup", "partition_count", "path", "status", "table_offset", "table_type", "warnings")},
	BuiltinNameTableListPartitions: {signature: "table_list_partitions(handle)", summary: "Lists partitions with LBA ranges, absolute start_byte/length_byte, type, name, flags, and hex type_code/attributes. Use start_byte rather than start_lba * block_size, which mislocates every partition on a table parsed at a non-zero offset.", returns: pairRet("one hash per partition", ParamArray).ofElem(ParamHash).withFields("attributes", "end_lba", "flags", "guid_type", "guid_unique", "index", "length_byte", "length_lba", "name", "slot_number", "start_byte", "start_lba", "table_number", "type_code", "type_name"), params: []builtinParamDoc{param("handle", "Handle from table_open.", ParamString)}},
	BuiltinNameTablePartitionInfo:  {signature: "table_partition_info(handle, index)", summary: "Returns details for a single partition by index, including absolute start_byte/length_byte.", returns: pairRet("details for a single partition by index, including absolute start_byte/length_byte", ParamHash).withFields("attributes", "end_lba", "flags", "guid_type", "guid_unique", "index", "length_byte", "length_lba", "name", "slot_number", "start_byte", "start_lba", "table_number", "type_code", "type_name"), params: []builtinParamDoc{param("handle", "Handle from table_open.", ParamString), param("index", "Zero-based partition index.", ParamInt)}},
	BuiltinNameTableClose:          {signature: "table_close(handle)", summary: "Closes a partition-table handle.", returns: pairRet("confirmation that the handle has been released", ParamHash).withFields("closed", "handle", "status"), params: []builtinParamDoc{param("handle", "Handle from table_open.", ParamString)}},

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
	// concurrency
	{"chan_", "concurrency"},
	{"task_", "concurrency"},
	{"spawn", "concurrency"},
	// graph database
	{"db_", "graph database"},
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
	// cryptography / fingerprinting
	{"x509_", "cryptography"},
	{"jwt_", "cryptography"},
	{"aes_", "cryptography"},
	{"pem_", "cryptography"},
	{"imphash", "fingerprinting"},
	{"nt_hash", "fingerprinting"},
	{"lm_hash", "fingerprinting"},
	{"ja3", "fingerprinting"},
	// policy / cache
	{"policy_", "policy"},
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
