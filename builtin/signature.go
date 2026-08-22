package builtin

import "strings"

// SignatureParam is one parameter as written in a builtin's `signature` string.
//
// Name is the undecorated identifier; the `?` suffix and `...` prefix that a
// signature uses to mark optional and variadic parameters are lifted into the
// Optional and Variadic flags rather than left in the text.
type SignatureParam struct {
	Name     string
	Optional bool
	Variadic bool
}

// ParseSignature splits a builtin signature such as
// `http_post(url, body, contentType?)` into the builtin's name and the shape of
// each parameter. It reports false for anything that is not a single
// `name(params...)` form.
//
// Every signature currently in builtinDocs parses; metadata_param_test.go
// asserts that, so a new entry written in an unsupported shape fails the test
// suite rather than silently losing its parameter shape.
func ParseSignature(signature string) (string, []SignatureParam, bool) {
	open := strings.IndexByte(signature, '(')
	if open <= 0 || !strings.HasSuffix(signature, ")") {
		return "", nil, false
	}

	name := strings.TrimSpace(signature[:open])
	if name == "" {
		return "", nil, false
	}

	inner := strings.TrimSpace(signature[open+1 : len(signature)-1])
	if strings.ContainsAny(inner, "()") {
		return "", nil, false
	}
	if inner == "" {
		return name, nil, true
	}

	fields := strings.Split(inner, ",")
	params := make([]SignatureParam, 0, len(fields))
	for _, field := range fields {
		param, ok := parseSignatureParam(field)
		if !ok {
			return "", nil, false
		}
		params = append(params, param)
	}

	return name, params, true
}

// parseSignatureParam reads one `...name`, `name?`, or `name` token.
func parseSignatureParam(field string) (SignatureParam, bool) {
	text := strings.TrimSpace(field)
	var param SignatureParam

	if rest, found := strings.CutPrefix(text, "..."); found {
		param.Variadic = true
		text = rest
	}
	if rest, found := strings.CutSuffix(text, "?"); found {
		param.Optional = true
		text = rest
	}

	if text == "" || !isSignatureIdentifier(text) {
		return SignatureParam{}, false
	}

	param.Name = text
	return param, true
}

// isSignatureIdentifier reports whether s is a bare identifier: the only
// parameter spelling the signature grammar allows once `...` and `?` are lifted
// off. Keeping this strict is what lets ParseSignature be trusted as the source
// of a builtin's parameter shape.
func isSignatureIdentifier(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// ParamSpan is the [Start, End) byte range one parameter occupies inside a
// typed signature string. Every part of such a string is ASCII — builtin and
// parameter names are restricted to identifier characters by
// isSignatureIdentifier, and the kind names are constants — so these offsets
// double as UTF-16 code-unit offsets, which is the form the LSP asks for.
type ParamSpan struct {
	Start int
	End   int
}

// KindsText names a parameter's accepted kinds the way the language itself
// does — "STRING", or "STRING|ARRAY|HASH" for a union.
//
// It returns "" for any parameter that accepts anything, which covers both a
// parameter verified to take any value and one whose kinds have not been
// verified yet. The distinction matters to a checker, which must never flag the
// unverified case; it does not matter to a reader, for whom either way there is
// no constraint worth showing.
func (p BuiltinParamDoc) KindsText() string {
	if p.AcceptsAnyKind() {
		return ""
	}
	parts := make([]string, 0, len(p.Kinds))
	for _, kind := range p.Kinds {
		parts = append(parts, string(kind))
	}
	return strings.Join(parts, "|")
}

// TypedSignature renders a builtin's signature with each parameter's accepted
// kinds inline — `bytes_slice(data: STRING, start: INTEGER, length: INTEGER)` —
// and reports the span each parameter occupies in the result.
//
// Parameters keep the spelling they have in the signature string, so `topic?`
// and `...values` still read the way they do everywhere else, and a parameter
// with no declared kinds is left bare. A builtin that documents no parameters
// renders as its plain signature with no spans, which is what keeps the output
// sensible while kind coverage is still growing.
//
// It is the one renderer behind both the editor's signature help and the
// generated capability reference, so the two can never disagree.
func TypedSignature(name string) (string, []ParamSpan, bool) {
	signature, _, params, ok := TeachingDoc(name)
	if !ok {
		return "", nil, false
	}
	if len(params) == 0 {
		return signature, nil, true
	}

	var b strings.Builder
	spans := make([]ParamSpan, 0, len(params))

	b.WriteString(name)
	b.WriteByte('(')
	for i, p := range params {
		if i > 0 {
			b.WriteString(", ")
		}
		start := b.Len()
		b.WriteString(p.Name)
		if kinds := p.KindsText(); kinds != "" {
			b.WriteString(": ")
			b.WriteString(kinds)
		}
		spans = append(spans, ParamSpan{Start: start, End: b.Len()})
	}
	b.WriteByte(')')

	return b.String(), spans, true
}

// SignatureArity reports the smallest and largest legal argument counts implied
// by a parsed parameter list. maxArgs is -1 when the list ends in a variadic
// tail. It mirrors the language server's builtinArity contract so the curated
// table there can be cross-checked against the signature strings here.
func SignatureArity(params []SignatureParam) (minArgs, maxArgs int) {
	for _, param := range params {
		if param.Variadic {
			return minArgs, -1
		}
		if !param.Optional {
			minArgs++
		}
		maxArgs++
	}
	return minArgs, maxArgs
}
