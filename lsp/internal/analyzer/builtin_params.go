package analyzer

import (
	"fmt"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// Rendering of the machine-readable parameter contracts that builtin/metadata.go
// declares. Coverage there grows a category at a time, so everything here is
// written to degrade to the untyped output the editor showed before: a builtin
// with no declared kinds renders exactly as it always did.

// builtinSignatureLabel is the signature line to show for a builtin: the typed
// rendering from builtin.TypedSignature, converted to the offset form the LSP
// addresses parameters by. Spans are empty when the builtin documents no
// parameters and the label is therefore its plain signature.
func builtinSignatureLabel(name string) (string, [][2]lsp.UInteger, bool) {
	label, spans, ok := builtin.TypedSignature(name)
	if !ok {
		return "", nil, false
	}
	if len(spans) == 0 {
		return label, nil, true
	}

	converted := make([][2]lsp.UInteger, 0, len(spans))
	for _, span := range spans {
		converted = append(converted, [2]lsp.UInteger{lsp.UInteger(span.Start), lsp.UInteger(span.End)})
	}
	return label, converted, true
}

// builtinCompletionDetail is the one-line detail shown beside a builtin in the
// completion list: its typed signature and capability category.
//
// It must keep starting with "builtin" — completionCategory sorts builtins
// ahead of local bindings by that prefix.
func builtinCompletionDetail(name string) *string {
	detail := "builtin"
	if label, _, ok := builtinSignatureLabel(name); ok {
		detail += " · " + label
	}
	if category := builtin.CapabilityCategory(name); category != "" {
		detail += " · " + category
	}
	return &detail
}

// paramDocumentation is the hover card shown for one parameter in signature
// help: its accepted kinds in bold, then its prose. Either half may be absent.
func paramDocumentation(p builtin.BuiltinParamDoc) string {
	kinds := p.KindsText()
	switch {
	case kinds == "":
		return p.Doc
	case p.Doc == "":
		return "**" + kinds + "**"
	default:
		return "**" + kinds + "** — " + p.Doc
	}
}

// paramKindForType translates an inferred type into the kind vocabulary the
// parameter contracts are written in.
//
// It reports false for anything the vocabulary cannot name — Any, structs,
// enums, and errors. That is the translation's whole safety property: a type it
// cannot express becomes "no opinion", never a wrong opinion, so the argument
// is left unchecked rather than judged against a kind it was never compared to.
func paramKindForType(t Type) (builtin.ParamKind, bool) {
	switch t.Kind {
	case TypeInt:
		return builtin.ParamInt, true
	case TypeFloat:
		return builtin.ParamFloat, true
	case TypeBool:
		return builtin.ParamBool, true
	case TypeString:
		return builtin.ParamString, true
	case TypeArray:
		return builtin.ParamArray, true
	case TypeHash:
		return builtin.ParamHash, true
	case TypeFunction:
		return builtin.ParamFn, true
	case TypeNull:
		return builtin.ParamNull, true
	default:
		return "", false
	}
}

// paramForArgument maps an argument position onto the parameter that receives
// it, following a variadic tail when there is one.
//
// It reports false when the position has no parameter at all, which means the
// call's argument count does not fit the signature. Positional mapping is
// meaningless for such a call, so the type check declines it and leaves the
// complaint to the arity rule.
func paramForArgument(params []builtin.BuiltinParamDoc, index int) (builtin.BuiltinParamDoc, bool) {
	if index < len(params) {
		return params[index], true
	}
	if len(params) > 0 {
		if last := params[len(params)-1]; last.Variadic {
			return last, true
		}
	}
	return builtin.BuiltinParamDoc{}, false
}

// argumentCountFitsParams reports whether a call supplies enough arguments to
// bind every required parameter, and not more than the signature can absorb.
// Only a call that fits is worth type-checking — see paramForArgument.
func argumentCountFitsParams(params []builtin.BuiltinParamDoc, argCount int) bool {
	required := 0
	variadic := false
	for _, p := range params {
		if p.Variadic {
			variadic = true
			continue
		}
		if !p.Optional {
			required++
		}
	}
	if argCount < required {
		return false
	}
	return variadic || argCount <= len(params)
}

// argTypeMessage renders the complaint in the words the runtime uses when the
// same call fails — see the requireXArg helpers in builtin/arg_helpers.go — so
// what the editor says before the run matches what the program says during it.
func argTypeMessage(name string, position int, p builtin.BuiltinParamDoc, got builtin.ParamKind) string {
	return fmt.Sprintf("argument %d to `%s` must be %s, got %s", position, name, kindListText(p.Kinds), got)
}

// elementTypeMessage renders the complaint for an element of an array argument,
// naming the argument it belongs to so the reader can find it in a call with
// several. It follows the runtime's own phrasing — str_join says "must be an
// ARRAY of STRING; element 0 is INTEGER".
func elementTypeMessage(name string, position int, p builtin.BuiltinParamDoc, got builtin.ParamKind) string {
	return fmt.Sprintf("argument %d to `%s` must be an ARRAY of %s; this element is %s",
		position, name, kindListText(p.Elem), got)
}

// ArgTypeDiagnosticRule is the value a builtinArgType diagnostic carries under
// "rule", so a code-action provider can recognise its payload without matching
// on the message text.
const ArgTypeDiagnosticRule = "builtinArgType"

// ArgTypeDiagnosticData is the machine-readable half of a builtinArgType
// diagnostic: the kinds the parameter accepts and the kind the argument had.
//
// It goes in Diagnostic.Data, which the protocol preserves between
// publishDiagnostics and codeAction precisely so a fix does not have to
// re-derive — or worse, re-parse out of English — what the diagnostic already
// knew. Every value is a string because the payload round-trips through JSON on
// the way to the client and back: strings survive that unchanged, where a
// number would come back as a float64 and a struct as a map.
func ArgTypeDiagnosticData(p builtin.BuiltinParamDoc, got builtin.ParamKind) map[string]any {
	return map[string]any{
		"rule": ArgTypeDiagnosticRule,
		"want": p.KindsText(),
		"got":  string(got),
	}
}

// ElementTypeDiagnosticData is the same payload for an array element, carrying
// the element contract rather than the parameter's own kinds.
//
// It uses the same rule name on purpose: a fix that knows how to convert a
// value to a wanted kind works identically whether the value is the argument or
// one of its elements, so `str_join([1, 2], ",")` gets the same to_string offer
// on each element that `str_upper(1)` gets on its argument.
func ElementTypeDiagnosticData(p builtin.BuiltinParamDoc, got builtin.ParamKind) map[string]any {
	return map[string]any{
		"rule": ArgTypeDiagnosticRule,
		"want": p.ElemText(),
		"got":  string(got),
	}
}

// ArgTypeDiagnosticKinds reads back what ArgTypeDiagnosticData wrote, reporting
// false for anything that is not a builtinArgType payload.
//
// It accepts both the map the analyzer built and the map a JSON round-trip
// produces, which are the same shape by construction.
func ArgTypeDiagnosticKinds(data any) (want []builtin.ParamKind, got builtin.ParamKind, ok bool) {
	fields, isMap := data.(map[string]any)
	if !isMap {
		return nil, "", false
	}
	if rule, _ := fields["rule"].(string); rule != ArgTypeDiagnosticRule {
		return nil, "", false
	}

	wantText, _ := fields["want"].(string)
	gotText, _ := fields["got"].(string)
	if wantText == "" || gotText == "" {
		return nil, "", false
	}

	for _, name := range strings.Split(wantText, "|") {
		if name == "" {
			return nil, "", false
		}
		want = append(want, builtin.ParamKind(name))
	}
	return want, builtin.ParamKind(gotText), true
}

// argumentTypeIsCertain reports whether an argument's inferred type can be
// trusted enough to fail a build on.
//
// Inference (infer.go) is best-effort by design: its contract is that an
// unknown collapses to Any so the editor merely shows less, and it is a single
// forward walk that does not re-type a name after an assignment. Hover can live
// with that; a diagnostic cannot. So the check accepts only two shapes:
//
//   - a literal, whose type is not inferred but read straight off the syntax;
//   - an identifier that is never assigned to anywhere in the document, so the
//     type recorded at its binding is the type it still holds.
//
// Everything else — calls, index and field accesses, arithmetic — is left
// alone. That deliberately gives up `str_upper(read_name())` to guarantee no
// correct program is ever flagged.
func argumentTypeIsCertain(arg mast.Expression, reassigned map[string]struct{}) bool {
	switch node := arg.(type) {
	case *mast.IntegerLiteral, *mast.FloatLiteral, *mast.StringLiteral,
		*mast.Boolean, *mast.ArrayLiteral, *mast.HashLiteral, *mast.FunctionLiteral:
		return true
	case *mast.PrefixExpression:
		// `!x` is a boolean whatever x is; `-42` is the literal's own kind.
		if node.Operator == "!" {
			return true
		}
		if node.Operator != "-" {
			return false
		}
		switch node.Right.(type) {
		case *mast.IntegerLiteral, *mast.FloatLiteral:
			return true
		}
		return false
	case *mast.Identifier:
		if node == nil || node.Value == "" {
			return false
		}
		_, assigned := reassigned[node.Value]
		return !assigned
	default:
		return false
	}
}

// reassignedNames collects every name that appears on the left of an assignment
// anywhere in the document.
//
// It reads the node table rather than walking the tree because the table
// already holds every node the parser produced, and this needs no order — only
// membership. A name in this set has a type that inference cannot be trusted to
// track, so arguments mentioning it go unchecked.
func reassignedNames(snapshot *Snapshot) map[string]struct{} {
	names := make(map[string]struct{})
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return names
	}
	for node := range snapshot.Program.NodePositions {
		assign, ok := node.(*mast.AssignExpression)
		if !ok || assign == nil {
			continue
		}
		if ident, ok := assign.Left.(*mast.Identifier); ok && ident != nil && ident.Value != "" {
			names[ident.Value] = struct{}{}
		}
	}
	return names
}

// kindListText writes a kind set as English: "STRING", "INTEGER or FLOAT",
// "STRING, ARRAY, or HASH".
func kindListText(kinds []builtin.ParamKind) string {
	names := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		names = append(names, string(kind))
	}
	switch len(names) {
	case 0:
		return "a supported type"
	case 1:
		return names[0]
	case 2:
		return names[0] + " or " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + ", or " + names[len(names)-1]
	}
}
