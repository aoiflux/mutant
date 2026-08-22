package analyzer

import (
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
)

// One hover card shape, for every callable.
//
// Before this, hovering a builtin showed a typed signature and prose bullets,
// hovering a user function showed a bare parameter-name list, and neither said
// what the call returned. Which meant the amount a reader learned from hover
// depended on which of 399 builtins they happened to be looking at.
//
// So the card is a data structure rather than a string built at each call site:
// builtins fill it from their declared contracts, user functions from what the
// solver worked out, and both render through the same function. A section can be
// empty of *content* — a builtin that takes no parameters, a function whose types
// could not be solved — but never absent, because "no parameters" is itself
// information and a missing heading reads as an oversight.
type callableCard struct {
	// kindWord opens the card: "builtin", "function".
	kindWord  string
	signature string
	summary   string
	params    []cardParam
	returns   cardReturn
	// footer holds the trailing italic lines: capability category, platform
	// support, behavioural caveats.
	footer []string
}

type cardParam struct {
	name string
	// types is the accepted kinds as text — "STRING", "INTEGER|FLOAT",
	// "ARRAY of STRING" — or "" when the parameter is unconstrained.
	types string
	doc   string
	// note is the parenthetical marker: "optional", "variadic", "inferred".
	note string
}

type cardReturn struct {
	// text is the return type as it appears in the signature, including the
	// pair form "(STRING, ERROR)".
	text   string
	doc    string
	fields []string
	// bind is a worked example of destructuring a (value, err) result, shown
	// only for the builtins that return one.
	bind string
	note string
}

// render lays the card out as Markdown.
func (c callableCard) render() string {
	var b strings.Builder

	b.WriteString(c.kindWord)
	b.WriteString(" `")
	b.WriteString(c.signature)
	b.WriteString("`")

	if c.summary != "" {
		b.WriteString("\n\n")
		b.WriteString(c.summary)
	}

	b.WriteString("\n\n**Parameters**\n")
	if len(c.params) == 0 {
		b.WriteString("- _none_")
	} else {
		for i, p := range c.params {
			if i > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.render())
		}
	}

	b.WriteString("\n\n**Returns**\n")
	b.WriteString(c.returns.render())

	for _, line := range c.footer {
		b.WriteString("\n\n")
		b.WriteString(line)
	}

	return b.String()
}

func (p cardParam) render() string {
	var b strings.Builder
	b.WriteString("- `")
	b.WriteString(p.name)
	b.WriteString("`")
	if p.types != "" {
		b.WriteString(" · `")
		b.WriteString(p.types)
		b.WriteString("`")
	}
	if p.note != "" {
		b.WriteString(" _(")
		b.WriteString(p.note)
		b.WriteString(")_")
	}
	if p.doc != "" {
		b.WriteString(" — ")
		b.WriteString(p.doc)
	}
	return b.String()
}

func (r cardReturn) render() string {
	text := r.text
	if text == "" {
		text = string(builtin.ParamAny)
	}

	var b strings.Builder
	b.WriteString("- `")
	b.WriteString(text)
	b.WriteString("`")
	if r.note != "" {
		b.WriteString(" _(")
		b.WriteString(r.note)
		b.WriteString(")_")
	}
	if r.doc != "" {
		b.WriteString(" — ")
		b.WriteString(r.doc)
	}
	if len(r.fields) > 0 {
		b.WriteString("\n- fields: ")
		b.WriteString(quotedList(r.fields))
	}
	if r.bind != "" {
		b.WriteString("\n- bind both: `")
		b.WriteString(r.bind)
		b.WriteString("`")
	}
	return b.String()
}

func quotedList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, "`"+item+"`")
	}
	return strings.Join(quoted, ", ")
}

// builtinCard fills the card from a builtin's declared contracts. Every one of
// the 399 has a signature, a summary, a return, and a parameter list that may be
// empty, so this never has to decide whether a section is worth showing.
func builtinCard(name string) (callableCard, bool) {
	signature, summary, params, ok := builtin.TeachingDoc(name)
	if !ok {
		return callableCard{}, false
	}

	label, _, labelOK := builtinSignatureLabel(name)
	if !labelOK {
		label = signature
	}

	card := callableCard{kindWord: "builtin", signature: label, summary: summary}
	for _, p := range params {
		card.params = append(card.params, cardParam{
			name:  p.Name,
			types: parameterTypesText(p),
			doc:   p.Doc,
			note:  parameterNote(p),
		})
	}

	if spec, ok := builtin.ReturnSpec(name); ok {
		card.returns = cardReturn{
			text:   spec.Text(),
			doc:    spec.Doc,
			fields: spec.Fields,
		}
		if spec.Pair {
			card.returns.bind = pairBindingExample(name, params)
		}
	}

	card.footer = builtinFooter(name)
	return card, true
}

// userFunctionCard fills the same card for a user-defined function.
//
// Nothing here is declared: Mutant has no type annotations, so every type on the
// card was deduced — parameter kinds by the constraint solver, the return by
// inference running over a body whose parameters the solver had already narrowed.
// Each one is marked _(inferred)_ for that reason. A builtin's types are
// contracts checked against their implementations; these are conclusions, and a
// reader deciding how much to trust them needs to see which they are looking at.
func userFunctionCard(s *Snapshot, name string, literal *mast.FunctionLiteral, docBlock string) callableCard {
	doc := parseFunctionDoc(docBlock)
	solved := s.solvedFunctions()[literal]

	card := callableCard{kindWord: "function", summary: doc.description}

	rendered := make([]string, 0, len(literal.Parameters))
	for i, p := range literal.Parameters {
		if p == nil || p.Value == "" {
			continue
		}
		types, note, solvedText := "", "", ""
		if solved != nil && i < len(solved.kinds) {
			if solvedText = solved.kinds[i].text(); solvedText != "" {
				types, note = solvedText, "inferred"
			} else if observed := observedText(solved, i); observed != "" {
				types, note = observed, "observed at call sites"
			}
		}

		// Only a solved kind reaches the signature line. Call-site evidence is
		// worth showing, but a signature reads as a claim about every call, and
		// "every caller so far passed a string" is not that claim.
		label := p.Value
		if solvedText != "" {
			label += ": " + solvedText
		}
		rendered = append(rendered, label)

		card.params = append(card.params, cardParam{
			name:  p.Value,
			types: types,
			doc:   doc.params[p.Value],
			note:  note,
		})
	}

	// An unknown return is reported as unknown. A builtin's `ANY` is a verified
	// fact — it really does yield any value — while a user function's is the
	// editor coming up short, and the card must not let the two read alike.
	card.returns = cardReturn{doc: doc.returns, note: "not inferred"}
	returnText := ""
	if ty, ok := s.TypeOf(literal); ok && ty.Kind == TypeFunction && ty.Ret != nil && ty.Ret.IsKnown() {
		if returnText = kindTextForType(*ty.Ret); returnText != "" {
			card.returns.text = returnText
			card.returns.note = "inferred"
		}
	}

	signature := name + "(" + strings.Join(rendered, ", ") + ")"
	if returnText != "" {
		signature += " -> " + returnText
	}
	card.signature = signature

	return card
}

// observedText renders the kinds a parameter has actually been passed at call
// sites in this document.
//
// It is offered only where the body constrained nothing, and it is labelled as
// an observation rather than a type on purpose: a function called once with a
// string is not a function that takes strings, it is a function nobody has yet
// called with anything else.
func observedText(fn *solvedFunction, index int) string {
	if fn == nil || index >= len(fn.observed) {
		return ""
	}
	return fn.observed[index].text()
}

// kindTextForType renders an inferred type in the same uppercase vocabulary the
// builtin cards use, so the two kinds of card read alike. A struct or enum keeps
// its own name, which is more useful than any kind word would be.
func kindTextForType(t Type) string {
	if kind, ok := paramKindForType(t); ok {
		if t.Kind == TypeArray && t.Elem != nil && t.Elem.IsKnown() {
			if elem, ok := paramKindForType(*t.Elem); ok {
				return "ARRAY of " + string(elem)
			}
		}
		return string(kind)
	}
	switch t.Kind {
	case TypeStruct, TypeEnum:
		if t.Name != "" {
			return t.Name
		}
	case TypeError:
		return "ERROR"
	case TypeMulti:
		parts := make([]string, 0, len(t.Parts))
		for _, part := range t.Parts {
			parts = append(parts, kindTextForType(part))
		}
		return "(" + strings.Join(parts, ", ") + ")"
	}
	return ""
}

// parameterTypesText renders what a parameter accepts, including the element
// contract of an array that has one — "ARRAY of STRING" says more than "ARRAY",
// and it is the same fact the element-type diagnostic enforces.
func parameterTypesText(p builtin.BuiltinParamDoc) string {
	kinds := p.KindsText()
	if elem := p.ElemText(); elem != "" && kinds == string(builtin.ParamArray) {
		return "ARRAY of " + elem
	}
	return kinds
}

// parameterNote spells out what the name's punctuation already encodes. The `?`
// and `...` spellings are the language's convention, but a reader meeting them
// for the first time should not have to infer what they mean from context.
func parameterNote(p builtin.BuiltinParamDoc) string {
	switch {
	case p.Variadic:
		return "variadic"
	case p.Optional:
		return "optional"
	}
	return ""
}

// pairBindingExample writes the destructuring line for a builtin that returns a
// (value, err) pair, using the builtin's own parameter names.
//
// This is the card's most useful line. Mutant's standard library is split
// between two shapes, and which binding receives the error depends on which
// shape the builtin has — a bare-error builtin puts it in the *first*. Showing
// the correct destructuring for this builtin removes the guess.
func pairBindingExample(name string, params []builtin.BuiltinParamDoc) string {
	args := make([]string, 0, len(params))
	for _, p := range params {
		if p.Optional {
			continue
		}
		args = append(args, strings.TrimPrefix(p.Name, "..."))
	}
	return "let value, err = " + name + "(" + strings.Join(args, ", ") + ");"
}
