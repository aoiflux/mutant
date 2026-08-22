package analyzer

import (
	"sort"

	mast "mutant/ast"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// InlayHints returns parameter-name hints (`name:`) placed before each
// positional argument of every call whose argument lies within rng. Parameter
// names are resolved through the same machinery as signature help, so they cover
// both user functions and builtins. Because Mutant is dynamically typed, these
// name hints are the only inlay hints that carry real meaning.
func (s *Snapshot) InlayHints(rng lsp.Range) []localprotocol.InlayHint {
	if s == nil || s.Program == nil || s.Program.NodePositions == nil {
		return nil
	}

	kind := localprotocol.InlayHintKindParameter
	padRight := true

	var hints []localprotocol.InlayHint

	// Type hints: `let count`‸`: int` after each `let` binding name whose type is
	// confidently inferred. Absent (Any) types produce no hint, so they stay
	// noise-free.
	for node := range s.Program.NodePositions {
		let, ok := node.(*mast.LetStatement)
		if !ok || let == nil {
			continue
		}
		names := let.Names
		if len(names) == 0 && let.Name != nil {
			names = []*mast.Identifier{let.Name}
		}
		for _, name := range names {
			if name == nil {
				continue
			}
			ty, ok := s.TypeOf(name)
			if !ok {
				continue
			}
			nameRange, ok := s.Program.RangeOf(name)
			if !ok || !nameRange.IsValid() {
				continue
			}
			pos := lsp.Position{
				Line:      lsp.UInteger(nameRange.End.Line - 1),
				Character: lsp.UInteger(nameRange.End.Column - 1),
			}
			if pos.Line < rng.Start.Line || pos.Line > rng.End.Line {
				continue
			}
			tk := localprotocol.InlayHintKindType
			hints = append(hints, localprotocol.InlayHint{
				Position: pos,
				Label:    ": " + ty.String(),
				Kind:     &tk,
			})
		}
	}

	for node := range s.Program.NodePositions {
		call, ok := node.(*mast.CallExpression)
		if !ok || call == nil || len(call.Arguments) == 0 {
			continue
		}

		sig, ok := s.signatureInformationForCall(call, lsp.Position{})
		if !ok || len(sig.Parameters) == 0 {
			continue
		}

		for i, arg := range call.Arguments {
			if i >= len(sig.Parameters) {
				break // variadic tail / extra args: no name to show
			}
			// ParameterInformation.Label is `string | [uint, uint]`; we only emit
			// hints for the plain-string form.
			name, ok := sig.Parameters[i].Label.(string)
			if !ok || name == "" {
				continue
			}
			// Noise reduction: skip when the argument is exactly the identifier
			// with the same name as the parameter (e.g. push(list, list)).
			if ident, ok := arg.(*mast.Identifier); ok && ident.Value == name {
				continue
			}

			argRange, ok := s.Program.RangeOf(arg)
			if !ok || !argRange.IsValid() {
				continue
			}
			pos := lsp.Position{
				Line:      lsp.UInteger(argRange.Start.Line - 1),
				Character: lsp.UInteger(argRange.Start.Column - 1),
			}
			if pos.Line < rng.Start.Line || pos.Line > rng.End.Line {
				continue
			}

			k := kind
			pr := padRight
			hints = append(hints, localprotocol.InlayHint{
				Position:     pos,
				Label:        name + ":",
				Kind:         &k,
				PaddingRight: &pr,
			})
		}
	}

	if len(hints) == 0 {
		return nil
	}
	// Deterministic order (NodePositions iteration is random).
	sort.Slice(hints, func(i, j int) bool {
		if hints[i].Position.Line != hints[j].Position.Line {
			return hints[i].Position.Line < hints[j].Position.Line
		}
		return hints[i].Position.Character < hints[j].Position.Character
	})
	return hints
}
