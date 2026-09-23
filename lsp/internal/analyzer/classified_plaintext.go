package analyzer

// classifiedPlaintext reports plaintext read out of a classified record being
// handed to a builtin that refuses it.
//
// The refusal itself happens at run time: record_read marks the buffer it
// returns, and the sinks -- putln, fs_write, http_post and the rest -- refuse a
// marked buffer anywhere inside their arguments. That is the agreed
// enforcement, and it is exact. What it cannot do is say so before the program
// runs, and a program that reads a record usually asks for a passphrase first,
// so the first anyone hears of the mistake is after typing one. This rule is
// the other half of that decision: the same finding, in the editor, at the line.
//
// It reads the lists the run time is held to -- builtin.ClassifiedSinks and
// builtin.ClassifiedSources, each checked against the code by a test in the
// builtin package -- so it cannot warn about a builtin that does not refuse, or
// miss one that was added.
//
// Certainty is the whole design. An argument is reported only when it is,
// written out, one of:
//
//   - a call to record_read or record_read_partial;
//   - a name this scope binds exactly once, to one of these;
//   - bytes_slice of one of these, which carries the mark to the slice;
//   - the `bytes` entry of record_read_partial's hash;
//   - an array, hash or struct literal holding one of these, because the run
//     time looks inside containers too.
//
// Anything else is quiet -- a value that came back from a user function, a
// name bound twice, `a + b`, which carries the mark only when both sides are
// buffers. record_release is not in the list, so its result is never reported:
// it is the deliberate way out.

import (
	"fmt"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// classifiedResolveDepth bounds how many names and slices the rule follows
// from an argument back to the read. A chain longer than this is not worth the
// risk of following a binding somewhere it does not reach.
const classifiedResolveDepth = 8

func lintClassifiedPlaintext(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}
	severity, ok := lintConfig.severityForRule("classifiedPlaintext")
	if !ok {
		return nil
	}

	sinks := make(map[string]struct{})
	for _, name := range builtin.ClassifiedSinks() {
		sinks[name] = struct{}{}
	}
	sources := make(map[string]struct{})
	for _, name := range builtin.ClassifiedSources() {
		sources[name] = struct{}{}
	}

	statements := snapshot.Program.Statements
	shadowed := namesBoundAnywhere(statements)
	isShadowed := func(name string) bool {
		_, taken := shadowed[name]
		return taken
	}
	source := "mutant-lint"
	var result []lsp.Diagnostic

	forEachBuiltinCall(statements, shadowed,
		func(name string, anchor mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			if _, isSink := sinks[name]; !isSink {
				return
			}
			finder := classifiedFinder{
				bindings:   bindings,
				isShadowed: isShadowed,
				sources:    sources,
			}
			for index, argument := range call.Arguments {
				origin, held, ok := finder.origin(argument, 0)
				if !ok {
					continue
				}
				rng, found := snapshot.Program.RangeOf(argument)
				if !found {
					if rng, found = snapshot.Program.RangeOf(anchor); !found {
						return
					}
				}
				result = append(result, lsp.Diagnostic{
					Range:    localprotocol.ToLSPRange(rng),
					Severity: severity,
					Source:   &source,
					Message: fmt.Sprintf(
						"`%s` refuses classified plaintext, and argument %d holds %s `%s` read out of a classified record. The call fails when it runs, naming the record and its class. If these bytes are meant to leave the process, `%s(buffer, reason)` returns a copy that may, and records who let them go and why.",
						name, index+1, held, origin, builtin.BuiltinNameRecordRelease),
				})
				// One report per call, as the run time refuses at the first
				// argument that holds any.
				return
			}
		})

	return result
}

// classifiedFinder follows an argument back to a classified read.
type classifiedFinder struct {
	bindings   map[string]mast.Expression
	isShadowed func(string) bool
	sources    map[string]struct{}
}

// origin reports the source builtin an expression certainly holds plaintext
// from, and how it holds it, phrased to follow "argument N holds".
func (f classifiedFinder) origin(expr mast.Expression, depth int) (source, held string, ok bool) {
	if expr == nil || depth > classifiedResolveDepth {
		return "", "", false
	}
	switch node := expr.(type) {
	case *mast.Identifier:
		if node == nil || node.Value == "" {
			return "", "", false
		}
		bound, found := f.bindings[node.Value]
		if !found || bound == nil {
			return "", "", false
		}
		source, _, ok := f.origin(bound, depth+1)
		if !ok {
			return "", "", false
		}
		return source, "`" + node.Value + "`, the plaintext", true

	case *mast.CallExpression:
		if node == nil {
			return "", "", false
		}
		name, _, isBuiltin := builtinCallee(node.Function, f.isShadowed)
		if !isBuiltin {
			return "", "", false
		}
		if _, isSource := f.sources[name]; isSource {
			return name, "the plaintext", true
		}
		if name == builtin.BuiltinNameBytesSlice {
			source, _, ok := f.origin(argumentAt(node, 0), depth+1)
			if !ok {
				return "", "", false
			}
			return source, "a slice of the plaintext", true
		}

	case *mast.IndexExpression:
		if node == nil {
			return "", "", false
		}
		// Only record_read_partial's hash has a `bytes` entry holding the
		// buffer. An index into record_read's buffer is one byte, an integer,
		// and carries nothing.
		key, literal := literalString(node.Index)
		if !literal || key != "bytes" {
			return "", "", false
		}
		source, _, ok := f.origin(node.Left, depth+1)
		if !ok || source != builtin.BuiltinNameRecordReadPartial {
			return "", "", false
		}
		return source, "the plaintext", true

	case *mast.ArrayLiteral:
		if node == nil {
			return "", "", false
		}
		for _, element := range node.Elements {
			if source, _, ok := f.origin(element, depth+1); ok {
				return source, "an array holding the plaintext", true
			}
		}

	case *mast.HashLiteral:
		if node == nil {
			return "", "", false
		}
		for _, value := range node.Pairs {
			if source, _, ok := f.origin(value, depth+1); ok {
				return source, "a hash holding the plaintext", true
			}
		}

	case *mast.StructLiteral:
		if node == nil {
			return "", "", false
		}
		for _, field := range node.Fields {
			if field == nil {
				continue
			}
			if source, _, ok := f.origin(field.Value, depth+1); ok {
				return source, "a struct holding the plaintext", true
			}
		}
	}
	return "", "", false
}
