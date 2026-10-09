package analyzer

// secretOption reports an option named for a secret -- `passphrase`,
// `password`, `secret` or `key` -- in the options hash of a builtin that
// refuses one by name.
//
// A passphrase is asked for at the terminal where one is needed, and never
// taken as an argument: key material in program text sits in every copy of the
// file, in a variable a traceback can print, and in a Go string nothing can
// zero. So every builtin that handles a case, its key, its classes, its records,
// their disclosure, its reviews, retention and erasures -- and ledger_open --
// refuses such an option by name before it looks at anything else, rather than
// answering "unknown option", which reads as a misspelling. This rule says so
// at the key, before the program runs.
//
// It reads builtin.SecretOptionRefusers and builtin.SecretOptionNames, which a
// test in the builtin package holds to the calls that refuse, and finds the
// options hash where the builtin's metadata puts it. It fires only on a hash
// literal written in the call or bound once in its scope, and on a key written
// as a string literal; the names are matched exactly, as the run time matches
// them, so `Passphrase` is left to the run time's own "unknown option".

import (
	"fmt"
	"slices"

	mast "mutant/ast"
	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

func lintSecretOption(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}
	severity, ok := lintConfig.severityForRule("secretOption")
	if !ok {
		return nil
	}
	refusers := make(map[string]struct{})
	for _, name := range builtin.SecretOptionRefusers() {
		refusers[name] = struct{}{}
	}
	secrets := builtin.SecretOptionNames()

	statements := snapshot.Program.Statements
	source := "mutant-lint"
	var result []lsp.Diagnostic

	forEachBuiltinCall(statements, namesBoundAnywhere(statements),
		func(name string, anchor mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			if _, refuses := refusers[name]; !refuses {
				return
			}
			hash := optionsHashLiteral(name, call, bindings)
			if hash == nil {
				return
			}
			// The first such key as written, which is the first in the literal's
			// own order: the run time refuses the call at whichever it meets
			// first, and one report per call is enough. A key the parser recorded
			// no range for is passed over rather than reported without one.
			var first mast.Expression
			var firstRange mast.Range
			var firstName string
			for _, pair := range hash.Pairs {
				text, literal := literalString(pair.Key)
				if !literal || !slices.Contains(secrets, text) {
					continue
				}
				rng, found := snapshot.Program.RangeOf(pair.Key)
				if !found {
					continue
				}
				first, firstRange, firstName = pair.Key, rng, text
				break
			}
			if first == nil {
				return
			}
			result = append(result, lsp.Diagnostic{
				Range:    snapshot.Range(firstRange),
				Severity: severity,
				Source:   &source,
				Message: fmt.Sprintf("`%s` refuses an option named %q: %s.", name, firstName,
					builtin.SecretOptionRefusal()),
			})
		})

	return result
}

// optionsHashLiteral returns the hash literal a call hands a builtin as its
// options: the argument at the position the builtin's metadata gives, written
// in the call or bound once in its scope. A call whose argument count the
// signature does not fit is declined, as the arity rule reports it.
func optionsHashLiteral(name string, call *mast.CallExpression, bindings map[string]mast.Expression) *mast.HashLiteral {
	position, ok := builtin.OptionsPosition(name)
	if !ok {
		return nil
	}
	params, ok := builtin.ParamSpecs(name)
	if !ok || !argumentCountFitsParams(params, len(call.Arguments)) {
		return nil
	}
	argument := argumentAt(call, position-1)
	if argument == nil {
		return nil
	}
	hash, ok := resolveOneHop(argument, bindings).(*mast.HashLiteral)
	if !ok || hash == nil {
		return nil
	}
	return hash
}
