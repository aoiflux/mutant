package analyzer

// weakCrypto reports MD5, SHA-1 and CRC-32 used to decide whether something is
// authentic.
//
// The difficulty here is the opposite of the usual one. In most languages
// `hash_md5` is simply a mistake and a linter can say so. In this one it is
// daily work: matching an artifact against a known-file set, looking a sample
// up in a threat-intelligence feed, reproducing a tool's output so two reports
// can be compared. Every one of those wants MD5 specifically, because the other
// side of the comparison is MD5, and a rule that reported them would be telling
// a forensic analyst their correct code is wrong. That is the fastest way to
// have a security rule switched off, and a switched-off rule catches nothing.
//
// So the rule does not look at the algorithm. It looks at the decision the
// program makes with the digest:
//
//   - `hash_md5(data) == "<a digest written into the program>"` is verifying
//     that data is what it is supposed to be. That is an authenticity decision,
//     and MD5 and SHA-1 have both had practical collisions for years -- an
//     attacker who can choose the data can produce a different file with the
//     same digest. Reported.
//   - `hash_md5(a) == hash_md5(b)`, a digest put in a hash set, printed,
//     returned, or written to a report is matching or recording. Silent.
//   - `hmac(key, message, "md5")` is authentication by definition -- there is
//     no other reason to key a hash. Reported when the algorithm is a literal.
//
// The comparison side must be a string literal, or a name bound once to one. A
// digest read from a manifest at run time might be either, and "might be" is
// not enough to squiggle someone's screen.

import (
	"fmt"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// weakDigests are the digest builtins whose output must not decide
// authenticity, with the reason for each.
var weakDigests = map[string]string{
	builtin.BuiltinNameHashMD5:   "MD5 has had practical chosen-prefix collisions since 2009",
	builtin.BuiltinNameHashSHA1:  "SHA-1 has had practical chosen-prefix collisions since 2019",
	builtin.BuiltinNameHashCRC32: "CRC-32 is an error-detecting checksum and was never a hash: a matching value is trivial to construct",
}

// weakHMACAlgorithms are the `algo` values hmac accepts that name a broken
// hash. sha256 and sha512 are the other two it accepts and are fine.
var weakHMACAlgorithms = map[string]string{
	"md5":  "MD5",
	"sha1": "SHA-1",
}

func lintWeakCrypto(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("weakCrypto")
	if !ok {
		return nil
	}

	source := "mutant-lint"
	var result []lsp.Diagnostic

	report := func(anchor mast.Node, message string) {
		rng, ok := snapshot.Program.RangeOf(anchor)
		if !ok {
			return
		}
		result = append(result, lsp.Diagnostic{
			Range:    localprotocol.ToLSPRange(rng),
			Severity: severity,
			Source:   &source,
			Message:  message,
		})
	}

	shadowed := namesBoundAnywhere(snapshot.Program.Statements)

	// An HMAC over a broken hash needs no context: keying a hash has exactly
	// one purpose, so the algorithm alone settles it.
	forEachBuiltinCall(snapshot.Program.Statements, shadowed,
		func(name string, anchor mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			if name != builtin.BuiltinNameHMAC {
				return
			}
			algorithm := argumentAt(call, 2)
			if algorithm == nil {
				return
			}
			text, known := literalString(resolveOneHop(algorithm, bindings))
			if !known {
				return
			}
			label, weak := weakHMACAlgorithms[strings.ToLower(strings.TrimSpace(text))]
			if !weak {
				return
			}
			report(algorithm, fmt.Sprintf(
				"`hmac` is asked for %s. An HMAC exists to prove a message was not altered by anyone without the key, so its hash is doing authentication and nothing else. Use `\"sha256\"`, which this builtin also accepts.",
				label))
		})

	// The digest rules need both sides of a comparison, so they walk for
	// themselves.
	forEachScope(snapshot.Program.Statements, func(scope []mast.Statement) {
		var bindings map[string]mast.Expression

		for _, stmt := range scope {
			walkExpressions(stmt, false, func(expr mast.Expression) {
				infix, ok := expr.(*mast.InfixExpression)
				if !ok || infix == nil {
					return
				}
				if infix.Operator != "==" && infix.Operator != "!=" {
					return
				}
				if bindings == nil {
					bindings = singleBindings(scope)
				}

				if digest, reason, anchor, found := weakDigestAgainstALiteral(infix, bindings, shadowed); found {
					report(anchor, fmt.Sprintf(
						"`%s` decides whether this matches a digest written into the program, which makes it an authenticity check. %s, so an attacker who controls the input can produce different data with this same digest and the comparison will still pass. Use `hash_sha256` for anything that has to be trustworthy. If you are instead matching an artifact against a known-file set, compare against the other side's digest or use `hashset_contains`, and this rule will stay quiet.",
						digest, reason))
				}
			})
		}
	})

	return result
}

// weakDigestAgainstALiteral reports whether one side of a comparison is a weak
// digest and the other is a digest the program has written down.
func weakDigestAgainstALiteral(
	infix *mast.InfixExpression,
	bindings map[string]mast.Expression,
	shadowed map[string]struct{},
) (digest string, reason string, anchor mast.Node, found bool) {
	sides := [2][2]mast.Expression{
		{infix.Left, infix.Right},
		{infix.Right, infix.Left},
	}

	for _, side := range sides {
		name, callAnchor, ok := weakDigestCall(side[0], bindings, shadowed)
		if !ok {
			continue
		}
		// The other side has to be a digest the source contains. A call is
		// another computed digest -- matching, not verifying -- and anything
		// else is a value this cannot see.
		if _, literal := literalString(resolveOneHop(side[1], bindings)); !literal {
			continue
		}
		return name, weakDigests[name], callAnchor, true
	}

	return "", "", nil, false
}

// weakDigestCall unwraps an operand to the weak-digest call behind it, whether
// it was written in the comparison or bound to a name first.
func weakDigestCall(
	expr mast.Expression,
	bindings map[string]mast.Expression,
	shadowed map[string]struct{},
) (string, mast.Node, bool) {
	call, ok := resolveOneHop(expr, bindings).(*mast.CallExpression)
	if !ok || call == nil {
		return "", nil, false
	}
	name, anchor, ok := builtinCallee(call.Function, func(candidate string) bool {
		_, taken := shadowed[candidate]
		return taken
	})
	if !ok {
		return "", nil, false
	}
	if _, weak := weakDigests[name]; !weak {
		return "", nil, false
	}
	if !isLiveBuiltin(name) {
		return "", nil, false
	}
	return name, anchor, true
}
