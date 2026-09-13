package analyzer

// unboundedResource reports a `range` or `cidr_hosts` call whose literal
// arguments ask for more than the builtin will hand back.
//
// The interesting fact found while writing this rule is that neither builtin is
// actually unbounded: `range` errors once the array it is building passes
// 10,000,000 elements (builtin/collections_builtins.go:256) and `cidr_hosts`
// refuses more than 20 host bits (builtin/ioc_builtins.go:88). So the finding
// is not "this will exhaust memory" -- it is "this call raises at run time",
// which is a far better thing for a linter to be able to say, because it is
// checkable rather than arguable.
//
// That puts the rule in the same certainty class as builtinArity: it evaluates
// exactly the predicate the builtin evaluates, on arguments the author wrote
// out in full. An argument that is not a literal is one this says nothing
// about. There is no threshold here that anybody chose -- the two numbers are
// read off the implementations, and the tests pin them there.
//
// `cidr_hosts("10.0.0.0/8")` is the call this exists for. It looks like a
// reasonable thing to write, it is the natural way to sweep a corporate
// network, and it fails.

import (
	"fmt"
	"math/big"
	"net"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

const (
	// maxRangeLength mirrors the `maxRange` constant in Range. The builtin
	// errors once the array it is building is LONGER than this, so a range of
	// exactly this many elements succeeds.
	maxRangeLength = 10_000_000

	// maxCIDRHostBits mirrors the check in CIDRHosts: more than this many host
	// bits is refused before a single address is generated.
	maxCIDRHostBits = 20
)

func lintUnboundedResource(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("unboundedResource")
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
	forEachBuiltinCall(snapshot.Program.Statements, shadowed,
		func(name string, _ mast.Node, call *mast.CallExpression, bindings map[string]mast.Expression) {
			switch name {
			case builtin.BuiltinNameCIDRHosts:
				checkCIDRHosts(call, bindings, report)
			case builtin.BuiltinNameRange:
				checkRange(call, bindings, report)
			}
		})

	return result
}

// checkCIDRHosts reports a CIDR literal with more host bits than cidr_hosts
// will expand.
func checkCIDRHosts(call *mast.CallExpression, bindings map[string]mast.Expression, report func(mast.Node, string)) {
	argument := argumentAt(call, 0)
	if argument == nil {
		return
	}
	text, known := literalString(resolveOneHop(argument, bindings))
	if !known {
		return
	}

	_, network, err := net.ParseCIDR(strings.TrimSpace(text))
	if err != nil || network == nil {
		// An unparseable CIDR is also a guaranteed runtime error, and also not
		// this rule's subject. Reporting it here would mean a rule whose name
		// does not describe half of what it says.
		return
	}
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits <= maxCIDRHostBits {
		return
	}

	addresses := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	report(argument, fmt.Sprintf(
		"`cidr_hosts` refuses more than %d host bits, and %s has %d -- %s addresses. This call raises at run time rather than returning a large array. Walk the range in blocks a /%d or smaller at a time, or test membership with `ip_in_cidr` instead of materialising the hosts.",
		maxCIDRHostBits, strings.TrimSpace(text), hostBits, addresses.String(), bits-maxCIDRHostBits))
}

// checkRange reports a range whose literal bounds build a longer array than
// range will return.
func checkRange(call *mast.CallExpression, bindings map[string]mast.Expression, report func(mast.Node, string)) {
	if len(call.Arguments) < 2 || len(call.Arguments) > 3 {
		// Wrong arity is builtinArity's report, and a second squiggle saying
		// the same thing differently helps nobody.
		return
	}

	start, startKnown := literalInt(resolveOneHop(call.Arguments[0], bindings))
	end, endKnown := literalInt(resolveOneHop(call.Arguments[1], bindings))
	if !startKnown || !endKnown {
		return
	}

	step := int64(1)
	if len(call.Arguments) == 3 {
		literal, known := literalInt(resolveOneHop(call.Arguments[2], bindings))
		if !known {
			return
		}
		step = literal
	}
	if step == 0 {
		// `range: step must not be zero` is the builtin's own message and is
		// not about size.
		return
	}

	length := rangeLength(start, end, step)
	if length == nil || length.Cmp(big.NewInt(maxRangeLength)) <= 0 {
		return
	}

	report(call, fmt.Sprintf(
		"`range` returns at most %d elements and this asks for %s. The call raises at run time -- and it allocates its way up to the limit before it finds out, because the check is on the array as it grows. Loop with `for` over the bounds instead of building the array, or take the range in chunks.",
		maxRangeLength, length.String()))
}

// rangeLength is how many elements Range would produce, computed the way Range
// counts them: from start, stepping, while the bound has not been passed.
//
// big.Int rather than int64 because the bounds are whatever the author typed,
// and a literal pair like `range(-9000000000000000000, 9000000000000000000)`
// overflows the subtraction long before it overflows the point. Nothing here is
// hot -- it runs once per `range` written in a document.
func rangeLength(start, end, step int64) *big.Int {
	from := big.NewInt(start)
	to := big.NewInt(end)
	by := big.NewInt(step)

	span := new(big.Int).Sub(to, from)
	if span.Sign() != by.Sign() {
		// Stepping away from the bound, or already at it: the loop body never
		// runs and the array is empty.
		return big.NewInt(0)
	}

	span.Abs(span)
	by.Abs(by)

	// ceil(span / step): the last element is the final value strictly before
	// the exclusive bound.
	length, remainder := new(big.Int).QuoRem(span, by, new(big.Int))
	if remainder.Sign() != 0 {
		length.Add(length, big.NewInt(1))
	}
	return length
}
