package analyzer

// tlsVerificationDisabled reports the two ways a TLS call in this language can
// be told to accept something it should not: `insecure: true`, which turns off
// certificate verification outright, and a `min_version` below 1.2, which
// leaves the connection open to protocol versions with published attacks.
//
// The rule is exact rather than heuristic. Both options are read by
// applyClientTLSOptions / applyServerTLSOptions (builtin/secure_net.go) out of
// a hash or struct the author wrote, so when that hash is a literal the
// linter knows precisely what the runtime will do with it. Nothing is inferred
// and nothing is guessed: an option whose value is not a literal is an option
// this says nothing about.
//
// The one thing it deliberately does NOT report is the absence of
// `min_version`. A missing option is not a weakened one -- the default belongs
// to the runtime, and a lint that demanded the option be written out would be
// style advice wearing a security rule's clothes.

import (
	"fmt"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// tlsOptionSink is one builtin that takes TLS options, and where in its
// argument list they sit.
type tlsOptionSink struct {
	builtin string
	index   int
	// client is true for the two builtins whose options reach
	// applyClientTLSOptions, which is the only side that reads `insecure`.
	// A server has no peer certificate to verify by default, so the key is
	// not read there and reporting it would be reporting nothing.
	client bool
}

var tlsOptionSinks = []tlsOptionSink{
	// net_tls_connect(address, timeoutMs, options?)
	{builtin: builtin.BuiltinNameNetTlsConnect, index: 2, client: true},
	// net_tls_upgrade_client(handle, options?)
	{builtin: builtin.BuiltinNameNetTlsUpgradeClient, index: 1, client: true},
	// net_tls_listen(address, certPem, keyPem, options?)
	{builtin: builtin.BuiltinNameNetTlsListen, index: 3},
	// net_tls_upgrade_server(handle, certPem, keyPem, options?)
	{builtin: builtin.BuiltinNameNetTlsUpgradeServer, index: 3},
}

var tlsOptionSinksByName = func() map[string]tlsOptionSink {
	index := make(map[string]tlsOptionSink, len(tlsOptionSinks))
	for _, sink := range tlsOptionSinks {
		index[sink.builtin] = sink
	}
	return index
}()

// weakTLSVersions are the min_version spellings tlsVersionFromString accepts
// that name a version below 1.2.
//
// Spelled out rather than derived, because the derivation would have to know
// which versions are weak, and that is the judgement this table exists to
// record. TLS 1.0 and 1.1 were deprecated by RFC 8996 in 2021.
var weakTLSVersions = map[string]string{
	"1.0":    "1.0",
	"TLS1.0": "1.0",
	"TLS1_0": "1.0",
	"1.1":    "1.1",
	"TLS1.1": "1.1",
	"TLS1_1": "1.1",
}

func lintTlsVerificationDisabled(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("tlsVerificationDisabled")
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
			sink, isSink := tlsOptionSinksByName[name]
			if !isSink {
				return
			}
			options := argumentAt(call, sink.index)
			if options == nil {
				return
			}
			options = resolveOneHop(options, bindings)

			if sink.client {
				if value, found := literalEntry(options, "insecure"); found {
					if disabled, known := literalBool(value); known && disabled {
						report(value, fmt.Sprintf(
							"`%s` is asked to skip certificate verification. With `insecure: true` the connection is encrypted but unauthenticated: anything that can reach the wire can present its own certificate and read and rewrite the traffic, and the call will succeed and report no error. If this is for an appliance with a self-signed certificate, pin it with `ca_cert` instead, which keeps verification on.",
							name))
					}
				}
			}

			if value, found := literalEntry(options, "min_version"); found {
				if text, known := literalString(value); known {
					if version, weak := weakTLSVersions[text]; weak {
						report(value, fmt.Sprintf(
							"`%s` allows TLS %s. RFC 8996 deprecated 1.0 and 1.1 in 2021; both are downgrade targets and neither is a floor a new connection should accept. Use `\"1.2\"`, or `\"1.3\"` where the other end supports it.",
							name, version))
					}
				}
			}
		})

	return result
}
