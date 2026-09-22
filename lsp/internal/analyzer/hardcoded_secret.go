package analyzer

// hardcodedSecret reports a credential written into the program text.
//
// This is the rule the corpus argued with before a line of it was written.
// Three literals under examples/ are what a textbook secret scanner flags
// first, and all three are legitimate teaching material:
//
//	let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + ...;  // jwt_inspect.mut
//	{"Authorization": "Bearer my-token"}                             // http_example.mut
//	hmac("secret-key", msg, "sha256")                                // crypto_toolkit.mut
//
// A forensic language holds credential-shaped strings for the same reason it
// holds malware: they are the subject, not the configuration. So the rule asks
// three questions rather than one, and needs all three to agree.
//
//  1. Is it *called* a secret -- a `let` name, hash key or struct field that
//     says password, token, api_key and so on -- or *shaped* like one: a
//     provider's own prefix, or a PEM private-key header. Argument positions
//     carry no name signal, which is the line that leaves `hmac("secret-key",
//     ...)` alone without a special case for it.
//  2. Does the value read like a generated credential rather than a word or a
//     placeholder: long enough, no whitespace, not "changeme" or "your-key",
//     and with the digits, punctuation or mixed case that a generated string
//     has and "password" does not.
//  3. Does the program *use* it as a credential -- or does it take it apart? A
//     value whose fate is `jwt_decode`, `base64_decode`, `pem_decode` or
//     `x509_parse` is a sample being examined, which is what both corpus JWTs
//     are. That question is a statement about the program rather than about
//     the linter, which is why it is a better answer here than a suppression
//     comment would be.
//
// What it cannot do is prove a string is not a credential. A random-looking
// literal called `nonce` that is never decoded stays quiet, and that is the
// deliberate direction: this rule reports the shapes that are worth the
// interruption and leaves the rest to a scanner that runs over the repository
// rather than over one open document.

import (
	"fmt"
	"regexp"
	"strings"

	mast "mutant/ast"
	"mutant/builtin"
	localprotocol "mutant/lsp/internal/protocol"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

// secretNamePattern is the name signal: a binding whose name says the value is
// a credential. Anchored on word boundaries so `tokenize` and `authority` are
// not names about secrets.
var secretNamePattern = regexp.MustCompile(
	`(?i)(^|[^a-z])(pass(word|wd|phrase)?|secret|token|api[_-]?key|apikey|access[_-]?key|auth|credential|priv(ate)?[_-]?key|client[_-]?secret|bearer)([^a-z]|$)`)

// providerSecret is a literal shape belonging to one issuer, recognisable
// without any help from the name beside it.
type providerSecret struct {
	pattern *regexp.Regexp
	issuer  string
}

// providerSecrets holds only shapes whose issuer publishes the prefix, so a
// match is a statement of fact rather than an entropy guess. A JWT is in the
// list because a signed one is a bearer credential; question 3 is what keeps
// the corpus's two sample tokens quiet.
var providerSecrets = []providerSecret{
	{regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`), "an AWS access key ID"},
	{regexp.MustCompile(`^ASIA[0-9A-Z]{16}$`), "an AWS temporary access key ID"},
	{regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{16,}$`), "a GitHub token"},
	{regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{20,}$`), "a GitHub fine-grained token"},
	{regexp.MustCompile(`^xox[baprs]-[A-Za-z0-9-]{10,}$`), "a Slack token"},
	{regexp.MustCompile(`^sk-[A-Za-z0-9_-]{20,}$`), "an API secret key"},
	{regexp.MustCompile(`^-----BEGIN [A-Z ]*PRIVATE KEY-----`), "a private key"},
	{regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.`), "a signed JWT"},
}

// placeholderPrefixes begin a value that is standing in for a credential
// rather than being one.
var placeholderPrefixes = []string{
	"your", "my-", "my_", "changeme", "change-me", "replace", "insert",
	"example", "placeholder", "dummy", "sample", "redacted", "removed",
	"todo", "fixme", "none", "null", "<", "{{", "${", "xxx", "...",
}

// minimumSecretLength is where a value stops being a word someone typed and
// starts being something issued. Eight is the shortest a generated credential
// realistically is, and shorter values are where a length-only rule starts
// reporting flags and modes.
const minimumSecretLength = 8

// secretDecoders take a credential-shaped value apart. A literal handed to one
// of these is a sample under examination -- it is being read, not presented.
var secretDecoders = map[string]struct{}{
	builtin.BuiltinNameJWTDecode:       {},
	builtin.BuiltinNameBase64Decode:    {},
	builtin.BuiltinNameBase64URLDecode: {},
	builtin.BuiltinNameHexDecode:       {},
	builtin.BuiltinNamePEMDecode:       {},
	builtin.BuiltinNameX509Parse:       {},
	builtin.BuiltinNameDerParse:        {},
}

func lintHardcodedSecret(snapshot *Snapshot, lintConfig LintConfig) []lsp.Diagnostic {
	if snapshot == nil || snapshot.Program == nil || snapshot.Program.NodePositions == nil {
		return nil
	}

	severity, ok := lintConfig.severityForRule("hardcodedSecret")
	if !ok {
		return nil
	}

	statements := snapshot.Program.Statements
	decoded := namesHandedToADecoder(statements)
	source := "mutant-lint"
	var result []lsp.Diagnostic

	for _, site := range secretSites(statements) {
		if site.name != "" {
			if _, taken := decoded[site.name]; taken {
				continue
			}
		}

		for _, literal := range stringLiteralsIn(site.value) {
			if _, taken := decoded[literal.Value]; taken {
				continue
			}
			issuer, named, report := secretVerdict(site.name, literal.Value)
			if !report {
				continue
			}

			rng, ok := snapshot.Program.RangeOf(literal)
			if !ok {
				continue
			}

			var message string
			if issuer != "" {
				message = fmt.Sprintf(
					"This literal is %s. A credential in source is a credential in every copy of the source -- in the repository's history after it is removed, in each clone, and in the bytecode a compiled program ships. Read it from a file the program opens at run time, or take it as an argument, and rotate this one: it should be treated as disclosed.",
					issuer)
			} else {
				message = fmt.Sprintf(
					"`%s` holds what looks like a credential written into the program. A credential in source is a credential in every copy of the source -- in the repository's history after it is removed, in each clone, and in the bytecode a compiled program ships. Read it from a file the program opens at run time, or take it as an argument. If this value is sample data rather than a credential, passing it to a decoder such as `jwt_decode` or `base64_decode` says so and silences this.",
					named)
			}

			result = append(result, lsp.Diagnostic{
				Range:    localprotocol.ToLSPRange(rng),
				Severity: severity,
				Source:   &source,
				Message:  message,
			})
		}
	}

	return result
}

// secretSite is one place a value is written down under a name: a `let`, a
// hash entry, or a struct field. A bare argument is a site with no name, which
// is exactly the difference that decides whether the name signal applies.
type secretSite struct {
	name  string
	value mast.Expression
}

// secretSites collects every named value in the document, plus every string
// literal that is not under one -- the latter can still be reported, but only
// on a provider shape.
func secretSites(statements []mast.Statement) []secretSite {
	var sites []secretSite
	named := make(map[*mast.StringLiteral]struct{})

	note := func(name string, value mast.Expression) {
		if value == nil {
			return
		}
		sites = append(sites, secretSite{name: name, value: value})
		for _, literal := range stringLiteralsIn(value) {
			named[literal] = struct{}{}
		}
	}

	for _, stmt := range statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			switch node := expr.(type) {
			case *mast.HashLiteral:
				if node == nil {
					return
				}
				for key, value := range node.Pairs {
					if text, ok := literalString(key); ok {
						note(text, value)
					}
				}
			case *mast.StructLiteral:
				if node == nil {
					return
				}
				for _, field := range node.Fields {
					if field != nil && field.Name != nil {
						note(field.Name.Value, field.Value)
					}
				}
			}
		})
	}

	var walk func(mast.Statement)
	walk = func(stmt mast.Statement) {
		if isNilStatement(stmt) {
			return
		}
		if let, ok := stmt.(*mast.LetStatement); ok {
			names := letNames(let)
			if len(names) == 1 && names[0] != nil {
				note(names[0].Value, let.Value)
			}
		}
		switch n := stmt.(type) {
		case *mast.BlockStatement:
			for _, inner := range n.Statements {
				walk(inner)
			}
		case *mast.ForStatement:
			walk(n.Init)
			walk(n.Body)
		case *mast.WhileStatement:
			walk(n.Body)
		case *mast.ForInStatement:
			walk(n.Body)
		case *mast.ExpressionStatement:
			forEachNestedBlockExpression(n.Expression, walk)
		case *mast.LetStatement:
			forEachNestedBlockExpression(n.Value, walk)
		}
		visitExpressions(stmt, func(expr mast.Expression) {
			if literal, ok := expr.(*mast.FunctionLiteral); ok && literal != nil && literal.Body != nil {
				for _, inner := range literal.Body.Statements {
					walk(inner)
				}
			}
		})
	}
	for _, stmt := range statements {
		walk(stmt)
	}

	// Every remaining literal, with no name of its own.
	for _, stmt := range statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			literal, ok := expr.(*mast.StringLiteral)
			if !ok || literal == nil {
				return
			}
			if _, covered := named[literal]; covered {
				return
			}
			sites = append(sites, secretSite{value: literal})
		})
	}

	return sites
}

// stringLiteralsIn returns the string literals an expression is built from:
// itself, or the pieces of a concatenation. Both corpus JWTs are written as a
// `+` chain of three, so a rule that only looked at a bare literal would not
// see them at all.
func stringLiteralsIn(expr mast.Expression) []*mast.StringLiteral {
	var found []*mast.StringLiteral

	var walk func(mast.Expression)
	walk = func(e mast.Expression) {
		switch node := e.(type) {
		case *mast.StringLiteral:
			if node != nil {
				found = append(found, node)
			}
		case *mast.InfixExpression:
			if node != nil && node.Operator == "+" {
				walk(node.Left)
				walk(node.Right)
			}
		}
	}
	walk(expr)

	return found
}

// namesHandedToADecoder collects every name, and every string literal value,
// that the document passes to a builtin whose job is to take a credential-
// shaped value apart.
//
// File-wide and by name rather than scope-accurate, for the reason the other
// rules in this family give for the same choice: over-excusing is the harmless
// direction, and a sample decoded in one function is still a sample.
func namesHandedToADecoder(statements []mast.Statement) map[string]struct{} {
	decoded := make(map[string]struct{})
	shadowed := namesBoundAnywhere(statements)

	for _, stmt := range statements {
		visitExpressions(stmt, func(expr mast.Expression) {
			call, ok := expr.(*mast.CallExpression)
			if !ok || call == nil {
				return
			}
			name, _, ok := builtinCallee(call.Function, func(candidate string) bool {
				_, taken := shadowed[candidate]
				return taken
			})
			if !ok {
				return
			}
			if _, decoder := secretDecoders[name]; !decoder {
				return
			}
			for _, argument := range call.Arguments {
				switch node := argument.(type) {
				case *mast.Identifier:
					if node != nil && node.Value != "" {
						decoded[node.Value] = struct{}{}
					}
				case *mast.StringLiteral:
					if node != nil {
						decoded[node.Value] = struct{}{}
					}
				}
			}
		})
	}

	return decoded
}

// secretVerdict answers questions 1 and 2 for one literal under one name.
func secretVerdict(name, value string) (issuer string, named string, report bool) {
	for _, provider := range providerSecrets {
		if provider.pattern.MatchString(value) {
			// A provider shape is its own evidence and needs no name, but a
			// placeholder is still a placeholder.
			if isPlaceholder(value) {
				return "", "", false
			}
			return provider.issuer, name, true
		}
	}

	if name == "" || !secretNamePattern.MatchString(name) {
		return "", "", false
	}
	// A name ending in _file, _path or _dir names a LOCATION, not a secret.
	//
	// This rule's own advice is "read it from a file the program opens at run
	// time", and a name given to doing exactly that must not be the thing it
	// flags. The combination is not hypothetical: secretNamePattern matches
	// `pass(word|wd|phrase)?` followed by a non-letter, so `passphrase_file`
	// matches, and looksIssued fires on any value containing a symbol -- which
	// every real path does, through its separators or its dot. The rule was
	// therefore certain to fire on every correct use of the idiom it
	// recommends, and to tell the author to do what they had just done.
	//
	// The exemption is narrow on purpose. It is about what the value is FOR,
	// which is the question the rest of this function already asks, and it
	// leaves a literal assigned to a name like `api_key_file` unflagged -- a
	// blind spot worth accepting against a rule that was otherwise wrong every
	// time it spoke.
	if strings.HasSuffix(name, "_file") || strings.HasSuffix(name, "_path") ||
		strings.HasSuffix(name, "_dir") {
		return "", "", false
	}
	if !looksIssued(value) {
		return "", "", false
	}
	return "", name, true
}

// looksIssued asks whether a value reads like something generated rather than
// something typed.
func looksIssued(value string) bool {
	if len(value) < minimumSecretLength {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n") {
		// "Bearer my-token" and "the password is on the wiki" are prose or a
		// header, not a credential on its own.
		return false
	}
	if isPlaceholder(value) {
		return false
	}

	// A generated credential has digits, punctuation, or a case mixture. A word
	// -- `password`, `secret`, `bearer` -- has none of the three, and a name
	// signal beside a word is a label, not a leak.
	var hasDigit, hasUpper, hasLower, hasSymbol bool
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		default:
			hasSymbol = true
		}
	}
	return hasDigit || hasSymbol || (hasUpper && hasLower)
}

// isPlaceholder reports whether a value is standing in for a credential.
func isPlaceholder(value string) bool {
	folded := strings.ToLower(strings.TrimSpace(value))
	if folded == "" {
		return true
	}
	for _, prefix := range placeholderPrefixes {
		if strings.HasPrefix(folded, prefix) {
			return true
		}
	}
	// A run of one character -- "aaaaaaaa", "********" -- is a redaction.
	first := rune(folded[0])
	for _, r := range folded {
		if r != first {
			return false
		}
	}
	return true
}
