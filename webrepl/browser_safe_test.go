package webrepl

import (
	"strings"
	"testing"

	"mutant/builtin"
)

// The browser REPL's restriction is a symbol table: a host-bound name is simply
// not defined, so calling it fails to compile. That works for every builtin
// whose name a program has to write down.
//
// with_resource is the one that does not. Its closer argument is a string, and
// it resolves that string through the whole registry at run time, which no
// symbol table ever sees. Denied for that reason, and pinned here because the
// derivation in browser_safe.go would otherwise let it back in the moment
// somebody looks at its category and sees "standard library".
func TestWithResourceIsNotBrowserSafe(t *testing.T) {
	if BrowserSafe(builtin.BuiltinNameWithResource) {
		t.Fatal("with_resource is exposed to the browser REPL, where its string closer would resolve any builtin by name")
	}

	repl := New()
	output, err := repl.Eval(`with_resource(0, "gets", fn(h) { return 1; })`)
	if err == nil && !strings.Contains(output, "undefined") {
		t.Fatalf("the browser REPL ran with_resource: err=%v output=%q", err, output)
	}
}

// Everything the deny list names has to still exist, or the entry is a comment
// pretending to be a restriction.
func TestExplicitDenyNamesLiveBuiltins(t *testing.T) {
	for name := range explicitDeny {
		if builtin.GetBuiltinByName(name) == nil {
			t.Errorf("%s is denied to the browser but is not a registered builtin", name)
		}
	}
}
