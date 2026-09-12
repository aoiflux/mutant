package server

import "testing"

// TestFormatterRendersImports pins the terminator rule as much as the layout.
// ImportStatement.String() ends in `;` because it is an AST debug rendering,
// but statements() appends `;` for every statement whose RequiresSemicolon
// reports true. Falling through to the default arm therefore emitted `;;` --
// and because that output re-parsed and re-printed identically, the
// idempotence corpus could not catch it.
func TestFormatterRendersImports(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"unaliased", `import "pkg/util.mut";`, "import \"pkg/util.mut\";\n"},
		{"aliased", `import u "pkg/util.mut";`, "import u \"pkg/util.mut\";\n"},
		{"missing terminator is supplied", `import "pkg/util.mut"`, "import \"pkg/util.mut\";\n"},
		{"redundant terminator is removed", `import "pkg/util.mut";;`, "import \"pkg/util.mut\";\n"},
		{"spacing is normalized", `import    u     "pkg/util.mut" ;`, "import u \"pkg/util.mut\";\n"},
		{
			"imports precede code",
			"import \"a.mut\";\nimport b \"b.mut\";\nlet x = 1;",
			"import \"a.mut\";\nimport b \"b.mut\";\nlet x = 1;\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := format(t, tt.src)
			if got != tt.want {
				t.Fatalf("formatted = %q, want %q", got, tt.want)
			}
			if again := format(t, got); again != got {
				t.Fatalf("formatting is not idempotent: %q -> %q", got, again)
			}
		})
	}
}

// TestFormatterPreservesImportPathEscapes guards against the path being
// re-emitted from the raw token rather than through quoteString. A Windows
// separator in a path is the case that would silently corrupt.
func TestFormatterPreservesImportPathEscapes(t *testing.T) {
	src := `import "pkg\\util.mut";`
	want := "import \"pkg\\\\util.mut\";\n"
	if got := format(t, src); got != want {
		t.Fatalf("formatted = %q, want %q", got, want)
	}
}
