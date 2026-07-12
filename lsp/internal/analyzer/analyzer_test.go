package analyzer

import (
	mast "mutant/ast"
	"mutant/builtin"
	"strings"
	"testing"
)

func TestSemanticTokensDataHandlesTypedNilStatements(t *testing.T) {
	var typedNilInit *mast.ExpressionStatement

	s := &Snapshot{
		Program: &mast.Program{
			Statements: []mast.Statement{
				&mast.ForStatement{Init: typedNilInit},
			},
			NodePositions: map[mast.Node]mast.Range{},
		},
	}

	_ = s.SemanticTokensData()
}

func TestUndefinedCollectorMarksMultiNameLetDeclarations(t *testing.T) {
	collector := &undefinedCollector{snapshot: &Snapshot{}}
	root := newDeclarationScope(nil, 0)

	collector.collectStatement(&mast.LetStatement{
		Names: []*mast.Identifier{
			{Value: "first"},
			{Value: "err"},
		},
	}, root)

	firstInfo, ok := root.find("first")
	if !ok {
		t.Fatal("expected declaration for first")
	}
	if !firstInfo.fromMultiNameLet {
		t.Fatal("expected first declaration to be marked as from multi-name let")
	}

	errInfo, ok := root.find("err")
	if !ok {
		t.Fatal("expected declaration for err")
	}
	if !errInfo.fromMultiNameLet {
		t.Fatal("expected err declaration to be marked as from multi-name let")
	}

	collector.collectStatement(&mast.LetStatement{
		Names: []*mast.Identifier{{Value: "single"}},
	}, root)

	singleInfo, ok := root.find("single")
	if !ok {
		t.Fatal("expected declaration for single")
	}
	if singleInfo.fromMultiNameLet {
		t.Fatal("expected single-name declaration to not be marked as from multi-name let")
	}
}

func TestMacroSpecialFormsAreNotUndefinedInMacros(t *testing.T) {
	a := New()
	s := a.Analyze(`let unless = macro(condition, consequence, alternative) {
    quote(if (!(unquote(condition))) {
        unquote(consequence);
    } else {
        unquote(alternative);
    });
};`)

	diagnostics := Diagnostics(s, DefaultLintConfig())
	for _, diagnostic := range diagnostics {
		if strings.Contains(diagnostic.Message, "undefined identifier `quote`") {
			t.Fatalf("unexpected undefined quote diagnostic: %s", diagnostic.Message)
		}
		if strings.Contains(diagnostic.Message, "undefined identifier `unquote`") {
			t.Fatalf("unexpected undefined unquote diagnostic: %s", diagnostic.Message)
		}
	}
}

func TestBuiltinsHaveCompletionAndTeachingCoverage(t *testing.T) {
	a := New()
	s := a.Analyze("let sample = 1;\nsample;\n")
	items := s.CompletionItems()

	byLabel := make(map[string]struct {
		detail string
		has    bool
	}, len(items))
	for _, item := range items {
		detail := ""
		if item.Detail != nil {
			detail = *item.Detail
		}
		byLabel[item.Label] = struct {
			detail string
			has    bool
		}{detail: detail, has: true}
	}

	for _, entry := range builtin.Builtins {
		item, ok := byLabel[entry.Name]
		if !ok || !item.has {
			t.Fatalf("builtin %q missing from completion items", entry.Name)
		}
		if item.detail != "builtin" {
			t.Fatalf("builtin %q completion detail = %q, want %q", entry.Name, item.detail, "builtin")
		}

		hover, ok := builtinHoverText(entry.Name)
		if !ok {
			t.Fatalf("builtin %q missing hover coverage", entry.Name)
		}
		if !strings.Contains(hover, "builtin `") {
			t.Fatalf("builtin %q hover text = %q, want builtin teaching prefix", entry.Name, hover)
		}

		sig, ok := builtinSignatureInformation(entry.Name)
		if !ok {
			t.Fatalf("builtin %q missing signature coverage", entry.Name)
		}
		if strings.TrimSpace(sig.Label) == "" {
			t.Fatalf("builtin %q signature label is empty", entry.Name)
		}
	}
}

func TestBuiltinFamilyTeachingCoverageForLatestFamilies(t *testing.T) {
	cases := []struct {
		name         string
		wantContains []string
	}{
		{name: "process_kill", wantContains: []string{"Process forensics helper", "Sends a signal to a process"}},
		{name: "cache_stats", wantContains: []string{"In-memory cache helper", "Returns cache counters"}},
		{name: "text_similarity", wantContains: []string{"Text analysis and fuzzy matching helper", "Computes normalized Levenshtein similarity"}},
		{name: "regex_replace", wantContains: []string{"Regular expression matching and extraction helper", "Replaces all regex matches"}},
		{name: "policy_trace", wantContains: []string{"Policy evaluation and trace helper", "Runs policy evaluation with trace output"}},
		{name: "bin_pe_parse", wantContains: []string{"Binary analysis helper", "Parses PE headers"}},
		{name: "reg_timeline", wantContains: []string{"Registry forensics helper", "Returns timeline events extracted"}},
		{name: "email_parse", wantContains: []string{"Email forensics helper", "Parses a raw email message"}},
		{name: "mem_find_shellcode", wantContains: []string{"Memory forensics helper", "Scans a memory dump file"}},
		{name: "detect_persistence", wantContains: []string{"Detection helper", "Detects persistence indicators"}},
	}

	for _, tc := range cases {
		hover, ok := builtinHoverText(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing hover coverage", tc.name)
		}

		matched := false
		for _, want := range tc.wantContains {
			if strings.Contains(hover, want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("builtin %q hover text = %q, want one of %q", tc.name, hover, tc.wantContains)
		}

		sig, ok := builtinSignatureInformation(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing signature coverage", tc.name)
		}
		if strings.TrimSpace(sig.Label) == "" {
			t.Fatalf("builtin %q signature label is empty", tc.name)
		}
	}
}

func TestBuiltinRichTeachingForNewerBuiltins(t *testing.T) {
	cases := []struct {
		name          string
		wantSignature string
		wantContains  []string
	}{
		{name: "cache_put", wantSignature: "cache_put(name, key, value, ttlSeconds?)", wantContains: []string{"Stores a value in a named cache key", "- `ttlSeconds?`: Optional expiration in seconds"}},
		{name: "process_kill", wantSignature: "process_kill(pid, signal?)", wantContains: []string{"Sends a signal to a process", "- `pid`: Target process ID."}},
		{name: "regex_replace", wantSignature: "regex_replace(pattern, input, replacement)", wantContains: []string{"Replaces all regex matches", "- `pattern`: Regular expression pattern."}},
		{name: "policy_eval", wantSignature: "policy_eval(policy, input)", wantContains: []string{"Evaluates a loaded policy", "- `input`: Input data evaluated by the policy."}},
		{name: "bin_pe_parse", wantSignature: "bin_pe_parse(path)", wantContains: []string{"Parses PE headers", "- `path`: Path to PE file."}},
	}

	for _, tc := range cases {
		hover, ok := builtinHoverText(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing hover coverage", tc.name)
		}
		for _, want := range tc.wantContains {
			if !strings.Contains(hover, want) {
				t.Fatalf("builtin %q hover text = %q, want to contain %q", tc.name, hover, want)
			}
		}

		sig, ok := builtinSignatureInformation(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing signature coverage", tc.name)
		}
		if sig.Label != tc.wantSignature {
			t.Fatalf("builtin %q signature label = %q, want %q", tc.name, sig.Label, tc.wantSignature)
		}
	}
}

func TestBuiltinRichTeachingCoverageExpansion(t *testing.T) {
	cases := []struct {
		name          string
		wantSignature string
		wantSnippet   string
	}{
		{name: "text_contains", wantSignature: "text_contains(haystack, needle)", wantSnippet: "contains a substring"},
		{name: "policy_load", wantSignature: "policy_load(name, source)", wantSnippet: "Loads a policy module by name"},
		{name: "cache_clear", wantSignature: "cache_clear(name)", wantSnippet: "Clears all entries"},
		{name: "process_tree", wantSignature: "process_tree(rootPid?)", wantSnippet: "descendant processes"},
		{name: "cmd_builder", wantSignature: "cmd_builder(shell?)", wantSnippet: "command builder object"},
		{name: "fs_magic", wantSignature: "fs_magic(path)", wantSnippet: "file type/magic information"},
		{name: "bin_sections", wantSignature: "bin_sections(path)", wantSnippet: "section table information"},
		{name: "net_dns_query", wantSignature: "net_dns_query(name, qtype)", wantSnippet: "Queries DNS records"},
		{name: "reg_open", wantSignature: "reg_open(path)", wantSnippet: "returns a handle"},
		{name: "email_urls", wantSignature: "email_urls(raw)", wantSnippet: "Extracts and normalizes URLs"},
		{name: "mem_scan", wantSignature: "mem_scan(path, pattern)", wantSnippet: "Scans a memory image"},
		{name: "detect_suspicious_files", wantSignature: "detect_suspicious_files(paths)", wantSnippet: "suspicious file artifacts"},
		{name: "db_query", wantSignature: "db_query(db, query)", wantSnippet: "graph query expression"},
		{name: "bytes_cursor_read_u32_le", wantSignature: "bytes_cursor_read_u32_le(cursor)", wantSnippet: "32-bit little-endian"},
		{name: "lua_run_http", wantSignature: "lua_run_http(url)", wantSnippet: "runs a Lua script from an HTTP endpoint"},
	}

	for _, tc := range cases {
		hover, ok := builtinHoverText(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing hover coverage", tc.name)
		}
		if !strings.Contains(strings.ToLower(hover), strings.ToLower(tc.wantSnippet)) {
			t.Fatalf("builtin %q hover text = %q, want snippet containing %q", tc.name, hover, tc.wantSnippet)
		}

		sig, ok := builtinSignatureInformation(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing signature coverage", tc.name)
		}
		if sig.Label != tc.wantSignature {
			t.Fatalf("builtin %q signature label = %q, want %q", tc.name, sig.Label, tc.wantSignature)
		}
	}
}

func TestBuiltinBytesScalarTeachingCoverage(t *testing.T) {
	cases := []struct {
		name          string
		wantSignature string
		wantSnippet   string
	}{
		{name: "bytes_char_from_int", wantSignature: "bytes_char_from_int(value)", wantSnippet: "integer byte value"},
		{name: "bytes_int_from_char", wantSignature: "bytes_int_from_char(char)", wantSnippet: "single-character string"},
		{name: "bytes_read_u16_le", wantSignature: "bytes_read_u16_le(data, offset)", wantSnippet: "16-bit little-endian"},
		{name: "bytes_read_u16_be", wantSignature: "bytes_read_u16_be(data, offset)", wantSnippet: "16-bit big-endian"},
		{name: "bytes_read_u32_le", wantSignature: "bytes_read_u32_le(data, offset)", wantSnippet: "32-bit little-endian"},
		{name: "bytes_read_u32_be", wantSignature: "bytes_read_u32_be(data, offset)", wantSnippet: "32-bit big-endian"},
		{name: "bytes_read_u64_le", wantSignature: "bytes_read_u64_le(data, offset)", wantSnippet: "64-bit little-endian"},
		{name: "bytes_read_u64_be", wantSignature: "bytes_read_u64_be(data, offset)", wantSnippet: "64-bit big-endian"},
		{name: "bytes_write_u16_le", wantSignature: "bytes_write_u16_le(data, offset, value)", wantSnippet: "Writes unsigned 16-bit"},
		{name: "bytes_write_u16_be", wantSignature: "bytes_write_u16_be(data, offset, value)", wantSnippet: "Writes unsigned 16-bit"},
		{name: "bytes_write_u32_le", wantSignature: "bytes_write_u32_le(data, offset, value)", wantSnippet: "Writes unsigned 32-bit"},
		{name: "bytes_write_u32_be", wantSignature: "bytes_write_u32_be(data, offset, value)", wantSnippet: "Writes unsigned 32-bit"},
		{name: "bytes_write_u64_le", wantSignature: "bytes_write_u64_le(data, offset, value)", wantSnippet: "Writes unsigned 64-bit"},
		{name: "bytes_write_u64_be", wantSignature: "bytes_write_u64_be(data, offset, value)", wantSnippet: "Writes unsigned 64-bit"},
	}

	for _, tc := range cases {
		hover, ok := builtinHoverText(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing hover coverage", tc.name)
		}
		if !strings.Contains(strings.ToLower(hover), strings.ToLower(tc.wantSnippet)) {
			t.Fatalf("builtin %q hover text = %q, want snippet containing %q", tc.name, hover, tc.wantSnippet)
		}

		sig, ok := builtinSignatureInformation(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing signature coverage", tc.name)
		}
		if sig.Label != tc.wantSignature {
			t.Fatalf("builtin %q signature label = %q, want %q", tc.name, sig.Label, tc.wantSignature)
		}
	}
}

func TestBuiltinRichParameterDocsForNewerFamilies(t *testing.T) {
	cases := []struct {
		name        string
		wantBullets []string
	}{
		{name: "process_memory_scan", wantBullets: []string{"- `pid`:", "- `pattern`:"}},
		{name: "exec_string", wantBullets: []string{"- `command`:", "- `shell?`:"}},
		{name: "cmd_add", wantBullets: []string{"- `builder`:", "- `arg`:"}},
		{name: "net_dns_query", wantBullets: []string{"- `name`:", "- `qtype`:"}},
		{name: "reg_get_value", wantBullets: []string{"- `hiveHandle`:", "- `keyPath`:", "- `valueName`:"}},
		{name: "mem_read", wantBullets: []string{"- `path`:", "- `offset`:", "- `size`:"}},
		{name: "detect_suspicious_files", wantBullets: []string{"- `paths`:"}},
		{name: "db_add_relation", wantBullets: []string{"- `db`:", "- `from`:", "- `to`:", "- `relation`:", "- `props?`:"}},
	}

	for _, tc := range cases {
		hover, ok := builtinHoverText(tc.name)
		if !ok {
			t.Fatalf("builtin %q missing hover coverage", tc.name)
		}
		for _, bullet := range tc.wantBullets {
			if !strings.Contains(hover, bullet) {
				t.Fatalf("builtin %q hover text = %q, want parameter bullet %q", tc.name, hover, bullet)
			}
		}
	}
}
