package webrepl

import (
	"strings"
	"testing"
)

// The browser REPL used to be its own tree-walking interpreter, so it disagreed
// with the compiler+VM the CLI runs. Each case here is a construct that used to
// behave differently (or not work at all) in the browser; they pass now because
// the browser runs the same pipeline.
func TestBrowserRunsRealVMSemantics(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "index assignment",
			input: `let a = [1, 2, 3]; a[1] = 99; a[1]`,
			want:  "99",
		},
		{
			name:  "string indexing",
			input: `let s = "AB"; s[0]`,
			want:  "A",
		},
		{
			name:  "negative index counts from the end",
			input: `let a = [1, 2, 3]; a[-1]`,
			want:  "3",
		},
		{
			name:  "compound assignment",
			input: `let n = 10; n += 5; n *= 2; n`,
			want:  "30",
		},
		{
			name:  "postfix increment",
			input: `let i = 0; i++; i++; i`,
			want:  "2",
		},
		{
			name:  "short-circuit logical operators",
			input: `let hits = 0; let bump = fn() { hits = hits + 1; return true; }; false && bump(); hits`,
			want:  "0",
		},
		{
			name:  "closures capture free variables",
			input: `let adder = fn(n) { return fn(x) { return x + n; }; }; let add10 = adder(10); add10(5)`,
			want:  "15",
		},
		{
			name:  "higher-order builtins call user closures",
			input: `let doubled = map([1, 2, 3], fn(x) { return x * 2; }); doubled[2]`,
			want:  "6",
		},
		{
			name:  "multi-value destructuring",
			input: `let f = fn() { return 1, 2; }; let a, b = f(); a + b`,
			want:  "3",
		},
		{
			name:  "field assignment on a struct",
			input: `struct P { x; y; }; let p = P { x: 1, y: 2 }; p.y = 9; p.y`,
			want:  "9",
		},
		{
			name:  "macros expand before compilation",
			input: `let unless = macro(cond, body) { quote(if (!unquote(cond)) { unquote(body) }); }; unless(false, 42)`,
			want:  "42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A fresh session per case so one case cannot mask another through
			// leftover globals.
			got := evalInput(t, New(), tt.input)
			if got != tt.want {
				t.Fatalf("Eval(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Errors the tree-walking browser REPL either missed entirely or reported
// differently from the CLI.
func TestBrowserReportsRealVMErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantPart string
	}{
		{
			name:     "struct literal field names are validated",
			input:    `struct P { x; y; }; let p = P { x: 1, z: 2 };`,
			wantPart: "missing field y for struct P",
		},
		{
			name:     "calling with too few arguments is an error, not a panic",
			input:    `let f = fn(a, b) { return a + b; }; f(1)`,
			wantPart: "wrong number of arguments",
		},
		{
			name:     "unknown names are caught while compiling",
			input:    `unknown_fn(1)`,
			wantPart: "undefined variable: unknown_fn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New().Eval(tt.input)
			if err == nil {
				t.Fatalf("Eval(%q) expected an error, got none", tt.input)
			}
			if !strings.Contains(err.Error(), tt.wantPart) {
				t.Fatalf("Eval(%q) error = %q, want it to contain %q", tt.input, err, tt.wantPart)
			}
		})
	}
}

// Host-bound builtins must not be reachable from a browser sandbox, and the
// pure-computation library must be.
func TestBrowserSafetyGate(t *testing.T) {
	for _, name := range []string{"fs_read", "net_connect", "exec_string", "process_list", "sqlite_query", "imphash", "plist_parse", "db_open_disk", "lua_run_file", "gets", "sleep_ms"} {
		if BrowserSafe(name) {
			t.Errorf("%s reaches the host and must not be browser-safe", name)
		}
	}

	// A wasm build has one thread, so a wait with nobody to wake it is a fatal
	// runtime deadlock that takes the session down rather than an error the
	// session can report. pmap and peach are the deliberate exception: they only
	// ever wait on work that is already running, so they always finish.
	for _, name := range []string{"spawn", "task_wait", "task_done", "chan_new", "chan_send", "chan_recv", "chan_try_recv", "chan_close"} {
		if BrowserSafe(name) {
			t.Errorf("%s can wait indefinitely and must not be browser-safe", name)
		}
	}

	for _, name := range []string{"str_upper", "regex_find", "hash_sha256", "json_parse", "time_format", "base64_encode", "defang", "email_parse", "timeline_sort", "aes_encrypt", "map", "cache_put", "db_open", "pmap", "peach"} {
		if !BrowserSafe(name) {
			t.Errorf("%s always finishes and should be browser-safe", name)
		}
	}

	// A host-bound name must not merely fail at runtime -- it must not resolve.
	if _, err := New().Eval(`fs_read("/etc/passwd")`); err == nil {
		t.Fatal("fs_read resolved in the browser REPL; it must be undefined there")
	}
	if _, err := New().Eval(`chan_new(1)`); err == nil {
		t.Fatal("chan_new resolved in the browser REPL; it must be undefined there")
	}
}
