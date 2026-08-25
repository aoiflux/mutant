package analyzer

import (
	"strings"
	"testing"
)

// spawnWriteMessages returns the messages of every spawnGlobalWrite diagnostic
// in src. Those are the only lint messages that read "its own copy of the
// globals".
func spawnWriteMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "its own copy of the globals") {
			out = append(out, d.Message)
		}
	}
	return out
}

// The defect: the write compiles, runs, reports nothing, and lands in a copy of
// the globals that is discarded when the worker finishes.
func TestSpawnGlobalWriteFiresOnAWriteThatCannotEscape(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"plain assignment in a spawned closure",
			`let total = 0;
let t, e = spawn(fn() { total = 1; });`,
			"`total` is a global",
		},
		{
			"compound assignment",
			`let total = 0;
let t, e = spawn(fn() { total += 1; });`,
			"`total` is a global",
		},
		{
			"postfix increment",
			`let seen = 0;
let t, e = spawn(fn() { seen++; });`,
			"`seen` is a global",
		},
		{
			"pmap callback",
			`let count = 0;
let out, e = pmap([1, 2], fn(n) { count = count + n; return n; });`,
			"pmap runs this callback",
		},
		{
			"peach callback",
			`let count = 0;
let ok, e = peach([1, 2], fn(n) { count = n; });`,
			"peach runs this callback",
		},
		{
			"index write into a global container",
			`let bucket = [0, 0];
let t, e = spawn(fn() { bucket[0] = 1; });`,
			"`bucket` is a global",
		},
		{
			"write from a function nested inside the callback",
			`let total = 0;
let t, e = spawn(fn() { let bump = fn() { total = 1; }; bump(); });`,
			"`total` is a global",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := spawnWriteMessages(t, tc.src)
			if len(got) != 1 {
				t.Fatalf("expected exactly one diagnostic, got %d: %v", len(got), got)
			}
			if !strings.Contains(got[0], tc.want) {
				t.Fatalf("message does not say what is wrong:\n got: %s\nwant substring: %s", got[0], tc.want)
			}
		})
	}
}

// A false positive here tells someone their correct code is wrong, so each of
// these has to stay silent. They are the reasons the rule declines, one case
// each.
func TestSpawnGlobalWriteStaysSilentWhereTheWriteIsFine(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"a parameter shadows the global",
			`let total = 0;
let t, e = spawn(fn(total) { total = 1; }, 5);`,
		},
		{
			"a let inside the callback shadows the global",
			`let total = 0;
let t, e = spawn(fn() { let total = 0; total = 1; });`,
		},
		{
			"a let further down the body still shadows",
			`let total = 0;
let t, e = spawn(fn() { let inner = 1; let total = inner; total = 2; });`,
		},
		{
			"a local of the callback that was never global",
			`let t, e = spawn(fn() { let scratch = 0; scratch = 1; });`,
		},
		{
			"a nested function rebinds the name for itself",
			`let total = 0;
let t, e = spawn(fn() { let bump = fn(total) { total = 1; }; bump(1); });`,
		},
		{
			"the same write in an ordinary closure, where it does take effect",
			`let total = 0;
let bump = fn() { total = 1; };
bump();`,
		},
		{
			"a global write outside any callback",
			`let total = 0;
total = 1;`,
		},
		{
			"the callback is passed by name, so it may be called normally elsewhere",
			`let total = 0;
let work = fn() { total = 1; };
let t, e = spawn(work);`,
		},
		{
			"reading a global is fine; only writing is lost",
			`let limit = 10;
let t, e = spawn(fn() { let seen = limit + 1; return seen; });`,
		},
		{
			"map is not a worker builtin",
			`let count = 0;
let out = map([1, 2], fn(n) { count = n; return n; });`,
		},
		{
			"a for-loop counter declared inside the callback",
			`let i = 0;
let t, e = spawn(fn() { for (let i = 0; i < 3; i++) { i = i + 1; }; });`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := spawnWriteMessages(t, tc.src); len(got) != 0 {
				t.Fatalf("expected no diagnostic, got %d: %v", len(got), got)
			}
		})
	}
}

// Two writes to two different globals are two findings, not one: each is a
// separate line the author has to change.
func TestSpawnGlobalWriteReportsEveryWrite(t *testing.T) {
	src := `let a = 0;
let b = 0;
let t, e = spawn(fn() { a = 1; b = 2; });`

	if got := spawnWriteMessages(t, src); len(got) != 2 {
		t.Fatalf("expected two diagnostics, got %d: %v", len(got), got)
	}
}

// The rule has to be switchable like every other one, and off has to mean off.
func TestSpawnGlobalWriteRespectsItsSeveritySetting(t *testing.T) {
	src := `let total = 0;
let t, e = spawn(fn() { total = 1; });`

	config := DefaultLintConfig()
	config.SpawnGlobalWrite = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "its own copy of the globals") {
			t.Fatalf("the rule fired while switched off: %s", d.Message)
		}
	}
}
