package analyzer

import (
	"strings"
	"testing"

	"mutant/builtin"
)

// uncheckedMessages returns the messages of every uncheckedError diagnostic in
// src. They are the only lint messages that read "can fail".
func uncheckedMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "can fail") {
			out = append(out, d.Message)
		}
	}
	return out
}

// The defect: the call failed, the value beside the error is null, and the
// program carries on with nothing and reports success.
func TestUncheckedErrorFiresOnAnIgnoredFailure(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"the error is never mentioned again",
			`let contents, err = fs_read("notes.txt");
putln("file contents:");
putln(contents);`,
			"`fs_read` can fail",
		},
		{
			// The shape unusedDeclaration structurally cannot see: `err` is
			// read further down, so the name is used, but this binding of it
			// was replaced before anything looked.
			"the error is replaced before it is read",
			`let ok, err = cache_put("c", "k", 1);
let entry, err = cache_get("c", "k");
putln("entry:", entry, "err:", err);`,
			"`cache_put` can fail",
		},
		{
			"the failure is ignored inside a function",
			`let report = fn(path) {
  let info, err = fs_stat(path);
  return info["size"];
};`,
			"`fs_stat` can fail",
		},
		{
			// The value is explicitly discarded, which says nothing about the
			// error -- and here the error is what was worth having.
			"the value is discarded and the error dropped",
			`let _, err = fs_mkdir("out");
putln("done");`,
			"`fs_mkdir` can fail",
		},
		{
			// A read of `err` above the binding is a read of whatever `err`
			// was before this call, so it does not answer for this one.
			"the only mention of the name comes before the binding",
			`let first, err = fs_read("a.txt");
if (err) { putln("first failed"); };
let second, err = fs_read("b.txt");
putln(second);`,
			"`fs_read` can fail",
		},
		{
			// The value is a HASH, so reading it is not reading the failure:
			// on failure it is null and the index below raises instead.
			"a hash value used without the error being checked",
			`let resp, err = http_get("https://example.com");
putln("status:", resp["status"]);`,
			"`http_get` can fail",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := uncheckedMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("got %d diagnostics, want 1: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Errorf("message = %q, want it to contain %q", messages[0], tc.want)
			}
			if !strings.Contains(messages[0], "`_`") {
				t.Errorf("message = %q; it does not say how to silence itself", messages[0])
			}
		})
	}
}

// A false positive here tells someone who handled a failure that they ignored
// it, which is the one thing that would make the rule not worth having. Every
// shape below leaves it quiet.
func TestUncheckedErrorDeclinesWhenTheFailureIsAccountedFor(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"the error is tested",
			`let contents, err = fs_read("notes.txt");
if (err) { putln("read failed:", err); };`,
		},
		{
			// Deliberately generous: printing an error is reading it. Deciding
			// that it is not good enough would be a judgement about someone's
			// program rather than a fact about it.
			"the error is printed",
			`let contents, err = fs_read("notes.txt");
putln("err:", err);`,
		},
		{
			"the error is propagated to the caller",
			`let load = fn(path) {
  let contents, err = fs_read(path);
  return contents, err;
};`,
		},
		{
			"the error is handed to a helper",
			`let report = fn(e) { putln(e); return true; };
let contents, err = fs_read("notes.txt");
report(err);`,
		},
		{
			"the error is stored in a structure",
			`let contents, err = fs_read("notes.txt");
let failures = [err];`,
		},
		{
			// `_` is how the language says "this can fail and I am choosing
			// not to look". Reporting it would leave no way to say that.
			"the error binding is discarded",
			`let contents, _ = fs_read("notes.txt");
putln(contents);`,
		},
		{
			// One name against a pair is builtinPairReturn's report: the name
			// holds the whole MULTI_VALUE, so there is no error binding.
			"a single name binds the pair",
			`let both = fs_read("notes.txt");
putln(both);`,
		},
		{
			// push returns a bare ARRAY, so there is no error half at all.
			"the builtin returns a single value",
			`let items = ["a"];
let updated, err = push(items, "b");
putln(updated);`,
		},
		{
			"the builtin name is shadowed",
			`let fs_read = fn(p) { return p; };
let contents, err = fs_read("notes.txt");
putln(contents);`,
		},
		{
			// The failure is caught through the value: on failure req is null,
			// so the guard runs and the use below it does not.
			"the value is tested in an if condition",
			`let req, rerr = http_conn_read_request(0, 8000);
let path = "/";
if (req) { path = req["path"]; };
putln(path);`,
		},
		{
			"the value is tested in a for condition",
			`let listing, err = fs_list("out");
for (let i = 0; listing; i = i + 1) {
  putln(i);
}`,
		},
		{
			// A BOOLEAN success value is false on every failure path, so
			// reading it anywhere carries the failure with it.
			"a boolean success flag is read",
			`let wrote, err = fs_write("out.txt", "body");
if (wrote) { putln("wrote it"); };`,
		},
		{
			"a boolean success flag is returned rather than tested",
			`let save = fn(path, body) {
  let wrote, err = fs_write(path, body);
  return wrote;
};`,
		},
		{
			// A closure runs when it is called, not where it is written, so a
			// mention inside one is excused without asking where it sits.
			"the error is captured by a closure",
			`let contents, err = fs_read("notes.txt");
let report = fn() { return err; };
putln(contents);`,
		},
		{
			"the error is read before the name is rebound",
			`let first, err = fs_read("a.txt");
if (err) { putln("a failed"); };
let second, err = fs_read("b.txt");
if (err) { putln("b failed"); };
putln(first, second);`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := uncheckedMessages(t, tc.src); len(messages) != 0 {
				t.Errorf("reported %v on code that accounts for the failure", messages)
			}
		})
	}
}

// The rule's whole reason for existing over unusedDeclaration is that it
// answers for one binding rather than for a name. This pins that: the same
// `err`, twice in one scope, one dropped and one checked.
func TestUncheckedErrorAnswersPerBindingRatherThanPerName(t *testing.T) {
	src := `let a, err = fs_read("a.txt");
let b, err = fs_read("b.txt");
if (err) { putln("b failed:", err); };
putln(a, b);`

	messages := uncheckedMessages(t, src)
	if len(messages) != 1 {
		t.Fatalf("got %d diagnostics, want exactly the dropped one: %v", len(messages), messages)
	}
}

// The rule reads builtin.ReturnSpec, so what it considers fallible has to be
// what the registry says is fallible -- not a list that can drift from it.
func TestUncheckedErrorFollowsTheDeclaredContract(t *testing.T) {
	pairs, singles := 0, 0
	for _, entry := range builtin.Builtins {
		spec, declared := builtin.ReturnSpec(entry.Name)
		if !declared {
			continue
		}
		if spec.Pair {
			pairs++
		} else {
			singles++
		}
	}
	if pairs == 0 || singles == 0 {
		t.Fatalf("the registry declares %d pair and %d single returns; the rule cannot be meaningful against that", pairs, singles)
	}

	// A builtin the registry calls fallible is reported; one it does not is
	// never reported, whatever its name looks like.
	if got := uncheckedMessages(t, `let value, err = json_parse("{}");
putln(value);`); len(got) != 1 {
		t.Errorf("a declared pair return was not reported: %v", got)
	}
	if got := uncheckedMessages(t, `let value, err = str_upper("abc");
putln(value);`); len(got) != 0 {
		t.Errorf("a declared single return was reported: %v", got)
	}
}

// The rule is off when its severity is, like every other rule.
func TestUncheckedErrorRespectsItsSeverity(t *testing.T) {
	src := `let contents, err = fs_read("notes.txt");
putln(contents);`

	config := DefaultLintConfig()
	config.UncheckedError = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "can fail") {
			t.Fatalf("the rule reported %q while switched off", d.Message)
		}
	}
}
