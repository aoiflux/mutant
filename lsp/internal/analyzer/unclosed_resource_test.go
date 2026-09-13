package analyzer

import (
	"strings"
	"testing"

	"mutant/builtin"
)

// unclosedMessages returns the messages of every unclosedResource diagnostic in
// src. They are the only lint messages that read "opens a resource".
func unclosedMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "opens a resource") {
			out = append(out, d.Message)
		}
	}
	return out
}

// The defect: the program compiles, runs, reports nothing, and holds an OS
// resource until the process exits.
func TestUnclosedResourceFiresOnAnAbandonedHandle(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a disk image opened and never closed",
			`let img, err = ntfs_open("disk.img");
let files, list_err = ntfs_list_files(img["handle"], "/");`,
			"`ntfs_open` opens a resource",
		},
		{
			"a channel that outlives the program",
			`let c, err = chan_new(1);
let sent, send_err = chan_send(c, 1, 0);`,
			"`chan_new` opens a resource",
		},
		{
			// The shape §7 names: a loop over a corpus, one handle leaked per
			// iteration, and the process holding every one of them.
			"a handle opened once per iteration of a bounded loop",
			`let scan = fn(paths) {
  for (let i = 0; i < len(paths); i = i + 1) {
    let img, err = ntfs_open(paths[i]);
    let files, list_err = ntfs_list_files(img["handle"], "/");
  };
  return true;
};`,
			"`ntfs_open` opens a resource",
		},
		{
			"an archive opened inside a function",
			`let scan = fn(path) {
  let zip, err = zip_open(path);
  let entries, list_err = zip_list(zip["handle"]);
  return len(entries);
};`,
			"`zip_open` opens a resource",
		},
		{
			// A close in one function does not close what another opened. The
			// scope is the unit precisely so this is still reported.
			"closed in a different function",
			`let cleanup = fn(h) { let ok, e = ntfs_close(h); return ok; };
let scan = fn(path) {
  let img, err = ntfs_open(path);
  let files, list_err = ntfs_list_files(img["handle"], "/");
  return len(files);
};`,
			"`ntfs_open` opens a resource",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := unclosedMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("got %d diagnostics, want 1: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Errorf("message = %q, want it to contain %q", messages[0], tc.want)
			}
			if !strings.Contains(messages[0], "with_resource") {
				t.Errorf("message = %q; it does not offer the guarantee that fixes it", messages[0])
			}
		})
	}
}

// A false positive here tells someone their correct code leaks, so every shape
// the rule cannot follow has to leave it quiet. These are the shapes.
func TestUnclosedResourceDeclinesWhenItCannotBeSure(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"closed on the straight-line path",
			`let img, err = ntfs_open("disk.img");
let files, list_err = ntfs_list_files(img["handle"], "/");
let closed, close_err = ntfs_close(img["handle"]);`,
		},
		{
			"closed in the else arm, as the corpus writes it",
			`let img, err = ntfs_open("disk.img");
if (err) {
  putln("ntfs_open error:", err);
} else {
  let files, list_err = ntfs_list_files(img["handle"], "/");
  let closed, close_err = ntfs_close(img["handle"]);
}`,
		},
		{
			// The closer is a string here, not a call. Reading only calls would
			// report the one construct that makes the report wrong.
			"wrapped in with_resource",
			`let img, err = ntfs_open("disk.img");
let files, ferr = with_resource(img, "ntfs_close", fn(h) { return ntfs_list_files(h["handle"], "/"); });`,
		},
		{
			"the opener's result never bound at all",
			`let files, err = with_resource(ntfs_open("disk.img"), "ntfs_close", fn(h) { return 1; });`,
		},
		{
			"the handle is returned to a caller",
			`let open_image = fn(path) {
  let img, err = ntfs_open(path);
  return img;
};`,
		},
		{
			"the handle is handed to a helper",
			`let process = fn(h) { let ok, e = ntfs_close(h); return ok; };
let img, err = ntfs_open("disk.img");
process(img);`,
		},
		{
			"the handle is stored in a structure",
			`let img, err = ntfs_open("disk.img");
let images = [img];`,
		},
		{
			"the handle is captured by a closure the rule cannot follow",
			`let img, err = ntfs_open("disk.img");
let t, terr = spawn(fn() { return img; });`,
		},
		{
			// A file that binds the opener's own name is not calling the
			// builtin at all.
			"the opener name is shadowed",
			`let ntfs_open = fn(p) { return p; };
let img = ntfs_open("disk.img");`,
		},
		{
			"a builtin that opens nothing",
			`let reachable, err = net_dial("127.0.0.1:80", 500);`,
		},
		{
			// The server shape: net_serve runs an accept loop that has no
			// ordinary return, so the program never reaches a close and is not
			// wrong for that. Every server in the corpus is written this way.
			"a listener handed to net_serve",
			`let ln, err = net_listen("127.0.0.1:8130");
let ok, serr = net_serve(ln, "handler.mut", "ctx");`,
		},
		{
			"a listener used inside a loop with no exit",
			`let ln, err = net_listen("127.0.0.1:8130");
for (;;) {
  let acc, aerr = net_accept(ln, 0);
  net_conn_close(acc["handle"]);
}`,
		},
		{
			"a listener used inside a loop whose condition is always true",
			`let ln, err = net_tls_listen("127.0.0.1:8443", "cert", "key", {});
for (let i = 0; true; i = i + 1) {
  let acc, aerr = net_accept(ln, 0);
}`,
		},
		{
			"the binding discards the handle",
			`let _, err = chan_new(1);`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := unclosedMessages(t, tc.src); len(messages) != 0 {
				t.Errorf("reported %v on code the rule cannot be sure about", messages)
			}
		})
	}
}

// The rule is only as honest as its table, and the table is hand-written
// because the naming is not regular -- hashset opens with _load, chan with
// _new, a connection is closed by net_conn_close. This pins it to the registry
// so a new close family cannot be added without being accounted for.
func TestResourceFamiliesCoverEveryCloser(t *testing.T) {
	claimed := make(map[string]struct{}, len(resourceFamilies))
	for _, family := range resourceFamilies {
		if builtin.GetBuiltinByName(family.closer) == nil {
			t.Errorf("closer %q is not a registered builtin", family.closer)
		}
		if _, duplicate := claimed[family.closer]; duplicate {
			t.Errorf("closer %q is claimed by two families", family.closer)
		}
		claimed[family.closer] = struct{}{}

		if len(family.openers) == 0 {
			t.Errorf("family for %q names no opener", family.closer)
		}
		for _, opener := range family.openers {
			if builtin.GetBuiltinByName(opener) == nil {
				t.Errorf("opener %q is not a registered builtin", opener)
			}
		}
		if len(family.prefixes) == 0 {
			t.Errorf("family for %q names no consumer prefix, so every use of its handle escapes", family.closer)
		}
	}

	for _, entry := range builtin.Builtins {
		if !strings.HasSuffix(entry.Name, "_close") {
			continue
		}
		if _, covered := claimed[entry.Name]; covered {
			continue
		}
		if reason, exempt := nonResourceClosers[entry.Name]; exempt {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is exempt from the rule with no reason given", entry.Name)
			}
			continue
		}
		t.Errorf("%s closes something the rule knows nothing about; add its family to resourceFamilies, "+
			"or -- if it closes nothing a name can hold -- to nonResourceClosers with the reason", entry.Name)
	}
}

// The rule is off when its severity is, like every other rule.
func TestUnclosedResourceRespectsItsSeverity(t *testing.T) {
	src := `let img, err = ntfs_open("disk.img");
let files, list_err = ntfs_list_files(img["handle"], "/");`

	config := DefaultLintConfig()
	config.UnclosedResource = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "opens a resource") {
			t.Fatalf("the rule reported %q while switched off", d.Message)
		}
	}
}
