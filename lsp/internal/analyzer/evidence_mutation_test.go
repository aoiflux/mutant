package analyzer

import (
	"strings"
	"testing"
)

// evidenceMessages returns the messages of every evidenceMutation diagnostic in
// src. Its one message says "Evidence is written once and read forever".
func evidenceMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "Evidence is written once") {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestEvidenceMutationFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a write to the image that was opened",
			`let img, err = raw_open("case01.dd");
let w, werr = fs_write("case01.dd", "notes");`,
			"`fs_write` overwrites the same path `raw_open` opened as a raw disk image",
		},
		{
			"a delete of the image path held in a name",
			`let path = "case01.E01";
let img, err = ewf_open(path);
let d, derr = fs_delete(path);`,
			"`fs_delete` deletes the same path `ewf_open` opened",
		},
		{
			"an append to a hive that is being read",
			`let hive, err = hive_open("SYSTEM");
let a, aerr = fs_append("SYSTEM", "x");`,
			"`fs_append` appends to the same path `hive_open` opened as a registry hive",
		},
		{
			"moving the evidence away",
			`let img, err = ntfs_open("disk.img");
let m, merr = fs_move("disk.img", "archive/disk.img");`,
			"`fs_move` moves the same path",
		},
		{
			"copying something over the evidence",
			`let img, err = vhdi_open("vm.vhdx");
let c, cerr = fs_copy("scratch.bin", "vm.vhdx");`,
			"`fs_copy` copies over the same path",
		},
		{
			// A string literal names the same file wherever the two calls sit,
			// so this one crosses a function boundary.
			"an opener and a write in different functions",
			`let examine = fn() {
  let img, err = raw_open("case01.dd");
  return img;
};
let tidy = fn() {
  let d, derr = fs_delete("case01.dd");
  return d;
};`,
			"`fs_delete` deletes the same path",
		},
		{
			"an archive opened and then overwritten",
			`let z, err = zip_open("exhibit.zip");
let w, werr = fs_write("exhibit.zip", data);`,
			"a zip archive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := evidenceMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("want exactly one report, got %d: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Fatalf("message %q does not contain %q", messages[0], tc.want)
			}
		})
	}
}

func TestEvidenceMutationStaysQuiet(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// Working on a copy is the correct procedure and must never be
			// reported: the image is the source, and the destination is new.
			"copying the evidence somewhere else",
			`let img, err = raw_open("case01.dd");
let c, cerr = fs_copy("case01.dd", "work/case01.dd");`,
		},
		{
			"a report written beside the evidence",
			`let img, err = raw_open("case01.dd");
let w, werr = fs_write("case01.report.json", report);`,
		},
		{
			// A path derived from the evidence path is a guess about two
			// run-time strings.
			"a derived path",
			`let path = "case01.dd";
let img, err = raw_open(path);
let w, werr = fs_write(path + ".log", entry);`,
		},
		{
			// db_open_disk is the analyst's own case database, not an exhibit.
			"writing to the program's own database path",
			`let db, err = db_open_disk("case.graph");
let w, werr = fs_write("case.graph", "x");`,
		},
		{
			// Two different functions, two different parameters that happen to
			// share a common name. Matching those would invent a finding.
			"a common parameter name in two functions",
			`let examine = fn(path) {
  let img, err = raw_open(path);
  return img;
};
let clean = fn(path) {
  let d, derr = fs_delete(path);
  return d;
};`,
		},
		{
			"a write with no opener anywhere",
			`let w, werr = fs_write("output.txt", data);`,
		},
		{
			"an opener with no mutation anywhere",
			`let img, err = raw_open("case01.dd");
let meta, merr = raw_metadata(img["handle"]);`,
		},
		{
			"a shadowed opener",
			`let raw_open = fn(p) { return p; };
let img = raw_open("case01.dd");
let w, werr = fs_write("case01.dd", "x");`,
		},
		{
			"a shadowed mutator",
			`let fs_write = fn(p, d) { return true; };
let img, err = raw_open("case01.dd");
let w = fs_write("case01.dd", "x");`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := evidenceMessages(t, tc.src); len(messages) != 0 {
				t.Fatalf("want silence, got %v", messages)
			}
		})
	}
}

// fs_move names two paths and either of them can be the evidence, but one
// call is one mistake.
func TestEvidenceMutationReportsAMoveOnce(t *testing.T) {
	src := `let img, err = raw_open("case01.dd");
let m, merr = fs_move("case01.dd", "case01.dd");`
	if messages := evidenceMessages(t, src); len(messages) != 1 {
		t.Fatalf("want one report, got %d: %v", len(messages), messages)
	}
}

func TestEvidenceMutationCanBeTurnedOff(t *testing.T) {
	src := `let img, err = raw_open("case01.dd");
let w, werr = fs_write("case01.dd", "notes");`

	config := DefaultLintConfig()
	config.EvidenceMutation = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "Evidence is written once") {
			t.Fatalf("rule is off but still reported: %s", d.Message)
		}
	}
}
