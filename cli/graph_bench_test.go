package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The symbol graph's two halves, measured on a program large enough for a
// change to either to show.
//
// The program is generated rather than checked in: a chain of modules, each
// importing the one before it, whose functions call across that import and
// name the previous module's struct and enum. Those last two are the
// cross-module type uses the export did not record before 2.6.0, so the same
// program measures the export before and after it learned to.
//
// Read B/op and allocs/op. ns/op is only comparable between interleaved runs;
// builtin/db_bench_test.go says why.

// benchSize is one generated program: how many modules, and how many
// functions each declares.
type benchSize struct {
	name      string
	modules   int
	functions int
}

var benchSizes = []benchSize{
	{"M", 20, 25},
	{"L", 100, 100},
}

// benchProgram writes the generated program and returns its entry file.
func benchProgram(b *testing.B, size benchSize) string {
	b.Helper()
	root := b.TempDir()
	write := func(rel, src string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	for m := 0; m < size.modules; m++ {
		var src strings.Builder
		if m > 0 {
			fmt.Fprintf(&src, "import \"m%d.mut\";\n", m-1)
		}
		fmt.Fprintf(&src, "struct S%d { a, b }\n", m)
		fmt.Fprintf(&src, "enum E%d { One, Two }\n", m)
		for f := 0; f < size.functions; f++ {
			if m == 0 {
				fmt.Fprintf(&src, "let f%d_%d = fn(x) { return x + %d; };\n", m, f, f)
				continue
			}
			fmt.Fprintf(&src, "let f%d_%d = fn(x) { let s = S%d{a: x, b: %d}; let e = E%d.One; return m%d.f%d_%d(s.a); };\n",
				m, f, m-1, f, m-1, m-1, m-1, f)
		}
		write(fmt.Sprintf("lib/m%d.mut", m), src.String())
	}
	last := size.modules - 1
	write("main.mut", fmt.Sprintf("import \"lib/m%d.mut\";\nputln(m%d.f%d_0(1));\n", last, last, last))
	return filepath.Join(root, "main.mut")
}

func BenchmarkGraphExport(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(size.name, func(b *testing.B) {
			entry := benchProgram(b, size)
			outRoot := b.TempDir()
			b.ReportAllocs()
			n := 0
			for b.Loop() {
				n++
				out := filepath.Join(outRoot, strconv.Itoa(n))
				if _, err := ExportGraph(ExportOptions{Entry: entry, Out: out}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchQuestionArguments is what each question is asked about in the generated
// M program. Every question on the list must have an entry, so a question
// cannot be added without being measured; where is asked twice because a miss
// reads every declaration and a hit does not.
var benchQuestionArguments = map[string][]string{
	"summary":  {""},
	"modules":  {""},
	"where":    {"f10_3", "no_such_name"},
	"callers":  {"f10_3"},
	"callees":  {"f10_3"},
	"outline":  {"lib/m10.mut"},
	"exported": {""},
}

// BenchmarkGraphQuery asks every question the way the command does, opening
// and closing the store each time, because that is what a query costs.
func BenchmarkGraphQuery(b *testing.B) {
	size := benchSizes[0]
	entry := benchProgram(b, size)
	dir := filepath.Join(b.TempDir(), "store")
	if _, err := ExportGraph(ExportOptions{Entry: entry, Out: dir}); err != nil {
		b.Fatal(err)
	}
	for _, question := range QueryQuestions() {
		arguments, measured := benchQuestionArguments[question.Name]
		if !measured {
			b.Fatalf("question %q has no benchmark argument; add one to benchQuestionArguments", question.Name)
		}
		for _, argument := range arguments {
			name := question.Name
			if argument != "" {
				name += "/" + argument
			}
			b.Run(name, func(b *testing.B) {
				opts := QueryOptions{Store: dir, Question: question.Name, Argument: argument}
				if _, err := QueryGraph(opts); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					if _, err := QueryGraph(opts); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
