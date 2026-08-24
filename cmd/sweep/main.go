// Command sweep compiles and runs every Mutant example, honouring the
// `// mutant:sweep` markers that say how each one expects to be treated.
//
// Sweeping the examples is the cheapest end-to-end check this repo has: it runs
// the real CLI over 100-odd real programs and has caught engine defects that no
// unit test did. It was previously done with throwaway shell, which is why the
// same two problems kept recurring -- servers that never return read as hangs,
// and per-example artifacts left in a shared working directory produce diffs
// that are not real. Both are handled here: markers settle the first, and every
// run starts from the same tree state.
//
// Usage:
//
//	go run ./cmd/sweep [options] [paths...]
//	go run ./cmd/sweep --levels 0,5,10          # also compare output across mutation levels
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"mutant/global"
)

type options struct {
	tree     string
	levels   []int
	timeout  time.Duration
	alive    time.Duration
	mutant   string
	seed     int64
	password string
	keep     bool
	verbose  bool
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	opts, paths, err := parseOptions(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sweep: %v\n", err)
		return 2
	}

	files, err := collectExamples(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sweep: %v\n", err)
		return 2
	}
	if len(files) == 0 {
		fmt.Println("no .mut files found")
		return 0
	}

	binary, cleanupBinary, err := resolveMutantBinary(opts.mutant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sweep: %v\n", err)
		return 2
	}
	defer cleanupBinary()

	scratch, err := newScratch(opts.tree, opts.keep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sweep: %v\n", err)
		return 2
	}
	defer scratch.cleanup()

	fmt.Printf("sweeping %d examples at mutation %s\n\n", len(files), formatLevels(opts.levels))

	runner := &sweeper{opts: opts, binary: binary, scratch: scratch}
	results := make([]result, 0, len(files))
	for _, file := range files {
		res := runner.sweepOne(file)
		results = append(results, res)
		fmt.Println(res)
	}

	return report(results)
}

func parseOptions(argv []string) (options, []string, error) {
	opts := options{}
	levels := ""

	set := flag.NewFlagSet("sweep", flag.ContinueOnError)
	set.StringVar(&opts.tree, "tree", "examples", "directory copied into the scratch working tree")
	set.StringVar(&levels, "levels", "0", "comma-separated mutation levels; more than one compares output across them")
	set.DurationVar(&opts.timeout, "timeout", 60*time.Second, "per-run wall clock limit")
	set.DurationVar(&opts.alive, "alive", 3*time.Second, "how long a `server` example must stay up to pass")
	set.StringVar(&opts.mutant, "mutant", "", "path to a prebuilt mutant binary (default: build one)")
	set.Int64Var(&opts.seed, "seed", 424242, "build seed")
	set.StringVar(&opts.password, "password", "sweep-Pass!42", "build password")
	set.BoolVar(&opts.keep, "keep", false, "keep the scratch tree instead of deleting it")
	set.BoolVar(&opts.verbose, "v", false, "print each run's output")
	if err := set.Parse(argv); err != nil {
		return opts, nil, err
	}

	parsed, err := parseLevels(levels)
	if err != nil {
		return opts, nil, err
	}
	opts.levels = parsed

	paths := set.Args()
	if len(paths) == 0 {
		paths = []string{opts.tree}
	}
	return opts, paths, nil
}

func parseLevels(text string) ([]int, error) {
	levels := []int{}
	for _, field := range strings.Split(text, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		level, err := strconv.Atoi(field)
		if err != nil || level < 0 || level > 10 {
			return nil, fmt.Errorf("bad mutation level %q: want 0-10", field)
		}
		levels = append(levels, level)
	}
	if len(levels) == 0 {
		return nil, errors.New("--levels named no levels")
	}
	return levels, nil
}

func formatLevels(levels []int) string {
	parts := make([]string, 0, len(levels))
	for _, level := range levels {
		parts = append(parts, strconv.Itoa(level))
	}
	return strings.Join(parts, ", ")
}

func collectExamples(paths []string) ([]string, error) {
	seen := map[string]bool{}
	files := []string{}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if strings.HasSuffix(path, global.MutantSourceCodeFileExtention) && !seen[path] {
				seen[path] = true
				files = append(files, filepath.ToSlash(path))
			}
			continue
		}

		err = filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(candidate, global.MutantSourceCodeFileExtention) {
				return nil
			}
			slashed := filepath.ToSlash(candidate)
			if !seen[slashed] {
				seen[slashed] = true
				files = append(files, slashed)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sort.Strings(files)
	return files, nil
}

// resolveMutantBinary returns a mutant executable to sweep with. Building one is
// the default so that a sweep always exercises the working tree rather than
// whatever happens to be on PATH.
func resolveMutantBinary(supplied string) (string, func(), error) {
	if supplied != "" {
		absolute, err := filepath.Abs(supplied)
		if err != nil {
			return "", func() {}, err
		}
		return absolute, func() {}, nil
	}

	dir, err := os.MkdirTemp("", "mutant-sweep-bin-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }

	binary := filepath.Join(dir, "mutant")
	if isWindows() {
		binary += ".exe"
	}

	fmt.Println("building mutant...")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("building mutant: %v\n%s", err, output)
	}
	return binary, cleanup, nil
}

func isWindows() bool { return runtime.GOOS == "windows" }

// scratch is a throwaway copy of the example tree. Examples write into their
// working directory -- reports, graph databases, generated .mu files -- so every
// run has to start from the same state or a later run sees an earlier run's
// leftovers. Sweeping in a copy also means a sweep never dirties the repository.
type scratch struct {
	root     string
	manifest map[string]bool
	keep     bool
}

func newScratch(tree string, keep bool) (*scratch, error) {
	root, err := os.MkdirTemp("", "mutant-sweep-")
	if err != nil {
		return nil, err
	}

	if err := copyTree(tree, filepath.Join(root, tree)); err != nil {
		os.RemoveAll(root)
		return nil, fmt.Errorf("copying %s: %w", tree, err)
	}

	area := &scratch{root: root, manifest: map[string]bool{}, keep: keep}
	if err := area.record(); err != nil {
		os.RemoveAll(root)
		return nil, err
	}
	return area, nil
}

// record snapshots what the tree holds, so reset knows what is a leftover.
func (s *scratch) record() error {
	return filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		s.manifest[filepath.ToSlash(relative)] = true
		return nil
	})
}

// reset removes everything the last run created. Files that were part of the
// original tree are left alone even if a run rewrote them -- an example that
// edits its own inputs would need a full re-copy, and none does.
func (s *scratch) reset() error {
	leftovers := []string{}

	err := filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, relErr := filepath.Rel(s.root, path)
		if relErr != nil {
			return relErr
		}
		if !s.manifest[filepath.ToSlash(relative)] {
			leftovers = append(leftovers, path)
			if entry.IsDir() {
				return filepath.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, leftover := range leftovers {
		if err := os.RemoveAll(leftover); err != nil {
			return err
		}
	}
	return nil
}

func (s *scratch) cleanup() {
	if s.keep {
		fmt.Printf("\nscratch tree kept at %s\n", s.root)
		return
	}
	os.RemoveAll(s.root)
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)

		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		return copyFile(path, target)
	})
}

func copyFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
