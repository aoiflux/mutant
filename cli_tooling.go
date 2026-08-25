package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mutant/global"
	"mutant/lsp/api"
)

// handleFmtCommand implements `mutant fmt [--check] [--stdout] <paths...>`.
// Without flags it rewrites each file in place with the canonical formatting.
func handleFmtCommand(args []string) int {
	set := flag.NewFlagSet("fmt", flag.ContinueOnError)
	check := set.Bool("check", false, "Do not write; exit non-zero if any file is not already formatted.")
	toStdout := set.Bool("stdout", false, "Write the formatted result to stdout instead of editing files.")
	if err := set.Parse(args[2:]); err != nil {
		return 2
	}

	paths := set.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: mutant fmt [--check] [--stdout] <file-or-dir>...")
		return 2
	}

	files, err := collectMutantSourceFiles(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutant fmt: %v\n", err)
		return 1
	}

	exitCode := 0
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutant fmt: %v\n", err)
			exitCode = 1
			continue
		}
		formatted := api.Format(string(src))

		switch {
		case *toStdout:
			fmt.Print(formatted)
		case *check:
			if formatted != string(src) {
				fmt.Fprintf(os.Stderr, "would reformat: %s\n", file)
				exitCode = 1
			}
		default:
			if formatted == string(src) {
				continue
			}
			mode := fs.FileMode(0o644)
			if info, statErr := os.Stat(file); statErr == nil {
				mode = info.Mode().Perm()
			}
			if err := os.WriteFile(file, []byte(formatted), mode); err != nil {
				fmt.Fprintf(os.Stderr, "mutant fmt: %v\n", err)
				exitCode = 1
				continue
			}
			fmt.Printf("formatted: %s\n", file)
		}
	}
	return exitCode
}

// handleLintCommand implements `mutant lint [--strict] <paths...>`. It prints
// diagnostics as `file:line:col: severity: message [source]` and exits non-zero
// when any error (or, with --strict, any warning) is found.
func handleLintCommand(args []string) int {
	set := flag.NewFlagSet("lint", flag.ContinueOnError)
	strict := set.Bool("strict", false, "Treat warnings as failures (exit non-zero).")
	if err := set.Parse(args[2:]); err != nil {
		return 2
	}

	paths := set.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: mutant lint [--strict] <file-or-dir>...")
		return 2
	}

	files, err := collectMutantSourceFiles(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutant lint: %v\n", err)
		return 1
	}

	failed := false
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutant lint: %v\n", err)
			failed = true
			continue
		}
		for _, d := range api.Lint(string(src)) {
			source := ""
			if d.Source != "" {
				source = " [" + d.Source + "]"
			}
			fmt.Printf("%s:%d:%d: %s: %s%s\n", file, d.Line, d.Column, d.Severity, d.Message, source)
			if d.Severity == api.SeverityError || (*strict && d.Severity == api.SeverityWarning) {
				failed = true
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}

// collectMutantSourceFiles expands the given paths into a flat list of Mutant
// source files: plain file arguments are taken as-is, and directories are walked
// for `*.mut` files (skipping .git/node_modules/vendor and dot-directories).
func collectMutantSourceFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		walkErr := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == "node_modules" || name == "vendor" || (strings.HasPrefix(name, ".") && name != "." && name != "..") {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, global.MutantSourceCodeFileExtention) {
				files = append(files, path)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	return files, nil
}
