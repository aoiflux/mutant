package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mutant/compiler"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/security"
	"mutant/vm"
)

// handleTestCommand implements `mutant test [paths...]`. Each `*_test.mut` file
// is run as a program; it PASSES unless running it produces an error (parse,
// compile, or runtime) or its final value is `false`. With no paths it tests the
// current directory.
func handleTestCommand(args []string) int {
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	if err := set.Parse(args[2:]); err != nil {
		return 2
	}

	paths := set.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	files, err := collectMutantTestFiles(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutant test: %v\n", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Println("no *_test.mut files found")
		return 0
	}

	passed, failed := 0, 0
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("FAIL  %s: %v\n", file, err)
			failed++
			continue
		}
		if ok, msg := runTestFile(string(src)); ok {
			fmt.Printf("ok    %s\n", file)
			passed++
		} else {
			fmt.Printf("FAIL  %s: %s\n", file, msg)
			failed++
		}
	}

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// runTestFile runs a single test program and reports pass/fail with a reason.
func runTestFile(src string) (ok bool, reason string) {
	result, err := runMutantSource(src)
	if err != nil {
		return false, err.Error()
	}
	if e, isErr := result.(*object.Error); isErr {
		return false, e.Message
	}
	if b, isBool := result.(*object.Boolean); isBool && !b.Value {
		return false, "test evaluated to false"
	}
	return true, ""
}

// runMutantSource compiles and runs Mutant source in-process and returns its
// final value. It mirrors the production compile+VM path (deterministic
// encryption keyed off the instruction hash) but injects no security-check
// opcodes, so it runs anywhere without the anti-sandbox gate. A VM panic is
// converted into an error rather than crashing the runner.
func runMutantSource(src string) (result object.Object, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("panic during execution: %v", recovered)
		}
	}()

	l := lexer.New(src)
	p := parser.New(l)
	program := p.ParseProgram()
	if errs := p.Errors(); len(errs) > 0 {
		return nil, fmt.Errorf("parse error: %s", strings.Join(errs, "; "))
	}

	comp := compiler.New()
	if err := comp.Compile(program); err != nil {
		return nil, fmt.Errorf("compile error: %w", err)
	}

	byteCode := comp.ByteCode()
	password := fmt.Sprint(security.DerivePasswordFromInstructions(byteCode.Instructions))
	byteCode = mutil.EncryptByteCode(byteCode, password)

	machine := vm.NewWithGlobalStoreAndPassword(byteCode, make([]object.Object, global.GlobalSize), password)
	if runErr := machine.Run(); runErr != nil {
		return nil, fmt.Errorf("runtime error: %w", runErr)
	}
	return machine.LastPoppedStackElement(), nil
}

// collectMutantTestFiles expands paths into `*_test.mut` files: explicit file
// arguments are taken as-is; directories are walked for the `_test.mut` suffix
// (skipping .git/node_modules/vendor and dot-directories).
func collectMutantTestFiles(paths []string) ([]string, error) {
	testSuffix := "_test" + global.MutantSourceCodeFileExtention
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
			if strings.HasSuffix(path, testSuffix) {
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
