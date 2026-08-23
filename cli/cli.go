package cli

import (
	"fmt"
	"mutant/errrs"
	"mutant/generator"
	"mutant/global"
	"mutant/repl"
	"mutant/runner"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func RunRepl(version string, enableMacros bool, theme string) {
	repl.Start(os.Stdin, os.Stdout, version, enableMacros, theme)
}

// CompileCode returns the process exit code: 0 on a successful compile, 1 when
// the source could not be compiled. A parse error and a compiler error both
// used to be printed and then reported as success.
func CompileCode(src, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64) int {
	start := time.Now()
	srcpath, err := filepath.Abs(src)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	dstpath := strings.TrimSuffix(srcpath, global.MutantSourceCodeFileExtention)

	// Pass nil for privateKey - Generate() will create a new one
	// In production, you'd load a persistent key from a secure location
	if err, errtype, errors := generator.Generate(srcpath, dstpath, goos, goarch, release, password, mutationLevel, mutationSeed, nil); err != nil {
		switch errtype {
		case errrs.ERROR:
			fmt.Println(err)
		case errrs.PARSER_ERROR:
			errrs.PrintParseErrors(os.Stdout, errors)
		case errrs.COMPILER_ERROR:
			errrs.PrintCompilerError(os.Stdout, err.Error())
		default:
			fmt.Println(err)
		}
		return 1
	}

	fmt.Println("Compiled in:", time.Since(start))
	return 0
}

// GenerateReleaseAssets returns the process exit code, 0 on success and 1 when
// the assets could not be written.
func GenerateReleaseAssets(outputPath string) int {
	start := time.Now()

	if err := generator.GenerateReleaseAssets(outputPath); err != nil {
		fmt.Println(err)
		return 1
	}

	fmt.Println("Generated in:", time.Since(start))
	return 0
}

// RunCode returns the process exit code: 0 when the program ran to completion,
// 1 when it did not.
//
// The failure used to be printed and then discarded, so `mutant prog.mu` exited
// 0 whatever happened -- a runtime error, a missing file, or a wrong password.
// Nothing calling it could tell a successful run from a failed one, and a
// released standalone binary reported success after refusing to decrypt.
func RunCode(src string, password string, secureMode bool, enforceSignerAuth bool) int {
	srcpath, err := filepath.Abs(src)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	if err, errtype := runner.Run(srcpath, password, secureMode, enforceSignerAuth); err != nil {
		switch errtype {
		case errrs.ERROR:
			fmt.Println(err)
		case errrs.VM_ERROR:
			errrs.PrintMachineError(os.Stdout, err.Error())
		default:
			fmt.Println(err)
		}
		return 1
	}

	return 0
}
