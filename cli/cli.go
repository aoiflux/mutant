package cli

import (
	"fmt"
	"mutant/errrs"
	"mutant/generator"
	"mutant/global"
	"mutant/repl"
	"mutant/runner"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func RunRepl(version string, enableMacros bool, theme string) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		repl.GracefulExit()
	}()
	repl.Start(os.Stdin, os.Stdout, version, enableMacros, theme)
}

func CompileCode(src, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64) {
	start := time.Now()
	srcpath, err := filepath.Abs(src)
	if err != nil {
		fmt.Println(err)
		return
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
		}
		return
	}

	fmt.Println("Compiled in:", time.Since(start))
}

func GenerateReleaseAssets(outputPath string) {
	start := time.Now()

	if err := generator.GenerateReleaseAssets(outputPath); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Generated in:", time.Since(start))
}

func RunCode(src string, password string, secureMode bool, enforceSignerAuth bool) {
	srcpath, err := filepath.Abs(src)
	if err != nil {
		fmt.Println(err)
		return
	}

	if err, errtype := runner.Run(srcpath, password, secureMode, enforceSignerAuth); err != nil {
		switch errtype {
		case errrs.ERROR:
			fmt.Println(err)
		case errrs.VM_ERROR:
			errrs.PrintMachineError(os.Stdout, err.Error())
		}
	}
}
