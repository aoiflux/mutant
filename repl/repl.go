package repl

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mutant/builtin"
	"mutant/compiler"
	"mutant/errrs"
	"mutant/evaluator"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/vm"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

const PROMPT = ">> "

const idleInterval = 30 * time.Second

var replBanners = []string{
	`  __  __       _       _
 |  \/  | __ _| |_ ___| |__
 | |\/| |/ _' | __/ __| '_ \
 | |  | | (_| | || (__| | | |
 |_|  |_|\__,_|\__\___|_| |_|

      /\_/\\
     ( o.o )    mutant.exe
      > ^ <`,
	` __  __                 _
|  \/  | ___  _ __ _   _| |_ ___
| |\/| |/ _ \| '__| | | | __/ _ \
| |  | | (_) | |  | |_| | ||  __/
|_|  |_|\___/|_|   \__,_|\__\___|

   /\/\
  ( o.o )   tiny chaos, large charm
   > ^ <`,
	` __  __                 _
|  \/  | ___  _ __   ___| |_ ___
| |\/| |/ _ \| '_ \ / _ \ __/ _ \
| |  | | (_) | | | |  __/ ||  __/
|_|  |_|\___/|_| |_|\___|\__\___|

      .-.
     (o o)  beep
     | O \
      \   \
       ~~~'`,
	` __  __           _        _
|  \/  | ___   __| |_   _ | |_
| |\/| |/ _ \ / _' | | | || __|
| |  | | (_) | (_| | |_| || |_
|_|  |_|\___/ \__,_|\__,_| \__|

     __
  .-'  '-.
 /  .--.  \   mutant moon
 | (____) |
  \      /
   '----'`,
	` __  __       _              _
|  \/  | __ _| |_ __ _ _ __ | |_
| |\/| |/ _' | __/ _' | '_ \| __|
| |  | | (_| | || (_| | | | | |_
|_|  |_|\__,_|\__\__,_|_| |_|\__|

   [====]
  [| .. |]   hello, little universe
   [|__|]`,
}

var idleMessages = []string{
	"mutant is stretching its tiny compiler muscles while it waits.",
	"the REPL is sipping tea and pretending to be a very serious wizard.",
	"still here, still cute, still ready for the next spell.",
	"mutant is doing a little idle wiggle. no pressure, just vibes.",
	"a tiny bytecode bird just nested on the prompt.",
}

var tinyTaskMessages = []string{
	"tiny spell detected. the goblin compiler approves with a gentle nod.",
	"that looks delightfully snack-sized. mutant is fully supportive.",
	"a compact little incantation. elegant and very hard-working.",
	"small input, big personality. the REPL appreciates the efficiency.",
	"mutant heard a tiny task and put on its ceremonial mini-hat.",
}

var exitMessages = []string{
	"---- Leaving for a byte? I'll see you later! ----",
	"---- Bye for now. The prompt will keep your seat warm. ----",
	"---- Mutant is waving from the exit tunnel. Come back soon. ----",
}

// Start function is the entrypoint of our repl
func Start(in io.Reader, out io.Writer, version string, enableMacros bool) {
	welcome(version, enableMacros)
	scanner := bufio.NewScanner(in)
	if scanner.Err() != nil {
		log.Fatalln(scanner.Err())
	}
	env := object.NewEnvironment()
	macroEnv := object.NewEnvironment()

	constants := []object.Object{}
	globals := make([]object.Object, global.GlobalSize)
	replPassword := mutil.GetPwd()
	symbolTable := compiler.NewSymbolTable()
	for i, v := range builtin.Builtins {
		symbolTable.DefineBuiltin(i, v.Name)
	}

	for {
		fmt.Fprintf(out, "\n\n%s", PROMPT)
		line, scanned := scanLineWithIdle(scanner, out)
		if !scanned {
			return
		}

		if vanity(line, out, enableMacros) {
			continue
		}

		l := lexer.New(line)
		p := parser.New(l)
		program := p.ParseProgram()
		if len(p.Errors()) != 0 {
			errrs.PrintParseErrors(out, p.Errors())
			continue
		}

		if enableMacros {
			evaluator.DefineMacros(program, macroEnv)
			expanded := evaluator.ExpandMacros(program, macroEnv)
			evaluated := evaluator.Eval(expanded, env)
			if evaluated == nil {
				continue
			}
			io.WriteString(out, evaluated.Inspect())
			io.WriteString(out, "\n")
			if tinyTask(line) {
				io.WriteString(out, "  ")
				io.WriteString(out, randomTinyTaskMessage())
				io.WriteString(out, "\n")
			}
			continue
		}

		comp := compiler.NewWithState(symbolTable, constants)
		if err := comp.Compile(program); err != nil {
			errrs.PrintCompilerError(out, err.Error())
			continue
		}

		byteCode := comp.ByteCode()
		byteCode = mutil.EncryptByteCode(byteCode, replPassword)
		constants = byteCode.Constants

		machine := vm.NewWithGlobalStoreAndPassword(byteCode, globals, replPassword)
		if err := machine.Run(); err != nil {
			globals = machine.GlobalStore()
			machine.CleanupRuntimeSensitiveData(false, false)
			errrs.PrintMachineError(out, err.Error())
			continue
		}

		last := machine.LastPoppedStackElement()
		if multi, ok := last.(*object.MultiValue); ok && multi.IsVoid() {
			// No-op result; keep the REPL quiet.
		} else if last != nil {
			io.WriteString(out, last.Inspect())
			io.WriteString(out, "\n")
		}
		if tinyTask(line) {
			io.WriteString(out, "  ")
			io.WriteString(out, randomTinyTaskMessage())
			io.WriteString(out, "\n")
		}
		globals = machine.GlobalStore()
		machine.CleanupRuntimeSensitiveData(false, false)
	}
}

func welcome(version string, enableMacros bool) {
	fmt.Print(randomBanner())
	fmt.Print("\n")

	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Hello %s! Welcome to mutant, a programming language!\n", user.Name)
	fmt.Printf("Running %s with Process ID: %d\n", version, os.Getpid())
	if enableMacros {
		fmt.Println("Running Mutant REPL in experimental mode. Macros are enabled.")
	}
	fmt.Println("Please get started by using this REPL")
	fmt.Println("Tip: if you leave it alone for a bit, it may serenade you.")
}

func vanity(line string, out io.Writer, enableMacros bool) bool {
	if line == "" {
		return true
	}

	if line == "clear" || line == "cls" {
		clear := make(map[string]func())
		clear[global.LINUX] = func() {
			cmd := exec.Command("clear")
			cmd.Stdout = os.Stdout
			cmd.Run()
		}
		clear[global.DARWIN] = func() {
			cmd := exec.Command("clear")
			cmd.Stdout = os.Stdout
			cmd.Run()
		}
		clear[global.WINDOWS] = func() {
			cmd := exec.Command("cmd", "/c", "cls")
			cmd.Stdout = os.Stdout
			cmd.Run()
		}

		if value, ok := clear[runtime.GOOS]; ok {
			value()
		} else {
			io.WriteString(out, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
		}
		return true
	}

	if line == "exit" {
		GracefulExit()
	}

	if enableMacros {
		return false
	}

	if macroCheck(line) {
		io.WriteString(out, "Macros are experimental features. To enable them, please use `-em or --enableMacros` CLI arguments while running Mutant REPL.")
		return true
	}

	return false
}

func scanLineWithIdle(scanner *bufio.Scanner, out io.Writer) (string, bool) {
	type scanResult struct {
		line string
		ok   bool
	}

	resultCh := make(chan scanResult, 1)
	go func() {
		if scanner.Scan() {
			resultCh <- scanResult{line: scanner.Text(), ok: true}
			return
		}
		resultCh <- scanResult{ok: false}
	}()

	ticker := time.NewTicker(idleInterval)
	defer ticker.Stop()

	for {
		select {
		case result := <-resultCh:
			return result.line, result.ok
		case <-ticker.C:
			fmt.Fprintf(out, "\n%s\n%s", randomIdleMessage(), PROMPT)
		}
	}
}

func macroCheck(line string) bool {
	lowerLine := strings.ToLower(line)
	return strings.Contains(lowerLine, "macro") ||
		strings.Contains(lowerLine, "quote") ||
		strings.Contains(lowerLine, "unquote")
}

func tinyTask(line string) bool {
	trimmed := strings.TrimSpace(strings.TrimSuffix(line, ";"))
	if trimmed == "" {
		return false
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "len(") || strings.HasPrefix(lower, "puts(") || strings.HasPrefix(lower, "putln(") {
		return true
	}

	if strings.Contains(trimmed, " = ") && !strings.Contains(trimmed, "==") {
		return true
	}

	if basicMath(trimmed) {
		return true
	}

	return len(trimmed) <= 14 && strings.Count(trimmed, "+")+strings.Count(trimmed, "-")+strings.Count(trimmed, "*")+strings.Count(trimmed, "/") == 1
}

func basicMath(line string) bool {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return false
	}
	if !isDigits(parts[0]) || !isDigits(parts[2]) {
		return false
	}
	switch parts[1] {
	case "+", "-", "*", "/":
		return true
	default:
		return false
	}
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func randomBanner() string {
	return replBanners[rand.Intn(len(replBanners))]
}

func randomIdleMessage() string {
	return idleMessages[rand.Intn(len(idleMessages))]
}

func randomTinyTaskMessage() string {
	return tinyTaskMessages[rand.Intn(len(tinyTaskMessages))]
}

func GracefulExit() {
	fmt.Printf("\n\n")
	fmt.Println(exitMessages[rand.Intn(len(exitMessages))])
	fmt.Printf("\n\n")
	os.Exit(0)
}
