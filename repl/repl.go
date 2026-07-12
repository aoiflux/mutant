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
	"os/signal"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const PROMPT = ">> "

const idleInterval = 30 * time.Second
const tinyTaskEasterEggChance = 20
const idleEasterEggChance = 8
const welcomeEasterEggChance = 6
const generalSuccessEasterEggChance = 40

const (
	ansiReset       = "\033[0m"
	ansiBoldCyan    = "\033[1;36m"
	ansiBoldGreen   = "\033[1;32m"
	ansiBoldYellow  = "\033[1;33m"
	ansiBoldMagenta = "\033[1;35m"
	ansiBoldBlue    = "\033[1;34m"
	ansiBoldRed     = "\033[1;31m"
	ansiGray        = "\033[90m"
	ansiCyan        = "\033[36m"
	ansiGreen       = "\033[32m"
	ansiYellow      = "\033[33m"
	ansiMagenta     = "\033[35m"
	ansiBlue        = "\033[34m"
	ansiBrightBlue  = "\033[94m"
	ansiBrightCyan  = "\033[96m"
	ansiBrightGreen = "\033[92m"
	ansiBrightWhite = "\033[97m"
)

const defaultReplTheme = "default"

type replTheme struct {
	Prompt        string
	Welcome       string
	Info          string
	Tip           string
	WelcomeEgg    string
	Idle          string
	TinyTask      string
	General       string
	Exit          string
	BannerPalette []string
}

var replRNG = rand.New(rand.NewSource(time.Now().UnixNano()))
var replColorEnabled bool
var resolvedReplThemeName = defaultReplTheme
var replThemeFallbackFrom = ""
var activeReplTheme = replTheme{
	Prompt:        ansiBoldCyan,
	Welcome:       ansiBoldGreen,
	Info:          ansiGray,
	Tip:           ansiBoldMagenta,
	WelcomeEgg:    ansiBoldMagenta,
	Idle:          ansiBoldBlue,
	TinyTask:      ansiBoldYellow,
	General:       ansiBoldMagenta,
	Exit:          ansiBoldGreen,
	BannerPalette: []string{ansiBoldCyan, ansiBoldGreen, ansiBoldYellow, ansiBoldMagenta, ansiBoldBlue},
}

var replThemes = map[string]replTheme{
	"default": activeReplTheme,
	"neon": {
		Prompt:        ansiBrightCyan,
		Welcome:       ansiBrightGreen,
		Info:          ansiCyan,
		Tip:           ansiMagenta,
		WelcomeEgg:    ansiMagenta,
		Idle:          ansiBrightBlue,
		TinyTask:      ansiYellow,
		General:       ansiBrightWhite,
		Exit:          ansiBrightGreen,
		BannerPalette: []string{ansiBrightCyan, ansiBrightBlue, ansiMagenta, ansiBrightGreen},
	},
	"pastel": {
		Prompt:        ansiCyan,
		Welcome:       ansiGreen,
		Info:          ansiGray,
		Tip:           ansiMagenta,
		WelcomeEgg:    ansiMagenta,
		Idle:          ansiBlue,
		TinyTask:      ansiYellow,
		General:       ansiCyan,
		Exit:          ansiGreen,
		BannerPalette: []string{ansiCyan, ansiGreen, ansiBlue, ansiMagenta},
	},
	"forest": {
		Prompt:        ansiGreen,
		Welcome:       ansiBoldGreen,
		Info:          ansiGray,
		Tip:           ansiYellow,
		WelcomeEgg:    ansiYellow,
		Idle:          ansiCyan,
		TinyTask:      ansiYellow,
		General:       ansiGreen,
		Exit:          ansiBoldGreen,
		BannerPalette: []string{ansiGreen, ansiBoldGreen, ansiCyan, ansiYellow},
	},
	"sunset": {
		Prompt:        ansiBoldYellow,
		Welcome:       ansiBoldMagenta,
		Info:          ansiGray,
		Tip:           ansiBoldYellow,
		WelcomeEgg:    ansiBoldYellow,
		Idle:          ansiBoldRed,
		TinyTask:      ansiBoldYellow,
		General:       ansiBoldMagenta,
		Exit:          ansiBoldRed,
		BannerPalette: []string{ansiBoldYellow, ansiBoldRed, ansiBoldMagenta},
	},
}

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
	` __  __       _         _
|  \/  | ___ | |_ _   _| |_
| |\/| |/ _ \| __| | | | __|
| |  | | (_) | |_| |_| | |_
|_|  |_|\___/ \__|\__,_|\__|

	.----.
  / .--. \   tiny byte parade
  | |  | |
  \ '--' /
	'----'`,
	` __  __       _        _
|  \/  | __ _| |_ _ __(_)_  __
| |\/| |/ _' | __| '__| \ \/ /
| |  | | (_| | |_| |  | |>  <
|_|  |_|\__,_|\__|_|  |_/_/\_\

	/\_/\
  ( ^.^ )   mutation station online
	> ^ <`,
	` __  __       _              _
|  \/  | __ _| |_ _ __ _   _| |_
| |\/| |/ _' | __| '__| | | | __|
| |  | | (_| | |_| |  | |_| | |_
|_|  |_|\__,_|\__|_|   \__,_|\__|

	 .-""-.
	/ .--. \
  / /    \ \   cozy compiler hours
  | |    | |
  \ \____/ /
	'------'`,
	` __  __       _       _
|  \/  | __ _| |_ ___| |__
| |\/| |/ _' | __/ __| '_ \
| |  | | (_| | || (__| | | |
|_|  |_|\__,_|\__\___|_| |_|

	  .--.
	 / _.-'    pocket portal initialized
	 \  '-.
	  '--'`,
	` __  __       _       _
|  \/  | __ _| |_ ___| |__
| |\/| |/ _' | __/ __| '_ \
| |  | | (_| | || (__| | | |
|_|  |_|\__,_|\__\___|_| |_|

	[::]
   [::::]   tiny reactor stable
	[::]
	 ||`,
	` __  __       _       _
|  \/  | __ _| |_ ___| |__
| |\/| |/ _' | __/ __| '_ \
| |  | | (_| | || (__| | | |
|_|  |_|\__,_|\__\___|_| |_|

	/^_^\
  /|   |\   compiler familiar online
	|___|`,
	` __  __       _       _
|  \/  | __ _| |_ ___| |__
| |\/| |/ _' | __/ __| '_ \
| |  | | (_| | || (__| | | |
|_|  |_|\__,_|\__\___|_| |_|

	.----.
  / .-.  \   byte ferry docking
  | | |  |
  \ '-'  /
	'----'`,
	` __  __       _       _
|  \/  | __ _| |_ ___| |__
| |\/| |/ _' | __/ __| '_ \
| |  | | (_| | || (__| | | |
|_|  |_|\__,_|\__\___|_| |_|

	(\_/)
	(o.o)   stack bunny reports: all good
	(> <)`,
}

var idleMessages = []string{
	"mutant is stretching its tiny compiler muscles while it waits.",
	"the REPL is sipping tea and pretending to be a very serious wizard.",
	"still here, still cute, still ready for the next spell.",
	"mutant is doing a little idle wiggle. no pressure, just vibes.",
	"a tiny bytecode bird just nested on the prompt.",
	"quiet mode engaged. a mini compiler squirrel is organizing semicolons.",
	"the prompt is humming softly in 8-bit while waiting.",
	"a pocket-sized debugger just offered everyone cookies.",
	"mutant is polishing tiny opcodes until they sparkle.",
	"idle detected. summoning one (1) wholesome stack frame.",
	"the REPL planted a tiny fern in the heap. it is thriving.",
	"compiler goblin status: cozy, focused, and mildly dramatic.",
	"the cursor is blinking with polite enthusiasm.",
	"a gentle byte-breeze passes through the prompt.",
	"mutant is practicing little victory dances between inputs.",
	"the tiny runtime orchestra is tuning in the background.",
	"a patient little parser dragon is guarding your prompt.",
	"the REPL drew a smiley face in invisible bytecode chalk.",
	"quietly compiling good vibes and minimal syntax.",
	"mutant checked the weather: 100% chance of tiny triumphs.",
}

var tinyTaskMessages = []string{
	"tiny spell detected. the goblin compiler approves with a gentle nod.",
	"that looks delightfully snack-sized. mutant is fully supportive.",
	"a compact little incantation. elegant and very hard-working.",
	"small input, big personality. the REPL appreciates the efficiency.",
	"mutant heard a tiny task and put on its ceremonial mini-hat.",
	"micro-expression accepted. the byte sprites are clapping politely.",
	"that was a fun-sized command with premium vibes.",
	"tiny but mighty. the prompt salutes your minimalist power.",
	"approved by the department of adorable computation.",
	"the stack called it: crisp, cute, and correct.",
	"mini command processed. confetti budget remains responsible.",
	"you dropped a pocket command and it landed perfectly.",
	"small spell, clean aura, excellent craftsmanship.",
	"mutant logged this as: little spell, huge heart.",
	"byte-sized brilliance detected. proceed with confidence.",
	"compact syntax, maximum charm, no notes.",
	"the runtime handed this one a gold star sticker.",
	"tiny task complete. morale increased by 3 points.",
	"the REPL whispers: very neat, very cute, very legal.",
	"this command would fit in a lunchbox and still impress everyone.",
	"small code energy, legendary outcome potential.",
	"the prompt did a tiny happy nod and carried on.",
	"mini task processed with artisanal care.",
	"every great codebase starts with little wins like this.",
	"postcard-sized command, full-sized excellence.",
	"mutant sends a tiny high-five across the terminal.",
}

var generalSuccessMessages = []string{
	"clean run. the byte sprites approve this timeline.",
	"that landed smoothly. excellent command posture.",
	"mutant quietly logs this under: tasteful craftsmanship.",
	"nice move. the REPL is impressed in a chill way.",
	"solid execution. tiny confetti released under budget.",
	"that had good rhythm. parser and VM both nodded.",
	"quiet excellence detected. keep cooking.",
	"another neat step forward. the prompt is proud.",
	"elegant result. very respectable terminal aura.",
	"smooth and correct. the stack remains hydrated.",
}

var welcomeMessages = []string{
	"A tiny cosmic duck has been assigned as your session mascot.",
	"Fun fact: this REPL runs on equal parts bytecode and optimism.",
	"Today's vibe: compile gently, ship bravely.",
	"A mini parser wizard has taken the night shift for you.",
	"Terminal weather report: calm syntax with scattered brilliance.",
	"The prompt requested snacks and received semicolons instead.",
	"Session blessing: may your stack stay balanced and your bugs tiny.",
}

var exitMessages = []string{
	"---- Leaving for a byte? I'll see you later! ----",
	"---- Bye for now. The prompt will keep your seat warm. ----",
	"---- Mutant is waving from the exit tunnel. Come back soon. ----",
	"---- Session closed gently. Tiny compiler goblins say bye-bye. ----",
	"---- Logging off with style. The prompt saved your sparkle. ----",
	"---- Doors closing softly. The byte sprites will miss you. ----",
	"---- End of session. Tiny stars now rendering in the terminal sky. ----",
	"---- Good run. Your prompt chair remains respectfully reserved. ----",
}

// Start function is the entrypoint of our repl
func Start(in io.Reader, out io.Writer, version string, enableMacros bool, themeName string) {
	replColorEnabled = shouldUseColor(out)
	activeReplTheme, resolvedReplThemeName, replThemeFallbackFrom = resolveReplTheme(themeName)
	welcome(out, version, enableMacros)

	replSignals := make(chan os.Signal, 1)
	signal.Notify(replSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGABRT)
	defer signal.Stop(replSignals)

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
		fmt.Fprintf(out, "\n\n%s", styledPrompt())
		line, scanned, interrupted := scanLineWithIdle(scanner, out, replSignals)
		if interrupted {
			gracefulExit()
		}
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
			tinyShown := false
			if shouldShowTinyTaskEasterEgg(line) {
				io.WriteString(out, "  ")
				io.WriteString(out, styledTinyTaskMessage(randomTinyTaskMessage()))
				io.WriteString(out, "\n")
				tinyShown = true
			}
			if shouldShowGeneralSuccessEasterEgg(line, tinyShown) {
				io.WriteString(out, "  ")
				io.WriteString(out, styledGeneralSuccessMessage(randomGeneralSuccessMessage()))
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
		tinyShown := false
		if shouldShowTinyTaskEasterEgg(line) {
			io.WriteString(out, "  ")
			io.WriteString(out, styledTinyTaskMessage(randomTinyTaskMessage()))
			io.WriteString(out, "\n")
			tinyShown = true
		}
		if shouldShowGeneralSuccessEasterEgg(line, tinyShown) {
			io.WriteString(out, "  ")
			io.WriteString(out, styledGeneralSuccessMessage(randomGeneralSuccessMessage()))
			io.WriteString(out, "\n")
		}
		globals = machine.GlobalStore()
		machine.CleanupRuntimeSensitiveData(false, false)
	}
}

func welcome(out io.Writer, version string, enableMacros bool) {
	fmt.Fprint(out, styledBanner(randomBanner()))
	fmt.Fprint(out, "\n")

	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(out, "%s\n", styledWelcomeLine(fmt.Sprintf("Hello %s! Welcome to mutant, a programming language!", user.Name)))
	fmt.Fprintf(out, "%s\n", styledInfoLine(fmt.Sprintf("Running %s with Process ID: %d", version, os.Getpid())))
	if replColorEnabled {
		fmt.Fprintf(out, "%s\n", styledInfoLine(fmt.Sprintf("REPL theme: %s", resolvedReplThemeName)))
		if replThemeFallbackFrom != "" {
			fmt.Fprintf(out, "%s\n", styledInfoLine(fmt.Sprintf("Requested theme %q not found; using %q.", replThemeFallbackFrom, resolvedReplThemeName)))
		}
	}
	if enableMacros {
		fmt.Fprintf(out, "%s\n", styledInfoLine("Running Mutant REPL in experimental mode. Macros are enabled."))
	}
	fmt.Fprintf(out, "%s\n", styledInfoLine("Please get started by using this REPL"))
	fmt.Fprintf(out, "%s\n", styledTipLine("Tip: if you leave it alone for a bit, it may serenade you."))
	if shouldShowWelcomeEasterEgg() {
		fmt.Fprintf(out, "%s\n", styledWelcomeEasterEgg("Tiny surprise: "+randomWelcomeMessage()))
	}
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

	if isExitCommand(line) {
		gracefulExit()
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

func scanLineWithIdle(scanner *bufio.Scanner, out io.Writer, signalCh <-chan os.Signal) (string, bool, bool) {
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
			return result.line, result.ok, false
		case <-signalCh:
			return "", false, true
		case <-ticker.C:
			if shouldShowIdleEasterEgg() {
				fmt.Fprintf(out, "\n%s\n%s", styledIdleMessage(randomIdleMessage()), styledPrompt())
			}
		}
	}
}

func shouldUseColor(out io.Writer) bool {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("MUTANT_REPL_COLOR")))
	switch mode {
	case "1", "true", "on", "always":
		return true
	case "0", "false", "off", "never":
		return false
	}

	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return false
	}

	if out != os.Stdout {
		return false
	}

	if runtime.GOOS == global.WINDOWS {
		if os.Getenv("WT_SESSION") != "" || os.Getenv("ANSICON") != "" || strings.ToUpper(os.Getenv("ConEmuANSI")) == "ON" {
			return true
		}
	}

	term := strings.ToLower(strings.TrimSpace(os.Getenv("TERM")))
	if term == "" || term == "dumb" {
		return runtime.GOOS == global.WINDOWS && os.Getenv("WT_SESSION") != ""
	}

	return true
}

func styledPrompt() string {
	return colorize(PROMPT, activeReplTheme.Prompt)
}

func styledBanner(banner string) string {
	palette := activeReplTheme.BannerPalette
	if len(palette) == 0 {
		palette = replThemes[defaultReplTheme].BannerPalette
	}
	return colorize(banner, palette[replRNG.Intn(len(palette))])
}

func styledWelcomeLine(line string) string {
	return colorize(line, activeReplTheme.Welcome)
}

func styledInfoLine(line string) string {
	return colorize(line, activeReplTheme.Info)
}

func styledTipLine(line string) string {
	return colorize(line, activeReplTheme.Tip)
}

func styledWelcomeEasterEgg(line string) string {
	return colorize(line, activeReplTheme.WelcomeEgg)
}

func styledIdleMessage(line string) string {
	return colorize(line, activeReplTheme.Idle)
}

func styledTinyTaskMessage(line string) string {
	return colorize(line, activeReplTheme.TinyTask)
}

func styledGeneralSuccessMessage(line string) string {
	return colorize(line, activeReplTheme.General)
}

func resolveReplTheme(name string) (replTheme, string, string) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		normalized = strings.ToLower(strings.TrimSpace(os.Getenv("MUTANT_REPL_THEME")))
	}
	if normalized == "" {
		return replThemes[defaultReplTheme], defaultReplTheme, ""
	}
	if theme, ok := replThemes[normalized]; ok {
		return theme, normalized, ""
	}
	return replThemes[defaultReplTheme], defaultReplTheme, normalized
}

func colorize(text, code string) string {
	if !replColorEnabled {
		return text
	}
	return code + text + ansiReset
}

func shouldShowTinyTaskEasterEgg(line string) bool {
	if !tinyTask(line) {
		return false
	}
	return chanceOneIn(tinyTaskEasterEggChance)
}

func shouldShowIdleEasterEgg() bool {
	return chanceOneIn(idleEasterEggChance)
}

func shouldShowWelcomeEasterEgg() bool {
	return chanceOneIn(welcomeEasterEggChance)
}

func shouldShowGeneralSuccessEasterEgg(line string, tinyShown bool) bool {
	if tinyShown {
		return false
	}
	if strings.TrimSpace(line) == "" {
		return false
	}
	return chanceOneIn(generalSuccessEasterEggChance)
}

func chanceOneIn(n int) bool {
	if n <= 1 {
		return true
	}
	return replRNG.Intn(n) == 0
}

func macroCheck(line string) bool {
	lowerLine := strings.ToLower(line)
	return strings.Contains(lowerLine, "macro") ||
		strings.Contains(lowerLine, "quote") ||
		strings.Contains(lowerLine, "unquote")
}

func isExitCommand(line string) bool {
	trimmed := strings.TrimSpace(line)
	for strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
	}

	lower := strings.ToLower(trimmed)
	return lower == "exit" || lower == "quit" || lower == "bye"
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
	return replBanners[replRNG.Intn(len(replBanners))]
}

func randomIdleMessage() string {
	return idleMessages[replRNG.Intn(len(idleMessages))]
}

func randomTinyTaskMessage() string {
	return tinyTaskMessages[replRNG.Intn(len(tinyTaskMessages))]
}

func randomGeneralSuccessMessage() string {
	return generalSuccessMessages[replRNG.Intn(len(generalSuccessMessages))]
}

func randomWelcomeMessage() string {
	return welcomeMessages[replRNG.Intn(len(welcomeMessages))]
}

func gracefulExit() {
	fmt.Printf("\n\n")
	fmt.Println(colorize(exitMessages[replRNG.Intn(len(exitMessages))], activeReplTheme.Exit))
	fmt.Printf("\n\n")
	os.Exit(0)
}
