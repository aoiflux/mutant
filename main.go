package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"mutant/cli"
	"mutant/global"
	"mutant/mutil"
	"mutant/runner"
	"mutant/security"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultPolymorphicLevel = 5

const (
	RELEASECMD = "release"
	GENCMD     = "gen"
	RUNCMD     = "run"
	HELPCMD    = "help"
	VERSION    = "Version: 2.2.0"
)

type cliRuntime struct {
	runRepl               func(string, bool, string)
	compileCode           func(string, string, string, bool, string, int, int64)
	generateReleaseAssets func(string)
	runCode               func(string, string, bool, bool)
	hasStandalonePayload  func(string) (bool, error)
	executablePath        func() (string, error)
	getPwd                func() string
}

var runtimeDeps = cliRuntime{
	runRepl:               cli.RunRepl,
	compileCode:           cli.CompileCode,
	generateReleaseAssets: cli.GenerateReleaseAssets,
	runCode:               cli.RunCode,
	hasStandalonePayload:  runner.HasStandalonePayload,
	executablePath:        os.Executable,
	getPwd:                mutil.GetPwd,
}

var commandHandlers = map[string]func([]string) int{
	GENCMD:     handleGenCommand,
	RUNCMD:     handleGenCommand,
	RELEASECMD: handleReleaseCommand,
}

func main() {
	exitCode := run(os.Args)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func run(args []string) int {
	if handled, exitCode := tryEmbeddedPayloadRun(args); handled {
		return exitCode
	}

	return runCommandFlow(args)
}

func tryEmbeddedPayloadRun(args []string) (bool, int) {
	if !shouldAttemptEmbeddedRun(args) {
		return false, 0
	}

	executablePath, err := runtimeDeps.executablePath()
	if err != nil {
		return false, 0
	}

	hasStandalonePayload, payloadErr := runtimeDeps.hasStandalonePayload(executablePath)
	if payloadErr != nil {
		fmt.Println(payloadErr)
		return true, 1
	}

	if !hasStandalonePayload {
		return false, 0
	}

	runEmbeddedPayload(executablePath, args)
	return true, 0
}

func runEmbeddedPayload(executablePath string, args []string) {
	password, devMode, secureMode, enforceSignerAuth := resolveRuntimeExecutionOptions(args)

	configureSecurityLogging(args, devMode)
	if password == "" && devMode {
		password = runtimeDeps.getPwd()
	}

	runtimeDeps.runCode(executablePath, password, secureMode, enforceSignerAuth)
}

func resolveRuntimeExecutionOptions(args []string) (string, bool, bool, bool) {
	password := extractPasswordArg(args)
	devMode := hasDevModeArg(args)
	secureMode := extractSecurityModeArg(args)
	if devMode {
		secureMode = false
	}

	enforceSignerAuth := extractSignerAuthArg(args)
	return password, devMode, secureMode, enforceSignerAuth
}

func runCommandFlow(args []string) int {
	if len(args) == 1 {
		runtimeDeps.runRepl(VERSION, false, extractReplThemeArg(args))
		return 0
	}

	if shouldStartReplFromFlags(args[1:]) {
		runtimeDeps.runRepl(VERSION, hasEnableMacrosArg(args), extractReplThemeArg(args))
		return 0
	}

	if handleBuiltinCommand(args) {
		return 0
	}

	if handleFileInvocation(args) {
		return 0
	}

	handler, ok := commandHandlers[args[1]]
	if !ok {
		fmt.Printf("unknown command or file: %s\n\n", args[1])
		printGeneralHelp()
		return 1
	}

	return handler(args)
}

func shouldAttemptEmbeddedRun(args []string) bool {
	if len(args) == 1 {
		return true
	}

	for _, arg := range args[1:] {
		switch arg {
		case RELEASECMD, GENCMD, RUNCMD, HELPCMD:
			return false
		}

		if isHelpArg(arg) || isVersionArg(arg) || isEnableMacrosArg(arg) {
			return false
		}

		if strings.HasSuffix(arg, global.MutantSourceCodeFileExtention) ||
			strings.HasSuffix(arg, global.MutantByteCodeCompiledFileExtension) {
			return false
		}
	}

	return true
}

// extractSecurityModeArg scans args for explicit mode flags.
// Defaults to secure mode unless --compat is supplied.
func extractSecurityModeArg(args []string) bool {
	secureMode := true
	for _, arg := range args {
		switch arg {
		case "--dev", "-dev":
			secureMode = false
		case "--compat", "-compat":
			secureMode = false
		case "--secure", "-secure":
			secureMode = true
		}
	}
	return secureMode
}

func hasDevModeArg(args []string) bool {
	for _, arg := range args {
		if arg == "--dev" || arg == "-dev" {
			return true
		}
	}
	return false
}

func extractSecurityLogLevelArg(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--security-log-level" || args[i] == "-security-log-level" || args[i] == "--log-level" || args[i] == "-log-level" {
			return strings.TrimSpace(args[i+1])
		}
	}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--security-log-level=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "--security-log-level="))
		}
		if strings.HasPrefix(args[i], "--log-level=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "--log-level="))
		}
	}
	return ""
}

func handleBuiltinCommand(args []string) bool {
	if len(args) < 2 {
		return false
	}

	if isHelpArg(args[1]) {
		printGeneralHelp()
		return true
	}

	if args[1] == HELPCMD {
		printHelpTopic(args[2:])
		return true
	}

	if isVersionArg(args[1]) {
		fmt.Println(VERSION)
		return true
	}

	if isEnableMacrosArg(args[1]) {
		runtimeDeps.runRepl(VERSION, true, extractReplThemeArg(args))
		return true
	}

	return false
}

func handleFileInvocation(args []string) bool {
	if len(args) < 2 {
		return false
	}

	if isBuiltinCommand(args[1]) {
		return false
	}

	fileArg := findProgramArg(args[1:])
	if fileArg == "" {
		return false
	}

	return executeProgramFile(args, fileArg)
}

func isBuiltinCommand(arg string) bool {
	switch arg {
	case RELEASECMD, GENCMD, RUNCMD, HELPCMD:
		return true
	default:
		return false
	}
}

func executeProgramFile(args []string, fileArg string) bool {
	password, devMode, secureMode, enforceSignerAuth := resolveRuntimeExecutionOptions(args)
	configureSecurityLogging(args, devMode)

	if strings.HasSuffix(fileArg, global.MutantSourceCodeFileExtention) {
		runtimeDeps.compileCode(fileArg, "", "", false, password, defaultPolymorphicLevel, time.Now().UnixNano())
		return true
	}

	if !strings.HasSuffix(fileArg, global.MutantByteCodeCompiledFileExtension) {
		return false
	}

	password = resolveProgramRunPassword(args, password, devMode)
	runtimeDeps.runCode(fileArg, password, secureMode, enforceSignerAuth)
	return true
}

func resolveProgramRunPassword(args []string, password string, devMode bool) string {
	if password == "" && devMode {
		return runtimeDeps.getPwd()
	}

	if password == "" && len(args) == 2 {
		return runtimeDeps.getPwd()
	}

	return password
}

func handleGenCommand(args []string) int {
	if hasHelpFlag(args[2:]) {
		printGenCommandHelp(args)
		return 0
	}

	if hasReleaseAssetsArg(args) {
		return handleGenAssetsCommand(args)
	}

	return handleGenCompileCommand(args)
}

func handleReleaseCommand(args []string) int {
	if hasHelpFlag(args[2:]) {
		printReleaseHelp()
		return 0
	}

	return handleReleaseCompileCommand(args)
}

func printGenCommandHelp(args []string) {
	if hasReleaseAssetsArg(args) {
		printAssetsHelp()
		return
	}

	printGenHelp(args[1] == RUNCMD)
}

func handleGenAssetsCommand(args []string) int {
	out, err := prepareReleaseAssetsGeneration(args)
	if err != nil {
		printCommandError(err, "gen assets")
		printAssetsHelp()
		return 1
	}

	fmt.Println("Generating embedded release runtime assets...")
	runtimeDeps.generateReleaseAssets(out)
	return 0
}

func handleGenCompileCommand(args []string) int {
	src, password, mutationLevel, mutationSeed, err := prepareGenRun(args)
	if err != nil {
		printCommandError(err, args[1])
		printGenHelp(args[1] == RUNCMD)
		return 1
	}

	fmt.Println("Generating bytecode...")
	runtimeDeps.compileCode(src, "", "", false, password, mutationLevel, mutationSeed)
	return 0
}

func handleReleaseCompileCommand(args []string) int {

	src, goos, goarch, password, mutationLevel, mutationSeed, err := prepareRelease(args)
	if err != nil {
		printCommandError(err, RELEASECMD)
		printReleaseHelp()
		return 1
	}

	fmt.Println("Compiling release build...")
	runtimeDeps.compileCode(src, goos, goarch, true, password, mutationLevel, mutationSeed)
	return 0
}

func printHelpTopic(args []string) {
	if len(args) == 0 {
		printGeneralHelp()
		return
	}

	switch args[0] {
	case GENCMD:
		if len(args) > 1 && strings.EqualFold(args[1], "assets") {
			printAssetsHelp()
			return
		}
		printGenHelp(false)
	case RUNCMD:
		printGenHelp(true)
	case RELEASECMD:
		printReleaseHelp()
	default:
		fmt.Printf("unknown help topic: %s\n\n", args[0])
		printGeneralHelp()
	}
}

func printGeneralHelp() {
	fmt.Printf(`mutant
%s

Secure-by-default programming language and toolchain.

Usage:
  mutant
  mutant [global options] <file.mut>
  mutant [runtime options] <file.mu>
  mutant gen [options] --src <file.mut>
  mutant gen assets [options]
  mutant release [options] --src <file.mut>
  mutant help [command]

Commands:
  gen        Compile source into encrypted bytecode.
  gen assets Generate embedded runtime assets for release packaging.
  release    Build a standalone executable for a target OS/ARCH.
  help       Show general or command-specific help.

Global options:
  -h, --help                 Show help.
  -v, --version              Show version information.
  -em, --enable-macros       Start the REPL with experimental macros enabled.
	--repl-theme <name>        REPL theme: default, neon, pastel, forest, sunset.

Runtime options:
  --secure                   Enforce secure mode. Default behavior.
  --compat                   Use compatibility mode with weaker security checks.
  --dev                      Developer mode. Implies compatibility mode and local password fallback.
  --signer-auth              Require trusted signer verification in secure mode.
  --no-signer-auth           Disable signer verification.
  --security-log-level LEVEL Set security logging in dev mode.
  --log-level LEVEL          Alias for --security-log-level.

Examples:
  mutant
  mutant --enable-macros
	mutant --repl-theme neon
	mutant --enable-macros --repl-theme sunset
  mutant hello.mut
  mutant hello.mu --secure --signer-auth
  mutant gen --src hello.mut --password "My$tr0ngPass!"
  mutant gen assets --out ./releaseassets
  mutant release --src hello.mut --os windows --arch amd64 --mutation 5

Use "mutant help gen", "mutant help gen assets", or "mutant help release" for more detail.
`, VERSION)
}

func printGenHelp(isRunAlias bool) {
	commandName := GENCMD
	description := "Compile source into encrypted bytecode."
	if isRunAlias {
		commandName = RUNCMD
		description = "Legacy alias for \"mutant gen\". Compiles source into encrypted bytecode."
	}

	fmt.Printf(`mutant %s

%s

Usage:
  mutant %s --src <file.mut> [options]
  mutant %s <file.mut> [options]

Options:
  --src <file>         Path to the .mut source file.
  --password <value>   Encrypt output with a password.
  --pwd <value>        Alias for --password.
  --mutation <0-10>    Polymorphic mutation level. Default: %d.
  --seed <int64>       Polymorphic seed. Default: current timestamp.
  -h, --help           Show command help.

Examples:
  mutant %s --src hello.mut
  mutant %s hello.mut --password "My$tr0ngPass!"
  mutant %s hello.mut --mutation 5 --seed 42
`, commandName, description, commandName, commandName, defaultPolymorphicLevel, commandName, commandName, commandName)
}

func printAssetsHelp() {
	fmt.Printf(`mutant gen assets

Generate embedded release runtime assets used by standalone release builds.

Usage:
  mutant gen assets [--out <dir>]
  mutant gen --release-assets [--out <dir>]

Options:
  --out <dir>          Output directory. Default: releaseassets.
  --release-assets     Legacy flag-based form of the assets subcommand.
  -h, --help           Show command help.

Examples:
  mutant gen assets
  mutant gen assets --out ./build/releaseassets
`)
}

func printReleaseHelp() {
	fmt.Printf(`mutant release

Build a standalone executable for a target OS and architecture.

Usage:
  mutant release --src <file.mut> [options]
  mutant release <file.mut> [options]

Options:
  --src <file>         Path to the .mut source file.
  --os <name>          Target OS. Default: current host OS.
  --arch <name>        Target architecture. Default: current host architecture.
  --password <value>   Encrypt output with a password.
  --pwd <value>        Alias for --password.
  --mutation <0-10>    Polymorphic mutation level. Default: %d.
  --seed <int64>       Polymorphic seed. Default: current timestamp.
  -h, --help           Show command help.

Supported OS values:
  darwin, linux, windows

Supported architecture values:
  amd64, arm64, arm, 386, x86

Examples:
  mutant release --src hello.mut
  mutant release hello.mut --os windows --arch amd64
  mutant release hello.mut --password "My$tr0ngPass!" --mutation 5
`, defaultPolymorphicLevel)
}

func printCommandError(err error, command string) {
	fmt.Printf("%s: %v\n\n", command, err)
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if isHelpArg(arg) {
			return true
		}
	}
	return false
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help"
}

func isVersionArg(arg string) bool {
	return arg == "-v" || arg == "--version"
}

func isEnableMacrosArg(arg string) bool {
	switch arg {
	case "-em", "--enableMacros", "--enable-macros", "enableMacros":
		return true
	default:
		return false
	}
}

func hasEnableMacrosArg(args []string) bool {
	for _, arg := range args {
		if isEnableMacrosArg(arg) {
			return true
		}
	}
	return false
}

func shouldStartReplFromFlags(args []string) bool {
	if len(args) == 0 || findProgramArg(args) != "" {
		return false
	}

	hasReplFlag := false
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if isHelpArg(arg) || isVersionArg(arg) || isBuiltinCommand(arg) || arg == HELPCMD {
			return false
		}

		if isEnableMacrosArg(arg) {
			hasReplFlag = true
			continue
		}

		if strings.HasPrefix(arg, "--repl-theme=") || strings.HasPrefix(arg, "-repl-theme=") || strings.HasPrefix(arg, "--theme=") || strings.HasPrefix(arg, "-theme=") {
			hasReplFlag = true
			continue
		}

		if arg == "--repl-theme" || arg == "-repl-theme" || arg == "--theme" || arg == "-theme" {
			hasReplFlag = true
			i++
			if i >= len(args) {
				return false
			}
			continue
		}

		return false
	}

	return hasReplFlag
}

func extractReplThemeArg(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--repl-theme" || args[i] == "-repl-theme" || args[i] == "--theme" || args[i] == "-theme" {
			return strings.TrimSpace(args[i+1])
		}
	}

	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--repl-theme=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "--repl-theme="))
		}
		if strings.HasPrefix(args[i], "-repl-theme=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "-repl-theme="))
		}
		if strings.HasPrefix(args[i], "--theme=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "--theme="))
		}
		if strings.HasPrefix(args[i], "-theme=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "-theme="))
		}
	}

	return ""
}

func newFlagSet(name string) *flag.FlagSet {
	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	return flagSet
}

func findProgramArg(args []string) string {
	for _, arg := range args {
		if strings.HasSuffix(arg, global.MutantSourceCodeFileExtention) ||
			strings.HasSuffix(arg, global.MutantByteCodeCompiledFileExtension) {
			return arg
		}
	}

	return ""
}

func configureSecurityLogging(args []string, devMode bool) {
	security.SetSecurityDevMode(devMode)

	level := extractSecurityLogLevelArg(args)
	security.SetSecurityLogLevel(level)
}

// extractSignerAuthArg scans args for explicit signer-auth flags.
// Defaults to disabled unless --signer-auth is supplied.
func extractSignerAuthArg(args []string) bool {
	enforceSignerAuth := false
	for _, arg := range args {
		switch arg {
		case "--signer-auth", "-signer-auth":
			enforceSignerAuth = true
		case "--no-signer-auth", "-no-signer-auth":
			enforceSignerAuth = false
		}
	}
	return enforceSignerAuth
}

// extractPasswordArg scans args for -password|-pwd or --password=|--pwd=<value>
func extractPasswordArg(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-password" || args[i] == "-pwd" || args[i] == "--password" || args[i] == "--pwd" {
			return args[i+1]
		}
	}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--password=") {
			return strings.TrimPrefix(args[i], "--password=")
		}
		if strings.HasPrefix(args[i], "--pwd=") {
			return strings.TrimPrefix(args[i], "--pwd=")
		}
		if strings.HasPrefix(args[i], "-password=") {
			return strings.TrimPrefix(args[i], "-password=")
		}
		if strings.HasPrefix(args[i], "-pwd=") {
			return strings.TrimPrefix(args[i], "-pwd=")
		}
	}
	return ""
}

func prepareRelease(args []string) (string, string, string, string, int, int64, error) {
	var goos, goarch, src, password string
	var mutationLevel int
	var mutationSeed int64

	releasecmd := flag.NewFlagSet(RELEASECMD, flag.ExitOnError)

	releasecmd.StringVar(&src, "src", "", "Mutant Source Code File Path by using -src flag")
	releasecmd.StringVar(&goos, "os", runtime.GOOS, "Use thie flag to specify target OS for cross-compilation by using -os flag")
	releasecmd.StringVar(&goarch, "arch", runtime.GOARCH, "Use thie flag to specify target Architecture for cross-compilation by using -arch flag")
	releasecmd.StringVar(&password, "password", "", "Optional password for encryption (leave empty for deterministic encryption)")
	releasecmd.StringVar(&password, "pwd", "", "Short for -password")
	releasecmd.IntVar(&mutationLevel, "mutation", defaultPolymorphicLevel, "Polymorphic mutation level (0-10)")
	releasecmd.Int64Var(&mutationSeed, "seed", 0, "Polymorphic seed (default: current timestamp)")

	if err := releasecmd.Parse(filterSourceArgs(args[2:])); err != nil {
		return "", "", "", "", 0, 0, err
	}

	if src == "" {
		src = findSourceArg(args[2:])
	}

	if password == "" {
		password = extractPasswordArg(args)
	}

	if releasecmd.Parsed() {
		if src == "" {
			return "", "", "", "", 0, 0, errors.New("mutant source code file path is required, please use -src flag")
		}

		if !strings.HasSuffix(src, global.MutantSourceCodeFileExtention) {
			return "", "", "", "", 0, 0, errors.New("incorrect file extension, this program only works for mutant source code files")
		}

		absSrc, err := filepath.Abs(src)
		if err != nil {
			return "", "", "", "", 0, 0, err
		}

		return absSrc, goos, goarch, password, mutationLevel, mutationSeed, nil
	}

	return "", "", "", "", 0, 0, errors.New("could not parse values")
}

func prepareGenRun(args []string) (string, string, int, int64, error) {
	var src, password string
	var mutationLevel int
	var mutationSeed int64

	gencmd := flag.NewFlagSet(GENCMD, flag.ExitOnError)

	gencmd.StringVar(&src, "src", "", "Mutant Source Code File Path by using -src flag")
	gencmd.StringVar(&password, "password", "", "Optional password for encryption (leave empty for deterministic encryption)")
	gencmd.StringVar(&password, "pwd", "", "Short for -password")
	gencmd.IntVar(&mutationLevel, "mutation", defaultPolymorphicLevel, "Polymorphic mutation level (0-10)")
	gencmd.Int64Var(&mutationSeed, "seed", 0, "Polymorphic seed (default: current timestamp)")

	if err := gencmd.Parse(filterSourceArgs(args[2:])); err != nil {
		return "", "", 0, 0, err
	}

	if src == "" {
		src = findSourceArg(args[2:])
	}

	if password == "" {
		password = extractPasswordArg(args)
	}

	if gencmd.Parsed() {
		if src == "" {
			return "", "", 0, 0, errors.New("mutant source code file path is required, please use -src flag")
		}

		if !strings.HasSuffix(src, global.MutantSourceCodeFileExtention) {
			return "", "", 0, 0, errors.New("incorrect file extension, this program only works for mutant source code files")
		}

		absSrc, err := filepath.Abs(src)
		if err != nil {
			return "", "", 0, 0, err
		}

		return absSrc, password, mutationLevel, mutationSeed, nil
	}

	return "", "", 0, 0, errors.New("could not parse values")
}

func hasReleaseAssetsArg(args []string) bool {
	if len(args) >= 3 && strings.EqualFold(args[2], "assets") {
		return true
	}

	for _, arg := range args {
		if arg == "--release-assets" || arg == "-release-assets" {
			return true
		}
	}

	return false
}

func prepareReleaseAssetsGeneration(args []string) (string, error) {
	var out string

	gencmd := flag.NewFlagSet(GENCMD, flag.ExitOnError)
	gencmd.Bool("release-assets", false, "Generate embedded release runtime assets")
	gencmd.StringVar(&out, "out", "releaseassets", "Directory for generated release assets")

	if err := gencmd.Parse(filterAssetsArgs(args[2:])); err != nil {
		return "", err
	}

	if out == "releaseassets" {
		for _, arg := range gencmd.Args() {
			if strings.EqualFold(arg, "assets") {
				continue
			}
			out = arg
			break
		}
	}

	absOut, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}

	return absOut, nil
}

func filterSourceArgs(args []string) []string {
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-src" || arg == "--src" {
			filtered = append(filtered, arg)
			if i+1 < len(args) {
				filtered = append(filtered, args[i+1])
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "-src=") || strings.HasPrefix(arg, "--src=") {
			filtered = append(filtered, arg)
			continue
		}
		if strings.HasSuffix(arg, global.MutantSourceCodeFileExtention) {
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func filterAssetsArgs(args []string) []string {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.EqualFold(arg, "assets") {
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func findSourceArg(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}

		if strings.HasSuffix(arg, global.MutantSourceCodeFileExtention) {
			return arg
		}
	}

	return ""
}
