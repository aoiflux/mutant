package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"mutant/cli"
	"mutant/credential"
	"mutant/global"
	"mutant/mutil"
	"mutant/runner"
	"mutant/security"
	_ "mutant/serve" // installs net_serve concurrency hooks at init

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
	FMTCMD     = "fmt"
	LINTCMD    = "lint"
	TESTCMD    = "test"
	VERSION    = "Version: 2.4.0"
)

type cliRuntime struct {
	runRepl               func(string, bool, string)
	compileCode           func(string, string, string, bool, string, int, int64, []string) int
	generateReleaseAssets func(string) int
	runCode               func(string, runner.Options) int
	hasStandalonePayload  func(string) (bool, error)
	executablePath        func() (string, error)
	getPwd                func() string
}

// defaultPasswordResolver reads the real terminal and filesystem.
//
// resolvePassword is a package-level var rather than a cliRuntime field on
// purpose: tests replace runtimeDeps with a whole struct literal, so a new field
// there defaults to nil and every test that does not know about it panics on the
// first password resolution. A separate var stays wired unless a test
// deliberately overrides it.
var (
	defaultPasswordResolver = &credential.Resolver{}
	resolvePassword         = defaultPasswordResolver.Resolve
)

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
	FMTCMD:     handleFmtCommand,
	LINTCMD:    handleLintCommand,
	TESTCMD:    handleTestCommand,
}

func main() {
	exitCode := run(os.Args)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func run(args []string) int {
	// Flag validation runs before anything else, including the embedded-payload
	// branch, so a contradictory command line is rejected identically whichever
	// entry point would have served it. (M-5)
	if err := validateModeFlags(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

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

	return true, runEmbeddedPayload(executablePath, args)
}

func runEmbeddedPayload(executablePath string, args []string) int {
	opts, devMode := resolveRuntimeExecutionOptions(args)

	configureSecurityLogging(args, devMode)

	// A standalone payload only ever decrypts, so it never confirms.
	password, err := resolveProgramPassword(extractPasswordRequest(args, false), devMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	opts.Password = password

	return runtimeDeps.runCode(executablePath, opts)
}

// resolveRuntimeExecutionOptions returns the run options carried by args, plus
// whether --dev was among them. devMode is not part of runner.Options: it shapes
// security logging and the password fallback here, not the run itself.
func resolveRuntimeExecutionOptions(args []string) (runner.Options, bool) {
	devMode := hasDevModeArg(args)
	secureMode := extractSecurityModeArg(args)
	if devMode {
		secureMode = false
	}

	return runner.Options{
		SecureMode:        secureMode,
		EnforceSignerAuth: extractSignerAuthArg(args),
		Timing:            hasTimingArg(args),
		TrustedKeyPath:    extractTrustedKeyArg(args),
	}, devMode
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

	if handled, exitCode := handleFileInvocation(args); handled {
		return exitCode
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
		case RELEASECMD, GENCMD, RUNCMD, HELPCMD, FMTCMD, LINTCMD, TESTCMD:
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

// canonicalModeFlags maps every accepted spelling of a posture flag to one name,
// so a contradiction is reported under the canonical spelling rather than
// whichever of the two forms the user happened to type.
var canonicalModeFlags = map[string]string{
	"--secure":         "--secure",
	"-secure":          "--secure",
	"--compat":         "--compat",
	"-compat":          "--compat",
	"--dev":            "--dev",
	"-dev":             "--dev",
	"--signer-auth":    "--signer-auth",
	"-signer-auth":     "--signer-auth",
	"--no-signer-auth": "--no-signer-auth",
	"-no-signer-auth":  "--no-signer-auth",
}

// contradictoryFlagPairs are the combinations that have no coherent meaning.
//
// Every scanner in this file is last-flag-wins, which silently resolved these
// to whichever flag came last -- and `--dev` did not even need to come last,
// because resolveRuntimeExecutionOptions forces secureMode off whenever it is
// present. So `mutant prog.mu --dev --secure` ran unsecured, having been asked
// in the same breath to run secured, and said nothing about it. The user meant
// one of the two; guessing which is not the CLI's job. (M-5)
//
// `--dev --compat` is absent on purpose: dev mode implies compatibility mode, so
// naming both is redundant rather than contradictory. Repeating one flag is
// likewise harmless, which is why this tests for presence and not for count.
var contradictoryFlagPairs = []struct {
	first  string
	second string
	reason string
}{
	{
		first:  "--secure",
		second: "--compat",
		reason: "--secure terminates on a security probe hit, --compat downgrades it to a warning",
	},
	{
		first:  "--secure",
		second: "--dev",
		reason: "--secure terminates on a security probe hit, --dev downgrades it to a warning " +
			"and falls back to the built-in development key",
	},
	{
		first:  "--signer-auth",
		second: "--no-signer-auth",
		reason: "--signer-auth requires verification against a trusted public key, " +
			"--no-signer-auth declines it",
	},
}

// validateModeFlags rejects a command line that asks for two incompatible
// postures at once, naming both flags and why they conflict.
func validateModeFlags(args []string) error {
	present := make(map[string]bool, len(canonicalModeFlags))
	for _, arg := range args {
		if canonical, ok := canonicalModeFlags[arg]; ok {
			present[canonical] = true
		}
	}

	for _, pair := range contradictoryFlagPairs {
		if present[pair.first] && present[pair.second] {
			return fmt.Errorf("%s and %s cannot be combined: %s. Pass one of them",
				pair.first, pair.second, pair.reason)
		}
	}

	return nil
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

func hasTimingArg(args []string) bool {
	for _, arg := range args {
		if arg == "--timing" || arg == "-timing" {
			return true
		}
	}
	return false
}

// extractTrustedKeyArg returns the --trusted-key path, in either the separated
// or the =-joined spelling. A path only: key material never comes in on the
// command line, and never from the environment. See docs/CONFIGURATION_POLICY.md.
func extractTrustedKeyArg(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--trusted-key" || args[i] == "-trusted-key" {
			return strings.TrimSpace(args[i+1])
		}
	}
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--trusted-key=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "--trusted-key="))
		}
		if strings.HasPrefix(args[i], "-trusted-key=") {
			return strings.TrimSpace(strings.TrimPrefix(args[i], "-trusted-key="))
		}
	}
	return ""
}

// extractModulePathArgs collects every --module-path directory, in the order
// they were written.
//
// The flag repeats rather than taking a separator-joined list, so a directory
// whose name contains the platform's list separator is still expressible, and
// so the order -- which decides which of two same-named modules wins -- is
// exactly the order on the command line. This is the only way a search
// directory can be named: there is no manifest, no config key and no
// environment variable, per docs/CONFIGURATION_POLICY.md, because where a
// module came from must be visible in the invocation that built it.
func extractModulePathArgs(args []string) []string {
	var paths []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--module-path" || arg == "-module-path":
			if i+1 < len(args) {
				if dir := strings.TrimSpace(args[i+1]); dir != "" {
					paths = append(paths, dir)
				}
				i++
			}
		case strings.HasPrefix(arg, "--module-path="):
			if dir := strings.TrimSpace(strings.TrimPrefix(arg, "--module-path=")); dir != "" {
				paths = append(paths, dir)
			}
		case strings.HasPrefix(arg, "-module-path="):
			if dir := strings.TrimSpace(strings.TrimPrefix(arg, "-module-path=")); dir != "" {
				paths = append(paths, dir)
			}
		}
	}

	return paths
}

// modulePathFlag is the repeatable --module-path as a flag.Value, for the
// subcommand FlagSets. Those run with flag.ExitOnError, so a flag they have
// never heard of aborts the process with exit 2 -- declaring it is what keeps
// `mutant gen --src x.mut --module-path ./lib` from dying before it starts.
type modulePathFlag struct{ dirs *[]string }

func (f modulePathFlag) String() string {
	if f.dirs == nil {
		return ""
	}
	return strings.Join(*f.dirs, string(os.PathListSeparator))
}

func (f modulePathFlag) Set(value string) error {
	dir := strings.TrimSpace(value)
	if dir == "" {
		return errors.New("--module-path needs a directory")
	}
	*f.dirs = append(*f.dirs, dir)
	return nil
}

// registerModulePathFlag declares --module-path on a subcommand FlagSet.
func registerModulePathFlag(fs *flag.FlagSet, dirs *[]string) {
	fs.Var(modulePathFlag{dirs: dirs}, "module-path",
		"Directory to search for imported modules; repeat for more, searched in order")
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

func handleFileInvocation(args []string) (bool, int) {
	if len(args) < 2 {
		return false, 0
	}

	if isBuiltinCommand(args[1]) {
		return false, 0
	}

	fileArg := findProgramArg(args[1:])
	if fileArg == "" {
		return false, 0
	}

	return executeProgramFile(args, fileArg)
}

func isBuiltinCommand(arg string) bool {
	switch arg {
	case RELEASECMD, GENCMD, RUNCMD, HELPCMD, FMTCMD, LINTCMD, TESTCMD:
		return true
	default:
		return false
	}
}

// executeProgramFile reports whether it handled the invocation, and the exit
// code to leave with when it did.
func executeProgramFile(args []string, fileArg string) (bool, int) {
	isSource := strings.HasSuffix(fileArg, global.MutantSourceCodeFileExtention)
	isCompiled := strings.HasSuffix(fileArg, global.MutantByteCodeCompiledFileExtension)
	if !isSource && !isCompiled {
		return false, 0
	}

	opts, devMode := resolveRuntimeExecutionOptions(args)
	configureSecurityLogging(args, devMode)

	// The password is resolved before the extension branch rather than after it.
	// It used to be resolved only on the .mu run path, so the .mut compile branch
	// ran with whatever argv held -- and the encryption layer rejects an empty
	// key. That made --dev's no-password contract unreachable: no Mutant program
	// could be compiled without a password by any means. (M-1)
	//
	// isSource decides whether to confirm: compiling encrypts, and a mistyped
	// password there produces an artifact nobody can ever open. Running only
	// decrypts, where a wrong password simply fails.
	password, err := resolveProgramPassword(extractPasswordRequest(args, isSource), devMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return true, 1
	}
	opts.Password = password

	if isSource {
		return true, runtimeDeps.compileCode(fileArg, "", "", false, opts.Password, defaultPolymorphicLevel, time.Now().UnixNano(), extractModulePathArgs(args))
	}

	return true, runtimeDeps.runCode(fileArg, opts)
}

// resolveProgramPassword returns the password a compile or run should use, or an
// error naming the fix when one is required and absent.
//
// The development-key fallback is gated on --dev alone. It used to fire whenever
// argv happened to be exactly two items, which handed the built-in development
// key to default (secure) mode with no flag typed and nothing printed. Because
// the test was positional, adding a supposedly no-op --secure changed which key
// decrypted the artifact: `mutant prog.mu` and `mutant prog.mu --secure` were
// the same request with different keys. (M-2)
func resolveProgramPassword(req credential.Request, devMode bool) (string, error) {
	// --dev's built-in key applies only when the command line named no password
	// source at all. Checking Any() rather than an empty string is what keeps
	// --dev from silently overriding an explicit --password-file whose read
	// failed, and what stops a dev-mode run from prompting. (M-1, M-3)
	if !req.Any() && devMode {
		// GetPwd() is a fixed HKDF derivation over three string constants compiled
		// into the binary, so every Mutant binary ever built derives the identical
		// key. Anything encrypted under it is readable by anyone holding a copy of
		// the binary. That is a fine local convenience and it must never be silent. (M-3)
		fmt.Fprintln(os.Stderr,
			"[dev] no password supplied; using the built-in development key -- not for release artifacts")
		return runtimeDeps.getPwd(), nil
	}

	secret, _, err := resolvePassword(req)
	if err != nil {
		return "", err
	}

	// The string conversion copies the password into immutable memory that can
	// never be erased; zeroing the byte slice closes the half of the window that
	// is closable today. Removing the other half means threading []byte through
	// the encryption pipeline end to end -- see credential.Zero.
	defer credential.Zero(secret)
	return string(secret), nil
}

// refuseDevModeForRelease rejects --dev on any command that produces a release
// artifact. The development key is public by construction, so an artifact built
// under it has no confidentiality -- acceptable in an edit-compile-run loop,
// never in something shipped. (M-3)
func refuseDevModeForRelease(args []string) error {
	if !hasDevModeArg(args) {
		return nil
	}

	return errors.New("--dev cannot be used when producing a release artifact: the development " +
		"key is a compile-time constant shared by every Mutant binary, so the artifact would " +
		"have no confidentiality. Pass --password <value> instead")
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

	if err := refuseDevModeForRelease(args); err != nil {
		printCommandError(err, RELEASECMD)
		return 1
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
	if err := refuseDevModeForRelease(args); err != nil {
		printCommandError(err, "gen assets")
		return 1
	}

	out, err := prepareReleaseAssetsGeneration(args)
	if err != nil {
		printCommandError(err, "gen assets")
		printAssetsHelp()
		return 1
	}

	fmt.Println("Generating embedded release runtime assets...")
	return runtimeDeps.generateReleaseAssets(out)
}

func handleGenCompileCommand(args []string) int {
	src, request, mutationLevel, mutationSeed, modulePaths, err := prepareGenRun(args)
	if err != nil {
		printCommandError(err, args[1])
		printGenHelp(args[1] == RUNCMD)
		return 1
	}

	// Resolved after argument validation so a malformed command line fails on
	// the malformed part rather than prompting for a password it will not use.
	//
	// --dev is honoured here for the same reason it is on `mutant file.mut`:
	// the two are the same operation typed two ways, and having one of them
	// accept the development key while the other silently prompted was a
	// difference nobody could have predicted from the flag. `gen` produces a
	// .mu for local use; `release` and `gen assets` still refuse --dev, because
	// those produce artifacts that ship. (M-1, S-2)
	password, err := resolveProgramPassword(request, hasDevModeArg(args))
	if err != nil {
		printCommandError(err, args[1])
		return 1
	}

	fmt.Println("Generating bytecode...")
	return runtimeDeps.compileCode(src, "", "", false, password, mutationLevel, mutationSeed, modulePaths)
}

func handleReleaseCompileCommand(args []string) int {

	src, goos, goarch, request, mutationLevel, mutationSeed, modulePaths, err := prepareRelease(args)
	if err != nil {
		printCommandError(err, RELEASECMD)
		printReleaseHelp()
		return 1
	}

	password, err := resolveProgramPassword(request, false)
	if err != nil {
		printCommandError(err, RELEASECMD)
		return 1
	}

	fmt.Println("Compiling release build...")
	return runtimeDeps.compileCode(src, goos, goarch, true, password, mutationLevel, mutationSeed, modulePaths)
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
  mutant <file.mut> [password options]
  mutant <file.mu> [runtime options] [password options]
  mutant gen [options] --src <file.mut>
  mutant gen assets [options]
  mutant release [options] --src <file.mut>
  mutant fmt [--check] [--stdout] <file-or-dir>...
  mutant lint [--strict] <file-or-dir>...
  mutant test [file-or-dir]...
  mutant help [command]

Commands:
  gen        Compile source into encrypted bytecode.
  gen assets Generate embedded runtime assets for release packaging.
  release    Build a standalone executable for a target OS/ARCH.
  fmt        Format Mutant source in place (or --check / --stdout).
  lint       Report diagnostics for Mutant source (--strict fails on warnings).
  test       Run *_test.mut files (fail on error or a false result).
  help       Show general or command-specific help.

Global options:
  -h, --help                 Show help.
  -v, --version              Show version information.
  -em, --enable-macros       Start the REPL with experimental macros enabled.
  --repl-theme <name>        REPL theme: default, neon, pastel, forest, sunset.

Password options:
  (none)                     Prompt on the terminal with echo off. Preferred.
  --password-file PATH       Read the password from PATH. Refused if the file is
                             readable by other users (POSIX permissions only).
  --password-stdin           Read the password from stdin, for CI and pipelines.
  --password <value>         DEPRECATED: visible in the process table and shell
                             history. Warns on use; will require
                             --password-insecure in the next minor release.
  --password-insecure <v>    Same as --password, opted into explicitly.

Execution modes (pick at most one; naming two is an error):
  --secure                   Secure mode: the default. A security probe hit ends
                             the run. Say it explicitly to record the posture.
  --compat                   Compatibility mode: a probe hit warns and the run
                             continues. Use where secure mode's probes fire on an
                             ordinary container, VM or CI runner.
  --dev                      Developer mode. Compatibility posture, plus a
                             fallback to a development key that is a compile-time
                             constant shared by every Mutant binary, so anyone
                             holding a copy of the binary can decrypt what it
                             produced. Local development only; refused for
                             release artifacts.

  --compat weakens the response. --dev weakens the key. Compat still requires
  your password and still verifies the artifact; it only declines to stop the run
  when a probe fires. An artifact built or run under --dev has no
  confidentiality. See docs/EXECUTION_MODES.md.

Runtime options:
  --signer-auth              Upgrade signature verification to a trusted public
                             key. Self-verification runs in every mode already.
  --no-signer-auth           Do not verify against a trusted key. The default.
  --trusted-key PATH         Verify against the public key in PATH (hex-encoded).
  --security-log-level LEVEL Set security logging in dev mode.
  --log-level LEVEL          Alias for --security-log-level.
  --timing                   Print per-stage run timing to stderr.

Examples:
  mutant
  mutant --enable-macros
  mutant --repl-theme neon
  mutant --enable-macros --repl-theme sunset
  mutant hello.mut                       (prompts, and confirms, for a password)
  mutant hello.mu                        (prompts for a password)
  mutant hello.mu --secure --signer-auth
  mutant hello.mu --timing
  mutant hello.mu --password-file ~/.mutant/case-42.key
  mutant gen --src hello.mut --password-stdin < ./secret
  mutant gen assets --out ./releaseassets
  mutant release --src hello.mut --os windows --arch amd64 --mutation 5
  mutant fmt examples/
  mutant fmt --check hello.mut
  mutant lint --strict examples/
  mutant test examples/

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
  --password-file PATH Read the encryption password from PATH.
  --password-stdin     Read the encryption password from stdin.
  --password <value>   DEPRECATED: visible in the process table. Warns on use.
  --pwd <value>        Alias for --password.
  --module-path <dir>  Directory to search for imports that do not resolve
                       relative to the file that wrote them. Repeat the flag to
                       add more; they are searched in the order given.
  --mutation <0-10>    Polymorphic mutation level. Default: %d.
  --seed <int64>       Build seed: reproduces the bytecode (mutations and
                       security-check placement). The .mu file still differs
                       every build. Default: current timestamp.
  -h, --help           Show command help.

With no password option the password is prompted for twice, so a typo cannot
produce an artifact nobody can open.

Examples:
  mutant %s --src hello.mut
  mutant %s hello.mut --password-file ~/.mutant/case-42.key
  mutant %s hello.mut --password-stdin --mutation 5 --seed 42 < ./secret

The compiled .mu lands beside the source. Run it with:
  mutant hello.mu --password-file ~/.mutant/case-42.key
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
  --password-file PATH Read the encryption password from PATH.
  --password-stdin     Read the encryption password from stdin.
  --password <value>   DEPRECATED: visible in the process table. Warns on use.
  --pwd <value>        Alias for --password.
  --module-path <dir>  Directory to search for imports that do not resolve
                       relative to the file that wrote them. Repeat the flag to
                       add more; they are searched in the order given.
  --mutation <0-10>    Polymorphic mutation level. Default: %d.
  --seed <int64>       Build seed: reproduces the bytecode (mutations and
                       security-check placement). The .mu file still differs
                       every build. Default: current timestamp.
  -h, --help           Show command help.

Supported OS values:
  darwin, linux, windows

Supported architecture values:
  amd64, arm64, arm, 386, x86

Examples:
  mutant release --src hello.mut
  mutant release hello.mut --os windows --arch amd64
  mutant release hello.mut --password-file ~/.mutant/release.key --mutation 5

--dev is refused here: the development key is a compile-time constant shared by
every Mutant binary, so a release built under it has no confidentiality.
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

// extractPasswordRequest collects every password source named on the command
// line. It reports what was asked for; credential.Resolver decides what that
// means, including rejecting a command line that names more than one.
func extractPasswordRequest(args []string, confirm bool) credential.Request {
	return credential.Request{
		Inline:   extractFlagValue(args, "password", "pwd"),
		Insecure: extractFlagValue(args, "password-insecure"),
		FilePath: extractFlagValue(args, "password-file"),
		Stdin:    hasBoolFlag(args, "password-stdin"),
		Confirm:  confirm,
	}
}

// extractFlagValue returns the value of the first of names present in args,
// accepting `-name value`, `--name value`, `-name=value` and `--name=value`.
func extractFlagValue(args []string, names ...string) string {
	for i := 0; i < len(args); i++ {
		for _, name := range names {
			if i+1 < len(args) && (args[i] == "-"+name || args[i] == "--"+name) {
				return args[i+1]
			}
			for _, prefix := range []string{"--" + name + "=", "-" + name + "="} {
				if strings.HasPrefix(args[i], prefix) {
					return strings.TrimPrefix(args[i], prefix)
				}
			}
		}
	}
	return ""
}

func hasBoolFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == "-"+name || arg == "--"+name {
			return true
		}
	}
	return false
}

// registerPasswordFlags declares the password flags on a subcommand FlagSet.
//
// The values are deliberately discarded: extractPasswordRequest reads the raw
// command line, so it stays the single place that knows how a password source
// is spelled. These declarations exist so the FlagSet -- which runs with
// flag.ExitOnError -- does not abort on a flag it has never heard of, and so
// they appear in the subcommand's own -h output.
func registerPasswordFlags(fs *flag.FlagSet) {
	var (
		discardString string
		discardBool   bool
	)
	fs.StringVar(&discardString, "password-file", "", "Read the encryption password from this file")
	fs.StringVar(&discardString, "password-insecure", "", "Password on argv, opted into explicitly")
	fs.BoolVar(&discardBool, "password-stdin", false, "Read the encryption password from stdin")
	fs.BoolVar(&discardBool, "dev", false, "Use the built-in development key (local development only)")
}

func prepareRelease(args []string) (string, string, string, credential.Request, int, int64, []string, error) {
	var goos, goarch, src, password string
	var mutationLevel int
	var mutationSeed int64
	var modulePaths []string

	releasecmd := flag.NewFlagSet(RELEASECMD, flag.ExitOnError)

	releasecmd.StringVar(&src, "src", "", "Mutant Source Code File Path by using -src flag")
	releasecmd.StringVar(&goos, "os", runtime.GOOS, "Use thie flag to specify target OS for cross-compilation by using -os flag")
	releasecmd.StringVar(&goarch, "arch", runtime.GOARCH, "Use thie flag to specify target Architecture for cross-compilation by using -arch flag")
	releasecmd.StringVar(&password, "password", "", "Password on argv (deprecated -- visible in the process table)")
	releasecmd.StringVar(&password, "pwd", "", "Short for -password")
	registerPasswordFlags(releasecmd)
	registerModulePathFlag(releasecmd, &modulePaths)
	releasecmd.IntVar(&mutationLevel, "mutation", defaultPolymorphicLevel, "Polymorphic mutation level (0-10)")
	releasecmd.Int64Var(&mutationSeed, "seed", 0, "Build seed; reproduces the bytecode, not the .mu file (default: current timestamp)")

	if err := releasecmd.Parse(filterSourceArgs(args[2:])); err != nil {
		return "", "", "", credential.Request{}, 0, 0, nil, err
	}

	if src == "" {
		src = findSourceArg(args[2:])
	}

	// release compiles, so it confirms an interactively typed password.
	request := extractPasswordRequest(args, true)
	if request.Inline == "" {
		request.Inline = password
	}

	if releasecmd.Parsed() {
		if src == "" {
			return "", "", "", request, 0, 0, nil, errors.New("mutant source code file path is required, please use -src flag")
		}

		if !strings.HasSuffix(src, global.MutantSourceCodeFileExtention) {
			return "", "", "", request, 0, 0, nil, errors.New("incorrect file extension, this program only works for mutant source code files")
		}

		absSrc, err := filepath.Abs(src)
		if err != nil {
			return "", "", "", request, 0, 0, nil, err
		}

		return absSrc, goos, goarch, request, mutationLevel, mutationSeed, modulePaths, nil
	}

	return "", "", "", request, 0, 0, nil, errors.New("could not parse values")
}

func prepareGenRun(args []string) (string, credential.Request, int, int64, []string, error) {
	var src, password string
	var mutationLevel int
	var mutationSeed int64
	var modulePaths []string

	gencmd := flag.NewFlagSet(GENCMD, flag.ExitOnError)

	gencmd.StringVar(&src, "src", "", "Mutant Source Code File Path by using -src flag")
	gencmd.StringVar(&password, "password", "", "Password on argv (deprecated -- visible in the process table)")
	gencmd.StringVar(&password, "pwd", "", "Short for -password")
	registerPasswordFlags(gencmd)
	registerModulePathFlag(gencmd, &modulePaths)
	gencmd.IntVar(&mutationLevel, "mutation", defaultPolymorphicLevel, "Polymorphic mutation level (0-10)")
	gencmd.Int64Var(&mutationSeed, "seed", 0, "Build seed; reproduces the bytecode, not the .mu file (default: current timestamp)")

	if err := gencmd.Parse(filterSourceArgs(args[2:])); err != nil {
		return "", credential.Request{}, 0, 0, nil, err
	}

	if src == "" {
		src = findSourceArg(args[2:])
	}

	// gen compiles, so it confirms an interactively typed password.
	request := extractPasswordRequest(args, true)
	if request.Inline == "" {
		request.Inline = password
	}

	if gencmd.Parsed() {
		if src == "" {
			return "", request, 0, 0, nil, errors.New("mutant source code file path is required, please use -src flag")
		}

		if !strings.HasSuffix(src, global.MutantSourceCodeFileExtention) {
			return "", request, 0, 0, nil, errors.New("incorrect file extension, this program only works for mutant source code files")
		}

		absSrc, err := filepath.Abs(src)
		if err != nil {
			return "", request, 0, 0, nil, err
		}

		return absSrc, request, mutationLevel, mutationSeed, modulePaths, nil
	}

	return "", request, 0, 0, nil, errors.New("could not parse values")
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
