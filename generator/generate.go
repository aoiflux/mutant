package generator

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"mutant/ast"
	"mutant/builtin"
	"mutant/compiler"
	"mutant/errrs"
	"mutant/evaluator"
	"mutant/global"
	"mutant/module"
	"mutant/mutil"
	"mutant/object"
	"mutant/security"
	"mutant/serialize"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Generate compiles the source at srcpath and writes the encrypted, signed
// artifact to dstpath.
//
// password is required, not optional: the encryption layer rejects an empty key
// outright ("password cannot be empty"). This comment used to say an empty
// string selected deterministic encryption, which was never true of the code it
// documents -- and it is the reason passwordless --dev looked implemented while
// no program could actually be compiled without a password. Callers that want
// the development key must resolve it before calling. (M-1)
//
// privateKey: Ed25519 private key for signing (if nil, one is loaded or bootstrapped)
// modulePaths are the directories from repeated --module-path flags, searched
// in order for any import that does not resolve relative to the file that
// wrote it. Nil means relative resolution only.
func Generate(srcpath, dstpath, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64, privateKey []byte, modulePaths []string) (error, errrs.ErrorType, []string) {
	var err error

	// Generate signing key if not provided
	if privateKey == nil {
		privateKey, err = loadOrBootstrapSigningPrivateKey()
		if err != nil {
			return err, errrs.ERROR, nil
		}

		if privateKey == nil {
			keyPair, err := security.GenerateKeyPair()
			if err != nil {
				return err, errrs.ERROR, nil
			}
			privateKey = keyPair.PrivateKey

			// Local keypair bootstrap provides deterministic signer identity per host.
		}
	}

	// Release artifacts ship without source positions; see stripDebugInfo in
	// compile. A local compile keeps them, because the program is about to run
	// on the machine that holds the source anyway.
	bytecode, err, errtype, details := compile(srcpath, modulePaths, release, password, mutationLevel, mutationSeed, privateKey)
	if err != nil {
		return err, errtype, details
	}

	if release {
		if goos == global.WINDOWS {
			dstpath += global.WindowsPE32ExecutableExtension
		}

		if err := writeBinaryRelease(dstpath, goos, goarch, bytecode); err != nil {
			return err, errrs.ERROR, nil
		}

		return nil, "", nil
	}

	if err := os.WriteFile(dstpath+global.MutantByteCodeCompiledFileExtension, bytecode, 0644); err != nil {
		return err, errrs.ERROR, nil
	}

	return nil, "", nil
}

// loadOrBootstrapSigningPrivateKey returns the host's persistent signing key,
// creating the local keypair on first use. It reads no environment variable --
// the name it used to carry said otherwise, and there has been nothing to read
// for some time. See docs/CONFIGURATION_POLICY.md.
func loadOrBootstrapSigningPrivateKey() ([]byte, error) {
	privateKey, _, created, keyDir, err := security.EnsureLocalSigningKeyPair()
	if err != nil {
		return nil, err
	}

	if created {
		privatePath, publicPath := security.LocalKeyPairPaths(keyDir)
		fmt.Fprintf(os.Stderr,
			"[security] generated local signing keypair for reuse\n[security] private=%s\n[security] public=%s\n",
			filepath.Clean(privatePath),
			filepath.Clean(publicPath),
		)
	}

	return privateKey, nil
}

// compile turns the program rooted at entrypath into an encoded, encrypted
// bytecode image.
//
// The entry path is recorded in the image so a runtime error can name the
// program it came from. stripDebug removes that name and every line table
// before encoding: line tables are a reverse-engineering aid, and a release
// artifact is the thing that leaves the machine. Polymorphism strips them too,
// unconditionally and for a second reason -- see ByteCode.StripDebugInfo.
//
// The module graph is walked, linked and driven through ONE compiler, with
// ByteCode() called exactly once. That is forced by the bytecode format, not
// chosen: the polymorphic engine shuffles the whole constant pool and rewrites
// every operand against it, the opcode permutation ships as a single 256-entry
// table for the entire program, and jumps carry absolute stream offsets. Two
// separately compiled modules could not be merged afterwards without each
// indexing the other's constants.
func compile(entrypath string, modulePaths []string, stripDebug bool, password string, mutationLevel int, mutationSeed int64, privateKey []byte) ([]byte, error, errrs.ErrorType, []string) {
	bytecode, level, err, errType, details := buildByteCode(entrypath, modulePaths, mutationLevel, mutationSeed)
	if err != nil {
		return nil, err, errType, details
	}

	if stripDebug {
		bytecode.StripDebugInfo()
	}

	encodedByteCode, err := encode(bytecode, level, password, privateKey)
	if err != nil {
		return nil, err, errrs.ERROR, nil
	}

	return encodedByteCode, nil, "", nil
}

// CompileForDebug compiles a program to bytecode a debugger can drive: every
// position kept, and no mutation.
//
// It stops where compile continues -- before stripping, before encoding, before
// signing -- because a debug session runs the program in the process that
// compiled it. Round-tripping it through an artifact would mean either a
// password prompt in the middle of a protocol handshake the editor owns, or a
// release build with nothing left to step through. See decision 2 in
// plans/T1_DEBUGGER.md.
//
// Mutation is off for the same reason: nothing is being protected in a session
// whose whole purpose is to watch the program execute, and every layer removed
// is a layer that cannot misreport a position. The injected security checks
// stay on, so the program being stepped is the program that runs.
func CompileForDebug(entrypath string, modulePaths []string) (*compiler.ByteCode, error, errrs.ErrorType, []string) {
	bytecode, _, err, errType, details := buildByteCode(entrypath, modulePaths, 0, 0)
	return bytecode, err, errType, details
}

// buildByteCode walks the import graph, links it, and compiles the result. It
// is everything compile does up to the point where the bytecode becomes a file,
// split out so a debug session can take the bytecode and stop there.
//
// The second return is the polymorphism level the compiler actually applied,
// which encode needs and which is not recoverable from the instruction bytes.
func buildByteCode(entrypath string, modulePaths []string, mutationLevel int, mutationSeed int64) (*compiler.ByteCode, int, error, errrs.ErrorType, []string) {
	graph, err := module.Load(entrypath, modulePaths)
	if err != nil {
		return nil, 0, err, moduleErrorType(err), moduleErrorDetails(err)
	}
	linked := graph.Link()

	constants := []object.Object{}
	symbolTable := compiler.NewSymbolTable()
	for i, v := range builtin.Builtins {
		symbolTable.DefineBuiltin(i, v.Name)
	}

	comp := compiler.NewWithState(symbolTable, constants)
	// SourceFile stays the entry: it is the program's identity. Which file any
	// individual line came from is what ModuleSpans answers.
	comp.SetSourceFile(linked.EntryPath)
	comp.SetSourceText(linked.SourceText)
	comp.SetModuleSpans(linked.Spans)
	comp.EnableSecurityOpcodeInjection()
	// The same seed the polymorphic engine gets, applied whatever the mutation
	// level: the injected security checks are part of what --seed has to
	// reproduce, and they are emitted even at level 0.
	comp.SetSecurityCheckSeed(resolvePolymorphismSeed(mutationSeed))
	configureCompilerPolymorphism(comp, mutationLevel, mutationSeed)

	// One macro environment for the whole program, filled in link order, so a
	// macro a module defines is available to everything that imports it and to
	// nothing it imports. Expansion runs after linking has already rebased the
	// positions, which is what puts absolute lines into the macro table.
	macroEnv := object.NewEnvironment()
	for _, mod := range linked.Modules {
		// Each module gets its own top-level scope, so two files may both
		// declare `helper` and `ns.name` knows which one it means. The order is
		// the graph's post-order, so every module a file imports has already
		// been entered and compiled by the time that file names it.
		comp.EnterModule(mod.Scope())

		evaluator.DefineMacros(mod.Program, macroEnv)
		expandedNode, expandErr := evaluator.ExpandMacros(mod.Program, macroEnv)
		if expandErr != nil {
			return nil, 0, expandErr, errrs.COMPILER_ERROR, nil
		}
		expanded, ok := expandedNode.(*ast.Program)
		if !ok || expanded == nil {
			return nil, 0, fmt.Errorf("macro expansion did not return program"), errrs.COMPILER_ERROR, nil
		}

		if err := comp.Compile(expanded); err != nil {
			return nil, 0, err, errrs.COMPILER_ERROR, nil
		}
	}

	return comp.ByteCode(), comp.PolymorphicLevel(), nil, "", nil
}

// moduleErrorType classifies a failure from walking the import graph so the
// CLI prints it the way it prints the same failure for a single file.
//
// A module that would not parse is a parse error whether it was the entry or
// something the entry imported; anything else about resolution -- a path that
// names no file, a cycle, an unreadable file -- is an ordinary error, because
// nothing was ever compiled.
func moduleErrorType(err error) errrs.ErrorType {
	var parseErr *module.ParseError
	if errors.As(err, &parseErr) {
		return errrs.PARSER_ERROR
	}
	return errrs.ERROR
}

// moduleErrorDetails returns the individual parser messages when the failure
// was a parse error, so they print one per line rather than as one blob.
func moduleErrorDetails(err error) []string {
	var parseErr *module.ParseError
	if errors.As(err, &parseErr) {
		return parseErr.Errors
	}
	return nil
}

func configureCompilerPolymorphism(comp *compiler.Compiler, mutationLevel int, mutationSeed int64) {
	if mutationLevel <= 0 {
		return
	}

	comp.EnablePolymorphismWithSeed(mutationLevel, resolvePolymorphismSeed(mutationSeed))
}

func resolvePolymorphismSeed(seed int64) int64 {
	if seed != 0 {
		return seed
	}
	return time.Now().UnixNano()
}

// encode serialises the bytecode for writing. polymorphicLevel is the level the
// compiler actually applied, not a level guessed from the instruction bytes.
func encode(compByteCode *compiler.ByteCode, polymorphicLevel int, password string, privateKey []byte) ([]byte, error) {
	var content bytes.Buffer

	// The polymorphic marker is compile-time metadata and must not reach the VM.
	// It is present exactly when the compiler ran a mutation level above zero, so
	// that is what decides the trim.
	//
	// This used to call DetectPolymorphicLevel, which reads the last two bytes and
	// treats [0xFF, n<=10] as a marker. Real bytecode hits that pattern by itself:
	// a program with 256 constants ending in `OpConstant 255` (operand 0x00FF)
	// followed by OpPop ends in 0xFF 0x01. Two real bytes were then cut from the
	// program, and it died in the VM on "not enough bytes for operand" -- at
	// mutation level 0, with no mutation involved anywhere.
	if polymorphicLevel > 0 && len(compByteCode.Instructions) >= 2 {
		compByteCode.Instructions = compByteCode.Instructions[:len(compByteCode.Instructions)-2]
	}

	compByteCode = mutil.EncryptByteCode(compByteCode, password)

	serialize.RegisterGobTypes()
	enc := gob.NewEncoder(&content)
	if err := enc.Encode(compByteCode); err != nil {
		return nil, err
	}

	byteCode := content.Bytes()
	compressedByteCode, err := compressEncodedByteCode(byteCode)
	if err != nil {
		return nil, err
	}
	return encryptCode(compressedByteCode, password, privateKey)
}

func compressEncodedByteCode(encoded []byte) ([]byte, error) {
	var buf bytes.Buffer
	encoder, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return nil, err
	}

	if _, err := encoder.Write(encoded); err != nil {
		_ = encoder.Close()
		return nil, err
	}

	if err := encoder.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func encryptCode(b64ByteCode []byte, password string, privateKey []byte) ([]byte, error) {
	// Apply secure XOR (replaces insecure math/rand-based XOR)
	xorByteCode, err := security.SecureXOREncrypt(b64ByteCode)
	if err != nil {
		return nil, err
	}

	// Encrypt using new secure method (no key storage)
	var encodedByteCode string
	encodedByteCode, err = security.AESEncrypt(xorByteCode, password)
	if err != nil {
		return nil, err
	}

	// Sign with Ed25519 (replaces insecure MD5)
	signedCode, err := security.SignCode(encodedByteCode, privateKey)
	if err != nil {
		return nil, err
	}

	return signedCode, nil
}
