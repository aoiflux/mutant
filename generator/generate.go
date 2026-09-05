package generator

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"mutant/ast"
	"mutant/builtin"
	"mutant/compiler"
	"mutant/errrs"
	"mutant/evaluator"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
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
func Generate(srcpath, dstpath, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64, privateKey []byte) (error, errrs.ErrorType, []string) {
	data, err := os.ReadFile(srcpath)
	if err != nil {
		return err, errrs.ERROR, nil
	}

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
	bytecode, err, errtype, errors := compile(data, srcpath, release, password, mutationLevel, mutationSeed, privateKey)
	if err != nil {
		return err, errtype, errors
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

// compile turns source into an encoded, encrypted bytecode image.
//
// srcpath is recorded in the image so a runtime error can name the file it came
// from. stripDebug removes that name and every line table before encoding: line
// tables are a reverse-engineering aid, and a release artifact is the thing that
// leaves the machine. Polymorphism strips them too, unconditionally and for a
// second reason -- see ByteCode.StripDebugInfo.
func compile(data []byte, srcpath string, stripDebug bool, password string, mutationLevel int, mutationSeed int64, privateKey []byte) ([]byte, error, errrs.ErrorType, []string) {
	constants := []object.Object{}
	symbolTable := compiler.NewSymbolTable()
	for i, v := range builtin.Builtins {
		symbolTable.DefineBuiltin(i, v.Name)
	}

	l := lexer.New(string(data))
	p := parser.New(l)
	program := p.ParseProgram()

	if len(p.Errors()) != 0 {
		return nil, fmt.Errorf("pareser error"), errrs.PARSER_ERROR, p.Errors()
	}

	macroEnv := object.NewEnvironment()
	evaluator.DefineMacros(program, macroEnv)
	expandedNode, expandErr := evaluator.ExpandMacros(program, macroEnv)
	if expandErr != nil {
		return nil, expandErr, errrs.COMPILER_ERROR, nil
	}
	expanded, ok := expandedNode.(*ast.Program)
	if !ok || expanded == nil {
		return nil, fmt.Errorf("macro expansion did not return program"), errrs.COMPILER_ERROR, nil
	}

	comp := compiler.NewWithState(symbolTable, constants)
	comp.SetSourceFile(srcpath)
	comp.SetSourceText(string(data))
	comp.EnableSecurityOpcodeInjection()
	// The same seed the polymorphic engine gets, applied whatever the mutation
	// level: the injected security checks are part of what --seed has to
	// reproduce, and they are emitted even at level 0.
	comp.SetSecurityCheckSeed(resolvePolymorphismSeed(mutationSeed))
	configureCompilerPolymorphism(comp, mutationLevel, mutationSeed)
	if err := comp.Compile(expanded); err != nil {
		return nil, err, errrs.COMPILER_ERROR, nil
	}

	bytecode := comp.ByteCode()
	if stripDebug {
		bytecode.StripDebugInfo()
	}

	encodedByteCode, err := encode(bytecode, comp.PolymorphicLevel(), password, privateKey)
	if err != nil {
		return nil, err, errrs.ERROR, nil
	}

	return encodedByteCode, nil, "", nil
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
