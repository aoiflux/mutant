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
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Generate function takes a `string`, it's the path for the source code
// password: optional password for encryption (empty string for deterministic encryption)
// privateKey: Ed25519 private key for signing (if nil, a temporary key is generated)
func Generate(srcpath, dstpath, goos, goarch string, release bool, password string, mutationLevel int, mutationSeed int64, privateKey []byte) (error, errrs.ErrorType, []string) {
	data, err := os.ReadFile(srcpath)
	if err != nil {
		return err, errrs.ERROR, nil
	}

	// Generate signing key if not provided
	if privateKey == nil {
		privateKey, err = loadSigningPrivateKeyFromEnv()
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

	bytecode, err, errtype, errors := compile(data, password, mutationLevel, mutationSeed, privateKey)
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

func loadSigningPrivateKeyFromEnv() ([]byte, error) {
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

func compile(data []byte, password string, mutationLevel int, mutationSeed int64, privateKey []byte) ([]byte, error, errrs.ErrorType, []string) {
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
	expanded, ok := evaluator.ExpandMacros(program, macroEnv).(*ast.Program)
	if !ok || expanded == nil {
		return nil, fmt.Errorf("macro expansion did not return program"), errrs.COMPILER_ERROR, nil
	}

	comp := compiler.NewWithState(symbolTable, constants)
	comp.EnableSecurityOpcodeInjection()
	configureCompilerPolymorphism(comp, mutationLevel, mutationSeed)
	if err := comp.Compile(expanded); err != nil {
		return nil, err, errrs.COMPILER_ERROR, nil
	}

	encodedByteCode, err := encode(comp.ByteCode(), password, privateKey)
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

func encode(compByteCode *compiler.ByteCode, password string, privateKey []byte) ([]byte, error) {
	var content bytes.Buffer

	// Polymorphic marker is compile-time metadata and must not be executed by VM.
	if compiler.DetectPolymorphicLevel(compByteCode.Instructions) > 0 && len(compByteCode.Instructions) >= 2 {
		compByteCode.Instructions = compByteCode.Instructions[:len(compByteCode.Instructions)-2]
	}

	compByteCode = mutil.EncryptByteCode(compByteCode, password)

	registerTypes()
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

func registerTypes() {
	gob.Register(&object.Float{})
	gob.Register(&object.Integer{})
	gob.Register(&object.Boolean{})
	gob.Register(&object.Null{})
	gob.Register(&object.ReturnValue{})
	gob.Register(&object.MultiValue{})
	gob.Register(&object.Error{})
	gob.Register(&object.Function{})
	gob.Register(&object.String{})
	gob.Register(&builtin.BuiltIn{})
	gob.Register(&object.Array{})
	gob.Register(&object.Hash{})
	gob.Register(&object.Quote{})
	gob.Register(&object.Macro{})
	gob.Register(&object.CompiledFunction{})
	gob.Register(&object.Closure{})
	gob.Register(&object.Encrypted{})
}
