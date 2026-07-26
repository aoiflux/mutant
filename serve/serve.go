// Package serve implements the per-connection VM spawn behind the net_serve
// builtin (dev-sec-platform-upgrades). It lives in its own package because it
// imports compiler/vm, which the builtin package cannot (import cycle). It wires
// itself into builtin via the NetServe*Hook variables at init time; main.go must
// import this package (blank import is fine) so init() runs.
//
// Model: a handler .mut is compiled ONCE to bytecode (parse -> compile ->
// EncryptByteCode, mirroring the REPL's in-process path), cached by path, then
// executed on a fresh VM per connection. Each VM gets its own stack/frames and
// its own globals slice, and shares the read-only, already-encrypted bytecode of
// the cached handler. The connection handle and shared arg are exposed to the
// handler via the serve_conn()/serve_arg() builtins (a goroutine-keyed context
// set around machine.Run()), so a handler file compiles/runs standalone too and a
// program can serve itself. Per-connection VMs deliberately skip cleanup so a
// finishing worker never wipes the shared bytecode its siblings are still running.
package serve

import (
	"fmt"
	"os"
	"sync"

	"mutant/builtin"
	"mutant/compiler"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/vm"
)

// servePassword keys the in-memory EncryptByteCode/VM XOR. It never touches disk;
// any consistent value works, exactly as replPassword does for the REPL.
const servePassword = "mutant-net-serve-inproc-v1"

type prepared struct {
	bc *compiler.ByteCode
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*prepared{}
)

func init() { Install() }

// Install wires the spawn implementation into the builtin package.
func Install() {
	builtin.NetServePrepareHook = prepare
	builtin.NetServeRunHook = run
	builtin.NetSpawnHook = spawn
}

// prepare compiles and caches a handler's bytecode once. The arg is per-run (not
// cached), so the same handler file can be run with different args (e.g. Splice
// serving a connection vs. a WebSocket reverse pump).
func prepare(handlerPath string) *object.Error {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if _, ok := cache[handlerPath]; ok {
		return nil
	}

	src, err := os.ReadFile(handlerPath)
	if err != nil {
		return errObj("net_serve: cannot read handler %q: %s", handlerPath, err.Error())
	}

	p := parser.New(lexer.New(string(src)))
	program := p.ParseProgram()
	if perrs := p.Errors(); len(perrs) > 0 {
		return errObj("net_serve: handler %q parse error: %s", handlerPath, perrs[0])
	}

	// Fresh symbol table with all builtins defined (serve_conn/serve_arg are among
	// them, so the handler resolves them like any builtin).
	st := compiler.NewSymbolTable()
	for i, b := range builtin.Builtins {
		st.DefineBuiltin(i, b.Name)
	}

	comp := compiler.NewWithState(st, []object.Object{})
	if cerr := comp.Compile(program); cerr != nil {
		return errObj("net_serve: handler %q compile error: %s", handlerPath, cerr.Error())
	}

	bc := mutil.EncryptByteCode(comp.ByteCode(), servePassword)
	cache[handlerPath] = &prepared{bc: bc}
	return nil
}

// run executes the prepared handler for one connection on a fresh VM, exposing
// (connHandle, arg) via serve_conn()/serve_arg().
func run(handlerPath string, connHandle int64, arg object.Object) {
	cacheMu.Lock()
	pr := cache[handlerPath]
	cacheMu.Unlock()
	if pr == nil {
		return
	}

	globals := make([]object.Object, global.GlobalSize)

	// Expose the connection + arg to the handler via serve_conn()/serve_arg() for
	// the duration of this Run (goroutine-keyed; the handler VM runs on this
	// goroutine synchronously).
	builtin.SetServeContext(connHandle, arg)
	defer builtin.ClearServeContext()

	machine := vm.NewWithGlobalStoreAndPassword(pr.bc, globals, servePassword)
	// NOTE: do NOT call CleanupRuntimeSensitiveData here. Its stack sweep calls
	// clearObjectSensitiveData on stack entries, which alias the SHARED constant
	// objects of pr.bc — a finishing worker would zero the encrypted constants
	// its concurrent siblings are still decrypting (SecureXOR then fails on the
	// emptied buffer -> "unusable as a hashkey: ENCRYPTED"). Reads of the shared
	// bytecode (SecureXOROneAt on instructions, DecryptObject on constants) are
	// pure/read-only, so leaving cleanup off makes concurrent execution safe; the
	// per-connection stack/globals are GC-reclaimed when the goroutine returns.
	if err := machine.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[net_serve] handler error (conn %d): %s\n", connHandle, err.Error())
	}
}

// spawn compiles (if needed) and runs a handler on a new goroutine with no
// connection (serve_conn() -> 0) and the given arg (serve_arg()).
func spawn(handlerPath string, arg object.Object) *object.Error {
	if errObj := prepare(handlerPath); errObj != nil {
		return errObj
	}
	go run(handlerPath, 0, arg)
	return nil
}

func errObj(format string, a ...any) *object.Error {
	return &object.Error{Message: fmt.Sprintf(format, a...)}
}
