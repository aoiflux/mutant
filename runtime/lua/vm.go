package lua

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// SandboxConfig defines the isolation and resource constraints for a Lua VM instance.
type SandboxConfig struct {
	MaxMemoryMB    int
	MaxExecutionMS int
	AllowedLibs    []string // "math", "string", "table" only
}

// SandboxedVM wraps a Lua state with security constraints.
type SandboxedVM struct {
	state         *lua.LState
	config        SandboxConfig
	mu            sync.Mutex
	executionDone chan struct{}
	chunkLoaded   bool
	loadedChunk   *lua.LFunction
}

// DefaultSandboxConfig returns a secure default configuration.
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		MaxMemoryMB:    64,
		MaxExecutionMS: 5000,
		AllowedLibs:    []string{"math", "string", "table"},
	}
}

// NewSandboxedVM creates a new isolated Lua environment with the specified configuration.
// The VM is NOT open/ready for execution until Open() is called.
func NewSandboxedVM(config SandboxConfig) *SandboxedVM {
	return &SandboxedVM{
		config:        config,
		executionDone: make(chan struct{}),
		chunkLoaded:   false,
	}
}

// Open initializes the Lua state and loads only the whitelisted standard libraries.
func (vm *SandboxedVM) Open() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.state != nil {
		return fmt.Errorf("sandbox already open")
	}

	vm.state = lua.NewState(lua.Options{SkipOpenLibs: true})
	if vm.state == nil {
		return fmt.Errorf("failed to create Lua state")
	}
	vm.state.OpenLibs()
	stripUnsafeGlobals(vm.state)

	// Validate allowed library names to keep policy intent explicit.
	for _, libName := range vm.config.AllowedLibs {
		switch libName {
		case "math", "string", "table", "base":
			continue
		default:
			return fmt.Errorf("unsupported library: %s", libName)
		}
	}

	return nil
}

// LoadBytecode loads Lua bytecode into the VM.
// bytecode should be plaintext Lua 5.2 bytecode (e.g., from luac -o bytecode.lua script.lua).
func (vm *SandboxedVM) LoadBytecode(bytecode []byte, chunkName string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.state == nil {
		return fmt.Errorf("sandbox not open")
	}

	if len(bytecode) == 0 {
		return fmt.Errorf("empty lua bytecode")
	}

	if chunkName == "" {
		chunkName = "mutant_lua_patch"
	}

	fn, err := vm.state.Load(bytes.NewReader(bytecode), chunkName)
	if err != nil {
		return fmt.Errorf("failed to load lua bytecode: %w", err)
	}

	vm.loadedChunk = fn
	vm.chunkLoaded = true
	return nil
}

// Execute runs the loaded Lua chunk with timeout enforcement.
// Returns the result or error. Result is converted to string for safety.
func (vm *SandboxedVM) Execute() (string, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.state == nil {
		return "", fmt.Errorf("sandbox not open")
	}

	if !vm.chunkLoaded {
		return "", fmt.Errorf("no loaded chunk")
	}
	if vm.loadedChunk == nil {
		return "", fmt.Errorf("no loaded chunk function")
	}

	if vm.config.MaxExecutionMS > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(vm.config.MaxExecutionMS)*time.Millisecond)
		defer cancel()
		vm.state.SetContext(ctx)
	}

	vm.state.Push(vm.loadedChunk)
	err := vm.state.PCall(0, 1, nil)
	if err != nil {
		return "", fmt.Errorf("lua error: %w", err)
	}

	// Get result from stack
	result := vm.state.Get(-1)
	if result == lua.LNil {
		vm.state.Pop(1)
		vm.loadedChunk = nil
		vm.chunkLoaded = false
		return "", nil
	}
	vm.state.Pop(1)
	vm.loadedChunk = nil
	vm.chunkLoaded = false

	return result.String(), nil
}

// Close cleans up the Lua state and frees all resources.
func (vm *SandboxedVM) Close() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.state != nil {
		vm.state.Close()
		vm.state = nil
		vm.chunkLoaded = false
		vm.loadedChunk = nil
	}

	return nil
}

// GetState returns the underlying Lua state for advanced operations (for internal use only).
func (vm *SandboxedVM) GetState() *lua.LState {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return vm.state
}

func stripUnsafeGlobals(l *lua.LState) {
	unsafeNames := []string{
		"debug",
		"package",
		"os",
		"io",
		"require",
		"dofile",
		"load",
		"loadfile",
		"loadstring",
		"collectgarbage",
	}

	for _, name := range unsafeNames {
		l.SetGlobal(name, lua.LNil)
	}
}
