package lua

import (
	"errors"
	"fmt"
	"sort"

	"mutant/object"
	"mutant/security"
)

var ErrLuaPatchExecution = errors.New("lua patch execution failed")

// ExecutePatches decrypts and executes Lua patches in deterministic order.
// Each patch runs in a fresh sandboxed VM and its plaintext is zeroed after use.
func ExecutePatches(patches map[string]*object.LuaPatch, password string, inslen int, ctx *APIContext) error {
	if len(patches) == 0 {
		return nil
	}

	loader := NewPatchLoader(password, int64(inslen))

	names := make([]string, 0, len(patches))
	for name := range patches {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		patch := patches[name]
		if err := executeSinglePatch(loader, patch, ctx); err != nil {
			return err
		}
	}

	return nil
}

func executeSinglePatch(loader *PatchLoader, patch *object.LuaPatch, baseCtx *APIContext) error {
	if err := ValidatePatchMetadata(patch); err != nil {
		security.RecordIntegrityFailure("lua-patch-metadata")
		return scrubLuaError(err)
	}

	buffer, err := loader.LoadPatch(patch)
	if err != nil {
		return scrubLuaError(fmt.Errorf("load patch %q: %w", patch.Name, err))
	}
	defer buffer.Close()

	vm := NewSandboxedVM(DefaultSandboxConfig())
	if err := vm.Open(); err != nil {
		return scrubLuaError(fmt.Errorf("open sandbox for patch %q: %w", patch.Name, err))
	}
	defer vm.Close()

	ctx := cloneAPIContext(baseCtx)
	ctx.PatchName = patch.Name

	if err := RegisterMutantAPI(vm, ctx); err != nil {
		return scrubLuaError(fmt.Errorf("register API for patch %q: %w", patch.Name, err))
	}

	if err := vm.LoadBytecode(buffer.Bytes(), patch.Name); err != nil {
		return scrubLuaError(fmt.Errorf("load bytecode for patch %q: %w", patch.Name, err))
	}

	if _, err := vm.Execute(); err != nil {
		return scrubLuaError(fmt.Errorf("execute patch %q: %w", patch.Name, err))
	}

	return nil
}

func cloneAPIContext(ctx *APIContext) *APIContext {
	if ctx == nil {
		return &APIContext{
			Globals:   map[string]object.Object{},
			PatchName: "",
		}
	}

	globals := make(map[string]object.Object, len(ctx.Globals))
	for k, v := range ctx.Globals {
		globals[k] = v
	}

	return &APIContext{
		Globals:   globals,
		PatchName: ctx.PatchName,
	}
}

func scrubLuaError(err error) error {
	if err == nil {
		return nil
	}
	return ErrLuaPatchExecution
}
