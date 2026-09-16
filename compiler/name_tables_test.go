package compiler

import (
	"bytes"
	"encoding/gob"
	"reflect"
	"sort"
	"testing"

	"mutant/object"
	"mutant/serialize"
)

// onlyFunction returns the single compiled function in the pool, failing when
// there is not exactly one. Every program here declares one on purpose.
func onlyFunction(t *testing.T, bytecode *ByteCode) *object.CompiledFunction {
	t.Helper()

	var found *object.CompiledFunction
	for _, constant := range bytecode.Constants {
		fn, ok := constant.(*object.CompiledFunction)
		if !ok {
			continue
		}
		if found != nil {
			t.Fatal("the program compiled to more than one function")
		}
		found = fn
	}
	if found == nil {
		t.Fatal("the program compiled to no function at all")
	}
	return found
}

// A frame's slots are numbers to the VM and have to be names to a reader. The
// parameters come first, in declaration order, and the body's own bindings
// follow in the order they were written.
func TestLocalSlotNamesNameEveryFrameSlot(t *testing.T) {
	src := "let tally = fn(xs, start) {\n" +
		"\tlet total = start;\n" +
		"\tlet count = 0;\n" +
		"\treturn total + count;\n" +
		"};\n" +
		"tally([1], 0);\n"

	fn := onlyFunction(t, compileWithPositions(t, src))

	want := []string{"xs", "start", "total", "count"}
	if !reflect.DeepEqual(fn.LocalNames, want) {
		t.Fatalf("local slots are named %v, want %v", fn.LocalNames, want)
	}
	if len(fn.LocalNames) != fn.NumLocals {
		t.Errorf("%d names for %d slots: a debugger would read past the frame",
			len(fn.LocalNames), fn.NumLocals)
	}
	// Params predates this table and is what a traceback prints. The two must
	// agree where they overlap, or the same argument is called two things in
	// two windows of the same editor.
	for i, param := range fn.Params {
		if fn.LocalNames[i] != param {
			t.Errorf("slot %d is %q in LocalNames and %q in Params", i, fn.LocalNames[i], param)
		}
	}
}

// Nothing stops a second `let` from taking a name over, and each allocates its
// own slot. The first slot then answers to nothing -- which is what has to be
// reported, because showing two live variables called `x` when one of them can
// no longer be reached from any source line is worse than showing one.
func TestASlotWhoseNameWasTakenOverReportsNoName(t *testing.T) {
	src := "let f = fn() {\n\tlet x = 1;\n\tlet x = 2;\n\treturn x;\n};\nf();\n"

	fn := onlyFunction(t, compileWithPositions(t, src))

	if fn.NumLocals != 2 {
		t.Fatalf("the two declarations took %d slots, want 2", fn.NumLocals)
	}
	if fn.LocalNames[0] != "" {
		t.Errorf("the shadowed slot is named %q, want no name", fn.LocalNames[0])
	}
	if fn.LocalNames[1] != "x" {
		t.Errorf("the live slot is named %q, want \"x\"", fn.LocalNames[1])
	}
}

func TestGlobalSlotNamesNameEveryGlobal(t *testing.T) {
	src := "let first = 1;\nlet second = 2;\nlet third = first + second;\n"

	bytecode := compileWithPositions(t, src)

	want := []string{"first", "second", "third"}
	if !reflect.DeepEqual(bytecode.GlobalNames, want) {
		t.Fatalf("global slots are named %v, want %v", bytecode.GlobalNames, want)
	}
}

// DefineBuiltin hands out indices from the registry's own numbering, which has
// nothing to do with global slots. A builtin let through would overwrite the
// name of whichever global happens to hold that index -- and with several
// hundred builtins it would overwrite all of them.
func TestBuiltinsAreNotGlobalSlots(t *testing.T) {
	table := NewSymbolTable()
	table.DefineBuiltin(0, "len")
	table.DefineBuiltin(1, "putln")
	table.Define("mine")

	names := table.GlobalSlotNames()
	if !reflect.DeepEqual(names, []string{"mine"}) {
		t.Fatalf("global slots are named %v, want [mine]", names)
	}
}

// A name resolved out of an enclosing scope is a free variable in the inner
// table, held in a capture list rather than a frame slot. Counting it as a
// local would name a slot the frame does not have.
func TestCapturesAreNotLocalSlots(t *testing.T) {
	outer := NewSymbolTable()
	outer.Define("shared")

	inner := NewEnclosedSymbolTable(outer)
	inner.Define("own")
	if _, ok := inner.Resolve("shared"); !ok {
		t.Fatal("the enclosing binding did not resolve")
	}

	names := inner.LocalSlotNames()
	if !reflect.DeepEqual(names, []string{"own"}) {
		t.Fatalf("local slots are named %v, want [own]", names)
	}
	if outer.LocalSlotNames() != nil {
		t.Error("the root table reported locals; its definitions are globals")
	}
}

// The names travel in the artifact, so they have to survive the encoding that
// puts them there -- and an artifact compiled before they existed has to decode
// to "unknown" rather than to something that looks like an answer.
func TestNameTablesSurviveTheArtifact(t *testing.T) {
	src := "let scale = 2;\nlet f = fn(n) {\n\tlet doubled = n * scale;\n\treturn doubled;\n};\nf(1);\n"

	serialize.RegisterGobTypes()

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(compileWithPositions(t, src)); err != nil {
		t.Fatalf("encode: %s", err)
	}

	var decoded *ByteCode
	if err := gob.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatalf("decode: %s", err)
	}

	if !reflect.DeepEqual(decoded.GlobalNames, []string{"scale", "f"}) {
		t.Errorf("global names came back as %v", decoded.GlobalNames)
	}
	fn := onlyFunction(t, decoded)
	if !reflect.DeepEqual(fn.LocalNames, []string{"n", "doubled"}) {
		t.Errorf("local names came back as %v", fn.LocalNames)
	}
}

// debugFields lists what StripDebugInfo has to clear, and semanticFields what it
// must leave alone. Between them they must name every field of each struct: the
// test below fails on a field in neither list, so a field added later cannot
// reach a release artifact without someone deciding which half it belongs to.
// That decision is the whole of the debug-info policy, and it is exactly the
// decision a hurried patch skips.
var (
	bytecodeDebugFields = []string{
		"SourceFile", "SourceText", "LineTable", "MacroTable", "EndTable",
		"ModuleSpans", "GlobalNames",
	}
	bytecodeSemanticFields = []string{
		"Instructions", "Constants", "StructDefs", "EnumDefs", "LuaPatches",
		"Version", "BuiltinNames", "OpcodeMap",
	}
	functionDebugFields = []string{
		"Name", "Params", "LocalNames", "LineTable", "MacroTable", "EndTable",
	}
	functionSemanticFields = []string{
		"Instructions", "NumLocals", "NumParams", "CapturedLocals",
	}
)

func TestStripDebugInfoClearsEveryFieldClassifiedAsDebugInfo(t *testing.T) {
	src := "let scale = 2;\nlet f = fn(n) {\n\tlet doubled = n * scale;\n\treturn doubled;\n};\nf(1);\n"

	bytecode := compileWithPositions(t, src)
	fn := onlyFunction(t, bytecode)

	assertFieldsAccountedFor(t, reflect.TypeOf(ByteCode{}), bytecodeDebugFields, bytecodeSemanticFields)
	assertFieldsAccountedFor(t, reflect.TypeOf(object.CompiledFunction{}), functionDebugFields, functionSemanticFields)

	// Something has to be there before stripping, or an empty program would
	// pass this test without stripping anything at all.
	if len(bytecode.GlobalNames) == 0 || len(fn.LocalNames) == 0 {
		t.Fatal("nothing to strip: the program compiled without name tables")
	}

	bytecode.StripDebugInfo()

	assertFieldsAreZero(t, "ByteCode", reflect.ValueOf(*bytecode), bytecodeDebugFields)
	assertFieldsAreZero(t, "CompiledFunction", reflect.ValueOf(*fn), functionDebugFields)

	if len(bytecode.Instructions) == 0 {
		t.Error("stripping took the instructions with it")
	}
	if fn.NumLocals == 0 {
		t.Error("stripping took the slot count, which the VM needs to build the frame")
	}
}

func assertFieldsAccountedFor(t *testing.T, typ reflect.Type, debug, semantic []string) {
	t.Helper()

	known := make(map[string]bool, len(debug)+len(semantic))
	for _, name := range append(append([]string{}, debug...), semantic...) {
		known[name] = true
	}

	unclassified := make([]string, 0, 1)
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; !known[name] {
			unclassified = append(unclassified, name)
		}
	}

	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("%s has fields this test does not classify: %v. "+
			"Decide whether each is debug info -- if so add it to StripDebugInfo and to the debug list -- "+
			"or semantic, and add it to the semantic list.", typ.Name(), unclassified)
	}
}

func assertFieldsAreZero(t *testing.T, what string, value reflect.Value, fields []string) {
	t.Helper()

	for _, name := range fields {
		field := value.FieldByName(name)
		if !field.IsValid() {
			t.Errorf("%s has no field %s; the list is out of date", what, name)
			continue
		}
		if !field.IsZero() {
			t.Errorf("%s.%s survived stripping: %v", what, name, field.Interface())
		}
	}
}
