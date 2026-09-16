package serialize

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

// TestGobTypesCoversEveryObject reads the object package's source and asserts
// that every type implementing object.Object appears in GobTypes.
//
// This is the check that was missing. The three copies of the registration list
// drifted precisely because nothing connected them to the set of types that
// exist -- adding an object type compiled fine, passed the suite, and only
// failed later at an encode or decode. Reading the source rather than the
// binary is deliberate: reflection cannot enumerate the types in a package, and
// gob exposes no way to list what has been registered.
func TestGobTypesCoversEveryObject(t *testing.T) {
	registered := map[string]bool{}
	for _, v := range GobTypes() {
		rt := reflect.TypeOf(v)
		if rt.Kind() != reflect.Ptr {
			t.Fatalf("GobTypes entry %T is not a pointer; gob needs the pointer form", v)
		}
		elem := rt.Elem()
		if elem.PkgPath() != "mutant/object" {
			continue
		}
		if registered[elem.Name()] {
			t.Errorf("object.%s is listed twice in GobTypes", elem.Name())
		}
		registered[elem.Name()] = true
	}

	for _, name := range objectImplementations(t) {
		if !registered[name] {
			t.Errorf("object.%s implements object.Object but is not in GobTypes; "+
				"add it, or it will fail to encode the first time it reaches a "+
				"constant pool", name)
		}
		delete(registered, name)
	}

	for name := range registered {
		t.Errorf("GobTypes lists object.%s, which no longer implements object.Object", name)
	}
}

// TestGobTypesIncludesBuiltin pins the one entry that does not come from the
// object package. A compiled function can close over a builtin, so the wrapper
// crosses the boundary too.
func TestGobTypesIncludesBuiltin(t *testing.T) {
	for _, v := range GobTypes() {
		if reflect.TypeOf(v).Elem().PkgPath() == "mutant/builtin" {
			return
		}
	}
	t.Error("GobTypes does not register builtin.BuiltIn")
}

// TestRegisterGobTypesIsRepeatable guards the sync.Once: callers register from
// several entry points and must not have to coordinate.
func TestRegisterGobTypesIsRepeatable(t *testing.T) {
	RegisterGobTypes()
	RegisterGobTypes()
}

// objectImplementations returns the names of types in ../object that declare a
// pointer-receiver Type() ObjectType method, which is what makes a type an
// object.Object in practice -- every implementation declares it there.
func objectImplementations(t *testing.T) []string {
	t.Helper()

	skipTests := func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}

	pkgs, err := parser.ParseDir(token.NewFileSet(), "../object", skipTests, 0)
	if err != nil {
		t.Fatalf("parse ../object: %s", err)
	}

	var names []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "Type" || fn.Recv == nil || len(fn.Recv.List) != 1 {
					continue
				}
				star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				ident, ok := star.X.(*ast.Ident)
				if !ok {
					continue
				}
				if res := fn.Type.Results; res == nil || len(res.List) != 1 {
					continue
				}
				if id, ok := fn.Type.Results.List[0].Type.(*ast.Ident); !ok || id.Name != "ObjectType" {
					continue
				}
				names = append(names, ident.Name)
			}
		}
	}

	if len(names) == 0 {
		t.Fatal("found no object.Object implementations; the source scan is broken, not the list")
	}
	return names
}
