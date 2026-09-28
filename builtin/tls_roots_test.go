package builtin

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// TestTheLinuxCertificateLocationsAreGos holds linuxCertFiles and
// linuxCertDirectories to the lists crypto/x509 reads on Linux, in the
// toolchain that built this test: Mutant reads the system's store from them
// itself (M26-NET-010), and a store that moved in a new Go release must move
// here too. The order of the files matters, since the first that can be read
// is the only one read.
func TestTheLinuxCertificateLocationsAreGos(t *testing.T) {
	if build.Default.GOROOT == "" {
		t.Fatal("GOROOT is unknown, so crypto/x509's source cannot be read")
	}
	source := filepath.Join(build.Default.GOROOT, "src", "crypto", "x509", "root_linux.go")
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("read crypto/x509's Linux locations: %v", err)
	}
	lists := map[string][]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, element := range literal.Elts {
				if lit, ok := element.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if path, err := strconv.Unquote(lit.Value); err == nil {
						lists[value.Names[0].Name] = append(lists[value.Names[0].Name], path)
					}
				}
			}
		}
	}
	for name, ours := range map[string][]string{"certFiles": linuxCertFiles, "certDirectories": linuxCertDirectories} {
		if !slices.Equal(ours, lists[name]) {
			t.Errorf("crypto/x509's %s in %s is %q, and Mutant reads %q", name, source, lists[name], ours)
		}
	}
}
