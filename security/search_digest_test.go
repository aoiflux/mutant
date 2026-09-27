package security

import (
	"bytes"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// A pattern digest confirms a guess only to a holder of the case key: the same
// pattern under the same key is the same digest, under another case's key it
// is a different one, and it is never the bare SHA-256 anybody could compute.
func TestASearchPatternDigestIsKeyedToTheCase(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, KeySize)
	second := bytes.Repeat([]byte{0x22}, KeySize)
	pattern := []byte("finance@example.org")

	a, err := SearchPatternDigest(first, pattern)
	if err != nil {
		t.Fatal(err)
	}
	again, err := SearchPatternDigest(first, pattern)
	if err != nil {
		t.Fatal(err)
	}
	if a != again {
		t.Fatal("one pattern under one case key gave two digests, so a timeline could not be checked against it")
	}
	other, err := SearchPatternDigest(second, pattern)
	if err != nil {
		t.Fatal(err)
	}
	if a == other {
		t.Fatal("two case keys gave one digest, so it is not keyed to the case at all")
	}
	if bare := sha256.Sum256(pattern); a == bare {
		t.Fatal("the digest is the bare SHA-256 of the pattern, which confirms any guess to anyone")
	}
	neighbour, err := SearchPatternDigest(first, []byte("finance@example.orG"))
	if err != nil {
		t.Fatal(err)
	}
	if a == neighbour {
		t.Fatal("two patterns gave one digest")
	}

	if _, err := SearchPatternDigest(first[:KeySize-1], pattern); err == nil {
		t.Fatal("a short case key was accepted")
	}

	// Its key is its own: a pattern spelt as a class tag's message is not that
	// class's tag, as it would be if the digest were keyed under the class-tag
	// key, which the case's manifest publishes tags under.
	tagKey, err := ClassTagKey(first)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := TagForClass(tagKey, "restricted")
	if err != nil {
		t.Fatal(err)
	}
	spelt, err := SearchPatternDigest(first, []byte(ClassTagDomain+"restricted"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spelt[:], tag[:]) {
		t.Fatal("a pattern digest is a class tag: the two are keyed under one key")
	}
}

// Every HKDF purpose string in this package is its own: none repeats another,
// and none is a prefix of another -- two derivations append "|" and more to
// theirs, so a prefix would let one purpose's input be spelt as another's.
// Read from the source, so a purpose added later is held to it too.
func TestEveryHKDFPurposeHasItsOwnInfo(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	infos := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range value.Names {
					if !strings.HasPrefix(ident.Name, "HKDFInfo") || i >= len(value.Values) {
						continue
					}
					lit, ok := value.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s is not a string literal, so this test cannot read it", ident.Name)
						continue
					}
					text, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					infos[ident.Name] = text
				}
			}
		}
	}
	if _, found := infos["HKDFInfoSearchPattern"]; !found || len(infos) < 2 {
		t.Fatalf("read %d purposes and not HKDFInfoSearchPattern among them: %v", len(infos), infos)
	}
	for name, info := range infos {
		for otherName, other := range infos {
			if name != otherName && strings.HasPrefix(other, info) {
				t.Errorf("%s (%q) is a prefix of %s (%q)", name, info, otherName, other)
			}
		}
	}
	t.Logf("%d HKDF purposes, each its own", len(infos))
}
