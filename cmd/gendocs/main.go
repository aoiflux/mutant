// Command gendocs writes the two artifacts that describe the builtin registry
// to somebody outside it: docs/CAPABILITY_REFERENCE.md, and the builtin
// highlighting rule in the VS Code grammar.
//
// The reference has always claimed to be "generated from the builtin metadata",
// but until now nothing generated it, so its signatures and counts could drift
// away from builtin/metadata.go silently. This makes the claim true: every
// signature, parameter type, platform set, summary, and count in the document
// is read from builtin.Builtins and the metadata beside it.
//
// The grammar was the same problem in a different file, and had drifted
// further: 76 of 490 builtins highlighted. Its builtin alternation is now read
// from the same registry; see grammar.go for what is and is not generated.
//
//	go run ./cmd/gendocs           # rewrite both
//	go run ./cmd/gendocs -check    # fail if either is out of date
//
// The -check mode is the drift gate: it makes an out-of-date artifact a
// failure rather than something a reader has to notice.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"mutant/builtin"
)

const defaultOutputPath = "docs/CAPABILITY_REFERENCE.md"

func main() {
	output := flag.String("o", defaultOutputPath, "path to write the capability reference to")
	grammarOutput := flag.String("grammar", defaultGrammarPath, "path to the TextMate grammar whose builtin pattern is generated")
	check := flag.Bool("check", false, "report whether the generated files are up to date instead of writing them")
	flag.Parse()

	document, err := renderDocument()
	if err != nil {
		fail(err)
	}

	existingDocument, err := os.ReadFile(*output)
	if err != nil {
		fail(err)
	}
	document = matchExistingNewlines(document, existingDocument)

	// The grammar is rewritten from the copy on disk rather than rendered from
	// nothing, because only one rule in it is generated.
	existingGrammar, err := os.ReadFile(*grammarOutput)
	if err != nil {
		fail(err)
	}
	grammar, err := renderGrammar(string(existingGrammar))
	if err != nil {
		fail(err)
	}

	names, err := builtinNames()
	if err != nil {
		fail(err)
	}

	if *check {
		// Both artifacts are reported before exiting. Being told about one
		// stale file, regenerating, and then being told about the other is two
		// round trips where one will do.
		//
		// Compare with line endings normalised: the working tree may be checked
		// out with CRLF, which says nothing about whether the content drifted.
		stale := false
		if normalizeNewlines(string(existingDocument)) != normalizeNewlines(document) {
			fmt.Fprintf(os.Stderr, "gendocs: %s is out of date; run `go run ./cmd/gendocs`\n", *output)
			stale = true
		}
		if normalizeNewlines(string(existingGrammar)) != normalizeNewlines(grammar) {
			fmt.Fprintf(os.Stderr, "gendocs: %s is out of date; run `go run ./cmd/gendocs`\n", *grammarOutput)
			stale = true
		}
		if stale {
			os.Exit(1)
		}
		fmt.Printf("gendocs: %s is up to date (%d builtins, %d categories)\n",
			*output, len(builtin.Builtins), len(categorySections))
		fmt.Printf("gendocs: %s is up to date (%d builtins highlighted)\n",
			*grammarOutput, len(names))
		return
	}

	if err := os.WriteFile(*output, []byte(document), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("gendocs: wrote %s (%d builtins, %d categories)\n",
		*output, len(builtin.Builtins), len(categorySections))

	if err := os.WriteFile(*grammarOutput, []byte(grammar), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("gendocs: wrote %s (%d builtins highlighted)\n",
		*grammarOutput, len(names))
}

// fail reports a generator error and stops. Writing half the artifacts would
// leave the tree in a state where -check disagrees with itself.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "gendocs: %v\n", err)
	os.Exit(1)
}

// renderDocument builds the whole reference. It returns an error rather than
// emitting a partial document when the metadata and the section list disagree —
// a new capability category with no section, or a section naming a category no
// builtin belongs to — because either would silently drop builtins from the
// catalog.
func renderDocument() (string, error) {
	byCategory := make(map[string][]string, len(categorySections))
	for _, b := range builtin.Builtins {
		if b.Name == "" {
			continue
		}
		category := builtin.CapabilityCategory(b.Name)
		byCategory[category] = append(byCategory[category], b.Name)
	}

	described := make(map[string]struct{}, len(categorySections))
	for _, section := range categorySections {
		if _, duplicate := described[section.category]; duplicate {
			return "", fmt.Errorf("category %q is listed twice in categorySections", section.category)
		}
		described[section.category] = struct{}{}
		if len(byCategory[section.category]) == 0 {
			return "", fmt.Errorf("category %q has a section but no builtins", section.category)
		}
	}
	missing := make([]string, 0)
	for category := range byCategory {
		if _, ok := described[category]; !ok {
			missing = append(missing, category)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("capability categories with no section in cmd/gendocs/sections.go: %s",
			strings.Join(missing, ", "))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", documentTitle)
	fmt.Fprintf(&b, documentPreamble, len(builtin.Builtins), len(categorySections))
	writePlatformNotes(&b)
	b.WriteString("\n---\n")

	for _, section := range categorySections {
		names := byCategory[section.category]
		sort.Strings(names)

		fmt.Fprintf(&b, "\n## %s (%d)\n\n", section.heading, len(names))
		fmt.Fprintf(&b, "%s\n\n", section.blurb)
		b.WriteString("| Builtin | Platforms | Description |\n")
		b.WriteString("| --- | --- | --- |\n")
		for _, name := range names {
			b.WriteString(builtinRow(name))
		}
	}

	return b.String(), nil
}

// writePlatformNotes emits the platform-restricted table and the sentence about
// builtins that run everywhere but behave differently on one platform. Both are
// read from the metadata, so a newly restricted builtin appears here without
// anyone remembering to add it.
func writePlatformNotes(b *strings.Builder) {
	restricted := make([]string, 0, 4)
	noted := make([]string, 0, 4)
	for _, def := range builtin.Builtins {
		if def.Name == "" {
			continue
		}
		platforms, note := builtin.PlatformSupport(def.Name)
		switch {
		case len(platforms) > 0:
			restricted = append(restricted, def.Name)
		case note != "":
			noted = append(noted, def.Name)
		}
	}
	sort.Strings(restricted)
	sort.Strings(noted)

	b.WriteString("\n| Builtin | Platforms | Note |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, name := range restricted {
		platforms, note := builtin.PlatformSupport(name)
		if note == "" {
			note = "fails honestly on other platforms"
		}
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", name, strings.Join(platforms, ", "), escapeTableCell(note))
	}

	if len(noted) == 0 {
		return
	}
	quoted := make([]string, 0, len(noted))
	for _, name := range noted {
		quoted = append(quoted, "`"+name+"`")
	}
	fmt.Fprintf(b, "\n%s work on all platforms but have platform-specific behavior in one path; hover in the editor shows the note.\n",
		joinWithAnd(quoted))
}

// builtinRow renders one table row: the typed signature, the platforms the
// builtin works on, and its one-line summary.
func builtinRow(name string) string {
	signature, _, ok := builtin.TypedSignature(name)
	if !ok {
		signature = name + "(...)"
	}

	platforms, _ := builtin.PlatformSupport(name)
	platformText := "all"
	if len(platforms) > 0 {
		platformText = strings.Join(platforms, ", ")
	}

	summary := ""
	if _, s, _, ok := builtin.TeachingDoc(name); ok {
		summary = s
	}

	return fmt.Sprintf("| `%s` | %s | %s |\n",
		escapeTableCell(signature), platformText, escapeTableCell(summary))
}

// escapeTableCell keeps a value from breaking out of its table cell. A pipe in
// prose (bodyfile's `MD5|name|inode|...` field list, for one) would otherwise
// start a new column, and an embedded newline would end the row.
func escapeTableCell(text string) string {
	text = strings.ReplaceAll(text, "\r\n", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "|", `\|`)
	return strings.TrimSpace(text)
}

func joinWithAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}

func normalizeNewlines(text string) string {
	return string(bytes.ReplaceAll([]byte(text), []byte("\r\n"), []byte("\n")))
}

// matchExistingNewlines gives a rendered document the line endings the file it
// is about to replace already had.
//
// The documents are built with "\n", and this tree is checked out with CRLF.
// Writing LF over a CRLF file turns a one-line regeneration into a whole-file
// rewrite that says nothing about the content, and leaves one file disagreeing
// with every other file beside it. The grammar rewrite preserves endings for
// free because it edits the document it was handed; this is the same guarantee
// for the reference, which is rendered from scratch.
func matchExistingNewlines(rendered string, existing []byte) string {
	if !bytes.Contains(existing, []byte("\r\n")) {
		return rendered
	}
	return strings.ReplaceAll(normalizeNewlines(rendered), "\n", "\r\n")
}
