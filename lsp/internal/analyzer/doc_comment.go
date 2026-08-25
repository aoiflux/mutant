package analyzer

import "strings"

// Doc-comment tags for user-defined functions.
//
// A builtin documents each parameter individually because its contracts live in
// Go. A user function had no way to do the same: its leading `//` block was
// shown verbatim as one paragraph, so "what is `host`?" could only be answered
// in prose the reader had to match up to the signature themselves.
//
// These two tags close that gap, and nothing else about the block changes. Lines
// that carry no tag stay the description, which is what every existing doc
// comment in the corpus is made of — so adding this changes no card that does
// not opt in.
//
//	// Normalises a hostname for comparison.
//	// @param host — the raw hostname, with or without a scheme
//	// @returns the lower-cased, trimmed host
//	let norm = fn(host) { return str_lower(str_trim(host)); };
type functionDoc struct {
	description string
	// params maps a parameter name to its documented text.
	params map[string]string
	// returns is the documented result, empty when untagged.
	returns string
}

// parseFunctionDoc splits a leading comment block into its description and tags.
func parseFunctionDoc(block string) functionDoc {
	doc := functionDoc{params: map[string]string{}}
	if strings.TrimSpace(block) == "" {
		return doc
	}

	var description []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "@param "):
			name, text := splitTag(strings.TrimPrefix(trimmed, "@param "))
			if name != "" {
				doc.params[name] = text
			}
		case strings.HasPrefix(trimmed, "@returns "):
			doc.returns = tagBody(strings.TrimPrefix(trimmed, "@returns "))
		case strings.HasPrefix(trimmed, "@return "):
			doc.returns = tagBody(strings.TrimPrefix(trimmed, "@return "))
		default:
			description = append(description, line)
		}
	}

	doc.description = strings.TrimSpace(strings.Join(description, "\n"))
	return doc
}

// splitTag reads `name — text`, `name - text`, `name: text`, or `name text`.
func splitTag(rest string) (string, string) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", ""
	}
	name, remainder, found := strings.Cut(rest, " ")
	if !found {
		return strings.TrimSuffix(name, ":"), ""
	}
	return strings.TrimSuffix(name, ":"), tagBody(remainder)
}

// tagBody strips the separator a writer may have put between a tag and its text,
// so `@returns — the host` and `@returns the host` read the same.
func tagBody(text string) string {
	text = strings.TrimSpace(text)
	for _, separator := range []string{"—", "--", "-", ":"} {
		if rest, found := strings.CutPrefix(text, separator); found {
			return strings.TrimSpace(rest)
		}
	}
	return text
}
