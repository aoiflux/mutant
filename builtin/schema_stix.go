package builtin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"mutant/object"
)

// --- STIX 2.1 ---
//
// The other side of the interchange story. schema_events.go and
// schema_emitters.go carry *what happened* out to a timeline; this file carries
// *what to look for* out to the tools that hunt: a STIX bundle of Cyber-observable
// Objects, optionally with an Indicator beside each one.
//
// It does not take envelope events. An indicator is not an event -- it is a
// value an investigation decided was worth watching for -- so the input here is
// the hash `extract_iocs` produces, or one written by hand in the same shape.
//
// Everything an examiner hands to someone else has to be reproducible, and a
// bundle is the clearest case in the tree: run the same extraction over the same
// evidence twice and the two bundles must be the same bytes, or nobody can diff
// them and nobody can say what changed between two readings of one artifact.
// That is why every id here is derived from content rather than generated, and
// why the one field that cannot be -- the time an indicator was written down --
// is an option rather than a clock read.

// stixNamespace is the UUIDv5 namespace STIX 2.1 fixes for Cyber-observable
// Objects. It is not ours to choose: two tools that saw the same indicator must
// arrive at the same id, and that only works because both the namespace and the
// form of the hashed name are written down in the specification.
var stixNamespace = uuid.MustParse("00abedb4-aa42-466c-9c01-fed23315a9b7")

const stixSpecVersion = "2.1"

// stixKind is one indicator type: the key it arrives under, the Cyber-observable
// Object it becomes, and the path a pattern over it addresses.
type stixKind struct {
	key       string   // canonical key, and the type name stix_pattern takes
	aliases   []string // the other spellings the same thing arrives under
	sco       string   // the SCO type
	algorithm string   // the STIX hash algorithm name, for the file SCOs
	path      string   // the object path a STIX pattern addresses
	normalize func(string) string
	validate  func(string) string // says why a value is not one of these, or ""
}

// stixKinds is the whole mapping, in the order the bundle lists them.
//
// The canonical keys are `extract_iocs`'s own, so its output can be handed
// straight over; the aliases are what the same thing gets called when the hash
// is written by hand.
var stixKinds = []stixKind{
	{key: "ipv4", aliases: []string{"ipv4s", "ips"}, sco: "ipv4-addr", path: "ipv4-addr:value",
		normalize: stixCanonicalIP, validate: stixValidIPv4},
	{key: "ipv6", aliases: []string{"ipv6s"}, sco: "ipv6-addr", path: "ipv6-addr:value",
		normalize: stixCanonicalIP, validate: stixValidIPv6},
	{key: "domains", aliases: []string{"domain"}, sco: "domain-name", path: "domain-name:value",
		normalize: strings.ToLower, validate: stixValidDomain},
	{key: "urls", aliases: []string{"url"}, sco: "url", path: "url:value",
		validate: stixValidURL},
	{key: "emails", aliases: []string{"email"}, sco: "email-addr", path: "email-addr:value",
		normalize: strings.ToLower, validate: stixValidEmail},
	{key: "md5", sco: "file", algorithm: "MD5", path: `file:hashes.'MD5'`,
		normalize: strings.ToLower, validate: stixValidHex(32, "MD5")},
	{key: "sha1", aliases: []string{"sha-1"}, sco: "file", algorithm: "SHA-1", path: `file:hashes.'SHA-1'`,
		normalize: strings.ToLower, validate: stixValidHex(40, "SHA-1")},
	{key: "sha256", aliases: []string{"sha-256"}, sco: "file", algorithm: "SHA-256", path: `file:hashes.'SHA-256'`,
		normalize: strings.ToLower, validate: stixValidHex(64, "SHA-256")},
}

func stixKindByName(name string) (stixKind, bool) {
	wanted := strings.ToLower(strings.TrimSpace(name))
	for _, kind := range stixKinds {
		if kind.key == wanted {
			return kind, true
		}
		for _, alias := range kind.aliases {
			if alias == wanted {
				return kind, true
			}
		}
	}
	return stixKind{}, false
}

// stixKeyNames lists every key a hash may carry, for the error that reports one
// it may not. A key nobody accepts is refused by name rather than skipped: a
// bundle silently missing the hashes because they arrived under "hash" would
// look like a clean extraction.
func stixKeyNames() string {
	names := make([]string, 0, len(stixKinds)*2)
	for _, kind := range stixKinds {
		names = append(names, kind.key)
		names = append(names, kind.aliases...)
	}
	return strings.Join(names, ", ")
}

// --- what counts as one of these ---

func stixCanonicalIP(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func stixValidIPv4(value string) string {
	if ip := net.ParseIP(value); ip == nil || ip.To4() == nil {
		return "is not an IPv4 address"
	}
	return ""
}

func stixValidIPv6(value string) string {
	if ip := net.ParseIP(value); ip == nil || ip.To4() != nil {
		return "is not an IPv6 address"
	}
	return ""
}

func stixValidDomain(value string) string {
	if strings.ContainsAny(value, " \t/\\@") || !strings.Contains(value, ".") {
		return "is not a domain name"
	}
	return ""
}

func stixValidURL(value string) string {
	if !strings.Contains(value, "://") {
		return `is not a URL; a STIX url observable takes the scheme too, and a bare host belongs under "domains"`
	}
	return ""
}

func stixValidEmail(value string) string {
	at := strings.IndexByte(value, '@')
	if at <= 0 || at == len(value)-1 || strings.ContainsAny(value, " \t") {
		return "is not an email address"
	}
	return ""
}

// stixValidHex checks a digest's length exactly, because the length is the only
// thing that says which algorithm produced it. A 40-character value filed under
// sha256 would otherwise become a file observable whose id no other tool
// computes, and nothing downstream would ever match it.
func stixValidHex(length int, algorithm string) func(string) string {
	return func(value string) string {
		if len(value) != length {
			return fmt.Sprintf("is not a %s digest (%d hex characters, got %d)", algorithm, length, len(value))
		}
		for i := 0; i < len(value); i++ {
			c := value[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return fmt.Sprintf("is not a %s digest (not hexadecimal)", algorithm)
			}
		}
		return ""
	}
}

// stixNormalize trims, normalizes and checks one value.
//
// Normalizing is not cosmetic here. A digest in upper case, a domain with a
// capital letter and an IPv6 address written the long way each hash to a
// different id than the same indicator written the ordinary way, and an id that
// nothing else arrives at is an indicator nothing else can correlate.
func stixNormalize(op string, kind stixKind, key, raw string) (string, *object.Error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", newError("%s: %s contains an empty value", op, key)
	}
	if kind.normalize != nil {
		value = kind.normalize(value)
	}
	if kind.validate != nil {
		if complaint := kind.validate(value); complaint != "" {
			return "", newError("%s: %q under %q %s", op, raw, key, complaint)
		}
	}
	return value, nil
}

// --- identity ---

// stixID derives an object id from the properties STIX says identify it.
//
// SCO ids are UUIDv5 over the canonical JSON of the ID contributing properties,
// so the same indicator is the same object wherever it is seen -- twice in one
// case, or here and in someone else's platform.
//
// The bundle and the indicators get v5 ids too, over their own content, which is
// a deliberate departure: the specification asks for v4 outside the observables.
// A v4 would be a fresh random id on every run, and two bundles built from the
// same evidence would then differ in every id they contain while describing
// exactly the same findings. Reproducible evidence is worth more here than a
// version nibble, and no consumer reads that nibble.
func stixID(objectType string, contributing map[string]any) (string, *object.Error) {
	canonical, errObj := stixCanonicalJSON(objectType, contributing)
	if errObj != nil {
		return "", errObj
	}
	return objectType + "--" + uuid.NewSHA1(stixNamespace, canonical).String(), nil
}

// stixCanonicalJSON renders the ID contributing properties the way RFC 8785
// asks: keys sorted, no insignificant whitespace, and -- the part that is easy
// to miss -- no HTML escaping. Go's json.Marshal replaces an ampersand with
// an escape sequence by default, which would quietly give a URL observable a
// different id here than every other STIX producer computes for the same URL.
func stixCanonicalJSON(objectType string, value map[string]any) ([]byte, *object.Error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, newError("stix: cannot derive an id for %s: %s", objectType, err.Error())
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// --- the objects ---

// stixObservable builds the Cyber-observable Object for one value, and the id
// STIX derives from it.
//
// A hash becomes a file observable carrying that one algorithm. Three digests
// of one file therefore produce three observables rather than one file with
// three hashes, because nothing in a list of digests says they describe the same
// file -- and merging them on the guess that they do would invent a file that
// was never observed.
func stixObservable(kind stixKind, value string) (*object.Hash, string, *object.Error) {
	contributing := map[string]any{}
	observable := docTree{}
	if kind.algorithm != "" {
		contributing["hashes"] = map[string]any{kind.algorithm: value}
		observable.set("hashes."+kind.algorithm, stringObj(value))
	} else {
		contributing["value"] = value
		observable.set("value", stringObj(value))
	}

	id, errObj := stixID(kind.sco, contributing)
	if errObj != nil {
		return nil, "", errObj
	}
	observable.set("type", stringObj(kind.sco))
	observable.set("id", stringObj(id))
	return observable.hash(), id, nil
}

// stixIndicator builds the Indicator that says to watch for one observable.
//
// The id is derived from the pattern rather than from the pattern and the
// timestamps together, so re-stamping a case does not renumber its indicators.
func stixIndicator(value, pattern string, config stixConfig) (*object.Hash, string, *object.Error) {
	id, errObj := stixID("indicator", map[string]any{"pattern": pattern})
	if errObj != nil {
		return nil, "", errObj
	}

	indicator := docTree{}
	indicator.set("type", stringObj("indicator"))
	indicator.set("spec_version", stringObj(stixSpecVersion))
	indicator.set("id", stringObj(id))
	indicator.set("created", stringObj(config.stamp))
	indicator.set("modified", stringObj(config.stamp))
	indicator.set("name", stringObj(value))
	indicator.set("pattern", stringObj(pattern))
	indicator.set("pattern_type", stringObj("stix"))
	indicator.set("valid_from", stringObj(config.stamp))
	// "unknown" is the honest entry in the indicator-type vocabulary for a value
	// that was extracted from evidence. Something was written down in a document
	// and found again here; that it is malicious is a conclusion the extraction
	// never reached, and a bundle asserting `malicious-activity` would carry that
	// conclusion into every platform it is shared with.
	indicator.set("indicator_types", stringArrayObj([]string{"unknown"}))
	if config.hasTags {
		indicator.set("labels", stringArrayObj(config.tags))
	}
	return indicator.hash(), id, nil
}

// stixPatternFor renders the pattern that matches one observable.
func stixPatternFor(kind stixKind, value string) string {
	return "[" + kind.path + " = '" + stixEscape(value) + "']"
}

// stixEscape quotes a value for a STIX pattern. Only the backslash and the
// single quote are special. A Replacer substitutes in one pass, so a backslash
// it doubles is not then read again as the escape for a following quote.
var stixEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

func stixEscape(value string) string {
	return stixEscaper.Replace(value)
}

// --- stix_bundle ---

var stixBundleOptions = []string{"indicators", "created", "tags"}

// stixConfig is the options hash, resolved.
type stixConfig struct {
	indicators bool
	stamp      string
	tags       []string
	hasTags    bool
}

func readStixConfig(opts *formatOptions) (stixConfig, *object.Error) {
	var config stixConfig
	var errObj *object.Error

	if config.indicators, errObj = opts.boolean("indicators", false); errObj != nil {
		return config, errObj
	}
	if config.tags, config.hasTags, errObj = opts.stringList("tags"); errObj != nil {
		return config, errObj
	}
	// A Cyber-observable Object has no labels property, so tags with no
	// indicators to carry them would go nowhere. Saying so beats accepting the
	// option and producing a bundle the tags are simply missing from.
	if config.hasTags && !config.indicators {
		return config, newError(`stix_bundle: option "tags" needs indicators: true -- a STIX observable has no labels property, so a tag has nothing to attach to`)
	}

	created, errObj := opts.str("created", "")
	if errObj != nil {
		return config, errObj
	}
	if created == "" {
		// Only the indicators carry this, and only when they are asked for, so
		// the default bundle is still the same bytes every run. An examiner who
		// wants that of the indicators too pins `created` to when the case was
		// collected, which is the more accurate answer anyway.
		config.stamp = stixTimestamp(time.Now())
	} else {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(created))
		if err != nil {
			return config, newError(`stix_bundle: option "created" must be an RFC 3339 timestamp such as 2026-01-31T09:00:00Z, got %q`, created)
		}
		config.stamp = stixTimestamp(parsed)
	}
	return config, nil
}

// stixTimestamp renders a STIX timestamp: UTC, millisecond precision, and the
// literal Z rather than a numeric offset.
func stixTimestamp(at time.Time) string {
	return at.UTC().Format("2006-01-02T15:04:05.000Z")
}

// StixBundle renders indicators as a STIX 2.1 bundle.
// stix_bundle(iocs, opts?) -> (bundle, err).
func StixBundle(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	// extract_iocs hands back a bare hash, but anything that reached its input
	// through a parser carries a (value, err) pair, and passing that straight in
	// should report the parser's own failure rather than a complaint about the
	// shape of something that was never built.
	iocs, failure := SplitResult(args[0])
	if failure != nil {
		return resultAndError(nil, failure)
	}
	hash, ok := iocs.(*object.Hash)
	if !ok {
		kind := "nothing"
		if iocs != nil {
			kind = string(iocs.Type())
		}
		return resultAndError(nil, newError("argument 1 to `stix_bundle` must be a HASH of indicators, as extract_iocs returns, got %s", kind))
	}

	opts, errObj := formatOptionsArg("stix_bundle", args, 2, stixBundleOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	config, errObj := readStixConfig(opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := stixCheckKeys(hash); errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The kinds are walked in table order rather than in the order the hash
	// happens to iterate, so the bundle is grouped by type and identical between
	// runs. Within a key the caller's order is kept: extract_iocs sorts already,
	// and a hand-written list has an order someone chose.
	var observables, indicators []object.Object
	var ids []any
	seen := map[string]bool{}

	for _, kind := range stixKinds {
		for _, key := range append([]string{kind.key}, kind.aliases...) {
			present := hashValueByKey(hash, key)
			if present == nil {
				continue
			}
			values, errObj := stixValues("stix_bundle", key, present)
			if errObj != nil {
				return resultAndError(nil, errObj)
			}
			for _, raw := range values {
				value, errObj := stixNormalize("stix_bundle", kind, key, raw)
				if errObj != nil {
					return resultAndError(nil, errObj)
				}
				observable, id, errObj := stixObservable(kind, value)
				if errObj != nil {
					return resultAndError(nil, errObj)
				}
				if seen[id] {
					continue
				}
				seen[id] = true
				observables = append(observables, observable)
				ids = append(ids, id)

				if !config.indicators {
					continue
				}
				indicator, indicatorID, errObj := stixIndicator(value, stixPatternFor(kind, value), config)
				if errObj != nil {
					return resultAndError(nil, errObj)
				}
				if seen[indicatorID] {
					continue
				}
				seen[indicatorID] = true
				indicators = append(indicators, indicator)
				ids = append(ids, indicatorID)
			}
		}
	}

	// The bundle's own id is derived from what it contains, for the same reason
	// the objects' are: two runs over one body of evidence must produce one
	// bundle, and a random id would make them two.
	bundleID, errObj := stixID("bundle", map[string]any{"objects": ids})
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	bundle := docTree{}
	bundle.set("type", stringObj("bundle"))
	bundle.set("id", stringObj(bundleID))
	if len(observables)+len(indicators) > 0 {
		// An extraction that found nothing is a real result, and it produces a
		// bundle with no `objects` key rather than an empty one: a STIX list
		// property that is empty must be left out. Count the indicators before
		// bundling if a script needs to branch on that.
		bundle.set("objects", &object.Array{Elements: append(observables, indicators...)})
	}
	return resultAndError(bundle.hash(), nil)
}

// stixCheckKeys refuses a key no kind claims.
func stixCheckKeys(hash *object.Hash) *object.Error {
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			return newError("stix_bundle: indicator keys must be STRING, got %s", pair.Key.Type())
		}
		if _, known := stixKindByName(key.Value); !known {
			return newError("stix_bundle: unknown indicator type %q (accepted: %s)", key.Value, stixKeyNames())
		}
	}
	return nil
}

// stixValues reads one key's values. A single indicator may be written as itself
// rather than as a list of one.
func stixValues(op, key string, value object.Object) ([]string, *object.Error) {
	switch typed := value.(type) {
	case *object.String:
		return []string{typed.Value}, nil
	case *object.Array:
		out := make([]string, 0, len(typed.Elements))
		for i, element := range typed.Elements {
			text, ok := element.(*object.String)
			if !ok {
				return nil, newError("%s: %s[%d] must be a STRING, got %s", op, key, i, element.Type())
			}
			out = append(out, text.Value)
		}
		return out, nil
	}
	return nil, newError("%s: %q must be a STRING or an ARRAY of STRING, got %s", op, key, value.Type())
}

// --- stix_pattern ---

// StixPattern renders the STIX pattern that matches one indicator.
// stix_pattern(type, value) -> (pattern, err).
func StixPattern(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	name, errObj := requireStringArg("stix_pattern", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	raw, errObj := requireStringArg("stix_pattern", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	kind, known := stixKindByName(name)
	if !known {
		return resultAndError(nil, newError("stix_pattern: unknown indicator type %q (accepted: %s)", name, stixKeyNames()))
	}
	value, errObj := stixNormalize("stix_pattern", kind, kind.key, raw)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(stringObj(stixPatternFor(kind, value)), nil)
}
