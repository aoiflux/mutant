package builtin

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"mutant/object"
)

// --- the normalized event envelope ---
//
// Every parser in this tree emits its own hash shape, and every interchange
// schema -- ECS, OCSF, Timesketch/plaso -- wants its own. Mapping each parser
// onto each schema directly is N x 3 tables that drift apart as either side
// grows. So there is one hop in between: a parser's entries normalize to a small
// fixed event vocabulary, and each schema is written once against that
// vocabulary. A new parser writes one source spec and reaches every schema; a
// new schema writes one emitter and reaches every parser.
//
// Normalization is additive, never lossy. `extra` carries the source entry
// verbatim, so nothing a parser found is discarded by passing through here --
// which matters, because a normalized view of evidence that quietly drops fields
// is a view an examiner cannot testify from.
//
// Two rules keep the output honest:
//
//   - An unknown field is omitted, not emitted empty. An empty string in a
//     forensic record reads as "the artifact recorded nothing here", and that is
//     usually a claim the parser never made.
//   - A zero or negative timestamp produces no event at all. These artifacts use
//     0 for "not recorded", and a supertimeline swamped with 1970 rows is worse
//     than a shorter one.

// eventTime names one timestamp an entry carries and says what that timestamp
// means. The description follows the plaso/Timesketch vocabulary, because
// reading a supertimeline is largely the act of asking which of a file's four
// times a given row is.
type eventTime struct {
	field   string // key in the source entry
	nsField string // companion key holding the sub-second fraction, if any
	desc    string // ts_desc: what this timestamp records
	format  string // timestamp format for normalizeTimestamp; "" means unix seconds
	array   bool   // the field holds an ARRAY of timestamps, one event each
}

// eventSource maps one artifact's entries onto the envelope.
type eventSource struct {
	kind       string
	entriesKey string // key holding the entry array; "" if the artifact is itself one entry
	category   string
	action     string
	times      []eventTime
	fields     map[string]string // envelope field <- entry field
	message    string            // "{field}" template, "{a|b}" for a fallback
	refine     func(entry *object.Hash, ev map[string]object.Object)
}

// eventZeroMeansAbsent lists the numeric envelope fields where 0 is "not
// recorded" rather than a value. "size" is deliberately not here: an empty file
// has a real size of zero.
var eventZeroMeansAbsent = map[string]bool{
	"pid": true, "src_port": true, "dst_port": true, "code": true,
}

var eventSources = map[string]*eventSource{
	"mft": {
		kind: "mft", entriesKey: "entries", category: "file",
		// Eight timestamps per record, and the $FILE_NAME set is called out
		// separately from $STANDARD_INFORMATION because the disagreement between
		// the two is the timestomping tell.
		times: []eventTime{
			{field: "si_created", nsField: "si_created_ns", desc: "Creation Time"},
			{field: "si_modified", nsField: "si_modified_ns", desc: "Content Modification Time"},
			{field: "si_mft_modified", nsField: "si_mft_modified_ns", desc: "Metadata Modification Time"},
			{field: "si_accessed", nsField: "si_accessed_ns", desc: "Last Access Time"},
			{field: "fn_created", nsField: "fn_created_ns", desc: "Creation Time ($FILE_NAME)"},
			{field: "fn_modified", nsField: "fn_modified_ns", desc: "Content Modification Time ($FILE_NAME)"},
			{field: "fn_mft_modified", nsField: "fn_mft_modified_ns", desc: "Metadata Modification Time ($FILE_NAME)"},
			{field: "fn_accessed", nsField: "fn_accessed_ns", desc: "Last Access Time ($FILE_NAME)"},
		},
		fields:  map[string]string{"path": "path", "file_name": "name", "size": "size"},
		message: "{path|name}",
	},
	"prefetch": {
		// A .pf is one artifact holding up to eight run times, so the artifact is
		// the entry and the timestamp field is an array.
		//
		// prefetch_parse renders the run times as ISO strings rather than unix
		// integers, which is why this is the one spec that names a format.
		kind: "prefetch", category: "execution", action: "run",
		times:   []eventTime{{field: "run_times", desc: "Last Time Executed", format: "iso", array: true}},
		fields:  map[string]string{"process": "executable", "file_name": "executable"},
		message: "{executable} was executed (run count {run_count})",
	},
	"evtx": {
		kind: "evtx", entriesKey: "records", category: "log",
		times:  []eventTime{{field: "timestamp", desc: "Recorded Time"}},
		fields: map[string]string{"code": "event_id", "provider": "provider", "host": "computer", "dataset": "channel"},
		refine: func(entry *object.Hash, ev map[string]object.Object) {
			if level, ok := hashValueByKey(entry, "level").(*object.Integer); ok {
				if severity := evtxLevelSeverity(level.Value); severity != "" {
					ev["severity"] = stringObj(severity)
				}
			}
		},
		message: "event {event_id} from {provider} on {computer} [{channel}]",
	},
	"lnk": {
		// The three FILETIMEs in a shell link's header are the target's, not the
		// link's, which is why the category is file rather than something shell.
		kind: "lnk", category: "file",
		times: []eventTime{
			{field: "creation_time", desc: "Creation Time"},
			{field: "write_time", desc: "Content Modification Time"},
			{field: "access_time", desc: "Last Access Time"},
		},
		fields:  map[string]string{"path": "local_base_path", "file_name": "name", "cmdline": "arguments"},
		message: "shell link to {local_base_path|relative_path} {arguments}",
	},
	"amcache": {
		// "execution" rather than "process": Amcache records that a program was
		// present on the host, which is evidence of execution but not proof of it.
		kind: "amcache", entriesKey: "entries", category: "execution", action: "present",
		times: []eventTime{{field: "last_write", desc: "Written Time"}},
		fields: map[string]string{
			"path": "path", "file_name": "name", "size": "size",
			"registry_path": "key", "hashes.sha1": "sha1",
		},
		message: "{path|name}",
	},
	"shimcache": {
		kind: "shimcache", entriesKey: "entries", category: "execution", action: "present",
		times:   []eventTime{{field: "last_modified", desc: "Content Modification Time"}},
		fields:  map[string]string{"path": "path"},
		message: "{path}",
	},
	"jumplist": {
		kind: "jumplist", entriesKey: "entries", category: "file", action: "open",
		times:   []eventTime{{field: "last_access", desc: "Last Access Time"}},
		fields:  map[string]string{"path": "target", "file_name": "name", "host": "hostname", "cmdline": "arguments"},
		message: "{target|name}",
	},
	"syslog": {
		kind: "syslog", entriesKey: "entries", category: "log",
		times:  []eventTime{{field: "ts", desc: "Recorded Time"}},
		fields: map[string]string{"host": "host", "process": "app_name", "pid": "pid"},
		refine: func(entry *object.Hash, ev map[string]object.Object) {
			ev["dataset"] = stringObj("syslog")
			// The entry's severity is the numeric syslog level; the envelope's is a
			// word, so that ECS and OCSF can each take their own scale from it
			// without the two disagreeing about which way the numbers run.
			if severity, ok := hashValueByKey(entry, "severity").(*object.Integer); ok {
				ev["severity"] = stringObj(syslogSeverityWord(severity.Value))
			}
		},
		message: "{app_name}: {message}",
	},
	"browser_history": {
		kind: "browser_history", entriesKey: "entries", category: "web", action: "visit",
		times:   []eventTime{{field: "last_visit", desc: "Last Visited Time"}},
		fields:  map[string]string{"url": "url", "dataset": "browser"},
		message: "{title} <{url}>",
	},
	"browser_cookies": {
		kind: "browser_cookies", entriesKey: "entries", category: "web", action: "cookie",
		times:   []eventTime{{field: "expires", desc: "Expiration Time"}},
		fields:  map[string]string{"host": "host", "dataset": "browser"},
		message: "cookie {name} for {host}",
	},
	"browser_downloads": {
		kind: "browser_downloads", entriesKey: "entries", category: "web", action: "download",
		times: []eventTime{
			{field: "start_time", desc: "Start Time"},
			{field: "end_time", desc: "End Time"},
		},
		fields:  map[string]string{"url": "url", "path": "target_path", "size": "bytes_total", "dataset": "browser"},
		message: "{url} -> {target_path}",
	},
	"bodyfile": {
		// bodyfile_parse and mactime both return a bare array, so there is no
		// entries key to name: the array is the entries.
		kind: "bodyfile", category: "file",
		times: []eventTime{
			{field: "crtime", desc: "Creation Time"},
			{field: "mtime", desc: "Content Modification Time"},
			{field: "ctime", desc: "Metadata Modification Time"},
			{field: "atime", desc: "Last Access Time"},
		},
		fields:  map[string]string{"path": "name", "size": "size", "hashes.md5": "md5"},
		message: "{name}",
	},
	"mactime": {
		// One row already stands for every time that fired at that instant, so the
		// description is read off the MACB flags rather than fixed by the spec.
		kind: "mactime", category: "file",
		times:   []eventTime{{field: "ts", desc: "Recorded Time"}},
		fields:  map[string]string{"path": "name", "size": "size", "hashes.md5": "md5"},
		message: "{macb} {name}",
		refine: func(entry *object.Hash, ev map[string]object.Object) {
			if macb, ok := hashValueByKey(entry, "macb").(*object.String); ok {
				if desc := macbTimeDescription(macb.Value); desc != "" {
					ev["ts_desc"] = stringObj(desc)
				}
			}
		},
	},
}

// evtxLevelSeverity maps a Windows event Level onto the envelope's severity
// vocabulary. Level 0 (LogAlways) asserts nothing about severity, so it maps to
// nothing rather than to "informational".
func evtxLevelSeverity(level int64) string {
	switch level {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	case 4:
		return "informational"
	case 5:
		return "low"
	default:
		return ""
	}
}

// syslogSeverityWord maps an RFC 5424 severity (0 emergency .. 7 debug) onto the
// envelope vocabulary. The two scales run opposite ways, which is the whole
// reason the envelope carries a word rather than a number.
func syslogSeverityWord(severity int64) string {
	switch severity {
	case 0:
		return "fatal"
	case 1, 2:
		return "critical"
	case 3:
		return "high"
	case 4:
		return "medium"
	case 5:
		return "low"
	case 6, 7:
		return "informational"
	default:
		return "unknown"
	}
}

// macbTimeDescription expands a mactime MACB flag string into the time
// descriptions it stands for, joined by "; " in MACB order.
func macbTimeDescription(macb string) string {
	descriptions := map[byte]string{
		'm': "Content Modification Time",
		'a': "Last Access Time",
		'c': "Metadata Modification Time",
		'b': "Creation Time",
	}
	parts := make([]string, 0, 4)
	for i := 0; i < len(macb); i++ {
		if desc, ok := descriptions[macb[i]]; ok {
			parts = append(parts, desc)
		}
	}
	return strings.Join(parts, "; ")
}

// EventsFrom normalizes a parsed artifact into envelope events.
// events_from(artifact, kind_or_mapping) -> (events, err).
func EventsFrom(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	// A parser returns (result, err), so accepting that pair directly lets
	// events_from(mft_parse(path), "mft") read the way it is meant to -- and
	// carries the parser's own failure out rather than reporting it here as a
	// problem with the shape of something that was never built.
	artifact, failure := SplitResult(args[0])
	if failure != nil {
		return resultAndError(nil, failure)
	}
	switch artifact.(type) {
	case *object.Hash, *object.Array:
	case nil:
		return resultAndError(nil, newError("argument 1 to `events_from` must be HASH or ARRAY, got nothing"))
	default:
		return resultAndError(nil, newError("argument 1 to `events_from` must be HASH or ARRAY, got %s", artifact.Type()))
	}

	source, errObj := resolveEventSource(args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	entries, errObj := eventEntries(artifact, source)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(&object.Array{Elements: buildEvents(source, entries)}, nil)
}

// EventKinds lists the source kinds events_from understands and what each one
// maps. event_kinds() -> array of descriptors.
func EventKinds(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}

	names := make([]string, 0, len(eventSources))
	for name := range eventSources {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]object.Object, 0, len(names))
	for _, name := range names {
		source := eventSources[name]

		times := make([]object.Object, 0, len(source.times))
		for _, spec := range source.times {
			format := spec.format
			if format == "" {
				format = "unix"
			}
			times = append(times, makeHashObject(map[string]object.Object{
				"field":  stringObj(spec.field),
				"desc":   stringObj(spec.desc),
				"format": stringObj(format),
				"array":  boolObj(spec.array),
			}))
		}

		fields := make([]string, 0, len(source.fields))
		for field := range source.fields {
			fields = append(fields, field)
		}

		out = append(out, makeHashObject(map[string]object.Object{
			"kind":        stringObj(source.kind),
			"category":    stringObj(source.category),
			"action":      stringObj(source.action),
			"entries_key": stringObj(source.entriesKey),
			"times":       &object.Array{Elements: times},
			"fields":      stringArrayObj(fields),
		}))
	}
	return &object.Array{Elements: out}
}

// resolveEventSource turns the second argument into a source spec: a STRING
// names one of the built-in kinds, a HASH describes an artifact this tree has
// never seen.
func resolveEventSource(arg object.Object) (*eventSource, *object.Error) {
	switch value := arg.(type) {
	case *object.String:
		source, ok := eventSources[strings.ToLower(strings.TrimSpace(value.Value))]
		if !ok {
			return nil, newError("events_from: unknown source kind %q. Call event_kinds() for the list, or pass a mapping hash", value.Value)
		}
		return source, nil
	case *object.Hash:
		return parseEventMapping(value)
	default:
		return nil, newError("argument 2 to `events_from` must be STRING or HASH, got %s", arg.Type())
	}
}

// parseEventMapping reads an explicit mapping, so an artifact with no built-in
// kind -- a parser written in Mutant, a CSV someone exported -- reaches the same
// schemas without waiting for a source spec to be added here.
func parseEventMapping(mapping *object.Hash) (*eventSource, *object.Error) {
	source := &eventSource{kind: "custom"}

	for _, field := range []struct {
		key    string
		target *string
	}{
		{"kind", &source.kind},
		{"category", &source.category},
		{"action", &source.action},
		{"message", &source.message},
		{"entries", &source.entriesKey},
	} {
		value := hashValueByKey(mapping, field.key)
		if value == nil {
			continue
		}
		text, ok := value.(*object.String)
		if !ok {
			return nil, newError("events_from: mapping %q must be a STRING, got %s", field.key, value.Type())
		}
		*field.target = text.Value
	}

	times, ok := hashValueByKey(mapping, "times").(*object.Array)
	if !ok || len(times.Elements) == 0 {
		return nil, newError("events_from: mapping needs a non-empty `times` array of {field, desc} hashes")
	}
	for i, element := range times.Elements {
		spec, errObj := parseEventTime(element, i)
		if errObj != nil {
			return nil, errObj
		}
		source.times = append(source.times, spec)
	}

	source.fields = map[string]string{}
	if fields, ok := hashValueByKey(mapping, "fields").(*object.Hash); ok {
		for _, pair := range fields.Pairs {
			name, ok := pair.Key.(*object.String)
			if !ok {
				return nil, newError("events_from: mapping `fields` keys must be STRING, got %s", pair.Key.Type())
			}
			from, ok := pair.Value.(*object.String)
			if !ok {
				return nil, newError("events_from: mapping field %q must name a source field as a STRING, got %s", name.Value, pair.Value.Type())
			}
			source.fields[name.Value] = from.Value
		}
	}
	return source, nil
}

func parseEventTime(element object.Object, index int) (eventTime, *object.Error) {
	spec, ok := element.(*object.Hash)
	if !ok {
		return eventTime{}, newError("events_from: mapping times[%d] must be a HASH, got %s", index, element.Type())
	}

	field, ok := hashValueByKey(spec, "field").(*object.String)
	if !ok || field.Value == "" {
		return eventTime{}, newError("events_from: mapping times[%d] needs a `field` naming the timestamp", index)
	}

	out := eventTime{field: field.Value, desc: "Recorded Time"}
	if desc, ok := hashValueByKey(spec, "desc").(*object.String); ok && desc.Value != "" {
		out.desc = desc.Value
	}
	if format, ok := hashValueByKey(spec, "format").(*object.String); ok {
		out.format = strings.ToLower(strings.TrimSpace(format.Value))
	}
	if ns, ok := hashValueByKey(spec, "ns_field").(*object.String); ok {
		out.nsField = ns.Value
	}
	if array, ok := hashValueByKey(spec, "array").(*object.Boolean); ok {
		out.array = array.Value
	}
	return out, nil
}

// eventEntries finds the rows inside an artifact. An ARRAY is already the rows.
// A HASH is either the container the parser returned, named by entriesKey, or --
// for the single-record artifacts, a .pf and a .lnk -- the row itself.
func eventEntries(artifact object.Object, source *eventSource) ([]*object.Hash, *object.Error) {
	switch value := artifact.(type) {
	case *object.Array:
		entries := make([]*object.Hash, 0, len(value.Elements))
		for i, element := range value.Elements {
			entry, ok := element.(*object.Hash)
			if !ok {
				return nil, newError("events_from: entry %d must be a HASH, got %s", i, element.Type())
			}
			entries = append(entries, entry)
		}
		return entries, nil

	case *object.Hash:
		if source.entriesKey == "" {
			return []*object.Hash{value}, nil
		}
		held := hashValueByKey(value, source.entriesKey)
		if held == nil {
			return nil, newError("events_from: kind %q expects the artifact to carry %q; pass the parser's result hash or an array of entries",
				source.kind, source.entriesKey)
		}
		rows, ok := held.(*object.Array)
		if !ok {
			return nil, newError("events_from: %q in the artifact must be an ARRAY, got %s", source.entriesKey, held.Type())
		}
		return eventEntries(rows, source)

	default:
		return nil, newError("argument 1 to `events_from` must be HASH or ARRAY, got %s", artifact.Type())
	}
}

func buildEvents(source *eventSource, entries []*object.Hash) []object.Object {
	out := make([]object.Object, 0, len(entries))
	for _, entry := range entries {
		for _, spec := range source.times {
			for _, stamp := range entryTimestamps(entry, spec) {
				if event := buildEvent(source, entry, spec, stamp.unix, stamp.ns); event != nil {
					out = append(out, event)
				}
			}
		}
	}
	return out
}

type eventStamp struct{ unix, ns int64 }

// entryTimestamps reads one time spec off an entry. A value that will not
// normalize yields no event rather than an error: forensic input is partial by
// nature, and one unreadable field in one row is not a reason to refuse the
// other ten thousand. The original value is still in `extra` either way.
func entryTimestamps(entry *object.Hash, spec eventTime) []eventStamp {
	value := hashValueByKey(entry, spec.field)
	if value == nil {
		return nil
	}

	format := spec.format
	if format == "" {
		format = "unix"
	}

	if spec.array {
		values, ok := value.(*object.Array)
		if !ok {
			return nil
		}
		stamps := make([]eventStamp, 0, len(values.Elements))
		for _, element := range values.Elements {
			if unix, _, _, err := normalizeTimestamp(element, format); err == nil {
				stamps = append(stamps, eventStamp{unix: unix})
			}
		}
		return stamps
	}

	unix, _, _, err := normalizeTimestamp(value, format)
	if err != nil {
		return nil
	}
	return []eventStamp{{unix: unix, ns: entryNanos(entry, spec.nsField)}}
}

func entryNanos(entry *object.Hash, field string) int64 {
	if field == "" {
		return 0
	}
	ns, ok := hashValueByKey(entry, field).(*object.Integer)
	if !ok || ns.Value < 0 || ns.Value >= int64(time.Second) {
		return 0
	}
	return ns.Value
}

func buildEvent(source *eventSource, entry *object.Hash, spec eventTime, unix, ns int64) object.Object {
	if unix <= 0 {
		return nil
	}

	event := map[string]object.Object{
		"ts":       intObj(unix),
		"ts_ms":    intObj(unix*1000 + ns/int64(time.Millisecond)),
		"ts_desc":  stringObj(spec.desc),
		"iso":      stringObj(eventISO(unix, ns)),
		"kind":     stringObj(source.kind),
		"category": stringObj(source.category),
		"extra":    entry,
	}
	if source.action != "" {
		event["action"] = stringObj(source.action)
	}

	hashes := map[string]object.Object{}
	for name, field := range source.fields {
		setEventField(event, hashes, name, hashValueByKey(entry, field))
	}
	if len(hashes) > 0 {
		event["hashes"] = makeHashObject(hashes)
	}

	if message := renderEventMessage(source.message, entry); message != "" {
		event["message"] = stringObj(message)
	}
	if source.refine != nil {
		source.refine(entry, event)
	}
	return makeHashObject(event)
}

// setEventField writes one mapped field, dropping the values that would be a
// claim the artifact never made. A name under "hashes." nests into the hashes
// sub-hash instead.
func setEventField(event, hashes map[string]object.Object, name string, value object.Object) {
	switch typed := value.(type) {
	case nil:
		return
	case *object.Null:
		return
	case *object.String:
		if typed.Value == "" {
			return
		}
	case *object.Integer:
		if typed.Value == 0 && eventZeroMeansAbsent[name] {
			return
		}
	}

	if nested, ok := strings.CutPrefix(name, "hashes."); ok {
		hashes[nested] = value
		return
	}
	event[name] = value
}

func eventISO(unix, ns int64) string {
	moment := time.Unix(unix, ns).UTC()
	if ns == 0 {
		return moment.Format(time.RFC3339)
	}
	return moment.Format(time.RFC3339Nano)
}

// renderEventMessage fills a "{field}" template from the source entry. "{a|b}"
// takes the first of the two that has a value, which is how a record with no
// reconstructed path still reads as something.
//
// The result is a human-readable summary, not data -- the values are in `extra`
// verbatim -- so runs of whitespace left behind by a field the entry did not
// carry are collapsed rather than preserved.
func renderEventMessage(template string, entry *object.Hash) string {
	if template == "" {
		return ""
	}

	var out strings.Builder
	for {
		open := strings.IndexByte(template, '{')
		if open < 0 {
			out.WriteString(template)
			break
		}
		end := strings.IndexByte(template[open:], '}')
		if end < 0 {
			out.WriteString(template)
			break
		}
		end += open

		out.WriteString(template[:open])
		out.WriteString(firstEntryFieldText(entry, strings.Split(template[open+1:end], "|")))
		template = template[end+1:]
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

func firstEntryFieldText(entry *object.Hash, names []string) string {
	for _, name := range names {
		if text := entryFieldText(hashValueByKey(entry, strings.TrimSpace(name))); text != "" {
			return text
		}
	}
	return ""
}

func entryFieldText(value object.Object) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case *object.Null:
		return ""
	case *object.String:
		return typed.Value
	case *object.Integer:
		return strconv.FormatInt(typed.Value, 10)
	case *object.Float:
		return strconv.FormatFloat(typed.Value, 'g', -1, 64)
	case *object.Boolean:
		return strconv.FormatBool(typed.Value)
	default:
		return typed.Inspect()
	}
}
