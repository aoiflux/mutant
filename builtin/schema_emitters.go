package builtin

import (
	"strconv"
	"strings"

	"mutant/global"
	"mutant/object"
)

// --- the schema emitters ---
//
// The second hop. schema_events.go normalizes any parsed artifact into one event
// vocabulary; this file writes that vocabulary out in the three shapes the rest
// of the world reads: Elastic Common Schema, OCSF, and the plaso-flavoured JSONL
// Timesketch ingests. Each emitter is written against the envelope and knows
// nothing about which parser produced it, which is what keeps the cost at N + 3
// mappings rather than N x 3.
//
// The envelope's rules carry through. A field the artifact did not record is
// absent from the document rather than present and empty, because an empty
// string in a forensic record reads as a claim that the source recorded nothing
// there. The verbatim source entry travels with every document -- under
// `mutant.extra` in ECS, `unmapped.extra` in OCSF, `extra` in Timesketch -- so a
// row in a SIEM is still traceable back to the bytes the parser read.
//
// Where a schema requires a field the evidence does not supply, the emitters say
// "unknown" in that schema's own vocabulary rather than guessing: OCSF severity
// 0, OCSF file type 0. A guess is indistinguishable from a finding once it is
// indexed.

// docTree builds a nested document from dotted paths. ECS and OCSF both nest --
// `event.category`, `metadata.product.name`, `actor.process.pid` -- and spelling
// the nesting out at each assignment is what stops a mapping from reading as a
// mapping.
//
// A nil value is dropped rather than written, so "omit what the artifact did not
// record" is how the writer behaves by default instead of a check repeated at
// every call site. An interior node that ends up empty is dropped too: a
// document with `"file": {}` in it asserts there was a file.
type docTree map[string]any

func (d docTree) set(path string, value object.Object) {
	if value == nil {
		return
	}
	node := d
	for {
		dot := strings.IndexByte(path, '.')
		if dot < 0 {
			break
		}
		child, ok := node[path[:dot]].(docTree)
		if !ok {
			child = docTree{}
			node[path[:dot]] = child
		}
		node = child
		path = path[dot+1:]
	}
	node[path] = value
}

func (d docTree) hash() *object.Hash {
	values := make(map[string]object.Object, len(d))
	for key, value := range d {
		switch typed := value.(type) {
		case docTree:
			if len(typed) == 0 {
				continue
			}
			values[key] = typed.hash()
		case object.Object:
			values[key] = typed
		}
	}
	return makeHashObject(values)
}

// --- reading the envelope ---

func eventStr(event *object.Hash, key string) string {
	text, ok := hashValueByKey(event, key).(*object.String)
	if !ok {
		return ""
	}
	return text.Value
}

func eventStrObj(event *object.Hash, key string) object.Object {
	if text := eventStr(event, key); text != "" {
		return stringObj(text)
	}
	return nil
}

func eventInt(event *object.Hash, key string) (int64, bool) {
	value, ok := hashValueByKey(event, key).(*object.Integer)
	if !ok {
		return 0, false
	}
	return value.Value, true
}

func eventIntObj(event *object.Hash, key string) object.Object {
	value, ok := hashValueByKey(event, key).(*object.Integer)
	if !ok {
		return nil
	}
	return value
}

func eventHash(event *object.Hash, key string) *object.Hash {
	nested, ok := hashValueByKey(event, key).(*object.Hash)
	if !ok {
		return nil
	}
	return nested
}

// firstText returns the first of its arguments that has a value. It is how an
// option supplies what an artifact structurally cannot record: an $MFT knows
// every path on the volume and nothing at all about which host the volume came
// out of, and the examiner who mounted the image does.
func firstText(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// pathBase takes the last component of a path under either separator, because
// the paths here come off Windows images as often as not.
func pathBase(path string) string {
	if index := strings.LastIndexAny(path, `/\`); index >= 0 {
		return path[index+1:]
	}
	return path
}

// --- the shared entry point ---

// emitOptions are accepted by all three emitters, so switching schemas does not
// mean relearning the knobs.
var emitOptions = []string{"host", "user", "tags", "extra"}

// emitEvents applies one emitter to a single envelope event or to a whole
// timeline, returning the same shape it was handed.
//
// A timeline is the normal case -- one $MFT is hundreds of thousands of events
// -- and making the caller map over it row by row would mean a (value, err) pair
// per row and a decision about what to do with each one.
func emitEvents(op string, args []object.Object, allowed []string, settingKey string,
	emit func(*object.Hash, emitConfig) (object.Object, *object.Error)) object.Object {

	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	switch args[0].(type) {
	case *object.Hash, *object.Array:
	default:
		return resultAndError(nil, newError("argument 1 to `%s` must be HASH or ARRAY, got %s", op, args[0].Type()))
	}

	opts, errObj := formatOptionsArg(op, args, 2, allowed...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// The options are read once, before any event is looked at. A mistyped
	// option should be reported as one whatever the events turn out to be, and a
	// timeline is no reason to re-read the same hash a hundred thousand times.
	config, errObj := readEmitConfig(opts, settingKey)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	if event, ok := args[0].(*object.Hash); ok {
		doc, errObj := emit(event, config)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		return resultAndError(doc, nil)
	}

	events := args[0].(*object.Array)
	out := make([]object.Object, 0, len(events.Elements))
	for i, element := range events.Elements {
		event, ok := element.(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("%s: event %d must be a HASH, got %s", op, i, element.Type()))
		}
		doc, errObj := emit(event, config)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		out = append(out, doc)
	}
	return resultAndError(&object.Array{Elements: out}, nil)
}

// requireEnvelope refuses a hash that did not come out of events_from.
//
// The alternative is worse than an error. A raw parser entry has no `ts` and no
// `iso`, so it would emit a document with no timestamp and every mapped field
// missing -- which looks like a real document, indexes like one, and is not one.
func requireEnvelope(op string, event *object.Hash) *object.Error {
	if hashValueByKey(event, "ts") != nil && hashValueByKey(event, "iso") != nil {
		return nil
	}
	return newError("%s: expects an event from events_from(), which carries `ts`, `ts_ms`, `ts_desc` and `iso`; this hash does not. Normalize the artifact first: events_from(artifact, kind)", op)
}

// emitConfig is the options hash, resolved. `setting` is the one option each
// schema adds on top of the shared four: ecs.version, metadata.version, or a
// data_type overriding the plaso table. It is empty when unset, and each emitter
// supplies its own default.
type emitConfig struct {
	host    string
	user    string
	tags    []string
	hasTags bool
	extra   bool
	setting string
}

func readEmitConfig(opts *formatOptions, settingKey string) (emitConfig, *object.Error) {
	var config emitConfig
	var errObj *object.Error

	if config.host, errObj = opts.str("host", ""); errObj != nil {
		return config, errObj
	}
	if config.user, errObj = opts.str("user", ""); errObj != nil {
		return config, errObj
	}
	if config.extra, errObj = opts.boolean("extra", true); errObj != nil {
		return config, errObj
	}
	if config.tags, config.hasTags, errObj = opts.stringList("tags"); errObj != nil {
		return config, errObj
	}
	if config.setting, errObj = opts.str(settingKey, ""); errObj != nil {
		return config, errObj
	}
	return config, nil
}

// --- Elastic Common Schema ---

const ecsDefaultVersion = "8.11.0"

var ecsEmitOptions = append(append([]string{}, emitOptions...), "version")

// ecsCategories maps an envelope category onto ECS event.category.
//
// `log` is deliberately absent: ECS has no log category, and every value it does
// have would be a claim about what the log recorded. A document with no
// event.category is ordinary ECS; one filed under the wrong category is not.
var ecsCategories = map[string]string{
	"file":           "file",
	"execution":      "process",
	"process":        "process",
	"web":            "web",
	"network":        "network",
	"dns":            "network",
	"registry":       "registry",
	"authentication": "authentication",
	"configuration":  "configuration",
	"email":          "email",
	"iam":            "iam",
	"malware":        "malware",
	"session":        "session",
	"driver":         "driver",
}

// EcsEvent renders envelope events as Elastic Common Schema documents.
// ecs_event(event_or_events, opts?) -> (document_or_documents, err).
func EcsEvent(args ...object.Object) object.Object {
	return emitEvents("ecs_event", args, ecsEmitOptions, "version", buildECSDocument)
}

func buildECSDocument(event *object.Hash, config emitConfig) (object.Object, *object.Error) {
	if errObj := requireEnvelope("ecs_event", event); errObj != nil {
		return nil, errObj
	}

	doc := docTree{}
	doc.set("@timestamp", eventStrObj(event, "iso"))
	doc.set("ecs.version", stringObj(firstText(config.setting, ecsDefaultVersion)))
	doc.set("message", eventStrObj(event, "message"))
	if config.hasTags {
		doc.set("tags", stringArrayObj(config.tags))
	}

	doc.set("event.kind", stringObj("event"))
	doc.set("event.module", eventStrObj(event, "kind"))
	doc.set("event.dataset", eventStrObj(event, "dataset"))
	doc.set("event.action", eventStrObj(event, "action"))
	doc.set("event.provider", eventStrObj(event, "provider"))
	if category := ecsCategories[eventStr(event, "category")]; category != "" {
		doc.set("event.category", stringArrayObj([]string{category}))
	}
	doc.set("event.type", stringArrayObj([]string{
		ecsEventType(eventStr(event, "action"), eventStr(event, "ts_desc")),
	}))
	if code, ok := eventInt(event, "code"); ok {
		// ECS event.code is a keyword. An event id identifies a kind of event
		// rather than counting anything, and indexing it as a number invites
		// range queries over it that mean nothing.
		doc.set("event.code", stringObj(strconv.FormatInt(code, 10)))
	}
	if severity := eventStr(event, "severity"); severity != "" {
		doc.set("log.level", stringObj(severity))
		if code, ok := ecsSeverityCode(severity); ok {
			doc.set("event.severity", intObj(code))
		}
	}

	if host := firstText(eventStr(event, "host"), config.host); host != "" {
		doc.set("host.name", stringObj(host))
	}
	if user := firstText(eventStr(event, "user"), config.user); user != "" {
		doc.set("user.name", stringObj(user))
	}

	doc.set("file.path", eventStrObj(event, "path"))
	doc.set("file.name", eventStrObj(event, "file_name"))
	doc.set("file.size", eventIntObj(event, "size"))
	if hashes := eventHash(event, "hashes"); hashes != nil {
		for _, algorithm := range []string{"md5", "sha1", "sha256"} {
			doc.set("file.hash."+algorithm, eventStrObj(hashes, algorithm))
		}
	}

	doc.set("process.name", eventStrObj(event, "process"))
	doc.set("process.pid", eventIntObj(event, "pid"))
	doc.set("process.command_line", eventStrObj(event, "cmdline"))
	doc.set("source.ip", eventStrObj(event, "src_ip"))
	doc.set("source.port", eventIntObj(event, "src_port"))
	doc.set("destination.ip", eventStrObj(event, "dst_ip"))
	doc.set("destination.port", eventIntObj(event, "dst_port"))
	doc.set("url.full", eventStrObj(event, "url"))
	doc.set("registry.path", eventStrObj(event, "registry_path"))

	// ECS has no field for what a timestamp means, and without one the four
	// documents an $MFT record produces are the same document four times. It
	// goes in a custom top-level namespace, which is what ECS says to do with
	// fields it does not define.
	doc.set("mutant.kind", eventStrObj(event, "kind"))
	doc.set("mutant.category", eventStrObj(event, "category"))
	doc.set("mutant.ts_desc", eventStrObj(event, "ts_desc"))
	if config.extra {
		if entry := eventHash(event, "extra"); entry != nil {
			doc.set("mutant.extra", entry)
		}
	}
	return doc.hash(), nil
}

// ecsEventType picks the ECS subcategory. It reads the timestamp description
// before the action, because the envelope has already split one record into one
// event per timestamp: what that timestamp records is what the event is.
func ecsEventType(action, description string) string {
	switch strings.TrimSuffix(strings.TrimSpace(description), " ($FILE_NAME)") {
	case "Creation Time":
		return "creation"
	case "Content Modification Time", "Metadata Modification Time", "Written Time":
		return "change"
	case "Last Access Time", "Last Visited Time":
		return "access"
	}
	switch action {
	case "run":
		return "start"
	case "open", "visit", "download":
		return "access"
	case "create":
		return "creation"
	case "delete":
		return "deletion"
	}
	// "info" is ECS's own word for a document that records a state rather than
	// a transition, which is what an artifact of presence is.
	return "info"
}

// ecsSeverityCode maps the envelope's severity word onto a number for
// event.severity.
//
// The scale runs the syslog way -- 0 is the worst -- because that is the scale
// ECS's own example uses, event.severity 7 beside log.level "information", and
// because a good share of what reaches here was syslog to begin with. The word
// is emitted too, as log.level, so nothing depends on reading the direction
// right.
func ecsSeverityCode(severity string) (int64, bool) {
	switch severity {
	case "fatal":
		return 0, true
	case "critical":
		return 2, true
	case "high":
		return 3, true
	case "medium":
		return 4, true
	case "low":
		return 5, true
	case "informational":
		return 6, true
	}
	// "unknown" asserts nothing, and there is no number for that.
	return 0, false
}

// --- OCSF ---

const ocsfDefaultVersion = "1.1.0"

var ocsfEmitOptions = append(append([]string{}, emitOptions...), "version")

type ocsfClass struct {
	classUID     int64
	className    string
	categoryUID  int64
	categoryName string
}

// ocsfClasses maps an envelope category onto an OCSF class.
//
// An OCSF class describes activity a sensor observed. A forensic artifact is a
// record that activity happened, which is not the same claim -- so a class here
// says where the record belongs, not that anything watched it happen. Where no
// class fits, the answer is the Base Event rather than the nearest class: an
// analyst's rule on class_uid 1007 should not fire on an Amcache row.
//
// Two absences are deliberate. `execution` is not here, because Amcache and
// Shimcache record that a program was present, which Process Activity would
// state as a process having run. `registry` is not here, because the class that
// fits it lives in the `win` extension, and an extension uid means nothing to a
// consumer that has not loaded that extension.
var ocsfClasses = map[string]ocsfClass{
	"file":           {1001, "File System Activity", 1, "System Activity"},
	"process":        {1007, "Process Activity", 1, "System Activity"},
	"module":         {1005, "Module Activity", 1, "System Activity"},
	"scheduled_job":  {1006, "Scheduled Job Activity", 1, "System Activity"},
	"authentication": {3002, "Authentication", 3, "Identity & Access Management"},
	"network":        {4001, "Network Activity", 4, "Network Activity"},
	"dns":            {4003, "DNS Activity", 4, "Network Activity"},
	"email":          {4009, "Email Activity", 4, "Network Activity"},
	"web":            {6001, "Web Resources Activity", 6, "Application Activity"},
}

var ocsfBaseEvent = ocsfClass{0, "Base Event", 0, "Uncategorized"}

var ocsfSeverityIDs = map[string]int64{
	"unknown": 0, "informational": 1, "low": 2, "medium": 3,
	"high": 4, "critical": 5, "fatal": 6,
}

var ocsfSeverityNames = map[int64]string{
	0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
	4: "High", 5: "Critical", 6: "Fatal",
}

var ocsfHashAlgorithms = []struct {
	field string
	name  string
	id    int64
}{
	{"md5", "MD5", 1},
	{"sha1", "SHA-1", 2},
	{"sha256", "SHA-256", 3},
}

// OcsfEvent renders envelope events as OCSF events.
// ocsf_event(event_or_events, opts?) -> (event_or_events, err).
func OcsfEvent(args ...object.Object) object.Object {
	return emitEvents("ocsf_event", args, ocsfEmitOptions, "version", buildOCSFEvent)
}

func buildOCSFEvent(event *object.Hash, config emitConfig) (object.Object, *object.Error) {
	if errObj := requireEnvelope("ocsf_event", event); errObj != nil {
		return nil, errObj
	}

	class, ok := ocsfClasses[eventStr(event, "category")]
	if !ok {
		class = ocsfBaseEvent
	}
	activityID, activityName := ocsfActivity(class, eventStr(event, "action"), eventStr(event, "ts_desc"))

	doc := docTree{}
	doc.set("activity_id", intObj(activityID))
	doc.set("activity_name", stringObj(activityName))
	doc.set("category_uid", intObj(class.categoryUID))
	doc.set("category_name", stringObj(class.categoryName))
	doc.set("class_uid", intObj(class.classUID))
	doc.set("class_name", stringObj(class.className))
	doc.set("type_uid", intObj(class.classUID*100+activityID))
	doc.set("type_name", stringObj(class.className+": "+activityName))

	// OCSF counts milliseconds.
	if ms, ok := eventInt(event, "ts_ms"); ok {
		doc.set("time", intObj(ms))
	} else if seconds, ok := eventInt(event, "ts"); ok {
		doc.set("time", intObj(seconds*1000))
	}

	// severity_id is required, and the envelope's vocabulary was chosen to land
	// on it exactly. An event with no severity is 0 Unknown, which is OCSF's own
	// way of saying the source did not report one.
	severityID := ocsfSeverityIDs[eventStr(event, "severity")]
	doc.set("severity_id", intObj(severityID))
	doc.set("severity", stringObj(ocsfSeverityNames[severityID]))
	doc.set("message", eventStrObj(event, "message"))

	doc.set("metadata.version", stringObj(firstText(config.setting, ocsfDefaultVersion)))
	doc.set("metadata.product.name", stringObj("Mutant"))
	doc.set("metadata.product.vendor_name", stringObj("Mutant"))
	doc.set("metadata.product.version", stringObj(global.Version))
	doc.set("metadata.product.feature.name", eventStrObj(event, "kind"))
	doc.set("metadata.original_time", eventStrObj(event, "iso"))
	doc.set("metadata.log_name", eventStrObj(event, "dataset"))
	doc.set("metadata.log_provider", eventStrObj(event, "provider"))
	if code, ok := eventInt(event, "code"); ok {
		doc.set("metadata.event_code", stringObj(strconv.FormatInt(code, 10)))
	}
	if config.hasTags {
		doc.set("metadata.labels", stringArrayObj(config.tags))
	}

	if host := firstText(eventStr(event, "host"), config.host); host != "" {
		doc.set("device.hostname", stringObj(host))
	}
	if user := firstText(eventStr(event, "user"), config.user); user != "" {
		doc.set("actor.user.name", stringObj(user))
	}
	doc.set("actor.process.name", eventStrObj(event, "process"))
	doc.set("actor.process.pid", eventIntObj(event, "pid"))
	doc.set("actor.process.cmd_line", eventStrObj(event, "cmdline"))

	if file := ocsfFile(event); file != nil {
		doc.set("file", file)
	}

	doc.set("src_endpoint.ip", eventStrObj(event, "src_ip"))
	doc.set("src_endpoint.port", eventIntObj(event, "src_port"))
	doc.set("dst_endpoint.ip", eventStrObj(event, "dst_ip"))
	doc.set("dst_endpoint.port", eventIntObj(event, "dst_port"))
	doc.set("url.url_string", eventStrObj(event, "url"))

	// OCSF keeps a field for exactly this: what the source recorded that the
	// schema has no home for.
	doc.set("unmapped.kind", eventStrObj(event, "kind"))
	doc.set("unmapped.category", eventStrObj(event, "category"))
	doc.set("unmapped.timestamp_desc", eventStrObj(event, "ts_desc"))
	doc.set("unmapped.registry_path", eventStrObj(event, "registry_path"))
	if config.extra {
		if entry := eventHash(event, "extra"); entry != nil {
			doc.set("unmapped.extra", entry)
		}
	}
	return doc.hash(), nil
}

// ocsfActivity picks the activity within a class. For a file event the
// timestamp's meaning is the activity -- a creation time records a create -- so
// the description is read before the action.
//
// Anything else is 99 Other with the envelope's action as the name, or 0 Unknown
// when the artifact did not say what happened. Both are OCSF's own answers for
// "the source did not tell me", and both keep the reading in activity_name where
// a consumer can still see it.
func ocsfActivity(class ocsfClass, action, description string) (int64, string) {
	switch class.classUID {
	case 1001:
		switch strings.TrimSuffix(strings.TrimSpace(description), " ($FILE_NAME)") {
		case "Creation Time":
			return 1, "Create"
		case "Content Modification Time":
			return 3, "Update"
		case "Last Access Time":
			return 2, "Read"
		case "Metadata Modification Time", "Written Time":
			return 6, "Set Attributes"
		}
		if action == "open" {
			return 2, "Read"
		}
	case 6001:
		if action == "visit" || action == "download" {
			return 2, "Read"
		}
	}
	if action != "" {
		return 99, action
	}
	return 0, "Unknown"
}

// ocsfFile describes the file an event is about.
//
// The OCSF File object requires a name, so the object is written only when the
// event carries one or a path to take one from. Nothing is lost when it does
// not: `unmapped.extra` still holds the entry the parser produced.
func ocsfFile(event *object.Hash) object.Object {
	name := firstText(eventStr(event, "file_name"), pathBase(eventStr(event, "path")))
	if name == "" {
		return nil
	}

	file := docTree{}
	file.set("name", stringObj(name))
	file.set("path", eventStrObj(event, "path"))
	file.set("size", eventIntObj(event, "size"))
	// type_id is required and 0 is Unknown. An $MFT record does say whether the
	// entry is a directory, but it says so in `extra` under the parser's own
	// field name; deciding it here would be the emitter inventing a fact about
	// evidence.
	file.set("type_id", intObj(0))
	file.set("type", stringObj("Unknown"))

	if hashes := eventHash(event, "hashes"); hashes != nil {
		fingerprints := make([]object.Object, 0, len(ocsfHashAlgorithms))
		for _, algorithm := range ocsfHashAlgorithms {
			value := eventStr(hashes, algorithm.field)
			if value == "" {
				continue
			}
			fingerprints = append(fingerprints, makeHashObject(map[string]object.Object{
				"algorithm_id": intObj(algorithm.id),
				"algorithm":    stringObj(algorithm.name),
				"value":        stringObj(value),
			}))
		}
		if len(fingerprints) > 0 {
			file.set("hashes", &object.Array{Elements: fingerprints})
		}
	}
	return file.hash()
}

// --- Timesketch / plaso ---

var timesketchEmitOptions = append(append([]string{}, emitOptions...), "data_type")

// timesketchDataTypes gives each source kind its plaso data_type, which is the
// field Timesketch's analyzers and most saved searches key off.
//
// A kind with no plaso equivalent gets "mutant:<kind>:event" rather than the
// nearest plaso string. An analyzer that matched a borrowed data_type would run
// over rows it was never written for, and report on them.
var timesketchDataTypes = map[string]string{
	"mft":       "fs:stat:ntfs",
	"prefetch":  "windows:prefetch:execution",
	"evtx":      "windows:evtx:record",
	"lnk":       "windows:lnk:link",
	"amcache":   "windows:registry:amcache",
	"shimcache": "windows:registry:appcompatcache",
	"jumplist":  "olecf:dest_list:entry",
	"syslog":    "syslog:line",
	"bodyfile":  "fs:mactime:line",
	"mactime":   "fs:mactime:line",
}

// timesketchBrowserDataTypes are the kinds whose plaso type depends on which
// browser the entry came out of. The envelope carries that in `dataset`, which
// is the whole reason `dataset` exists: the emitters never reach into `extra`.
var timesketchBrowserDataTypes = map[string]map[string]string{
	"browser_history": {
		"chrome":  "chrome:history:page_visited",
		"firefox": "firefox:places:page_visited",
	},
	"browser_cookies": {
		"chrome":  "chrome:cookie:entry",
		"firefox": "firefox:cookie:entry",
	},
	"browser_downloads": {
		"chrome":  "chrome:history:file_downloaded",
		"firefox": "firefox:downloads:download",
	},
}

func timesketchDataType(kind, dataset string) string {
	if byBrowser, ok := timesketchBrowserDataTypes[kind]; ok {
		if dataType, ok := byBrowser[strings.ToLower(dataset)]; ok {
			return dataType
		}
	}
	if dataType, ok := timesketchDataTypes[kind]; ok {
		return dataType
	}
	if kind == "" {
		kind = "event"
	}
	return "mutant:" + kind + ":event"
}

// TimesketchEvent renders envelope events as Timesketch/plaso JSONL records.
// timesketch_event(event_or_events, opts?) -> (record_or_records, err).
func TimesketchEvent(args ...object.Object) object.Object {
	return emitEvents("timesketch_event", args, timesketchEmitOptions, "data_type", buildTimesketchEvent)
}

func buildTimesketchEvent(event *object.Hash, config emitConfig) (object.Object, *object.Error) {
	if errObj := requireEnvelope("timesketch_event", event); errObj != nil {
		return nil, errObj
	}
	kind := eventStr(event, "kind")
	dataType := firstText(config.setting, timesketchDataType(kind, eventStr(event, "dataset")))

	doc := docTree{}
	// Timesketch rejects a record missing any of message, datetime or
	// timestamp_desc, so each of the three is filled from whatever the event
	// does identify rather than going out empty and losing the row.
	doc.set("message", stringObj(timesketchMessage(event, kind)))
	doc.set("datetime", eventStrObj(event, "iso"))
	doc.set("timestamp_desc", stringObj(firstText(eventStr(event, "ts_desc"), "Recorded Time")))
	// plaso counts microseconds; the envelope counts milliseconds.
	if ms, ok := eventInt(event, "ts_ms"); ok {
		doc.set("timestamp", intObj(ms*1000))
	} else if seconds, ok := eventInt(event, "ts"); ok {
		doc.set("timestamp", intObj(seconds*1000000))
	}
	doc.set("data_type", stringObj(dataType))
	if config.hasTags {
		doc.set("tag", stringArrayObj(config.tags))
	}

	doc.set("kind", eventStrObj(event, "kind"))
	doc.set("category", eventStrObj(event, "category"))
	doc.set("action", eventStrObj(event, "action"))
	doc.set("severity", eventStrObj(event, "severity"))

	if host := firstText(eventStr(event, "host"), config.host); host != "" {
		doc.set("hostname", stringObj(host))
	}
	if user := firstText(eventStr(event, "user"), config.user); user != "" {
		doc.set("username", stringObj(user))
	}

	doc.set("filename", eventStrObj(event, "path"))
	doc.set("file_size", eventIntObj(event, "size"))
	if hashes := eventHash(event, "hashes"); hashes != nil {
		for _, algorithm := range []string{"md5", "sha1", "sha256"} {
			doc.set(algorithm+"_hash", eventStrObj(hashes, algorithm))
		}
	}
	doc.set("url", eventStrObj(event, "url"))
	doc.set("pid", eventIntObj(event, "pid"))
	doc.set("process_name", eventStrObj(event, "process"))
	doc.set("command_line", eventStrObj(event, "cmdline"))
	doc.set("source_ip", eventStrObj(event, "src_ip"))
	doc.set("source_port", eventIntObj(event, "src_port"))
	doc.set("destination_ip", eventStrObj(event, "dst_ip"))
	doc.set("destination_port", eventIntObj(event, "dst_port"))
	doc.set("key_path", eventStrObj(event, "registry_path"))
	doc.set("event_identifier", eventIntObj(event, "code"))
	doc.set("source_name", eventStrObj(event, "provider"))

	if config.extra {
		if entry := eventHash(event, "extra"); entry != nil {
			doc.set("extra", entry)
		}
	}
	return doc.hash(), nil
}

// timesketchMessage is the one field that cannot be omitted: Timesketch drops a
// record without it. So an event whose source spec built no message falls back
// to whatever the event does identify, and last of all to naming its own kind --
// a row that reads "shimcache event" is still a row on the timeline, and a
// dropped row is not.
func timesketchMessage(event *object.Hash, kind string) string {
	if message := eventStr(event, "message"); message != "" {
		return message
	}
	for _, key := range []string{"path", "file_name", "url", "process", "registry_path", "host"} {
		if text := eventStr(event, key); text != "" {
			return text
		}
	}
	if kind == "" {
		return "event"
	}
	return kind + " event"
}
