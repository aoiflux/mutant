package builtin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"mutant/object"
)

// --- the case bundle ---
//
// A manifest is a document for a machine: JSON, sealed, signed, exact. A report
// is a document for a person. An investigation produces both, of the same facts,
// and the danger of producing both is that they drift -- a report written by hand
// beside a manifest written by the tool is two accounts of one case, and the
// difference between them is where a cross-examination starts.
//
// So `case_report` does not read the session. It reads the manifest, the same
// native document `case_manifest()` returns and `case_write` seals, and renders
// it. The report cannot say anything the manifest does not, because there is
// nothing else for it to say it from.
//
// `case_bundle` is the handover: the manifest, the report in both formats an
// examiner is likely to want, and a SHA256SUMS a reader can check with the
// coreutils tool they already have.
//
// **Which document vouches for which.** The manifest records the digests of the
// report files; the report says nothing about the manifest's digest. That is
// deliberate and it is the only ordering that can be honest. The reports are
// written first, so a manifest can record what they hashed to; a report that
// quoted the manifest's hash would have to quote it before the manifest existed,
// and would then be quoting the hash of a document that was about to change.
//
// What this buys is F-1's rule. The bundle asserts that these files belong to
// this case, and the assertion is checkable: edit one byte of report.html and its
// digest no longer matches the one inside manifest.json, whose seal is a SHA-256
// over every other field and, when the machine has a key, an Ed25519 signature
// over the same bytes. `case_manifest_verify` takes the manifest alone and says
// so. SHA256SUMS is the convenience on top, not the guarantee underneath.

// Bundle members. Fixed names: a handover whose file names vary is a handover
// whose reader has to be told what to look at.
const (
	bundleManifestName  = "manifest.json"
	bundleHTMLName      = "report.html"
	bundleMarkdownName  = "report.md"
	bundleChecksumsName = "SHA256SUMS"
)

var caseReportOptions = []string{"title", "subtitle", "generated"}

// CaseReport renders the open case as a report: case_report(opts?).
func CaseReport(args ...object.Object) object.Object {
	if len(args) > 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0 or 1", len(args)))
	}
	opts, errObj := formatOptionsArg("case_report", args, 1, caseReportOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	manifest, errObj := caseManifestSnapshot("case_report")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	report, errObj := caseReportDocument("case_report", manifest, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(report, nil)
}

var caseBundleOptions = []string{"title", "subtitle", "generated", "sign"}

// CaseBundle writes the handover: case_bundle(dir, opts?).
func CaseBundle(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	dir, errObj := requireStringArg("case_bundle", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(dir) == "" {
		return resultAndError(nil, newError("case_bundle: the directory must not be empty"))
	}
	opts, errObj := formatOptionsArg("case_bundle", args, 2, caseBundleOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	sign, errObj := opts.boolean("sign", true)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	manifest, errObj := caseManifestSnapshot("case_bundle")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// One report, two renderings. Built before the directory exists so a
	// document that cannot be rendered leaves nothing behind.
	report, errObj := caseReportDocument("case_bundle", manifest, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	renderOpts, errObj := formatOptionsArg("case_bundle", nil, 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	htmlText, errObj := renderReport("case_bundle", report, "html", renderOpts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	markdownText, errObj := renderReport("case_bundle", report, "markdown", renderOpts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// 0700 for the same reason every artifact here is 0600: the bundle names
	// evidence, and it is about to be somewhere a backup agent can see.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return resultAndError(nil, newError("case_bundle: %s", err.Error()))
	}

	written := map[string]writtenArtifact{}
	for name, text := range map[string]string{bundleHTMLName: htmlText, bundleMarkdownName: markdownText} {
		artifact, errObj := writeArtifact("case_bundle", filepath.Join(dir, name), []byte(text))
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		written[name] = artifact
	}

	// The reports are now facts about files, so the manifest can record them and
	// be sealed over what it recorded. Names only, never the directory: a bundle
	// that stops being true when somebody copies the folder is worse than one
	// that says nothing about where it lives.
	manifest["bundle"] = map[string]any{
		"wrote": []any{
			bundleFileRecord(bundleHTMLName, written[bundleHTMLName]),
			bundleFileRecord(bundleMarkdownName, written[bundleMarkdownName]),
		},
		"checksums": bundleChecksumsName,
		"covers": "the documents written beside this manifest. Their digests are inside this " +
			"document's seal, so a report edited after the fact no longer matches the case it claims to be from",
	}
	if err := custodySeal(manifest, sign); err != nil {
		return resultAndError(nil, newError("case_bundle: %s", err.Error()))
	}
	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return resultAndError(nil, newError("case_bundle: the manifest cannot be written as JSON: %s", err.Error()))
	}
	document = append(document, '\n')

	artifact, errObj := writeArtifact("case_bundle", filepath.Join(dir, bundleManifestName), document)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	written[bundleManifestName] = artifact

	// SHA256SUMS last, in the format `sha256sum -c` reads, so checking a bundle
	// needs nothing from this project at all.
	sums, errObj := writeArtifact("case_bundle", filepath.Join(dir, bundleChecksumsName), []byte(bundleChecksums(written)))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	written[bundleChecksumsName] = sums

	seal, _ := manifest["seal"].(map[string]any)
	signed, _ := seal["signed"].(bool)
	manifestHash := stringField(seal, "manifest_hash")

	names := make([]string, 0, len(written))
	for name := range written {
		names = append(names, name)
	}
	sort.Strings(names)
	files := make([]object.Object, 0, len(names))
	for _, name := range names {
		files = append(files, makeHashObject(map[string]object.Object{
			"name":   stringObj(name),
			"bytes":  intObj(written[name].bytes),
			"sha256": stringObj(written[name].digest),
		}))
	}

	custodyRecordArtifact("case_bundle",
		fmt.Sprintf("wrote the case bundle to %s (manifest sha256 %s, signed %t)", dir, manifestHash, signed),
		map[string]any{
			"dir":           dir,
			"manifest_hash": manifestHash,
			"signed":        signed,
		})

	result := map[string]object.Object{
		"dir":           stringObj(dir),
		"files":         &object.Array{Elements: files},
		"manifest":      stringObj(bundleManifestName),
		"checksums":     stringObj(bundleChecksumsName),
		"manifest_hash": stringObj(manifestHash),
		"signed":        boolObj(signed),
		"status":        stringObj("ok"),
	}
	if reason, ok := seal["signature_error"].(string); ok {
		result["signature_error"] = stringObj(reason)
	}
	return resultAndError(makeHashObject(result), nil)
}

func bundleFileRecord(name string, artifact writtenArtifact) map[string]any {
	return map[string]any{
		"name":      name,
		"bytes":     artifact.bytes,
		"sha256":    artifact.digest,
		"hash_algo": "sha256",
	}
}

// bundleChecksums renders the digests in the format coreutils' sha256sum writes
// and reads: the hex, two spaces, the name. Sorted, because a checksum file that
// reorders itself between runs is a diff nobody can read.
func bundleChecksums(written map[string]writtenArtifact) string {
	names := make([]string, 0, len(written))
	for name := range written {
		names = append(names, name)
	}
	sort.Strings(names)

	var out strings.Builder
	for _, name := range names {
		out.WriteString(written[name].digest)
		out.WriteString("  ")
		out.WriteString(name)
		out.WriteString("\n")
	}
	return out.String()
}

// caseManifestSnapshot renders the open case once, under the read lock.
//
// The lock is held across the render rather than only long enough to pick the
// session up, for the same reason `case_manifest` holds it: a spawned task
// reading evidence is writing into these maps.
func caseManifestSnapshot(op string) (map[string]any, *object.Error) {
	custodyStore.RLock()
	defer custodyStore.RUnlock()

	session := custodyStore.session
	if session == nil {
		return nil, newError("%s: no case has been opened; call `case_open(id, examiner)` first", op)
	}
	return session.manifest(), nil
}

// --- the manifest, as a report ---

// caseReportDocument builds the report value. It is a document in exactly the
// shape `report_new` and its builders produce, so it can be added to before it
// is rendered: an examiner's conclusions are not something a manifest holds.
func caseReportDocument(op string, manifest map[string]any, opts *formatOptions) (*object.Hash, *object.Error) {
	caseInfo := manifestMap(manifest, "case")
	id := stringField(caseInfo, "id")
	examiner := stringField(caseInfo, "examiner")

	title, errObj := opts.str("title", "")
	if errObj != nil {
		return nil, errObj
	}
	if strings.TrimSpace(title) == "" {
		title = "Case " + id
	}
	subtitle, errObj := opts.str("subtitle", "")
	if errObj != nil {
		return nil, errObj
	}
	generated, errObj := reportGenerated(opts)
	if errObj != nil {
		return nil, errObj
	}

	builder := &caseReportBuilder{}
	caseReportLead(builder, manifest, caseInfo)
	caseReportEvidence(builder, manifest)
	caseReportTimeline(builder, manifest)
	caseReportIntegrity(builder, manifest)
	caseReportSecurity(builder, manifest)
	caseReportProvenance(builder, manifest)
	caseReportAbout(builder)

	values := map[string]object.Object{
		"title":     stringObj(title),
		"generated": stringObj(generated),
		"sections":  &object.Array{Elements: builder.done()},
	}
	if subtitle != "" {
		values["subtitle"] = stringObj(subtitle)
	}
	if examiner != "" {
		values["examiner"] = stringObj(examiner)
	}
	if id != "" {
		values["case_id"] = stringObj(id)
	}
	return makeHashObject(values), nil
}

func caseReportLead(b *caseReportBuilder, manifest map[string]any, caseInfo map[string]any) {
	status := stringField(caseInfo, "status")
	closing := "is still open"
	if closed := stringField(caseInfo, "closed_at"); status == "closed" && closed != "" {
		closing = "was closed at " + closed
	} else if status == "closed" {
		closing = "is closed"
	}
	b.text(fmt.Sprintf("Case %s, examined by %s. Opened at %s; it %s.",
		stringField(caseInfo, "id"), stringField(caseInfo, "examiner"),
		stringField(caseInfo, "opened_at"), closing))

	integrity := manifestMap(manifest, "integrity")
	policy := stringField(integrity, "hash_policy")
	total := manifestInt(integrity, "sources_total")
	hashed := manifestInt(integrity, "sources_hashed")
	switch {
	case total == 0:
		b.text("No evidence source was registered under this case.")
	case policy == "none":
		b.text(fmt.Sprintf("%s under custody. The case was opened with no hash policy, so sizes and "+
			"modification times are recorded and no digests were taken.", countOf(total, "source", "sources")))
	default:
		b.text(fmt.Sprintf("%s under custody; %d hashed with %s.",
			countOf(total, "source", "sources"), hashed, policy))
	}
}

func caseReportEvidence(b *caseReportBuilder, manifest map[string]any) {
	sources := manifestList(manifest, "evidence")
	if len(sources) == 0 {
		return
	}

	b.section("Evidence")
	rows := make([][]string, 0, len(sources))
	access := make([][]string, 0, len(sources))
	for _, element := range sources {
		source, ok := element.(map[string]any)
		if !ok {
			continue
		}
		path := stringField(source, "path")
		size := "-"
		if manifestBool(source, "on_disk") {
			size = strconv.FormatInt(manifestInt(source, "size"), 10)
		}
		modified := stringField(source, "mod_time")
		if modified == "" {
			modified = "-"
		}
		rows = append(rows, []string{path, size, modified, evidenceDigestCell(source)})

		for _, touched := range manifestList(source, "touches") {
			touch, ok := touched.(map[string]any)
			if !ok {
				continue
			}
			access = append(access, []string{
				path,
				stringField(touch, "builtin"),
				strconv.FormatInt(manifestInt(touch, "count"), 10),
				stringField(touch, "first"),
				stringField(touch, "last"),
			})
		}
	}
	b.table([]string{"source", "size", "modified", "digest"}, rows)

	if len(access) > 0 {
		b.section("Access")
		b.text("What was read, and by what. One row per builtin per source; the count is the number of calls.")
		b.table([]string{"source", "builtin", "calls", "first", "last"}, access)
	}
}

// evidenceDigestCell says what is known about a source's digest, including when
// the answer is that there isn't one. "not hashed" and "hashing failed" are
// different facts and a blank cell is neither.
func evidenceDigestCell(source map[string]any) string {
	if reason := stringField(source, "hash_error"); reason != "" {
		return "hashing failed: " + reason
	}
	if !manifestBool(source, "hashed") {
		return "not hashed"
	}
	return stringField(source, "hash_algo") + " " + stringField(source, "hash")
}

func caseReportTimeline(b *caseReportBuilder, manifest map[string]any) {
	events := manifestList(manifest, "timeline")
	if len(events) == 0 {
		return
	}

	b.section("Timeline")
	rows := make([][]string, 0, len(events))
	for _, element := range events {
		event, ok := element.(map[string]any)
		if !ok {
			continue
		}
		rows = append(rows, []string{
			stringField(event, "at"),
			strconv.FormatInt(manifestInt(event, "elapsed_ms"), 10),
			stringField(event, "event"),
			stringField(event, "detail"),
		})
	}
	b.table([]string{"at", "elapsed (ms)", "event", "detail"}, rows)
}

func caseReportIntegrity(b *caseReportBuilder, manifest map[string]any) {
	integrity := manifestMap(manifest, "integrity")
	if len(integrity) == 0 {
		return
	}

	b.section("Integrity")
	items := []string{
		"Hash policy: " + stringField(integrity, "hash_policy"),
		fmt.Sprintf("Sources under custody: %d, of which %d hashed",
			manifestInt(integrity, "sources_total"), manifestInt(integrity, "sources_hashed")),
	}
	if manifestBool(integrity, "evidence_read_only") {
		items = append(items, "Evidence was opened read-only. This is checked rather than asserted: "+
			"policy/evidence_guard_test.go fails the build if any code that reads evidence asks the "+
			"operating system to change something. The policy is "+stringField(integrity, "read_only_policy")+".")
	}
	b.list(items, false)
}

// caseReportSecurity renders the counters, zeros and all.
//
// Nothing is filtered out. "Was anything abnormal while this ran?" is a question
// asked of every forensic tool, and a table of counters that silently omits the
// ones reading zero is a table that cannot distinguish "nothing happened" from
// "nothing was watching".
func caseReportSecurity(b *caseReportBuilder, manifest map[string]any) {
	counters := manifestMap(manifest, "security_telemetry")

	b.section("Security counters")
	if len(counters) == 0 {
		b.text("This run recorded no security counters.")
		return
	}

	names := make([]string, 0, len(counters))
	for name := range counters {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([][]string, 0, len(names))
	for _, name := range names {
		rows = append(rows, []string{name, fmt.Sprintf("%v", counters[name])})
	}

	b.text("What the runtime counted while this case was open. A number rather than a reassurance, " +
		"and every counter is listed whether it moved or not.")
	b.table([]string{"counter", "count"}, rows)
}

func caseReportProvenance(b *caseReportBuilder, manifest map[string]any) {
	tool := manifestMap(manifest, "tool")
	program := manifestMap(manifest, "program")
	if len(tool) == 0 && len(program) == 0 {
		return
	}

	b.section("Provenance")
	items := []string{}
	if len(tool) > 0 {
		items = append(items, fmt.Sprintf("Mutant %s, built with %s, running on %s/%s",
			stringField(tool, "version"), stringField(tool, "go_version"),
			stringField(tool, "os"), stringField(tool, "arch")))
	}
	if manifestBool(program, "recorded") {
		items = append(items, fmt.Sprintf("Program: %s (%s %s)",
			stringField(program, "path"), stringField(program, "hash_algo"), stringField(program, "hash")))
	} else if detail := stringField(program, "detail"); detail != "" {
		items = append(items, "Program: "+detail)
	}
	b.list(items, false)
}

func caseReportAbout(b *caseReportBuilder) {
	b.section("About this document")
	b.text("This report is a rendering of the case manifest. Every value in it was read from " +
		"that document rather than written beside it, so the two cannot disagree about what was examined.")
	b.text("It carries no digest of the manifest, on purpose. `case_bundle` writes the reports first and " +
		"records what they hashed to inside the manifest it then seals, so the manifest vouches for the " +
		"report and not the other way round. A hash of the manifest quoted in here would be a hash of a " +
		"document that had not been written yet.")
	b.text("Text in the tables above came out of the evidence, which is to say it was written by the " +
		"subject of the investigation. It is escaped, never interpreted, and never turned into a link.")
}

// countOf renders "1 source" and "4 sources" without the reader having to work
// out which of the two the report meant.
func countOf(n int64, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.FormatInt(n, 10) + " " + plural
}

// --- building the document ---

// caseReportBuilder accumulates sections. Blocks written before the first
// section land in a lead section with no heading, the same rule `report_text`
// follows, because a report opens with a summary.
type caseReportBuilder struct {
	sections []object.Object
	heading  string
	blocks   []object.Object
	started  bool
}

func (b *caseReportBuilder) section(heading string) {
	b.flush()
	b.heading = heading
	b.started = true
}

func (b *caseReportBuilder) text(text string) {
	b.blocks = append(b.blocks, makeHashObject(map[string]object.Object{
		"kind": stringObj(reportBlockText),
		"text": stringObj(text),
	}))
}

func (b *caseReportBuilder) list(items []string, ordered bool) {
	if len(items) == 0 {
		return
	}
	b.blocks = append(b.blocks, makeHashObject(map[string]object.Object{
		"kind":    stringObj(reportBlockList),
		"items":   stringListObj(items),
		"ordered": boolObj(ordered),
	}))
}

// table adds a table with no caption. Every table here sits alone under a
// heading that already names it, and a caption repeating that heading is a line
// of noise in all three formats. `report_render`'s CSV selection falls back to
// the section heading for exactly this case, so naming a table still works.
func (b *caseReportBuilder) table(columns []string, rows [][]string) {
	b.blocks = append(b.blocks, makeHashObject(map[string]object.Object{
		"kind":    stringObj(reportBlockTable),
		"columns": stringListObj(columns),
		"rows":    reportRowsObj(rows),
	}))
}

func (b *caseReportBuilder) flush() {
	if !b.started && len(b.blocks) == 0 {
		return
	}
	b.sections = append(b.sections, makeHashObject(map[string]object.Object{
		"heading": stringObj(b.heading),
		"level":   intObj(reportDefaultLevel),
		"blocks":  &object.Array{Elements: b.blocks},
	}))
	b.heading = ""
	b.blocks = nil
}

func (b *caseReportBuilder) done() []object.Object {
	b.flush()
	if b.sections == nil {
		return []object.Object{}
	}
	return b.sections
}

// --- reading the manifest ---
//
// The manifest is native Go values, so these are the plain accessors. Each
// returns the zero value for a field that is absent or another type: a report
// built from a manifest it does not fully recognise should still say what it
// does recognise, because the alternative is refusing to render a case.

func manifestMap(m map[string]any, key string) map[string]any {
	nested, _ := m[key].(map[string]any)
	return nested
}

func manifestList(m map[string]any, key string) []any {
	list, _ := m[key].([]any)
	return list
}

func manifestInt(m map[string]any, key string) int64 {
	switch value := m[key].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	}
	return 0
}

func manifestBool(m map[string]any, key string) bool {
	value, _ := m[key].(bool)
	return value
}
