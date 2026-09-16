# Interchange schemas

Mutant parses thirteen kinds of artifact and each parser hands back its own
shape, because each artifact *is* its own shape: an `$MFT` record carries eight
timestamps, a Prefetch file carries a list of run times, a syslog line carries
one. That is the right thing for a parser to do and the wrong thing for a
timeline, and it is the wrong thing for anything downstream — Timesketch, plaso,
a SIEM — that wants one row format.

`events_from` is the bridge. It normalizes any parsed artifact into a small,
fixed event vocabulary, and that vocabulary is what the schema emitters are
written against.

## Why one vocabulary and not three mappings

The obvious design is a table per (artifact, schema) pair: MFT→ECS, MFT→OCSF,
MFT→Timesketch, Prefetch→ECS, and so on. Thirteen artifacts and three schemas is
thirty-nine tables, each of which has to be correct, and each of which drifts
the moment either side changes.

There is one hop in between instead:

```
artifact hash  ──(one source spec per artifact)──▶  event envelope  ──(one emitter per schema)──▶  ECS │ OCSF │ Timesketch
```

Thirteen plus three, not thirteen times three. A new parser writes one source
spec and reaches every schema. A new schema writes one emitter and reaches every
parser.

## `events_from(artifact, kind_or_mapping)`

```
let mft, err = mft_parse("evidence/$MFT");
let events, err = events_from(mft, "mft");
```

The first argument is whatever the parser returned — the result hash, with its
`entries` or `records` array found for you — or a bare array of entries. A
parser's `(result, err)` pair is accepted directly, so this also works:

```
let events, err = events_from(mft_parse("evidence/$MFT"), "mft");
```

and a parse that failed reports its own error rather than a complaint about the
shape of something that was never built.

The second argument names a source kind, or is a mapping hash for an artifact
Mutant does not know. `event_kinds()` lists the built-in kinds, the timestamps
each one reads, and the envelope fields each one fills.

Because every kind produces the same shape, a supertimeline is a merge:

```
let timeline = timeline_merge([
  events_from(mft_parse(mft_path), "mft"),
  events_from(prefetch_parse(pf_path), "prefetch"),
  events_from(evtx_parse(evtx_path), "evtx"),
  events_from(browser_history(history_path), "browser_history"),
]);
```

## The envelope

Every event carries these:

| Field | Meaning |
| --- | --- |
| `ts` | Unix seconds |
| `ts_ms` | Unix milliseconds, carrying any sub-second fraction the artifact recorded |
| `ts_desc` | What this timestamp *means*, in the plaso/Timesketch vocabulary — `Creation Time`, `Last Time Executed`, `Last Visited Time` |
| `iso` | RFC 3339, with the fraction when there is one |
| `kind` | The source kind, e.g. `mft` |
| `category` | `file`, `execution`, `log`, `web`, … — what the emitters switch on |
| `extra` | The source entry, verbatim |

And these when the artifact recorded them:

`action`, `message`, `host`, `user`, `path`, `file_name`, `size`,
`hashes{md5,sha1,sha256}`, `process`, `pid`, `cmdline`, `src_ip`, `dst_ip`,
`src_port`, `dst_port`, `url`, `registry_path`, `code`, `provider`, `dataset`,
`severity`.

### Three rules that keep it honest

**An unknown field is absent, not empty.** An empty string in a forensic record
reads as "the artifact recorded nothing here", and that is usually a claim the
parser never made. A record whose path could not be reconstructed has no `path`
key at all. The exception is deliberate: a `size` of zero is a real size, an
empty file, so zero sizes are kept. Only the fields where zero genuinely means
"not recorded" — `pid`, `code`, `src_port`, `dst_port` — are dropped when zero.

**A zero timestamp produces no event.** These artifacts use 0 for "not
recorded", and an `$MFT` has plenty. Emitting them would put thousands of 1970
rows in front of the handful of real ones.

**`extra` is the whole source entry.** Normalization is additive. Every field
the parser found is still reachable, under the name the parser gave it — which
matters, because a normalized view of evidence that quietly drops fields is a
view an examiner cannot testify from. The envelope is a lens, not a replacement.

### `severity` is a word

The envelope's `severity` is one of `unknown`, `informational`, `low`, `medium`,
`high`, `critical`, `fatal`.

It is a word rather than a number because the numeric scales disagree about
which direction they run. Syslog counts down — 0 is Emergency, 7 is Debug.
Windows event Levels count up from 1 (Critical) to 5 (Verbose). ECS
`event.severity` and OCSF `severity_id` each have their own. Mapping the raw
number through would mean every emitter re-deriving which scale it came from;
mapping it to a word once, in the source spec, means each emitter converts from
one known thing.

Windows Level 0 (`LogAlways`) asserts nothing about severity, so it produces no
`severity` at all rather than a guessed `informational`.

### `message` is a summary, not data

Each source kind fills a short human-readable line — `CALC.EXE was executed (run
count 7)`, `sshd: Failed password for root`. It is for reading. The values it
was built from are in `extra`, unmodified, and that is what anything
machine-readable should use.

## The source kinds

| Kind | Category | Timestamps read |
| --- | --- | --- |
| `mft` | file | the four `$STANDARD_INFORMATION` and four `$FILE_NAME` times, named apart |
| `prefetch` | execution | every run time in the file |
| `evtx` | log | the record time; Level becomes `severity`, Channel becomes `dataset` |
| `lnk` | file | the target's creation/write/access times from the link header |
| `amcache` | execution | the key's last-write time |
| `shimcache` | execution | the entry's last-modified time |
| `jumplist` | file | the destination's last-access time |
| `syslog` | log | the line's time; the numeric severity becomes a word |
| `browser_history` | web | last visit |
| `browser_cookies` | web | expiration |
| `browser_downloads` | web | start and end |
| `bodyfile` | file | the four MAC times |
| `mactime` | file | the row's time, described by its own MACB flags |

`$FILE_NAME` times are described separately from `$STANDARD_INFORMATION` ones —
`Creation Time ($FILE_NAME)` — because the disagreement between the two sets is
the timestomping tell, and a timeline that merged them would hide it.

`amcache` and `shimcache` are `execution` rather than `process`: both record
that a program was *present* on the host, which is evidence of execution rather
than proof of it, and the action they carry is `present` rather than `run`.

`reg_timeline` is deliberately not a source kind. Its rows are free-form JSON
with no stable shape, so there is nothing to map.

## Writing it out

Three emitters take envelope events and render them in the schema the next tool
reads. Each takes one event or a whole timeline and hands back the same shape,
because a timeline is the normal case — one `$MFT` is hundreds of thousands of
events, and mapping over it a row at a time would mean a `(value, err)` pair per
row.

```
let events, err = events_from(mft_parse(mft_path), "mft");
let rows, err   = timesketch_event(events, {"host": "WS01"});
let jsonl, err  = ndjson_stringify(rows);
```

All three take the same four options, so changing schema is not relearning the
knobs:

| Option | Meaning |
| --- | --- |
| `host`, `user` | Fill in what the artifact structurally could not record. An `$MFT` knows every path on the volume and nothing about which host the volume came out of; the examiner who mounted the image does. What the artifact *did* record wins — the option fills a gap, it does not overwrite evidence |
| `tags` | An array of strings: ECS `tags`, OCSF `metadata.labels`, Timesketch `tag` |
| `extra` | `false` leaves the verbatim source entry out. The default is to carry it |

A fifth option differs by schema: `version` for `ecs_event` (default `8.11.0`)
and `ocsf_event` (default `1.1.0`), `data_type` for `timesketch_event`.

An unknown option key is an error rather than something ignored, and so is a
hash that did not come out of `events_from`. A raw parser entry has no `ts` and
no `iso`, so emitting it would produce a document with no timestamp and every
mapped field missing — which looks like a real document, indexes like one, and
is not one.

### `ecs_event` — Elastic Common Schema

Nested ECS 8.11: `@timestamp`, `event.*`, `host.name`, `user.name`, `file.*`
(including `file.hash.md5|sha1|sha256`), `process.*`, `source.*`,
`destination.*`, `url.full`, `registry.path`.

`event.type` is read off the timestamp's meaning rather than the artifact's
kind, because the envelope has already split one record into one event per
timestamp: a creation time is `creation`, an access time is `access`, a record
of presence is `info`. `event.category` is left out entirely where ECS has no
honest value — there is no log category, and every value ECS does have would be
a claim about what the line recorded.

Severity is emitted twice: the envelope's word in `log.level`, and a number in
`event.severity` running the syslog way, 0 worst. That is the scale ECS's own
example uses. The word is there so that nothing has to know the direction.

ECS has no field for what a timestamp means, and without one the four documents
an `$MFT` record produces are the same document four times. That, the source
kind, the category and the verbatim entry go under a custom `mutant` namespace,
which is what ECS says to do with fields it does not define.

### `ocsf_event` — OCSF 1.1

An OCSF class describes activity a sensor observed. A forensic artifact is a
record that activity happened, which is a different claim — so the class here
says where the record belongs, not that Mutant watched it happen.

| Envelope category | Class |
| --- | --- |
| `file` | 1001 File System Activity |
| `web` | 6001 Web Resources Activity |
| `network` / `dns` / `email` | 4001 / 4003 / 4009 |
| `authentication` | 3002 Authentication |
| `process` / `module` / `scheduled_job` | 1007 / 1005 / 1006 |
| everything else | 0 Base Event |

Two of those "everything else" cases are deliberate. `execution` is not 1007
Process Activity: Amcache and Shimcache record that a program was *present*, and
a detection written against 1007 would fire on that. `registry` is not the `win`
extension's 201002, because an extension uid means nothing to a consumer that
has not loaded that extension.

`activity_id` comes from the timestamp for file events — a creation time is
`Create`, a content modification is `Update`, an access is `Read`, a metadata
change is `Set Attributes`. Anything else is 99 Other with the envelope's action
as `activity_name`, or 0 Unknown when the artifact did not say what happened.
Both keep the reading somewhere a consumer can still read it.

`severity_id` is the envelope's word mapped one to one, which is what the word
vocabulary was chosen for. An event with no severity is 0 Unknown — OCSF's own
way of saying the source did not report one — and the same reasoning puts
`file.type_id` at 0 rather than guessing Regular File.

What OCSF has no home for goes in `unmapped`, the field OCSF keeps for exactly
that: the source kind, the timestamp description, the registry path, and the
verbatim entry.

### `timesketch_event` — Timesketch / plaso

A record ready for `ndjson_stringify`. Timesketch *drops* a record missing any
of `message`, `datetime` or `timestamp_desc` rather than flagging it, so all
three are always filled: an event whose source spec built no message falls back
to whatever the event does identify, and last of all to naming its own kind. A
row reading `shimcache event` is still a row on the timeline; a dropped row is
not.

`timestamp` counts plaso's microseconds. `data_type` is the plaso string
Timesketch's analyzers and saved searches key off:

| Kind | `data_type` |
| --- | --- |
| `mft` | `fs:stat:ntfs` |
| `prefetch` | `windows:prefetch:execution` |
| `evtx` | `windows:evtx:record` |
| `lnk` | `windows:lnk:link` |
| `amcache` | `windows:registry:amcache` |
| `shimcache` | `windows:registry:appcompatcache` |
| `jumplist` | `olecf:dest_list:entry` |
| `syslog` | `syslog:line` |
| `bodyfile`, `mactime` | `fs:mactime:line` |
| the browser kinds | by the browser in `dataset`: `chrome:history:page_visited`, `firefox:places:page_visited`, and so on |

A kind with no plaso equivalent gets `mutant:<kind>:event` rather than the
nearest plaso string. An analyzer that matched a borrowed `data_type` would run
over rows it was never written for, and report on them.

## Indicators out: STIX 2.1

Everything above carries *what happened*. `stix_bundle` carries *what to look
for*: the values an investigation decided are worth watching for, in the form
the platforms that hunt them read.

It takes no envelope events, because an indicator is not an event. The input is
the hash `extract_iocs` returns, or one written by hand in the same shape:

```
let iocs = extract_iocs(fs_read("report.txt"));
let bundle, err = stix_bundle(iocs, {"indicators": true, "created": "2026-01-31T09:00:00Z"});
let doc, err = json_stringify(bundle);
```

| Key | Becomes |
| --- | --- |
| `ipv4`, `ipv6` | `ipv4-addr`, `ipv6-addr` |
| `domains` | `domain-name` |
| `urls` | `url` |
| `emails` | `email-addr` |
| `md5`, `sha1`, `sha256` | `file`, carrying that one algorithm in `hashes` |

Each value is a string or a list of strings, and the singular spellings
(`domain`, `url`, `email`) are accepted too. A key no type claims is an error
rather than something skipped — a bundle quietly missing its hashes because they
arrived under `hash` would look like a clean extraction.

So is a value that is not what its key says. A forty-character digest filed
under `sha256` would become a file observable whose id nothing else computes,
and a STIX object nothing matches produces no report at all: the pipeline that
ignores it reports success.

### Why every id is derived rather than generated

An observable's id is a UUIDv5 over the canonical JSON of the properties STIX
says identify it, under the namespace the specification fixes for the purpose.
That is not a choice; it is how two tools that saw the same indicator agree they
saw the same one.

Mutant extends it to the bundle and the indicators, which the specification
would let be random. A random id is a new id every run, and two bundles built
from one body of evidence would then differ in every identifier while describing
exactly the same findings — impossible to diff, and impossible to say what
changed between two readings of one artifact. Reproducible evidence is worth
more than the version nibble, which no consumer reads.

Values are normalized before they are hashed, for the same reason: a digest in
upper case and the same digest in lower case would otherwise be two objects.
Digests, domain names and email addresses are lowercased, and an IPv6 address is
written the short way.

Three digests of one file therefore become three file observables rather than
one file with three hashes. Nothing in a list of digests says they describe the
same file, and merging them on the guess that they do would invent a file nobody
observed.

### Indicators

`indicators: true` adds an Indicator beside each observable, carrying the
pattern that matches it.

| Option | Meaning |
| --- | --- |
| `indicators` | `true` adds an Indicator per observable. Default `false` |
| `created` | RFC 3339; stamps `created`, `modified` and `valid_from` |
| `tags` | Each Indicator's `labels`. Needs `indicators: true`, since a STIX observable has no labels property to put them in |

The three timestamps an Indicator requires all come from `created`, which
defaults to now. Pin it to when the case was collected and the whole bundle is
byte-identical between runs, indicators included; an indicator's own id comes
from its pattern alone, so re-stamping a case does not renumber it.

Every indicator is typed `unknown` rather than `malicious-activity`. The
extraction found a value written in a document — it concluded nothing about it,
and a bundle that says otherwise carries that conclusion into every platform it
is shared with.

A bundle from an extraction that found nothing has no `objects` key at all,
because an empty STIX list property must be left out. Count the indicators
before bundling if a script needs to branch on that.

### `stix_pattern(type, value)`

The same pattern, one at a time, for a query rather than a bundle:

```
let pattern, err = stix_pattern("sha256", digest);
// [file:hashes.'SHA-256' = '...']
```

It takes the type names `stix_bundle` takes, normalizes and checks the value the
same way, and escapes it: a quote inside a URL would otherwise close the
pattern's own string and leave the rest of the value sitting in the grammar as
if someone had written it there.

## Mapping an artifact Mutant does not know

Pass a hash instead of a kind name:

```
let events, err = events_from(rows, {
  "kind":     "caselog",
  "category": "configuration",
  "action":   "seal",
  "message":  "{who}: {what}",
  "times":    [{"field": "when", "desc": "Recorded Time", "format": "iso"}],
  "fields":   {"user": "who", "path": "artifact"},
});
```

| Key | Meaning |
| --- | --- |
| `kind` | What to call this artifact. Defaults to `custom` |
| `category` | One of the categories above; what the emitters switch on |
| `action` | A verb for what the event records |
| `entries` | The key holding the rows, if the artifact is a container hash |
| `message` | A `{field}` template. `{a\|b}` takes the first that has a value |
| `times` | Required. `[{field, desc, format?, ns_field?, array?}]` |
| `fields` | `{envelope_field: source_field}`. `hashes.sha1` nests |

`format` is anything `timestamp_normalize` accepts — `unix`, `unix_ms`,
`filetime`, `webkit`, `dos`, `iso`, `auto` — and defaults to `unix`. `array`
says the field holds a list of timestamps rather than one.

This is the same mechanism the built-in kinds use; there is no privileged path.

## When a mapping produces nothing

A value that will not normalize yields no event rather than an error: forensic
input is partial by nature, and one unreadable field in one row is not a reason
to refuse the other ten thousand. The cost is that a *wrong* mapping is quiet
too — an empty array looks the same as an artifact with no timestamps.

`event_kinds()` is the way back. It reports, for every kind, the exact field
names it reads and the format it reads them as, which is the difference between
"the field is not there" and "the field is there and I am reading it as the
wrong type".

## See also

- [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md#schema-interchange-7) — the
  generated signatures.
- [COOKBOOK.md](COOKBOOK.md) — timeline recipes.
- [STRUCTURED_DATA.md](STRUCTURED_DATA.md) — `ndjson_stringify`, which is how a
  normalized timeline becomes a JSONL file.
