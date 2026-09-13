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

- [CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md#schema-interchange-2) — the
  generated signatures.
- [COOKBOOK.md](COOKBOOK.md) — timeline recipes.
- [STRUCTURED_DATA.md](STRUCTURED_DATA.md) — `ndjson_stringify`, which is how a
  normalized timeline becomes a JSONL file.
