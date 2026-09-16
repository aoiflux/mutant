# Detection rules — Sigma

[Sigma](https://sigmahq.io) is the portable format for log detections: a rule is
a YAML file naming the fields to look at and the condition that has to hold, and
a backend compiles it into whatever the SIEM of the day speaks. Mutant does not
compile Sigma rules into something else. It evaluates them, here, against the
events `events_from` produces.

That is possible for a reason worth stating plainly, because the sibling
question has the opposite answer. A YARA engine needs libyara, libyara needs
cgo, and everything in this project builds under `CGO_ENABLED=0` — so
`bin_yara_scan` is a literal multi-string scan, says so in its own output
(`engine: "literal-substring"`), and a real YARA engine is not coming. Sigma has
no such dependency. It is YAML and a matching model, both of which are ordinary
code, and the two things an implementation needs here already existed:
`yaml_parse_all`, because a ruleset is a multi-document YAML file, and
`events_from`, because a rule needs something uniform to match against.

## The four builtins

```
let text, err   = fs_read("rules/encoded_powershell.yml");
let rule, err   = sigma_parse(text);

let source, err = fs_read("rules/windows.yml");
let rules, err  = sigma_parse_all(source);

let hit, err    = sigma_match(rule, event);
let report, err = sigma_scan(rules, events);
```

A rule written inline goes in a raw triple-quoted string, so the backslashes and
quotes a Sigma rule is full of stay as they were written:

```
let rule, err = sigma_parse(r"""
title: Encoded PowerShell Command Line
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
level: high
""");
```

`sigma_parse` compiles one rule; `sigma_parse_all` compiles a whole ruleset in
file order. Both hand back ordinary hashes, not opaque handles, so a rule can be
printed, stored in a case with `case_add_evidence`, or diffed against last
week's copy of the same rule. The hash carries its `detection` block verbatim,
which is what makes it a rule rather than a description of one: `sigma_match`
and `sigma_scan` take it straight back.

`sigma_match` asks one rule about one event. `sigma_scan` runs a ruleset over a
timeline, and it is the call that matters at scale — it compiles each rule once
and then walks the events, where `sigma_match` recompiles the rule it is handed
on every call.

## The rule this engine is built around

**A rule this engine cannot evaluate is a compile error, never a silent
non-match.**

The alternative is worse than it looks. A backend that quietly ignores an
aggregation, or shrugs at a modifier it does not know, produces a rule that sits
in the ruleset, counts toward coverage, appears in the report of what was run —
and cannot fire. Nobody goes looking for a rule that never alerts, because a
rule that never alerts looks exactly like a rule with nothing to find.

So these are all errors, each naming itself:

| Refused | Because |
|---|---|
| `condition: selection \| count() by X > 5` | An aggregation counts events. This engine answers about one event at a time. |
| `condition: selection \| near other` | Same: `near` correlates across a window. |
| `timeframe: 15m` | Same. |
| `action: global` / `repeat` | Rule collections inherit fields across documents. Split the collection first. |
| `Field\|expand: '%placeholder%'` | `\|expand` substitutes a value from the backend's own configuration. There is no backend here to ask. |
| `Field\|startswithish: x` | An unknown modifier. Guessing what it meant is how a rule ends up meaning something else. |
| `condition: selection and filter` with no `filter` | The condition names a search the detection block does not define. |
| `condition: not all of filter*` with no `filter*` | `all of` over nothing is true for every event ever seen, and the rule did not mean that. |

`sigma_parse_all` refuses the whole ruleset when one rule in it does not
compile, for the same reason: a ruleset that loads 43 of its 44 rules is a
ruleset you believe covers something it does not.

## What is supported

**Search identifiers.** A mapping of field tests (AND-ed), a list of mappings
(OR-ed), or a list of keywords, matched against every value the event carries
wherever it sits. A field whose value is a list is OR-ed unless `|all`.

**Conditions.** `and`, `or`, `not`, parentheses, bare identifiers, and the
quantifiers `all of them`, `1 of them`, `any of selection*`, `N of selection*`.
A list of conditions is OR-ed, as the spec says. Identifier patterns are
resolved when the rule compiles, so `all of filter_optional_*` knows which
filters it covers before an event ever arrives.

**Value modifiers.**

| | |
|---|---|
| `contains`, `startswith`, `endswith` | anchoring. An unmodified value is the *whole* field. |
| `all` | every value in the list has to hold, not just one |
| `cased` | case-sensitive. Everything else is case-insensitive, as Sigma specifies. |
| `re`, with `i` / `m` / `s` | a regular expression instead of wildcards |
| `base64`, `base64offset` | the value as it appears encoded; `base64offset` covers all three byte offsets |
| `utf16`, `utf16le`, `utf16be`, `wide` | the value as it sits in memory before encoding |
| `windash` | `-enc`, `/enc`, and the three Unicode dashes Windows also accepts |
| `cidr` | the field is an address inside the network |
| `lt`, `lte`, `gt`, `gte` | numeric comparison |
| `exists` | the field is present, or is not |
| `fieldref` | the field equals another field of the same event |

Values carry Sigma's `*` and `?` wildcards. A backslash escapes `*`, `?` and
itself, and is a plain backslash before anything else — which is why
`Image|endswith: '\powershell.exe'` works as written and a path wildcard is
`'*\cmd.exe'` or `'C:\\*\\cmd.exe'`, never `'C:\*\cmd.exe'` (that asks for a
literal asterisk).

## Field names, and why there is no mapping file

A Sigma rule names fields in its source's own taxonomy: `Image`, `CommandLine`,
`EventID`. A Mutant event carries the normalized envelope — `kind`, `ts`,
`category` and the rest — and keeps the parser's entry verbatim under `extra`.

So a field is looked up on the event first, then inside `extra`. That is the
whole mapping layer, and it is enough: a rule written for Windows process
creation runs against an EVTX artifact Mutant parsed, with no field-mapping
configuration in between, because the field it wants is sitting in `extra` under
the name the rule already uses. Dotted names traverse
(`winlog.event_data.TargetUserName`), and a key that literally contains dots
wins over the traversal, because that is what the event says it is called.

## The question a Sigma backend does not answer

Both `sigma_match` and `sigma_scan` report the fields a rule read that the
evidence did not carry — `fields_missing` on one event, `unmatched_fields`
across a scan.

This is the difference between two results that otherwise look identical:

- the rule looked at `CommandLine` and disagreed with what it found
- the rule read `CommandLine` and the timeline has no such field

The first is a clean host. The second is a rule that never ran, written down as
a clean host. A ruleset pointed at an artifact that does not carry its fields
will return zero hits and be perfectly correct about it, and that zero means
nothing at all.

```
let report, err = sigma_scan(rules, events);
putln("hits:", report["matched"], "of", report["rules"], "rules");
if (len(report["unmatched_fields"]) > 0) {
  putln("[warn] no event carried:", report["unmatched_fields"]);
};
```

## End to end

```
let evtx, err   = evtx_parse("evidence/Security.evtx");
let events, err = events_from(evtx, "evtx");
let source, err = fs_read("rules/windows.yml");
let rules, err  = sigma_parse_all(source);
let report, err = sigma_scan(rules, events);

for (hit in report["hits"]) {
  putln(hit["level"], hit["title"], "->", hit["event"]["iso"]);
}
```

`examples/detection/sigma_rules.mut` is this shape, runnable. Compiled and run
through the CLI it prints, among the rest:

```
scanned 3 events against 2 rules
hits: 2 by level: {high: 1, medium: 1}
   high | Encoded PowerShell Command Line | event 0 | 2026-03-01T09:14:02Z
   medium | Service Installed | event 1 | 2026-03-01T09:14:40Z
fields no event carried: []
```

Both rules there name fields (`CommandLine`, `EventID`) that the events carry
only inside `extra`, which is the mapping layer doing its one job.

Every hit carries the event it fired on, so review does not need a second
lookup, and the event is still an `events_from` event — which means
`ecs_event`, `ocsf_event` and `timesketch_event` will render the hits for
whatever reads them next. See [INTERCHANGE_SCHEMAS.md](INTERCHANGE_SCHEMAS.md).

## Where this fits

Rules are declarative and Mutant is not; that has not changed, and
[COMPARISON.md](COMPARISON.md) still says what a rule is better at. What has
changed is that expressing a detection as a rule no longer means leaving the
language to run it. The parsing, the timeline, the correlation and the matching
are one script, and the rule is reviewable and shareable exactly as it was
written — because it *is* the rule, not a translation of one.
