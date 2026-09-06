# Mutant Cookbook

Recipes organised by the question you are actually asking, not by which builtin
category the answer happens to live in. Each one is a whole program you can
paste into a file and run, followed by its real output.

New to the language? Read **[Mutant in 30 minutes](TUTORIAL_30_MIN.md)** first —
it covers the compile / run two-step, the `(value, err)` convention, and the
traps that bite everyone once. The full catalogue of builtins is
[CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md); this file is the other half
of that pair, showing them in combination.

## The sample case

Every recipe below runs against the same small evidence set, so you can work
through them in order:

- `case/invoice.pdf.exe` — 4 KiB, starts with `MZ`, body is random data
- `case/update.dat` — 8 KiB of random data
- `case/notes.txt`, `case/hosts.bak` — small text files
- `case/svchost.exe` — any real executable; the outputs below used a Go binary
- `auth.log` — a handful of syslog lines covering an ssh brute force, a
  successful login, a `curl` to an attacker host, and an outbound connection
- `unallocated.bin` — ~6.8 KiB of random bytes with a PNG, a ZIP header, a PE
  header and a second PNG embedded at known offsets

Two of the recipes read fixtures that ship with the repository, so you can run
them unchanged: [`examples/data/autoruns_hive.json`](../examples/data/autoruns_hive.json)
(recipe 7) and [`examples/data/phish.eml`](../examples/data/phish.eml)
(recipe 9). Both are synthetic — no real host or mailbox data.

Run each recipe the usual way — compile, then run:

```bash
mutant recipe.mut     # writes recipe.mu
mutant recipe.mu      # runs it
```

Add `--dev` to both while you are iterating; it uses the built-in development
key so you are not typing a password on every edit. Real artifacts get a real
password.

---

# Part 1 — A file landed. What is it?

## 1. What is this file, really?

The extension is a claim made by whoever named the file. The header is
evidence. `fs_magic` reads the header, `fs_hash` gives you something to search
for, and `bin_entropy` says whether the contents are compressed, encrypted or
packed.

```mutant
let target = "case/invoice.pdf.exe";

let magic, merr = fs_magic(target);
if (merr) { putln("[error] fs_magic:", merr); };
let digest, herr = fs_hash(target, "sha256");
if (herr) { putln("[error] fs_hash:", herr); };
let ent, eerr = bin_entropy(target);
if (eerr) { putln("[error] bin_entropy:", eerr); };

putf("path     %s\n", target);
putf("claims   %s\n", "PDF (by extension)");
putf("actually %s (%s)\n", magic["type"], magic["mime"]);
putf("size     %d bytes\n", digest["size"]);
putf("sha256   %s\n", digest["hash"]);
putf("entropy  %.3f\n", ent["entropy"]);
```

```
path     case/invoice.pdf.exe
claims   PDF (by extension)
actually pe (application/vnd.microsoft.portable-executable)
size     4112 bytes
sha256   2579a3b96db26145b55510cb3561029fadc5b56529d943a56b2f4022474ac46a
entropy  7.956
```

**Reading it.** Entropy runs 0–8 bits per byte. English prose sits near 4.5, an
ordinary PE around 6, and anything above 7.5 is compressed, encrypted or packed
— 7.956 over 4 KiB means essentially no structure at all.

**The field is `hash`, not the algorithm name.** `fs_hash(p, "sha256")` returns
`{algo, bytes, hash, path, size, status}`. `digest["sha256"]` is not an error;
it is `null`, and prints as nothing. The digest is under `hash` whichever
algorithm you asked for.

## 2. Have I seen this file before?

Most files on a host are boring. The fastest way to shrink an evidence set is
to subtract everything you already know. `hashset_load` reads one hash per
line, or NSRL/CSV where the hash is the first field, skipping comments and
headers for you.

```mutant
let known, lerr = hashset_load("known_good.txt");
if (lerr) { putln("[error] hashset_load:", lerr); };
putf("loaded %d known-good hashes\n\n", known["count"]);

let files = ["case/notes.txt", "case/invoice.pdf.exe", "case/update.dat"];
each(files, fn(path) {
    let d, err = fs_hash(path, "sha256");
    if (err) { putln("[error]", path, err); return; };
    let seen, serr = hashset_contains(known["handle"], d["hash"]);
    if (serr) { putln("[error]", path, serr); return; };
    let verdict = "UNKNOWN -- triage this";
    if (seen) { verdict = "known good"; };
    putf("%-24s %s\n", path, verdict);
});

hashset_close(known["handle"]);
putln("");
putln("done");
```

```
loaded 2 known-good hashes

case/notes.txt           known good
case/invoice.pdf.exe     UNKNOWN -- triage this
case/update.dat          UNKNOWN -- triage this

done
```

Comparison is case-insensitive, so a set of uppercase NSRL hashes matches
Mutant's lowercase digests without you normalising anything.

## 3. It is an executable. What is inside it?

```mutant
let target = "case/svchost.exe";

let pe, perr = bin_pe_parse(target);
if (perr) { putln("[error] bin_pe_parse:", perr); };
putf("format      %s\n", pe["format"]);
putf("machine     0x%x\n", pe["machine"]);
putf("compiled    %s\n", time_format(pe["timestamp"], "2006-01-02 15:04:05 UTC"));
putf("sections    %d\n", pe["num_sections"]);

let go, gerr = bin_is_go(target);
if (gerr) { putln("[error] bin_is_go:", gerr); };
putf("toolchain   go %s  buildinfo=%t build_id=%t pclntab=%t\n",
     go["go_version"], go["has_buildinfo"], go["has_build_id"], go["has_pclntab"]);

let sec, serr = bin_sections(target);
if (serr) { putln("[error] bin_sections:", serr); };
putln("");
each(sec["sections"], fn(s) {
    putf("  %-10s addr=0x%-8x size=%d\n", s["name"], s["addr"], s["size"]);
});
```

```
format      pe
machine     0x8664
compiled    1970-01-01 00:00:00 UTC
sections    8
toolchain   go 1.26.2  buildinfo=true build_id=false pclntab=false

  .text      addr=0x1000     size=13747200
  .rdata     addr=0xd1e000   size=18840064
  .data      addr=0x1f16000  size=1466880
  .pdata     addr=0x481c000  size=305152
  .xdata     addr=0x4867000  size=512
  .idata     addr=0x4868000  size=1536
  .reloc     addr=0x4869000  size=306176
  .symtab    addr=0x48b4000  size=512
```

**That 1970 date is a finding, not a bug.** The PE timestamp field is zero.
Go's linker zeroes it so builds are reproducible, and several other toolchains
and packers do the same. A zero compile timestamp tells you something about how
the binary was produced; it does not tell you it was built in 1970.

**`bin_is_go` reports three signals separately on purpose.** Here the build
info blob is present but the Go build ID and the pclntab are not — what a
partially stripped Go binary looks like. `is_go` collapses the three into an
answer; the three fields tell you how much to trust it. The pclntab is the
signal that survives stripping, so its absence is worth noticing.

Use `bin_elf_parse` / `bin_macho_parse` for the other formats, `bin_imports`
for the import table, and `bin_dwarf_parse` when symbols survived.

## 4. Find a known indicator inside a file nothing will parse

```mutant
let rules = ["update.svc-cdn.top", "185.220.101.44", "/tmp/a.sh"];

let hit, err = bin_yara_scan("auth.log", rules, true);
if (err) { putln("[error] bin_yara_scan:", err); };

putf("engine=%s  rules matched=%d/%d  total hits=%d\n\n",
     hit["engine"], hit["matched"], len(rules), hit["total_hits"]);

each(hit["hits"], fn(h) {
    let offsets = str_join(map(h["offsets"], fn(o) { return to_string(o); }), ", ");
    putf("%-22s x%-3d at byte %s\n", h["rule"], h["count"], offsets);
});
```

```
engine=literal-substring  rules matched=3/3  total hits=6

update.svc-cdn.top     x1   at byte 498
185.220.101.44         x3   at byte 64, 159, 258
/tmp/a.sh              x2   at byte 394, 465
```

**This is not a YARA engine.** The name is a nod to the shape of the problem;
the implementation is a literal multi-string scan, because a real YARA engine
needs cgo and Mutant is pure Go. It takes literal strings, not YARA rule
syntax, and there are no conditions, wildcards or modules. What it does give
you is every offset of every hit, which is what you want when the next step is
carving. `matched` is the **number of rules** that hit, not a boolean.

For structure rather than strings, `fs_carve(path, type)` scans for known
artifact signatures and reports the offsets where they begin. It reports
offsets only — it does not extract the artifact or work out its length.

---

# Part 2 — A directory arrived. Where do I look first?

## 5. Which of these files deserve attention?

```mutant
let entries, werr = fs_walk("case", 2);
if (werr) { putln("[error] fs_walk:", werr); };

// fs_walk returns directories too -- is_dir is there so you can drop them.
let files = filter(entries, fn(e) { return !e["is_dir"]; });
let paths = map(files, fn(e) { return e["path"]; });

let report, derr = detect_suspicious_files(paths);
if (derr) { putln("[error] detect_suspicious_files:", derr); };

putf("%d files walked, %d flagged\n\n", len(paths), report["count"]);

each(report["hits"], fn(h) {
    putf("%s\n", h["path"]);
    putf("    type     %s\n", h["type"]);
    putf("    entropy  %.3f\n", h["entropy"]);
    putf("    reasons  %s\n", str_join(h["reasons"], ", "));
});
```

```
5 files walked, 2 flagged

case\invoice.pdf.exe
    type     pe
    entropy  7.956
    reasons  very_high_entropy, double_extension
case\update.dat
    type     unknown
    entropy  7.978
    reasons  very_high_entropy
```

**Filter `is_dir` before you pass paths to anything.** `fs_walk` returns the
root and every directory under it alongside the files. Hand a directory to
`fs_hash` and you get a read error rather than a hash. Each entry already
carries `depth`, `is_dir`, `mod_time`, `name`, `path` and `size`, so you rarely
need a second `fs_stat`.

`reasons` is a list because a file can be suspicious in several ways at once,
and the combination is what matters: high entropy alone is a zip file; high
entropy *and* a double extension is a delivery.

## 6. The same question, over thousands of files

`pmap` runs the function on many elements at once and returns results in the
original order. Each worker is a whole VM with its own stack and a *snapshot*
of the globals, so nothing is shared and nothing needs a lock.

```mutant
let entries, werr = fs_walk("case", 2);
if (werr) { putln("[error] fs_walk:", werr); };
let paths = map(filter(entries, fn(e) { return !e["is_dir"]; }), fn(e) { return e["path"]; });

let started, terr = time_ms();
if (terr) { putln("[error] time_ms:", terr); };

// Each worker is a whole VM with a snapshot of globals, so fn must be
// self-contained: it cannot assign back to anything outside itself.
let rows = pmap(paths, fn(p) {
    let d, err = fs_hash(p, "sha256");
    if (err) { return {"path": p, "size": 0, "sha256": "-- " + to_string(err)}; };
    return {"path": p, "size": d["size"], "sha256": d["hash"]};
}, 8);

let now, terr2 = time_ms();
if (terr2) { putln("[error] time_ms:", terr2); };

each(sort_by(rows, fn(r) { return (0 - r["size"]); }), fn(r) {
    putf("%12d  %s  %s\n", r["size"], str_substr(r["sha256"], 0, 16), r["path"]);
});
putf("\n%d files hashed in %dms across 8 workers\n", len(rows), (now - started));
```

```
    34673153  5084cf4bc9fa88c4  case\svchost.exe
        8192  b35c760764208b27  case\update.dat
        4112  2579a3b96db26145  case\invoice.pdf.exe
          56  4be5303ed3457ebe  case\notes.txt
          54  a4d5991111669291  case\hosts.bak

5 files hashed in 34ms across 8 workers
```

**The worker function must be self-contained.** Assigning to a global inside it
writes to that worker's snapshot and is lost when the worker exits. Return the
result — as `pmap` does here — or write through a shared store (`cache_*`,
`db_*`). `peach` is the same thing for side effects, returning nothing.

**Sorting descending.** There is no `sort_desc`; negate the key, as
`fn(r) { return (0 - r["size"]); }` does. `sort_by` is stable, so ties keep
their original order.

---

# Part 3 — A host. What is set to run?

## 7. Hunt persistence in the registry

`reg_open` dispatches on what you hand it: a regf hive file (`SOFTWARE`,
`SYSTEM`, `NTUSER.DAT`) is parsed as a hive, a hive-JSON file is read as JSON,
and anything else is treated as a live Windows registry path. The program below
is identical in all three cases — only the string changes. It runs against
[`examples/data/autoruns_hive.json`](../examples/data/autoruns_hive.json) so you
can reproduce it on any platform; point it at
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` on a live Windows host and
the same code reads the real thing.

```mutant
let source = "autoruns_hive.json";

let hive, err = reg_open(source);
if (err) { putln("[error] reg_open:", err); };
putf("source_type=%s  status=%s\n\n", hive["source_type"], hive["status"]);

let run = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
let vals, verr = reg_enum_values(hive["handle"], run);
if (verr) { putln("[error] reg_enum_values:", verr); };

putln("autoruns");
each(vals, fn(v) {
    let data = v["data"];
    let suspicious = "";
    if (text_contains(str_lower(data), "appdata")) { suspicious = "  <-- runs from AppData"; };
    putf("  %-16s %s%s\n", v["name"], data, suspicious);
});

let gone, gerr = reg_deleted_keys(hive["handle"]);
if (gerr) { putln("[error] reg_deleted_keys:", gerr); };
putln("");
putln("deleted keys (unallocated cells)");
each(gone, fn(k) { putf("  %s\n", k); });

let events, terr = reg_timeline(hive["handle"]);
if (terr) { putln("[error] reg_timeline:", terr); };
putln("");
putln("registry writes");
each(events, fn(e) {
    putf("  %s  %s %s\n", e["timestamp"], e["action"], e["name"]);
});

reg_close(hive["handle"]);
putln("");
putln("done");
```

```
source_type=json  status=ok

autoruns
  OneDrive         "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background
  SecurityHealth   %windir%\system32\SecurityHealthSystray.exe
  UpdateSvc        C:\Users\deploy\AppData\Roaming\svc.exe -q  <-- runs from AppData

deleted keys (unallocated cells)
  HKLM\Software\Microsoft\Windows\CurrentVersion\Run\StagerV1

registry writes
  2026-03-14T02:12:55Z  set_value UpdateSvc
  2026-03-14T02:13:10Z  set_value Cleanup

done
```

**`reg_deleted_keys` and `reg_timeline` are only populated for the JSON
source.** A real hive file and the live registry both return empty arrays —
there is no unallocated-cell carving behind this API, and the builtins say so
in their own documentation rather than returning a plausible nothing. When you
need deleted keys out of a real hive, that is a different tool's job today.

**Key paths are absolute for the JSON source and relative to the opened key for
hive files and the live registry.** That is the one behaviour that does *not*
carry across the three sources.

Once you have execution evidence rather than just configuration:
`amcache_parse` reads `Amcache.hve`, `shimcache_parse` decodes the
AppCompatCache out of a `SYSTEM` hive or a raw blob, and `prefetch_parse`
handles `.pf` files.

---

# Part 4 — Logs, mail and network traffic

## 8. Pull the indicators out of a log

```mutant
let raw, err = fs_read("auth.log");
if (err) { putln("[error] fs_read:", err); };

let iocs = extract_iocs(raw);

putln("external addresses");
each(filter(iocs["ipv4"], fn(ip) { return !ip_is_private(ip); }), fn(ip) {
    putf("  %s\n", defang(ip));
});

putln("");
putln("callback hosts (registrable domain)");
let hosts = unique(map(iocs["urls"], fn(u) { return domain_extract(u); }));
each(hosts, fn(h) {
    let parts = tld_extract(h);
    putf("  %-28s etld+1=%s  suffix=%s\n", defang(h), defang(parts["etld1"]), parts["suffix"]);
});

putln("");
putln("file hashes seen in the log");
each(concat(concat(iocs["md5"], iocs["sha1"]), iocs["sha256"]), fn(h) {
    putf("  %s\n", h);
});
```

```
external addresses
  185[.]220[.]101[.]44
  91[.]219[.]236[.]18

callback hosts (registrable domain)
  update[.]svc-cdn[.]top       etld+1=svc-cdn[.]top  suffix=top

file hashes seen in the log
  6f1ed002ab5595859014ebf0951522d9
```

**`extract_iocs` refangs before it matches**, so `hxxp://update.svc-cdn[.]top`
in the source log is found as a URL without you doing anything. Everything it
returns is already unique and sorted.

**Prefer `domain_extract` over `iocs["domains"]`.** The domain matcher is
deliberately greedy and reports anything shaped like `label.tld` — including
path fragments such as `a.sh` and filenames such as `svc.exe`. Taking hostnames
out of `iocs["urls"]` gives you hosts that were genuinely contacted, which is
the better question anyway.

**`ip_is_private` covers RFC1918, loopback and link-local**, which is the
filter you want before enriching addresses against anything external.

## 9. Reconstruct an email attack chain

One message carries the whole first stage: who sent it, whether the sending
domain authorised them, what it wanted you to click, and what it dropped.
Runs against [`examples/data/phish.eml`](../examples/data/phish.eml).

```mutant
let raw, err = fs_read("phish.eml");
if (err) { putln("[error] fs_read:", err); };

let msg, perr = email_parse(raw);
if (perr) { putln("[error] email_parse:", perr); };
putf("from     %s\n", msg["from"]);
putf("to       %s\n", msg["to"]);
putf("subject  %s\n", msg["subject"]);
putf("date     %s\n", msg["date"]);

let auth, aerr = email_spf_dkim(raw);
if (aerr) { putln("[error] email_spf_dkim:", aerr); };
putln("");
putf("from domain   %s\n", defang(auth["from_domain"]));
putf("spf           %s (%s)\n", auth["spf"], auth["spf_source"]);
putf("dkim          %s (signature present: %t)\n", auth["dkim"], auth["dkim_signature_present"]);
putf("dmarc         %s (dkim aligned: %t)\n", auth["dmarc"], auth["dkim_aligned"]);

let urls, uerr = email_urls(raw);
if (uerr) { putln("[error] email_urls:", uerr); };
putln("");
putln("links");
each(urls, fn(u) {
    putf("  %-12s %s\n", u["scheme"], defang(u["url"]));
});

let atts, terr = email_attachments(raw);
if (terr) { putln("[error] email_attachments:", terr); };
putln("");
putln("attachments");
each(atts, fn(a) {
    putf("  %-18s %d bytes\n", a["filename"], a["size"]);
    putf("  %-18s sha256 %s\n", "", a["sha256"]);
});
```

```
from     "Accounts Payable" <billing@svc-cdn.top>
to       <finance@example.org>
subject  Invoice INV-88214 overdue - action required
date     Sat, 14 Mar 2026 02:09:38 +0000

from domain   svc-cdn[.]top
spf           fail (authentication_results)
dkim          none (signature present: false)
dmarc         fail (dkim aligned: false)

links
  http         hxxp://update[.]svc-cdn[.]top/portal/INV-88214

attachments
  invoice.pdf.exe    128 bytes
                     sha256 bfdf5e72651b4ec588bd5fc6a9f17e9e0972248146bbacc10478f48d72f29b81
```

That attachment sha256 is the handle for recipe 2: look it up in a hash set,
and if it is unknown, recipe 1 tells you what it actually is.

**`spf_source` tells you where the verdict came from.** SPF cannot be
re-evaluated after the fact — it is a check the *receiving* MTA performed at
delivery time — so Mutant reports what the MTA recorded and names the header it
read it from. DKIM is different: the signature is in the message, so
`email_spf_dkim` verifies it cryptographically, fetching the public key by DNS.
That means this one builtin touches the network where the rest of the family
does not.

**`email_urls` returns hashes, not strings** — `{host, scheme, url}` per link,
already normalised. Feed `host` to `tld_extract` and you are in recipe 10.

## 10. Which of these domains is impersonating ours?

```mutant
let ours = "svc-cdn.com";
let seen = ["svc-cdn.top", "svc-cdn.com", "svccdn.com", "svc-cdn.com.co", "microsoft.com"];

putln("candidate                score  registrable        verdict");
each(seen, fn(d) {
    let parts = tld_extract(d);
    let score = text_jaro_winkler(ours, d);
    let verdict = "-";
    if (d != ours) {
        if (score > 0.85) { verdict = "LOOKALIKE"; };
    };
    if (d == ours) { verdict = "ours"; };
    putf("%-24s %.3f  %-18s %s\n", defang(d), score, defang(parts["etld1"]), verdict);
});
```

```
candidate                score  registrable        verdict
svc-cdn[.]top            0.927  svc-cdn[.]top      LOOKALIKE
svc-cdn[.]com            1.000  svc-cdn[.]com      ours
svccdn[.]com             0.979  svccdn[.]com       LOOKALIKE
svc-cdn[.]com[.]co       0.957  svc-cdn[.]com[.]co LOOKALIKE
microsoft[.]com          0.530  microsoft[.]com    -
```

**`tld_extract` uses the real public suffix list**, which is why
`svc-cdn.com.co` comes back with `com.co` as the suffix and the whole thing as
the registrable domain — the classic trick of hiding your brand's `.com` in
front of a foreign second-level suffix. Splitting on the last dot gets that
wrong.

Jaro-Winkler weights a shared prefix heavily, which suits typosquats (`svccdn`,
`svc-cdns`) but not homoglyph or keyboard-adjacency attacks. Reach for
`text_levenshtein` when you want edit distance, and treat the threshold — 0.85
here — as something you tune against your own domain list, not a constant.

## 11. Is that traffic beaconing?

Malware calling home looks regular in a way human traffic does not.
`detect_network_beacon` scores the *coefficient of variation* of the gaps
between connections, and of the transfer sizes, per destination.

```mutant
let flows = [
    {"dst": "91.219.236.18:8443", "ts": 1741918800, "bytes": 812},
    {"dst": "91.219.236.18:8443", "ts": 1741919100, "bytes": 796},
    {"dst": "91.219.236.18:8443", "ts": 1741919401, "bytes": 804},
    {"dst": "91.219.236.18:8443", "ts": 1741919699, "bytes": 799},
    {"dst": "91.219.236.18:8443", "ts": 1741920002, "bytes": 810},
    {"dst": "104.18.32.7:443", "ts": 1741918811, "bytes": 40122},
    {"dst": "104.18.32.7:443", "ts": 1741918903, "bytes": 1877},
    {"dst": "104.18.32.7:443", "ts": 1741919655, "bytes": 92014},
    {"dst": "104.18.32.7:443", "ts": 1741921002, "bytes": 3311}
];

let result, err = detect_network_beacon(flows);
if (err) { putln("[error] detect_network_beacon:", err); };

putf("beaconing detected: %t\n\n", result["detected"]);
each(result["hits"], fn(h) {
    putf("%s\n", h["dst"]);
    putf("    score       %d (%s confidence)\n", h["score"], h["confidence"]);
    putf("    interval    %.1fs mean, cv=%.4f\n", h["interval_mean_s"], h["interval_cv"]);
    putf("    size        cv=%.4f over %d flows\n", h["bytes_cv"], h["count"]);
    putf("    reasons     %s\n", str_join(h["reasons"], ", "));
});
```

```
beaconing detected: true

91.219.236.18:8443
    score       100 (medium confidence)
    interval    300.5s mean, cv=0.0069
    size        cv=0.0085 over 5 flows
    reasons     regular_interval, consistent_size
```

The CDN destination in the same input is not reported: its intervals and
transfer sizes vary the way real browsing does. Five flows is enough to score
but not enough to be sure, which is what `confidence: medium` beside
`score: 100` is telling you — the score is how regular the pattern is, the
confidence is how much evidence there was. `ts` accepts epoch seconds or
RFC3339.

---

# Part 5 — A disk image, or the space between the files

## 12. Carve artifacts out of unallocated space

`fs_carve` scans a file for a known header signature and reports every offset
where one starts. That file can be a disk image, a memory dump, a pagefile, or
a blob of unallocated space you pulled out of one.

```mutant
let image = "unallocated.bin";

each(["png", "zip", "pe", "sqlite"], fn(kind) {
    let found, err = fs_carve(image, kind);
    if (err) { putf("%-8s %s\n", kind, err); return; };
    if (len(found) == 0) { putf("%-8s none\n", kind); return; };
    let offsets = map(found, fn(h) { return to_string(h["offset"]); });
    putf("%-8s %d at byte %s\n", kind, len(found), str_join(offsets, ", "));
});
```

```
png      2 at byte 1024, 6770
zip      1 at byte 3146
pe       1 at byte 4362
sqlite   none
```

**It reports offsets, and only offsets.** It does not extract the artifact and
it does not work out where it ends — a header signature says where something
begins, and nothing more. To recover the bytes, take the offset and read
forward: `fs_read_bytes` for the whole file then `bytes_slice`, or a
`bytes_cursor` if you want to walk the structure and find the real end
yourself.

An unsupported type is an error, not an empty result, and the message lists
every type it does know:

```
ERROR:fs_carve: unsupported type `docx`. supported: 7z, bmp, bzip2, cab, elf,
evtx, flac, gif, gzip, ico, jpeg, lnk, lz4, macho32, macho32le, macho64,
macho64le, macho_universal, matroska, mp3, mp4, ogg, ole, pcap_be, pcap_le,
pcapng, pdf, pe, png, prefetch_mam, psd, rar, regf, riff, rtf, sqlite, tar,
tiff_be, tiff_le, xz, zip, zstd
```

(wrapped here; it is one line in the terminal, and carries the source position
and `context=builtin.fs_carve` at the end)

For a whole image with a filesystem still on it, the parsers are a better
starting point than carving: `ntfs_*`, `fat_*`, `ext_*`, `hfs_*`, `xfs_*` and
`xfat_*` read the filesystem, `ewf_*` / `vhdi_*` / `raw_*` read the container,
and `fs_deleted` and `mft_*` recover what the filesystem still remembers.
Carving is what you do for the space they no longer describe.

---

# Part 6 — Putting it together

## 13. One timeline from several sources

```mutant
let ssh = map(["2026-03-14T02:11:44Z", "2026-03-14T02:14:59Z"], fn(s) {
    let ts, err = time_parse(s, "2006-01-02T15:04:05Z");
    if (err) { putln("[error] time_parse:", err); };
    return {"ts": ts, "source": "auth.log", "what": "ssh accepted for deploy"};
});

let net = [
    {"ts": 1773454384, "source": "netflow", "what": "outbound 91.219.236.18:8443"}
];

let files = [
    {"ts": 1773454351, "source": "fs", "what": "/tmp/a.sh created"}
];

let all = timeline_merge([ssh, net, files]);
each(all, fn(e) {
    putf("%s  %-9s %s\n", time_format(e["ts"], "2006-01-02 15:04:05"), e["source"], e["what"]);
});
```

```
2026-03-14 02:11:44  auth.log  ssh accepted for deploy
2026-03-14 02:12:31  fs        /tmp/a.sh created
2026-03-14 02:13:04  netflow   outbound 91.219.236.18:8443
2026-03-14 02:14:59  auth.log  ssh accepted for deploy
```

**Layouts are Go reference layouts**, not `strftime`: the pattern is the fixed
date `Mon Jan 2 15:04:05 MST 2006` written the way you want your input read.
`2006-01-02T15:04:05Z` reads an ISO-8601 timestamp; `%Y-%m-%d` reads nothing.

**Normalise to epoch seconds as you parse.** `timeline_merge` and
`timeline_sort` both sort on a numeric field (`ts` by default, or one you name),
and events missing that field sort last rather than throwing. Convert once, at
the edge, and everything downstream is comparable.

## 14. Hand the result to the next tool

```mutant
let entries, werr = fs_walk("case", 2);
if (werr) { putln("[error] fs_walk:", werr); };
let paths = map(filter(entries, fn(e) { return !e["is_dir"]; }), fn(e) { return e["path"]; });

let report, derr = detect_suspicious_files(paths);
if (derr) { putln("[error] detect_suspicious_files:", derr); };

// One JSON object per line: greppable, and every log pipeline already reads it.
each(report["hits"], fn(h) {
    let d, herr = fs_hash(h["path"], "sha256");
    let row = {
        "tool": "mutant",
        "case": "INC-4471",
        "path": h["path"],
        "sha256": d["hash"],
        "file_type": h["type"],
        "entropy": h["entropy"],
        "reasons": h["reasons"]
    };
    let line, jerr = json_stringify(row);
    if (jerr) { putln("[error] json_stringify:", jerr); return; };
    putln(line);
});

// CSV for the people who want it in a spreadsheet.
let header = "path,sha256,type,entropy,reasons";
let lines = map(report["hits"], fn(h) {
    let d, herr = fs_hash(h["path"], "sha256");
    return str_join([h["path"], d["hash"], h["type"], to_string(h["entropy"]),
                     "\"" + str_join(h["reasons"], ";") + "\""], ",");
});
let csv = (str_join(concat([header], lines), "\n") + "\n");
let ok, werr2 = fs_write("findings.csv", csv);
if (werr2) { putln("[error] fs_write:", werr2); };
putf("\nwrote findings.csv (%d rows)\n", len(lines));
```

```
{"case":"INC-4471","entropy":7.9556017088764905,"file_type":"pe","path":"case\\invoice.pdf.exe","reasons":["very_high_entropy","double_extension"],"sha256":"2579a3b96db26145b55510cb3561029fadc5b56529d943a56b2f4022474ac46a","tool":"mutant"}
{"case":"INC-4471","entropy":7.97789779649468,"file_type":"unknown","path":"case\\update.dat","reasons":["very_high_entropy"],"sha256":"b35c760764208b274bc73eda8467cf325b93f8c27b6f2fa1ec9d608c46515e19","tool":"mutant"}

wrote findings.csv (2 rows)
```

`json_stringify` sorts hash keys, so a diff between two runs shows what changed
rather than what got reordered. There is no CSV writer — quoting rules vary too
much between the tools that consume it — so build the line yourself and pick
your own quoting, as above.

To ship the analysis to someone who does not have Mutant installed, see
[§7 of the tutorial](TUTORIAL_30_MIN.md): `mutant gen` produces the Go program,
`mutant release` produces a signed standalone binary for a named target.

---

# Traps

Every one of these was hit while writing the recipes above.

**The program's last value is printed.** Whatever the final statement evaluates
to lands on stdout, so a program ending in `hashset_close(handle);` prints a
stray `true`, and one ending in `let _ = 2 + 3;` prints `5`. Intermediate
statements are not printed — only the last. End with `putln(...)` and nothing
extra appears. An error in that position is deliberately expanded with its
position, which is usually what you want.

**Binding one name to a fallible builtin keeps the pair.** `let t = time_ms();`
binds `t` to a `MULTI_VALUE`, and the failure surfaces later and elsewhere:

```
vm error:
	vm_runtime_error ip=114 op=OpSub: unsupported types for binary operation: MULTI_VALUE, MULTI_VALUE
	  11 | let elapsed = (time_ms() - started);
	     |                ^^^^^^^^^^^^^^^^^^^
```

Write `let t, err = time_ms();`. The convention is not uniform — `push`,
`first`, `last`, `rest` and `len` return a single value, and destructuring
those splits the value instead of handing you an error. `mutant lint` has a
rule for it.

**A missing hash key is `null`, not an error.** `digest["sha256"]` prints
nothing at all rather than complaining. When a field comes back empty, check
the spelling against the return shape in
[CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md) before you believe the
value.

**`putf` formats are Go's**, and a wrong verb is reported inline rather than
raised: `%s` on an integer prints `%!s(int64=34404)`, `%t` on an integer prints
`%!t(int64=3)`. If your output has `%!` in it, the format string is wrong, not
the data. `%d` for integers, `%.3f` for floats, `%t` for booleans, `%x` for
hex.

**Read the return shape, do not guess it.** `bin_yara_scan`'s `matched` is a
count of rules, not a boolean. `bin_sections` gives each section `addr`, `name`
and `size` — no entropy. `detect_suspicious_files` returns
`{count, detected, hits}`, with the per-file records under `hits`. When in
doubt, `putln(keys(result));` or `json_stringify` the whole thing once.

**Windows paths come back with backslashes**, and they survive into JSON as
`\\`. That is correct JSON and consumers unescape it — but if you compare paths
as strings across platforms, normalise first.

---

## Where to go next

- **[Mutant in 30 minutes](TUTORIAL_30_MIN.md)** — install to standalone binary
- **[CAPABILITY_REFERENCE.md](CAPABILITY_REFERENCE.md)** — all 457 builtins,
  with signatures and return shapes
- **[MUTANT_LANGUAGE_REFERENCE.md](MUTANT_LANGUAGE_REFERENCE.md)** — syntax and
  semantics
- **[Why Mutant, and when not to](COMPARISON.md)** — how this compares with
  plaso, Velociraptor, osquery and a YARA+Sigma pipeline
- **`examples/`** — 104 runnable programs, including `examples/workshop/` for
  guided exercises and `examples/forensics/supertimeline.mut` for a longer
  timeline build
