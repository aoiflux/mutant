# Structured Data: The Formats Evidence Arrives In

Mutant scripts spend most of their time moving data between "shapes":
text off the wire, bytes on disk, and the hashes/arrays/scalars a script
actually computes with. This branch's structured-data toolkit covers that
whole path:

1. **JSON** — the backbone format. Parse arbitrary JSON text into nested
   mutant hashes/arrays/scalars, walk and transform them with the ordinary
   collection builtins, and serialize the result back out.
2. **Encoding** — base64 / base64url / base32 / hex / URL-escaping, for
   moving text and bytes through transports that don't like raw binary.
3. **Compression** — gzip and zlib, for shrinking JSON payloads before they
   hit disk or the network.
4. **Numeric bases & type conversion** — arbitrary-base integers, and safe
   coercion between strings, ints, floats, and bools.
5. **Apple plist** — read binary (`bplist00`) or XML property lists straight
   into a mutant hash.
6. **Everything that is not JSON** — CSV/TSV, XML, YAML (including
   multi-document streams), TOML, NDJSON/JSONL, CBOR, MessagePack, and
   schemaless walkers for protobuf and DER/ASN.1. Section 7.

Every fallible builtin here follows the language convention of returning
`(result, err)`; destructure with `let value, err = ...` and check `err`
before touching `value`. A few return a bare value with no error path —
those are called out in the tables below.

---

## 1. JSON

| Builtin | Signature | Returns |
| --- | --- | --- |
| `json_parse` | `(text)` | `(value, err)` — nested hashes/arrays/scalars |
| `json_stringify` | `(value)` | `(text, err)` |

`json_parse` accepts any valid JSON text: an object, an array, or a bare
scalar. JSON objects become mutant hashes (string keys only), JSON arrays
become mutant arrays, and numbers become `INTEGER` or `FLOAT` depending on
whether the literal looked whole or fractional. `json_stringify` is the
inverse — it walks a mutant value (hash, array, string, integer, float,
bool, null) and produces compact JSON text. Struct values are stringified
using their field names as JSON object keys too.

---

## 2. Encoding

Encoders return the encoded **string** directly (no error path — the input
is always representable). Decoders return `(bytes, err)`, since the input
text might not actually be valid in that encoding.

| Builtin | Signature | Returns |
| --- | --- | --- |
| `base64_encode` | `(s)` | encoded string |
| `base64_decode` | `(s)` | `(bytes, err)` |
| `base64url_encode` | `(s)` | encoded string |
| `base64url_decode` | `(s)` | `(bytes, err)` |
| `base32_encode` | `(s)` | encoded string |
| `base32_decode` | `(s)` | `(bytes, err)` |
| `hex_encode` | `(s)` | encoded string |
| `hex_decode` | `(s)` | `(bytes, err)` |
| `url_encode` | `(s)` | encoded string (query-escaped) |
| `url_decode` | `(s)` | `(bytes, err)` |

---

## 3. Compression

Compressors return a **byte string** directly; decompressors return
`(bytes, err)` since the input might not be a valid gzip/zlib stream.

| Builtin | Signature | Returns |
| --- | --- | --- |
| `gzip` | `(s)` | compressed byte string |
| `gunzip` | `(s)` | `(bytes, err)` |
| `zlib_compress` | `(s)` | compressed byte string |
| `zlib_decompress` | `(s)` | `(bytes, err)` |

---

## 4. Numeric base conversion

| Builtin | Signature | Returns |
| --- | --- | --- |
| `to_base` | `(n, base)` | digit string (`base` 2–36) |
| `from_base` | `(s, base)` | `(n, err)` (`base` 2–36) |

---

## 5. Type conversion

| Builtin | Signature | Returns |
| --- | --- | --- |
| `to_int` | `(v)` | `(int, err)` |
| `to_float` | `(v)` | `(float, err)` |
| `to_bool` | `(v)` | `(bool, err)` |
| `to_string` | `(v)` | string (no error) |
| `parse_int` | `(s, base)` | `(int, err)` (`base` 0 or 2–36; 0 = infer from prefix like `0x`) |
| `parse_float` | `(s)` | `(float, err)` |
| `type_of` | `(v)` | object type name string (`"INTEGER"`, `"STRING"`, `"ARRAY"`, `"HASH"`, ...) |
| `is_null` | `(v)` | bool |

`to_int`/`to_float`/`to_bool` accept ints, floats, bools, and strings, and
coerce between them (e.g. `to_int("42")`, `to_bool(0)`); `parse_int`/
`parse_float` only accept strings, and `parse_int` additionally lets you
pick the numeric base explicitly.

---

## 6. Apple plist

| Builtin | Signature | Returns |
| --- | --- | --- |
| `plist_parse` | `(path)` | `(value, err)` |

Reads a file from disk and auto-detects binary (`bplist00`) vs. XML plist
format. `dict` becomes a hash, `array` becomes an array, and scalars map
onto the obvious mutant types; dates and `data` blobs both come back as
strings (see [Notes & limits](#notes--limits)).

---

## 7. Text and binary formats beyond JSON

Forensic input is mostly not JSON. A SIEM export is CSV, a Scheduled Task is
XML, a Sigma ruleset is a multi-document YAML file, Zeek writes NDJSON, a COSE
token is CBOR, and a certificate extension is DER. All of these decode through
one shared bridge, so a byte string is a `BYTES` buffer and a timestamp is an
RFC 3339 string no matter which format it came from.

Every parse builtin accepts `BYTES` **or** `STRING`, because evidence reaches a
program either way — `fs_read_bytes` and `zip_read_bytes` hand back buffers,
`fs_read` hands back text — and neither should need a conversion first.

### 7.1 Tables and markup

| Builtin | Signature | Returns |
| --- | --- | --- |
| `csv_parse` | `csv_parse(data, options?)` | `(rows, err)` — one hash per row, keyed by the header |
| `csv_stringify` | `csv_stringify(rows, options?)` | `(text, err)` |
| `xml_parse` | `xml_parse(data)` | `(root, err)` — `{name, namespace, attrs, text, children}` |
| `xml_find` | `xml_find(node, selector)` | `(nodes, err)` |

`csv_parse` options: `delimiter` (default `","`), `comment`, `header` (default
`true`), `trim_space`, `lazy_quotes`. `csv_stringify` options: `delimiter`,
`header`, `columns`, `crlf`. An unknown option key is refused by name rather
than ignored — `{"headers": true}` would otherwise run and silently return
positional arrays.

Three things `csv_parse` refuses to guess at:

- A **UTF-8 BOM** is stripped. Excel and PowerShell's `Export-Csv` both write
  one, so without this the first column is named `<BOM>Timestamp` and every
  lookup of `Timestamp` misses — silently, since a missing key is not an error.
- **Duplicate column names** are refused rather than resolved. First-wins,
  last-wins and auto-rename each silently answer a question only the analyst
  can; `header: false` reads the file either way.
- **Ragged rows** are accepted, but fields beyond the header go into an
  `_extra` array rather than off the end. (A column literally named `_extra` is
  rejected, with an explanation.)

`xml_find`'s selector language is three rules, not XPath: a name matches an
element, `*` matches any single level, and `**` matches any number of levels
including none — so `"**/Command"` finds a direct child as well as a deep one.
A partial XPath that quietly disagrees with a real one on a predicate would be
worse than a small language that does not pretend.

`xml_parse` is safe against the two classic XML attacks by construction: the
decoder is left with no entity table, so an undeclared entity fails at the
reference instead of expanding (billion laughs), and Go's `encoding/xml` never
fetches a SYSTEM identifier (XXE). Comments, processing instructions and
directives are skipped. Declared charsets `utf-8`, `us-ascii`, `windows-1252`,
`cp1252`, `iso-8859-1`, `latin1`, `iso-8859-15` and `windows-1251` are decoded;
anything else fails **by name**, because a document silently misdecoded is
worse than one that will not open.

### 7.2 Streams and configuration

| Builtin | Signature | Returns |
| --- | --- | --- |
| `ndjson_parse` | `ndjson_parse(data)` | `(values, err)` — one per line |
| `ndjson_stringify` | `ndjson_stringify(values)` | `(text, err)` |
| `yaml_parse` | `yaml_parse(data)` | `(value, err)` — the **first** document |
| `yaml_parse_all` | `yaml_parse_all(data)` | `(documents, err)` |
| `yaml_stringify` | `yaml_stringify(value)` | `(text, err)` |
| `toml_parse` | `toml_parse(data)` | `(table, err)` |
| `toml_stringify` | `toml_stringify(value)` | `(text, err)` |

`yaml_parse_all` is not a convenience. A Sigma ruleset is one file of
`---`-separated documents, and `yaml_parse` returns only the first — silently.
Reach for `yaml_parse` when you know there is one document and
`yaml_parse_all` when you do not.

`ndjson_parse` skips blank lines and reports a malformed line **with its line
number** rather than truncating the stream at the first bad record.
`ndjson_stringify` ends every record with a newline, including the last, so its
output concatenates with another stream.

TOML datetimes become RFC 3339 strings, so they sort against every other
timestamp the language produces. `toml_stringify` requires a `HASH` or `STRUCT`
at the top level — a TOML document is a table, and there is no other shape.

`yaml_stringify` and `toml_stringify` write a `BYTES` buffer as hex, matching
`Inspect` and `json_stringify`; `string_to_bytes(s, "hex")` converts it back.

### 7.3 Binary serializations

| Builtin | Signature | Returns |
| --- | --- | --- |
| `cbor_parse` | `cbor_parse(data)` | `(value, err)` |
| `cbor_encode` | `cbor_encode(value)` | `(bytes, err)` |
| `msgpack_parse` | `msgpack_parse(data)` | `(value, err)` |
| `msgpack_encode` | `msgpack_encode(value)` | `(bytes, err)` |
| `protobuf_parse` | `protobuf_parse(data)` | `(fields, err)` |
| `der_parse` | `der_parse(data)` | `(nodes, err)` |

CBOR and MessagePack both distinguish a byte string from a text string, and
both decode the former to a `BYTES` buffer. Encoding is **deterministic** —
canonical CBOR, and sorted map keys with compact integers for MessagePack — so
`hash_sha256(cbor_encode(v))` is a stable identifier for `v` rather than for
one particular walk of a map.

CBOR tags are preserved rather than dropped: an unrecognised tag becomes
`{"_cbor_tag": n, "value": ...}`, because tag 18 is a COSE_Sign1 and losing it
would turn a signed structure into an anonymous array. The standard time tags
are the exception — those resolve to an RFC 3339 string like every other
timestamp. Integer map keys are supported, since COSE labels its keys that way,
and duplicate keys are refused.

`msgpack_parse` reports trailing bytes rather than ignoring them: a blob that
decodes and then keeps going is either a stream or not what it was thought to
be, and silently returning the first value hides both.

**`protobuf_parse` and `der_parse` are schemaless on purpose.** An analyst
holding a blob from a packet capture or a certificate extension has neither the
`.proto` nor the ASN.1 module, and Go's `encoding/asn1` unmarshals into a struct
the caller has already written — the one thing they cannot supply.

`protobuf_parse` therefore reports *every* reading the bytes admit. Each field
carries `{field, wire_type, offset}` plus:

- a varint as `value`, `zigzag` and `bool`;
- a fixed32/fixed64 as `value` and `float`;
- a length-delimited field as `value` (bytes) and `length`, plus `text` when
  the payload is printable UTF-8 and `message` when it parses as a nested
  message.

Naming the ambiguity is the honest thing a schemaless reader can do.

`der_parse` walks structure. Each node carries `{offset, header_len, length,
class, tag, constructed, tag_name}`; a constructed node carries `children`, and
a primitive carries raw `value` bytes plus, for universal-class tags, a
`decoded` rendering: OIDs dotted, `PrintableString`/`UTF8String`/`IA5String`/
`BMPString` as text, `UTCTime`/`GeneralizedTime` as RFC 3339, and INTEGERs as
an `INTEGER` when they fit and as **decimal text** when they do not — a
20-byte certificate serial reduced to its low 64 bits is a different serial.
BER indefinite length is refused by name; DER forbids it.

## Examples

### 6.1 Parsing nested JSON and reading deep fields

A realistic API response: a top-level object with metadata and a list of
record objects, each holding its own nested object.

```
let payload = "{" +
    "\"status\":\"ok\"," +
    "\"page\":1," +
    "\"records\":[" +
        "{\"id\":1,\"name\":\"alice\",\"roles\":[\"admin\",\"ops\"],\"meta\":{\"active\":true,\"score\":91.5}}," +
        "{\"id\":2,\"name\":\"bob\",\"roles\":[\"ops\"],\"meta\":{\"active\":false,\"score\":42.0}}" +
    "]" +
"}";

let parsed, err = json_parse(payload);
if (err) {
    putln("[parse error]", err);
} else {
    putln("status:", parsed["status"]);

    // Deep field access: array within object within object.
    let first_record = parsed["records"][0];
    putln("first record name:", first_record["name"]);
    putln("first record active:", first_record["meta"]["active"]);
    putln("first record score:", first_record["meta"]["score"]);

    // Iterate and pull out one field per record.
    let names = map(parsed["records"], fn(r) { return r["name"]; });
    putln("all names:", names);

    // Filter on a nested field, then re-serialize just the matches.
    let active_only = filter(parsed["records"], fn(r) { return r["meta"]["active"]; });
    let active_json, err2 = json_stringify(active_only);
    if (err2) {
        putln("[stringify error]", err2);
    } else {
        putln("active records (round-tripped):", active_json);
    };
};
```

### 6.2 Transforming a parsed structure

Add a computed field, rename a key, drop a field, and build a fresh array —
then serialize the result.

```
let record = { "id": 7, "name": "carol", "score": 88 };

// add: a derived field.
let with_grade = set(record, "grade", "B+");

// rename: copy under the new key, delete the old one.
let with_full_name = set(with_grade, "full_name", get(with_grade, "name", ""));
let renamed = delete(with_full_name, "name");

// merge: apply a batch of overrides in one step.
let overrides = { "score": 91, "reviewed": true };
let final_record = merge(renamed, overrides);

let out, err = json_stringify(final_record);
if (err) {
    putln("[stringify error]", err);
} else {
    putln("transformed record:", out);
};

// Build a brand-new array of summaries from a list of records.
let records = [
    { "id": 1, "score": 91 },
    { "id": 2, "score": 42 },
    { "id": 3, "score": 77 }
];
let summaries = map(records, fn(r) {
    let passed = r["score"] > 60;
    return { "id": r["id"], "passed": passed };
});
let summaries_json, err2 = json_stringify(summaries);
if (err2) {
    putln("[stringify error]", err2);
} else {
    putln("summaries:", summaries_json);
};
```

### 6.3 Encoding round-trips

```
let blob = "{\"user\":\"alice\",\"token\":\"s3cr3t\"}";

// base64: safe for embedding JSON in text-only channels (headers, URLs, etc).
let b64 = base64_encode(blob);
putln("base64:", b64);
let back, err = base64_decode(b64);
if (err) {
    putln("[base64_decode error]", err);
} else {
    putln("round-trip ok:", back == blob);
};

// hex: useful for logging/debugging raw bytes.
let hexed = hex_encode(blob);
putln("hex:", hexed);
let unhexed, err2 = hex_decode(hexed);
if (err2) {
    putln("[hex_decode error]", err2);
} else {
    putln("round-trip ok:", unhexed == blob);
};

// url_encode: safe query parameters from arbitrary text.
let query_value = url_encode("alice smith & co");
putln("encoded query param:", query_value);
let decoded_value, err3 = url_decode(query_value);
if (err3) {
    putln("[url_decode error]", err3);
} else {
    putln("decoded query param:", decoded_value);
};

// gzip: shrink a large JSON payload before writing/sending it.
let big_records = [];
for (let i = 0; i < 500; i = i + 1) {
    let updated, err4 = push(big_records, { "id": i, "name": "record-" + to_string(i) });
    big_records = updated;
}
let big_json, err5 = json_stringify(big_records);
if (err5) {
    putln("[json_stringify error]", err5);
} else {
    let compressed = gzip(big_json);
    putln("original bytes:", len(big_json));
    putln("compressed bytes:", len(compressed));   // conceptually much smaller

    let restored, err6 = gunzip(compressed);
    if (err6) {
        putln("[gunzip error]", err6);
    } else {
        putln("gunzip round-trip ok:", restored == big_json);
    };
};
```

### 6.4 Safe type conversion from external input

Treat anything that came from JSON, a file, or user input as a string until
it's been explicitly converted, and always check the error.

```
let raw_fields = { "age": "34", "rating": "4.5", "verbose": "not-a-bool" };

let age, err = to_int(raw_fields["age"]);
if (err) {
    putln("[to_int error]", err);
} else {
    putln("age:", age);
};

let rating, err2 = parse_float(raw_fields["rating"]);
if (err2) {
    putln("[parse_float error]", err2);
} else {
    putln("rating:", rating);
};

// parse_int with an explicit base — handy for hex/octal/binary input.
let hex_value, err3 = parse_int("1f", 16);
if (err3) {
    putln("[parse_int error]", err3);
} else {
    putln("0x1f as int:", hex_value);
};

// A field that fails to convert cleanly.
let verbose, err4 = to_bool(raw_fields["verbose"]);
if (err4) {
    putln("[to_bool error]", err4, "- falling back to false");
    verbose = false;
};
putln("verbose:", verbose);

// type_of / is_null for dynamic dispatch over a parsed JSON value.
let describe = fn(v) {
    if (is_null(v)) {
        return "null";
    };
    let t = type_of(v);
    return t;
};
putln("type of age:", describe(age));
putln("type of raw_fields:", describe(raw_fields));
```

### 6.5 Reading an Apple plist

```
let plist_path = "example_output/structured_data/Info.plist";
let info, err = plist_parse(plist_path);
if (err) {
    putln("[plist_parse error]", err);
} else {
    let bundle_id = get(info, "CFBundleIdentifier", "");
    let version = get(info, "CFBundleShortVersionString", "");
    putln("bundle id:", bundle_id);
    putln("version:", version);

    // Nested access, same as any other mutant hash/array.
    let url_types = get(info, "CFBundleURLTypes", []);
    if (len(url_types) > 0) {
        let first_scheme = url_types[0]["CFBundleURLSchemes"][0];
        putln("first URL scheme:", first_scheme);
    };
};
```

---

## Notes & limits

- **JSON number typing.** `json_parse` distinguishes integers from floats by
  looking at the literal itself: `5` decodes to `INTEGER`, `5.0` decodes to
  `FLOAT`. Round-tripping through `json_stringify` preserves that shape.
  Numbers too large for a 64-bit integer, or with an exponent/decimal point,
  decode as `FLOAT`.
- **Object keys must be strings.** `json_stringify` fails (returns a non-null
  `err`) if a hash contains a non-`STRING` key — JSON objects have no other
  key type.
- **Byte strings vs. text.** Mutant has a real `BYTES` type. The formats in
  section 7 that distinguish binary from text — CBOR, MessagePack, DER —
  decode it to a buffer. The older decoders (`base64_decode`, `gunzip`,
  `plist_parse`'s `data` fields) still return `STRING` values that may contain
  arbitrary bytes rather than printable text; each has a `*_bytes` companion
  (`base64_decode_bytes`, `gunzip_bytes`, ...) that returns a buffer instead,
  and `string_to_bytes(s, "raw")` converts losslessly from any of them.
- **Decoders and decompressors always return `(value, err)`.** Because the
  input might not actually be valid base64/hex/gzip/etc., always check
  `err` before using the result — unlike the encoders/compressors, which
  cannot fail on well-formed string input.
- **plist dates and data become strings.** `plist_parse` doesn't introduce a
  separate date type: binary plist dates are formatted as RFC 3339 strings,
  and both binary and XML `data` elements are decoded to raw bytes and
  returned as a `STRING` (same byte-string caveat as above).
- **`to_base`/`from_base` are 64-bit and base 2–36.** `to_base` never fails
  (any `INTEGER` is representable); `from_base` fails if the string has
  digits outside the given base or overflows 64 bits.
