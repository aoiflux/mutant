# Graph Database

The `db_*` builtins embed a property graph database in the mutant runtime for
modeling entities and the relationships between them: people and documents in
a knowledge graph, or processes, files, and network endpoints in a forensic
artifact graph built up while investigating an incident. Graphs are opened
either in memory or on disk, referenced afterward by an integer handle, and
support typed nodes and edges, named relations, forensic artifact nodes with
indexed attributes, reading any of it back by value, breadth-first traversal,
shortest-path search, a schema and index check, and storage statistics.

All `db_*` builtins are fallible and follow the language convention of
returning `(result, err)`; destructure with `let value, err = ...` and check
`err` before using `value`.

---

## Capability table

| Builtin | Signature | Returns |
| --- | --- | --- |
| `db_open` | `()` | in-memory graph database handle |
| `db_open_disk` | `(path, opts?)` | disk-backed graph database handle; `opts` is `{memory_budget, discover_memory_budget, verify_on_open, read_only}` |
| `db_close` | `(db)` | `true` on success |
| `db_add_node` | `(db, nodeType?)` | new node ID |
| `db_add_artifact` | `(db, type, attrs?)` | `{node_id, artifact_type, indexed_props}` |
| `db_add_edge` | `(db, from, to, edgeType?)` | new edge ID |
| `db_add_relation` | `(db, from, to, relation, attrs?)` | `{edge_id, src, dst, relation, created, indexed_props}` |
| `db_index_prop` | `(db, nodeID, key, value)` | `true` on success |
| `db_query` | `(db)` | array of DATA-type node IDs (alias for `db_query_nodes` with no filter) |
| `db_query_nodes` | `(db, nodeType?)` | array of node IDs, optionally filtered to one type |
| `db_find` | `(db, key, value, nodeType?)` | `{nodes, count, key_indexed}` |
| `db_node` | `(db, id)` | `{id, labels, properties, property_count, multi_valued, blob_bytes}` |
| `db_relations` | `(db, node, direction)` | `{node, direction, relations, count, unlabelled}` |
| `db_schema` | `(db)` | `{nodes, edges, node_types, edge_types, node_keys, edge_keys, relations}` |
| `db_verify` | `(db)` | `{checked, consistent, problem, values_checked}` |
| `db_bfs` | `(db, origin, depth, direction)` | `{nodes, edges}` — arrays of IDs reached, every edge crossed |
| `db_shortest_path` | `(db, from, to)` | array of node IDs from `from` to `to`, empty when not connected |
| `db_stats` | `(db)` | `{nodes, edges, has_storage, read_only, lock_free, ...}` |
| `db_compact` | `(db)` | `{has_storage, delta_records_before, delta_records_after, snapshot_root, prev_root}` |
| `db_timeline` | `(db)` | array of timeline event hashes |

`nodeType` and `edgeType` are optional integer/enum values in the range
0–127; `0` (the `DATA` tag, if you declare an `enum`) is the default used
when omitted.

---

## 1. Creating a graph

`db_open()` opens an in-memory graph — fastest option, gone when the handle
is closed or the process exits, good for one-off analysis and tests.
`db_open_disk(path)` opens or creates a graph rooted at `path`, backed by a
write-ahead log and a delta layer that periodically merges into an on-disk
CSR store; every other `db_*` builtin works identically against either
backend. Always release a handle with `db_close` when done with it; a disk
store the program forgets is closed at its end and named on stderr.

`db_open_disk` reads the directory's `graphene.labels` before opening it,
because graphene registers a store's label names for the whole process. It
refuses a table that names any of the custom labels 0-127 that `db_*` writes
without names -- a symbol graph from `mutant graph export` is one, and is read
with `mutant graph query` -- or that gives a label of the disclosure ledger's
schema another name, or that is torn. A forensic ledger is refused as well.

`db_open_disk(path, {"read_only": true})` opens an existing store without
changing it. It never creates a store -- a mistyped path is an error, not an
empty graph -- runs beside other readers, and is refused while a writer holds
the store rather than reading it mid-change. Every write through the handle is
an error. A store with no `graphene.lock`, which is how graphene's own backups
arrive, or one on write-protected media, is read without taking a lock rather
than given one, and `db_stats(db)["lock_free"]` says which and why; it is empty
when the read took a lock.

```
let db, err = db_open();
if (err) { putln("[error] db_open: ", err); };

let disk_db, err = db_open_disk("./investigation.graphdb");
if (err) { putln("[error] db_open_disk: ", err); };

// ... work with db / disk_db ...

let closed, err = db_close(db);
if (err) { putln("[error] db_close: ", err); };
let disk_closed, err = db_close(disk_db);
if (err) { putln("[error] db_close disk: ", err); };
```

Compacting a disk-backed store rewrites it in a newer on-disk format that
older mutant builds cannot open — see [Statistics & maintenance](#6-statistics--maintenance)
below.

---

## 2. Modeling entities & relationships

### Plain nodes and edges

`db_add_node` and `db_add_edge` are the primitives. A node optionally carries
an integer/enum type; an edge optionally carries one the same way. Neither
takes a property hash — use `db_add_artifact` for indexed node attributes, or
`db_index_prop` to attach one property at a time to any node.

```
enum NodeType { DATA, PERSON, DOCUMENT };
enum EdgeType { DATA, KNOWS, AUTHORED };

let db, err = db_open();
if (err) { putln("[error] db_open: ", err); };

let alice, err = db_add_node(db, NodeType.PERSON);
let bob, err = db_add_node(db, NodeType.PERSON);
let doc, err = db_add_node(db, NodeType.DOCUMENT);
if (err) { putln("[error] db_add_node: ", err); };

let e1, err = db_add_edge(db, alice, bob, EdgeType.KNOWS);
let e2, err = db_add_edge(db, alice, doc, EdgeType.AUTHORED);
if (err) { putln("[error] db_add_edge: ", err); };
```

### Forensic artifacts

`db_add_artifact(db, type, attrs?)` is the entity-modeling shortcut: it adds
a node, tags it with a string `type`, indexes every key of the optional
`attrs` hash, and returns a hash instead of a bare ID:

```
let proc, err = db_add_artifact(db, "process", {
    "pid": 4021,
    "name": "powershell.exe",
    "user": "CORP\\svc_backup"
});
if (err) { putln("[error] db_add_artifact: ", err); };
let proc_id = proc["node_id"];   // proc also carries artifact_type, indexed_props
```

### Named relations

`db_add_relation(db, from, to, relation, attrs?)` links two existing node IDs —
plain nodes or an artifact's `node_id` — with an edge that carries a string
relation label. The edge and its label land in one transaction: the label is
indexed on the edge under `relation`, which is where `db_relations` and
`db_schema` read it back, and each key of the optional `attrs` hash is stored
beside it as `attr_<key>`, exactly as `db_add_artifact` stores a node's. It
returns a hash rather than a bare edge ID:

```
let file, err = db_add_artifact(db, "file", {"path": "C:/Users/Public/updater.ps1"});
if (err) { putln("[error] db_add_artifact: ", err); };
let file_id = file["node_id"];

let rel, err = db_add_relation(db, proc_id, file_id, "writes", {"bytes": 4096});
if (err) { putln("[error] db_add_relation: ", err); };
putln("relation: ", rel["relation"], " created=", rel["created"]);
```

An empty relation, or one that is not valid UTF-8, is refused, and so is a node
that does not exist; nothing is written in any of those cases. `attrs` refuses
classified plaintext from `record_read`, as `db_add_artifact`'s does, and a key
in either hash that is not a string is an error rather than skipped.

**Stores written before 2.6.0 carry no relation labels.** `db_add_relation`
used to add a plain edge and send the label only to `db_timeline`'s journal,
which lives in the process and is gone at `db_close`. Those labels cannot be
recovered from the store. `db_relations` reports such an edge with
`relation: null` and counts it in `unlabelled`, the same as an edge `db_add_edge`
wrote.

---

## 3. Indexing properties for lookup

`db_index_prop(db, nodeID, key, value)` attaches a single indexed
`key=value` pair to any node — plain, typed, or artifact. All four arguments
are required, and `value` must be a string; stringify non-string values
first (`json_stringify` for numbers, hashes, and the like):

```
let ip_node, err = db_add_node(db);
if (err) { putln("[error] db_add_node: ", err); };
let _, err = db_index_prop(db, ip_node, "ip", "192.168.1.4");
if (err) { putln("[error] db_index_prop: ", err); };

let count_json, err = json_stringify(3);
if (err) { putln("[error] json_stringify: ", err); };
let _, err = db_index_prop(db, ip_node, "failed_logins", count_json);
if (err) { putln("[error] db_index_prop: ", err); };
```

`db_add_artifact`'s `attrs` hash is indexed the same way automatically, so
artifacts rarely need an extra `db_index_prop` call on top of it.

`db_index_prop` runs in a transaction that fails, and indexes nothing, when the
node does not exist. Indexing a key a second time **adds** a value rather than
replacing the first: after `db_index_prop(db, n, "status", "open")` and then
`"closed"`, the node holds both, and is found under either.

---

## 4. Reading a graph back

Everything above is indexed, and five builtins read it.

`db_find(db, key, value, nodeType?)` returns the nodes whose indexed `key` holds
exactly `value`, in ascending ID order, optionally restricted to one node type:

```
let found, err = db_find(db, "ip", "192.168.1.4");
if (err) { putln("[error] db_find: ", err); };
if (found["key_indexed"] == false) {
    putln("nothing in this store was ever indexed under ip");
};
putf("%d node(s) hold that ip\n", found["count"]);
```

`key_indexed` is the field to read before trusting an empty answer. graphene
answers a lookup on a key it never indexed with nothing and no error, so
`"ip"` misspelled as `"IP"` would otherwise look exactly like "no host has
that address".

`db_node(db, id)` reads one node back: its `labels` (the type numbers given to
`db_add_node`) and a `properties` hash of everything indexed on it, by
`db_add_artifact`, `db_index_prop` or anything else. Values come back as
strings, or as BYTES when they are not valid UTF-8. A key indexed more than once
holds an array of every value and is listed in `multi_valued`, rather than one
value being picked and the other hidden:

```
let node, err = db_node(db, proc_id);
if (err) { putln("[error] db_node: ", err); };
putln("pid: ", node["properties"]["attr_pid"]);
```

`db_relations(db, node, direction)` lists one node's edges in a direction --
`"out"`, `"in"` or `"both"` -- in the order they were added, each with the
`relation` it carries (or `null`), its endpoints, its type and its `attr_`
properties. `unlabelled` counts the edges with no relation.

`db_schema(db)` says what a store holds: node and edge counts by type, the
property keys its index has held, and how many edges carry each relation.
`db_verify(db)` cross-checks the indexes against the records and reports
`checked` and `consistent` separately, so a store that cannot check itself never
reads as a pass. `values_checked` is always `false`: the check covers the index's
structure, not whether an indexed value still says what the script meant.

---

## 5. Traversal & pathfinding

`db_bfs(db, origin, depth, direction)` walks outward from `origin` up to
`depth` hops; `direction` is `"in"`, `"out"`, or `"both"`, and any other word
is an error. `depth` 0 is the origin alone, and a negative depth is an error.
It returns a hash of two arrays — `nodes`, in the order reached, origin first,
and `edges` — holding every ID it reached and every edge it crossed, parallel
edges included: three relations from one process to one file are three edges.

`db_shortest_path(db, from, to)` returns the path with the fewest edges as an
ordered array of node IDs from `from` to `to`, and an empty array when the two
are not connected. It walks edges in either direction, so a path can run
against an edge; `db_bfs` with `"out"` answers what is reachable going forward.
A node that does not exist is an error for both.

Both run under the language's fixed traversal budget -- the limits are in
[LIMITS_REFERENCE.md](LIMITS_REFERENCE.md) -- and a walk that reaches it is
refused rather than cut short, so an answer is never a partial walk that reads
like a complete one.

Consider a small incident-response graph: a process that spawned a child
process, wrote a file, and the child that reached out to a network endpoint.

```
let db, err = db_open();
if (err) { putln("[error] db_open: ", err); };

let proc, err = db_add_artifact(db, "process", {"pid": 4021, "name": "powershell.exe"});
let child, err = db_add_artifact(db, "process", {"pid": 4102, "name": "cmd.exe"});
let file, err = db_add_artifact(db, "file", {"path": "C:/Users/Public/updater.ps1"});
let endpoint, err = db_add_artifact(db, "network", {"dst": "198.51.100.25", "port": 443});
if (err) { putln("[error] db_add_artifact: ", err); };

let proc_id = proc["node_id"];
let child_id = child["node_id"];
let file_id = file["node_id"];
let endpoint_id = endpoint["node_id"];

let _, err = db_add_relation(db, proc_id, child_id, "spawned");
let _, err = db_add_relation(db, proc_id, file_id, "writes");
let _, err = db_add_relation(db, child_id, endpoint_id, "connects_to");
if (err) { putln("[error] db_add_relation: ", err); };

putln("=== BFS outbound from root process, depth 2 ===");
let bfs, err = db_bfs(db, proc_id, 2, "out");
if (err) { putln("[error] db_bfs: ", err); };
putf("nodes reachable: ", len(bfs["nodes"]), "  edges traversed: ", len(bfs["edges"]));
putln("");

putln("=== Shortest path: process -> network endpoint ===");
let path, err = db_shortest_path(db, proc_id, endpoint_id);
if (err) {
    putln("[error] db_shortest_path: ", err);
} else if (len(path) == 0) {
    putln("not connected");
} else {
    putf("hops: ", len(path) - 1);
    putln("");
};
```

Relation edges are ordinary edges of the default type, so they show up in
`db_bfs` and `db_shortest_path` the same as plain edges do.

---

## 6. Statistics & maintenance

`db_stats(db)` always reports `nodes`, `edges`, and `has_storage`
(`false` for in-memory graphs, which have no delta layer, WAL, or
compaction). Disk-backed graphs report more:

| Field | Meaning |
| --- | --- |
| `nodes` / `edges` | current live counts |
| `has_storage` | `true` for disk-backed graphs |
| `delta_records` | writes sitting in the uncompacted delta layer |
| `csr_records` | records already folded into the compact CSR store |
| `deleted_nodes` / `deleted_edges` | tombstoned entries not yet reclaimed |
| `wal_bytes` | bytes in the write-ahead log awaiting merge |
| `commit_seq` | monotonically increasing commit counter |
| `last_compact` | timestamp of the last compaction |
| `read_only` | `true` for a store opened with `{"read_only": true}` (every handle reports it) |
| `lock_free` | why a read-only store was read without a lock; empty when it took one |

```
let stats, err = db_stats(db);
if (err) { putln("[error] db_stats: ", err); };
putf("nodes: ", stats["nodes"], "  edges: ", stats["edges"]);
putln("");
```

`delta_records` and `wal_bytes` that keep climbing across runs of a
long-running disk-backed graph mean compaction is overdue: everything
written since the last compaction stays in memory and is replayed on every
open, so an uncompacted store degrades in memory use, open time, and read
speed with no error to signal it.

`db_compact(db)` is what acts on those figures. It merges the delta layer
into the compact store and truncates the write-ahead log, which is what
gives the memory back.

```
let stats, err = db_stats(db);
if (err) { putln("[error] db_stats: ", err); };
if (stats["has_storage"] && stats["delta_records"] > 100000) {
  let report, err = db_compact(db);
  if (err) { putln("[error] db_compact: ", err); };
  putf("compacted: ", report["delta_records_before"], " -> ", report["delta_records_after"]);
  putln("");
};
```

It reports what it moved rather than just that it ran, because a compaction
that merged nothing and one that merged a million records both return
successfully. It also reports `snapshot_root`, the Merkle root of the image it
wrote, and `prev_root`, the root of the one it replaced: the store's identity at
that moment, which a script can record and a later check can be held to. On an in-memory handle it is a no-op and reports
`has_storage: false`, so a script that compacts on a schedule does not have
to know which kind of handle it was given.

When a store is compacted it is rewritten in a newer on-disk format that
older mutant builds cannot open, so account for that in any deployment that
mixes build versions against the same graph file. Reading is unaffected: this
build opens a store written by any earlier one.

`db_timeline(db)` returns the chronological list of timeline events recorded
for the graph — but only events from `db_add_artifact` (`{action:
"add_artifact", node_id, artifact_type}`) and `db_add_relation` (`{action:
"add_relation", src, dst, relation, edge_id}`). Plain `db_add_node` /
`db_add_edge` calls are not recorded on the timeline. The timeline lives in the
process, not the store: it is empty after a reopen, and `db_close` clears it.
The store itself is read with the builtins in [Reading a graph back](#4-reading-a-graph-back).

```
let timeline, err = db_timeline(db);
if (err) { putln("[error] db_timeline: ", err); };
putf("timeline events recorded: ", len(timeline));
putln("");
```

---

## Putting it together: a small investigation graph

Build a disk-backed graph, model a process/file/network chain as artifacts
and relations, index an extra property, traverse it, and print stats:

```
let check_err = fn(err, op) {
    if (err) {
        putln("[error] ", op, ": ", err);
    };
};

putln("=== investigation graph ===");

let db, err = db_open_disk("./example_output/investigation_graph");
check_err(err, "db_open_disk");

let proc, err = db_add_artifact(db, "process", {
    "pid": 4021,
    "name": "powershell.exe",
    "user": "CORP\\svc_backup"
});
check_err(err, "db_add_artifact process");
let proc_id = proc["node_id"];

let file, err = db_add_artifact(db, "file", {
    "path": "C:/Users/Public/updater.ps1",
    "sha256": "3fa2c1d9e4b7"
});
check_err(err, "db_add_artifact file");
let file_id = file["node_id"];

let endpoint, err = db_add_artifact(db, "network", {
    "dst": "198.51.100.25",
    "port": 443
});
check_err(err, "db_add_artifact endpoint");
let endpoint_id = endpoint["node_id"];

let _, err = db_add_relation(db, proc_id, file_id, "writes");
check_err(err, "db_add_relation writes");
let _, err = db_add_relation(db, proc_id, endpoint_id, "connects_to");
check_err(err, "db_add_relation connects_to");

let _, err = db_index_prop(db, proc_id, "hostname", "WORKSTATION07");
check_err(err, "db_index_prop hostname");

putln("");
putln("=== BFS outbound from process, depth 2 ===");
let bfs, err = db_bfs(db, proc_id, 2, "out");
check_err(err, "db_bfs");
putf("nodes reachable: ", len(bfs["nodes"]), "  edges traversed: ", len(bfs["edges"]));
putln("");

putln("");
putln("=== Shortest path: process -> network endpoint ===");
let path, err = db_shortest_path(db, proc_id, endpoint_id);
check_err(err, "db_shortest_path");
putf("hops: ", len(path) - 1);
putln("");

putln("");
putln("=== What the process touched ===");
let touched, err = db_relations(db, proc_id, "out");
check_err(err, "db_relations");
for (rel in touched["relations"]) {
    putln(rel["relation"], " -> node ", rel["dst"]);
};

putln("");
putln("=== Stats & timeline ===");
let stats, err = db_stats(db);
check_err(err, "db_stats");
putf("nodes: ", stats["nodes"], "  edges: ", stats["edges"], "  wal_bytes: ", stats["wal_bytes"]);
putln("");

let timeline, err = db_timeline(db);
check_err(err, "db_timeline");
putf("timeline events recorded: ", len(timeline));
putln("");

let closed, err = db_close(db);
check_err(err, "db_close");
if (closed) {
    putln("graph closed cleanly");
};
```

---

## Notes & limits

- **No property hashes on plain nodes or edges.** `db_add_node` and
  `db_add_edge` accept only a type, not attributes. Reach for
  `db_add_artifact` when a node needs indexed attributes, or attach them one
  at a time afterward with `db_index_prop` (values must be strings).
- **No query-expression language.** `db_find` looks nodes up by one key and
  one exact value; `db_query` / `db_query_nodes` filter by type. There is no
  filter or predicate syntax, no range or prefix match, and no conjunction of
  keys: narrow a result set in the script, with `db_node` and `db_relations`
  over the IDs `db_find` returned. A script that wants its own index can keep
  one in a hash -- `ip_index["192.168.1.4"] = ip_node;`.
- **`db_timeline` only sees `db_add_artifact` and `db_add_relation`,** and only
  in the process that wrote them. Plain `db_add_node` / `db_add_edge` calls do
  not produce timeline entries.
- **Compaction is a script's call.** `db_stats` exposes the figures that show
  a disk-backed store is due (`delta_records`, `wal_bytes`), and `db_compact`
  acts on them. A compacted store is rewritten in a newer on-disk format that
  older mutant builds cannot open.
