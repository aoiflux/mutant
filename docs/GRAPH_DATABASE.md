# Graph Database

The `db_*` builtins embed a property graph database in the mutant runtime for
modeling entities and the relationships between them: people and documents in
a knowledge graph, or processes, files, and network endpoints in a forensic
artifact graph built up while investigating an incident. Graphs are opened
either in memory or on disk, referenced afterward by an integer handle, and
support typed nodes and edges, named relations, forensic artifact nodes with
indexed attributes, breadth-first traversal, shortest-path search, and basic
storage statistics.

All `db_*` builtins are fallible and follow the language convention of
returning `(result, err)`; destructure with `let value, err = ...` and check
`err` before using `value`.

---

## Capability table

| Builtin | Signature | Returns |
| --- | --- | --- |
| `db_open` | `()` | in-memory graph database handle |
| `db_open_disk` | `(path)` | disk-backed graph database handle |
| `db_close` | `(db)` | `true` on success |
| `db_add_node` | `(db, nodeType?)` | new node ID |
| `db_add_artifact` | `(db, type, attrs?)` | `{node_id, artifact_type, indexed_props}` |
| `db_add_edge` | `(db, from, to, edgeType?)` | new edge ID |
| `db_add_relation` | `(db, from, to, relation)` | `{edge_id, src, dst, relation, created}` |
| `db_index_prop` | `(db, nodeID, key, value)` | `true` on success |
| `db_query` | `(db)` | array of DATA-type node IDs (alias for `db_query_nodes` with no filter) |
| `db_query_nodes` | `(db, nodeType?)` | array of node IDs, optionally filtered to one type |
| `db_bfs` | `(db, origin, depth, direction)` | `{nodes, edges}` — arrays of IDs reached |
| `db_shortest_path` | `(db, from, to)` | array of node IDs from `from` to `to` |
| `db_stats` | `(db)` | `{nodes, edges, has_storage, ...}` |
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
backend. Always release a handle with `db_close` when done with it.

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
older mutant builds cannot open — see [Statistics & maintenance](#5-statistics--maintenance)
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

`db_add_relation(db, from, to, relation)` links two existing node IDs — plain
nodes or an artifact's `node_id` — with a string relation label. All four
arguments are required, and it too returns a hash rather than a bare edge ID:

```
let file, err = db_add_artifact(db, "file", {"path": "C:/Users/Public/updater.ps1"});
if (err) { putln("[error] db_add_artifact: ", err); };
let file_id = file["node_id"];

let rel, err = db_add_relation(db, proc_id, file_id, "writes");
if (err) { putln("[error] db_add_relation: ", err); };
putln("relation: ", rel["relation"], " created=", rel["created"]);
```

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

There is no `db_*` builtin that queries nodes back out by an indexed
property value — indexing feeds the graph's own storage/index layer, not a
lookup builtin exposed to mutant scripts. If a script needs to find a node
again by a key it indexed, keep its own hash from that key to the node ID
for the life of the run, built with `set` (which returns a new hash rather
than mutating in place, since index-assignment on an existing hash value is
not supported):

```
let ip_index = {};
ip_index = set(ip_index, "192.168.1.4", ip_node);
// later: ip_index["192.168.1.4"] holds the node ID
```

---

## 4. Traversal & pathfinding

`db_bfs(db, origin, depth, direction)` walks outward from `origin` up to
`depth` hops; `direction` is `"in"`, `"out"`, or `"both"`. It returns a hash
of two arrays — `nodes` and `edges` — holding every ID it reached.
`db_shortest_path(db, from, to)` returns the path as an ordered array of node
IDs from `from` to `to`; if no path exists it returns a non-null `err`
rather than an empty array, so check `err` first.

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
} else {
    putf("hops: ", len(path) - 1);
    putln("");
};
```

`db_add_relation` walks through `db_add_edge` under the hood, so relation
edges show up in `db_bfs` and `db_shortest_path` the same as plain edges do.

---

## 5. Statistics & maintenance

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
speed with no error to signal it. There is currently no `db_*` builtin a
mutant script can call to trigger compaction itself — watch these fields via
`db_stats` and plan maintenance accordingly. When a store is compacted, it is
rewritten in a newer on-disk format that older mutant builds cannot open, so
account for that in any deployment that mixes build versions against the
same graph file.

`db_timeline(db)` returns the chronological list of timeline events recorded
for the graph — but only events from `db_add_artifact` (`{action:
"add_artifact", node_id, artifact_type}`) and `db_add_relation` (`{action:
"add_relation", src, dst, relation, edge_id}`). Plain `db_add_node` /
`db_add_edge` calls are not recorded on the timeline.

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
- **No query-expression language.** `db_query` / `db_query_nodes` return
  node IDs filtered only by type; there is no `db_*` builtin to query nodes
  by an indexed property value, and no filter/predicate syntax. Reach for
  `db_query_nodes` plus `db_bfs` / `db_shortest_path` to narrow a result set
  programmatically, and keep your own ID index in a mutant hash (built with
  `set`, since hash index-assignment is not supported) if you need to look a
  node back up by a value you indexed.
- **`db_timeline` only sees `db_add_artifact` and `db_add_relation`.** Plain
  `db_add_node` / `db_add_edge` calls do not produce timeline entries.
- **Disk compaction has no script-level trigger.** `db_stats` exposes the
  figures that show a disk-backed store is due for compaction
  (`delta_records`, `wal_bytes`), but no `db_*` builtin performs it from
  mutant code. When a store is compacted, it is rewritten in a newer
  on-disk format that older mutant builds cannot open.
