# Graph Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/graph/db_enums_example.mut --dev
mutant examples/graph/db_enums_example.mu --dev
```

Scripts:
- db_enums_example.mut
- db_example.mut
- db_wrappers_example.mut
- graph_detection_timeline.mut
- incident_graph.mut — model an intrusion as a graph (process to file, process to network), then traverse it
- mini_log_correlator.mut
- mini_timeline_builder.mut
