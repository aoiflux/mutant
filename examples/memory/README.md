# Memory Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/memory/memory_forensics_example.mut --password <password>
mutant examples/memory/memory_forensics_example.mu --dev --password <password>
```

Scripts:
- memory_forensics_example.mut
- memory_scan_to_detection.mut

Notes:
- Some scripts use examples/data or root fixtures in examples.
