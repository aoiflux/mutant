# Registry Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/registry/persistence_triage_commands.mut --password <password>
mutant examples/registry/persistence_triage_commands.mu --dev --password <password>
```

Scripts:
- persistence_triage_commands.mut
- registry_forensics_example.mut
- registry_persistence_hunt.mut

Notes:
- Some scripts use examples/data or root fixtures in examples.
