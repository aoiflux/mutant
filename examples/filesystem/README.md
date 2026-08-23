# Filesystem Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/filesystem/dependency_version_auditor.mut --password <password>
mutant examples/filesystem/dependency_version_auditor.mu --dev --password <password>
```

Scripts:
- dependency_version_auditor.mut
- fs_example.mut
- fs_forensics_example.mut
- fs_integrity_baseline.mut

Notes:
- Some scripts use examples/data or root fixtures in examples.
