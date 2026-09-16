# Filesystem Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/filesystem/dependency_version_auditor.mut --dev
mutant examples/filesystem/dependency_version_auditor.mu --dev
```

Scripts:
- dependency_version_auditor.mut
- file_triage_report.mut — hash a file, identify its type, and check it against a hash set
- fs_example.mut
- fs_forensics_example.mut
- fs_integrity_baseline.mut

One per image or volume format, each opening a placeholder path so it prints
what to provide rather than inventing a result. Point them at real evidence:

- ewf_example.mut — EnCase/Expert Witness segments (`.E01`, `.E02`, …)
- ext_example.mut — ext2/ext3/ext4
- fat_example.mut — FAT12/16/32
- hfs_example.mut — HFS+
- ntfs_example.mut — NTFS
- raw_example.mut — a raw/`dd` image
- vhdi_example.mut — VHD / VHDX
- xfat_example.mut — exFAT
- xfs_example.mut — XFS

Notes:
- Some scripts use examples/data or root fixtures in examples.
