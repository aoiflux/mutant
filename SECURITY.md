# Security Policy

Mutant is a language for security research and digital forensics. Its binaries
sign and encrypt bytecode, detect tampering, and read memory, processes and disk
images. That combination means "is this a vulnerability?" has a sharper answer
here than in most projects, so this document says where the line is before
asking you to judge it.

## Reporting a vulnerability

**Use GitHub private vulnerability reporting.** Go to the
[Security tab](https://github.com/aoiflux/mutant/security/advisories/new) of this
repository and open a draft advisory. It is private to the maintainers until
published.

Do not open a public issue, pull request, or discussion for a security report.
Do not post a proof of concept anywhere public before the advisory is published.

A useful report contains:

- the affected version (`mutant --version`) and platform;
- what an attacker gains, in one sentence;
- a minimal reproducer — a `.mut` source, a `.mu` artifact, or a crafted image
  file. Attach files to the advisory rather than pasting hex;
- whether it reproduces under `--compat` as well as the default `--secure`.

**What to expect:**

| Stage                             | Target                         |
| --------------------------------- | ------------------------------ |
| Acknowledgement                    | 3 business days                |
| Initial assessment (in scope? severity?) | 10 business days         |
| Fix or a dated plan                | 30 days for high and critical  |
| Coordinated public disclosure      | 90 days, or on release, sooner if agreed |

Reporters are credited in the advisory and in [CHANGELOG.md](CHANGELOG.md)
unless you ask not to be.

## Supported versions

Security fixes land on the latest released minor version. There are no
long-term-support branches.

| Version | Supported |
| ------- | --------- |
| 2.4.x   | ✅ current |
| 2.3.x and earlier | ❌ upgrade |

## In scope

Anything that breaks a promise the toolchain makes to the person running it:

- **Artifact integrity** — producing a `.mu` or standalone binary that passes
  signature verification without the trusted signer's key; re-signing a modified
  artifact so tamper detection stays silent; downgrade or replay of an older
  artifact past a check meant to reject it.
- **Fail-open in secure mode.** `--secure` is fail-closed by design. Any input
  that turns a verification failure into a successful run is a vulnerability,
  including malformed artifacts that make a check error out and get skipped.
- **Confidentiality of the payload.** Recovering plaintext bytecode or constants
  from an artifact at rest without the password, or from a core dump / swap /
  crash report of a running process, beyond what §"Not in scope" allows.
- **Credential handling.** Any path that writes a password to disk, argv, an
  environment block, or a log. See
  [docs/CONFIGURATION_POLICY.md](docs/CONFIGURATION_POLICY.md) §4.
- **The Lua sandbox.** A `.mut` program's embedded Lua reaching the filesystem,
  network, or host process outside the executor's documented surface.
- **Memory safety of the VM and the parsers.** A crafted `.mu`, disk image,
  registry hive, EVTX log, SQLite database or PE file that drives the VM or a
  forensic parser into an out-of-bounds read, an unbounded allocation, or a
  panic that escapes as anything other than a Mutant error. Forensic input is
  hostile by definition — a parser that trusts a length field is a bug, not a
  limitation.
- **Path handling.** Traversal or symlink following that lets a parsed artifact
  write outside the directory the operator named.
- **The language server.** `mlsp` parses untrusted source from an editor;
  anything that turns opening a file into code execution is in scope.
- **Supply chain.** A compromised or unexpected dependency, a released binary
  whose hash does not match its provenance, or a build script that fetches code
  at build time.

## Not in scope

These are known and deliberate. Reporting them is not useful; they will be
closed as documented behaviour.

**The obfuscation ceiling.** Encrypted bytecode, polymorphic emission, anti-debug
and anti-tamper raise the cost of analysis. They do not make it impossible, and
they are not claimed to.
[docs/SECURITY_LLD.md](docs/SECURITY_LLD.md) §2.2 states the non-objectives
plainly: no malware-grade anti-debug resistance (not achievable in pure
userland), no hardware root of trust, no remote attestation. Someone holding the
binary, the password and a debugger will reach the bytecode. That is the
threat model, not a hole in it.

**Adversaries above the process.** Kernel-level arbitrary memory write,
hypervisor introspection, and physical attacks on hardware secrets are out of
scope for the current release
([docs/SECURITY_LLD.md](docs/SECURITY_LLD.md) §3.2).

**A program doing what its author wrote.** Mutant's standard library reads
process memory, enumerates handles, scans remote hosts and parses raw disks
because that is the job. A `.mut` script using those builtins is the tool
working. Running an untrusted `.mut` file is equivalent to running an untrusted
executable, and the toolchain does not currently claim otherwise. *Capability
configuration is under design; no interface is specified.*

**Weaker modes behaving weakly.** `--compat` and `--dev` deliberately downgrade
verification and tamper response so that debugging and analysis are possible.
A check that `--secure` enforces and `--compat` does not is the documented
difference between them.

**Antivirus detections.** Mutant binaries carry anti-debug, anti-tamper,
process scanning and polymorphic bytecode — the behavioural signature of packed
malware. False positives are expected and are not vulnerabilities. If a scanner
flags a release binary, please open a normal issue with the vendor and detection
name so it can be submitted for allowlisting; `--compat` disables the protections
that trip heuristics in an analysis lab.

**Findings from a scanner, unreproduced.** A CVE in a transitive dependency that
no Mutant code path reaches, or a static-analysis hit with no demonstrated
impact, needs a reproducer before it is a report.

## Safe harbour

Research conducted in good faith under this policy — testing against your own
systems and your own artifacts, not accessing other people's data, not degrading
anyone's service, and giving us the disclosure window above — is welcome, and we
will not pursue or support action against you for it. This is a statement of
intent from the maintainers, not legal advice, and it cannot waive third
parties' rights.

## Further reading

- [docs/SECURITY_LLD.md](docs/SECURITY_LLD.md) — objectives, threat model, and
  the implementation-accurate design.
- [docs/BINARY_ARTIFACT_SECURITY_DEEP_DIVE.md](docs/BINARY_ARTIFACT_SECURITY_DEEP_DIVE.md)
  — signing, signer trust, and the runtime decision matrix.
- [docs/SECURITY_RUNBOOK.md](docs/SECURITY_RUNBOOK.md) — operational posture.
- [docs/SANDBOX_DETECTION.md](docs/SANDBOX_DETECTION.md) — what the detection
  probes read and what they may do about it.
- [docs/CONFIGURATION_POLICY.md](docs/CONFIGURATION_POLICY.md) — why nothing is
  configured through the environment.
