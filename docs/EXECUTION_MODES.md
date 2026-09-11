# Execution Modes

Mutant has three execution modes and one modifier. This document is the
definitive statement of what each one changes; every row below is traced to the
code that implements it.

Mutant takes no configuration from environment variables, so the command line is
the complete record of the posture a run used. See
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

## The one-sentence version

> **`--compat` weakens the response. `--dev` weakens the key.**

Compatibility mode still requires your password and still verifies the artifact.
It only declines to stop the run when a security probe fires. Developer mode
does that too, and additionally falls back to a key that is public. **An artifact
built or run under `--dev` has no confidentiality.**

## The modes

There are three, not four. `--secure` names the default; it is not a fourth
mode.

| Mode | Intent | Use it for |
| --- | --- | --- |
| **default** (`--secure`) | Ship it | Release artifacts, untrusted input, evidence handling |
| **`--compat`** | Run it where secure mode cannot | Containers, CI, VMs — anywhere a probe fires on an ordinary host |
| **`--dev`** | Edit-compile-run loop | Local development only. Never a release artifact |
| **`--signer-auth`** | A modifier, not a mode | Combine with the default wherever provenance matters |

Naming two modes on one command line is an error. `--secure --compat` and
`--secure --dev` each exit non-zero naming both flags, rather than resolving to
whichever came last. `--dev --compat` is accepted, because dev mode implies
compatibility mode — that is redundant, not contradictory — and repeating a flag
is harmless.

## What each mode actually changes

| Behaviour | **default** (`--secure`) | `--secure --signer-auth` | `--compat` | `--dev` |
| --- | --- | --- | --- | --- |
| **Signature verification** | Embedded self-verify | Ed25519 against a trusted public key | Embedded self-verify | Embedded self-verify |
| **Anti-reversing probe passes** | 2 — pre-decode and pre-execution | 2 | 1 — pre-decode only | 1 |
| **Probe outcome** | terminate, with detector and remedy | terminate | warn to stderr, continue | warn, continue |
| **Tamper response** | `terminate` | `terminate` | `warn` | `warn` |
| **VM `OpChkDbg` / `OpChkSnd`** | halt with an explanation | halt | log and continue | log and continue |
| **VM integrity check** | terminate | terminate | warn, continue | warn, continue |
| **Security dev logging** | off | off | off | on, at `--security-log-level debug\|trace` |
| **Password** | required | required | required | falls back to the built-in key, announced |

Sources: [runner/runner.go](../runner/runner.go) — signature verification and
probe passes; [security/response_policy.go](../security/response_policy.go) and
[security/profile.go](../security/profile.go) — tamper response;
[vm/vm.go](../vm/vm.go) — security opcodes and integrity checks;
[main.go](../main.go) — mode resolution, logging, password fallback.

**Security is monotonic in the mode.** The set of checks a stronger mode performs
is a superset of every weaker mode's. This was not always true: secure mode
without `--signer-auth` once matched neither verification branch and verified
nothing at all, while `--compat` self-verified — the most secure-sounding
invocation performed the fewest checks. Self-verification is now the floor in
every mode, and `--signer-auth` upgrades it.

## `--signer-auth` and `--trusted-key`

Self-verification proves internal consistency: the signature in the envelope
matches the code, under the key travelling inside the envelope. It cannot prove
who produced the artifact, because an attacker who re-signs a modified artifact
with their own key produces something that self-verifies.

`--signer-auth` upgrades verification to a trusted public key, which is what
establishes provenance. `--trusted-key <path>` names that key as a file holding
hex-encoded key material; without it, verification uses a locally bootstrapped
keypair, which trusts whatever signed the artifact on this host. Secure mode
without `--signer-auth` prints one line saying self-verification is all it did.

`--signer-auth` and `--no-signer-auth` on the same command line is an error.

## When secure mode stops the run

Secure mode terminates when a probe reports a debugger, an analysis sandbox,
injection or hooking activity in this process, or a hostile-scoring process
elsewhere on the host. A termination prints what fired and what to do:

```
[security] event=sandbox_detected stage=pre-decode action=terminate
[security] detector=sandbox type=docker confidence=90 signals=cgroup:docker,/.dockerenv
[security] reason: secure mode does not run where the host looks like an analysis sandbox
[security] remedy: re-run with --compat if this host is expected to look like this.
[security]         --compat weakens the response only: a probe hit warns instead of stopping
[security]         the run. Your password is still required and the artifact is still verified.
sandbox detected, execution halted for security
```

**A probe reports what the machine looks like**, and an ordinary container, VM or
CI runner looks enough like an analysis sandbox to trip one — which is exactly
where forensic tooling runs. `--compat` is the supported answer to that false
positive.

**The artifact events do not offer `--compat`.** A signature that does not
verify, and bytecode that fails its own integrity check, are statements about the
file rather than readings taken of the host. `--compat` would downgrade them to a
warning and run the artifact anyway, so those events name the artifact as the
thing to fix instead.

## Passwords

A password is required in every mode. The only exception is `--dev`, and only
when the command line names no password source at all: naming a source and
having it fail is an error, not a reason to reach for the development key.

`mutil.GetPwd()` — the development key — is not a prompt and not random. It is a
fixed HKDF-SHA512 derivation over three string constants compiled into the
binary, so **every Mutant binary ever built derives the identical key**. Anyone
with a copy of the binary can decrypt anything encrypted under it. Every use of
it prints:

```
[dev] no password supplied; using the built-in development key -- not for release artifacts
```

`--dev` is refused outright for `mutant release` and `mutant gen assets`.

## Choosing a posture

| Situation | Command |
| --- | --- |
| Production, trusted release artifact | `mutant prog.mu --secure --signer-auth --trusted-key <path>` |
| Production, no pinned signer yet | `mutant prog.mu --secure --signer-auth` |
| A probe fires on a container, VM or CI runner | `mutant prog.mu --compat` |
| Local development | `mutant prog.mu --dev` |

`--secure` is the default; naming it explicitly is how an incident note records
the posture unambiguously. Nothing needs resetting afterwards — a previous run
cannot leave state that changes the next one.

## See also

- [CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md) — why none of this comes
  from the environment.
- [SECURITY_RUNBOOK.md](SECURITY_RUNBOOK.md) — operating the controls.
- [SECURITY_LLD.md](SECURITY_LLD.md) — the design behind them.
- [SANDBOX_DETECTION.md](SANDBOX_DETECTION.md) — what the sandbox probe looks at.
