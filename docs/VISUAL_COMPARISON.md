# Visual Comparison (Current Security Model)

## 1. Detection vs Enforcement

```mermaid
flowchart LR
    A[Detector or Probe] --> B[Signal: name, detected, confidence, detail]
    B --> C[Policy Layer]
    C --> D[warn]
    C --> E[delay]
    C --> F[terminate]
```

Old confusion:

1. Signal and action were treated as the same concept.

Current model:

1. Signal generation is separate from policy action.

## 2. Probe Gates

```mermaid
flowchart TD
    A[RunAntiTamperProbe] --> B{MUTANT_ENABLE_ANTITAMPER_PROBE == 1?}
    B -->|No| C[No probe execution]
    B -->|Yes| D[Run probes]

    D --> E{Runner process-protection path?}
    E -->|No| F[Diagnostic output]
    E -->|Yes| G{MUTANT_ENABLE_PROCESS_PROTECTION enabled?}
    G -->|No| H[No enforcement]
    G -->|Yes| I[Evaluate threshold and apply policy]
```

## 3. Process Protection Scope

```mermaid
flowchart LR
    A[Runner] --> B[Focused 5-probe enforcement set]
    C[Builtins] --> D[Broader diagnostic probe sets]
```

## 4. Polymorphic Status Snapshot

```mermaid
flowchart TD
    A[Mutation level supplied] --> B[Engine engaged]
    B --> C[Marker/tagging active]
    B --> D[Advanced transforms]
    D --> E[Currently gated]
```

## 5. Memory Hardening Snapshot

```mermaid
flowchart LR
    A[VM runtime path] --> B[mutil object encrypt/decrypt flow]
    C[Additional primitives] --> D[SecureGlobal/SecureStack/SecureConstantPool]
```

## 6. Source of Truth

1. [SECURITY_DIAGRAMS](SECURITY_DIAGRAMS.md)
2. [SECURITY_LLD](SECURITY_LLD.md)
3. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)
4. [POLYMORPHIC_BYTECODE_LLD](POLYMORPHIC_BYTECODE_LLD.md)
