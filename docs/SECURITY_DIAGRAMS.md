# Security Architecture Diagrams (Code-Synced)

## 1. End-to-End Runtime Security Flow

```mermaid
flowchart TD
    A[Load artifact] --> B[Signature verification]
    B --> C[Anti-debug pre-decode]
    C --> D[Sandbox pre-decode]
    D --> E[Process-protection pre-decode]
    E --> F[Decrypt and decode bytecode]
    F --> G[Anti-debug pre-execution]
    G --> H[Sandbox pre-execution]
    H --> I[Process-protection pre-execution]
    I --> J[VM execution]
    J --> K[Integrity probes periodic+jitter+sweep]
    K --> L[Tamper response policy]
    L --> M[Telemetry export]
```

## 2. Policy Decision Flow

```mermaid
flowchart LR
    A[Security event] --> B{MUTANT_TAMPER_RESPONSE set?}
    B -->|Yes| C[Use explicit env action]
    B -->|No| D[Use profile default]
    D --> E{Profile}
    E -->|minimal| F[warn]
    E -->|standard| G[secure=terminate or compat=warn]
    E -->|paranoid| H[terminate]
    C --> I[Apply warn/delay/terminate]
    F --> I
    G --> I
    H --> I
```

## 3. Anti-Tamper Probe Gates

```mermaid
flowchart TD
    A[RunAntiTamperProbe called] --> B{MUTANT_ENABLE_ANTITAMPER_PROBE == 1?}
    B -->|No| C[Return enabled=false, no signals]
    B -->|Yes| D[Run requested probes]
    D --> E[Return signals + enabled=true]

    E --> F{Called from runner process-protection path?}
    F -->|No| G[Diagnostic use only]
    F -->|Yes| H{MUTANT_ENABLE_PROCESS_PROTECTION enabled?}
    H -->|No| I[Skip enforcement]
    H -->|Yes| J{Any detected && confidence >= 80?}
    J -->|No| K[Continue]
    J -->|Yes| L[process_protection_detected -> policy action]
```

## 4. Runner vs Builtin Probe Scope

```mermaid
flowchart LR
    A[Runner enforcement] --> B[Focused 5 probes]
    C[Builtin diagnostics] --> D[Broader probe sets]
    B --> E[Policy action possible]
    D --> F[Observability and troubleshooting]
```

## 5. VM Integrity Scheduling

```mermaid
stateDiagram-v2
    [*] --> Running
    Running --> ProbeCurrent: every integrityEvery steps
    Running --> ProbeJitter: stepCount%97 == jitter%97
    Running --> ProbeSweep: every 251 steps

    ProbeCurrent --> Running: hash matches
    ProbeJitter --> Running: hash matches
    ProbeSweep --> Running: all active frames match

    ProbeCurrent --> TamperDetected: mismatch
    ProbeJitter --> TamperDetected: mismatch
    ProbeSweep --> TamperDetected: mismatch

    TamperDetected --> PolicyWarn: warn
    TamperDetected --> PolicyDelay: delay
    TamperDetected --> PolicyTerminate: terminate

    PolicyWarn --> Running
    PolicyDelay --> Running
    PolicyTerminate --> [*]
```

## 6. Polymorphic Engine Reality Snapshot

```mermaid
flowchart TD
    A[Compiler with mutation level] --> B[Polymorphic engine enabled]
    B --> C[Current: marker/tag path active]
    B --> D[Advanced transforms exist in code paths]
    D --> E[Currently gated in config]
```

Note:

1. Mutation controls and seed are wired through CLI.
2. Advanced transform activation is intentionally constrained in current
   configuration.
