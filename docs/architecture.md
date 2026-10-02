# System Architecture: SentinelFlow

This document explains the internal architecture of SentinelFlow using high-level system design patterns.

---

## 1. High-Level Scan Pipeline

The scanning process follows a structured pipeline: ingestion, concurrent analysis, policy evaluation, and reporting.

```mermaid
graph LR
    subgraph "Input Layer"
        SRC["Local Source Code"]
        CFG[".sentinelflow.yaml"]
    end

    subgraph "Engine Layer (Concurrent)"
        S1["Secrets Scanner"]
        S2["IaC Scanner"]
        S3["Dependency Scanner"]
        S4["SAST / Go AST"]
        S5["License Scanner"]
        S6["Policy Engine (OPA)"]
        S7["Artifacts"]
        S8["External adapters"]
    end

    subgraph "External Feeds"
        VDB["OSV.dev querybatch"]
        CACHE["Disk + memory cache"]
    end

    SRC --> S1 & S2 & S3 & S4 & S5 & S7
    CFG --> S1 & S2 & S3 & S4 & S5 & S6 & S7 & S8
    VDB --> CACHE --> S3
    S7 --> CACHE

    S1 & S2 & S3 & S4 & S5 & S6 & S7 & S8 --> AGG["Suppressions + gate"]

    subgraph "Output Layer"
        AGG --> R1["SARIF (GitHub)"]
        AGG --> R2["Markdown / job summary"]
        AGG --> R3["JSON / HTML / JUnit / GitLab"]
    end
```

### Security Insight:

- **Isolation**: Scanners run in parallel but do not share state, preventing a malicious file from affecting the analysis of another.
- **Caching**: The local cache reduces network calls, making the tool faster and more resistant to rate-limiting or API downtime.

---

## 2. Dependency Scanner Flow

How we identify vulnerabilities in third-party packages without executing their code.

```mermaid
sequenceDiagram
    participant CLI as CLI Engine
    participant P as Parser (go.mod, package.json)
    participant C as Cache Manager
    participant OSV as OSV.dev API

    CLI->>P: Extract Dependencies
    P-->>CLI: List of [Package, Version]

    loop For each Dependency
        CLI->>C: Check local cache?
        alt Cache Hit
            C-->>CLI: Return findings
        else Cache Miss
            C->>OSV: Query Vulnerabilities
            OSV-->>C: Vulnerability JSON
            C->>C: Store in disk cache (TTL) + memory
            C-->>CLI: Return findings
        end
    end
    CLI->>CLI: Format Results
```

### Security Insight:

- **Version Range Matching**: We use semver comparison to see if your version falls within the "affected range" provided by the vulnerability database.

---

## 3. Policy-as-Code (OPA) Integration

SentinelFlow uses Open Policy Agent (OPA) to allow users to write custom security rules in the **Rego** language.

```mermaid
graph TD
    subgraph "Policy Ingestion"
        RULES["Policies (*.rego)"]
        DATA["Scan JSON Data"]
    end

    subgraph "Evaluation Engine (OPA)"
        COMP["Compiler"]
        EXEC["Rego Virtual Machine"]
    end

    RULES --> COMP
    DATA --> EXEC
    COMP --> EXEC

    EXEC --> DEC["Policy Decision"]

    DEC --> |"Allow"| OK["Success"]
    DEC --> |"Deny"| FAIL["Fail Build"]
```

### Security Insight:

- **Context-Aware**: OPA doesn't just look for strings; it analyzes the _state_ of your infrastructure. For example: "Fail if an S3 bucket is public AND does not have encryption enabled."

---

## 4. CI/CD Integration Architecture

How SentinelFlow acts as a security gatekeeper in a modern DevOps environment.

```mermaid
flowchart TD
    DEV["Developer"] --> |"git push"| GITHUB["GitHub / GitLab"]

    subgraph "CI Pipeline"
        GITHUB --> |"Trigger"| ACTION["GitHub Action"]
        ACTION --> |"Step 1"| BUILD["Build App"]
        ACTION --> |"Step 2 (SentinelFlow)"| SF["SentinelFlow Binary"]
    end

    subgraph "External"
        SF --> |"Lookup"| VULN["Vulnerability DB"]
    end

    SF --> |"Findings > Threshold"| BLOCK["❌ Block PR"]
    SF --> |"Pass"| MERGE["✅ Allow Merge"]

    SF --> |"Upload"| DASH["Security Dashboard"]
```

---

## 5. Security Principles of SentinelFlow

1.  **Zero Trust Pattern**: We don't trust any input file. Each is treated as potentially malicious or misconfigured.
2.  **Defense in Depth**: We use multiple scanning layers (Secrets + IaC + Deps) because a single vulnerability often spans multiple areas.
3.  **Local First**: Sensitive data never leaves your environment. We only send package names/versions to the vulnerability database—never your source code.
4.  **Static over Dynamic**: We analyze the code _before_ it runs (SAST), which is safer than running it and observing behavior (DAST) for a build-time tool.
