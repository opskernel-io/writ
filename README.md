# writ — cryptographic audit trail for AI calls

```
go get github.com/opskernel-io/writ
```

---

## The problem

EU AI Act Article 12 requires automatic, tamper-evident logging of AI system decisions over the system's lifetime. Enforcement begins August 2, 2026.

Most teams building on LLM APIs have neither: standard observability logs can be edited after the fact, and database rows have no chain-integrity check.

---

## What writ does

- **Drop-in Go SDK** — `writ.New(cfg)` wraps your `*anthropic.Client`; one line at construction time, zero behaviour change in existing agent code
- **Merkle audit chain** — every LLM call is SHA-256-linked to the previous entry; post-hoc modification is detectable by anyone who runs `writ verify`
- **Optional OPA policy gate** — Rego rules run before each call; unauthorized calls never reach the API, violations are logged with chain entries

---

## Article 12 compliance status

| Requirement | Status |
|-------------|--------|
| Logging of AI system outputs | ✅ MET |
| Tamper-evident chain integrity | ✅ MET |
| Third-party verification path | ✅ MET |
| eIDAS-qualified timestamp | ⏳ Commercial tier |
| 6-month minimum retention | ⏳ BYO (v0 is pre-commercial) |

Three partial requirements have defined close paths:
- **Filesystem-level tamper protection** — `writ.ChainProtected()` sets `chattr +a` on Linux; prevents in-place overwrites without breaking the chain
- **Cross-restart chain continuity** — chain is append-only within a process run; session boundaries are flagged explicitly in `VerifyFull()` for auditor review
- **Full input capture** — input hashes logged by default; `StoreFullInputs: true` writes full request/response JSON to a sidecar JSONL for replay

---

## Quick start

```go
import (
    "github.com/opskernel-io/writ"
    "github.com/anthropics/anthropic-sdk-go"
)

// Initialize — wraps your anthropic.Client with gate + audit.
// One-line change at construction time; the rest of your agent code stays the same.
client, err := writ.New(writ.Config{
    PolicyPath: "/etc/writ/policy.rego",  // OPA Rego bundle directory
    AuditPath:  "/var/writ/audit.chain",  // Merkle chain JSONL file
    CallerID:   "myagent-v1",             // stable agent identifier
})
if err != nil {
    log.Fatal(err)
}

// LLM calls go through the gate automatically.
// Allowed calls are audited and dispatched; denied calls return *writ.DenialError.
msg, err := client.Messages.New(ctx, anthropic.MessageNewParams{
    Model:     anthropic.ModelClaudeSonnet4_6,
    MaxTokens: 1024,
    Messages: []anthropic.MessageParam{
        anthropic.NewUserMessage(anthropic.NewTextBlock("summarise the Q3 results")),
    },
})
if err != nil {
    var denial *writ.DenialError
    if errors.As(err, &denial) {
        log.Printf("blocked by policy: %s (audit_id=%s)", denial.Reason, denial.AuditID)
    }
}

// Streaming calls work the same way.
stream, err := client.Messages.NewStreaming(ctx, params)
if err != nil { ... }
defer stream.Close() // writes the streaming-complete audit entry

// For tool use and other non-LLM events:
h := sha256.Sum256([]byte(filePath))
client.Audit(writ.AuditEvent{
    ActionType: "write_file",
    Actor:      writ.ActorAgent,
    InputHash:  fmt.Sprintf("%x", h),
    Result:     "success",
})

// Verify chain integrity (run in CI or on-demand audits):
err = writ.Verify("/var/writ/audit.chain")
```

**Helm (Kubernetes):** writ-core is a library dependency of your agent process, not a sidecar. Add to your agent container's Go dependencies. See `docs/helm/` for a reference values.yaml with policy ConfigMap mounting.

A runnable end-to-end demo is at [`examples/demo/`](examples/demo/).

---

## What's in v0

- `writ.New()` SDK wrapping `*anthropic.Client`
- SHA-256 Merkle chain — append-only JSONL, filesystem protection (`chattr +a`) on Linux
- OPA codification gate — Rego policy evaluation before each call; hot-reload via file watch without restart
- `writ verify` CLI — standalone chain verification for CI pipelines
- `StoreFullInputs` mode — sidecar JSONL with full request/response JSON for audit replay

Not in v0: managed timestamp authority, 6-month retention service, multi-agent cross-chain tracing.

---

## Known limitations

- **Process-level boundary only** — writ intercepts at the SDK call site in your process. A transitive dependency that constructs its own `anthropic.Client` bypasses the gate. See the threat model ADR for the scope and mitigation options.
- **Single-process append assumption** — no concurrent writers to the same chain file. Multi-process setups require separate chain files or the pluggable `AuditStore` interface.
- **No timestamp authority in OSS tier** — chain timestamps are machine-generated, not externally signed. eIDAS-compliant timestamping is a commercial-tier feature.

---

## How it's different

| | writ | Asqav | Snyk Agent Guard | Microsoft AGT |
|---|---|---|---|---|
| Pre-execution gate | **✓** | ✗ | ✗ | ✗ |
| Tamper-evident audit | Merkle chain | Hash chain + RFC 3161 | Mutable session logs | ✗ |
| OPA policy enforcement | **✓** | ✗ | private preview | ✓ |
| Tiered dispatch | **✓** | ✗ | ✗ | ✗ |
| Language | Go | Python | N/A | TypeScript |
| License | Apache 2.0 + commercial | MIT | Commercial | MIT |

**From Asqav:** Asqav logs what happened after execution. writ controls what is allowed to happen before execution. These are different architectural positions: authorize-then-enforce vs. observe-and-record. In a regulated environment you need both; writ's gate is the piece no other tool ships.

**From Microsoft AGT:** The Agent Governance Toolkit has OPA enforcement and Ed25519 signing. It has no tamper-evident audit log. writ's Merkle chain fills that specific gap.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Process                         │
│                                                          │
│  task ──► [writ codification gate] ──► LLM API call     │
│                     │                       │            │
│               DENY (blocked)          ALLOW (proceed)   │
│                     │                       │            │
│              structured error        [Merkle audit]      │
│                                             │            │
│                                    [tiered dispatch]     │
│                                             │            │
│                               Ollama / Sonnet / Opus     │
└─────────────────────────────────────────────────────────┘
         │                         │
   [OPA policy]              [audit chain]
   file watch                append-only
   hot-reload                tamper-evident
         │                         │
  /etc/writ/policy.rego     /var/writ/audit.chain
```

The gate sits between your agent's code and the LLM API call — not between your machine and the internet. It intercepts at the call site in-process.

---

## Supported agents

v0 targets **Go agents that call `anthropic.Client` directly** — any agent built with `github.com/anthropics/anthropic-sdk-go`. Drop `writ.New()` in at the client construction site.

| Agent | v0 support | Notes |
|---|---|---|
| Custom Go agent (anthropic-sdk-go) | **✓ Supported** | `writ.New()` wraps at construction time — one line |
| Cursor | Roadmap | Cursor proxies all LLM calls through its own servers; requires HTTP middleware path (ADR #20) |
| Devin | Not planned | Cognition cloud-only; no user-controlled process to intercept |

**Cursor:** writ cannot intercept at the SDK level because Cursor routes every LLM call through Cursor's backend regardless of your API key. The roadmap item (ADR #20) is a local HTTP proxy that Cursor can be configured to route through via its OpenAI-compatible base-URL override. Not yet implemented.

**Devin:** Devin is a fully cloud-hosted system. There is no user-controlled process making LLM calls — Cognition's infrastructure handles all inference. writ integration is not viable without a Cognition self-hosted tier.

---

## License

The writ-core SDK is Apache 2.0. Use it, fork it, embed it, build commercial products on top of it.

**What's in the commercial tier** ([writ.opskernel.io](https://writ.opskernel.io)):
- Compliance dashboard — Article 12 audit report export (PDF + JSON)
- Hosted RFC 3161 timestamping — eIDAS-compliant, third-party signed timestamps
- 6-month retention management — cloud storage backend with compliance attestation
- Multi-agent audit chains — cross-agent tracing across chained agent calls

---

## Roadmap

- [ ] RFC 3161 timestamping integration (closes Article 12 gap 1)
- [ ] 6-month retention management, commercial tier (closes Article 12 gap 2)
- [ ] Multi-agent audit chains — single verifiable chain spanning Agent A → Agent B calls
- [ ] Agent integration guides — Devin, Cursor, and other agents (requires OQ-5 investigation)
- [x] `writ verify` CLI — standalone chain verification for CI pipelines

---

## Early access

writ is pre-launch. To request early access or discuss Article 12 compliance requirements: [writ.opskernel.io](https://writ.opskernel.io) or reach out directly via [opskern.io](https://opskern.io).

---

## Related

- **[hookd](https://opskernel.io)** — governs external AI traffic: MCP server verification, replay detection, per-source audit. writ governs what agents do internally; hookd governs what external servers agents call.
- **[opskern-policy](https://github.com/OpsKern/opskern-policy)** — shared OPA Rego policy templates for hookd + writ.
- **[Asqav](https://github.com/jagmarques/asqav-sdk)** — MIT Python SDK for agent audit trails with RFC 3161 timestamps. Complementary to writ (observe-and-record layer); writ adds the pre-execution gate that Asqav does not have.
- **[EU AI Act Article 12 text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)** — the specific requirement writ's architecture addresses.
