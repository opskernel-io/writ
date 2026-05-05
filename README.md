# writ

**Codification gate and Merkle audit chain for Go agents.**

```
go get github.com/opskernel-io/writ
```

---

## The problem

Autonomous coding agents run with whatever permissions you gave them at setup time. There is no runtime gate that asks "is this call within policy?" before the LLM acts, and standard observability logs can be edited after the fact.

---

## What writ does

- **Blocks unauthorized agent calls before execution** — the codification gate intercepts every outbound LLM API call at the process level and evaluates it against your OPA policy before it leaves
- **Logs every agent decision in a tamper-evident chain** — SHA-256-linked Merkle chain; altering any entry breaks verification from that point forward
- **Routes tasks to the cheapest model tier that can handle them** — Ollama (free/local) → Claude Sonnet → Claude Opus, enforced by policy
- **Reloads policy without restarting** — OPA hot-reload via file watch; policy changes take effect on the next call

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

**The key distinction from Asqav:** Asqav logs what happened after execution. writ controls what is allowed to happen before execution. These are different architectural positions: authorize-then-enforce vs. observe-and-record. In a regulated environment you need both; writ's gate is the piece no other tool ships.

**The key distinction from Microsoft AGT:** The Agent Governance Toolkit has OPA enforcement and Ed25519 signing. It has no tamper-evident audit log. writ's Merkle chain fills that specific gap.

---

## EU AI Act Article 12

EU AI Act Article 12 requires automatic, technical, tamper-evident logging over the lifetime of high-risk AI systems. Enforcement begins August 2, 2026.

**Three requirements met in full:**
- Automatic logging — the gate emits chain entries without human action per call
- Technical logging — machine-generated, structured, SHA-256-linked
- Traceability — every gate decision links to its chain entry by AuditID

**Three requirements partially met (remediation paths defined, days not weeks):**
- Tamper-evident — SHA-256 chain detects alteration; filesystem-level write protection (`chattr +a` + `writ.ChainProtected()`) closes the gap
- Lifetime coverage — chain is append-only within a process run; cross-restart hash linking closes the gap
- Granularity — input hashes logged by default; `StoreFullInputs: true` opt-in logs the full input data

**Two named gaps:**
- **RFC 3161 timestamping** — chain timestamps are machine-generated but not externally signed. Integration roadmap: `github.com/digitorus/timestamp`. Commercial tier: hosted eIDAS-compliant timestamping.
- **6-month retention management** — the open-source core writes to local storage with no managed expiry. Commercial-tier feature.

writ-core is suitable for teams building toward Article 12 compliance. The three partial requirements close with days of engineering. The commercial tier closes the two named gaps.

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
    CallerID:   "myagent-v1",             // optional stable agent identifier
})
if err != nil {
    log.Fatal(err)
}

// LLM calls go through the gate automatically.
// Allowed calls are audited and dispatched; denied calls return *writ.DenialError.
msg, err := client.Messages.New(ctx, anthropic.MessageNewParams{
    Model:     anthropic.ModelClaude_Sonnet_4_6,
    MaxTokens: 1024,
    Messages:  anthropic.F([]anthropic.MessageParam{
        anthropic.NewUserMessage(anthropic.NewTextBlock("refactor the auth module")),
    }),
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
client.Audit(writ.AuditEvent{
    ActionType: "write_file",
    Actor:      writ.ActorAgent,
    InputHash:  writ.HashInput([]byte(filePath)),
    Result:     "success",
})

// Verify the chain (run in CI or on-demand audits):
err = writ.Verify("/var/writ/audit.chain")
```

**Helm (Kubernetes):** writ-core is a library dependency of your agent process, not a sidecar. Add to your agent container's Go dependencies. See `docs/helm/` for a reference values.yaml with policy ConfigMap mounting.

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

## Related

- **[hookd](https://opskernel.io)** — governs external AI traffic: MCP server verification, replay detection, per-source audit. writ governs what agents do internally; hookd governs what external servers agents call.
- **[opskern-policy](https://github.com/OpsKern/opskern-policy)** — shared OPA Rego policy templates for hookd + writ.
- **[Asqav](https://github.com/jagmarques/asqav-sdk)** — MIT Python SDK for agent audit trails with RFC 3161 timestamps. Complementary to writ (observe-and-record layer); writ adds the pre-execution gate that Asqav does not have.
- **[EU AI Act Article 12 text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)** — the specific requirement writ's architecture addresses.

---

*writ is built by [OpsKern](https://opskern.io). Early access: [writ.opskernel.io](https://writ.opskernel.io)*
