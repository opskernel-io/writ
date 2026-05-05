## writ v0.1.0

writ is a pre-execution codification gate and Merkle audit chain for Go agents. Every outbound LLM API call is evaluated against an OPA policy before it leaves the process; every gate decision is written to a SHA-256-linked append-only chain that breaks verification if altered.

**EU AI Act Article 12 posture (enforcement begins 2026-08-02):**

- 3 requirements met in full: automatic logging, technical logging, traceability
- 3 requirements partially met with defined remediation paths: tamper-evident storage, cross-restart chain continuity, full input capture
- 2 named gaps with a roadmap: RFC 3161 external timestamping, managed 6-month retention

**What's next:**

- Cross-restart hash linking (closes partial requirement 2)
- `chattr +a` filesystem protection helper (closes partial requirement 1)
- RFC 3161 timestamp integration via `github.com/digitorus/timestamp`
- Commercial-tier: hosted eIDAS-compliant timestamping and retention management
