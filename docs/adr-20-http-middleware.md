---
id: ADR-20
title: HTTP Middleware Integration Path for Proxying Agents
status: proposed
date: 2026-05-04
deciders: Will Smith
---

# ADR #20 — HTTP Middleware Integration Path for Proxying Agents

## Context

writ v0 intercepts LLM calls by wrapping `anthropic.Client` at construction time in a Go process the developer controls. This works for any agent built with `github.com/anthropics/anthropic-sdk-go` that runs in user-controlled code.

It does not work for agents that proxy LLM calls through their own backend servers. OQ-5 investigation (2026-05-04) identified Cursor as the primary target in this category. Cursor routes all LLM calls through Cursor's servers even when the user provides their own API key ("all requests are routed through Cursor's servers for final prompt building" — official Cursor docs).

The TensorZero team independently confirmed this architecture by reverse engineering Cursor's LLM client flow.

## Problem

writ.New() cannot intercept calls that never pass through user-controlled code. For proxying agents, interception must happen at the HTTP transport layer.

## Decision

Implement an optional `writ-proxy` HTTP server package that:

1. Listens on a local port (configurable, default `127.0.0.1:7437`)
2. Accepts Anthropic-format POST requests to `/v1/messages`
3. Accepts OpenAI-compatible POST requests to `/v1/chat/completions` (for agents that support OpenAI base-URL override but not Anthropic base-URL override, as is the case with Cursor as of 2026-04)
4. Evaluates OPA policy against the incoming request (pre-call gate)
5. On DENY: returns a structured error response matching the upstream format
6. On ALLOW: forwards to the real Anthropic endpoint, writes Merkle audit entry, returns response to caller

This proxy is a separate package (`github.com/opskernel-io/writ/proxy`) and binary (`cmd/writ-proxy`), not part of the core `writ.New()` path.

## Integration model for Cursor

```
Cursor → writ-proxy (127.0.0.1:7437) → Anthropic API
              │
         OPA gate + Merkle audit
```

Configuration in Cursor: override the OpenAI-compatible base URL to `http://127.0.0.1:7437/v1`. Cursor currently does not support Anthropic base-URL override; OpenAI-compat endpoint is the only viable path until Cursor ships that feature.

The proxy translates OpenAI-format requests to Anthropic format before forwarding. Response is translated back.

## Transport security

The proxy listens on localhost only (127.0.0.1, not 0.0.0.0). No TLS is required for the local leg; the outbound leg to Anthropic uses standard HTTPS. This is the same model used by LiteLLM and TensorZero in the same topology.

## Audit chain continuity

The proxy writes to the same Merkle chain format as `writ.New()`. The `CallerID` field in audit entries is set to the `X-Writ-Caller` request header if present, otherwise defaults to `"writ-proxy"`. This allows auditors to distinguish SDK-intercepted calls from proxy-intercepted calls in the same chain.

## Devin

Devin is **explicitly excluded** from this ADR and from the writ roadmap. Devin is a fully cloud-hosted system; Cognition does not expose an API key slot, base-URL override, or any user-controlled process making LLM calls. There is no HTTP layer the user controls through which to insert a proxy. writ integration with Devin is not viable without Cognition shipping a self-hosted tier.

## Alternatives considered

**Interface injection:** Replace the Anthropic HTTP client at the `http.RoundTripper` level within the SDK. Requires using unexported fields or a fork. Rejected — creates maintenance burden against upstream SDK changes.

**stdin/stdout hook at Claude CLI level:** For Claude Code specifically (subprocess invocation pattern), a stdin/stdout wrapper is feasible. Out of scope for the proxy ADR; tracked separately if needed.

## Status

Proposed. Not scheduled for v0. Prerequisite for Cursor integration guide in README.

Before implementing: verify Cursor has not shipped Anthropic base-URL override (which would simplify to a direct proxy without OpenAI-compat translation).

## Consequences

- Cursor can be added to the roadmap section of the README once this proxy is implemented and tested.
- The proxy introduces a latency hop (localhost round-trip, ~0.1–0.5ms). Negligible for interactive agents.
- The proxy must be kept running alongside the agent process. Packaging and lifecycle management are out of scope for writ-core v0.
