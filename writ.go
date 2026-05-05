// Package writ provides a codification gate, Merkle audit chain, and tiered
// dispatch for LLM agents. Import writ and replace your anthropic.Client
// construction with writ.New() — one line change.
//
// See README.md for usage and compliance posture.
package writ

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// Version is the current writ-core release.
const Version = "0.0.1-dev"

// Config holds construction-time configuration for the writ gate.
type Config struct {
	// PolicyPath is the directory containing OPA Rego policy files.
	// Required. Hot-reload watches this directory for changes.
	PolicyPath string

	// AuditPath is the file path for the JSONL Merkle audit chain.
	// Used when Store is nil.
	AuditPath string

	// Store is a pluggable audit backend (ADR #18).
	// If nil, defaults to a JSONL file store at AuditPath.
	Store AuditStore

	// CallerID is an optional stable identifier for the agent process
	// (e.g. "myagent-v1"). Written into each audit entry.
	CallerID string

	// HookdTraceID is an optional hookd trace ID to cross-reference
	// in writ audit entries (ADR #13). Set per-request via RequestOptions
	// for dynamic values; set here for static/single-agent deployments.
	HookdTraceID string

	// EagerReload enables a goroutine-based policy watcher.
	// Default (false) uses lazy reload: policy is re-read when mtime changes.
	EagerReload bool

	// AllowCorruptChainRecovery, when true, permits New() to open a chain that
	// fails Merkle verification. A ChainSegmentBoundary entry is written
	// recording the recovery event. Default false: corrupt chain → ErrCorruptChain.
	AllowCorruptChainRecovery bool

	// AllowedCallers restricts which CallerID values may open a writ.Client
	// that writes to this chain. Nil or empty allows any CallerID.
	// writ.New returns an error if CallerID is not in the list when it is set.
	AllowedCallers []string
}

// ErrCorruptChain is returned by New() when the existing chain fails Merkle
// verification and Config.AllowCorruptChainRecovery is false.
var ErrCorruptChain = errors.New("writ: existing chain fails Merkle verification")

// Client wraps an anthropic.Client with a pre-call codification gate and
// post-call Merkle audit chain write. Construct with writ.New().
type Client struct {
	Messages *MessagesService
	inner    *anthropic.Client
	cfg      Config
	gater    *gateWrapper
	chain    AuditStore
}

// New constructs a writ.Client with lazy OPA policy reload.
// The returned client wraps the inner anthropic.Client at the call boundary.
func New(cfg Config) (*Client, error) {
	return NewWithContext(context.Background(), cfg)
}

// NewWithContext constructs a writ.Client. If cfg.EagerReload is true,
// the context cancellation stops the background policy watcher goroutine.
func NewWithContext(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.PolicyPath == "" {
		return nil, fmt.Errorf("writ: Config.PolicyPath is required")
	}

	if len(cfg.AllowedCallers) > 0 {
		permitted := false
		for _, id := range cfg.AllowedCallers {
			if id == cfg.CallerID {
				permitted = true
				break
			}
		}
		if !permitted {
			return nil, fmt.Errorf("writ: caller %q not in AllowedCallers", cfg.CallerID)
		}
	}

	var store AuditStore
	if cfg.Store != nil {
		store = cfg.Store
	} else {
		if cfg.AuditPath == "" {
			return nil, fmt.Errorf("writ: Config.AuditPath is required when Store is nil")
		}
		var err error
		store, err = newJSONLStore(cfg.AuditPath)
		if err != nil {
			return nil, fmt.Errorf("writ: open audit store: %w", err)
		}
	}

	if err := openChainVerify(store, cfg); err != nil {
		return nil, err
	}

	g, err := newGate(ctx, cfg.PolicyPath, cfg.EagerReload)
	if err != nil {
		return nil, fmt.Errorf("writ: init gate: %w", err)
	}

	inner := anthropic.NewClient()
	c := &Client{
		inner: &inner,
		cfg:   cfg,
		gater: g,
		chain: store,
	}
	c.Messages = &MessagesService{wc: c}
	return c, nil
}

// DenialError is returned by Messages.New and Messages.NewStreaming when the
// OPA gate denies the call. The LLM API is never contacted on denial.
type DenialError struct {
	Reason  string
	AuditID string
	Tier    Tier
}

func (e *DenialError) Error() string {
	return fmt.Sprintf("writ: call denied by policy: %s (audit_id=%s)", e.Reason, e.AuditID)
}

// Tier classifies the dispatch routing tier assigned by the gate.
type Tier int

const (
	TierUnknown Tier = iota
	TierLocal        // local model (Ollama / LM Studio)
	TierFast         // fast cloud model (e.g. Haiku)
	TierStandard     // standard cloud model (e.g. Sonnet)
	TierPowerful     // powerful cloud model (e.g. Opus)
)

// Decision is the result of a gate evaluation.
type Decision struct {
	Allowed      bool
	Tier         Tier
	DenialReason string
	AuditID      string
}

// Actor classifies who triggered an audit event.
type Actor string

const (
	ActorAgent     Actor = "agent"     // autonomous agent action
	ActorHuman     Actor = "human"     // human-in-the-loop action
	ActorAutomated Actor = "automated" // scheduled / non-interactive automation
)

// AuditEvent is a structured event written to the Merkle chain.
// Used by writ.Audit() for explicit tool use events (file read, shell exec,
// web fetch, etc.) that require Article 12 granularity.
//
// Article 12 mapping:
//   - Who:    CallerID + Actor
//   - What:   ActionType + InputHash
//   - When:   Timestamp
//   - Result: Result (success/failure/error)
//   - Chain:  Merkle link computed automatically from previous entry
type AuditEvent struct {
	// EventType classifies the event (e.g. "llm_call", "tool_use", "denial").
	// Defaults to "tool_use" if empty.
	EventType string
	// ActionType is the agent-defined action label (e.g. "read_file", "shell_exec",
	// "web_fetch", "write_file", "list_dir"). Required for Article 12 granularity.
	ActionType string
	// Actor classifies who triggered the action. Defaults to ActorAgent.
	Actor Actor
	// CallerID is the agent process identifier.
	CallerID string
	// InputHash is the SHA-256 hex hash of the input content (path, command, URL).
	// Use audit.HashBytes([]byte(input)) to compute.
	InputHash string
	// OutputHash is the SHA-256 hex hash of the output (file contents, stdout, response).
	// Empty for failed or denied actions.
	OutputHash string
	// Result records the outcome: "success", "failure", "denied", "error".
	Result string
	// HookdTraceID cross-references the hookd event envelope (ADR #13).
	HookdTraceID string
	// Timestamp is the event time in UTC. Defaults to time.Now().UTC() if zero.
	Timestamp time.Time
	// Metadata holds arbitrary key-value pairs for extra context (max 200 chars per value).
	Metadata map[string]string
}

// Audit writes an explicit event to the writ chain. Use for tool use events
// (file read, shell exec, web fetch) that require Article 12 granularity.
// The chain entry includes a Merkle link to the previous entry.
func (c *Client) Audit(event AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	entry, err := buildChainEntry(c.chain, event, c.cfg.CallerID, c.cfg.HookdTraceID)
	if err != nil {
		return fmt.Errorf("writ.Audit: build entry: %w", err)
	}
	return c.chain.Append(entry)
}

// ChainProtected attempts to set the FS_APPEND_FL attribute (equivalent to
// chattr +a) on the chain file, preventing in-place overwrites at the
// filesystem level. Returns true if the flag is set or was successfully
// applied. Returns false if no AuditPath is configured, the filesystem does
// not support the attribute, or the process lacks sufficient privilege.
// On non-Linux platforms this always returns false.
func (c *Client) ChainProtected() bool {
	if c.cfg.AuditPath == "" {
		return false
	}
	return trySetAppendOnly(c.cfg.AuditPath)
}

// Verify reads the chain at chainPath and verifies the Merkle hash links.
// Returns nil if the chain is intact, or an error describing the first broken link.
// Also available as the `writ verify` CLI command.
func Verify(chainPath string) error {
	store, err := newJSONLStore(chainPath)
	if err != nil {
		return fmt.Errorf("writ.Verify: open chain: %w", err)
	}
	entries, err := store.ReadAll()
	if err != nil {
		return fmt.Errorf("writ.Verify: read chain: %w", err)
	}
	return verifyChain(entries)
}
