// Package gate implements the OPA Rego policy evaluation for the writ codification gate.
package gate

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Result is the output of a gate evaluation.
type Result struct {
	Allowed      bool
	Tier         int
	DenialReason string
}

// Gate evaluates OPA Rego policies against LLM call metadata.
type Gate struct {
	mu         sync.RWMutex
	policyPath string
	query      rego.PreparedEvalQuery
	lastMtime  time.Time
	eager      bool
	stopCh     chan struct{}
}

// GateInput is the input document passed to the Rego policy.
type GateInput struct {
	CallerID   string            `json:"caller_id"`
	ActionType string            `json:"action_type"`
	Model      string            `json:"model"`
	EstTokens  int               `json:"est_tokens"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// New constructs a Gate. If eager is true and ctx is cancellable,
// a background goroutine watches policyPath for changes.
func New(ctx context.Context, policyPath string, eager bool) (*Gate, error) {
	g := &Gate{
		policyPath: policyPath,
		eager:      eager,
		stopCh:     make(chan struct{}),
	}
	if err := g.load(); err != nil {
		return nil, err
	}
	if eager {
		go g.watch(ctx)
	}
	return g, nil
}

// Evaluate runs the loaded policy against input. Uses lazy reload when not in eager mode.
func (g *Gate) Evaluate(ctx context.Context, input GateInput) (Result, error) {
	if !g.eager {
		if err := g.reloadIfStale(); err != nil {
			return Result{}, fmt.Errorf("gate: reload policy: %w", err)
		}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	rs, err := g.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Result{}, fmt.Errorf("gate: rego eval: %w", err)
	}
	return parseResult(rs)
}

func (g *Gate) load() error {
	info, err := os.Stat(g.policyPath)
	if err != nil {
		return fmt.Errorf("gate: stat policy path: %w", err)
	}

	r := rego.New(
		rego.Query(`data.writ.gate`),
		rego.Load([]string{g.policyPath}, nil),
	)
	q, err := r.PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("gate: prepare rego query: %w", err)
	}

	g.mu.Lock()
	g.query = q
	g.lastMtime = info.ModTime()
	g.mu.Unlock()
	return nil
}

func (g *Gate) reloadIfStale() error {
	info, err := os.Stat(g.policyPath)
	if err != nil {
		return err
	}
	g.mu.RLock()
	stale := info.ModTime().After(g.lastMtime)
	g.mu.RUnlock()
	if stale {
		return g.load()
	}
	return nil
}

func (g *Gate) watch(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.stopCh:
			return
		case <-ticker.C:
			_ = g.reloadIfStale()
		}
	}
}

func parseResult(rs rego.ResultSet) (Result, error) {
	if len(rs) == 0 {
		return Result{Allowed: false, DenialReason: "no policy result"}, nil
	}
	bindings, ok := rs[0].Bindings["data"]
	if !ok {
		// Unnamed query result — use expressions
		if len(rs[0].Expressions) == 0 {
			return Result{Allowed: false, DenialReason: "empty policy expression"}, nil
		}
		bindings = rs[0].Expressions[0].Value
	}
	m, ok := bindings.(map[string]interface{})
	if !ok {
		return Result{}, fmt.Errorf("gate: unexpected policy result type %T", bindings)
	}
	result := Result{}
	if allow, ok := m["allow"].(bool); ok {
		result.Allowed = allow
	}
	if tier, ok := m["tier"].(float64); ok {
		result.Tier = int(tier)
	}
	if reason, ok := m["denial_reason"].(string); ok {
		result.DenialReason = reason
	}
	return result, nil
}
