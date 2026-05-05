package writ

import (
	"context"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	igate "github.com/opskernel-io/writ/internal/gate"
)

// gateWrapper bridges internal/gate.Gate to the public API types.
type gateWrapper struct {
	inner *igate.Gate
}

func newGate(ctx context.Context, policyPath string, eager bool) (*gateWrapper, error) {
	g, err := igate.New(ctx, policyPath, eager)
	if err != nil {
		return nil, err
	}
	return &gateWrapper{inner: g}, nil
}

func (g *gateWrapper) evaluate(ctx context.Context, params anthropic.MessageNewParams, cfg Config) (Decision, ChainEntry, error) {
	input := igate.GateInput{
		CallerID:   cfg.CallerID,
		ActionType: "llm_call",
		Model:      string(params.Model),
	}

	result, err := g.inner.Evaluate(ctx, input)
	if err != nil {
		return Decision{}, ChainEntry{}, fmt.Errorf("gate evaluate: %w", err)
	}

	auditID := newAuditID()
	tier := Tier(result.Tier)

	decision := Decision{
		Allowed:      result.Allowed,
		Tier:         tier,
		DenialReason: result.DenialReason,
		AuditID:      auditID,
	}

	entry := ChainEntry{
		ID:           auditID,
		EventType:    "llm_call",
		CallerID:     cfg.CallerID,
		HookdTraceID: cfg.HookdTraceID,
		Allowed:      result.Allowed,
		DenialReason: result.DenialReason,
		Tier:         tier,
		Timestamp:    time.Now().UTC(),
	}

	return decision, entry, nil
}
