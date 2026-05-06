//go:build integration

package writ_test

// TestSpikeB_EndToEnd is the Spike B acceptance test (writ-v0-spikes-2026-05-05.md).
// It validates writ.New() ergonomics end-to-end without an Anthropic API key:
//
//   - HARD_BLOCK: deny-all policy → DenialError returned, no Anthropic API call,
//     pre-call audit entry written with Merkle link intact.
//   - Explicit audit: writ.Audit() writes a tool_use entry to the same chain.
//   - Verification: writ.Verify confirms all Merkle hash links are intact.
//
// Produces /tmp/writ-chain.jsonl as a side effect for acceptance-criteria checks.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/opskernel-io/writ"
)

func TestSpikeB_EndToEnd(t *testing.T) {
	policyDir := t.TempDir()
	const denyPolicy = `package writ.gate
import rego.v1
default allow := false
default tier := 0
default denial_reason := "spike-b deny test"`
	if err := os.WriteFile(filepath.Join(policyDir, "deny_all.rego"), []byte(denyPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	chainPath := "/tmp/writ-chain.jsonl"
	_ = os.Remove(chainPath)

	c, err := writ.New(writ.Config{
		PolicyPath: policyDir,
		AuditPath:  chainPath,
		CallerID:   "spike-b-test",
	})
	if err != nil {
		t.Fatalf("writ.New: %v", err)
	}

	// HARD_BLOCK: deny policy → DenialError, Messages.New makes no Anthropic API call.
	_, callErr := c.Messages.New(context.Background(), anthropic.MessageNewParams{})
	if callErr == nil {
		t.Fatal("want DenialError from deny policy, got nil")
	}
	var denialErr *writ.DenialError
	if !errors.As(callErr, &denialErr) {
		t.Fatalf("want *writ.DenialError, got %T: %v", callErr, callErr)
	}
	t.Logf("HARD_BLOCK ok: reason=%q audit_id=%s", denialErr.Reason, denialErr.AuditID)

	// Explicit audit: tool_use event written via writ.Audit().
	if err := c.Audit(writ.AuditEvent{
		EventType:  "tool_use",
		ActionType: "read_file",
		InputHash:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Result:     "success",
		Timestamp:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("writ.Audit: %v", err)
	}

	// Chain verification: all Merkle hash links must be intact.
	if err := writ.Verify(chainPath); err != nil {
		t.Fatalf("writ.Verify: %v", err)
	}
	t.Logf("chain at %s verified OK", chainPath)
}
