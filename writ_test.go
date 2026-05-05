package writ_test

import (
	"testing"
	"time"

	"github.com/opskernel-io/writ"
)

func TestMemoryStoreAppendAndVerify(t *testing.T) {
	store := writ.NewMemoryStore()

	event := writ.AuditEvent{
		EventType:  "tool_use",
		ActionType: "read_file",
		CallerID:   "test-agent",
		InputHash:  "abc123",
		Timestamp:  time.Now().UTC(),
	}

	if err := store.Append(writ.ChainEntry{
		ID:        "entry-1",
		PrevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
		Hash:      "placeholder",
		EventType: event.EventType,
		CallerID:  event.CallerID,
		Allowed:   true,
		Timestamp: event.Timestamp,
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries, err := store.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].EventType != "tool_use" {
		t.Errorf("want event_type=tool_use, got %s", entries[0].EventType)
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	if err := writ.Verify("/nonexistent/chain.jsonl"); err == nil {
		t.Fatal("want error for nonexistent chain, got nil")
	}
}

func TestDenialErrorMessage(t *testing.T) {
	err := &writ.DenialError{
		Reason:  "daily ceiling exceeded",
		AuditID: "audit-xyz",
		Tier:    writ.TierStandard,
	}
	if err.Error() == "" {
		t.Fatal("DenialError.Error() returned empty string")
	}
}
