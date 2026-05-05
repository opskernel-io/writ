package writ_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opskernel-io/writ"
)

// testConfig creates a minimal writ.Config backed by a temp directory.
func testConfig(t *testing.T) writ.Config {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy")
	if err := os.MkdirAll(policyPath, 0o700); err != nil {
		t.Fatalf("mkdir policy: %v", err)
	}
	const policy = "package writ.gate\nimport rego.v1\ndefault allow := true\ndefault tier := 2\ndefault denial_reason := \"\""
	if err := os.WriteFile(filepath.Join(policyPath, "writ.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	return writ.Config{
		PolicyPath: policyPath,
		AuditPath:  filepath.Join(dir, "audit.chain"),
		CallerID:   "test-agent",
	}
}

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

// PR 1: AllowedCallers and ChainProtected tests.

func TestAllowedCallersPermitsKnownCaller(t *testing.T) {
	cfg := testConfig(t)
	cfg.AllowedCallers = []string{"test-agent", "other-agent"}
	c, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("want success for known caller, got: %v", err)
	}
	_ = c
}

func TestAllowedCallersDeniesUnknownCaller(t *testing.T) {
	cfg := testConfig(t)
	cfg.AllowedCallers = []string{"allowed-agent"}
	cfg.CallerID = "unknown-agent"
	if _, err := writ.New(cfg); err == nil {
		t.Fatal("want error for unknown caller, got nil")
	}
}

func TestAllowedCallersNilPermitsAnyCaller(t *testing.T) {
	cfg := testConfig(t)
	cfg.AllowedCallers = nil
	cfg.CallerID = "any-agent"
	c, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("want success for nil allowlist, got: %v", err)
	}
	_ = c
}

func TestChainProtectedReturnsBool(t *testing.T) {
	cfg := testConfig(t)
	c, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Return value is platform/filesystem-dependent; just verify the call succeeds.
	_ = c.ChainProtected()
}
