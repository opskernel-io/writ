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

// PR 2: SessionID, Warnings, VerifyFull tests.

func TestSessionIDWrittenToChain(t *testing.T) {
	cfg := testConfig(t)
	cfg.SessionID = "session-abc"
	c, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Audit(writ.AuditEvent{EventType: "tool_use", ActionType: "noop"}); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	result, err := c.VerifyFull()
	if err != nil {
		t.Fatalf("VerifyFull: %v", err)
	}
	if !result.Valid {
		t.Fatalf("want valid chain, got invalid")
	}
	if result.EntryCount != 1 {
		t.Fatalf("want 1 entry, got %d", result.EntryCount)
	}
}

func TestSessionIDMismatchWarning(t *testing.T) {
	cfg := testConfig(t)
	cfg.SessionID = "session-A"
	c1, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New (session-A): %v", err)
	}
	if err := c1.Audit(writ.AuditEvent{EventType: "tool_use", ActionType: "noop"}); err != nil {
		t.Fatalf("Audit: %v", err)
	}

	cfg.SessionID = "session-B"
	c2, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New (session-B): %v", err)
	}
	if len(c2.Warnings()) == 0 {
		t.Error("want session ID mismatch warning, got none")
	}
}

func TestSessionIDMatchNoWarning(t *testing.T) {
	cfg := testConfig(t)
	cfg.SessionID = "session-A"
	c1, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c1.Audit(writ.AuditEvent{EventType: "tool_use", ActionType: "noop"}); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	c2, err := writ.New(cfg) // same SessionID
	if err != nil {
		t.Fatalf("New (same session): %v", err)
	}
	if len(c2.Warnings()) != 0 {
		t.Errorf("want no warnings for matching session ID, got: %v", c2.Warnings())
	}
}

func TestVerifyFullSessionGapDetected(t *testing.T) {
	cfg := testConfig(t)
	cfg.SessionID = "session-A"
	c1, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New (A): %v", err)
	}
	if err := c1.Audit(writ.AuditEvent{EventType: "tool_use", ActionType: "noop"}); err != nil {
		t.Fatalf("Audit A: %v", err)
	}

	cfg.SessionID = "session-B"
	c2, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New (B): %v", err)
	}
	if err := c2.Audit(writ.AuditEvent{EventType: "tool_use", ActionType: "noop"}); err != nil {
		t.Fatalf("Audit B: %v", err)
	}

	result, err := c2.VerifyFull()
	if err != nil {
		t.Fatalf("VerifyFull: %v", err)
	}
	if !result.Valid {
		t.Fatal("want valid chain despite session gap")
	}
	if len(result.SessionGaps) == 0 {
		t.Error("want 1 session gap, got none")
	}
}

func TestVerifyFullNoGapsForSingleSession(t *testing.T) {
	cfg := testConfig(t)
	cfg.SessionID = "session-X"
	c, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Audit(writ.AuditEvent{EventType: "tool_use", ActionType: "noop"}); err != nil {
			t.Fatalf("Audit %d: %v", i, err)
		}
	}
	result, err := c.VerifyFull()
	if err != nil {
		t.Fatalf("VerifyFull: %v", err)
	}
	if !result.Valid {
		t.Fatal("want valid chain")
	}
	if len(result.SessionGaps) != 0 {
		t.Errorf("want no gaps for single session, got: %v", result.SessionGaps)
	}
}
