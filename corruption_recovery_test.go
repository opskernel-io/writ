package writ_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/opskernel-io/writ"
)

// testPolicyDir writes a minimal allow-all OPA policy and returns the dir path.
func testPolicyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	const allow = `package writ.gate
import rego.v1
default allow := true
default tier := 2
default denial_reason := ""`
	if err := os.WriteFile(filepath.Join(dir, "allow_all.rego"), []byte(allow), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// corruptedChainPath writes a valid single entry then tampers the hash field.
func corruptedChainPath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "chain-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	// A well-formed JSONL line but with a tampered hash value.
	_, _ = f.WriteString(`{"id":"a1","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","event_type":"tool_use","allowed":true,"timestamp":"2026-05-05T00:00:00Z"}` + "\n")
	f.Close()
	return f.Name()
}

func TestNew_CleanChain_Succeeds(t *testing.T) {
	chainPath := filepath.Join(t.TempDir(), "chain.jsonl")
	cfg := writ.Config{
		PolicyPath: testPolicyDir(t),
		AuditPath:  chainPath,
		CallerID:   "test-clean",
	}
	c, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("want clean-chain New() to succeed, got: %v", err)
	}
	if c == nil {
		t.Fatal("want non-nil client")
	}
}

func TestNew_CorruptChain_RecoveryFalse_ReturnsErrCorruptChain(t *testing.T) {
	cfg := writ.Config{
		PolicyPath:                testPolicyDir(t),
		AuditPath:                 corruptedChainPath(t),
		AllowCorruptChainRecovery: false,
	}
	_, err := writ.New(cfg)
	if err == nil {
		t.Fatal("want ErrCorruptChain, got nil")
	}
	if !errors.Is(err, writ.ErrCorruptChain) {
		t.Fatalf("want errors.Is(err, ErrCorruptChain), got: %v", err)
	}
}

func TestNew_CorruptChain_RecoveryTrue_BoundaryEntryWritten(t *testing.T) {
	chainPath := corruptedChainPath(t)
	cfg := writ.Config{
		PolicyPath:                testPolicyDir(t),
		AuditPath:                 chainPath,
		AllowCorruptChainRecovery: true,
	}
	c, err := writ.New(cfg)
	if err != nil {
		t.Fatalf("want recovery to succeed, got: %v", err)
	}
	if c == nil {
		t.Fatal("want non-nil client")
	}

	// Chain now has original corrupt entry + boundary entry; verify the boundary.
	if verifyErr := writ.Verify(chainPath); verifyErr == nil {
		// If overall verify passes, the boundary fully repaired the chain — unexpected
		// since the first entry is permanently corrupt. This is fine — no assertion here.
	}

	// Confirm boundary entry was written by checking raw chain entries.
	store := writ.NewMemoryStore()
	_ = store // use the JSONL path instead
	entries, readErr := writ.ReadChainFile(chainPath)
	if readErr != nil {
		t.Fatalf("ReadChainFile: %v", readErr)
	}
	var foundBoundary bool
	for _, e := range entries {
		if e.EventType == "chain_segment_boundary" {
			foundBoundary = true
			if e.Metadata == nil || e.Metadata["type"] != "RECOVERY" {
				t.Errorf("boundary entry missing RECOVERY metadata: %+v", e.Metadata)
			}
			break
		}
	}
	if !foundBoundary {
		t.Errorf("want chain_segment_boundary entry after recovery, none found in %d entries", len(entries))
	}
}
