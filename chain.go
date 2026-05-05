package writ

import (
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/google/uuid"
	inaudit "github.com/opskernel-io/writ/internal/audit"
)

func newAuditID() string {
	return uuid.New().String()
}

// buildChainEntry creates a Merkle-linked ChainEntry from an AuditEvent.
// Reads the last entry from store to get the previous hash.
func buildChainEntry(store AuditStore, event AuditEvent, callerID, hookdTraceID, sessionID string) (ChainEntry, error) {
	prev, err := lastHash(store)
	if err != nil {
		return ChainEntry{}, err
	}

	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	if event.CallerID == "" {
		event.CallerID = callerID
	}
	if event.HookdTraceID == "" {
		event.HookdTraceID = hookdTraceID
	}
	if event.EventType == "" {
		event.EventType = "tool_use"
	}
	actor := string(event.Actor)
	if actor == "" {
		actor = "agent"
	}
	result := event.Result
	if result == "" {
		result = "success"
	}

	id := newAuditID()
	internal := inaudit.Entry{
		ID:           id,
		PrevHash:     prev,
		EventType:    event.EventType,
		ActionType:   event.ActionType,
		Actor:        actor,
		CallerID:     event.CallerID,
		SessionID:    sessionID,
		InputHash:    event.InputHash,
		OutputHash:   event.OutputHash,
		Result:       result,
		HookdTraceID: event.HookdTraceID,
		Allowed:      true,
		Timestamp:    ts.Format(time.RFC3339Nano),
		Metadata:     event.Metadata,
	}

	hash, err := inaudit.ComputeHash(internal)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("compute chain hash: %w", err)
	}
	internal.Hash = hash

	return ChainEntry{
		ID:           internal.ID,
		PrevHash:     internal.PrevHash,
		Hash:         internal.Hash,
		EventType:    internal.EventType,
		ActionType:   internal.ActionType,
		Actor:        internal.Actor,
		CallerID:     internal.CallerID,
		SessionID:    internal.SessionID,
		InputHash:    internal.InputHash,
		OutputHash:   internal.OutputHash,
		Result:       internal.Result,
		HookdTraceID: internal.HookdTraceID,
		Allowed:      internal.Allowed,
		Timestamp:    ts,
	}, nil
}

func buildPostCallEntry(store AuditStore, preEntry ChainEntry, resp *anthropic.Message, callErr error, cfg Config) (ChainEntry, error) {
	prev, err := lastHash(store)
	if err != nil {
		return ChainEntry{}, err
	}

	outputHash := ""
	if resp != nil && len(resp.Content) > 0 {
		outputHash = inaudit.HashBytes([]byte(fmt.Sprintf("%v", resp.Content)))
	}

	id := newAuditID()
	ts := time.Now().UTC()
	eventType := "llm_call_complete"
	if callErr != nil {
		eventType = "llm_call_error"
	}

	internal := inaudit.Entry{
		ID:           id,
		PrevHash:     prev,
		EventType:    eventType,
		CallerID:     cfg.CallerID,
		SessionID:    cfg.SessionID,
		OutputHash:   outputHash,
		HookdTraceID: cfg.HookdTraceID,
		Allowed:      true,
		Timestamp:    ts.Format(time.RFC3339Nano),
		Metadata:     map[string]string{"pre_entry_id": preEntry.ID},
	}

	hash, err := inaudit.ComputeHash(internal)
	if err != nil {
		return ChainEntry{}, err
	}
	internal.Hash = hash

	return ChainEntry{
		ID:           internal.ID,
		PrevHash:     internal.PrevHash,
		Hash:         internal.Hash,
		EventType:    internal.EventType,
		CallerID:     internal.CallerID,
		SessionID:    internal.SessionID,
		OutputHash:   internal.OutputHash,
		HookdTraceID: internal.HookdTraceID,
		Allowed:      internal.Allowed,
		Timestamp:    ts,
		Metadata:     internal.Metadata,
	}, nil
}

func buildStreamCompleteEntry(store AuditStore, startEntry ChainEntry, streamErr error, cfg Config) (ChainEntry, error) {
	prev, err := lastHash(store)
	if err != nil {
		return ChainEntry{}, err
	}

	id := newAuditID()
	ts := time.Now().UTC()
	eventType := "llm_call_streaming_complete"
	if streamErr != nil {
		eventType = "llm_call_streaming_error"
	}

	internal := inaudit.Entry{
		ID:           id,
		PrevHash:     prev,
		EventType:    eventType,
		CallerID:     cfg.CallerID,
		SessionID:    cfg.SessionID,
		HookdTraceID: cfg.HookdTraceID,
		Allowed:      true,
		Timestamp:    ts.Format(time.RFC3339Nano),
		Metadata:     map[string]string{"stream_start_id": startEntry.ID},
	}

	hash, err := inaudit.ComputeHash(internal)
	if err != nil {
		return ChainEntry{}, err
	}
	internal.Hash = hash

	return ChainEntry{
		ID:           internal.ID,
		PrevHash:     internal.PrevHash,
		Hash:         internal.Hash,
		EventType:    internal.EventType,
		CallerID:     internal.CallerID,
		SessionID:    internal.SessionID,
		HookdTraceID: internal.HookdTraceID,
		Allowed:      internal.Allowed,
		Timestamp:    ts,
		Metadata:     internal.Metadata,
	}, nil
}

func lastHash(store AuditStore) (string, error) {
	entries, err := store.ReadAll()
	if err != nil {
		return "", fmt.Errorf("read chain for prev hash: %w", err)
	}
	internalEntries := make([]inaudit.Entry, len(entries))
	for i, e := range entries {
		internalEntries[i] = inaudit.Entry{
			Hash:      e.Hash,
			Timestamp: timestampString(e.Timestamp),
		}
	}
	return inaudit.PrevHashFor(internalEntries), nil
}

// timestampString normalises a ChainEntry.Timestamp (interface{}) to the RFC3339Nano
// string used in Merkle hash computation. Handles both time.Time (in-memory path) and
// string (JSONL read-back path).
func timestampString(v interface{}) string {
	switch t := v.(type) {
	case time.Time:
		return t.Format(time.RFC3339Nano)
	case string:
		return t
	default:
		return ""
	}
}

// computeEntryHash sets PrevHash to the last chain hash and computes the Merkle
// hash for entry. Must be called on gate decision entries before Append, since
// those are constructed without hash fields by the gate evaluator.
func computeEntryHash(store AuditStore, entry ChainEntry) (ChainEntry, error) {
	prevHash, err := lastHash(store)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("read prev hash: %w", err)
	}
	entry.PrevHash = prevHash

	internal := inaudit.Entry{
		PrevHash:     entry.PrevHash,
		EventType:    entry.EventType,
		ActionType:   entry.ActionType,
		Actor:        entry.Actor,
		CallerID:     entry.CallerID,
		SessionID:    entry.SessionID,
		InputHash:    entry.InputHash,
		OutputHash:   entry.OutputHash,
		Result:       entry.Result,
		HookdTraceID: entry.HookdTraceID,
		Allowed:      entry.Allowed,
		DenialReason: entry.DenialReason,
		Timestamp:    timestampString(entry.Timestamp),
	}
	hash, err := inaudit.ComputeHash(internal)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("compute entry hash: %w", err)
	}
	entry.Hash = hash
	return entry, nil
}

// openChainVerify verifies the existing chain on New(). If the chain is corrupt
// and AllowCorruptChainRecovery is false, it returns ErrCorruptChain.
// If recovery is allowed, it writes a ChainSegmentBoundary entry and proceeds.
func openChainVerify(store AuditStore, cfg Config) error {
	entries, err := store.ReadAll()
	if err != nil {
		return fmt.Errorf("writ: read chain for verification: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}
	verifyErr := verifyChain(entries)
	if verifyErr == nil {
		return nil
	}
	if !cfg.AllowCorruptChainRecovery {
		return fmt.Errorf("%w: %v", ErrCorruptChain, verifyErr)
	}
	lastValid := findLastValidHash(entries)
	reason := fmt.Sprintf("recovery at %s: %v", time.Now().UTC().Format(time.RFC3339), verifyErr)
	boundary, err := buildSegmentBoundaryEntry(lastValid, reason)
	if err != nil {
		return fmt.Errorf("writ: build recovery boundary: %w", err)
	}
	return store.Append(boundary)
}

// findLastValidHash walks entries and returns the hash of the last entry that
// verifies correctly, or the genesis hash if none verify.
func findLastValidHash(entries []ChainEntry) string {
	prevHash := inaudit.PrevHashFor(nil)
	for _, e := range entries {
		ie := inaudit.Entry{
			ID:           e.ID,
			PrevHash:     e.PrevHash,
			Hash:         e.Hash,
			EventType:    e.EventType,
			ActionType:   e.ActionType,
			Actor:        e.Actor,
			CallerID:     e.CallerID,
			SessionID:    e.SessionID,
			InputHash:    e.InputHash,
			OutputHash:   e.OutputHash,
			Result:       e.Result,
			HookdTraceID: e.HookdTraceID,
			Allowed:      e.Allowed,
			DenialReason: e.DenialReason,
			Timestamp:    timestampString(e.Timestamp),
		}
		if ie.PrevHash != prevHash {
			break
		}
		want, err := inaudit.ComputeHash(ie)
		if err != nil || ie.Hash != want {
			break
		}
		prevHash = ie.Hash
	}
	return prevHash
}

// buildSegmentBoundaryEntry creates a ChainSegmentBoundary entry that anchors
// the start of a new chain segment after corruption recovery.
func buildSegmentBoundaryEntry(lastValidHash, reason string) (ChainEntry, error) {
	id := newAuditID()
	ts := time.Now().UTC()

	internal := inaudit.Entry{
		ID:        id,
		PrevHash:  lastValidHash,
		EventType: "chain_segment_boundary",
		Allowed:   true,
		Timestamp: ts.Format(time.RFC3339Nano),
		Metadata:  map[string]string{"type": "RECOVERY", "reason": reason},
	}

	hash, err := inaudit.ComputeHash(internal)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("compute boundary hash: %w", err)
	}
	internal.Hash = hash

	return ChainEntry{
		ID:        internal.ID,
		PrevHash:  internal.PrevHash,
		Hash:      internal.Hash,
		EventType: internal.EventType,
		Allowed:   internal.Allowed,
		Timestamp: ts,
		Metadata:  internal.Metadata,
	}, nil
}


// verifyChain is the internal entry point for Verify().
func verifyChain(entries []ChainEntry) error {
	internalEntries := make([]inaudit.Entry, len(entries))
	for i, e := range entries {
		internalEntries[i] = inaudit.Entry{
			ID:           e.ID,
			PrevHash:     e.PrevHash,
			Hash:         e.Hash,
			EventType:    e.EventType,
			ActionType:   e.ActionType,
			Actor:        e.Actor,
			CallerID:     e.CallerID,
			SessionID:    e.SessionID,
			InputHash:    e.InputHash,
			OutputHash:   e.OutputHash,
			Result:       e.Result,
			HookdTraceID: e.HookdTraceID,
			Allowed:      e.Allowed,
			DenialReason: e.DenialReason,
			Timestamp:    timestampString(e.Timestamp),
		}
	}
	return inaudit.Verify(internalEntries)
}
