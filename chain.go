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
func buildChainEntry(store AuditStore, event AuditEvent, callerID, hookdTraceID string) (ChainEntry, error) {
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
		ts := ""
		if t, ok := e.Timestamp.(time.Time); ok {
			ts = t.Format(time.RFC3339Nano)
		}
		internalEntries[i] = inaudit.Entry{
			Hash:      e.Hash,
			Timestamp: ts,
		}
	}
	return inaudit.PrevHashFor(internalEntries), nil
}

// verifyChain is the internal entry point for Verify().
func verifyChain(entries []ChainEntry) error {
	internalEntries := make([]inaudit.Entry, len(entries))
	for i, e := range entries {
		ts := ""
		if t, ok := e.Timestamp.(time.Time); ok {
			ts = t.Format(time.RFC3339Nano)
		}
		internalEntries[i] = inaudit.Entry{
			ID:           e.ID,
			PrevHash:     e.PrevHash,
			Hash:         e.Hash,
			EventType:    e.EventType,
			ActionType:   e.ActionType,
			Actor:        e.Actor,
			CallerID:     e.CallerID,
			InputHash:    e.InputHash,
			OutputHash:   e.OutputHash,
			Result:       e.Result,
			HookdTraceID: e.HookdTraceID,
			Allowed:      e.Allowed,
			DenialReason: e.DenialReason,
			Timestamp:    ts,
		}
	}
	return inaudit.Verify(internalEntries)
}
