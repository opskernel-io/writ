// Package audit implements Merkle chain construction and verification.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is a single record in the Merkle audit chain.
// Mirrors writ.ChainEntry — audit package owns the hash logic;
// the public writ package exposes ChainEntry to callers.
type Entry struct {
	ID           string            `json:"id"`
	PrevHash     string            `json:"prev_hash"`
	Hash         string            `json:"hash"`
	EventType    string            `json:"event_type"`
	ActionType   string            `json:"action_type,omitempty"`
	CallerID     string            `json:"caller_id,omitempty"`
	InputHash    string            `json:"input_hash,omitempty"`
	OutputHash   string            `json:"output_hash,omitempty"`
	HookdTraceID string            `json:"hookd_trace_id,omitempty"`
	Allowed      bool              `json:"allowed"`
	DenialReason string            `json:"denial_reason,omitempty"`
	Tier         int               `json:"tier,omitempty"`
	Timestamp    string            `json:"timestamp"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// HashContent is the subset of fields included in the Merkle hash.
// Excludes Hash itself (computed from this) and Metadata (advisory).
type HashContent struct {
	PrevHash     string `json:"prev_hash"`
	EventType    string `json:"event_type"`
	ActionType   string `json:"action_type,omitempty"`
	CallerID     string `json:"caller_id,omitempty"`
	InputHash    string `json:"input_hash,omitempty"`
	OutputHash   string `json:"output_hash,omitempty"`
	HookdTraceID string `json:"hookd_trace_id,omitempty"`
	Allowed      bool   `json:"allowed"`
	DenialReason string `json:"denial_reason,omitempty"`
	Timestamp    string `json:"timestamp"`
}

// ComputeHash computes the SHA-256 hash for a chain entry given its previous hash.
func ComputeHash(e Entry) (string, error) {
	content := HashContent{
		PrevHash:     e.PrevHash,
		EventType:    e.EventType,
		ActionType:   e.ActionType,
		CallerID:     e.CallerID,
		InputHash:    e.InputHash,
		OutputHash:   e.OutputHash,
		HookdTraceID: e.HookdTraceID,
		Allowed:      e.Allowed,
		DenialReason: e.DenialReason,
		Timestamp:    e.Timestamp,
	}
	b, err := json.Marshal(content)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// HashContent returns the SHA-256 of arbitrary bytes — for input/output hashing.
func HashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// PrevHashFor returns the hash of the last entry in the chain,
// or the genesis hash if the chain is empty.
func PrevHashFor(entries []Entry) string {
	if len(entries) == 0 {
		return genesisHash
	}
	return entries[len(entries)-1].Hash
}

// Verify walks the chain and confirms each entry's Hash matches
// SHA-256(HashContent) and that PrevHash links are intact.
func Verify(entries []Entry) error {
	prevHash := genesisHash
	for i, e := range entries {
		if e.PrevHash != prevHash {
			return fmt.Errorf("chain broken at entry %d (id=%s): prev_hash mismatch (want %s, got %s)",
				i, e.ID, prevHash, e.PrevHash)
		}
		want, err := ComputeHash(e)
		if err != nil {
			return fmt.Errorf("chain: hash computation failed at entry %d: %w", i, err)
		}
		if e.Hash != want {
			return fmt.Errorf("chain tampered at entry %d (id=%s): hash mismatch (want %s, got %s)",
				i, e.ID, want, e.Hash)
		}
		prevHash = e.Hash
	}
	return nil
}
