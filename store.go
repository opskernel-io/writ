package writ

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// AuditStore is the pluggable backend for the Merkle audit chain (ADR #18).
// The default implementation is a JSONL file. Commercial tier adds S3 and PostgreSQL.
type AuditStore interface {
	Append(entry ChainEntry) error
	ReadAll() ([]ChainEntry, error)
	Verify() error
}

// ChainEntry is a single Merkle-linked audit record.
type ChainEntry struct {
	ID           string            `json:"id"`
	PrevHash     string            `json:"prev_hash"`
	Hash         string            `json:"hash"`
	EventType    string            `json:"event_type"`
	ActionType   string            `json:"action_type,omitempty"`
	Actor        string            `json:"actor,omitempty"`
	CallerID     string            `json:"caller_id,omitempty"`
	InputHash    string            `json:"input_hash,omitempty"`
	OutputHash   string            `json:"output_hash,omitempty"`
	Result       string            `json:"result,omitempty"`
	HookdTraceID string            `json:"hookd_trace_id,omitempty"`
	Allowed      bool              `json:"allowed"`
	DenialReason string            `json:"denial_reason,omitempty"`
	Tier         Tier              `json:"tier,omitempty"`
	Timestamp    interface{}       `json:"timestamp"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// jsonlStore is the default AuditStore implementation.
type jsonlStore struct {
	mu   sync.Mutex
	path string
}

func newJSONLStore(path string) (AuditStore, error) {
	path = filepath.Clean(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //#nosec G304 -- caller-configured path, not HTTP input
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	// Verify or restore 0600 — protects against umask drift and manual changes.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("writ: stat chain file: %w", err)
	}
	if fi.Mode().Perm() != 0o600 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("writ: chain file has insecure permissions (%#o) and chmod failed: %w", fi.Mode().Perm(), err)
		}
	}
	return &jsonlStore{path: path}, nil
}

func (s *jsonlStore) Append(entry ChainEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}

func (s *jsonlStore) ReadAll() ([]ChainEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []ChainEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e ChainEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("malformed chain entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

func (s *jsonlStore) Verify() error {
	entries, err := s.ReadAll()
	if err != nil {
		return err
	}
	return verifyChain(entries)
}

// ReadChainFile reads all entries from a JSONL chain file.
// Exported for testing and verification tooling.
func ReadChainFile(path string) ([]ChainEntry, error) {
	store, err := newJSONLStore(path)
	if err != nil {
		return nil, err
	}
	return store.ReadAll()
}

// memoryStore is an in-memory AuditStore for testing.
type memoryStore struct {
	mu      sync.Mutex
	entries []ChainEntry
}

// NewMemoryStore returns an in-memory AuditStore. Not safe for production use.
func NewMemoryStore() AuditStore {
	return &memoryStore{}
}

func (s *memoryStore) Append(entry ChainEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

func (s *memoryStore) ReadAll() ([]ChainEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ChainEntry, len(s.entries))
	copy(out, s.entries)
	return out, nil
}

func (s *memoryStore) Verify() error {
	entries, err := s.ReadAll()
	if err != nil {
		return err
	}
	return verifyChain(entries)
}
