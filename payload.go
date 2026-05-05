package writ

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// payloadEntry is a single record in the sidecar .payloads JSONL file.
// It stores the raw JSON of the input and/or output for one audited operation.
type payloadEntry struct {
	AuditID   string          `json:"audit_id"`
	Timestamp time.Time       `json:"timestamp"`
	EventType string          `json:"event_type"`
	Input     json.RawMessage `json:"input,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
}

// payloadWriter appends payloadEntry records to a sidecar JSONL file.
// Write failures are silent: the main chain is authoritative; the payloads
// file is supplementary and must not block normal operation.
type payloadWriter struct {
	mu   sync.Mutex
	path string
}

func newPayloadWriter(auditPath string) (*payloadWriter, error) {
	path := filepath.Clean(auditPath) + ".payloads"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //#nosec G304 -- construction-time path, same trust as AuditPath
	if err != nil {
		return nil, fmt.Errorf("writ: open payloads file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("writ: close payloads file: %w", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("writ: stat payloads file: %w", err)
	}
	if fi.Mode().Perm() != 0o600 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("writ: payloads file has insecure permissions (%#o) and chmod failed: %w", fi.Mode().Perm(), err)
		}
	}
	return &payloadWriter{path: path}, nil
}

func (pw *payloadWriter) write(entry payloadEntry) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	f, err := os.OpenFile(pw.path, os.O_APPEND|os.O_WRONLY, 0o600) //#nosec G304
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "%s\n", line)
}
