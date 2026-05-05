package writ

import (
	"context"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/packages/ssestream"
)

// MessagesService wraps anthropic's Messages API with gate + audit.
type MessagesService struct {
	wc *Client
}

// New evaluates the OPA policy gate, writes a pre-call audit entry,
// calls the inner anthropic.Client if allowed, then writes a post-call entry.
// Returns *DenialError if the policy denies the call (no network call made).
func (s *MessagesService) New(ctx context.Context, params anthropic.MessageNewParams) (*anthropic.Message, error) {
	decision, entry, err := s.wc.gater.evaluate(ctx, params, s.wc.cfg)
	if err != nil {
		return nil, fmt.Errorf("writ: gate evaluation: %w", err)
	}

	entry.Timestamp = time.Now().UTC()
	if err := s.wc.chain.Append(entry); err != nil {
		return nil, fmt.Errorf("writ: write pre-call audit entry: %w", err)
	}

	if !decision.Allowed {
		return nil, &DenialError{
			Reason:  decision.DenialReason,
			AuditID: decision.AuditID,
			Tier:    decision.Tier,
		}
	}

	resp, callErr := s.wc.inner.Messages.New(ctx, params)

	postEntry, buildErr := buildPostCallEntry(s.wc.chain, entry, resp, callErr, s.wc.cfg)
	if buildErr == nil {
		_ = s.wc.chain.Append(postEntry)
	}

	return resp, callErr
}

// NewStreaming evaluates the gate and, if allowed, opens a streaming response.
// A streaming-started audit entry is written before the stream opens.
// A streaming-complete entry is written after the stream closes (ADR #19).
// Returns *DenialError if the policy denies the call.
func (s *MessagesService) NewStreaming(ctx context.Context, params anthropic.MessageNewParams) (*WritStream, error) {
	decision, entry, err := s.wc.gater.evaluate(ctx, params, s.wc.cfg)
	if err != nil {
		return nil, fmt.Errorf("writ: gate evaluation: %w", err)
	}

	entry.EventType = "llm_call_streaming_started"
	entry.Timestamp = time.Now().UTC()
	if err := s.wc.chain.Append(entry); err != nil {
		return nil, fmt.Errorf("writ: write streaming-started audit entry: %w", err)
	}

	if !decision.Allowed {
		return nil, &DenialError{
			Reason:  decision.DenialReason,
			AuditID: decision.AuditID,
			Tier:    decision.Tier,
		}
	}

	inner := s.wc.inner.Messages.NewStreaming(ctx, params)
	return &WritStream{
		inner:      inner,
		wc:         s.wc,
		startEntry: entry,
	}, nil
}

// WritStream wraps the anthropic SSE stream to write the streaming-complete
// audit entry when the stream closes.
type WritStream struct {
	inner      *ssestream.Stream[anthropic.MessageStreamEventUnion]
	wc         *Client
	startEntry ChainEntry
}

// Stream returns the underlying SSE stream for reading events.
func (s *WritStream) Stream() *ssestream.Stream[anthropic.MessageStreamEventUnion] {
	return s.inner
}

// Close writes the streaming-complete audit entry and closes the stream.
func (s *WritStream) Close() error {
	closeErr := s.inner.Close()

	completeEntry, err := buildStreamCompleteEntry(s.wc.chain, s.startEntry, closeErr, s.wc.cfg)
	if err == nil {
		_ = s.wc.chain.Append(completeEntry)
	}

	return closeErr
}
