// Demo: writ end-to-end flow.
//
// Opens a Merkle audit chain, makes one LLM call through the writ gate,
// verifies the chain, and prints the result.
//
// Usage:
//
//	ANTHROPIC_API_KEY=sk-ant-... go run ./examples/demo/
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/opskernel-io/writ"
)

func main() {
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		log.Fatal("ANTHROPIC_API_KEY is not set")
	}

	chainPath := filepath.Join(os.TempDir(), "writ-demo-chain.jsonl")

	// Locate the policy directory bundled with this demo.
	_, thisFile, _, _ := runtime.Caller(0)
	policyDir := filepath.Join(filepath.Dir(thisFile), "policy")

	client, err := writ.New(writ.Config{
		PolicyPath: policyDir,
		AuditPath:  chainPath,
		CallerID:   "writ-demo",
	})
	if err != nil {
		log.Fatalf("writ.New: %v", err)
	}

	fmt.Printf("chain: %s\n", chainPath)

	msg, err := client.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeHaiku4_5,
		MaxTokens: 64,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock("Reply with exactly: writ demo ok")),
		},
	})
	if err != nil {
		log.Fatalf("Messages.New: %v", err)
	}

	if len(msg.Content) > 0 {
		fmt.Printf("response: %s\n", msg.Content[0].Text)
	}

	result, err := client.VerifyFull()
	if err != nil {
		log.Fatalf("VerifyFull: %v", err)
	}

	if result.Valid {
		fmt.Printf("chain verified: %d entries, root=%s\n", result.EntryCount, result.RootHash[:12])
	} else {
		fmt.Printf("chain INVALID\n")
		os.Exit(1)
	}
}
