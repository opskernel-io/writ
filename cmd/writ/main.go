// Command writ provides the writ verify CLI tool.
//
// Usage:
//
//	writ verify <chain.jsonl>   — verify Merkle chain integrity
//	writ version                — print writ-core version
package main

import (
	"fmt"
	"os"

	"github.com/opskernel-io/writ"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "verify":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: writ verify <chain.jsonl>")
			os.Exit(1)
		}
		if err := writ.Verify(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "chain verification failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("chain OK")
	case "version":
		fmt.Println(writ.Version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `writ — codification gate and audit chain for LLM agents

Usage:
  writ verify <chain.jsonl>   verify Merkle chain integrity
  writ version                print writ-core version`)
}
