package gate

import (
	"context"
	"testing"
)

func BenchmarkGateEvaluate(b *testing.B) {
	g, err := New(context.Background(), "/tmp/writ-bench-policy", false)
	if err != nil {
		b.Fatal(err)
	}
	input := GateInput{
		CallerID:   "bench-agent",
		ActionType: "llm_call",
		Model:      "claude-sonnet-4-6",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := g.Evaluate(context.Background(), input)
		if err != nil {
			b.Fatal(err)
		}
	}
}
