# writ examples

## demo

End-to-end flow: `writ.New()` → `Messages.New()` → `VerifyFull()`.

```
ANTHROPIC_API_KEY=sk-ant-... go run ./examples/demo/
```

Expected output:

```
chain: /tmp/writ-demo-chain.jsonl
response: writ demo ok
chain verified: 2 entries, root=<hash prefix>
```

The chain file at `/tmp/writ-demo-chain.jsonl` persists between runs. Delete it to start fresh.
