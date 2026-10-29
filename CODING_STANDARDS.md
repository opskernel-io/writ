# Coding Standards

Review criteria for every change in this repository (`ce-code-review` grades diffs against this file;
`ce-plan` and `ce-work` read it as project instructions). Floor-wide rules come from the Compound
Packs in `.compound-engineering/config.yaml`. Repo kind: go. Stub: extend it as the repo's rules are written down.

- Conventional commit subjects typed by intent; one unit of work per commit.
- No secrets, tokens, private keys or `.env` content in any commit or doc; reference a credential by its SOPS key.
- No hard-coded homelab addresses (`192.168.1.x` is temporary); name hosts by SSH alias or inventory name.
- A PR is not done until CI has decided.
