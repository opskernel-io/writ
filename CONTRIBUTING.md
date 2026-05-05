# Contributing to writ

## Opening an issue

- Search existing issues before opening a new one.
- For bugs: include the writ version (`go list -m github.com/opskernel-io/writ`), Go version, OS, and a minimal reproducer.
- For feature requests: describe the problem you're solving, not just the solution.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes. Run `go test ./...` and `go vet ./...` before pushing.
3. Open a PR against `main`. Keep the title concise and in the imperative mood ("Add X", "Fix Y").
4. A maintainer will review within 5 business days. CI must pass before merge.

## DCO sign-off

This project uses the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) in place of a CLA. Add a sign-off line to every commit:

```
git commit -s -m "your commit message"
```

This appends `Signed-off-by: Your Name <your@email.com>` to the commit message. By signing off you certify that you wrote the code or have the right to submit it under the Apache 2.0 license.

PRs with unsigned commits will not be merged.

## Code style

- Standard `gofmt` formatting.
- No new exported symbols without a doc comment.
- Security-sensitive code (`internal/audit`, `internal/gate`) must pass `gosec ./...` with no new suppressions unless reviewed and justified in the PR description.
