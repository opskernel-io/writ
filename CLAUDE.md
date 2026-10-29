# writ-core

<!-- ce:begin -->
## Compound Engineering loop

Work here runs the CE loop: `/ce-plan → /ce-work → /ce-code-review → /ce-commit-push-pr`.
PRs are merged by `~/.claude/scripts/ce-merge-pr.sh <pr> -R <owner/repo>`, not by hand.
CE artifacts (plans, solutions, brainstorms) live under `docs/ce` (`.compound-engineering/config.yaml`).
Review criteria: `CODING_STANDARDS.md`. New repo? `ce-bootstrap-repo.sh <path> --kind <k>`.
<!-- ce:end -->
