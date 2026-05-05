package writ.gate

import rego.v1

# Default policy: allow all calls, assign standard tier.
# Replace with your organisation's policy.
#
# Input fields available:
#   input.caller_id    — agent process identifier
#   input.action_type  — e.g. "llm_call"
#   input.model        — model string passed to the API
#   input.est_tokens   — estimated token count (0 if unknown)
#   input.metadata     — map of extra key-value context

default allow := true
default tier := 2        # TierStandard
default denial_reason := ""
