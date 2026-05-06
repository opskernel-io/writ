# caller_allowlist.rego — optional policy for restricting chain-writing callers.
#
# Activate by editing the set below and removing (or overriding) the
# `default allow := true` rule in writ.rego.
#
# writ passes input.caller_id on every gate evaluation. Only callers in the
# set below will be permitted to execute LLM calls (and write to the chain).
#
# Example (uncomment to activate):
#
# package writ.gate
#
# import rego.v1
#
# _allowed_callers := {"my-agent-v1", "my-agent-v2"}
#
# deny if {
#     count(_allowed_callers) > 0
#     not _allowed_callers[input.caller_id]
# }
#
# allow if {
#     not deny
# }
