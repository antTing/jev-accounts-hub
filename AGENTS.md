# Jev Decision Tool

This project exposes the local TypeSafe/Jev gateway through the `jev_decide` MCP
tool. Its stdio bridge lives at `cmd/jev-mcp` and is registered in the user-level
Codex MCP configuration so it is available from any project.

Use `jev_decide` when a task needs a narrow semantic judgment such as routing,
ranking, urgency, risk, or whether a stated condition holds. Keep the state
complete and the questions typed using the native TypeSafe System One format
(`choice`, `score`, or `noul`). Ask independent questions together. Do not use
Jev for exact lookups, deterministic rules, code generation, or tool execution;
those remain the agent's responsibility. Treat probabilities and confidence as
advisory evidence and escalate uncertain or consequential decisions.
