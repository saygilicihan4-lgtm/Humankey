# HUMANKEY
Human Control Plane for AI agents.

## v0.1 Gateway
Deterministic authorization enforcement with three outcomes: **ALLOW**, **DENY**, **REQUIRE_APPROVAL**.

### Security invariant
An LLM may help compile human intent into a mandate, but it never makes the final authorization decision.

### Run
```bash
npm install
npm test
npm run dev
```

### Demo
Create a mandate with `POST /v1/mandates`, then evaluate actions through `POST /v1/authorize`. Revoke with `POST /v1/mandates/:id/revoke`. Every authorization attempt is recorded at `GET /v1/audit`.

## Next milestone
Persistent storage, signed mandates, one-time approvals, hash-chained evidence ledger, delegation authority ceilings, dashboard and MCP adapter.

> v0.1 is an engineering prototype, not yet a production security boundary.
