# HUMANKEY Security Model

## Core invariants
1. The LLM is never the authorization authority.
2. Default deny when a mandate is missing, expired, revoked, malformed, or outside scope.
3. Delegated authority must be a strict subset of parent authority.
4. Approval tokens are short-lived and single-use.
5. Authorization evidence is hash chained so tampering can be detected.
6. Production credentials must never be stored in the repository.

## Threats covered in v0.2
- authority ceiling breach
- approval replay
- expired/revoked mandates
- action scope escalation
- delegation escalation
- audit-chain tampering detection

## Not production ready
The current implementation is a prototype. Durable storage, key management, authentication, rate limiting, tenant isolation and external security review are required before protecting real financial or sensitive actions.
