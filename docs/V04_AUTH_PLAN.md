# HUMANKEY v0.4 Auth + Persistence

This branch isolates the production-foundation work from main.

## Invariants
- Supabase Auth is the user identity source.
- RLS is the tenant boundary.
- No service-role key or private signing key is committed.
- Authorization remains default-deny.
- Mandates persist in PostgreSQL rather than process memory.
- Ed25519 signatures detect mandate tampering.
- Approval credentials are short-lived and single-use.

## Gate before merge
1. Authenticated session verification.
2. Organization ownership enforced by RLS.
3. Database-backed mandate create/read/revoke.
4. Cross-tenant negative tests.
5. Signing tamper tests.
6. Security Advisor returns no findings.
