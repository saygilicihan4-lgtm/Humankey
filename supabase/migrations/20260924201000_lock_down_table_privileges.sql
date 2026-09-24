revoke truncate, trigger, references on table public.organizations from authenticated;
revoke truncate, trigger, references on table public.agents from authenticated;
revoke truncate, trigger, references on table public.mandates from authenticated;
revoke truncate, trigger, references on table public.approvals from authenticated;
revoke truncate, trigger, references on table public.evidence_events from authenticated;
revoke truncate, trigger, references on table public.execution_tickets from authenticated;

revoke delete on table public.organizations from authenticated;
revoke delete on table public.agents from authenticated;
revoke delete on table public.mandates from authenticated;

revoke all on table public.organizations from anon;
revoke all on table public.agents from anon;
revoke all on table public.mandates from anon;
revoke all on table public.approvals from anon;
revoke all on table public.evidence_events from anon;
revoke all on table public.execution_tickets from anon;
