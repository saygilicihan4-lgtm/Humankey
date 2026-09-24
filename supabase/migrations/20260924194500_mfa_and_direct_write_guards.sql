create or replace function public.guard_approval_insert()
returns trigger
language plpgsql
security invoker
set search_path=''
as $$
declare
  m public.mandates;
  v_agent_id uuid;
  v_action text;
  v_amount numeric;
  v_currency text;
  canonical jsonb;
  expected_fp text;
begin
  if (select auth.uid()) is null then raise exception 'authentication_required'; end if;
  if new.decision is not null or new.decided_at is not null or new.used_at is not null then raise exception 'invalid_approval_state'; end if;
  if new.expires_at<=now() or new.expires_at>now()+interval '10 minutes 5 seconds' then raise exception 'invalid_approval_expiry'; end if;
  if new.token_hash is null or new.token_hash !~ '^[0-9a-f]{64}$' then raise exception 'invalid_token_hash'; end if;
  if jsonb_typeof(new.action_payload) is distinct from 'object' then raise exception 'invalid_action_payload'; end if;

  begin
    v_agent_id:=nullif(new.action_payload->>'agentId','')::uuid;
  exception when others then
    raise exception 'invalid_action_payload';
  end;

  v_action:=btrim(coalesce(new.action_payload->>'action',''));
  if v_agent_id is null or v_action='' or length(v_action)>120 then raise exception 'invalid_action_payload'; end if;

  if new.action_payload ? 'amount' and new.action_payload->'amount'<>'null'::jsonb then
    if jsonb_typeof(new.action_payload->'amount')<>'number' then raise exception 'invalid_action_payload'; end if;
    v_amount:=(new.action_payload->>'amount')::numeric;
    if v_amount<0 then raise exception 'invalid_action_payload'; end if;
  end if;

  if new.action_payload ? 'currency' and new.action_payload->'currency'<>'null'::jsonb then
    if jsonb_typeof(new.action_payload->'currency')<>'string' then raise exception 'invalid_action_payload'; end if;
    v_currency:=upper(btrim(new.action_payload->>'currency'));
    if v_currency !~ '^[A-Z]{3}$' then raise exception 'invalid_action_payload'; end if;
  end if;

  select x.* into m
  from public.mandates x
  join public.organizations o on o.id=x.organization_id
  where x.id=new.mandate_id
    and x.organization_id=new.organization_id
    and o.owner_id=(select auth.uid())
    and x.revoked_at is null
    and x.expires_at>now();

  if m.id is null then raise exception 'mandate_unavailable'; end if;
  if m.agent_id<>v_agent_id or not (v_action=any(m.actions)) then raise exception 'approval_not_required'; end if;
  if v_amount is null or m.approval_above is null or v_amount<=m.approval_above then raise exception 'approval_not_required'; end if;
  if m.currency is not null and v_currency is distinct from upper(m.currency) then raise exception 'approval_not_required'; end if;
  if m.max_amount is not null and v_amount>m.max_amount then raise exception 'approval_not_required'; end if;

  canonical:=jsonb_build_object('agentId',v_agent_id,'action',v_action,'amount',v_amount,'currency',v_currency);
  if new.action_payload is distinct from canonical then raise exception 'noncanonical_action_payload'; end if;

  expected_fp:=encode(extensions.digest(canonical::text,'sha256'),'hex');
  if new.action_fingerprint is distinct from expected_fp then raise exception 'action_fingerprint_mismatch'; end if;

  return new;
end $$;

drop trigger if exists approvals_insert_guard on public.approvals;
create trigger approvals_insert_guard
before insert on public.approvals
for each row execute function public.guard_approval_insert();

create or replace function public.guard_execution_ticket_insert()
returns trigger
language plpgsql
security invoker
set search_path=''
as $$
declare
  a public.approvals;
begin
  if (select auth.uid()) is null then raise exception 'authentication_required'; end if;
  if coalesce((select auth.jwt()->>'aal'),'aal1')<>'aal2' then raise exception 'mfa_required'; end if;
  if new.consumed_at is not null then raise exception 'invalid_ticket_state'; end if;
  if new.expires_at<=now() or new.expires_at>now()+interval '2 minutes 5 seconds' then raise exception 'invalid_ticket_expiry'; end if;
  if new.secret_hash is null or new.secret_hash !~ '^[0-9a-f]{64}$' then raise exception 'invalid_secret_hash'; end if;

  select x.* into a
  from public.approvals x
  join public.organizations o on o.id=x.organization_id
  where x.id=new.approval_id
    and o.owner_id=(select auth.uid())
    and x.decision='APPROVED'
    and x.used_at is not null
    and x.expires_at>now();

  if a.id is null then raise exception 'approval_unavailable'; end if;

  if new.organization_id<>a.organization_id
     or new.mandate_id<>a.mandate_id
     or new.action_fingerprint is distinct from a.action_fingerprint
     or new.action_payload is distinct from a.action_payload
  then raise exception 'ticket_binding_mismatch'; end if;

  return new;
end $$;

drop trigger if exists execution_ticket_insert_guard on public.execution_tickets;
create trigger execution_ticket_insert_guard
before insert on public.execution_tickets
for each row execute function public.guard_execution_ticket_insert();

drop policy if exists approvals_update_requires_aal2 on public.approvals;
create policy approvals_update_requires_aal2
on public.approvals
as restrictive
for update
to authenticated
using ((select auth.jwt()->>'aal')='aal2')
with check ((select auth.jwt()->>'aal')='aal2');

drop policy if exists execution_tickets_insert_requires_aal2 on public.execution_tickets;
create policy execution_tickets_insert_requires_aal2
on public.execution_tickets
as restrictive
for insert
to authenticated
with check ((select auth.jwt()->>'aal')='aal2');

drop policy if exists execution_tickets_update_requires_aal2 on public.execution_tickets;
create policy execution_tickets_update_requires_aal2
on public.execution_tickets
as restrictive
for update
to authenticated
using ((select auth.jwt()->>'aal')='aal2')
with check ((select auth.jwt()->>'aal')='aal2');

drop policy if exists mandates_update_requires_aal2 on public.mandates;
create policy mandates_update_requires_aal2
on public.mandates
as restrictive
for update
to authenticated
using ((select auth.jwt()->>'aal')='aal2')
with check ((select auth.jwt()->>'aal')='aal2');

drop policy if exists agents_update_requires_aal2 on public.agents;
create policy agents_update_requires_aal2
on public.agents
as restrictive
for update
to authenticated
using ((select auth.jwt()->>'aal')='aal2')
with check ((select auth.jwt()->>'aal')='aal2');

revoke execute on function public.guard_approval_insert() from public, anon, authenticated;
revoke execute on function public.guard_execution_ticket_insert() from public, anon, authenticated;
