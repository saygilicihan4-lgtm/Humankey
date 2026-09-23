create index if not exists execution_tickets_mandate_idx on public.execution_tickets(mandate_id);

revoke update on public.approvals from authenticated;
grant update(decision,decided_at,used_at) on public.approvals to authenticated;
drop policy if exists approvals_update_owner on public.approvals;
create policy approvals_update_owner on public.approvals for update to authenticated
using (exists(select 1 from public.organizations o where o.id=approvals.organization_id and o.owner_id=(select auth.uid())))
with check (exists(select 1 from public.organizations o where o.id=approvals.organization_id and o.owner_id=(select auth.uid())));

revoke update on public.execution_tickets from authenticated;
grant update(consumed_at) on public.execution_tickets to authenticated;

drop policy if exists execution_tickets_select on public.execution_tickets;
create policy execution_tickets_select on public.execution_tickets for select to authenticated
using (exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=(select auth.uid())));
drop policy if exists approvals_insert_owner on public.approvals;
create policy approvals_insert_owner on public.approvals for insert to authenticated
with check (exists(select 1 from public.organizations o where o.id=approvals.organization_id and o.owner_id=(select auth.uid())) and exists(select 1 from public.mandates m where m.id=approvals.mandate_id and m.organization_id=approvals.organization_id and m.revoked_at is null and m.expires_at>now()) and decision is null and decided_at is null and used_at is null);
drop policy if exists evidence_insert_owner on public.evidence_events;
create policy evidence_insert_owner on public.evidence_events for insert to authenticated
with check (exists(select 1 from public.organizations o where o.id=evidence_events.organization_id and o.owner_id=(select auth.uid())));
drop policy if exists execution_tickets_insert_owner on public.execution_tickets;
create policy execution_tickets_insert_owner on public.execution_tickets for insert to authenticated
with check (exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=(select auth.uid())) and exists(select 1 from public.approvals a where a.id=execution_tickets.approval_id and a.organization_id=execution_tickets.organization_id and a.mandate_id=execution_tickets.mandate_id and a.decision='APPROVED' and a.used_at is not null and a.expires_at>now()));
drop policy if exists execution_tickets_update_owner on public.execution_tickets;
create policy execution_tickets_update_owner on public.execution_tickets for update to authenticated
using (exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=(select auth.uid())))
with check (exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=(select auth.uid())));

create or replace function public.guard_approval_transition() returns trigger language plpgsql security invoker set search_path='' as $$
begin
 if new.organization_id<>old.organization_id or new.mandate_id<>old.mandate_id or new.token_hash<>old.token_hash or new.expires_at<>old.expires_at or new.created_at<>old.created_at or new.action_fingerprint is distinct from old.action_fingerprint or new.action_payload is distinct from old.action_payload then raise exception 'approval_immutable_fields'; end if;
 if old.decision is not null and new.decision is distinct from old.decision then raise exception 'approval_decision_immutable'; end if;
 if old.used_at is not null and new.used_at is distinct from old.used_at then raise exception 'approval_usage_immutable'; end if;
 if new.used_at is not null and new.decision<>'APPROVED' then raise exception 'approval_must_be_approved_before_use'; end if;
 return new;
end $$;
revoke all on function public.guard_approval_transition() from public,anon,authenticated;
drop trigger if exists approvals_transition_guard on public.approvals;
create trigger approvals_transition_guard before update on public.approvals for each row execute function public.guard_approval_transition();

create or replace function public.guard_execution_ticket_transition() returns trigger language plpgsql security invoker set search_path='' as $$
begin
 if new.organization_id<>old.organization_id or new.mandate_id<>old.mandate_id or new.approval_id<>old.approval_id or new.secret_hash<>old.secret_hash or new.action_fingerprint<>old.action_fingerprint or new.action_payload is distinct from old.action_payload or new.expires_at<>old.expires_at or new.created_at<>old.created_at then raise exception 'execution_ticket_immutable_fields'; end if;
 if old.consumed_at is not null and new.consumed_at is distinct from old.consumed_at then raise exception 'execution_ticket_already_consumed'; end if;
 return new;
end $$;
revoke all on function public.guard_execution_ticket_transition() from public,anon,authenticated;
drop trigger if exists execution_ticket_transition_guard on public.execution_tickets;
create trigger execution_ticket_transition_guard before update on public.execution_tickets for each row execute function public.guard_execution_ticket_transition();
