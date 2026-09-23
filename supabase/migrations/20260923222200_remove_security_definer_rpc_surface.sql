grant insert on public.approvals to authenticated;
grant insert on public.evidence_events to authenticated;
grant insert,update on public.execution_tickets to authenticated;

drop policy if exists approvals_insert_owner on public.approvals;
create policy approvals_insert_owner on public.approvals for insert to authenticated
with check (
 exists(select 1 from public.organizations o where o.id=approvals.organization_id and o.owner_id=auth.uid())
 and exists(select 1 from public.mandates m where m.id=approvals.mandate_id and m.organization_id=approvals.organization_id and m.revoked_at is null and m.expires_at>now())
 and decision is null and decided_at is null and used_at is null
);

drop policy if exists evidence_insert_owner on public.evidence_events;
create policy evidence_insert_owner on public.evidence_events for insert to authenticated
with check (exists(select 1 from public.organizations o where o.id=evidence_events.organization_id and o.owner_id=auth.uid()));

drop policy if exists execution_tickets_insert_owner on public.execution_tickets;
create policy execution_tickets_insert_owner on public.execution_tickets for insert to authenticated
with check (
 exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=auth.uid())
 and exists(select 1 from public.approvals a where a.id=execution_tickets.approval_id and a.organization_id=execution_tickets.organization_id and a.mandate_id=execution_tickets.mandate_id and a.decision='APPROVED' and a.used_at is null and a.expires_at>now())
);
drop policy if exists execution_tickets_update_owner on public.execution_tickets;
create policy execution_tickets_update_owner on public.execution_tickets for update to authenticated
using (exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=auth.uid()))
with check (exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=auth.uid()));

alter function public.append_authorization_evidence(uuid,text,jsonb) security invoker;
alter function public.create_approval_request(uuid,jsonb) security invoker;
alter function public.decide_approval(uuid,text) security invoker;
alter function public.issue_execution_ticket(uuid) security invoker;
alter function public.consume_execution_ticket(uuid,text,jsonb) security invoker;
