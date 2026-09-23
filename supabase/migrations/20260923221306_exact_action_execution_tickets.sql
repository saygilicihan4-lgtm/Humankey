create table if not exists public.execution_tickets(
 id uuid primary key default gen_random_uuid(),
 organization_id uuid not null references public.organizations(id) on delete cascade,
 mandate_id uuid not null references public.mandates(id) on delete cascade,
 approval_id uuid not null unique references public.approvals(id) on delete cascade,
 secret_hash text not null,
 action_fingerprint text not null,
 action_payload jsonb not null,
 expires_at timestamptz not null,
 consumed_at timestamptz,
 created_at timestamptz not null default now()
);
create index if not exists execution_tickets_org_idx on public.execution_tickets(organization_id);
alter table public.execution_tickets enable row level security;
drop policy if exists execution_tickets_select on public.execution_tickets;
create policy execution_tickets_select on public.execution_tickets for select to authenticated
using (exists(select 1 from public.organizations o where o.id=execution_tickets.organization_id and o.owner_id=auth.uid()));
revoke all on public.execution_tickets from public,anon;
grant select on public.execution_tickets to authenticated;

create or replace function public.issue_execution_ticket(p_approval_id uuid)
returns jsonb
language plpgsql security definer set search_path=''
as $$
declare a public.approvals; raw_secret text; t public.execution_tickets;
begin
 update public.approvals x set used_at=now()
 where x.id=p_approval_id and x.decision='APPROVED' and x.used_at is null and x.expires_at>now()
 and exists(select 1 from public.organizations o where o.id=x.organization_id and o.owner_id=auth.uid())
 returning * into a;
 if a.id is null then raise exception 'approval_unavailable'; end if;
 raw_secret:=gen_random_uuid()::text||gen_random_uuid()::text;
 insert into public.execution_tickets(organization_id,mandate_id,approval_id,secret_hash,action_fingerprint,action_payload,expires_at)
 values(a.organization_id,a.mandate_id,a.id,encode(extensions.digest(raw_secret,'sha256'),'hex'),a.action_fingerprint,a.action_payload,now()+interval '2 minutes')
 returning * into t;
 return jsonb_build_object('id',t.id,'secret',raw_secret,'expiresAt',t.expires_at,'actionFingerprint',t.action_fingerprint);
end $$;
revoke all on function public.issue_execution_ticket(uuid) from public,anon;
grant execute on function public.issue_execution_ticket(uuid) to authenticated;

create or replace function public.consume_execution_ticket(p_ticket_id uuid,p_secret text,p_action_payload jsonb)
returns jsonb
language plpgsql security definer set search_path=''
as $$
declare t public.execution_tickets; fp text;
begin
 fp:=encode(extensions.digest(p_action_payload::text,'sha256'),'hex');
 update public.execution_tickets x set consumed_at=now()
 where x.id=p_ticket_id and x.consumed_at is null and x.expires_at>now()
 and x.secret_hash=encode(extensions.digest(p_secret,'sha256'),'hex')
 and x.action_fingerprint=fp
 and exists(select 1 from public.organizations o where o.id=x.organization_id and o.owner_id=auth.uid())
 returning * into t;
 if t.id is null then raise exception 'execution_ticket_unavailable'; end if;
 return jsonb_build_object('id',t.id,'organizationId',t.organization_id,'mandateId',t.mandate_id,'approvalId',t.approval_id,'consumedAt',t.consumed_at,'actionFingerprint',t.action_fingerprint);
end $$;
revoke all on function public.consume_execution_ticket(uuid,text,jsonb) from public,anon;
grant execute on function public.consume_execution_ticket(uuid,text,jsonb) to authenticated;
