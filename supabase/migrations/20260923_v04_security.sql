-- HUMANKEY v0.4 database hardening
create index if not exists organizations_owner_idx on public.organizations(owner_id);
create index if not exists approvals_mandate_idx on public.approvals(mandate_id);

create or replace function public.enforce_mandate_agent_org()
returns trigger language plpgsql security invoker set search_path = '' as $$
begin
  if not exists (
    select 1 from public.agents a
    where a.id = new.agent_id and a.organization_id = new.organization_id
  ) then
    raise exception 'agent_not_in_organization';
  end if;
  return new;
end;
$$;

revoke all on function public.enforce_mandate_agent_org() from public, anon, authenticated;
drop trigger if exists mandates_agent_org_guard on public.mandates;
create trigger mandates_agent_org_guard
before insert or update of agent_id, organization_id on public.mandates
for each row execute function public.enforce_mandate_agent_org();
