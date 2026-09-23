alter table public.approvals add column if not exists decision text check (decision in ('APPROVED','REJECTED'));
alter table public.approvals add column if not exists decided_at timestamptz;

create or replace function public.decide_approval(p_approval_id uuid,p_decision text)
returns public.approvals
language plpgsql security definer set search_path=''
as $$
declare rec public.approvals;
begin
 if p_decision not in ('APPROVED','REJECTED') then raise exception 'invalid_decision'; end if;
 update public.approvals a set decision=p_decision,decided_at=now()
 where a.id=p_approval_id and a.decision is null and a.used_at is null and a.expires_at>now()
 and exists(select 1 from public.organizations o where o.id=a.organization_id and o.owner_id=auth.uid())
 returning * into rec;
 if rec.id is null then raise exception 'approval_unavailable'; end if;
 return rec;
end $$;
revoke all on function public.decide_approval(uuid,text) from public,anon;
grant execute on function public.decide_approval(uuid,text) to authenticated;
