alter table public.approvals add column if not exists action_fingerprint text;
alter table public.approvals add column if not exists action_payload jsonb;

create or replace function public.create_approval_request(p_mandate_id uuid,p_action_payload jsonb)
returns public.approvals
language plpgsql security definer set search_path=''
as $$
declare org uuid; rec public.approvals; fp text;
begin
 select m.organization_id into org from public.mandates m join public.organizations o on o.id=m.organization_id where m.id=p_mandate_id and o.owner_id=auth.uid() and m.revoked_at is null and m.expires_at>now();
 if org is null then raise exception 'forbidden'; end if;
 fp:=encode(extensions.digest(p_action_payload::text,'sha256'),'hex');
 insert into public.approvals(organization_id,mandate_id,token_hash,expires_at,action_fingerprint,action_payload)
 values(org,p_mandate_id,encode(extensions.digest(gen_random_uuid()::text,'sha256'),'hex'),now()+interval '10 minutes',fp,p_action_payload) returning * into rec;
 return rec;
end $$;
revoke all on function public.create_approval_request(uuid,jsonb) from public,anon;
grant execute on function public.create_approval_request(uuid,jsonb) to authenticated;
revoke all on function public.create_approval_request(uuid) from public,anon,authenticated;
drop function if exists public.create_approval_request(uuid);
