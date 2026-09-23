create or replace function public.append_authorization_evidence(p_organization_id uuid,p_event_type text,p_payload jsonb)
returns public.evidence_events
language plpgsql security definer set search_path=''
as $$
declare prev text; rec public.evidence_events;
begin
 if auth.uid() is null or not exists(select 1 from public.organizations o where o.id=p_organization_id and o.owner_id=auth.uid()) then raise exception 'forbidden'; end if;
 select e.event_hash into prev from public.evidence_events e where e.organization_id=p_organization_id order by e.created_at desc,e.id desc limit 1 for update;
 insert into public.evidence_events(organization_id,event_type,payload,previous_hash,event_hash)
 values(p_organization_id,p_event_type,p_payload,prev,encode(extensions.digest(coalesce(prev,'')||p_event_type||p_payload::text,'sha256'),'hex')) returning * into rec;
 return rec;
end $$;
revoke all on function public.append_authorization_evidence(uuid,text,jsonb) from public,anon;
grant execute on function public.append_authorization_evidence(uuid,text,jsonb) to authenticated;
