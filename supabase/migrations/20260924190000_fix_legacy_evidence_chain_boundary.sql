-- Keep the sequenced evidence chain independent from pre-chain legacy events.
create or replace function public.append_authorization_evidence(p_organization_id uuid,p_event_type text,p_payload jsonb)
returns public.evidence_events language plpgsql security invoker set search_path=''
as $$
declare prev text; next_seq bigint; rec public.evidence_events; canonical text;
begin
 if auth.uid() is null or not exists(select 1 from public.organizations o where o.id=p_organization_id and o.owner_id=auth.uid()) then raise exception 'forbidden'; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_organization_id::text,0));
 select e.event_hash,e.sequence_no into prev,next_seq from public.evidence_events e
 where e.organization_id=p_organization_id and e.sequence_no is not null
 order by e.sequence_no desc limit 1;
 next_seq:=coalesce(next_seq,0)+1;
 canonical:=coalesce(prev,'')||'|'||next_seq::text||'|'||p_event_type||'|'||p_payload::text;
 insert into public.evidence_events(organization_id,event_type,payload,previous_hash,event_hash,sequence_no)
 values(p_organization_id,p_event_type,p_payload,prev,encode(extensions.digest(canonical,'sha256'),'hex'),next_seq) returning * into rec;
 return rec;
end $$;
revoke all on function public.append_authorization_evidence(uuid,text,jsonb) from public, anon;
grant execute on function public.append_authorization_evidence(uuid,text,jsonb) to authenticated;
