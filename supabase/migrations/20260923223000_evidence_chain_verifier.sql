alter table public.evidence_events add column if not exists sequence_no bigint;
create unique index if not exists evidence_org_sequence_uidx on public.evidence_events(organization_id,sequence_no) where sequence_no is not null;

create or replace function public.append_authorization_evidence(p_organization_id uuid,p_event_type text,p_payload jsonb)
returns public.evidence_events
language plpgsql security invoker set search_path=''
as $$
declare prev text; next_seq bigint; rec public.evidence_events; canonical text;
begin
 if auth.uid() is null or not exists(select 1 from public.organizations o where o.id=p_organization_id and o.owner_id=auth.uid()) then raise exception 'forbidden'; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_organization_id::text,0));
 select e.event_hash,e.sequence_no into prev,next_seq from public.evidence_events e where e.organization_id=p_organization_id order by e.sequence_no desc nulls last,e.created_at desc,e.id desc limit 1;
 next_seq:=coalesce(next_seq,0)+1;
 canonical:=coalesce(prev,'')||'|'||next_seq::text||'|'||p_event_type||'|'||p_payload::text;
 insert into public.evidence_events(organization_id,event_type,payload,previous_hash,event_hash,sequence_no)
 values(p_organization_id,p_event_type,p_payload,prev,encode(extensions.digest(canonical,'sha256'),'hex'),next_seq) returning * into rec;
 return rec;
end $$;

create or replace function public.verify_evidence_chain(p_organization_id uuid)
returns jsonb
language plpgsql security invoker set search_path=''
as $$
declare r record; expected_prev text:=null; expected_hash text; checked bigint:=0; legacy bigint:=0;
begin
 if auth.uid() is null or not exists(select 1 from public.organizations o where o.id=p_organization_id and o.owner_id=auth.uid()) then raise exception 'forbidden'; end if;
 for r in select * from public.evidence_events e where e.organization_id=p_organization_id order by e.sequence_no asc nulls first,e.created_at asc,e.id asc loop
   if r.sequence_no is null then legacy:=legacy+1; continue; end if;
   if r.previous_hash is distinct from expected_prev then return jsonb_build_object('valid',false,'checked',checked,'legacyEvents',legacy,'brokenEventId',r.id,'reason','previous_hash_mismatch'); end if;
   expected_hash:=encode(extensions.digest(coalesce(expected_prev,'')||'|'||r.sequence_no::text||'|'||r.event_type||'|'||r.payload::text,'sha256'),'hex');
   if r.event_hash is distinct from expected_hash then return jsonb_build_object('valid',false,'checked',checked,'legacyEvents',legacy,'brokenEventId',r.id,'reason','event_hash_mismatch'); end if;
   expected_prev:=r.event_hash; checked:=checked+1;
 end loop;
 return jsonb_build_object('valid',true,'checked',checked,'legacyEvents',legacy,'headHash',expected_prev);
end $$;
revoke all on function public.verify_evidence_chain(uuid) from public,anon;
grant execute on function public.verify_evidence_chain(uuid) to authenticated;
