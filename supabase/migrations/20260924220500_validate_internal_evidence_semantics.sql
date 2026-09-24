create or replace function private.append_evidence(p_organization_id uuid,p_event_type text,p_payload jsonb)
returns public.evidence_events language plpgsql security definer set search_path=''
as $$
declare prev text; next_seq bigint; rec public.evidence_events; canonical text; t public.execution_tickets;
begin
 if (select auth.uid()) is null or not exists(select 1 from public.organizations o where o.id=p_organization_id and o.owner_id=(select auth.uid()))
 then raise exception 'forbidden'; end if;
 if p_event_type='authorization_decision' then
   if jsonb_typeof(p_payload) is distinct from 'object' or not(p_payload ?& array['mandateId','agentId','action','decision'])
      or p_payload->>'decision' not in ('ALLOW','DENY','REQUIRE_APPROVAL') then raise exception 'invalid_authorization_evidence'; end if;
   if not exists(select 1 from public.mandates m where m.id=(p_payload->>'mandateId')::uuid and m.organization_id=p_organization_id)
   then raise exception 'invalid_authorization_evidence'; end if;
 elsif p_event_type='execution_ticket_consumed' then
   if jsonb_typeof(p_payload) is distinct from 'object' or not(p_payload ?& array['ticketId','mandateId','approvalId','actionFingerprint'])
   then raise exception 'invalid_execution_evidence'; end if;
   select x.* into t from public.execution_tickets x where x.id=(p_payload->>'ticketId')::uuid and x.organization_id=p_organization_id and x.consumed_at is not null;
   if t.id is null or t.mandate_id::text is distinct from p_payload->>'mandateId' or t.approval_id::text is distinct from p_payload->>'approvalId' or t.action_fingerprint is distinct from p_payload->>'actionFingerprint'
   then raise exception 'invalid_execution_evidence'; end if;
 else raise exception 'invalid_event_type'; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_organization_id::text,0));
 select e.event_hash,e.sequence_no into prev,next_seq from public.evidence_events e where e.organization_id=p_organization_id and e.sequence_no is not null order by e.sequence_no desc limit 1;
 next_seq:=coalesce(next_seq,0)+1;
 canonical:=coalesce(prev,'')||'|'||next_seq::text||'|'||p_event_type||'|'||p_payload::text;
 insert into public.evidence_events(organization_id,event_type,payload,previous_hash,event_hash,sequence_no)
 values(p_organization_id,p_event_type,p_payload,prev,encode(extensions.digest(canonical,'sha256'),'hex'),next_seq) returning * into rec;
 return rec;
end $$;