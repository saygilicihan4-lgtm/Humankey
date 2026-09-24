create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.append_evidence(p_organization_id uuid,p_event_type text,p_payload jsonb)
returns public.evidence_events
language plpgsql
security definer
set search_path=''
as $$
declare prev text; next_seq bigint; rec public.evidence_events; canonical text;
begin
 if (select auth.uid()) is null or not exists(
   select 1 from public.organizations o where o.id=p_organization_id and o.owner_id=(select auth.uid())
 ) then raise exception 'forbidden'; end if;
 if p_event_type not in ('authorization_decision','execution_ticket_consumed') then raise exception 'invalid_event_type'; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_organization_id::text,0));
 select e.event_hash,e.sequence_no into prev,next_seq from public.evidence_events e
 where e.organization_id=p_organization_id and e.sequence_no is not null order by e.sequence_no desc limit 1;
 next_seq:=coalesce(next_seq,0)+1;
 canonical:=coalesce(prev,'')||'|'||next_seq::text||'|'||p_event_type||'|'||p_payload::text;
 insert into public.evidence_events(organization_id,event_type,payload,previous_hash,event_hash,sequence_no)
 values(p_organization_id,p_event_type,p_payload,prev,encode(extensions.digest(canonical,'sha256'),'hex'),next_seq)
 returning * into rec;
 return rec;
end $$;
revoke execute on function private.append_evidence(uuid,text,jsonb) from public, anon;
grant execute on function private.append_evidence(uuid,text,jsonb) to authenticated;

create or replace function public.authorize_action(p_mandate_id uuid,p_action_payload jsonb)
returns jsonb language plpgsql security invoker set search_path=''
as $$
declare m public.mandates; ev public.evidence_events; ap public.approvals; v_agent_id uuid; v_action text; v_amount numeric; v_currency text; v_decision text; fp text;
begin
 if jsonb_typeof(p_action_payload) is distinct from 'object' then raise exception 'invalid_action_payload'; end if;
 begin v_agent_id:=nullif(p_action_payload->>'agentId','')::uuid; exception when others then raise exception 'invalid_action_payload'; end;
 v_action:=btrim(coalesce(p_action_payload->>'action',''));
 if v_agent_id is null or v_action='' or length(v_action)>120 then raise exception 'invalid_action_payload'; end if;
 if p_action_payload ? 'amount' and p_action_payload->'amount'<>'null'::jsonb then
  if jsonb_typeof(p_action_payload->'amount')<>'number' then raise exception 'invalid_action_payload'; end if;
  v_amount:=(p_action_payload->>'amount')::numeric; if v_amount<0 then raise exception 'invalid_action_payload'; end if;
 end if;
 if p_action_payload ? 'currency' and p_action_payload->'currency'<>'null'::jsonb then
  if jsonb_typeof(p_action_payload->'currency')<>'string' then raise exception 'invalid_action_payload'; end if;
  v_currency:=upper(btrim(p_action_payload->>'currency')); if v_currency !~ '^[A-Z]{3}$' then raise exception 'invalid_action_payload'; end if;
 end if;
 select x.* into m from public.mandates x join public.organizations o on o.id=x.organization_id where x.id=p_mandate_id and o.owner_id=(select auth.uid());
 if m.id is null then raise exception 'forbidden'; end if;
 if m.revoked_at is not null or m.expires_at<=now() then v_decision:='DENY';
 elsif m.agent_id<>v_agent_id or not(v_action=any(m.actions)) then v_decision:='DENY';
 elsif v_amount is not null and m.currency is not null and v_currency is distinct from upper(m.currency) then v_decision:='DENY';
 elsif v_amount is not null and m.max_amount is not null and v_amount>m.max_amount then v_decision:='DENY';
 elsif v_amount is not null and m.approval_above is not null and v_amount>m.approval_above then v_decision:='REQUIRE_APPROVAL';
 else v_decision:='ALLOW'; end if;
 ev:=private.append_evidence(m.organization_id,'authorization_decision',jsonb_build_object('mandateId',m.id,'agentId',v_agent_id,'action',v_action,'amount',v_amount,'currency',v_currency,'decision',v_decision));
 if v_decision='REQUIRE_APPROVAL' then
  fp:=encode(extensions.digest(jsonb_build_object('agentId',v_agent_id,'action',v_action,'amount',v_amount,'currency',v_currency)::text,'sha256'),'hex');
  insert into public.approvals(organization_id,mandate_id,token_hash,expires_at,action_fingerprint,action_payload)
  values(m.organization_id,m.id,encode(extensions.digest(gen_random_uuid()::text,'sha256'),'hex'),now()+interval '10 minutes',fp,jsonb_build_object('agentId',v_agent_id,'action',v_action,'amount',v_amount,'currency',v_currency)) returning * into ap;
 end if;
 return jsonb_build_object('decision',v_decision,'evidenceId',ev.id,'approvalId',case when ap.id is null then null else ap.id end);
end $$;

create or replace function public.consume_execution_ticket(p_ticket_id uuid,p_secret text,p_action_payload jsonb)
returns jsonb language plpgsql security invoker set search_path=''
as $$
declare t public.execution_tickets; fp text;
begin
 fp:=encode(extensions.digest(p_action_payload::text,'sha256'),'hex');
 update public.execution_tickets x set consumed_at=now()
 where x.id=p_ticket_id and x.consumed_at is null and x.expires_at>now()
 and x.secret_hash=encode(extensions.digest(p_secret,'sha256'),'hex') and x.action_fingerprint=fp
 and exists(select 1 from public.organizations o where o.id=x.organization_id and o.owner_id=(select auth.uid()))
 returning * into t;
 if t.id is null then raise exception 'execution_ticket_unavailable'; end if;
 perform private.append_evidence(t.organization_id,'execution_ticket_consumed',jsonb_build_object('ticketId',t.id,'mandateId',t.mandate_id,'approvalId',t.approval_id,'actionFingerprint',t.action_fingerprint));
 return jsonb_build_object('id',t.id,'organizationId',t.organization_id,'mandateId',t.mandate_id,'approvalId',t.approval_id,'consumedAt',t.consumed_at,'actionFingerprint',t.action_fingerprint);
end $$;

revoke execute on function public.append_authorization_evidence(uuid,text,jsonb) from public, anon, authenticated;
revoke insert on table public.evidence_events from authenticated;
drop policy if exists evidence_insert_owner on public.evidence_events;
