-- Persist an authorization decision and its approval request atomically.
create or replace function public.record_authorization_decision(
 p_mandate_id uuid,p_action_payload jsonb,p_decision text
) returns jsonb language plpgsql security invoker set search_path=''
as $$
declare m public.mandates; ev public.evidence_events; ap public.approvals; fp text;
begin
 if p_decision not in ('ALLOW','DENY','REQUIRE_APPROVAL') then raise exception 'invalid_decision'; end if;
 select x.* into m from public.mandates x join public.organizations o on o.id=x.organization_id
 where x.id=p_mandate_id and o.owner_id=auth.uid();
 if m.id is null then raise exception 'forbidden'; end if;
 ev:=public.append_authorization_evidence(m.organization_id,'authorization_decision',
   jsonb_build_object('mandateId',m.id,'agentId',p_action_payload->'agentId','action',p_action_payload->'action','amount',p_action_payload->'amount','currency',p_action_payload->'currency','decision',p_decision));
 if p_decision='REQUIRE_APPROVAL' then
   if m.revoked_at is not null or m.expires_at<=now() then raise exception 'mandate_unavailable'; end if;
   fp:=encode(extensions.digest(p_action_payload::text,'sha256'),'hex');
   insert into public.approvals(organization_id,mandate_id,token_hash,expires_at,action_fingerprint,action_payload)
   values(m.organization_id,m.id,encode(extensions.digest(gen_random_uuid()::text,'sha256'),'hex'),now()+interval '10 minutes',fp,p_action_payload)
   returning * into ap;
 end if;
 return jsonb_build_object('evidenceId',ev.id,'approvalId',case when ap.id is null then null else ap.id end);
end $$;
revoke all on function public.record_authorization_decision(uuid,jsonb,text) from public,anon;
grant execute on function public.record_authorization_decision(uuid,jsonb,text) to authenticated;
