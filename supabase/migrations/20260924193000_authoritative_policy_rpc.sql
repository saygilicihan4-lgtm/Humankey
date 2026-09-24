create or replace function public.authorize_action(p_mandate_id uuid,p_action_payload jsonb)
returns jsonb
language plpgsql
security invoker
set search_path=''
as $$
declare
  m public.mandates;
  ev public.evidence_events;
  ap public.approvals;
  v_agent_id uuid;
  v_action text;
  v_amount numeric;
  v_currency text;
  v_decision text;
  fp text;
begin
  if jsonb_typeof(p_action_payload) is distinct from 'object' then raise exception 'invalid_action_payload'; end if;

  begin
    v_agent_id := nullif(p_action_payload->>'agentId','')::uuid;
  exception when others then
    raise exception 'invalid_action_payload';
  end;

  v_action := btrim(coalesce(p_action_payload->>'action',''));
  if v_agent_id is null or v_action='' or length(v_action)>120 then raise exception 'invalid_action_payload'; end if;

  if p_action_payload ? 'amount' and p_action_payload->'amount' <> 'null'::jsonb then
    if jsonb_typeof(p_action_payload->'amount') <> 'number' then raise exception 'invalid_action_payload'; end if;
    v_amount := (p_action_payload->>'amount')::numeric;
    if v_amount < 0 then raise exception 'invalid_action_payload'; end if;
  end if;

  if p_action_payload ? 'currency' and p_action_payload->'currency' <> 'null'::jsonb then
    if jsonb_typeof(p_action_payload->'currency') <> 'string' then raise exception 'invalid_action_payload'; end if;
    v_currency := upper(btrim(p_action_payload->>'currency'));
    if v_currency !~ '^[A-Z]{3}$' then raise exception 'invalid_action_payload'; end if;
  end if;

  select x.* into m
  from public.mandates x
  join public.organizations o on o.id=x.organization_id
  where x.id=p_mandate_id and o.owner_id=(select auth.uid());

  if m.id is null then raise exception 'forbidden'; end if;

  if m.revoked_at is not null or m.expires_at<=now() then
    v_decision:='DENY';
  elsif m.agent_id<>v_agent_id or not (v_action=any(m.actions)) then
    v_decision:='DENY';
  elsif v_amount is not null and m.currency is not null and v_currency is distinct from upper(m.currency) then
    v_decision:='DENY';
  elsif v_amount is not null and m.max_amount is not null and v_amount>m.max_amount then
    v_decision:='DENY';
  elsif v_amount is not null and m.approval_above is not null and v_amount>m.approval_above then
    v_decision:='REQUIRE_APPROVAL';
  else
    v_decision:='ALLOW';
  end if;

  ev:=public.append_authorization_evidence(
    m.organization_id,
    'authorization_decision',
    jsonb_build_object(
      'mandateId',m.id,
      'agentId',v_agent_id,
      'action',v_action,
      'amount',v_amount,
      'currency',v_currency,
      'decision',v_decision
    )
  );

  if v_decision='REQUIRE_APPROVAL' then
    fp:=encode(extensions.digest(
      jsonb_build_object('agentId',v_agent_id,'action',v_action,'amount',v_amount,'currency',v_currency)::text,
      'sha256'
    ),'hex');

    insert into public.approvals(
      organization_id,mandate_id,token_hash,expires_at,action_fingerprint,action_payload
    )
    values(
      m.organization_id,
      m.id,
      encode(extensions.digest(gen_random_uuid()::text,'sha256'),'hex'),
      now()+interval '10 minutes',
      fp,
      jsonb_build_object('agentId',v_agent_id,'action',v_action,'amount',v_amount,'currency',v_currency)
    )
    returning * into ap;
  end if;

  return jsonb_build_object(
    'decision',v_decision,
    'evidenceId',ev.id,
    'approvalId',case when ap.id is null then null else ap.id end
  );
end $$;

revoke execute on function public.authorize_action(uuid,jsonb) from public, anon;
grant execute on function public.authorize_action(uuid,jsonb) to authenticated;

revoke execute on function public.record_authorization_decision(uuid,jsonb,text) from public, anon, authenticated;
revoke execute on function public.create_approval_request(uuid,jsonb) from public, anon, authenticated;
