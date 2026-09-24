alter function public.authorize_action(uuid,jsonb) security definer;
alter function public.consume_execution_ticket(uuid,text,jsonb) security definer;

revoke execute on function private.append_evidence(uuid,text,jsonb) from public, anon, authenticated;
revoke usage on schema private from anon, authenticated;

revoke execute on function public.authorize_action(uuid,jsonb) from public, anon;
grant execute on function public.authorize_action(uuid,jsonb) to authenticated;

create or replace function public.consume_execution_ticket(p_ticket_id uuid,p_secret text,p_action_payload jsonb)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare t public.execution_tickets; fp text;
begin
 if (select auth.uid()) is null then raise exception 'authentication_required'; end if;
 if coalesce(((select auth.jwt())->>'aal'),'aal1')<>'aal2' then raise exception 'mfa_required'; end if;
 fp:=encode(extensions.digest(p_action_payload::text,'sha256'),'hex');
 update public.execution_tickets x set consumed_at=now()
 where x.id=p_ticket_id and x.consumed_at is null and x.expires_at>now()
 and x.secret_hash=encode(extensions.digest(p_secret,'sha256'),'hex')
 and x.action_fingerprint=fp
 and exists(select 1 from public.organizations o where o.id=x.organization_id and o.owner_id=(select auth.uid()))
 returning * into t;
 if t.id is null then raise exception 'execution_ticket_unavailable'; end if;
 perform private.append_evidence(t.organization_id,'execution_ticket_consumed',
   jsonb_build_object('ticketId',t.id,'mandateId',t.mandate_id,'approvalId',t.approval_id,'actionFingerprint',t.action_fingerprint));
 return jsonb_build_object('id',t.id,'organizationId',t.organization_id,'mandateId',t.mandate_id,'approvalId',t.approval_id,'consumedAt',t.consumed_at,'actionFingerprint',t.action_fingerprint);
end $$;
revoke execute on function public.consume_execution_ticket(uuid,text,jsonb) from public, anon;
grant execute on function public.consume_execution_ticket(uuid,text,jsonb) to authenticated;
