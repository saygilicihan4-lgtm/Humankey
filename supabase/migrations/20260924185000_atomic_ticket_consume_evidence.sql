-- Make one-time execution consumption and its audit evidence one database transaction.
create or replace function public.consume_execution_ticket(p_ticket_id uuid,p_secret text,p_action_payload jsonb)
returns jsonb language plpgsql security invoker set search_path=''
as $$
declare t public.execution_tickets; fp text;
begin
 fp:=encode(extensions.digest(p_action_payload::text,'sha256'),'hex');
 update public.execution_tickets x set consumed_at=now()
 where x.id=p_ticket_id and x.consumed_at is null and x.expires_at>now()
 and x.secret_hash=encode(extensions.digest(p_secret,'sha256'),'hex')
 and x.action_fingerprint=fp
 and exists(select 1 from public.organizations o where o.id=x.organization_id and o.owner_id=auth.uid())
 returning * into t;
 if t.id is null then raise exception 'execution_ticket_unavailable'; end if;
 perform public.append_authorization_evidence(t.organization_id,'execution_ticket_consumed',
   jsonb_build_object('ticketId',t.id,'mandateId',t.mandate_id,'approvalId',t.approval_id,'actionFingerprint',t.action_fingerprint));
 return jsonb_build_object('id',t.id,'organizationId',t.organization_id,'mandateId',t.mandate_id,'approvalId',t.approval_id,'consumedAt',t.consumed_at,'actionFingerprint',t.action_fingerprint);
end $$;
revoke all on function public.consume_execution_ticket(uuid,text,jsonb) from public, anon;
grant execute on function public.consume_execution_ticket(uuid,text,jsonb) to authenticated;
