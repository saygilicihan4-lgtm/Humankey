alter function public.authorize_action(uuid,jsonb) security invoker;
alter function public.consume_execution_ticket(uuid,text,jsonb) security invoker;
grant usage on schema private to authenticated;
grant execute on function private.append_evidence(uuid,text,jsonb) to authenticated;
