create or replace function public.pause_all_agents()
returns jsonb
language plpgsql security invoker set search_path=''
as $$
declare v_mandates int; v_agents int; v_now timestamptz:=now();
begin
 update public.mandates set revoked_at=v_now where revoked_at is null;
 get diagnostics v_mandates=row_count;
 update public.agents set status='paused' where status='active';
 get diagnostics v_agents=row_count;
 return jsonb_build_object('ok',true,'pausedAt',v_now,'mandatesRevoked',v_mandates,'agentsPaused',v_agents);
end $$;
revoke all on function public.pause_all_agents() from public,anon;
grant execute on function public.pause_all_agents() to authenticated;
