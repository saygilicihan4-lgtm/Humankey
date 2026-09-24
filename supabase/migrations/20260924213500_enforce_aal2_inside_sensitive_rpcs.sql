create or replace function public.decide_approval(p_approval_id uuid,p_decision text)
returns public.approvals language plpgsql security invoker set search_path=''
as $$
declare rec public.approvals;
begin
 if (select auth.uid()) is null then raise exception 'authentication_required'; end if;
 if coalesce(((select auth.jwt())->>'aal'),'aal1')<>'aal2' then raise exception 'mfa_required'; end if;
 if p_decision not in ('APPROVED','REJECTED') then raise exception 'invalid_decision'; end if;
 update public.approvals a set decision=p_decision,decided_at=now()
 where a.id=p_approval_id and a.decision is null and a.used_at is null and a.expires_at>now()
 and exists(select 1 from public.organizations o where o.id=a.organization_id and o.owner_id=(select auth.uid()))
 returning * into rec;
 if rec.id is null then raise exception 'approval_unavailable'; end if;
 return rec;
end $$;

create or replace function public.issue_execution_ticket(p_approval_id uuid)
returns jsonb language plpgsql security invoker set search_path=''
as $$
declare a public.approvals; raw_secret text; t public.execution_tickets;
begin
 if (select auth.uid()) is null then raise exception 'authentication_required'; end if;
 if coalesce(((select auth.jwt())->>'aal'),'aal1')<>'aal2' then raise exception 'mfa_required'; end if;
 update public.approvals x set used_at=now()
 where x.id=p_approval_id and x.decision='APPROVED' and x.used_at is null and x.expires_at>now()
 and exists(select 1 from public.organizations o where o.id=x.organization_id and o.owner_id=(select auth.uid()))
 returning * into a;
 if a.id is null then raise exception 'approval_unavailable'; end if;
 raw_secret:=gen_random_uuid()::text||gen_random_uuid()::text;
 insert into public.execution_tickets(organization_id,mandate_id,approval_id,secret_hash,action_fingerprint,action_payload,expires_at)
 values(a.organization_id,a.mandate_id,a.id,encode(extensions.digest(raw_secret,'sha256'),'hex'),a.action_fingerprint,a.action_payload,now()+interval '2 minutes')
 returning * into t;
 return jsonb_build_object('id',t.id,'secret',raw_secret,'expiresAt',t.expires_at,'actionFingerprint',t.action_fingerprint);
end $$;

create or replace function public.pause_all_agents()
returns jsonb language plpgsql security invoker set search_path=''
as $$
declare v_mandates int; v_agents int; v_now timestamptz:=now();
begin
 if (select auth.uid()) is null then raise exception 'authentication_required'; end if;
 if coalesce(((select auth.jwt())->>'aal'),'aal1')<>'aal2' then raise exception 'mfa_required'; end if;
 update public.mandates m set revoked_at=v_now where m.revoked_at is null
 and exists(select 1 from public.organizations o where o.id=m.organization_id and o.owner_id=(select auth.uid()));
 get diagnostics v_mandates=row_count;
 update public.agents a set status='paused' where a.status='active'
 and exists(select 1 from public.organizations o where o.id=a.organization_id and o.owner_id=(select auth.uid()));
 get diagnostics v_agents=row_count;
 return jsonb_build_object('ok',true,'pausedAt',v_now,'mandatesRevoked',v_mandates,'agentsPaused',v_agents);
end $$;
