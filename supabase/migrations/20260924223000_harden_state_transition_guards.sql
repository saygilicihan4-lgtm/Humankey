create or replace function public.guard_approval_transition()
returns trigger language plpgsql security invoker set search_path=''
as $$
begin
 if new.organization_id<>old.organization_id or new.mandate_id<>old.mandate_id or new.token_hash<>old.token_hash
    or new.expires_at<>old.expires_at or new.created_at<>old.created_at
    or new.action_fingerprint is distinct from old.action_fingerprint or new.action_payload is distinct from old.action_payload
 then raise exception 'approval_immutable_fields'; end if;
 if old.decision is null then
   if new.decision is null then
     if new.used_at is distinct from old.used_at or new.decided_at is distinct from old.decided_at then raise exception 'invalid_approval_transition'; end if;
   elsif new.decision in ('APPROVED','REJECTED') then
     if new.decided_at is null or new.used_at is not null then raise exception 'invalid_approval_transition'; end if;
   else raise exception 'invalid_approval_transition'; end if;
 else
   if new.decision is distinct from old.decision or new.decided_at is distinct from old.decided_at then raise exception 'approval_decision_immutable'; end if;
   if old.used_at is null and new.used_at is not null then
     if old.decision<>'APPROVED' then raise exception 'approval_must_be_approved_before_use'; end if;
   elsif new.used_at is distinct from old.used_at then raise exception 'approval_usage_immutable'; end if;
 end if;
 return new;
end $$;

create or replace function public.guard_execution_ticket_transition()
returns trigger language plpgsql security invoker set search_path=''
as $$
begin
 if new.organization_id<>old.organization_id or new.mandate_id<>old.mandate_id or new.approval_id<>old.approval_id
    or new.secret_hash<>old.secret_hash or new.action_fingerprint<>old.action_fingerprint
    or new.action_payload is distinct from old.action_payload or new.expires_at<>old.expires_at or new.created_at<>old.created_at
 then raise exception 'execution_ticket_immutable_fields'; end if;
 if old.consumed_at is null and new.consumed_at is null then return new; end if;
 if old.consumed_at is null and new.consumed_at is not null then return new; end if;
 if new.consumed_at is distinct from old.consumed_at then raise exception 'execution_ticket_already_consumed'; end if;
 return new;
end $$;