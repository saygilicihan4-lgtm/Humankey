create or replace function public.guard_mandate_shape()
returns trigger language plpgsql security invoker set search_path=''
as $$
declare a text; seen text[]:=array[]::text[];
begin
 if tg_op='UPDATE' then
   if new.id<>old.id or new.organization_id<>old.organization_id or new.agent_id<>old.agent_id or new.created_at<>old.created_at
   then raise exception 'immutable_mandate_identity'; end if;
   if old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at then raise exception 'revocation_is_final'; end if;
 end if;
 if cardinality(new.actions)<1 or cardinality(new.actions)>32 then raise exception 'invalid_actions'; end if;
 foreach a in array new.actions loop
   if a is null or btrim(a)='' or length(btrim(a))>120 or a<>btrim(a) or a=any(seen) then raise exception 'invalid_actions'; end if;
   seen:=array_append(seen,a);
 end loop;
 if new.currency is not null and new.currency !~ '^[A-Z]{3}$' then raise exception 'invalid_currency'; end if;
 if new.max_amount is not null and (new.max_amount<0 or new.max_amount::text in ('NaN','Infinity','-Infinity')) then raise exception 'invalid_max_amount'; end if;
 if new.approval_above is not null and (new.approval_above<0 or new.approval_above::text in ('NaN','Infinity','-Infinity')) then raise exception 'invalid_approval_threshold'; end if;
 if new.max_amount is not null and new.approval_above is not null and new.approval_above>new.max_amount then raise exception 'approval_above_max'; end if;
 if not exists(select 1 from public.agents x where x.id=new.agent_id and x.organization_id=new.organization_id) then raise exception 'agent_not_in_organization'; end if;
 return new;
end $$;
drop trigger if exists mandates_shape_guard on public.mandates;
create trigger mandates_shape_guard before insert or update on public.mandates for each row execute function public.guard_mandate_shape();
revoke execute on function public.guard_mandate_shape() from public,anon,authenticated;
drop policy if exists mandates_insert_requires_aal2 on public.mandates;
create policy mandates_insert_requires_aal2 on public.mandates as restrictive for insert to authenticated
with check (((select auth.jwt())->>'aal')='aal2');
