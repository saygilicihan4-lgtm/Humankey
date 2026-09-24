import type {Request,Response,NextFunction} from 'express';
import {userClient} from './supabase.js';

function jwtPayload(token:string):Record<string,unknown>|null{try{const p=token.split('.')[1];if(!p)return null;return JSON.parse(Buffer.from(p,'base64url').toString('utf8'))}catch{return null}}
export function assuranceLevel(token:string):'aal1'|'aal2'|null{const aal=jwtPayload(token)?.aal;return aal==='aal1'||aal==='aal2'?aal:null}
export function requireAal2(_req:Request,res:Response,next:NextFunction){if(assuranceLevel(res.locals.token)!=='aal2')return res.status(403).json({error:'mfa_required',required:'aal2'});next()}


export function parseBearer(value:string|undefined):string|null{
 if(!value)return null;
 const m=/^Bearer ([^\s]+)$/.exec(value);
 return m?.[1]??null;
}
export async function requireUser(req:Request,res:Response,next:NextFunction){
 const token=parseBearer(req.headers.authorization);
 if(!token)return res.status(401).json({error:'authentication_required'});
 const {data,error}=await userClient(token).auth.getUser(token);
 if(error||!data.user)return res.status(401).json({error:'invalid_session'});
 res.locals.userId=data.user.id;
 res.locals.token=token;
 next();
}
