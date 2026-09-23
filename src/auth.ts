import type {Request,Response,NextFunction} from 'express';
import {userClient} from './supabase.js';

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
