import type {Request,Response,NextFunction} from 'express';
import {userClient} from './supabase.js';
export async function requireUser(req:Request,res:Response,next:NextFunction){
 const token=req.headers.authorization?.replace(/^Bearer /,'');
 if(!token)return res.status(401).json({error:'authentication_required'});
 const {data,error}=await userClient(token).auth.getUser(token);
 if(error||!data.user)return res.status(401).json({error:'invalid_session'});
 res.locals.userId=data.user.id;
 res.locals.token=token;
 next();
}
