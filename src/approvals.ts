import {randomBytes,createHash} from "node:crypto";
type Approval={hash:string;expiresAt:number;used:boolean};
export class ApprovalStore{private rows=new Map<string,Approval>();
 issue(ttlSeconds=300){const token=randomBytes(32).toString("base64url");const hash=createHash("sha256").update(token).digest("hex");this.rows.set(hash,{hash,expiresAt:Date.now()+ttlSeconds*1000,used:false});return token}
 consume(token:string){const hash=createHash("sha256").update(token).digest("hex");const a=this.rows.get(hash);if(!a||a.used||Date.now()>=a.expiresAt)return false;a.used=true;return true}
}