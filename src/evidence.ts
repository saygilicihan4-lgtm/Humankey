import {createHash} from "node:crypto";
export type Evidence={id:string;at:string;payload:unknown;previousHash:string|null;hash:string};
export class EvidenceLedger{private rows:Evidence[]=[];
 append(payload:unknown){const previousHash=this.rows.at(-1)?.hash??null;const at=new Date().toISOString();const id=crypto.randomUUID();const hash=createHash("sha256").update(JSON.stringify({id,at,payload,previousHash})).digest("hex");const row={id,at,payload,previousHash,hash};this.rows.push(row);return row}
 verify(){for(let i=0;i<this.rows.length;i++){const r=this.rows[i];const expectedPrev=i?this.rows[i-1].hash:null;if(r.previousHash!==expectedPrev)return false;const h=createHash("sha256").update(JSON.stringify({id:r.id,at:r.at,payload:r.payload,previousHash:r.previousHash})).digest("hex");if(h!==r.hash)return false}return true}
 list(){return [...this.rows]}
}