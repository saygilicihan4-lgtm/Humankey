import {generateKeyPairSync,sign,verify,createPublicKey,createPrivateKey} from "node:crypto";
export function generateMandateKeyPair(){const {publicKey,privateKey}=generateKeyPairSync("ed25519");return {publicKey:publicKey.export({type:"spki",format:"pem"}).toString(),privateKey:privateKey.export({type:"pkcs8",format:"pem"}).toString()}}
export function signMandate(payload:unknown,privateKeyPem:string){return sign(null,Buffer.from(canonical(payload)),createPrivateKey(privateKeyPem)).toString("base64url")}
export function verifyMandate(payload:unknown,signature:string,publicKeyPem:string){return verify(null,Buffer.from(canonical(payload)),createPublicKey(publicKeyPem),Buffer.from(signature,"base64url"))}
function canonical(v:any):string{if(v===null||typeof v!=="object")return JSON.stringify(v);if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}"}
