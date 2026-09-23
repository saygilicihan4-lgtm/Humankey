import type {Mandate} from "./policy.js";
export function canDelegate(parent:Mandate,child:Mandate){
 if(parent.revoked)return false;
 if(new Date(child.expiresAt)>new Date(parent.expiresAt))return false;
 if(child.actions.some(a=>!parent.actions.includes(a)))return false;
 if(parent.currency&&child.currency!==parent.currency)return false;
 if(parent.maxAmount!==undefined&&(child.maxAmount===undefined||child.maxAmount>parent.maxAmount))return false;
 return true;
}