export type Decision="ALLOW"|"DENY"|"REQUIRE_APPROVAL";
export type Mandate={id:string;agentId:string;actions:string[];maxAmount?:number;currency?:string;expiresAt:string;approvalAbove?:number;revoked?:boolean};
export type Action={agentId:string;action:string;amount?:number;currency?:string};
export function authorize(m:Mandate,a:Action,now=new Date()):Decision{
 if(m.revoked||now>=new Date(m.expiresAt)) return "DENY";
 if(m.agentId!==a.agentId||!m.actions.includes(a.action)) return "DENY";
 if(a.amount!==undefined){
  if(m.currency&&a.currency!==m.currency) return "DENY";
  if(m.maxAmount!==undefined&&a.amount>m.maxAmount) return "DENY";
  if(m.approvalAbove!==undefined&&a.amount>m.approvalAbove) return "REQUIRE_APPROVAL";
 }
 return "ALLOW";
}