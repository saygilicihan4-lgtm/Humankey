import test from "node:test";import assert from "node:assert/strict";
type Org={id:string;ownerId:string};type Agent={id:string;orgId:string};type Mandate={orgId:string;agentId:string};
function visible(userId:string,org:Org){return org.ownerId===userId}
function mandateAllowed(userId:string,org:Org,agent:Agent,m:Mandate){return visible(userId,org)&&m.orgId===org.id&&agent.orgId===org.id&&m.agentId===agent.id}
test("tenant B cannot access tenant A organization",()=>{const a={id:"org-a",ownerId:"user-a"};assert.equal(visible("user-b",a),false)});
test("mandate cannot attach agent from another tenant",()=>{const org={id:"org-a",ownerId:"user-a"};const foreign={id:"agent-b",orgId:"org-b"};assert.equal(mandateAllowed("user-a",org,foreign,{orgId:"org-a",agentId:"agent-b"}),false)});
test("owner with same-tenant agent passes boundary",()=>{const org={id:"org-a",ownerId:"user-a"};const agent={id:"agent-a",orgId:"org-a"};assert.equal(mandateAllowed("user-a",org,agent,{orgId:"org-a",agentId:"agent-a"}),true)});
