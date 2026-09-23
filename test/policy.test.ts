import test from "node:test";import assert from "node:assert/strict";import {authorize,type Mandate} from "../src/policy.js";
const base:Mandate={id:"m1",agentId:"travel",actions:["purchase"],maxAmount:1000,currency:"EUR",approvalAbove:500,expiresAt:"2099-01-01T00:00:00Z"};
test("allows low-risk action",()=>assert.equal(authorize(base,{agentId:"travel",action:"purchase",amount:200,currency:"EUR"}),"ALLOW"));
test("requires approval above threshold",()=>assert.equal(authorize(base,{agentId:"travel",action:"purchase",amount:700,currency:"EUR"}),"REQUIRE_APPROVAL"));
test("denies authority ceiling breach",()=>assert.equal(authorize(base,{agentId:"travel",action:"purchase",amount:1001,currency:"EUR"}),"DENY"));
test("denies wrong action",()=>assert.equal(authorize(base,{agentId:"travel",action:"send_email"}),"DENY"));
test("denies revoked mandate",()=>assert.equal(authorize({...base,revoked:true},{agentId:"travel",action:"purchase",amount:1,currency:"EUR"}),"DENY"));