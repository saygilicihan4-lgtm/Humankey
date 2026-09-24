import test from "node:test";
import assert from "node:assert/strict";
import {parseBearer,assuranceLevel} from "../src/auth.js";

test("accepts a strict Bearer token",()=>assert.equal(parseBearer("Bearer abc.def.123"),"abc.def.123"));
test("rejects missing authorization",()=>assert.equal(parseBearer(undefined),null));
test("rejects wrong scheme",()=>assert.equal(parseBearer("Basic abc"),null));
test("rejects malformed Bearer values",()=>{assert.equal(parseBearer("Bearer "),null);assert.equal(parseBearer("Bearer a b"),null);assert.equal(parseBearer("bearer abc"),null)});

function token(payload:object){return "x."+Buffer.from(JSON.stringify(payload)).toString("base64url")+".y"}
test("reads Supabase aal2 assurance",()=>assert.equal(assuranceLevel(token({aal:"aal2"})),"aal2"));
test("does not elevate aal1 or malformed tokens",()=>{assert.equal(assuranceLevel(token({aal:"aal1"})),"aal1");assert.equal(assuranceLevel("broken"),null);assert.equal(assuranceLevel(token({aal:"admin"})),null)});
