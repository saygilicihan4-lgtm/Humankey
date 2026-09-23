import test from "node:test";
import assert from "node:assert/strict";
import {parseBearer} from "../src/auth.js";

test("accepts a strict Bearer token",()=>assert.equal(parseBearer("Bearer abc.def.123"),"abc.def.123"));
test("rejects missing authorization",()=>assert.equal(parseBearer(undefined),null));
test("rejects wrong scheme",()=>assert.equal(parseBearer("Basic abc"),null));
test("rejects malformed Bearer values",()=>{assert.equal(parseBearer("Bearer "),null);assert.equal(parseBearer("Bearer a b"),null);assert.equal(parseBearer("bearer abc"),null)});
