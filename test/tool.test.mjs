import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCsrfFixtures, TOOL_ID, LIMITS, RULES } from '../src/index.mjs';
import { runCli } from '../src/cli.mjs';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const policy={schemaVersion:'1',expectedOrigin:'https://app.example.invalid',protectedMethods:['POST','PUT','PATCH','DELETE'],requireOrigin:true,requireToken:true};
const good={id:'valid',request:{method:'POST',origin:'https://app.example.invalid',tokenState:'valid'},observedDecision:'allow'};
const missing={id:'missing',request:{method:'POST',origin:'https://app.example.invalid',tokenState:'missing'},observedDecision:'reject'};
const mismatch={id:'mismatch',request:{method:'POST',origin:'https://other.example.invalid',tokenState:'valid'},observedDecision:'reject'};
const fixtures={schemaVersion:'1',complete:true,cases:[good,missing,mismatch]};
const evaluate=(f=fixtures,p=policy)=>evaluateCsrfFixtures(f,p);

test('valid same-origin passes and required rejection cases remain covered',()=>{
  const result=evaluate();assert.equal(TOOL_ID,'csrf-fixture-tester');assert.equal(result.status,'pass');assert.equal(result.summary.checked,3);
  assert.equal(JSON.stringify(result).includes('app.example.invalid'),false);
});

test('missing token and mismatched origin accepted by middleware fail at case ordinals',()=>{
  const bad={...fixtures,cases:[good,{...missing,observedDecision:'allow'},{...mismatch,observedDecision:'allow'}]};
  const result=evaluate(bad);assert.equal(result.status,'fail');
  assert.deepEqual(result.findings.filter(f=>f.ruleId==='unsafe-allowed').map(f=>f.location.pointer),['/cases/1','/cases/2']);
});

test('legitimate same-origin default-port origin is accepted; false middleware rejection fails',()=>{
  const same={...good,request:{...good.request,origin:'https://APP.example.invalid:443'}};
  assert.equal(evaluate({...fixtures,cases:[same,missing,mismatch]}).status,'pass');
  const refused=evaluate({...fixtures,cases:[{...good,observedDecision:'reject'},missing,mismatch]});
  assert.equal(refused.status,'fail');assert.ok(refused.findings.some(f=>f.ruleId==='safe-rejected'));
});

test('missing fixture coverage or either unknown decision and incomplete export cannot pass',()=>{
  assert.equal(evaluate({...fixtures,complete:false}).status,'incomplete');
  assert.equal(evaluate({...fixtures,cases:[good]}).status,'incomplete');
  assert.equal(evaluate({...fixtures,cases:[{...good,observedDecision:null},missing,mismatch]}).status,'incomplete');
  assert.equal(evaluate({...fixtures,cases:[{...good,request:{...good.request,origin:'not-an-origin'}},missing,mismatch]}).status,'incomplete');
});

test('case/depth N/N+1 and injected deadline are exact',()=>{
  const many=n=>({...fixtures,cases:[good,missing,mismatch,...Array.from({length:n-3},(_,i)=>({...good,id:`case-${i}`}))]});
  assert.equal(evaluate(many(LIMITS.cases)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(evaluate(many(LIMITS.cases+1)).findings.some(f=>f.ruleId==='limit-exceeded'));
  const deep=n=>{const d=structuredClone(fixtures);let x=d;for(let i=0;i<n;i++){x.extra={};x=x.extra;}return d;};
  assert.equal(evaluate(deep(16)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(evaluate(deep(17)).findings.some(f=>f.ruleId==='limit-exceeded'));
  assert.equal(evaluateCsrfFixtures(fixtures,policy,{now:()=>5000,deadline:5000}).status,'pass');
  assert.equal(evaluateCsrfFixtures(fixtures,policy,{now:()=>5001,deadline:5000}).status,'incomplete');
});

test('CLI confinement, duplicate JSON keys and byte boundaries',()=>{
  const root=mkdtempSync(join(tmpdir(),'csrf-fixtures-')),outside=mkdtempSync(join(tmpdir(),'csrf-out-'));
  const args=['--root',root,'--policy','policy.json','--fixtures','fixtures.json'];
  const capture=()=>{let stdout='';return{io:{stdout:{write:s=>{stdout+=s;}},stderr:{write(){}}},get stdout(){return stdout;}};};
  try{const base={'policy.json':JSON.stringify(policy),'fixtures.json':JSON.stringify(fixtures)};for(const [name,raw] of Object.entries(base))writeFileSync(join(root,name),raw);
    let o=capture();assert.equal(runCli(args,o.io),0);assert.equal(JSON.parse(o.stdout).status,'pass');
    writeFileSync(join(root,'fixtures.json'),base['fixtures.json'].replace('"complete":true','"compl\\u0065te":false,"complete":true'));
    o=capture();assert.equal(runCli(args,o.io),2);assert.equal(JSON.parse(o.stdout).status,'incomplete');
    writeFileSync(join(outside,'fixtures.json'),base['fixtures.json']);symlinkSync(join(outside,'fixtures.json'),join(root,'linked.json'));
    o=capture();assert.equal(runCli(['--root',root,'--policy','policy.json','--fixtures','linked.json'],o.io),2);assert.equal(o.stdout,'');
    o=capture();assert.equal(runCli(['--root',join(root,'policy.json'),'--policy','policy.json','--fixtures','fixtures.json'],o.io),2);assert.equal(o.stdout,'');
    for(const [file,limit] of [['policy.json',LIMITS.policyBytes],['fixtures.json',LIMITS.fixturesBytes]])for(const delta of [0,1]){for(const [name,raw] of Object.entries(base))writeFileSync(join(root,name),raw);const raw=base[file];writeFileSync(join(root,file),raw+' '.repeat(limit+delta-Buffer.byteLength(raw)));o=capture();runCli(args,o.io);if(file==='policy.json')assert.equal(o.stdout==='',delta===1);else assert.equal(JSON.parse(o.stdout).findings.some(f=>f.ruleId==='limit-exceeded'),delta===1);}
  }finally{rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
});

test('severity table is pinned',()=>{assert.deepEqual(RULES,{'policy-invalid':'warning','fixtures-invalid':'warning','fixtures-incomplete':'warning','coverage-gap':'warning','decision-missing':'warning','limit-exceeded':'warning','input-unreadable':'warning','unsafe-allowed':'error','safe-rejected':'error'});});
