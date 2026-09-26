export const TOOL_ID='csrf-fixture-tester';
export const LIMITS=Object.freeze({policyBytes:65536,fixturesBytes:1048576,cases:1000,depth:16,milliseconds:5000});
export const RULES=Object.freeze({'policy-invalid':'warning','fixtures-invalid':'warning','fixtures-incomplete':'warning','coverage-gap':'warning','decision-missing':'warning','limit-exceeded':'warning','input-unreadable':'warning','unsafe-allowed':'error','safe-rejected':'error'});
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const only=(x,keys)=>Object.keys(x).every(k=>keys.includes(k));
const slug=x=>typeof x==='string'&&/^[a-z][a-z0-9-]{0,127}$/.test(x);
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const methods=['GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'];
const unsafe=['POST','PUT','PATCH','DELETE'];
function origin(x){if(typeof x!=='string'||x.length>2048||/[\u0000-\u0020\u007f-\u009f]/u.test(x))return null;try{const u=new URL(x);if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.pathname!=='/'||u.search||u.hash||u.origin==='null')return null;return u.origin;}catch{return null;}}
function depth(x){const stack=[[x,0,new Set()]];while(stack.length){const[v,n,a]=stack.pop();if(n>LIMITS.depth)return n;if(v&&typeof v==='object'){if(a.has(v))return LIMITS.depth+1;const next=new Set(a);next.add(v);for(const c of Object.values(v))stack.push([c,n+1,next]);}}return 0;}
export function validPolicy(p){return obj(p)&&only(p,['schemaVersion','expectedOrigin','protectedMethods','requireOrigin','requireToken'])&&p.schemaVersion==='1'&&origin(p.expectedOrigin)!==null&&Array.isArray(p.protectedMethods)&&p.protectedMethods.length>0&&p.protectedMethods.every(x=>unsafe.includes(x))&&new Set(p.protectedMethods).size===p.protectedMethods.length&&p.protectedMethods.includes('POST')&&p.requireOrigin===true&&p.requireToken===true;}
export function evaluateCsrfFixtures(fixtures,policy,{now=Date.now,deadline=now()+LIMITS.milliseconds}={}){
  const findings=[];
  const add=(ruleId,file,pointer,message)=>{if(!Object.hasOwn(RULES,ruleId))throw new Error('Unknown rule');findings.push({ruleId,severity:RULES[ruleId],message,location:{file,pointer}});};
  const finish=checked=>{findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));return{schemaVersion:'1',tool:TOOL_ID,status:findings.some(f=>f.severity==='warning')?'incomplete':findings.length?'fail':checked?'pass':'incomplete',summary:{checked,errors:findings.filter(f=>f.severity==='error').length,warnings:findings.filter(f=>f.severity==='warning').length},findings};};
  if(!validPolicy(policy)){add('policy-invalid','@policy','','CSRF fixture policy is invalid.');return finish(0);}
  if(depth(fixtures)>LIMITS.depth){add('limit-exceeded','@fixtures','','Fixture JSON depth limit exceeded.');return finish(0);}
  if(!obj(fixtures)||!only(fixtures,['schemaVersion','complete','cases'])||fixtures.schemaVersion!=='1'||typeof fixtures.complete!=='boolean'||!Array.isArray(fixtures.cases)){add('fixtures-invalid','@fixtures','','Fixture suite shape is invalid.');return finish(0);}
  if(fixtures.cases.length>LIMITS.cases){add('limit-exceeded','@fixtures','/cases','Fixture case limit exceeded.');return finish(0);}
  if(!fixtures.complete)add('fixtures-incomplete','@fixtures','/complete','Fixture suite declares partial coverage.');
  const coverage={valid:false,missing:false,mismatch:false},seen=new Set(),expected=origin(policy.expectedOrigin);
  for(let i=0;i<fixtures.cases.length;i++){
    if(now()>deadline){add('limit-exceeded','@fixtures','','Evaluation deadline exceeded.');return finish(i);}
    const c=fixtures.cases[i],at=`/cases/${i}`;
    if(!obj(c)||!only(c,['id','request','observedDecision'])||!slug(c.id)||seen.has(c.id)||!obj(c.request)||!only(c.request,['method','origin','tokenState'])||!methods.includes(c.request.method)||!(c.request.origin===null||origin(c.request.origin)!==null)||!['valid','missing','invalid'].includes(c.request.tokenState)){add('fixtures-invalid','@fixtures',at,'Case identity or abstract request attributes are invalid.');continue;}
    seen.add(c.id);
    const protectedMethod=policy.protectedMethods.includes(c.request.method),actualOrigin=c.request.origin===null?null:origin(c.request.origin),same=actualOrigin===expected;
    const expectedDecision=!protectedMethod||(same&&c.request.tokenState==='valid')?'allow':'reject';
    if(protectedMethod&&same&&c.request.tokenState==='valid')coverage.valid=true;
    if(protectedMethod&&same&&c.request.tokenState==='missing')coverage.missing=true;
    if(protectedMethod&&actualOrigin!==null&&!same&&c.request.tokenState==='valid')coverage.mismatch=true;
    if(!['allow','reject'].includes(c.observedDecision)){add('decision-missing','@fixtures',`${at}/observedDecision`,'Recorded middleware decision is missing or unsupported.');continue;}
    if(expectedDecision==='reject'&&c.observedDecision==='allow')add('unsafe-allowed','@fixtures',at,'Recorded middleware decision allowed an abstract request that policy requires rejecting.');
    if(expectedDecision==='allow'&&c.observedDecision==='reject')add('safe-rejected','@fixtures',at,'Recorded middleware decision rejected an abstract request that policy allows.');
  }
  for(const [category,covered] of Object.entries(coverage))if(!covered)add('coverage-gap','@fixtures','/cases',`Required ${category} scenario is absent from fixture suite.`);
  return finish(fixtures.cases.length);
}
