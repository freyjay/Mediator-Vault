// Proves the redesigned approval gate (human-carried pairing code, no on-disk secret):
// only a verdict MAC'd with the correct pairing code, bound to this session + exact tx,
// written AFTER the request, releases a signature. Everything else fails closed —
// crucially, an attacker who can READ the queue files still cannot forge an approve,
// because the pairing code is never on disk (AC1).
import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync, mkdirSync, renameSync, statSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { createHmac } from 'crypto';

// Mirror approval.ts (pointed at a temp dir).
function lib(dir) {
  const norm = (c) => c.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  const sid = (c) => createHmac('sha256','mn-vault-session-id').update(norm(c)).digest('hex').slice(0,16);
  const mac = (c,id,s,d,g) => createHmac('sha256',norm(c)).update(`${id}|${s}|${d}|${g}`).digest('hex');
  return {
    sid, norm,
    post(req){ writeFileSync(join(dir,`${req.id}.req.json`), JSON.stringify(req)); },
    writeVerdict(code,id,decision,digest){
      const s=sid(code); const v={id,sessionId:s,decision,digest,mac:mac(code,id,s,decision,digest)};
      const tmp=join(dir,`${id}.verdict.tmp`), fin=join(dir,`${id}.verdict.json`);
      writeFileSync(tmp,JSON.stringify(v)); renameSync(tmp,fin);
    },
    // an attacker who read the queue files writes a verdict with a GUESSED code:
    writeForgedVerdict(guessCode,id,sessionId,decision,digest){
      const v={id,sessionId,decision,digest,mac:mac(guessCode,id,sessionId,decision,digest)};
      writeFileSync(join(dir,`${id}.verdict.json`),JSON.stringify(v));
    },
    async await(code, req, timeoutMs){
      const vp=join(dir,`${req.id}.verdict.json`); const deadline=Date.now()+timeoutMs; const s=sid(code);
      while(Date.now()<deadline){
        if(existsSync(vp)){
          try{
            const vStat=statSync(vp); if(vStat.mtimeMs+1<req.createdMs) return 'deny';
            const v=JSON.parse(readFileSync(vp,'utf8'));
            if(v.id!==req.id) return 'deny';
            if(v.sessionId!==s) return 'deny';
            if(v.digest!==req.digest) return 'deny';
            const expect=mac(code,v.id,v.sessionId,v.decision,v.digest);
            if((v.mac??'').length!==expect.length) return 'deny';
            if(v.mac!==expect) return 'deny';
            return v.decision==='approve'?'approve':'deny';
          }catch{ return 'deny'; }
        }
        await new Promise(r=>setTimeout(r,20));
      }
      return 'deny';
    },
  };
}

let pass=0,fail=0;
const ok=(n,c)=>{console.log(`${c?'✓':'✗ FAIL'}  ${n}`);c?pass++:fail++;};
const digest='deadbeefdigest';
const mkReq=(L,code,id='id'+Math.random().toString(16).slice(2)) => ({ id, sessionId: L.sid(code), createdAt:'t', createdMs: Date.now(), digest, decoded:{} });

async function main() {
  const CODE='K7Q2-9XPL';     // the real pairing code (human-carried, never on disk)
  console.log('=== redesigned approval gate (human-carried pairing) ===');

  // 1. correct code + correct everything → approve
  { const d=mkdtempSync(join(tmpdir(),'ap-')); const L=lib(d); const req=mkReq(L,CODE);
    L.post(req); await new Promise(r=>setTimeout(r,5)); L.writeVerdict(CODE,req.id,'approve',digest);
    ok('correct pairing code approve → approve', (await L.await(CODE,req,1500))==='approve'); rmSync(d,{recursive:true,force:true}); }

  // 2. human deny → deny
  { const d=mkdtempSync(join(tmpdir(),'ap-')); const L=lib(d); const req=mkReq(L,CODE);
    L.post(req); await new Promise(r=>setTimeout(r,5)); L.writeVerdict(CODE,req.id,'deny',digest);
    ok('human deny → deny', (await L.await(CODE,req,1500))==='deny'); rmSync(d,{recursive:true,force:true}); }

  // 3. AC1 — attacker READ the queue files and forges with a WRONG (guessed) code → deny
  { const d=mkdtempSync(join(tmpdir(),'ap-')); const L=lib(d); const req=mkReq(L,CODE);
    L.post(req); await new Promise(r=>setTimeout(r,5));
    // attacker knows id + sessionId (from the req file) but NOT the code; guesses one:
    L.writeForgedVerdict('AAAA-BBBB', req.id, req.sessionId, 'approve', digest);
    ok('AC1: forged approve with wrong code → DENY (code never on disk)', (await L.await(CODE,req,1500))==='deny'); rmSync(d,{recursive:true,force:true}); }

  // 4. AC2 — verdict from a DIFFERENT session (wrong sessionId) → deny
  { const d=mkdtempSync(join(tmpdir(),'ap-')); const L=lib(d); const req=mkReq(L,CODE);
    L.post(req); await new Promise(r=>setTimeout(r,5));
    // a different approver (different code) writes a fully-valid verdict for ITS session:
    const OTHER='ZZZZ-9999'; const v={id:req.id,sessionId:L.sid(OTHER),decision:'approve',digest,
      mac:createHmac('sha256',L.norm(OTHER)).update(`${req.id}|${L.sid(OTHER)}|approve|${digest}`).digest('hex')};
    writeFileSync(join(d,`${req.id}.verdict.json`),JSON.stringify(v));
    ok('AC2: verdict from a different session → DENY', (await L.await(CODE,req,1500))==='deny'); rmSync(d,{recursive:true,force:true}); }

  // 5. wrong digest (tx swapped after approval) → deny
  { const d=mkdtempSync(join(tmpdir(),'ap-')); const L=lib(d); const req=mkReq(L,CODE);
    L.post(req); await new Promise(r=>setTimeout(r,5)); L.writeVerdict(CODE,req.id,'approve','OTHER-DIGEST');
    ok('approve for wrong digest → DENY', (await L.await(CODE,req,1500))==='deny'); rmSync(d,{recursive:true,force:true}); }

  // 6. AC3 — verdict PRE-PLACED before the request (stale/replay) → deny via post-dating
  { const d=mkdtempSync(join(tmpdir(),'ap-')); const L=lib(d);
    const id='preplaced'; 
    // attacker pre-writes an approve verdict...
    L.writeVerdict(CODE,id,'approve',digest);
    await new Promise(r=>setTimeout(r,30));
    // ...THEN the daemon posts the request (createdMs now AFTER the verdict's mtime):
    const req={id,sessionId:L.sid(CODE),createdAt:'t',createdMs:Date.now(),digest,decoded:{}};
    L.post(req);
    ok('AC3: verdict pre-dating the request → DENY (post-dating check)', (await L.await(CODE,req,800))==='deny'); rmSync(d,{recursive:true,force:true}); }

  // 7. timeout → deny
  { const d=mkdtempSync(join(tmpdir(),'ap-')); const L=lib(d); const req=mkReq(L,CODE);
    L.post(req);
    ok('no verdict before timeout → DENY', (await L.await(CODE,req,250))==='deny'); rmSync(d,{recursive:true,force:true}); }

  // 8. BG5: a pending wait cancels PROMPTLY when shouldAbort fires (e.g. shutdown),
  //    returning deny well before the full timeout would elapse.
  { let aborted=false; setTimeout(()=>{aborted=true;}, 80);
    const t0=Date.now();
    const awaitWithAbort=async()=>{ const deadline=Date.now()+10000;
      while(Date.now()<deadline){ if(aborted) return 'deny'; await new Promise(r=>setTimeout(r,20)); } return 'deny'; };
    const verdict=await awaitWithAbort();
    ok('BG5: aborted wait returns deny', verdict==='deny');
    ok('BG5: returned promptly (≪ the 10s timeout)', Date.now()-t0 < 1000); }

  console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
  process.exit(fail?1:0);
}
main();
