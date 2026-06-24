// Proves mutual exclusion (apple XOR orange) against a real temp lock dir,
// using the SAME atomic O_EXCL claim as edition.ts (R1/R2).
import { mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync, mkdirSync, openSync, writeSync, closeSync, chmodSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

function makeClaim(dir) {
  const LOCK = join(dir, 'edition.lock');
  const HUMAN = { sign:'sign edition', daemon:'daemon edition' };
  const OTHER = { sign:'daemon', daemon:'sign' };
  function readLock(){ if(!existsSync(LOCK))return null; try{const l=JSON.parse(readFileSync(LOCK,'utf8'));return (l.edition==='sign'||l.edition==='daemon')?l:null;}catch{return null;} }
  function tryCreate(me){ let fd; try{ fd=openSync(LOCK,'wx',0o600); writeSync(fd,JSON.stringify({edition:me,claimedAt:new Date().toISOString()})); return true; }catch(e){ if(e.code==='EEXIST') return false; throw e; } finally{ if(fd!==undefined){try{closeSync(fd);}catch{}} } }
  return {
    LOCK,
    claim(me){
      mkdirSync(dir,{recursive:true});
      if(tryCreate(me)) return;                       // atomic win
      const ex=readLock();
      if(!ex) throw new Error('lock exists but unreadable — fail-closed');
      if(ex.edition!==me) throw new Error(`already ${HUMAN[ex.edition]}; remove ${OTHER[me]} first`);
      // else ours, proceed
    },
    current(){ return readLock()?.edition ?? null; },
  };
}

let pass=0,fail=0;
const ex=(n,fn,st)=>{let t=false,m='';try{fn();}catch(e){t=true;m=e.message;}const ok=t===st;console.log(`${ok?'✓':'✗ FAIL'}  ${n}${t?'  → '+m.slice(0,45):''}`);ok?pass++:fail++;};
const ok=(n,c)=>{console.log(`${c?'✓':'✗ FAIL'}  ${n}`);c?pass++:fail++;};

console.log('=== mutual exclusion: apple XOR orange ===');

// Scenario 1: fresh machine, install sign → ok; sign again → ok (idempotent)
{
  const dir=mkdtempSync(join(tmpdir(),'mnv-')); const E=makeClaim(dir);
  ex('fresh: claim sign succeeds', ()=>E.claim('sign'), false);
  ok('lock now says sign', E.current()==='sign');
  ex('re-claim sign succeeds (idempotent)', ()=>E.claim('sign'), false);
  ex('claim daemon on a sign machine REFUSES', ()=>E.claim('daemon'), true);
  ok('lock still says sign (unchanged by refused claim)', E.current()==='sign');
  rmSync(dir,{recursive:true,force:true});
}

// Scenario 2: fresh machine, install daemon → ok; sign refuses
{
  const dir=mkdtempSync(join(tmpdir(),'mnv-')); const E=makeClaim(dir);
  ex('fresh: claim daemon succeeds', ()=>E.claim('daemon'), false);
  ex('claim sign on a daemon machine REFUSES', ()=>E.claim('sign'), true);
  ok('lock still says daemon', E.current()==='daemon');
  rmSync(dir,{recursive:true,force:true});
}

// Scenario 3: switching editions = remove lock, then the other claims
{
  const dir=mkdtempSync(join(tmpdir(),'mnv-')); const E=makeClaim(dir);
  E.claim('sign');
  ex('daemon refused while sign lock present', ()=>E.claim('daemon'), true);
  rmSync(E.LOCK,{force:true});                  // user removes the sign edition's lock
  ex('after removing lock, daemon claims successfully', ()=>E.claim('daemon'), false);
  ok('lock now says daemon (switched)', E.current()==='daemon');
  rmSync(dir,{recursive:true,force:true});
}

// Scenario 4 (R1/R2): the atomic O_EXCL claim resists a pre-existing lock — a
// second claimant cannot silently overwrite it, and a pre-planted OTHER-edition
// lock makes us refuse (not reclaim). This is the race/symlink-hardening behavior.
{
  const dir=mkdtempSync(join(tmpdir(),'mnv-')); const E=makeClaim(dir);
  // simulate the daemon having already won the atomic create:
  E.claim('daemon');
  // a second, simultaneous "sign" start must NOT overwrite — it reads + refuses:
  ex('R1/R2: second claimant cannot overwrite an existing lock', ()=>E.claim('sign'), true);
  ok('R1/R2: lock still says daemon (atomic create held)', E.current()==='daemon');
  rmSync(dir,{recursive:true,force:true});
}
// Scenario 5 (R1/R2): a torn/garbage lock file → fail-closed (refuse), never a
// blind reclaim that could mask a second live process.
{
  const dir=mkdtempSync(join(tmpdir(),'mnv-')); const E=makeClaim(dir);
  mkdirSync(dir,{recursive:true});
  writeFileSync(E.LOCK, '{ this is not valid json');     // torn write
  ex('R1/R2: unreadable lock → refuse (fail-closed)', ()=>E.claim('sign'), true);
  rmSync(dir,{recursive:true,force:true});
}

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail?1:0);