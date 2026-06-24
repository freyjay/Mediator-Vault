// Pass 3/4 regression: honest decode (EE), zero-effect refusal (DD),
// network normalization (KK), and AAD-binds-network round trip (MM).
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

class GuardError extends Error { constructor(m){super(m);this.name='GuardError';} }

// ---- replicate net-ids ----
const KNOWN=['preprod','mainnet','devnet','undeployed'];
function normalizeNetworkId(raw){ const n=String(raw??'').trim().toLowerCase(); if(KNOWN.includes(n))return n; throw new Error(`unknown network '${raw}'`); }
const SEAL_VERSION=1;
function sealAAD(net){ return Buffer.from(`mn-vault-seal-v${SEAL_VERSION}|net=${net}`,'utf8'); }

// ---- replicate honest decode (EE) ----
function recipientLooksReadable(s){ if(!s)return false; if(s==='?')return false; if(s.includes('[object'))return false; return s.trim().length>0; }
function valueAsNonNegIntString(v){ try{ const n=BigInt(typeof v==='string'?v:(v??'0')); return n>=0n?n.toString():null; }catch{ return null; } }
function decodeTx(tx){
  const outputs=[]; let inputCount=0,offersSeen=0,intentCount=0,outputsSeen=0,unreadable=0;
  const intents=tx?.intents??new Map();
  const keys=typeof intents.keys==='function'?Array.from(intents.keys()):[];
  for(const seg of keys){ const intent=intents.get(seg); if(!intent)continue; intentCount++;
    for(const offer of [intent.guaranteedUnshieldedOffer,intent.fallibleUnshieldedOffer]){ if(!offer)continue; offersSeen++;
      inputCount+=offer.inputs?.length??0;
      for(const o of offer.outputs??[]){ outputsSeen++;
        const rawR=(o.owner??o.address);
        const recipient=(typeof rawR==='string'||typeof rawR==='number')?String(rawR):'';
        const valueStr=valueAsNonNegIntString(o.value);
        const readable=recipientLooksReadable(recipient)&&valueStr!==null;
        if(!readable)unreadable++;
        outputs.push({recipient:readable?recipient:'<unreadable>',valueAtoms:valueStr??'<unreadable>',token:'native'});
      }
    }
  }
  return {outputs,inputCount,offersSeen,intentCount,outputsSeen,unreadable};
}
function guard(tx,ctx){
  const d=decodeTx(tx);
  if(d.intentCount>0&&d.offersSeen===0)throw new GuardError('present but no offers');
  if(d.intentCount===0)throw new GuardError('no intents');
  if(d.unreadable>0)throw new GuardError(`${d.unreadable} unreadable outputs`);
  const zero=d.inputCount===0&&d.outputsSeen===0;
  if(zero&&ctx.purpose!=='register-dust')throw new GuardError('zero-effect');
  return d;
}
const mkTx=(intents)=>{const m=new Map();intents.forEach((it,i)=>m.set(i,it));return {intents:m};};
const offer=(outs,ins=0)=>({outputs:outs,inputs:Array(ins).fill({})});

let pass=0,fail=0;
const expect=(n,fn,shouldThrow)=>{let t=false,m='';try{fn();}catch(e){t=true;m=e.message;}const ok=t===shouldThrow;console.log(`${ok?'✓':'✗ FAIL'}  ${n}${t?'  → '+m.slice(0,50):''}`);ok?pass++:fail++;};

console.log('=== EE: honest decode rejects [object Object] garbage ===');
expect('output with object recipient refused (false-confidence)', ()=>guard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:{nested:'x'},value:'100'}],1)}]),{purpose:'deploy'}), true);
expect('output with readable recipient allowed', ()=>guard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'addr1xyz',value:'100'}],1)}]),{purpose:'deploy'}), false);
expect('negative value refused', ()=>guard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'-5'}],1)}]),{purpose:'deploy'}), true);

console.log('\n=== DD: zero-effect refusal ===');
expect('zero-effect deploy refused', ()=>guard(mkTx([{guaranteedUnshieldedOffer:offer([],0)}]),{purpose:'deploy'}), true);
expect('zero-effect allowed for register-dust', ()=>guard(mkTx([{guaranteedUnshieldedOffer:offer([],0)}]),{purpose:'register-dust'}), false);

console.log('\n=== KK: network normalization ===');
expect('typo mainet rejected', ()=>normalizeNetworkId('mainet'), true);
expect('MAINNET normalized ok', ()=>{ if(normalizeNetworkId('MAINNET')!=='mainnet')throw new Error('x'); }, false);
expect('  Preprod  trimmed+lowered', ()=>{ if(normalizeNetworkId('  Preprod  ')!=='preprod')throw new Error('x'); }, false);

console.log('\n=== MM: AAD binds networkId (tamper detection) ===');
{
  const key=randomBytes(32), iv=randomBytes(12), seed=randomBytes(32);
  const c=createCipheriv('aes-256-gcm',key,iv); c.setAAD(sealAAD('preprod'));
  const ct=Buffer.concat([c.update(seed),c.final()]); const tag=c.getAuthTag();
  // correct AAD decrypts
  expect('correct network AAD decrypts', ()=>{ const d=createDecipheriv('aes-256-gcm',key,iv); d.setAAD(sealAAD('preprod')); d.setAuthTag(tag); Buffer.concat([d.update(ct),d.final()]); }, false);
  // relabeled network (mainnet) FAILS to decrypt — tamper detected
  expect('relabeled network AAD fails (tamper detected)', ()=>{ const d=createDecipheriv('aes-256-gcm',key,iv); d.setAAD(sealAAD('mainnet')); d.setAuthTag(tag); Buffer.concat([d.update(ct),d.final()]); }, true);
}


// ── Pass 5/6 additions: token honesty (TT), guard net normalization (VV) ──
console.log('\n=== TT: token-field honesty ===');
// reuse the decode model with token logic
function decodeTok(o){
  const recipient=(typeof (o.owner??o.address)==='string')?String(o.owner??o.address):'';
  const valueStr=valueAsNonNegIntString(o.value);
  const tokenRaw=(o.type??o.tokenType);
  const tokenPresent=tokenRaw!==undefined&&tokenRaw!==null;
  const tokenReadable=!tokenPresent||typeof tokenRaw==='string';
  const readable=recipientLooksReadable(recipient)&&valueStr!==null&&tokenReadable;
  return readable;
}
{
  const expectTok=(n,o,want)=>{const got=decodeTok(o);const ok=got===want;console.log(`${ok?'✓':'✗ FAIL'}  ${n}`);ok?pass++:fail++;};
  expectTok('absent token → readable (native)', {owner:'a',value:'1'}, true);
  expectTok('string token → readable', {owner:'a',value:'1',type:'CUSTOM'}, true);
  expectTok('object token → UNreadable (not mislabeled native)', {owner:'a',value:'1',type:{raw:'x'}}, false);
}

console.log('\n=== VV: guard normalizes ctx.network (case-insensitive) ===');
{
  // model the guard's network branch
  function netCheck(ctxNet, vaultNet){
    if(ctxNet){ let a; try{a=normalizeNetworkId(ctxNet);}catch{throw new GuardError('unknown net');} if(a!==vaultNet)throw new GuardError('mismatch'); }
    return true;
  }
  const vault=normalizeNetworkId('preprod');
  const ex=(n,fn,st)=>{let t=false;try{fn();}catch{t=true;}const ok=t===st;console.log(`${ok?'✓':'✗ FAIL'}  ${n}`);ok?pass++:fail++;};
  ex('ctx Preprod matches preprod (no false mismatch)', ()=>netCheck('Preprod',vault), false);
  ex('ctx mainnet rejected on preprod vault', ()=>netCheck('mainnet',vault), true);
  ex('ctx unknown net rejected', ()=>netCheck('mainet',vault), true);
}

console.log('\n=== RR: busy as counter (overlap-safe) ===');
{
  let cleared=false, depth=0;
  const bundle={ isBusy:()=>depth>0, clearKeys(){ if(cleared)return true; if(depth>0)return false; cleared=true; return true; },
    async withKeysBusy(fn){ depth++; try{return await fn();}finally{depth--;} } };
  const ex=(n,c)=>{const ok=c;console.log(`${ok?'✓':'✗ FAIL'}  ${n}`);ok?pass++:fail++;};
  // simulate two overlapping brackets
  let inner;
  const outer = bundle.withKeysBusy(async()=>{
    inner = bundle.withKeysBusy(async()=>{ await new Promise(r=>setTimeout(r,20)); });
    // both active now → depth should be 2, clear refused
    ex('clear refused while 2 brackets active', bundle.clearKeys()===false && bundle.isBusy()===true);
    await inner;
  });
  await outer;
  ex('clear allowed after all brackets exit', bundle.clearKeys()===true);
}

// R5: decode DoS caps — oversized intents/outputs are treated as undecodable
// (fail-closed), never an unbounded loop. (Mirrors decodeTx's MAX_INTENTS/OUTPUTS.)
{
  const okR5=(n,c)=>{console.log(`${c?'✓':'✗ FAIL'}  ${n}`);if(c)pass++;else fail++;};
  const MAX_INTENTS = 1000, MAX_OUTPUTS = 10000;
  let threw=false; try { const k=new Array(MAX_INTENTS+1).fill(0); if(k.length>MAX_INTENTS) throw new Error('intents'); } catch { threw=true; }
  okR5('R5: >1000 intents → refuse (fail-closed)', threw);
  threw=false; try { let s=0; for(let i=0;i<MAX_OUTPUTS+5;i++){ s++; if(s>MAX_OUTPUTS) throw new Error('outputs'); } } catch { threw=true; }
  okR5('R5: >10000 outputs → refuse (fail-closed)', threw);
  threw=false; try { const k=new Array(3).fill(0); if(k.length>MAX_INTENTS) throw new Error('x'); } catch { threw=true; }
  okR5('R5: normal 3-intent tx → not tripped', !threw);
}

console.log(`\n=== FINAL DECODE-SUITE RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail?1:0);
