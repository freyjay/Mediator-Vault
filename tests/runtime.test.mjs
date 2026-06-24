// PASS 7 — RUNTIME adversarial harness. Execute the real logic against hostile
// payloads instead of reasoning about it. Replicates the guard + the daemon's
// request-validation + the JSON line protocol exactly as written.

class GuardError extends Error { constructor(m){super(m);this.name='GuardError';} }
class VaultLockedError extends Error { constructor(m='locked'){super(m);this.name='VaultLockedError';} }
const KNOWN=['preprod','mainnet','devnet','undeployed'];
function normalizeNetworkId(raw){ const n=String(raw??'').trim().toLowerCase(); if(KNOWN.includes(n))return n; throw new Error(`unknown network '${raw}'`); }

function recipientLooksReadable(s){ if(!s)return false; if(s==='?')return false; if(s.includes('[object'))return false; return s.trim().length>0; }
function valueAsNonNegIntString(v){ if(typeof v==='bigint')return v>=0n?v.toString():null; if(typeof v==='number')return Number.isInteger(v)&&v>=0?String(v):null; if(typeof v==='string'){ if(!/^[0-9]+$/.test(v))return null; try{const n=BigInt(v);return n>=0n?n.toString():null;}catch{return null;} } if(v===undefined||v===null)return '0'; return null; }
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
        const tokenRaw=(o.type??o.tokenType);
        const tokenPresent=tokenRaw!==undefined&&tokenRaw!==null;
        const tokenReadable=!tokenPresent||typeof tokenRaw==='string';
        const readable=recipientLooksReadable(recipient)&&valueStr!==null&&tokenReadable;
        if(!readable)unreadable++;
      }
    }
  }
  return {outputs,inputCount,offersSeen,intentCount,outputsSeen,unreadable};
}
function maxOutputAtoms(){ const v=process.env.MN_MAX_OUTPUT_ATOMS; if(!v)return null; try{const n=BigInt(v);return n>0n?n:null;}catch{return null;} }
function decodeAndGuard(tx,ctx,net,label){
  if(ctx.network){ let a; try{a=normalizeNetworkId(ctx.network);}catch{throw new GuardError(`unknown net '${ctx.network}'`);} if(a!==net.networkId)throw new GuardError('net mismatch'); }
  const allowed=new Set(['deploy','register-dust','interact','other']);
  if(!allowed.has(ctx.purpose))throw new GuardError(`purpose '${ctx.purpose}' not allowed`);
  let d; try{d=decodeTx(tx);}catch(e){throw new GuardError(`undecodable [${label}]: ${e?.message??e}`);}
  if(d.intentCount>0&&d.offersSeen===0)throw new GuardError('present but no offers');
  if(d.intentCount===0)throw new GuardError('no intents');
  if(d.unreadable>0)throw new GuardError(`${d.unreadable} unreadable`);
  const zero=d.inputCount===0&&d.outputsSeen===0;
  if(zero&&ctx.purpose!=='register-dust')throw new GuardError('zero-effect');
  const cap=maxOutputAtoms();
  return d;
}

let pass=0,fail=0;
const ex=(n,fn,st)=>{let t=false,m='';try{fn();}catch(e){t=true;m=String(e?.message??e);}const ok=t===st;console.log(`${ok?'✓':'✗ FAIL'}  ${n}${t?'  → '+m.slice(0,55):''}`);ok?pass++:fail++;};
const net={networkId:'preprod'};

console.log('=== PASS 7: hostile inputs the guard must survive WITHOUT crashing or fail-open ===');

// 1. tx is literally null/undefined/garbage — decodeTx must not throw uncaught
ex('tx=null → no intents (refused, not crash)', ()=>decodeAndGuard(null,{purpose:'deploy'},net,'x'), true);
ex('tx=undefined → refused', ()=>decodeAndGuard(undefined,{purpose:'deploy'},net,'x'), true);
ex('tx=number → refused', ()=>decodeAndGuard(42,{purpose:'deploy'},net,'x'), true);
ex('tx=string → refused', ()=>decodeAndGuard("haha",{purpose:'deploy'},net,'x'), true);

// 2. intents is not a Map (object, array, has fake keys())
ex('intents=plain object (no keys fn) → refused (no intents)', ()=>decodeAndGuard({intents:{a:1}},{purpose:'deploy'},net,'x'), true);
ex('intents.keys is not a function → refused', ()=>decodeAndGuard({intents:{keys:42}},{purpose:'deploy'},net,'x'), true);

// 3. a malicious intents whose keys() throws
ex('intents.keys() throws → caught as undecodable', ()=>{ const eviltx={intents:{keys:()=>{throw new Error('boom');}}}; decodeAndGuard(eviltx,{purpose:'deploy'},net,'x'); }, true);

// 4. intents.get returns a getter that throws
ex('intent getter throws → caught', ()=>{ const m=new Map(); Object.defineProperty(m,'_',{}); const tx={intents:{keys:()=>['s'],get:()=>{throw new Error('boom');}}}; decodeAndGuard(tx,{purpose:'deploy'},net,'x'); }, true);

// 5. offer.outputs is a hostile object with a throwing iterator
ex('outputs with throwing iterator → caught', ()=>{
  const badOutputs={ [Symbol.iterator]:()=>{throw new Error('iter boom');} };
  const tx={intents:{keys:()=>['s'],get:()=>({guaranteedUnshieldedOffer:{inputs:[{}],outputs:badOutputs}})}};
  decodeAndGuard(tx,{purpose:'deploy'},net,'x');
}, true);

// 6. value is a huge string (BigInt parse) — must not hang
ex('value = 10000-digit number → parses or refuses, no hang', ()=>{
  const big='9'.repeat(10000);
  const tx={intents:{keys:()=>['s'],get:()=>({guaranteedUnshieldedOffer:{inputs:[{}],outputs:[{owner:'a',value:big}]}})}};
  decodeAndGuard(tx,{purpose:'deploy'},net,'x'); // readable → allowed
}, false);

// 7. value with embedded null / weird unicode
ex('value="0x10" now REFUSED (decimal-only)', ()=>{
  const tx={intents:{keys:()=>['s'],get:()=>({guaranteedUnshieldedOffer:{inputs:[{}],outputs:[{owner:'a',value:'0x10'}]}})}};
  decodeAndGuard(tx,{purpose:'deploy'},net,'x');
}, true);
ex('value="1e9" (sci notation) → BigInt throws → unreadable → refused', ()=>{
  const tx={intents:{keys:()=>['s'],get:()=>({guaranteedUnshieldedOffer:{inputs:[{}],outputs:[{owner:'a',value:'1e9'}]}})}};
  decodeAndGuard(tx,{purpose:'deploy'},net,'x');
}, true);

// 8. recipient is the string "[object Object]" literally (attacker tries to mimic)
ex('recipient literally "[object Object]" → refused', ()=>{
  const tx={intents:{keys:()=>['s'],get:()=>({guaranteedUnshieldedOffer:{inputs:[{}],outputs:[{owner:'[object Object]',value:'1'}]}})}};
  decodeAndGuard(tx,{purpose:'deploy'},net,'x');
}, true);

// 9. ctx.purpose is an object / array / number (type confusion via JSON)
ex('ctx.purpose=object → not in allowlist → refused', ()=>decodeAndGuard({intents:new Map()},{purpose:{}},net,'x'), true);
ex('ctx.purpose=number → refused', ()=>decodeAndGuard({intents:new Map()},{purpose:7},net,'x'), true);
ex('ctx.purpose=null → refused', ()=>decodeAndGuard({intents:new Map()},{purpose:null},net,'x'), true);

// 10. ctx.network is an object (type confusion)
ex('ctx.network=object → normalize throws → GuardError', ()=>{
  const tx={intents:{keys:()=>['s'],get:()=>({guaranteedUnshieldedOffer:{inputs:[{}],outputs:[{owner:'a',value:'1'}]}})}};
  decodeAndGuard(tx,{purpose:'deploy',network:{}},net,'x');
}, true);

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail?1:0);
