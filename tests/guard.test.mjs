// Replicate the decodeAndGuard + decodeTx logic exactly as written in sign-core.ts
// (pure logic, no SDK) and prove the fail-closed properties hold on adversarial input.

class GuardError extends Error { constructor(m){super(m);this.name='GuardError';} }

function decodeTx(tx) {
  const outputs=[]; let inputCount=0, offersSeen=0, intentCount=0;
  const intents = tx?.intents ?? new Map();
  const keys = typeof intents.keys === 'function' ? Array.from(intents.keys()) : [];
  for (const seg of keys) {
    const intent = intents.get(seg);
    if (!intent) continue;
    intentCount++;
    for (const offer of [intent.guaranteedUnshieldedOffer, intent.fallibleUnshieldedOffer]) {
      if (!offer) continue;
      offersSeen++;
      inputCount += offer.inputs?.length ?? 0;
      for (const o of offer.outputs ?? []) {
        outputs.push({recipient:String(o.owner??o.address??'?'),valueAtoms:String(o.value??'0'),token:String(o.type??o.tokenType??'native')});
      }
    }
  }
  return {outputs,inputCount,offersSeen,intentCount};
}

function maxOutputAtoms(){ const v=process.env.MN_MAX_OUTPUT_ATOMS; if(!v)return null; try{const n=BigInt(v);return n>0n?n:null;}catch{return null;} }

function decodeAndGuard(tx, ctx, net, label) {
  if (ctx.network && ctx.network !== net.networkId) throw new GuardError(`network mismatch: request '${ctx.network}' vault '${net.networkId}'`);
  const allowed = new Set(['deploy','register-dust','interact','other']);
  if (!allowed.has(ctx.purpose)) throw new GuardError(`purpose '${ctx.purpose}' not allowed`);
  let d; try { d = decodeTx(tx); } catch(e){ throw new GuardError(`undecodable [${label}]: ${e.message}`); }
  if (d.intentCount > 0 && d.offersSeen === 0) throw new GuardError(`[${label}] ${d.intentCount} intents but no readable offers — refusing`);
  if (d.intentCount === 0) throw new GuardError(`[${label}] no intents — refusing`);
  const cap = maxOutputAtoms();
  if (cap !== null) { let total=0n; for (const o of d.outputs){ let v; try{v=BigInt(o.valueAtoms);}catch{throw new GuardError(`bad value [${label}]`);} if(v>cap) throw new GuardError(`output ${v} exceeds per-output cap ${cap}`); total+=v; } if(total>cap) throw new GuardError(`total ${total} exceeds cap ${cap}`); }
  return {outputs:d.outputs,inputCount:d.inputCount,network:net.networkId};
}

const net = {networkId:'preprod'};
const okCtx = {purpose:'deploy',description:'',network:'preprod'};
let pass=0, fail=0;
function expect(name, fn, shouldThrow) {
  let threw=false, msg='';
  try { fn(); } catch(e){ threw=true; msg=e.message; }
  const ok = threw === shouldThrow;
  console.log(`${ok?'✓':'✗ FAIL'}  ${name}${threw?'  → '+msg.slice(0,60):''}`);
  ok?pass++:fail++;
}

// helper to build a tx with N intents, each with given offers
function mkTx(intents){ const m=new Map(); intents.forEach((it,i)=>m.set(i,it)); return {intents:m}; }
const offer = (outs,ins=0)=>({outputs:outs,inputs:Array(ins).fill({})});

console.log('\n=== CRITICAL B: fail-CLOSED on unreadable / empty ===');
// genuinely empty tx (no intents) → REFUSE (nothing to sign)
expect('empty tx (no intents) refused', ()=>decodeAndGuard(mkTx([]), okCtx, net, 'base'), true);
// intents present but NO readable offers → REFUSE (the blind-signing case)
expect('intents present, zero offers refused (anti-blind-sign)', ()=>decodeAndGuard(mkTx([{}, {}]), okCtx, net, 'base'), true);
// intents with a real offer → ALLOWED
expect('intent with readable offer allowed', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'addr1',value:'100',type:'native'}],1)}]), okCtx, net, 'base'), false);

console.log('\n=== CRITICAL D: network cross-check ===');
expect('mainnet request on preprod vault refused', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'1'}])}]), {purpose:'deploy',network:'mainnet'}, net, 'base'), true);
expect('matching network allowed', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'1'}])}]), {purpose:'deploy',network:'preprod'}, net, 'base'), false);
expect('no network in ctx allowed (optional)', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'1'}])}]), {purpose:'deploy'}, net, 'base'), false);

console.log('\n=== policy: purpose allowlist ===');
expect('bad purpose refused', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'1'}])}]), {purpose:'drain-wallet'}, net, 'base'), true);

console.log('\n=== value cap (when MN_MAX_OUTPUT_ATOMS set) ===');
process.env.MN_MAX_OUTPUT_ATOMS='1000';
expect('output over cap refused', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'5000'}])}]), okCtx, net, 'base'), true);
expect('output under cap allowed', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'500'}])}]), okCtx, net, 'base'), false);
// R6: many individually-sub-cap outputs that SUM past the cap → refuse (total cap)
expect('R6: 3×400 (=1200) over total cap 1000 refused', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'400'},{owner:'b',value:'400'},{owner:'c',value:'400'}])}]), okCtx, net, 'base'), true);
expect('R6: 2×400 (=800) under total cap 1000 allowed', ()=>decodeAndGuard(mkTx([{guaranteedUnshieldedOffer:offer([{owner:'a',value:'400'},{owner:'b',value:'400'}])}]), okCtx, net, 'base'), false);
delete process.env.MN_MAX_OUTPUT_ATOMS;

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail?1:0);
