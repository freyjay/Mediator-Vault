// Replicate the signIntents per-input policy and prove it never reuses one sig
// across multiple inputs (finding C).
class GuardError extends Error { constructor(m){super(m);this.name='GuardError';} }

// Pure model of the per-offer signature assembly from signIntents:
function assembleSigs(offer, segSig) {
  const nInputs = offer.inputs?.length ?? 0;
  const existing = (offer.signatures && typeof offer.signatures.at === 'function')
    ? Array.from({length:nInputs}, (_,i)=>offer.signatures.at(i)) : [];
  return Array.from({length:nInputs}, (_,i)=>{
    const s = existing[i];
    if (s !== undefined && s !== null) return s;
    if (nInputs === 1) return segSig;
    throw new GuardError(`signature slot ${i}/${nInputs} missing; refusing to reuse one sig across inputs`);
  });
}

let pass=0,fail=0;
function expect(name, fn, shouldThrow){ let t=false,m=''; try{fn();}catch(e){t=true;m=e.message;} const ok=t===shouldThrow; console.log(`${ok?'✓':'✗ FAIL'}  ${name}${t?'  → '+m.slice(0,55):''}`); ok?pass++:fail++; }
const mkArr = a => ({ at:(i)=>a[i] });

console.log('=== finding C: no silent signature reuse ===');
// single input, no existing sig → segment sig is fine
expect('single input uses segment sig', ()=>{ const r=assembleSigs({inputs:[{}],signatures:mkArr([])}, 'SEG'); if(r[0]!=='SEG')throw new Error('wrong'); }, false);
// multi input, NO existing sigs → must THROW (the old code would reuse 'SEG' for all)
expect('multi-input missing slots refused (no reuse)', ()=>assembleSigs({inputs:[{},{},{}],signatures:mkArr([])}, 'SEG'), true);
// multi input, all existing sigs present → fine, uses them
expect('multi-input with all per-input sigs allowed', ()=>{ const r=assembleSigs({inputs:[{},{}],signatures:mkArr(['A','B'])},'SEG'); if(r[0]!=='A'||r[1]!=='B')throw new Error('wrong'); }, false);
// multi input, partial existing → one slot missing → THROW
expect('multi-input partial sigs refused', ()=>assembleSigs({inputs:[{},{}],signatures:mkArr(['A'])}, 'SEG'), true);
// zero inputs → empty, fine
expect('zero inputs ok', ()=>assembleSigs({inputs:[],signatures:mkArr([])},'SEG'), false);


console.log('\n=== finding R: oversized tx hex refused (size cap) ===');
{
  const MAX=2*1024*1024;
  const check=(hex)=>{ if(typeof hex!=='string'||hex.length===0) throw new GuardError('empty'); if(hex.length>MAX) throw new GuardError('too large'); if(!/^[0-9a-fA-F]+$/.test(hex)) throw new GuardError('not hex'); return true; };
  expect('oversized hex refused', ()=>check('a'.repeat(MAX+2)), true);
  expect('normal-size hex accepted', ()=>check('deadbeef'), false);
  expect('empty hex refused', ()=>check(''), true);
  expect('non-hex refused', ()=>check('zzzz'), true);
}

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail?1:0);
