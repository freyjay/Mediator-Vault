// Proves the busy-guard lifecycle (finding J): clearKeys() must NOT zero keys
// while a signing op is in flight, and must succeed once it finishes. Models the
// exact busy/cleared state machine from sign-core.ts unlock().

function makeBundle() {
  let cleared = false, busy = false;
  const bundle = {
    isCleared: () => cleared,
    isBusy: () => busy,
    clearKeys() {
      if (cleared) return true;
      if (busy) return false;            // refuse while in flight
      cleared = true; return true;
    },
  };
  bundle.__setBusy = (v) => { busy = v; };
  return bundle;
}

// Model signCore's busy bracketing around an async body.
async function signCoreModel(bundle, bodyMs, throwMid=false) {
  if (bundle.isCleared()) throw new Error('LOCKED: already cleared');
  bundle.__setBusy(true);
  try {
    await new Promise(r => setTimeout(r, bodyMs));
    if (bundle.isCleared()) throw new Error('LOCKED: cleared mid-op');
    if (throwMid) throw new Error('signing failed mid-op');
    return 'signed';
  } finally {
    bundle.__setBusy(false);
  }
}

let pass=0, fail=0;
const ok=(n,c)=>{ console.log(`${c?'✓':'✗ FAIL'}  ${n}`); c?pass++:fail++; };
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));

async function main() {
  console.log('=== finding J: keys cannot be cleared mid-signing ===');

  // 1. clearKeys during an in-flight op returns false (refused), op still completes.
  {
    const b = makeBundle();
    const op = signCoreModel(b, 60);
    await sleep(20);                       // op is in flight
    const clearedDuring = b.clearKeys();   // should be REFUSED
    ok('clearKeys() refused while op in flight', clearedDuring === false);
    ok('keys still live during op (not cleared)', b.isCleared() === false);
    const res = await op;
    ok('in-flight op completed successfully', res === 'signed');
    const clearedAfter = b.clearKeys();    // now allowed
    ok('clearKeys() succeeds after op finishes', clearedAfter === true && b.isCleared());
  }

  // 2. busy flag is released even if the op throws (finally), so a later clear works.
  {
    const b = makeBundle();
    let threw=false;
    try { await signCoreModel(b, 30, true); } catch { threw=true; }
    ok('op threw as expected', threw);
    ok('busy released after throw (not stuck busy)', b.isBusy() === false);
    ok('clearKeys() succeeds after a thrown op', b.clearKeys() === true);
  }

  // 3. signing after a successful clear fails closed (LOCKED), never signs.
  {
    const b = makeBundle();
    b.clearKeys();
    let lockErr=false;
    try { await signCoreModel(b, 5); } catch(e){ lockErr = /LOCKED/.test(e.message); }
    ok('signing after clear fails closed (LOCKED)', lockErr);
  }

  // 4. idle-tick logic: only clears when NOT busy and past deadline.
  {
    const b = makeBundle();
    const idleShouldClear = (busy, idleMs, deadlineMs) => (!b.isCleared() && !busy && idleMs > deadlineMs);
    ok('idle tick skips while busy', idleShouldClear(true, 999, 10) === false);
    ok('idle tick clears when idle past deadline', idleShouldClear(false, 999, 10) === true);
    ok('idle tick waits before deadline', idleShouldClear(false, 5, 10) === false);
  }

  console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
  process.exit(fail?1:0);
}
main();
