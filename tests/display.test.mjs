// AF6/AF7: the approver display is a security surface. Prove the sanitizer strips
// ANSI/control chars (so a crafted recipient can't spoof the approval screen) and
// that amounts are digit-grouped for readable magnitude.

function sanitizeForTerminal(s, maxLen = 120) {
  const str = String(s ?? '');
  let out = '';
  for (const ch of str) {
    const code = ch.codePointAt(0);
    if (code === 0x1b || code < 0x20 || (code >= 0x7f && code <= 0x9f)) out += '\uFFFD';
    else out += ch;
  }
  if (out.length > maxLen) out = out.slice(0, maxLen) + `…(+${out.length - maxLen} chars)`;
  return out;
}
function groupDigits(decimal) {
  if (!/^[0-9]+$/.test(decimal)) return sanitizeForTerminal(decimal, 40);
  return decimal.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

let pass=0,fail=0;
const ok=(n,c)=>{console.log(`${c?'✓':'✗ FAIL'}  ${n}`);c?pass++:fail++;};

console.log('=== AF6: terminal-injection sanitizer ===');
// a malicious recipient trying to inject a fake "approved" line + clear screen
const evil = 'addr1\x1b[2J\x1b[H\x1b[32mAPPROVED\x1b[0m\x07\n\rfake';
const cleaned = sanitizeForTerminal(evil, 200);
ok('ESC (0x1b) removed', !cleaned.includes('\x1b'));
ok('no raw ESC sequence survives', !/\x1b\[/.test(cleaned));
ok('newline/CR stripped (can\'t inject new prompt lines)', !cleaned.includes('\n') && !cleaned.includes('\r'));
ok('BEL (0x07) stripped', !cleaned.includes('\x07'));
ok('replacement char inserted for control bytes', cleaned.includes('\uFFFD'));
ok('legible text retained', cleaned.includes('addr1') && cleaned.includes('fake'));

console.log('\n=== AF6: length cap prevents prompt push-off ===');
const long = 'A'.repeat(500);
const capped = sanitizeForTerminal(long, 80);
ok('over-long field capped', capped.length < 120 && capped.includes('+420 chars'));

console.log('\n=== AF7: digit grouping for magnitude readability ===');
ok('5000000 → 5,000,000', groupDigits('5000000') === '5,000,000');
ok('100 → 100 (no comma)', groupDigits('100') === '100');
ok('1000000000 → 1,000,000,000', groupDigits('1000000000') === '1,000,000,000');
ok('non-decimal falls back to sanitized', groupDigits('<unreadable>') === '<unreadable>');

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
process.exit(fail?1:0);
