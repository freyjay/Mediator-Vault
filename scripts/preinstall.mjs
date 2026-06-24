#!/usr/bin/env node
// LAYER 1 of mutual exclusion: refuse `npm install` of one edition when the OTHER
// edition already owns this machine. Honest about its strength: this catches the
// normal install; it can be bypassed with --ignore-scripts, which is why the
// load-bearing check is at RUN TIME (edition.ts claimEdition in each entry point).
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const me = process.argv[2];                       // 'sign' | 'daemon'
const LOCK = join(homedir(), '.mn-vault', 'edition.lock');
const HUMAN = { sign: 'mn-vault-sign (apple, Path A)', daemon: 'mn-vault-daemon (orange, Path B)' };
const OTHER = { sign: 'daemon', daemon: 'sign' };

try {
  if (existsSync(LOCK)) {
    const lock = JSON.parse(readFileSync(LOCK, 'utf8'));
    if (lock?.edition && lock.edition !== me) {
      console.error('\n────────────────────────────────────────────────────────');
      console.error(`✋ Refusing to install ${HUMAN[me]}.`);
      console.error(`   This machine already has ${HUMAN[lock.edition]} active.`);
      console.error('   Only ONE signing edition may exist at a time.');
      console.error(`   If you want this edition, first remove the other:`);
      console.error(`     npm rm -g mn-vault-${OTHER[me]}  &&  rm ${LOCK}`);
      console.error('   (If you want apple, remove orange; if you want orange, remove apple.)');
      console.error('────────────────────────────────────────────────────────\n');
      process.exit(1);
    }
  }
} catch {
  // A malformed lock should not brick installs; the runtime check is authoritative.
}
process.exit(0);
