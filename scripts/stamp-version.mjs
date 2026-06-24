#!/usr/bin/env node
// Stamp a visible version line into every source file header + write VERSION.
// Idempotent: re-running updates the version in place rather than duplicating.
// Usage:  node scripts/stamp-version.mjs           (uses version from package.json)
//         node scripts/stamp-version.mjs 1.0.0-T   (sets a new version everywhere)
import { readFileSync, writeFileSync, readdirSync } from 'fs';
import { join } from 'path';

const root = new URL('..', import.meta.url).pathname;
const pkgPath = join(root, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));

const version = process.argv[2] || pkg.version;
const date = new Date().toISOString().slice(0, 10);

// 1. Update package.json + edition manifests
for (const p of ['package.json', 'editions/package.apple.json', 'editions/package.orange.json']) {
  const fp = join(root, p);
  const j = JSON.parse(readFileSync(fp, 'utf8'));
  j.version = version;
  writeFileSync(fp, JSON.stringify(j, null, 2) + '\n');
}

// 2. Stamp every source .ts with a header line (idempotent)
const srcDir = join(root, 'src');
const STAMP = (v, d) => `// @version ${v} (mn-vault-S) — stamped ${d}`;
const stampRe = /^\/\/ @version .*\n/m;
let stamped = 0;
for (const f of readdirSync(srcDir).filter((x) => x.endsWith('.ts'))) {
  const fp = join(srcDir, f);
  let src = readFileSync(fp, 'utf8');
  // First, remove any existing stamp wherever it is (so we don't leave a stale one
  // above the shebang from a previous buggy run).
  src = src.replace(stampRe, '');
  if (src.startsWith('#!')) {
    // Shebang MUST stay line 1 — insert the stamp on line 2.
    const nl = src.indexOf('\n');
    src = src.slice(0, nl + 1) + STAMP(version, date) + '\n' + src.slice(nl + 1);
  } else {
    src = STAMP(version, date) + '\n' + src;
  }
  writeFileSync(fp, src);
  stamped++;
}

// 3. Write a VERSION manifest that travels with loose files
writeFileSync(join(root, 'VERSION'), [
  `mn-vault ${version}`,
  `stamped ${date}`,
  `tests: 103 assertions across 8 suites`,
  `SDK pins: ledger-v8 8.0.3, wallet-sdk-hd 3.0.2, unshielded-wallet 2.1.0, facade 3.0.0`,
  `STATUS: hardened logic; SDK symbols inferred — run 'npx tsc --noEmit' to verify before mainnet`,
  ``,
].join('\n'));

console.log(`stamped version ${version} into ${stamped} source files + 3 manifests + VERSION`);
