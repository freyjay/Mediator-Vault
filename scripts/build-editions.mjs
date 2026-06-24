#!/usr/bin/env node
// Build BOTH editions from the single compiled source. The crypto core is shared
// (one sign-core.js), so the two artifacts CANNOT drift — they are assembled from
// the same dist/. Apple omits vault.js; orange omits sign-once.js.
import { execSync } from 'child_process';
import { mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync, existsSync } from 'fs';
import { join } from 'path';

const ROOT = process.cwd();
const DIST = join(ROOT, 'dist');
console.error('tsc → dist/ …');
execSync('npx tsc', { stdio: 'inherit' });

for (const [edition, pkgFile] of [['apple','package.apple.json'], ['orange','package.orange.json']]) {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'editions', pkgFile), 'utf8'));
  const outDir = join(ROOT, 'build', pkg.name);
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(join(outDir, 'dist'), { recursive: true });
  mkdirSync(join(outDir, 'scripts'), { recursive: true });
  for (const f of pkg.files) {
    if (f.startsWith('dist/')) {
      const src = join(DIST, f.slice(5));
      if (!existsSync(src)) { console.error(`  ✗ ${pkg.name}: missing ${f}`); process.exit(1); }
      copyFileSync(src, join(outDir, f));
    } else if (f === 'scripts/preinstall.mjs') {
      copyFileSync(join(ROOT,'scripts','preinstall.mjs'), join(outDir,'scripts','preinstall.mjs'));
    } else if (f === 'README.md') {
      const r = join(ROOT,'editions',`README.${edition}.md`);
      if (existsSync(r)) copyFileSync(r, join(outDir,'README.md'));
    }
  }
  writeFileSync(join(outDir,'package.json'), JSON.stringify(pkg, null, 2));
  // Sanity: assert the FORBIDDEN file is absent from this artifact.
  const forbidden = edition==='apple' ? 'dist/vault.js' : 'dist/sign-once.js';
  if (existsSync(join(outDir, forbidden))) { console.error(`  ✗ ${pkg.name} CONTAINS forbidden ${forbidden}!`); process.exit(1); }
  console.error(`  ✓ ${pkg.name} assembled (verified: no ${forbidden})`);
}
console.error('Both editions built under build/. Publish ONE per machine.');
