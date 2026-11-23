// Copies the generated @abja/tokens stylesheet from a base checkout and
// records its source commit. base is not published to a registry, so the
// generated CSS is vendored as its README describes for external consumers.
//   node scripts/sync-tokens.mjs [path-to-base]   (default: ../../base)
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const base = resolve(process.argv[2] ?? resolve(here, '../../../base'));
const source = resolve(base, 'packages/tokens/tokens.css');
const commit = execFileSync('git', ['-C', base, 'log', '-1', '--format=%H %cs', '--', 'packages/tokens'], { encoding: 'utf8' }).trim();
const css = readFileSync(source, 'utf8');
const header = `/* Vendored from @abja/tokens (base ${commit}).\n   Do not edit; run \`npm run sync-tokens\` in web/. */\n`;
writeFileSync(resolve(here, '../src/styles/tokens.css'), header + css);
console.log(`tokens.css synced from ${commit}`);
