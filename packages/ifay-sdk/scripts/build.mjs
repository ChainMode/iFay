import { chmodSync, copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(__dirname, '..');
const distDir = resolve(pkgRoot, 'dist');
const repoSchemaPath = resolve(pkgRoot, '../../schema/faymanifest/faymanifest.schema.json');

mkdirSync(distDir, { recursive: true });
copyFileSync(repoSchemaPath, resolve(distDir, 'faymanifest.schema.json'));

const cliSource = `#!/usr/bin/env node
import { formatIfayDemoReport, runIfayDemo } from '../src/demo.mjs';

const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  console.log(
    [
      'Usage: ifay-demo [options]',
      '',
      'Executes a zero-dependency cryptographic walkthrough of FayID, FayManifest,',
      'Faying 1.0 Mandate delegation, CAP 1.0 ALLOW/DENY safety gating, and iFACTS.',
      '',
      'Options:',
      '  --json      Emit machine-readable JSON walkthrough output',
      '  --random    Generate a fresh 32-byte random root seed instead of deterministic vector seed',
      '  -h, --help  Show this help message',
    ].join('\\n'),
  );
  process.exit(0);
}

const result = await runIfayDemo({
  randomSeed: args.includes('--random'),
});

if (args.includes('--json')) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(formatIfayDemoReport(result));
}

process.exit(result.ok ? 0 : 1);
`;

const cliPath = resolve(distDir, 'cli.js');
writeFileSync(cliPath, cliSource, 'utf8');
chmodSync(cliPath, 0o755);
