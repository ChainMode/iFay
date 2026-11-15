#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runIfactsSuite } from '../src/index.mjs';

function parseArgs(argv) {
  const opts = {
    selfTest: false,
    json: false,
    standalone: false,
    manifestPath: null,
    targetFayId: null,
    outputPath: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--self-test') opts.selfTest = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--standalone') opts.standalone = true;
    else if (arg === '--manifest' && argv[i + 1]) {
      opts.manifestPath = argv[++i];
    } else if (arg === '--target-fay-id' && argv[i + 1]) {
      opts.targetFayId = argv[++i];
    } else if (arg === '--output' && argv[i + 1]) {
      opts.outputPath = argv[++i];
    } else if (arg === '--help' || arg === '-h') {
      console.log(
        [
          'Usage: ifacts [options]',
          '',
          'Options:',
          '  --self-test             Run full L1 -> L2 -> L3 progressive self-test',
          '  --manifest <path>       Validate a specific FayManifest JSON file',
          '  --target-fay-id <id>    Specify target FayID (rejects cofay_ with exit code 2)',
          '  --standalone            Force built-in fallback vectors without sibling repo lookup',
          '  --json                  Print machine-readable ifacts-report/1.0 JSON to stdout',
          '  --output <path>         Write ifacts-report/1.0 JSON report to disk',
        ].join('\n'),
      );
      process.exit(0);
    }
  }
  return opts;
}

const cli = parseArgs(process.argv.slice(2));
const manifest = cli.manifestPath
  ? JSON.parse(readFileSync(resolve(process.cwd(), cli.manifestPath), 'utf8'))
  : undefined;

const report = runIfactsSuite({
  subjectId: cli.targetFayId ?? undefined,
  manifest,
  disableSiblingRepoLookup: cli.standalone,
});

if (cli.outputPath) {
  writeFileSync(resolve(process.cwd(), cli.outputPath), `${JSON.stringify(report, null, 2)}\n`);
}

if (cli.json) {
  console.log(JSON.stringify(report, null, 2));
} else if (report.overallStatus === 'rejected_out_of_scope') {
  console.error(`[iFACTS] REJECTED (${report.errorCode}): ${report.message}`);
} else {
  console.log(
    [
      `[iFACTS] Report Format : ${report.reportFormat}`,
      `[iFACTS] Subject       : ${report.subject}`,
      `[iFACTS] Resolved Phase: ${report.resolvedPhase}`,
      `[iFACTS] L1 Status     : ${report.levels.L1.status} (${report.levels.L1.passedCount}/${report.levels.L1.checks.length})`,
      `[iFACTS] L2 Status     : ${report.levels.L2.status} (${report.levels.L2.passedCount}/${report.levels.L2.checks.length})`,
      `[iFACTS] L3 Status     : ${report.levels.L3.status} (${report.levels.L3.passedCount}/${report.levels.L3.checks.length})`,
      `[iFACTS] L4 Status     : ${report.levels.L4.status}`,
      `[iFACTS] iFay Ready    : ${report.ifayReady.tier}`,
      `[iFACTS] Overall       : ${report.overallStatus.toUpperCase()}`,
    ].join('\n'),
  );
}

if (report.overallStatus === 'rejected_out_of_scope') {
  process.exit(2);
}
if (report.overallStatus !== 'passed') {
  process.exit(1);
}
