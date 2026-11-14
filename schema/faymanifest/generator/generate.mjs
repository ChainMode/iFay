import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCHEMA_PATH, stringifySchema } from './schema-factory.mjs';

const outputPath = fileURLToPath(SCHEMA_PATH);
const next = stringifySchema();
const check = process.argv.includes('--check');

if (check) {
  let current = '';
  try {
    current = await readFile(outputPath, 'utf8');
  } catch {
    throw new Error(`schema is missing: ${outputPath}`);
  }
  if (current !== next) {
    throw new Error(`schema is stale: ${outputPath}`);
  }
  console.log(`schema is current: ${outputPath}`);
} else {
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, next);
  console.log(`wrote ${outputPath}`);
}
