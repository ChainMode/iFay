import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { buildFayManifestSchema, SCHEMA_PATH } from './schema-factory.mjs';

const root = new URL('../', import.meta.url);
const fixtures = [
  ['minimal', new URL('examples/minimal.faymanifest.json', root)],
  ['drone', new URL('examples/drone-controller.faymanifest.json', root)],
];

const schema = buildFayManifestSchema();
const generated = JSON.parse(await readFile(fileURLToPath(SCHEMA_PATH), 'utf8'));

assert(generated.$schema === 'https://json-schema.org/draft/2020-12/schema', 'missing $schema');
assert(generated.$id === 'https://ifay.ai/schema/faymanifest/faymanifest.schema.json', 'missing $id');
assert(JSON.stringify(generated) === JSON.stringify(schema), 'generated schema differs from factory');
assertArrayItemsAreSchemas(generated);

for (const [name, url] of fixtures) {
  const manifest = JSON.parse(await readFile(fileURLToPath(url), 'utf8'));
  const errors = validate(manifest, schema, '$');
  assert(errors.length === 0, `${name} fixture failed validation:\n${errors.join('\n')}`);
}

const invalid = {
  name: 'missing-control-mode',
  version: '1.0.0',
  description: 'invalid',
  vendor: 'ifay',
  modules: [],
  protocols: [],
};
assert(
  validate(invalid, schema, '$').some((line) => line.includes('controlMode')),
  'invalid fixture without controlMode should fail',
);

console.log(`validated ${fixtures.length} FayManifest fixtures`);

function validate(value, node, path) {
  const resolved = resolve(node);
  const errors = [];

  if (resolved.type === 'object') {
    if (!isPlainObject(value)) return [`${path} must be object`];
    for (const key of resolved.required ?? []) {
      if (!(key in value)) errors.push(`${path}.${key} is required`);
    }
    const props = resolved.properties ?? {};
    if (resolved.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in props)) errors.push(`${path}.${key} is not allowed`);
      }
    }
    for (const [key, child] of Object.entries(props)) {
      if (key in value) errors.push(...validate(value[key], child, `${path}.${key}`));
    }
    return errors;
  }

  if (resolved.type === 'array') {
    if (!Array.isArray(value)) return [`${path} must be array`];
    for (const [idx, item] of value.entries()) {
      errors.push(...validate(item, resolved.items, `${path}[${idx}]`));
    }
    return errors;
  }

  if (resolved.type === 'string') {
    if (typeof value !== 'string') return [`${path} must be string`];
    if (resolved.minLength !== undefined && value.length < resolved.minLength) {
      errors.push(`${path} must have length >= ${resolved.minLength}`);
    }
    if (resolved.pattern && !new RegExp(resolved.pattern).test(value)) {
      errors.push(`${path} must match ${resolved.pattern}`);
    }
    if (resolved.enum && !resolved.enum.includes(value)) {
      errors.push(`${path} must be one of ${resolved.enum.join(', ')}`);
    }
    return errors;
  }

  return errors;
}

function resolve(node) {
  if (!node?.$ref) return node;
  const name = node.$ref.match(/^#\/\$defs\/(.+)$/)?.[1];
  assert(name && schema.$defs[name], `unknown ref ${node.$ref}`);
  return schema.$defs[name];
}

function assertArrayItemsAreSchemas(value, path = '$') {
  if (Array.isArray(value)) {
    value.forEach((child, idx) => assertArrayItemsAreSchemas(child, `${path}[${idx}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  if (value.type === 'array') {
    assert(isPlainObject(value.items) || typeof value.items === 'boolean', `${path}.items is not a schema`);
  }
  for (const [key, child] of Object.entries(value)) {
    assertArrayItemsAreSchemas(child, `${path}.${key}`);
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
