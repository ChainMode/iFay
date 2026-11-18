import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  computeCapParamsSha256,
  createFayManifest,
  createFayingMandate,
  deriveEntityKeypair,
  ed25519KeypairFromSeed,
  signCapDriverManifest,
  signSkillDescriptor,
  triggerG0EmergencyTakeover,
} from '@ifay/sdk';
import { IfayMcpServer, JSONRPC_ERRORS } from '../dist/index.js';

const CLI_PATH = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const SEED = Buffer.from(
  '2424242424242424242424242424242424242424242424242424242424242424',
  'hex',
);

function startMcpStdioClient() {
  const child = spawn(process.execPath, [CLI_PATH], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const pending = new Map();
  const rawResponses = [];

  rl.on('line', (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    rawResponses.push(msg);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const resolve = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  });

  return {
    sendRaw(line) {
      child.stdin.write(`${line}\n`);
    },
    notify(method, params) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
    },
    request(id, method, params) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`Timed out waiting for JSON-RPC response id=${id}`));
        }, 5000);
        pending.set(id, (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      });
    },
    rawResponses,
    async close() {
      rl.close();
      child.stdin.end();
      await new Promise((resolve) => child.once('close', resolve));
    },
  };
}

describe('@ifay/mcp-server — 1. Stdio JSON-RPC 2.0 Lifecycle & Error Handling', () => {
  it('1.1 negotiates MCP initialize (2024-11-05 & 2025-03-26), handles notifications/initialized silently, and lists 4 tools', async () => {
    const client = startMcpStdioClient();
    try {
      const initRes = await client.request(1, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'mcp-test-client', version: '1.0.0' },
      });
      assert.equal(initRes.result.protocolVersion, '2024-11-05');
      assert.equal(initRes.result.serverInfo.name, '@ifay/mcp-server');
      assert.deepEqual(initRes.result.capabilities, { tools: { listChanged: false } });

      client.notify('notifications/initialized', {});
      const pingRes = await client.request(2, 'ping');
      assert.deepEqual(pingRes.result, {});

      const listRes = await client.request(3, 'tools/list', {});
      const toolNames = listRes.result.tools.map((t) => t.name);
      assert.deepEqual(toolNames, [
        'fayid_validate',
        'faymanifest_validate',
        'cap_evaluate',
        'ssp_verify_descriptor',
      ]);
      // Ensure notification produced no extra frame (only ids 1, 2, 3)
      assert.equal(client.rawResponses.length, 3);
    } finally {
      await client.close();
    }
  });

  it('1.2 returns canonical JSON-RPC error codes (-32700, -32600, -32601, -32602)', () => {
    const server = new IfayMcpServer();

    const parseErr = server.handleJsonLine('{bad json');
    assert.equal(parseErr.error.code, JSONRPC_ERRORS.PARSE_ERROR);

    const invalidReq = server.handleJsonLine(JSON.stringify({ jsonrpc: '1.0', id: 10 }));
    assert.equal(invalidReq.error.code, JSONRPC_ERRORS.INVALID_REQUEST);

    const unknownMethod = server.handleMessage({
      jsonrpc: '2.0',
      id: 11,
      method: 'resources/unknown',
    });
    assert.equal(unknownMethod.error.code, JSONRPC_ERRORS.METHOD_NOT_FOUND);

    const unknownTool = server.handleMessage({
      jsonrpc: '2.0',
      id: 12,
      method: 'tools/call',
      params: { name: 'nonexistent_tool', arguments: {} },
    });
    assert.equal(unknownTool.error.code, JSONRPC_ERRORS.INVALID_PARAMS);

    const badParams = server.handleMessage({
      jsonrpc: '2.0',
      id: 13,
      method: 'tools/call',
      params: { name: 'fayid_validate', arguments: { fayId: 12345 } },
    });
    assert.equal(badParams.error.code, JSONRPC_ERRORS.INVALID_PARAMS);
  });
});

describe('@ifay/mcp-server — 2. End-to-End Tool Verification over Stdio', () => {
  it('2.1 fayid_validate validates canonical FayID, DID consistency, Ed25519 key hash, and HoK proof (valid & invalid)', async () => {
    const client = startMcpStdioClient();
    try {
      await client.request(1, 'initialize', { protocolVersion: '2025-03-26' });
      const ifay = deriveEntityKeypair(SEED, 'ifay', 0).value;
      const challenge = 'mcp-hok-challenge-2026';
      const sigHex = ifay.signPayload(Buffer.from(challenge, 'utf8')).toString('hex');

      const okCall = await client.request(2, 'tools/call', {
        name: 'fayid_validate',
        arguments: {
          fayId: ifay.entityId,
          expectedKind: 'IFAY_ID',
          did: `did:fay:${ifay.entityId}`,
          publicKeyHex: ifay.publicKeyHex,
          challengeUtf8: challenge,
          signatureHex: sigHex,
        },
      });
      const okPayload = JSON.parse(okCall.result.content[0].text);
      assert.equal(okPayload.valid, true);
      assert.equal(okPayload.kind, 'IFAY_ID');
      assert.equal(okPayload.didConsistent, true);
      assert.equal(okPayload.keyBindingVerified, true);
      assert.equal(okPayload.holderOfKeyVerified, true);

      const otherKey = deriveEntityKeypair(SEED, 'ifay', 1).value;
      const badCall = await client.request(3, 'tools/call', {
        name: 'fayid_validate',
        arguments: {
          fayId: ifay.entityId,
          expectedKind: 'HUMAN_ID',
          publicKeyHex: otherKey.publicKeyHex,
        },
      });
      const badPayload = JSON.parse(badCall.result.content[0].text);
      assert.equal(badPayload.valid, false);
      assert.equal(badPayload.keyBindingVerified, false);
      assert.equal(
        badPayload.errors.some((e) => e.includes('KIND_MISMATCH')),
        true,
      );
      assert.equal(badPayload.errors.includes('PUBLIC_KEY_HASH_MISMATCH_WITH_FAYID'), true);
    } finally {
      await client.close();
    }
  });

  it('2.2 faymanifest_validate validates FayManifest payloads and returns structured errors or resolved summary', async () => {
    const client = startMcpStdioClient();
    try {
      await client.request(1, 'initialize', { protocolVersion: '2025-03-26' });
      const ifay = deriveEntityKeypair(SEED, 'ifay', 0).value;
      const validManifest = createFayManifest({
        name: 'mcp-verified-ifay',
        version: '1.0.0',
        description: 'Validated via @ifay/mcp-server',
        vendor: 'ChainMode Tests',
        fayId: ifay.entityId,
        controlMode: 'ego',
        modules: ['device_driver_hub', 'sensor'],
        protocols: ['cap_protocol', 'ssp_protocol'],
        ego: { modelSource: '@ego-models/personal-v0.2' },
      });

      const okRes = await client.request(2, 'tools/call', {
        name: 'faymanifest_validate',
        arguments: { manifest: validManifest },
      });
      const okData = JSON.parse(okRes.result.content[0].text);
      assert.equal(okData.valid, true);
      assert.equal(okData.summary.resolvedPhase, 'Phase 3');
      assert.equal(okData.summary.egoNamespace, 'governed');
      assert.equal(okData.summary.resolvedModules.includes('ego_model'), true);

      const badRes = await client.request(3, 'tools/call', {
        name: 'faymanifest_validate',
        arguments: {
          manifest: {
            name: 'broken-manifest',
            fayId: 'not_a_valid_fayid',
            unknownExtraField: true,
          },
        },
      });
      const badData = JSON.parse(badRes.result.content[0].text);
      assert.equal(badData.valid, false);
      assert.equal(badData.errorCount > 0, true);
    } finally {
      await client.close();
    }
  });

  it('2.3 cap_evaluate enforces ALLOW, unknown-op DENY, tampered-mandate DENY, and G0 safe-state override', async () => {
    const client = startMcpStdioClient();
    try {
      await client.request(1, 'initialize', { protocolVersion: '2025-03-26' });

      const humanPrime = deriveEntityKeypair(SEED, 'hid', 0).value;
      const agentIfay = deriveEntityKeypair(SEED, 'ifay', 0).value;
      const anchorSeed = Buffer.alloc(32, 0x51);
      const anchorKp = ed25519KeypairFromSeed(anchorSeed);
      const trustAnchors = {
        key_mcp_anchor: {
          algorithm: 'Ed25519',
          public_key_raw_hex: anchorKp.publicKeyHex,
        },
      };
      const driverManifest = signCapDriverManifest(
        {
          manifest_id: 'mf_mcp_gate_01',
          driver_id: 'drv_mcp_host',
          version: '1.0.0',
          issued_at: '2026-11-18T00:00:00Z',
          signer_key_id: 'key_mcp_anchor',
          resources: [
            {
              resource_id: 'res_mcp_fs',
              safe_states: [{ safe_state_id: 'lock_fs_readonly', description: 'Lock read-only' }],
              operations: [
                {
                  operation_id: 'list_workspace_files',
                  mode: 'read',
                  criticality: 'routine',
                  consequence_irreversibility: 'reversible',
                  domain_category: 'software_control',
                },
                {
                  operation_id: 'delete_production_branch',
                  mode: 'execute',
                  criticality: 'high',
                  consequence_irreversibility: 'irreversible_consequence',
                  domain_category: 'software_control',
                },
              ],
            },
          ],
        },
        anchorSeed,
      );

      const mandate = createFayingMandate(
        {
          mandateId: 'mnd_mcp_01',
          humanPrimeId: humanPrime.entityId,
          fayId: agentIfay.entityId,
          grade: 'G2',
          bindingModel: 'model_a_plus_b',
          scope: {
            resources: ['res_mcp_fs'],
            actions: ['read', 'execute'],
            domains: ['https://ifay.ai'],
            terminals: ['terminal:mcp:host'],
          },
          issuedAtEpochMs: 1800000000000,
          expiresAtEpochMs: 1800003600000,
        },
        humanPrime,
      );

      // Case A: Routine read within scope -> ALLOW
      const allowRes = await client.request(2, 'tools/call', {
        name: 'cap_evaluate',
        arguments: {
          action: {
            requestId: 'req_allow_1',
            fayId: agentIfay.entityId,
            resourceId: 'res_mcp_fs',
            operationId: 'list_workspace_files',
            requestedMode: 'read',
            params: { dir: '/workspace' },
            nowEpochMs: 1800000010000,
          },
          policy: {
            manifest: driverManifest,
            trustAnchors,
            minGrade: 'G3',
          },
          mandate,
          trustedIssuerPublicKeyHex: humanPrime.publicKeyHex,
        },
      });
      const allowData = JSON.parse(allowRes.result.content[0].text);
      assert.equal(allowData.decision, 'ALLOW');
      assert.equal(allowData.rule, 'CAP-1.0-ALLOW:POLICY_AND_MANDATE_SATISFIED');
      assert.equal(allowData.auditTrace.mandateSignatureVerified, true);
      assert.equal(allowData.auditTrace.paramsSha256, computeCapParamsSha256({ dir: '/workspace' }));

      // Case B: High-criticality operation without Human Prime confirmation -> DENY (2006)
      const denyUnconfirmedRes = await client.request(3, 'tools/call', {
        name: 'cap_evaluate',
        arguments: {
          action: {
            requestId: 'req_deny_2',
            fayId: agentIfay.entityId,
            resourceId: 'res_mcp_fs',
            operationId: 'delete_production_branch',
            requestedMode: 'execute',
            params: { branch: 'production' },
            nowEpochMs: 1800000010000,
          },
          policy: {
            manifest: driverManifest,
            trustAnchors,
            minGrade: 'G2',
          },
          mandate,
          trustedIssuerPublicKeyHex: humanPrime.publicKeyHex,
        },
      });
      const denyUnconfirmed = JSON.parse(denyUnconfirmedRes.result.content[0].text);
      assert.equal(denyUnconfirmed.decision, 'DENY');
      assert.equal(denyUnconfirmed.errorCode, 'E_CONFIRMATION_REQUIRED');
      assert.equal(denyUnconfirmed.diagnosticCode, 2006);

      // Case C: Tampered Mandate signature -> DENY (2008)
      const tamperedMandate = { ...mandate, grade: 'G1' };
      const denyTamperedRes = await client.request(4, 'tools/call', {
        name: 'cap_evaluate',
        arguments: {
          action: {
            fayId: agentIfay.entityId,
            resourceId: 'res_mcp_fs',
            operationId: 'list_workspace_files',
            requestedMode: 'read',
            nowEpochMs: 1800000010000,
          },
          policy: { manifest: driverManifest, trustAnchors },
          mandate: tamperedMandate,
          trustedIssuerPublicKeyHex: humanPrime.publicKeyHex,
        },
      });
      const denyTampered = JSON.parse(denyTamperedRes.result.content[0].text);
      assert.equal(denyTampered.decision, 'DENY');
      assert.equal(denyTampered.errorCode, 'E_MANDATE_INVALID');
      assert.equal(denyTampered.rule, 'D-4:MANDATE_ED25519_SIGNATURE_INVALID');

      // Case D: G0 emergency takeover -> DENY with safeStateDirective
      const g0Mandate = triggerG0EmergencyTakeover(mandate, humanPrime, 1800000015000);
      const g0Res = await client.request(5, 'tools/call', {
        name: 'cap_evaluate',
        arguments: {
          action: {
            fayId: agentIfay.entityId,
            resourceId: 'res_mcp_fs',
            operationId: 'list_workspace_files',
            requestedMode: 'read',
            nowEpochMs: 1800000020000,
          },
          policy: { manifest: driverManifest, trustAnchors },
          mandate: g0Mandate,
          trustedIssuerPublicKeyHex: humanPrime.publicKeyHex,
        },
      });
      const g0Data = JSON.parse(g0Res.result.content[0].text);
      assert.equal(g0Data.decision, 'DENY');
      assert.equal(g0Data.errorCode, 'E_G0_EMERGENCY_OVERRIDE');
      assert.equal(g0Data.safeStateDirective.safe_state_id, 'lock_fs_readonly');
    } finally {
      await client.close();
    }
  });

  it('2.4 ssp_verify_descriptor validates SSP 1.0 descriptors and Detached Ed25519 JWS signatures', async () => {
    const client = startMcpStdioClient();
    try {
      await client.request(1, 'initialize', { protocolVersion: '2025-03-26' });
      const publisher = deriveEntityKeypair(SEED, 'ifay', 3).value;
      const baseDescriptor = {
        protocol: 'ssp/1.0',
        version: '1.0',
        skillId: 'skill.code.security_audit',
        name: 'Cryptographic Security Audit',
        publisherFayId: publisher.entityId,
        origin: 'https://skills.ifay.ai',
        visibility: 'public',
        executionMode: 'sync',
        inputSchema: { type: 'object', required: ['targetRepo'] },
        outputSchema: { type: 'object', required: ['findings'] },
      };
      const signed = signSkillDescriptor(baseDescriptor, { signer: publisher });

      const okRes = await client.request(2, 'tools/call', {
        name: 'ssp_verify_descriptor',
        arguments: {
          descriptor: signed,
          trustedPublicKeyHex: publisher.publicKeyHex,
        },
      });
      const okData = JSON.parse(okRes.result.content[0].text);
      assert.equal(okData.valid, true);
      assert.equal(okData.structuralValid, true);
      assert.equal(okData.signatureVerified, true);
      assert.equal(okData.publisherFayId, publisher.entityId);

      const tamperedRes = await client.request(3, 'tools/call', {
        name: 'ssp_verify_descriptor',
        arguments: {
          descriptor: { ...signed, name: 'Tampered Skill Name' },
          trustedPublicKeyHex: publisher.publicKeyHex,
        },
      });
      const tamperedData = JSON.parse(tamperedRes.result.content[0].text);
      assert.equal(tamperedData.valid, false);
      assert.equal(tamperedData.signatureVerified, false);
      assert.equal(tamperedData.errorCode, 'SSP_SIGNATURE_INVALID');
    } finally {
      await client.close();
    }
  });
});
