#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import {
  CofaySeatBuilder,
  OFFICIAL_DEVICE_PROFILES,
  PrimaryBodyStore,
  formatBufInspection,
  formatSoulDemoReport,
  parseBufBinary,
  runSoulDemo,
  sliceSoulForDevice,
  syncPrimaryReplicas,
} from '../src/index.mjs';

function parseFlags(argv) {
  const positionals = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx !== -1) {
        flags[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1);
      } else {
        const key = arg.slice(2);
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
          flags[key] = next;
          i += 1;
        } else {
          flags[key] = true;
        }
      }
    } else if (arg === '-o' && argv[i + 1] !== undefined) {
      flags.out = argv[i + 1];
      i += 1;
    } else if (arg === '-h') {
      flags.help = true;
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, flags };
}

function printHelp() {
  console.log(`ifay-soul — Portable iFay Digital Soul, Peer Sync Ledger & FayGer BuF Slicer

Usage:
  ifay-soul init <dir> [--name <name>] [--persona <id>] [--seed-hex <64hex>]
  ifay-soul init-cofay <dir> [--archetype project_collaborator|org_service|functional_post] [--org <slug>] [--name <name>]
  ifay-soul add-thought <dir> --title <title> --text <text> [--subtype content|data|knowledge_base|info_feed] [--domain <domain>] [--tags <a,b>]
  ifay-soul record-correction <dir> --prompt <ctx> --wrong <bad> --corrected <good> [--rule <redline>] [--device <id>]
  ifay-soul register-platform <dir> --platform <id> --handle <ref> [--category real_name|expert|commerce|service|social]
  ifay-soul switch-ego <dir> --persona <persona_id>
  ifay-soul sync <replicaDirA> <replicaDirB>
  ifay-soul slice <dir> [--tier super|plus|normal|lite|thin] [--profile <device.json>] [--ego-slot <id>] [--domains <a,b>] [--remote-only] --out <file.buf>
  ifay-soul inspect-buf <file.buf> [--json]
  ifay-soul demo [--out-dir <dir>] [--json]
`);
}

function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.length === 0 || rawArgs[0] === 'help' || rawArgs.includes('--help') || rawArgs.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  const subcommand = rawArgs[0];
  const { positionals, flags } = parseFlags(rawArgs.slice(1));

  switch (subcommand) {
    case 'init': {
      const targetDir = positionals[0];
      if (!targetDir) {
        throw new Error('Usage: ifay-soul init <dir> [--name <name>]');
      }
      const store = PrimaryBodyStore.init({
        dirPath: targetDir,
        displayName: flags.name ?? 'Personal iFay Soul',
        activePersonaId: flags.persona ?? 'professional',
        masterSeed: flags['seed-hex'],
        replicaId: flags['replica-id'] ?? 'replica:primary-01',
      });
      console.log(`Initialized iFay Primary Body in ${store.dirPath}`);
      console.log(`  fay_id:          ${store.fayId}`);
      console.log(`  human_prime_id:  ${store.profile.identity.human_prime_id}`);
      console.log(`  active_persona:  ${store.profile.ego.active_persona_id}`);
      console.log(`  visibility_mode: ${store.profile.identity.visibility_mode}`);
      console.log(`  state_root:      ${store.stateRootSha256}`);
      break;
    }

    case 'init-cofay': {
      const targetDir = positionals[0];
      if (!targetDir) {
        throw new Error('Usage: ifay-soul init-cofay <dir> [--archetype project_collaborator]');
      }
      const seat = CofaySeatBuilder.createSeat({
        roleArchetype: flags.archetype ?? 'project_collaborator',
        orgSlug: flags.org ?? 'ifay-community',
        displayName: flags.name,
        masterSeed: flags['seed-hex'],
      });
      const saved = CofaySeatBuilder.saveToDirectory(targetDir, seat);
      console.log(`Initialized coFay seat package in ${saved.dirPath}`);
      console.log(`  cofay_id:        ${seat.cofay_id}`);
      console.log(`  role_archetype:  ${seat.role_charter.role_archetype}`);
      console.log(`  owner:           ${seat.role_charter.owner.id}`);
      console.log(`  steward:         ${seat.role_charter.steward_human_id ?? seat.role_charter.owner.id}`);
      console.log(`  seat.buf:        ${saved.bufPath} (${saved.bufByteLength} bytes)`);
      break;
    }

    case 'add-thought': {
      const targetDir = positionals[0];
      if (!targetDir || !flags.title || !flags.text) {
        throw new Error('Usage: ifay-soul add-thought <dir> --title <title> --text <text>');
      }
      const store = PrimaryBodyStore.load(targetDir);
      const ev = store.addThought({
        subtype: flags.subtype ?? 'knowledge_base',
        title: String(flags.title),
        text: String(flags.text),
        domain: flags.domain ?? 'general',
        tags: typeof flags.tags === 'string' ? flags.tags.split(',').map((s) => s.trim()).filter(Boolean) : [],
      });
      console.log(`Committed thought_added event ${ev.event_hash.slice(0, 16)}...`);
      console.log(`  state_root: ${store.stateRootSha256}`);
      break;
    }

    case 'record-correction': {
      const targetDir = positionals[0];
      if (!targetDir || !flags.prompt || !flags.wrong || !flags.corrected) {
        throw new Error(
          'Usage: ifay-soul record-correction <dir> --prompt <ctx> --wrong <bad> --corrected <good>',
        );
      }
      const store = PrimaryBodyStore.load(targetDir);
      const ev = store.recordHumanCorrection({
        promptContext: String(flags.prompt),
        rejectedOutput: String(flags.wrong),
        preferredOutput: String(flags.corrected),
        extractedRule: typeof flags.rule === 'string' ? flags.rule : null,
        sourceDeviceId: typeof flags.device === 'string' ? flags.device : undefined,
      });
      console.log(`Recorded human_correction event ${ev.event_hash.slice(0, 16)}...`);
      console.log(`  state_root: ${store.stateRootSha256}`);
      break;
    }

    case 'register-platform': {
      const targetDir = positionals[0];
      if (!targetDir || !flags.platform || !flags.handle) {
        throw new Error('Usage: ifay-soul register-platform <dir> --platform <id> --handle <ref>');
      }
      const store = PrimaryBodyStore.load(targetDir);
      const ev = store.registerPlatform({
        platformId: String(flags.platform),
        category: flags.category ?? 'expert',
        handleOrRef: String(flags.handle),
        discoverable: flags.discoverable !== 'false',
      });
      console.log(`Registered opt-in platform attestation (${flags.platform}) — event ${ev.event_hash.slice(0, 16)}...`);
      console.log(`  visibility_mode: ${store.profile.identity.visibility_mode}`);
      break;
    }

    case 'switch-ego': {
      const targetDir = positionals[0];
      if (!targetDir || !flags.persona) {
        throw new Error('Usage: ifay-soul switch-ego <dir> --persona <persona_id>');
      }
      const store = PrimaryBodyStore.load(targetDir);
      const ev = store.switchActiveEgo(String(flags.persona));
      console.log(`Switched active Ego persona to '${store.profile.ego.active_persona_id}' (${ev.event_hash.slice(0, 16)}...)`);
      break;
    }

    case 'sync': {
      const [dirA, dirB] = positionals;
      if (!dirA || !dirB) {
        throw new Error('Usage: ifay-soul sync <replicaDirA> <replicaDirB>');
      }
      const storeA = PrimaryBodyStore.load(dirA);
      let storeB;
      if (existsSync(join(resolve(dirB), 'ledger.json'))) {
        storeB = PrimaryBodyStore.load(dirB);
      } else {
        storeB = PrimaryBodyStore.createPeerReplica(storeA, {
          replicaId: 'replica:peer-sync',
          dirPath: dirB,
        });
      }
      const report = syncPrimaryReplicas(storeA, storeB);
      if (!report.ok) {
        throw new Error(`Replica sync failed [${report.errorCode}]`);
      }
      console.log(`Synced Primary Body replicas (${report.totalEvents} verified events)`);
      console.log(`  pulled_into_A: ${report.pulledIntoA}`);
      console.log(`  pulled_into_B: ${report.pulledIntoB}`);
      console.log(`  consistent:    ${report.consistent}`);
      console.log(`  state_root:    ${report.stateRootSha256}`);
      break;
    }

    case 'slice': {
      const sourceDir = positionals[0];
      const outPath = flags.out;
      if (!sourceDir || !outPath) {
        throw new Error('Usage: ifay-soul slice <dir> [--tier lite] --out <out.buf>');
      }
      const absSource = resolve(sourceDir);
      const absOut = resolve(String(outPath));
      mkdirSync(dirname(absOut), { recursive: true });

      if (existsSync(join(absSource, 'cofay-seat.json'))) {
        const seat = CofaySeatBuilder.loadFromDirectory(absSource);
        const buf = CofaySeatBuilder.packSeatBuf(seat);
        writeFileSync(absOut, buf);
        console.log(`Sliced coFay seat ${seat.cofay_id} -> ${absOut} (${buf.length} bytes)`);
        break;
      }

      const store = PrimaryBodyStore.load(absSource);
      let deviceProfile = {};
      if (typeof flags.profile === 'string') {
        deviceProfile = JSON.parse(readFileSync(resolve(flags.profile), 'utf8'));
      } else {
        const tier = String(flags.tier ?? 'plus');
        deviceProfile = structuredClone(OFFICIAL_DEVICE_PROFILES[tier] ?? { tier });
      }
      if (typeof flags['ego-slot'] === 'string') {
        deviceProfile.ego_slot = flags['ego-slot'];
      }
      if (typeof flags.domains === 'string') {
        deviceProfile.preferred_domains = flags.domains
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
      }
      if (flags['remote-only'] === true || flags['remote-only'] === 'true') {
        deviceProfile.remote_only = true;
        deviceProfile.network_online = true;
      }

      const sliced = sliceSoulForDevice(store, deviceProfile, {
        signBuf: flags.unsigned !== true,
      });
      writeFileSync(absOut, sliced.bufBytes);
      console.log(`Sliced iFay Digital Soul ${store.fayId} -> ${absOut}`);
      console.log(`  mode:             ${sliced.mode} (tier=${sliced.tier})`);
      console.log(`  bundled_thoughts: ${sliced.sliceSummary.bundledThoughts}/${sliced.sliceSummary.totalPrimaryThoughts}`);
      console.log(`  bundled_skills:   ${sliced.sliceSummary.bundledSkills}/${sliced.sliceSummary.totalPrimarySkills}`);
      console.log(`  buf_bytes:        ${sliced.bufBytes.length}`);
      break;
    }

    case 'inspect-buf': {
      const bufFile = positionals[0];
      if (!bufFile) {
        throw new Error('Usage: ifay-soul inspect-buf <file.buf> [--json]');
      }
      const raw = readFileSync(resolve(bufFile));
      const parsed = parseBufBinary(raw);
      if (flags.json) {
        const printable = {
          header: parsed.header,
          manifest: parsed.manifest,
          trailer: parsed.trailer,
          verified: parsed.verified,
          sections: parsed.sections.map((s) => ({
            id: s.id,
            kind: s.kind,
            visibility: s.visibility,
            digestHex: s.digestHex,
            byteLength: s.payload.length,
          })),
        };
        console.log(JSON.stringify(printable, null, 2));
      } else {
        console.log(formatBufInspection(parsed));
      }
      break;
    }

    case 'demo': {
      const result = runSoulDemo({
        outDir: typeof flags['out-dir'] === 'string' ? flags['out-dir'] : undefined,
      });
      if (flags.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(formatSoulDemoReport(result));
      }
      break;
    }

    default:
      throw new Error(`Unknown subcommand '${subcommand}'. Run 'ifay-soul --help'.`);
  }
}

try {
  main();
} catch (err) {
  console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
