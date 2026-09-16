#!/usr/bin/env node
/* CWI Memory Seal — scripts/seal-dogfood.js
 * Dogfood run 2026-09-16: scans CWI's REAL memory files with the real rule
 * set, writes the findings as audits.json, and seals a real Ed25519-signed
 * checkpoint over the memory files' hashes.
 *
 * Usage: node scripts/seal-dogfood.js [--inspect-only]
 *   --inspect-only: print critical findings, write nothing.
 *
 * Private keys are written ONLY to ~/workspace/cwi-company/memory-seal/private-keys.json
 * (chmod 600). Only public keys + hashes go in the repo.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const MS = require('../memory.js');

const BUILD = path.join(__dirname, '..');
const INSPECT_ONLY = process.argv.includes('--inspect-only');
const PRIV_DIR = path.join(os.homedir(), 'workspace/cwi-company/memory-seal');
const PRIV_PATH = path.join(PRIV_DIR, 'private-keys.json');

const NOW = '2026-09-16T15:30:00.000Z';

const FILES = [
  path.join(os.homedir(), 'MEMORY.md'),
  path.join(os.homedir(), 'USER.md'),
  path.join(os.homedir(), 'dreams/alignment/derived/ALIGNMENT_SYNTHESIS.md'),
];

function load(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch (e) { return null; }
}

/* ---------- 1. scan each file ---------- */
const audits = [];
FILES.forEach(p => {
  const text = load(p);
  if (text === null) { console.log('skip (missing):', p); return; }
  const audit = MS.scan(text, {
    source: 'file://' + p.replace(os.homedir(), '~'),
    now: NOW,
    auditId: undefined,
  });
  audits.push(audit);
  console.log('== ' + path.basename(p) + ' :: ' + MS.summarizeAudit(audit) +
    ' :: ' + audit.finding_count + ' findings, ' + audit.line_count + ' lines');
});

/* ---------- 2. print every CRITICAL finding for review ---------- */
console.log('\n--- CRITICAL findings (review before publishing) ---');
let crit = 0;
audits.forEach(a => {
  a.findings.filter(f => f.severity === 'CRITICAL').forEach(f => {
    crit++;
    console.log('[' + a.source + ' L' + f.line + '] ' + f.rule + ' ' + f.title);
    console.log('   evidence: ' + f.evidence);
  });
});
console.log('total CRITICAL: ' + crit);

if (INSPECT_ONLY) { console.log('\ninspect-only: nothing written.'); process.exit(0); }

/* ---------- 3. keypair ---------- */
let privStore = {};
if (fs.existsSync(PRIV_PATH)) {
  try { privStore = JSON.parse(fs.readFileSync(PRIV_PATH, 'utf8')); } catch (e) { privStore = {}; }
}
const kp = MS.generateKeypair();
const KEY_ID = 'mskey_2026-09-16';
privStore[KEY_ID] = {
  privateKeyB64: kp.privateKeyB64,
  publicKeyB64: kp.publicKeyB64,
  created: NOW,
  note: 'Memory Seal dogfood checkpoint signer. NEVER publish this file.',
};
fs.mkdirSync(PRIV_DIR, { recursive: true });
fs.writeFileSync(PRIV_PATH, JSON.stringify(privStore, null, 2));
fs.chmodSync(PRIV_PATH, 0o600);
console.log('\nprivate key stored: ' + PRIV_PATH + ' (chmod 600, off-repo)');

/* ---------- 4. seal checkpoint over the memory files' hashes ---------- */
const entries = FILES.map(p => {
  const text = load(p);
  return { id: 'sha256:' + path.basename(p), text: 'sha256(' + p.replace(os.homedir(), '~') + ')=' + MS.sha256Hex(text || '') };
});
entries.push({ id: 'note', text: 'Checkpoint seals CONTENT HASHES of CWI memory files as of ' + NOW + '. Verifying the checkpoint later proves whether the files changed — not whether the contents were true.' });

const cp = MS.sealCheckpoint({
  entries,
  prevHash: null,
  keypair: kp,
  createdAt: NOW,
  label: 'dogfood genesis — CWI memory files 2026-09-16',
});
console.log('checkpoint sealed: ' + cp.checkpoint_id);

/* ---------- 5. write repo files ---------- */
fs.writeFileSync(path.join(BUILD, 'audits.json'),
  JSON.stringify({ schema: 'cwi.memory-audit-index/1.0', generated_at: NOW, rules_version: MS.RULES_VERSION, audits }, null, 2) + '\n');
fs.writeFileSync(path.join(BUILD, 'checkpoints.json'),
  JSON.stringify({ schema: MS.SCHEMA_CHECKPOINT_LOG, generated_at: NOW, signer_pubkey_b64: kp.publicKeyB64, signer_key_id: KEY_ID, entries, checkpoints: [cp] }, null, 2) + '\n');
console.log('wrote audits.json (' + audits.length + ' audits) and checkpoints.json');
console.log('checkpoint verify: ' + MS.verifyCheckpoint(cp, entries).verdict);
console.log('chain verify: ' + (MS.verifyChain({ checkpoints: [cp] }).ok ? 'OK' : 'BROKEN'));
