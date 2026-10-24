// #149: independently signed target-policy matrix in both directions and caveat negatives.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import jsigs from 'jsonld-signatures';
import {CapabilityDelegation, createRootCapability} from '@digitalbazaar/zcap';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {didKeyFromSeed, makeDocumentLoader, signInvocation, verifyInvocation, verifyDelegation,
  ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL} from './lib.mjs';
const dll = process.argv[2];
const directory = mkdtempSync(join(tmpdir(), 'zcap-profile-'));
const path = name => join(directory, name + '.json');
const read = name => JSON.parse(readFileSync(path(name), 'utf8'));
const write = (name, value) => writeFileSync(path(name), JSON.stringify(value));
let assertions = 0;
function check(actual, expected, label) {
  assert.equal(actual, expected, label);
  assertions++;
}
function dotnet(...args) {
  const result = spawnSync('dotnet', [dll, ...args], {encoding: 'utf8', timeout: 30000});
  if(result.error || result.signal || ![0, 1].includes(result.status))
    throw result.error ?? new Error(result.stderr || `CLI failed: ${result.signal}`);
  if(result.status === 1) assert.match(result.stdout, /^FAIL\n(?:MalformedCapability|AttenuationViolation|InvalidTarget|InvalidSignature):/,
    `Negative test must be a validation denial, not a crash: ${result.stdout}`);
  return result.status === 0;
}
const owner = await didKeyFromSeed(new Uint8Array(32).fill(1));
const holder = await didKeyFromSeed(new Uint8Array(32).fill(2));
const cases = [
  ['', '', true], ['', '/child', true], ['', '?day=tuesday', true],
  ['?day=tuesday', '&hour=12', true], ['', 'child', false], ['', '&hour=12', false],
  ['?day=tuesday', '?hour=12', false], ['?day=tuesday', '/child', false]
];
try {
  for(const [baseSuffix, suffix, allowed] of cases) {
    const base = 'https://example.com/profile' + baseSuffix;
    const target = base + suffix;
    assert.ok(dotnet('gen-profile', directory, base, target));
    const dotnetRoot = read('root');
    for(const mode of [false, true]) {
      const expected = suffix === '' || (mode && allowed);
      check((await verifyDelegation({delegated: read('delegated'), root: dotnetRoot,
        allowTargetAttenuation: mode})).verified, expected, `.NET → JS delegation ${target}, ${mode}`);
      for(const kind of ['root', 'delegated']) {
        check((await verifyInvocation({securedDocument: read(kind + '-invocation'), root: dotnetRoot,
          expectedAction: 'read', expectedTarget: target, expectedRootCapability: dotnetRoot.id,
          allowTargetAttenuation: mode})).verified, expected, `.NET → JS ${kind} invocation ${target}, ${mode}`);
      }
    }
    const root = createRootCapability({controller: owner.did, invocationTarget: base});
    const loader = makeDocumentLoader({roots: [root]});
    async function delegate(invocationTarget) {
      return jsigs.sign({'@context': [ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL],
        id: 'urn:uuid:' + randomUUID(), controller: holder.did, invocationTarget,
        allowedAction: ['read'], expires: new Date(Date.now() + 86400000).toISOString(), parentCapability: root.id}, {
        suite: new Ed25519Signature2020({key: owner.key}),
        purpose: new CapabilityDelegation({parentCapability: root.id}), documentLoader: loader});
    }
    const delegated = await delegate(base);
    write('root', root); write('delegated', await delegate(target));
    for(const kind of ['root', 'delegated']) {
      write(kind + '-invocation', await signInvocation({
        applicationDocument: {'@context': [ZCAP_CONTEXT_URL, ED25519_2020_CONTEXT_URL],
          id: 'urn:uuid:' + randomUUID(), type: 'https://example.com/Request'},
        capability: kind === 'root' ? root.id : delegated, capabilityAction: 'read', invocationTarget: target,
        key: kind === 'root' ? owner.key : holder.key, roots: [root]}));
    }
    for(const mode of [false, true]) {
      const expected = suffix === '' || (mode && allowed);
      check(dotnet('verify', path('delegated'), path('root'), String(mode)), expected, `JS → .NET delegation ${target}, ${mode}`);
      for(const kind of ['root', 'delegated'])
        check(dotnet('verify-invocation', path(kind + '-invocation'), path('root'), 'read', target, String(mode)), expected,
          `JS → .NET ${kind} invocation ${target}, ${mode}`);
    }
    // Stock JS rejects built-in caveat vocabulary; .NET rejects the field even when empty/null.
    if(suffix === '' && baseSuffix === '') {
      for(const caveat of [
        [{type: 'UsageCount', maxUses: 1000000}],
        [{type: 'ValidWhileTrue', uri: 'https://holder.example/always-valid'}],
        [{type: 'Expiration', expires: '2099-01-01T00:00:00Z'}]
      ]) {
        const received = {...delegated, caveat};
        check((await verifyDelegation({delegated: received, root})).verified, false, 'JS caveat rejection');
        write('legacy', received);
        check(dotnet('verify', path('legacy'), path('root')), false, '.NET caveat rejection');
        const unsigned = {...received}; delete unsigned.proof;
        await assert.rejects(() => jsigs.sign(unsigned, {suite: new Ed25519Signature2020({key: owner.key}),
          purpose: new CapabilityDelegation({parentCapability: root.id}), documentLoader: loader}), /./);
        assertions++;
      }
      for(const caveat of [null, [], {}, [{type: 'Unknown', value: 1}]]) {
        write('legacy', {...delegated, caveat});
        check(dotnet('verify', path('legacy'), path('root')), false, '.NET forbidden caveat shape');
      }
    }
  }
  console.log(`ALL ${assertions} PROFILE CHECKS PASSED — target policies and caveat rejection.`);
} finally {
  rmSync(directory, {recursive: true, force: true});
}
