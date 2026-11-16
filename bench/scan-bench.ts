/**
 * Benchmarks a cold wallet scan (the "what does this key own?" pass) over real pool history.
 *
 *   npx ts-node --transpile-only bench/scan-bench.ts [path/to/recovery/src/snapshots] [chain...]
 *
 * Reads the snapshots written by fiberevm/recovery's `bun run snapshot`, decodes them into
 * commitments the same way the recovery page does, then times each stage of the scan for a
 * fresh (empty) wallet: the per-leaf engine path, the LeafPrefilter path, and their parts.
 */
import fs from 'fs';
import path from 'path';
import { createHash, createPrivateKey, createPublicKey, diffieHellman, randomBytes } from 'crypto';
import { Interface, Result } from 'ethers';
import memdown from 'memdown';
import { ABIRailgunSmartWallet } from '../src/abi/abi';
import { V2Events } from '../src/contracts/railgun-smart-wallet/V2/V2-events';
import { Commitment, CommitmentType } from '../src/models/formatted-types';
import { CommitmentEvent } from '../src/models/event-types';
import { TXIDVersion } from '../src/models/poi-types';
import { ChainType } from '../src/models/engine-types';
import { Database } from '../src/database/database';
import { RailgunWallet } from '../src/wallet/railgun-wallet';
import { Prover } from '../src/prover/prover';
import { Mnemonic } from '../src/key-derivation/bip39';
import { getSharedSymmetricKey } from '../src/utils/keys-utils';
import { AES } from '../src/utils/encryption/aes';
import { ByteUtils } from '../src/utils/bytes';
import {
  LeafPrefilter,
  clearFastScanCache,
  isTorsionFreePoint,
  setFastScanEnabled,
} from '../src/utils/fast-scan';

const SNAPSHOT_DIR = process.argv[2] ?? path.join(process.env.HOME as string, 'code/recovery/src/snapshots');
const CHAINS = process.argv.length > 3 ? process.argv.slice(3) : ['ethereum', 'arbitrum', 'base', 'bnb'];
const txidVersion = TXIDVersion.V2_PoseidonMerkle;
const poolInterface = new Interface(ABIRailgunSmartWallet);
const POOL_EVENTS = new Set(['Shield', 'Transact']);

type SnapshotLog = [number, number, string, string[], string];

const now = () => Number(process.hrtime.bigint()) / 1e6;
const time = async <T>(fn: () => Promise<T> | T): Promise<[T, number]> => {
  const start = now();
  const out = await fn();
  return [out, now() - start];
};
const fmt = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms.toFixed(1)} ms`);
const us = (ms: number, n: number) => (n ? `${((ms * 1000) / n).toFixed(2)} µs` : '-');

function recursivelyDecodeResult(result: unknown): unknown {
  if (typeof result !== 'object' || result === null) return result;
  const decoded = result as Result;
  try {
    const obj = decoded.toObject();
    if ('_' in obj) throw new Error('Decode as array');
    for (const key of Object.keys(obj)) obj[key] = recursivelyDecodeResult(obj[key]);
    return obj;
  } catch {
    return decoded.toArray().map((item) => recursivelyDecodeResult(item));
  }
}

/** Snapshot logs -> leaves per tree, positioned as in the merkle tree. */
export async function loadLeaves(file: string): Promise<{ trees: Commitment[][]; logs: number }> {
  const snapshot = JSON.parse(fs.readFileSync(file, 'utf8')) as { logs: SnapshotLog[] };
  const byName = new Map<string, unknown[]>();
  for (const [block, logIndex, transactionHash, topics, data] of snapshot.logs) {
    const parsed = poolInterface.parseLog({ topics, data });
    if (!parsed || !POOL_EVENTS.has(parsed.name)) continue;
    const list = byName.get(parsed.name) ?? [];
    list.push({ args: recursivelyDecodeResult(parsed.args), transactionHash, blockNumber: block, index: logIndex });
    byName.set(parsed.name, list);
  }
  const events: CommitmentEvent[] = [];
  const collect = async (_: TXIDVersion, e: CommitmentEvent[]) => void events.push(...e);
  await V2Events.processShieldEvents(txidVersion, collect, (byName.get('Shield') ?? []) as never);
  await V2Events.processTransactEvents(txidVersion, collect, (byName.get('Transact') ?? []) as never);

  const trees: Commitment[][] = [];
  for (const event of events) {
    const tree = (trees[event.treeNumber] ??= []);
    event.commitments.forEach((commitment, i) => {
      tree[event.startPosition + i] = commitment;
    });
  }
  return { trees, logs: snapshot.logs.length };
}

/** The (point, ciphertext) attempts the engine makes per leaf. */
export function attempts(leaf: Commitment) {
  if (leaf.commitmentType === CommitmentType.TransactCommitmentV2) {
    const { ciphertext } = leaf;
    const prepared = AES.prepareGCM({
      ...(ciphertext.ciphertext as { iv: string; tag: string; data: string[] }),
      data: [...(ciphertext.ciphertext as { data: string[] }).data, ByteUtils.strip0x(ciphertext.memo)],
    });
    return [ciphertext.blindedSenderViewingKey, ciphertext.blindedReceiverViewingKey].map((hex) => ({
      point: ByteUtils.hexStringToBytes(hex),
      prepared,
    }));
  }
  if (leaf.commitmentType === CommitmentType.ShieldCommitment) {
    const h0 = ByteUtils.hexlify(leaf.encryptedBundle[0]);
    const h1 = ByteUtils.hexlify(leaf.encryptedBundle[1]);
    return [
      {
        point: ByteUtils.hexToBytes(leaf.shieldKey),
        prepared: AES.prepareGCM({ iv: h0.slice(0, 32), tag: h0.slice(32, 64), data: [h1.slice(0, 32)] }),
      },
    ];
  }
  return [];
}

async function benchChain(name: string) {
  const file = path.join(SNAPSHOT_DIR, `${name}.json`);
  const [{ trees, logs }, decodeMs] = await time(() => loadLeaves(file));
  const leaves = trees.flat().filter(Boolean);
  const allAttempts = leaves.flatMap(attempts);
  const distinctPoints = new Set(allAttempts.map((a) => Buffer.from(a.point).toString('hex')));
  const byType = new Map<string, number>();
  for (const leaf of leaves) byType.set(leaf.commitmentType, (byType.get(leaf.commitmentType) ?? 0) + 1);

  console.log(`\n=== ${name} (${path.basename(file)}) ===`);
  console.log(`logs ${logs}, trees ${trees.length}, leaves ${leaves.length} [${[...byType].map(([t, n]) => `${t}:${n}`).join(', ')}]`);
  console.log(`DH attempts ${allAttempts.length}, distinct points ${distinctPoints.size}`);
  console.log(`decode snapshot -> commitments: ${fmt(decodeMs)}`);

  const vpk = randomBytes(32);

  // 1. Engine per-leaf path: WASM scalar mult + sha256 + AES-GCM for every attempt.
  const [, engineMs] = await time(async () => {
    for (const { point, prepared } of allAttempts) {
      // eslint-disable-next-line no-await-in-loop
      const key = await getSharedSymmetricKey(vpk, point);
      if (key && prepared) AES.gcmOpens(prepared, key);
    }
  });
  console.log(`engine path (WASM DH + sha256 + GCM per attempt): ${fmt(engineMs)}  (${us(engineMs, allAttempts.length)}/attempt)`);

  // 2. Parts of the prefilter, isolated.
  clearFastScanCache();
  const points = [...distinctPoints].map((h) => Buffer.from(h, 'hex'));
  const [, torsionMs] = await time(() => points.forEach((p) => isTorsionFreePoint(p)));
  console.log(`  torsion check (noble, cold, per distinct point): ${fmt(torsionMs)}  (${us(torsionMs, points.length)}/point)`);

  const head = createHash('sha512').update(vpk).digest().subarray(0, 32);
  const xPriv = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), head]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = Buffer.from('302a300506032b656e032100', 'hex');
  const [, x25519Ms] = await time(() => {
    for (const p of points) {
      const u = Buffer.from(p);
      u[31] &= 0x7f; // not the real Edwards->Montgomery map; same cost per DH
      try {
        diffieHellman({ privateKey: xPriv, publicKey: createPublicKey({ key: Buffer.concat([spki, u]), format: 'der', type: 'spki' }) });
      } catch {
        /* ignore */
      }
    }
  });
  console.log(`  X25519 (OpenSSL, per distinct point):          ${fmt(x25519Ms)}  (${us(x25519Ms, points.length)}/point)`);

  const key = randomBytes(32);
  const [, gcmMs] = await time(() => {
    for (const { prepared } of allAttempts) if (prepared) { AES.gcmOpens(prepared, key); AES.gcmOpens(prepared, key); }
  });
  console.log(`  AES-GCM attempts (2 candidate keys/attempt):  ${fmt(gcmMs)}  (${us(gcmMs, allAttempts.length * 2)}/try)`);

  // 3. The prefilter, end to end (cold = torsion cache empty, warm = cached).
  const prefilter = (await LeafPrefilter.create(vpk)) as LeafPrefilter;
  clearFastScanCache();
  const [, prefilterColdMs] = await time(async () => {
    for (const tree of trees) await prefilter.mightBeMine(tree);
  });
  const [flagsPerTree, prefilterWarmMs] = await time(async () =>
    Promise.all(trees.map((tree) => prefilter.mightBeMine(tree))),
  );
  const flagged = flagsPerTree.flat().filter(Boolean).length;
  console.log(`LeafPrefilter.mightBeMine, cold torsion cache:    ${fmt(prefilterColdMs)}`);
  console.log(`LeafPrefilter.mightBeMine, warm torsion cache:    ${fmt(prefilterWarmMs)}  (${us(prefilterWarmMs, leaves.length)}/leaf, flagged ${flagged})`);

  // 4. Full wallet.scanLeaves for an empty wallet, fast pass off vs on.
  for (const fast of [false, true]) {
    setFastScanEnabled(fast);
    clearFastScanCache();
    const db = new Database(memdown());
    const wallet = await RailgunWallet.fromMnemonic(
      db,
      ByteUtils.randomHex(32),
      Mnemonic.generate(),
      0,
      undefined,
      new Prover({} as never),
    );
    const chain = { type: ChainType.EVM, id: 1 };
    const [, scanMs] = await time(async () => {
      for (let t = 0; t < trees.length; t += 1) {
        await wallet.scanLeaves(txidVersion, trees[t] ?? [], t, chain, 0, undefined);
      }
    });
    console.log(`wallet.scanLeaves (empty wallet, fast=${fast}):     ${fmt(scanMs)}  (${us(scanMs, leaves.length)}/leaf)`);
  }
  setFastScanEnabled(true);
}

if (require.main === module) (async () => {
  console.log(`node ${process.version}, snapshots: ${SNAPSHOT_DIR}`);
  for (const chain of CHAINS) await benchChain(chain);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
