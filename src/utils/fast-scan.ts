/**
 * A fast first pass over a wallet scan: which leaves could be addressed to this wallet?
 *
 * A cold wallet tries to decrypt every leaf in the tree. Nearly every attempt fails, and
 * each costs one or two curve25519 multiplications (the engine's WASM, ~100 µs) plus an
 * AES-GCM attempt that fails by throwing. This pass answers the same question faster, and
 * the scan then runs its usual, unchanged decryption on the leaves it flags:
 *
 * - Notes from one transaction share blinded keys, so each distinct point is multiplied once.
 * - Multiplications run in libsodium (`sodium-native`), ~3x faster than the WASM:
 *   `crypto_scalarmult_ed25519_noclamp` with the engine's own scalar computes exactly the
 *   engine's product. libsodium refuses points that aren't canonical, have small order or
 *   aren't in the prime-order subgroup; those (only crafted ones are) go through the
 *   engine's multiplication instead, so its result stands for every point.
 * - A failed AES-GCM attempt returns false rather than throwing.
 * - Large batches are split across a pool of worker threads (multiplications and AES-GCM
 *   attempts both run there); small batches, and any batch the pool fails, run inline.
 *
 * The pass only ever flags too much, never too little: a leaf type it doesn't handle is
 * always flagged, and a flagged leaf that isn't the wallet's is rejected by the full scan.
 * It runs only where `sodium-native` loads (Node); elsewhere scans run as before.
 */
import { Commitment, CommitmentType } from '../models/formatted-types';
import { ByteLength, ByteUtils } from './bytes';
import { AES, PreparedGCM } from './encryption/aes';
import { getScanPool, getSodium, PoolJob, ScanPool, Sodium } from './fast-scan-pool';
import { getPrivateScalarFromPrivateKey, getSharedSymmetricKey } from './keys-utils';

/** Attempts below which a batch runs inline: a round trip to the pool costs ~0.1-0.3 ms. */
const MIN_POOL_ATTEMPTS = 256;

let fastScanEnabled = true;

/** Turns the fast pass off (or back on), e.g. to compare scans in tests. */
export const setFastScanEnabled = (enabled: boolean): void => {
  fastScanEnabled = enabled;
};

let poolEnabled = true;

/** Turns the worker pool off (or back on); batches then run on the calling thread. */
export const setFastScanPoolEnabled = (enabled: boolean): void => {
  poolEnabled = enabled;
};

const HEX_POINT = /^[0-9a-f]{64}$/;

/**
 * Whether an encoded Edwards point is canonical, not of small order, and in the prime-order
 * subgroup (libsodium's own test). False everywhere libsodium isn't available.
 */
export const isTorsionFreePoint = (point: Uint8Array): boolean => {
  const lib = getSodium();
  return !!lib && point.length === 32 && lib.crypto_core_ed25519_is_valid_point(point);
};

type LeafCheck = {
  leafIndex: number;
  /** The point as lowercase hex without 0x, when it is exactly 32 bytes of hex. */
  key: Optional<string>;
  point: Uint8Array;
  ciphertext: PreparedGCM;
};

const pointCheck = (
  leafIndex: number,
  hex: string,
  toBytes: (hex: string) => Uint8Array,
  ciphertext: PreparedGCM,
): LeafCheck => {
  const stripped = ByteUtils.strip0x(hex).toLowerCase();
  if (HEX_POINT.test(stripped)) {
    return { leafIndex, key: stripped, point: Buffer.from(stripped, 'hex'), ciphertext };
  }
  // Anything unusual is decoded exactly as the engine does and takes the engine's path.
  return { leafIndex, key: undefined, point: toBytes(hex), ciphertext };
};

/**
 * The shared-key attempts the engine's decryption makes for one leaf (none when no key can
 * open its ciphertext), or undefined for any type it doesn't cover.
 */
const leafChecks = (leaf: Commitment, leafIndex: number): Optional<LeafCheck[]> => {
  switch (leaf.commitmentType) {
    case CommitmentType.TransactCommitmentV2: {
      const { ciphertext } = leaf;
      const noteCiphertext = ciphertext.ciphertext;
      if (!('tag' in noteCiphertext)) return undefined;
      // TransactNote.decrypt (V2) authenticates the memo with the note.
      const full = AES.prepareGCM({
        ...noteCiphertext,
        data: [...noteCiphertext.data, ByteUtils.strip0x(ciphertext.memo)],
      });
      if (!full) return [];
      return [ciphertext.blindedSenderViewingKey, ciphertext.blindedReceiverViewingKey].map(
        (blinded) => pointCheck(leafIndex, blinded, (hex) => ByteUtils.hexStringToBytes(hex), full),
      );
    }
    case CommitmentType.ShieldCommitment: {
      const { shieldKey, encryptedBundle } = leaf;
      // ShieldNote.decryptRandom's ciphertext.
      const hexlified0 = ByteUtils.hexlify(encryptedBundle[0]);
      const hexlified1 = ByteUtils.hexlify(encryptedBundle[1]);
      const random = AES.prepareGCM({
        iv: hexlified0.slice(0, 32),
        tag: hexlified0.slice(32, 64),
        data: [hexlified1.slice(0, 32)],
      });
      if (!random) return [];
      return [pointCheck(leafIndex, shieldKey, ByteUtils.hexToBytes, random)];
    }
    default:
      return undefined;
  }
};

/** Groups checks into at most `count` jobs of whole points, balanced by attempt count. */
const splitByPoint = (checks: LeafCheck[], count: number): LeafCheck[][][] => {
  const byPoint = new Map<string, LeafCheck[]>();
  for (const check of checks) {
    const group = byPoint.get(check.key as string);
    if (group) group.push(check);
    else byPoint.set(check.key as string, [check]);
  }
  const perJob = Math.ceil(checks.length / count);
  const jobs: LeafCheck[][][] = [];
  let current: LeafCheck[][] = [];
  let attempts = 0;
  for (const group of byPoint.values()) {
    current.push(group);
    attempts += group.length;
    if (attempts >= perJob) {
      jobs.push(current);
      current = [];
      attempts = 0;
    }
  }
  if (current.length) jobs.push(current);
  return jobs;
};

/**
 * Flags the leaves a wallet's viewing key might own. Created per scan, from the wallet's
 * viewing private key; undefined where libsodium isn't available.
 */
export class LeafPrefilter {
  private constructor(
    private readonly lib: Sodium,
    private readonly viewingPrivateKey: Uint8Array,
    /** The engine's scalar (sha512 head, clamped, mod l), little-endian. */
    private readonly scalar: Uint8Array,
  ) {}

  static async create(viewingPrivateKey: Uint8Array): Promise<Optional<LeafPrefilter>> {
    const lib = getSodium();
    if (!fastScanEnabled || !lib || viewingPrivateKey.length !== 32) return undefined;
    const scalar = await getPrivateScalarFromPrivateKey(viewingPrivateKey);
    const scalarLE = ByteUtils.nToBytes(scalar, ByteLength.UINT_256).reverse();
    return new LeafPrefilter(lib, viewingPrivateKey, scalarLE);
  }

  /** `flags[i]` is false only when leaf i certainly isn't this wallet's. */
  async mightBeMine(leaves: Optional<Commitment>[]): Promise<boolean[]> {
    const mine = new Set<number>();
    const checks: LeafCheck[] = [];
    for (let i = 0; i < leaves.length; i += 1) {
      const leaf = leaves[i];
      if (leaf != null) {
        const forLeaf = leafChecks(leaf, i);
        if (forLeaf) checks.push(...forLeaf);
        else mine.add(i);
      }
    }

    const scanPool =
      poolEnabled && checks.length >= MIN_POOL_ATTEMPTS ? getScanPool() : undefined;
    let pooled = false;
    if (scanPool) {
      try {
        const opened = await this.openInPool(scanPool, checks);
        opened.forEach((index) => mine.add(index));
        pooled = true;
      } catch {
        // A worker failed: the whole batch runs inline below.
      }
    }
    if (!pooled) {
      const opened = await this.openInline(checks, mine);
      opened.forEach((index) => mine.add(index));
    }
    return leaves.map((_, i) => mine.has(i));
  }

  /** Leaf indices whose ciphertext opens with the key from the leaf's point. */
  private async openInline(checks: LeafCheck[], skip: Set<number>): Promise<Set<number>> {
    const opened = new Set<number>();
    const sharedKeys = new Map<string, Optional<Uint8Array>>();
    const product = new Uint8Array(32);
    for (const check of checks) {
      if (skip.has(check.leafIndex) || opened.has(check.leafIndex)) continue;
      let sharedKey: Optional<Uint8Array>;
      if (check.key !== undefined && sharedKeys.has(check.key)) {
        sharedKey = sharedKeys.get(check.key);
      } else {
        // eslint-disable-next-line no-await-in-loop
        sharedKey = await this.sharedKey(check.point, product);
        if (check.key !== undefined) sharedKeys.set(check.key, sharedKey);
      }
      if (sharedKey && AES.gcmOpens(check.ciphertext, sharedKey)) opened.add(check.leafIndex);
    }
    return opened;
  }

  /**
   * openInline, with the distinct points (and the attempts that use them) split across the
   * pool. Points libsodium refuses come back and are checked inline by the engine's
   * multiplication, as are points that aren't plain 32-byte hex.
   */
  private async openInPool(scanPool: ScanPool, checks: LeafCheck[]): Promise<Set<number>> {
    const inline = checks.filter((check) => check.key === undefined);
    const jobs = splitByPoint(
      checks.filter((check) => check.key !== undefined),
      scanPool.size,
    );
    const results = await Promise.all(
      jobs.map((groups) => {
        const job: PoolJob = {
          scalar: this.scalar,
          points: new Uint8Array(groups.length * 32),
          attempts: [],
        };
        groups.forEach((group, point) => {
          job.points.set(group[0].point, point * 32);
          for (const { ciphertext } of group) job.attempts.push({ point, ...ciphertext });
        });
        return scanPool.run(job);
      }),
    );

    const opened = new Set<number>();
    results.forEach(({ opens, refused }, jobIndex) => {
      const groups = jobs[jobIndex];
      let attempt = 0;
      for (const group of groups) {
        for (const check of group) {
          if (opens[attempt]) opened.add(check.leafIndex);
          attempt += 1;
        }
      }
      for (const point of refused) inline.push(...groups[point]);
    });
    const openedInline = await this.openInline(inline, opened);
    openedInline.forEach((index) => opened.add(index));
    return opened;
  }

  /** The key `getSharedSymmetricKey` gives for this point: sha256 of [scalar]point. */
  private async sharedKey(point: Uint8Array, product: Uint8Array): Promise<Optional<Uint8Array>> {
    if (point.length === 32) {
      try {
        this.lib.crypto_scalarmult_ed25519_noclamp(product, this.scalar, point);
        const key = new Uint8Array(32);
        this.lib.crypto_hash_sha256(key, product);
        return key;
      } catch {
        // Refused (small order, torsion, non-canonical): the engine's multiplication decides.
      }
    }
    return getSharedSymmetricKey(this.viewingPrivateKey, point);
  }
}

/**
 * Kept for callers of the previous fast pass, which cached a per-point torsion check.
 * libsodium checks the subgroup inside each multiplication, so there is nothing to warm.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const warmFastScanPoints = (_leaves: Optional<Commitment>[]): void => {};

/** Kept for tests of the previous fast pass; there is no cache any more. */
export const clearFastScanCache = (): void => {};
