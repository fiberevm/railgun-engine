/**
 * A fast first pass over a wallet scan: which leaves could be addressed to this wallet?
 *
 * A cold wallet tries to decrypt every leaf in the tree. Nearly every attempt fails, and
 * each costs one or two curve25519 multiplications (the engine's WASM, ~110 µs) plus an
 * AES-GCM attempt that fails by throwing. This pass answers the same question faster, and
 * the scan then runs its usual, unchanged decryption on the leaves it flags:
 *
 * - Notes from one transaction share blinded keys, so each distinct point is multiplied once.
 * - Multiplications run in OpenSSL's X25519 (Node's `crypto`), ~6x faster than the WASM.
 *   X25519 multiplies by the clamped head of sha512(viewing key), which is the engine's
 *   scalar before its reduction mod l, so for a point in the prime-order subgroup the two
 *   agree. X25519 also clears a point's small-order component, which the engine's own
 *   multiplication keeps, so points that aren't torsion-free (only crafted ones are) go
 *   through the engine's multiplication instead. Torsion is a property of public chain
 *   data, so it is checked once per point per process and cached.
 * - X25519 works on Montgomery u, which drops the sign of Edwards x. Both encodings of the
 *   result are hashed into keys, and the AES-GCM tag accepts at most the right one.
 * - Field inversions for the Edwards/Montgomery conversions are batched: one per pass.
 * - A failed AES-GCM attempt returns false rather than throwing.
 *
 * The pass only ever flags too much, never too little: a leaf type it doesn't handle is
 * always flagged, and a flagged leaf that isn't the wallet's is rejected by the full scan.
 * It runs only where Node's crypto offers X25519; elsewhere scans run as before.
 */
import { CURVE, ExtendedPoint, Point } from '@noble/ed25519';
import type { KeyObject } from 'crypto';
import { Commitment, CommitmentType } from '../models/formatted-types';
import { ByteUtils } from './bytes';
import { AES, PreparedGCM } from './encryption/aes';
import { getSharedSymmetricKey } from './keys-utils';
import { isNodejs, isReactNative } from './runtime';

type NodeCrypto = Pick<
  typeof import('crypto'),
  'createHash' | 'createPrivateKey' | 'createPublicKey' | 'diffieHellman'
>;

const P = 2n ** 255n - 19n;
const Y_MASK = (1n << 255n) - 1n;
// DER prefixes for raw X25519 keys (RFC 8410).
const X25519_PKCS8_PREFIX = '302e020100300506032b656e04220420';
const X25519_SPKI_PREFIX = '302a300506032b656e032100';
// Points are public and few (thousands per chain); the bound only guards against misuse.
const TORSION_CACHE_LIMIT = 1_000_000;

const torsionFreeCache = new Map<string, boolean>();

let fastScanEnabled = true;

/** Turns the fast pass off (or back on), e.g. to compare scans in tests. */
export const setFastScanEnabled = (enabled: boolean): void => {
  fastScanEnabled = enabled;
};

let nodeCrypto: Optional<NodeCrypto> | null = null;

const getNodeCrypto = (): Optional<NodeCrypto> => {
  if (nodeCrypto !== null) return nodeCrypto;
  nodeCrypto = undefined;
  if (!isNodejs || isReactNative || process.env.RAILGUN_DISABLE_FAST_SCAN === '1') {
    return nodeCrypto;
  }
  try {
    // eslint-disable-next-line global-require, @typescript-eslint/no-var-requires
    const candidate = require('crypto') as NodeCrypto;
    const probe = candidate.createPrivateKey({
      key: Buffer.from(`${X25519_PKCS8_PREFIX}${'11'.repeat(32)}`, 'hex'),
      format: 'der',
      type: 'pkcs8',
    });
    if (probe.asymmetricKeyType === 'x25519') nodeCrypto = candidate;
  } catch {
    // No X25519 here (a browser shim, an old runtime): scans take the engine's path.
  }
  return nodeCrypto;
};

const leToBigInt = (bytes: Uint8Array): bigint =>
  BigInt(`0x${Buffer.from(bytes).reverse().toString('hex') || '0'}`);

const bigIntToLe32 = (value: bigint): Buffer =>
  Buffer.from(value.toString(16).padStart(64, '0'), 'hex').reverse();

const HEX_POINT = /^[0-9a-f]{64}$/;

const modPow = (base: bigint, exponent: bigint): bigint => {
  let result = 1n;
  let b = base % P;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
};

/** Inverts every (non-zero) value mod P with a single exponentiation. */
const batchInvert = (values: bigint[]): bigint[] => {
  const prefix = new Array<bigint>(values.length);
  let product = 1n;
  for (let i = 0; i < values.length; i += 1) {
    prefix[i] = product;
    product = (product * values[i]) % P;
  }
  let inverse = modPow(product, P - 2n);
  const out = new Array<bigint>(values.length);
  for (let i = values.length - 1; i >= 0; i -= 1) {
    out[i] = (inverse * prefix[i]) % P;
    inverse = (inverse * values[i]) % P;
  }
  return out;
};

const pointKey = (point: Uint8Array): string => Buffer.from(point).toString('hex');

/**
 * Whether an encoded Edwards point is valid and has no small-order component. Invalid and
 * non-canonical encodings count as not torsion-free, so they take the engine's own path.
 */
export const isTorsionFreePoint = (point: Uint8Array): boolean =>
  isTorsionFreeKey(pointKey(point), point);

const isTorsionFreeKey = (key: string, point: Uint8Array): boolean => {
  const cached = torsionFreeCache.get(key);
  if (cached !== undefined) return cached;
  let torsionFree = false;
  try {
    if (point.length === 32) {
      // [l]P = 0. Written as [l-1]P + P: some @noble/ed25519 1.7.x releases reject l itself
      // as a scalar, so their own isTorsionFree always throws.
      const extended = ExtendedPoint.fromAffine(Point.fromHex(point));
      torsionFree = extended
        .multiplyUnsafe(CURVE.l - 1n)
        .add(extended)
        .equals(ExtendedPoint.ZERO);
    }
  } catch {
    torsionFree = false;
  }
  if (torsionFreeCache.size >= TORSION_CACHE_LIMIT) torsionFreeCache.clear();
  torsionFreeCache.set(key, torsionFree);
  return torsionFree;
};

type LeafCheck = {
  leafIndex: number;
  /** The point as lowercase hex without 0x, when it is exactly 32 bytes of hex. */
  key: Optional<string>;
  point: Uint8Array;
  ciphertext: Optional<PreparedGCM>;
};

const pointCheck = (
  leafIndex: number,
  hex: string,
  toBytes: (hex: string) => Uint8Array,
  ciphertext: Optional<PreparedGCM>,
): LeafCheck => {
  const stripped = ByteUtils.strip0x(hex).toLowerCase();
  if (HEX_POINT.test(stripped)) {
    return { leafIndex, key: stripped, point: Buffer.from(stripped, 'hex'), ciphertext };
  }
  // Anything unusual is decoded exactly as the engine does and takes the engine's path.
  return { leafIndex, key: undefined, point: toBytes(hex), ciphertext };
};

/** The shared-key attempts the engine's decryption makes for one leaf, or undefined for any type it doesn't cover. */
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
      return [pointCheck(leafIndex, shieldKey, ByteUtils.hexToBytes, random)];
    }
    default:
      return undefined;
  }
};

/**
 * Flags the leaves a wallet's viewing key might own. Created per scan, from the wallet's
 * viewing private key; undefined where the runtime has no X25519.
 */
export class LeafPrefilter {
  private constructor(
    private readonly crypto: NodeCrypto,
    private readonly viewingPrivateKey: Uint8Array,
    private readonly xPrivateKey: KeyObject,
  ) {}

  static async create(viewingPrivateKey: Uint8Array): Promise<Optional<LeafPrefilter>> {
    const crypto = getNodeCrypto();
    if (!fastScanEnabled || !crypto || viewingPrivateKey.length !== 32) return undefined;
    // getPrivateScalarFromPrivateKey hashes the same way, then clamps and reduces mod l;
    // X25519 clamps the raw head itself.
    const head = crypto.createHash('sha512').update(viewingPrivateKey).digest().subarray(0, 32);
    const xPrivateKey = crypto.createPrivateKey({
      key: Buffer.concat([Buffer.from(X25519_PKCS8_PREFIX, 'hex'), head]),
      format: 'der',
      type: 'pkcs8',
    });
    return new LeafPrefilter(crypto, viewingPrivateKey, xPrivateKey);
  }

  /** `flags[i]` is false only when leaf i certainly isn't this wallet's. */
  async mightBeMine(leaves: Optional<Commitment>[]): Promise<boolean[]> {
    const flags = new Array<boolean>(leaves.length).fill(false);
    const fastChecks: LeafCheck[] = [];
    const engineChecks: LeafCheck[] = [];
    for (let i = 0; i < leaves.length; i += 1) {
      const leaf = leaves[i];
      if (leaf == null) continue;
      const checks = leafChecks(leaf, i);
      if (!checks) {
        flags[i] = true;
        continue;
      }
      for (const check of checks) {
        // A ciphertext no key opens can't make this leaf the wallet's.
        if (!check.ciphertext) continue;
        // y = 1 is the identity: 1 - y = 0 would poison the batched inversion. y >= P is a
        // non-canonical encoding. Both, like anything not torsion-free, take the engine's path.
        const y = check.key !== undefined ? leToBigInt(check.point) & Y_MASK : 0n;
        if (
          check.key !== undefined &&
          y !== 1n &&
          y < P &&
          isTorsionFreeKey(check.key, check.point)
        ) {
          fastChecks.push(check);
        } else {
          engineChecks.push(check);
        }
      }
    }

    // The engine's own multiplication, for the rare points X25519 can't stand in for.
    for (const check of engineChecks) {
      if (flags[check.leafIndex]) continue;
      // eslint-disable-next-line no-await-in-loop
      const sharedKey = await getSharedSymmetricKey(this.viewingPrivateKey, check.point);
      if (sharedKey && check.ciphertext && AES.gcmOpens(check.ciphertext, sharedKey)) {
        flags[check.leafIndex] = true;
      }
    }

    const keysByPoint = this.sharedKeyCandidates(fastChecks);
    for (const check of fastChecks) {
      if (flags[check.leafIndex] || !check.ciphertext) continue;
      const candidates = keysByPoint.get(check.key as string);
      if (!candidates) {
        // X25519 refused this point: fall back to the engine's multiplication.
        // eslint-disable-next-line no-await-in-loop
        const sharedKey = await getSharedSymmetricKey(this.viewingPrivateKey, check.point);
        if (sharedKey && AES.gcmOpens(check.ciphertext, sharedKey)) flags[check.leafIndex] = true;
        continue;
      }
      const { ciphertext } = check;
      if (candidates.some((key) => AES.gcmOpens(ciphertext, key))) {
        flags[check.leafIndex] = true;
      }
    }
    return flags;
  }

  /**
   * For each distinct torsion-free point, the two keys `getSharedSymmetricKey` could give:
   * sha256 of the product's encoding with either sign of x.
   */
  private sharedKeyCandidates(checks: LeafCheck[]): Map<string, [Uint8Array, Uint8Array]> {
    const distinct = new Map<string, bigint>();
    for (const { key, point } of checks) {
      if (key !== undefined && !distinct.has(key)) distinct.set(key, leToBigInt(point) & Y_MASK);
    }
    const keys = [...distinct.keys()];
    const ys = [...distinct.values()];

    // Edwards y -> Montgomery u = (1 + y) / (1 - y).
    const inverseOneMinusY = batchInvert(ys.map((y) => (1n - y + P) % P));
    const products = new Array<Optional<bigint>>(ys.length);
    for (let i = 0; i < ys.length; i += 1) {
      const u = ((1n + ys[i]) * inverseOneMinusY[i]) % P;
      try {
        const publicKey = this.crypto.createPublicKey({
          key: Buffer.concat([Buffer.from(X25519_SPKI_PREFIX, 'hex'), bigIntToLe32(u)]),
          format: 'der',
          type: 'spki',
        });
        products[i] = leToBigInt(
          this.crypto.diffieHellman({ privateKey: this.xPrivateKey, publicKey }),
        );
      } catch {
        // OpenSSL rejects an all-zero result; the caller falls back for this point.
        products[i] = undefined;
      }
    }

    // Montgomery u' -> Edwards y' = (u' - 1) / (u' + 1). u' = -1 has no Edwards image.
    const usable = products.map((u) => u !== undefined && (u + 1n) % P !== 0n);
    const inverseUPlusOne = batchInvert(
      products.map((u, i) => (usable[i] ? ((u as bigint) + 1n) % P : 1n)),
    );
    const out = new Map<string, [Uint8Array, Uint8Array]>();
    for (let i = 0; i < keys.length; i += 1) {
      if (!usable[i]) continue;
      const u = products[i] as bigint;
      const y = (((u - 1n + P) % P) * inverseUPlusOne[i]) % P;
      const even = bigIntToLe32(y);
      const odd = Buffer.from(even);
      odd[31] |= 0x80;
      out.set(keys[i], [
        new Uint8Array(this.crypto.createHash('sha256').update(even).digest()),
        new Uint8Array(this.crypto.createHash('sha256').update(odd).digest()),
      ]);
    }
    return out;
  }
}

/**
 * Runs the torsion check for every point in these leaves ahead of a scan, so the first
 * cold wallet after a restart doesn't pay for it. Safe to call repeatedly.
 */
export const warmFastScanPoints = (leaves: Optional<Commitment>[]): void => {
  for (let i = 0; i < leaves.length; i += 1) {
    const leaf = leaves[i];
    if (leaf == null) continue;
    for (const check of leafChecks(leaf, i) ?? []) {
      if (check.key !== undefined) isTorsionFreeKey(check.key, check.point);
    }
  }
};

/** Test hook: forget cached torsion results. */
export const clearFastScanCache = (): void => torsionFreeCache.clear();
