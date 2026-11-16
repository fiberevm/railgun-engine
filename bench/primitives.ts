// Times candidate primitives for the scan's per-point and per-attempt work on real pool points.
import path from 'path';
import { createDecipheriv, createHash, randomBytes } from 'crypto';
import { loadLeaves, attempts } from './scan-bench';
import { getPrivateScalarFromPrivateKey, getSharedSymmetricKey } from '../src/utils/keys-utils';
import { scalarMultiplyWasmFallbackToJavascript, initCurve25519Promise } from '../src/utils/scalar-multiply';
import { ByteUtils } from '../src/utils/bytes';
import { AES } from '../src/utils/encryption/aes';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const sodium = require(process.env.SODIUM ?? 'sodium-native');
const now = () => Number(process.hrtime.bigint()) / 1e6;
const bench = (label: string, n: number, fn: () => void) => {
  fn(); // warm
  const t = now(); fn(); const ms = now() - t;
  console.log(`${label.padEnd(48)} ${ms.toFixed(1).padStart(8)} ms  ${((ms * 1000) / n).toFixed(2).padStart(7)} µs/op`);
};

(async () => {
  await initCurve25519Promise;
  const { trees } = await loadLeaves(path.join(process.env.HOME as string, 'code/recovery/src/snapshots/base.json'));
  const all = trees.flat().filter(Boolean).flatMap(attempts);
  const points = [...new Set(all.map((a) => Buffer.from(a.point).toString('hex')))].map((h) => Buffer.from(h, 'hex'));
  const vpk = randomBytes(32);
  const scalar = await getPrivateScalarFromPrivateKey(vpk);
  const scalarLE = Buffer.from(ByteUtils.nToBytes(scalar, 32)).reverse();
  console.log(`${points.length} points, ${all.length} attempts`);

  bench('engine WASM scalarMultiply', points.length, () => points.forEach((p) => scalarMultiplyWasmFallbackToJavascript(p, scalar)));
  const out = Buffer.alloc(32);
  bench('sodium is_valid_point (subgroup check)', points.length, () => points.forEach((p) => sodium.crypto_core_ed25519_is_valid_point(p)));
  bench('sodium scalarmult_ed25519_noclamp', points.length, () => points.forEach((p) => { try { sodium.crypto_scalarmult_ed25519_noclamp(out, scalarLE, p); } catch {} }));
  const u = Buffer.alloc(32);
  bench('sodium ed25519_pk_to_curve25519', points.length, () => points.forEach((p) => { try { sodium.crypto_sign_ed25519_pk_to_curve25519(u, p); } catch {} }));
  const clamped = createHash('sha512').update(vpk).digest().subarray(0, 32);
  bench('sodium X25519 crypto_scalarmult', points.length, () => points.forEach((p) => { try { sodium.crypto_sign_ed25519_pk_to_curve25519(u, p); sodium.crypto_scalarmult(out, clamped, u); } catch {} }));
  bench('sha256 (node)', points.length, () => points.forEach((p) => createHash('sha256').update(p).digest()));
  const h = Buffer.alloc(32);
  bench('sha256 (sodium)', points.length, () => points.forEach((p) => sodium.crypto_hash_sha256(h, p)));

  // Exactness: sodium noclamp vs engine on every point.
  let same = 0; let rejected = 0; let differ = 0;
  for (const p of points) {
    const engine = Buffer.from(scalarMultiplyWasmFallbackToJavascript(p, scalar));
    try { sodium.crypto_scalarmult_ed25519_noclamp(out, scalarLE, p); } catch { rejected += 1; continue; }
    if (engine.equals(out)) same += 1; else differ += 1;
  }
  console.log(`noclamp vs engine: same ${same}, rejected ${rejected}, differ ${differ}`);
  const k = await getSharedSymmetricKey(vpk, points[0]);
  console.log(`sha256(noclamp) == getSharedSymmetricKey: ${createHash('sha256').update((sodium.crypto_scalarmult_ed25519_noclamp(out, scalarLE, points[0]), out)).digest().equals(Buffer.from(k as Uint8Array))}`);

  const key = randomBytes(32);
  const prepared = all.map((a) => a.prepared).filter(Boolean) as NonNullable<(typeof all)[0]['prepared']>[];
  bench('AES.gcmOpens (createDecipheriv, fails)', prepared.length, () => prepared.forEach((c) => AES.gcmOpens(c, key)));
  bench('createDecipheriv only', prepared.length, () => prepared.forEach((c) => createDecipheriv('aes-256-gcm', key, c.iv, { authTagLength: 16 })));
})();
