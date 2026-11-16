/**
 * Native pieces of the fast scan pass (see fast-scan.ts): libsodium, and a pool of worker
 * threads that run its multiplications and the AES-GCM attempts off the main thread.
 *
 * Both load only on Node, by computed `require` names so bundlers leave them out of browser
 * builds. Where they don't load, callers get undefined and scan without them.
 */
import type { Worker as NodeWorker } from 'worker_threads';
import { isNodejs, isReactNative } from './runtime';

export type Sodium = {
  crypto_scalarmult_ed25519_noclamp(q: Uint8Array, n: Uint8Array, p: Uint8Array): void;
  crypto_core_ed25519_is_valid_point(p: Uint8Array): boolean;
  crypto_hash_sha256(out: Uint8Array, data: Uint8Array): void;
};

/** Points (32 bytes each, concatenated) and the AES-GCM attempts made with each one's key. */
export type PoolJob = {
  /** The engine's viewing scalar, little-endian. */
  scalar: Uint8Array;
  points: Uint8Array;
  attempts: { point: number; iv: Uint8Array; tag: Uint8Array; data: Uint8Array[] }[];
};

/** `opens[a]` is 1 when attempt a's ciphertext opens; `refused` lists points libsodium rejected. */
export type PoolResult = { opens: Uint8Array; refused: number[] };

const SODIUM_MODULE = 'sodium-native';
/** Default pool size cap; RAILGUN_FAST_SCAN_THREADS overrides it (0 or 1 turns the pool off). */
const MAX_DEFAULT_THREADS = 8;

// eslint-disable-next-line global-require, import/no-dynamic-require, @typescript-eslint/no-var-requires
const requireNamed = (name: string): unknown => require(name);
const resolveNamed = (name: string): string => require.resolve(name);

const nodeOnly = () =>
  isNodejs && !isReactNative && process.env.RAILGUN_DISABLE_FAST_SCAN !== '1';

let sodium: Optional<Sodium> | null = null;

/** libsodium via `sodium-native`, an optional dependency. */
export const getSodium = (): Optional<Sodium> => {
  if (sodium !== null) return sodium;
  sodium = undefined;
  if (!nodeOnly()) return sodium;
  try {
    sodium = requireNamed(SODIUM_MODULE) as Sodium;
  } catch {
    // Not installed, or no native build for this platform.
  }
  return sodium;
};

/**
 * Worker body, run with `eval` so it needs no separate file in dist, ts-node or bundles.
 * Mirrors LeafPrefilter's libsodium key derivation and AES.gcmOpens exactly.
 */
const WORKER_SOURCE = `
const { parentPort, workerData } = require('worker_threads');
const { createDecipheriv } = require('crypto');
const sodium = require(workerData.sodiumPath);
const product = new Uint8Array(32);
parentPort.on('message', ({ id, scalar, points, attempts }) => {
  const count = points.length / 32;
  const keys = new Array(count);
  const refused = [];
  for (let i = 0; i < count; i += 1) {
    try {
      sodium.crypto_scalarmult_ed25519_noclamp(product, scalar, points.subarray(i * 32, i * 32 + 32));
      const key = new Uint8Array(32);
      sodium.crypto_hash_sha256(key, product);
      keys[i] = key;
    } catch {
      refused.push(i);
    }
  }
  const opens = new Uint8Array(attempts.length);
  for (let a = 0; a < attempts.length; a += 1) {
    const { point, iv, tag, data } = attempts[a];
    const key = keys[point];
    if (!key) continue;
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
      decipher.setAuthTag(tag);
      for (const block of data) decipher.update(block);
      decipher.final();
      opens[a] = 1;
    } catch {}
  }
  parentPort.postMessage({ id, opens, refused });
});
`;

type Pending = { resolve: (result: PoolResult) => void; reject: (error: Error) => void };
type PoolWorker = { worker: NodeWorker; pending: Map<number, Pending> };

/** Long-lived worker threads shared by every scan in the process. */
export class ScanPool {
  private nextJobId = 0;

  private nextWorker = 0;

  private readonly workers: PoolWorker[] = [];

  /** Jobs sent to workers so far (tests use it to check a batch really went to the pool). */
  get jobsRun(): number {
    return this.nextJobId;
  }

  get size(): number {
    return this.workers.length;
  }

  static create(): Optional<ScanPool> {
    if (!nodeOnly()) return undefined;
    try {
      const os = requireNamed('os') as typeof import('os');
      const { Worker } = requireNamed('worker_threads') as typeof import('worker_threads');
      const configured = Number(process.env.RAILGUN_FAST_SCAN_THREADS);
      const cores =
        typeof os.availableParallelism === 'function'
          ? os.availableParallelism()
          : os.cpus().length;
      const size =
        process.env.RAILGUN_FAST_SCAN_THREADS !== undefined && Number.isInteger(configured)
          ? configured
          : Math.min(cores - 1, MAX_DEFAULT_THREADS);
      if (size < 2) return undefined;
      const sodiumPath = resolveNamed(SODIUM_MODULE);
      const pool = new ScanPool();
      for (let i = 0; i < size; i += 1) pool.spawn(Worker, sodiumPath);
      return pool;
    } catch {
      return undefined;
    }
  }

  private spawn(Worker: typeof NodeWorker, sodiumPath: string): void {
    const worker = new Worker(WORKER_SOURCE, { eval: true, workerData: { sodiumPath } });
    // Idle workers never keep the process alive; a worker with jobs in flight does.
    worker.unref();
    const entry: PoolWorker = { worker, pending: new Map() };
    const fail = (error: Error) => {
      // A broken worker leaves the pool; its jobs reject and the caller runs them inline.
      const index = this.workers.indexOf(entry);
      if (index >= 0) this.workers.splice(index, 1);
      for (const { reject } of entry.pending.values()) reject(error);
      entry.pending.clear();
      worker.terminate().catch(() => undefined);
    };
    worker.on('message', ({ id, opens, refused }: { id: number } & PoolResult) => {
      const job = entry.pending.get(id);
      if (!job) return;
      entry.pending.delete(id);
      if (entry.pending.size === 0) worker.unref();
      job.resolve({ opens, refused });
    });
    // An unref() before the thread is online doesn't hold, so repeat it once it is.
    worker.on('online', () => {
      if (entry.pending.size === 0) worker.unref();
    });
    worker.on('error', fail);
    worker.on('exit', () => fail(new Error('fast-scan worker exited')));
    this.workers.push(entry);
  }

  run(job: PoolJob): Promise<PoolResult> {
    if (this.workers.length === 0) return Promise.reject(new Error('fast-scan pool is empty'));
    const entry = this.workers[this.nextWorker % this.workers.length];
    this.nextWorker += 1;
    const id = this.nextJobId;
    this.nextJobId += 1;
    return new Promise<PoolResult>((resolve, reject) => {
      entry.pending.set(id, { resolve, reject });
      entry.worker.ref();
      entry.worker.postMessage({ id, ...job });
    });
  }
}

let pool: Optional<ScanPool> | null = null;

/** The process's scan pool, created on first use; undefined where it can't run. */
export const getScanPool = (): Optional<ScanPool> => {
  if (pool === null) pool = getSodium() ? ScanPool.create() : undefined;
  return pool && pool.size > 0 ? pool : undefined;
};
