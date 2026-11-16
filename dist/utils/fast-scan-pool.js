"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getScanPool = exports.ScanPool = exports.getSodium = void 0;
const runtime_1 = require("./runtime");
const SODIUM_MODULE = 'sodium-native';
/** Default pool size cap; RAILGUN_FAST_SCAN_THREADS overrides it (0 or 1 turns the pool off). */
const MAX_DEFAULT_THREADS = 8;
// eslint-disable-next-line global-require, import/no-dynamic-require, @typescript-eslint/no-var-requires
const requireNamed = (name) => require(name);
const resolveNamed = (name) => require.resolve(name);
const nodeOnly = () => runtime_1.isNodejs && !runtime_1.isReactNative && process.env.RAILGUN_DISABLE_FAST_SCAN !== '1';
let sodium = null;
/** libsodium via `sodium-native`, an optional dependency. */
const getSodium = () => {
    if (sodium !== null)
        return sodium;
    sodium = undefined;
    if (!nodeOnly())
        return sodium;
    try {
        sodium = requireNamed(SODIUM_MODULE);
    }
    catch {
        // Not installed, or no native build for this platform.
    }
    return sodium;
};
exports.getSodium = getSodium;
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
/** Long-lived worker threads shared by every scan in the process. */
class ScanPool {
    nextJobId = 0;
    nextWorker = 0;
    workers = [];
    /** Jobs sent to workers so far (tests use it to check a batch really went to the pool). */
    get jobsRun() {
        return this.nextJobId;
    }
    get size() {
        return this.workers.length;
    }
    static create() {
        if (!nodeOnly())
            return undefined;
        try {
            const os = requireNamed('os');
            const { Worker } = requireNamed('worker_threads');
            const configured = Number(process.env.RAILGUN_FAST_SCAN_THREADS);
            const cores = typeof os.availableParallelism === 'function'
                ? os.availableParallelism()
                : os.cpus().length;
            const size = process.env.RAILGUN_FAST_SCAN_THREADS !== undefined && Number.isInteger(configured)
                ? configured
                : Math.min(cores - 1, MAX_DEFAULT_THREADS);
            if (size < 2)
                return undefined;
            const sodiumPath = resolveNamed(SODIUM_MODULE);
            const pool = new ScanPool();
            for (let i = 0; i < size; i += 1)
                pool.spawn(Worker, sodiumPath);
            return pool;
        }
        catch {
            return undefined;
        }
    }
    spawn(Worker, sodiumPath) {
        const worker = new Worker(WORKER_SOURCE, { eval: true, workerData: { sodiumPath } });
        // Idle workers never keep the process alive; a worker with jobs in flight does.
        worker.unref();
        const entry = { worker, pending: new Map() };
        const fail = (error) => {
            // A broken worker leaves the pool; its jobs reject and the caller runs them inline.
            const index = this.workers.indexOf(entry);
            if (index >= 0)
                this.workers.splice(index, 1);
            for (const { reject } of entry.pending.values())
                reject(error);
            entry.pending.clear();
            worker.terminate().catch(() => undefined);
        };
        worker.on('message', ({ id, opens, refused }) => {
            const job = entry.pending.get(id);
            if (!job)
                return;
            entry.pending.delete(id);
            if (entry.pending.size === 0)
                worker.unref();
            job.resolve({ opens, refused });
        });
        // An unref() before the thread is online doesn't hold, so repeat it once it is.
        worker.on('online', () => {
            if (entry.pending.size === 0)
                worker.unref();
        });
        worker.on('error', fail);
        worker.on('exit', () => fail(new Error('fast-scan worker exited')));
        this.workers.push(entry);
    }
    run(job) {
        if (this.workers.length === 0)
            return Promise.reject(new Error('fast-scan pool is empty'));
        const entry = this.workers[this.nextWorker % this.workers.length];
        this.nextWorker += 1;
        const id = this.nextJobId;
        this.nextJobId += 1;
        return new Promise((resolve, reject) => {
            entry.pending.set(id, { resolve, reject });
            entry.worker.ref();
            entry.worker.postMessage({ id, ...job });
        });
    }
}
exports.ScanPool = ScanPool;
let pool = null;
/** The process's scan pool, created on first use; undefined where it can't run. */
const getScanPool = () => {
    if (pool === null)
        pool = (0, exports.getSodium)() ? ScanPool.create() : undefined;
    return pool && pool.size > 0 ? pool : undefined;
};
exports.getScanPool = getScanPool;
//# sourceMappingURL=fast-scan-pool.js.map