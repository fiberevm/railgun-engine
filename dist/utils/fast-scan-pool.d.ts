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
    attempts: {
        point: number;
        iv: Uint8Array;
        tag: Uint8Array;
        data: Uint8Array[];
    }[];
};
/** `opens[a]` is 1 when attempt a's ciphertext opens; `refused` lists points libsodium rejected. */
export type PoolResult = {
    opens: Uint8Array;
    refused: number[];
};
/** libsodium via `sodium-native`, an optional dependency. */
export declare const getSodium: () => Optional<Sodium>;
/** Long-lived worker threads shared by every scan in the process. */
export declare class ScanPool {
    private nextJobId;
    private nextWorker;
    private readonly workers;
    /** Jobs sent to workers so far (tests use it to check a batch really went to the pool). */
    get jobsRun(): number;
    get size(): number;
    static create(): Optional<ScanPool>;
    private spawn;
    run(job: PoolJob): Promise<PoolResult>;
}
/** The process's scan pool, created on first use; undefined where it can't run. */
export declare const getScanPool: () => Optional<ScanPool>;
