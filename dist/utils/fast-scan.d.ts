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
import { Commitment } from '../models/formatted-types';
/** Turns the fast pass off (or back on), e.g. to compare scans in tests. */
export declare const setFastScanEnabled: (enabled: boolean) => void;
/** Turns the worker pool off (or back on); batches then run on the calling thread. */
export declare const setFastScanPoolEnabled: (enabled: boolean) => void;
/**
 * Whether an encoded Edwards point is canonical, not of small order, and in the prime-order
 * subgroup (libsodium's own test). False everywhere libsodium isn't available.
 */
export declare const isTorsionFreePoint: (point: Uint8Array) => boolean;
/**
 * Flags the leaves a wallet's viewing key might own. Created per scan, from the wallet's
 * viewing private key; undefined where libsodium isn't available.
 */
export declare class LeafPrefilter {
    private readonly lib;
    private readonly viewingPrivateKey;
    /** The engine's scalar (sha512 head, clamped, mod l), little-endian. */
    private readonly scalar;
    private constructor();
    static create(viewingPrivateKey: Uint8Array): Promise<Optional<LeafPrefilter>>;
    /** `flags[i]` is false only when leaf i certainly isn't this wallet's. */
    mightBeMine(leaves: Optional<Commitment>[]): Promise<boolean[]>;
    /** Leaf indices whose ciphertext opens with the key from the leaf's point. */
    private openInline;
    /**
     * openInline, with the distinct points (and the attempts that use them) split across the
     * pool. Points libsodium refuses come back and are checked inline by the engine's
     * multiplication, as are points that aren't plain 32-byte hex.
     */
    private openInPool;
    /** The key `getSharedSymmetricKey` gives for this point: sha256 of [scalar]point. */
    private sharedKey;
}
/**
 * Kept for callers of the previous fast pass, which cached a per-point torsion check.
 * libsodium checks the subgroup inside each multiplication, so there is nothing to warm.
 */
export declare const warmFastScanPoints: (_leaves: Optional<Commitment>[]) => void;
/** Kept for tests of the previous fast pass; there is no cache any more. */
export declare const clearFastScanCache: () => void;
