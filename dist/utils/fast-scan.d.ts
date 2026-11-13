import { Commitment } from '../models/formatted-types';
/** Turns the fast pass off (or back on), e.g. to compare scans in tests. */
export declare const setFastScanEnabled: (enabled: boolean) => void;
/**
 * Whether an encoded Edwards point is valid and has no small-order component. Invalid and
 * non-canonical encodings count as not torsion-free, so they take the engine's own path.
 */
export declare const isTorsionFreePoint: (point: Uint8Array) => boolean;
/**
 * Flags the leaves a wallet's viewing key might own. Created per scan, from the wallet's
 * viewing private key; undefined where the runtime has no X25519.
 */
export declare class LeafPrefilter {
    private readonly crypto;
    private readonly viewingPrivateKey;
    private readonly xPrivateKey;
    private constructor();
    static create(viewingPrivateKey: Uint8Array): Promise<Optional<LeafPrefilter>>;
    /** `flags[i]` is false only when leaf i certainly isn't this wallet's. */
    mightBeMine(leaves: Optional<Commitment>[]): Promise<boolean[]>;
    /**
     * For each distinct torsion-free point, the two keys `getSharedSymmetricKey` could give:
     * sha256 of the product's encoding with either sign of x.
     */
    private sharedKeyCandidates;
}
/**
 * Runs the torsion check for every point in these leaves ahead of a scan, so the first
 * cold wallet after a restart doesn't pay for it. Safe to call repeatedly.
 */
export declare const warmFastScanPoints: (leaves: Optional<Commitment>[]) => void;
/** Test hook: forget cached torsion results. */
export declare const clearFastScanCache: () => void;
