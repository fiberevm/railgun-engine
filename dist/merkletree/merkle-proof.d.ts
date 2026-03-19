import { MerkleProof } from '../models/formatted-types';
export declare const createDummyMerkleProof: (leaf: string) => MerkleProof;
/**
 * Verifies a merkle proof
 * @param proof - proof to verify
 * @returns is valid
 */
export declare const verifyMerkleProof: (proof: MerkleProof) => boolean;
