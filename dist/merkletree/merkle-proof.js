"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyMerkleProof = exports.createDummyMerkleProof = void 0;
const poseidon_1 = require("../utils/poseidon");
const merkletree_types_1 = require("../models/merkletree-types");
const bytes_1 = require("../utils/bytes");
const merkletree_1 = require("./merkletree");
const createDummyMerkleProof = (leaf) => {
    const indices = bytes_1.ByteUtils.nToHex(0n, bytes_1.ByteLength.UINT_256);
    // Fill with 0n dummy value
    const elements = new Array(merkletree_types_1.TREE_DEPTH).fill(0n);
    let latestHash = bytes_1.ByteUtils.hexToBigInt(leaf);
    for (const element of elements) {
        latestHash = (0, poseidon_1.poseidon)([latestHash, element]);
    }
    return {
        leaf,
        indices,
        elements: elements.map((el) => bytes_1.ByteUtils.nToHex(el, bytes_1.ByteLength.UINT_256)),
        root: bytes_1.ByteUtils.nToHex(latestHash, bytes_1.ByteLength.UINT_256),
    };
};
exports.createDummyMerkleProof = createDummyMerkleProof;
/**
 * Verifies a merkle proof
 * @param proof - proof to verify
 * @returns is valid
 */
const verifyMerkleProof = (proof) => {
    // Get indices as BN form
    const indices = bytes_1.ByteUtils.hexToBigInt(proof.indices);
    // Calculate proof root and return if it matches the proof in the MerkleProof
    // Loop through each element and hash till we've reduced to 1 element
    const calculatedRoot = proof.elements.reduce((current, element, index) => {
        // If index is right
        if ((indices & (2n ** BigInt(index))) > 0n) {
            return merkletree_1.Merkletree.hashLeftRight(element, current);
        }
        // If index is left
        return merkletree_1.Merkletree.hashLeftRight(current, element);
    }, proof.leaf);
    const valid = bytes_1.ByteUtils.hexlify(proof.root) === bytes_1.ByteUtils.hexlify(calculatedRoot);
    return valid;
};
exports.verifyMerkleProof = verifyMerkleProof;
//# sourceMappingURL=merkle-proof.js.map