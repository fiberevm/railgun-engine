"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.calculateRailgunTransactionVerificationHash = exports.createRailgunTransactionWithHash = exports.getRailgunTxidLeafHash = exports.getRailgunTransactionIDHex = exports.getRailgunTransactionIDFromBigInts = exports.getRailgunTransactionID = void 0;
const poseidon_1 = require("../utils/poseidon");
const bytes_1 = require("../utils/bytes");
const merkletree_types_1 = require("../models/merkletree-types");
const global_tree_position_1 = require("../utils/global-tree-position");
const hash_1 = require("../utils/hash");
const padWithZerosToMax = (array, max) => {
    const padded = [...array];
    while (padded.length < max) {
        padded.push(merkletree_types_1.MERKLE_ZERO_VALUE_BIGINT);
    }
    return padded;
};
const getRailgunTransactionID = (railgunTransaction) => {
    const nullifierBigInts = railgunTransaction.nullifiers.map((el) => bytes_1.ByteUtils.hexToBigInt(el));
    const commitmentBigInts = railgunTransaction.commitments.map((el) => bytes_1.ByteUtils.hexToBigInt(el));
    const boundParamsHashBigInt = bytes_1.ByteUtils.hexToBigInt(railgunTransaction.boundParamsHash);
    return (0, exports.getRailgunTransactionIDFromBigInts)(nullifierBigInts, commitmentBigInts, boundParamsHashBigInt);
};
exports.getRailgunTransactionID = getRailgunTransactionID;
const getRailgunTransactionIDFromBigInts = (nullifiers, commitments, boundParamsHash) => {
    const maxInputs = 13; // Always 13 - no matter the POI circuit
    const nullifiersPadded = padWithZerosToMax(nullifiers, maxInputs);
    const nullifiersHash = (0, poseidon_1.poseidon)(nullifiersPadded);
    const maxOutputs = 13; // Always 13 - no matter the POI circuit
    const commitmentsPadded = padWithZerosToMax(commitments, maxOutputs);
    const commitmentsHash = (0, poseidon_1.poseidon)(commitmentsPadded);
    return (0, poseidon_1.poseidon)([nullifiersHash, commitmentsHash, boundParamsHash]);
};
exports.getRailgunTransactionIDFromBigInts = getRailgunTransactionIDFromBigInts;
const getRailgunTransactionIDHex = (railgunTransaction) => {
    const railgunTxid = (0, exports.getRailgunTransactionID)(railgunTransaction);
    return bytes_1.ByteUtils.nToHex(railgunTxid, bytes_1.ByteLength.UINT_256);
};
exports.getRailgunTransactionIDHex = getRailgunTransactionIDHex;
const getRailgunTxidLeafHash = (railgunTxidBigInt, utxoTreeIn, globalTreePosition) => {
    return bytes_1.ByteUtils.nToHex((0, poseidon_1.poseidon)([railgunTxidBigInt, utxoTreeIn, globalTreePosition]), bytes_1.ByteLength.UINT_256);
};
exports.getRailgunTxidLeafHash = getRailgunTxidLeafHash;
const createRailgunTransactionWithHash = (railgunTransaction) => {
    const railgunTxidBigInt = (0, exports.getRailgunTransactionID)(railgunTransaction);
    const { utxoTreeIn, utxoTreeOut, utxoBatchStartPositionOut } = railgunTransaction;
    const globalTreePosition = (0, global_tree_position_1.getGlobalTreePosition)(utxoTreeOut, utxoBatchStartPositionOut);
    return {
        ...railgunTransaction,
        railgunTxid: bytes_1.ByteUtils.nToHex(railgunTxidBigInt, bytes_1.ByteLength.UINT_256),
        hash: (0, exports.getRailgunTxidLeafHash)(railgunTxidBigInt, BigInt(utxoTreeIn), globalTreePosition),
    };
};
exports.createRailgunTransactionWithHash = createRailgunTransactionWithHash;
const calculateRailgunTransactionVerificationHash = (previousVerificationHash, firstNullifier) => {
    // hash[n] = keccak(hash[n-1] ?? 0, n_firstNullifier);
    const combinedData = bytes_1.ByteUtils.combine([
        bytes_1.ByteUtils.hexToBytes(previousVerificationHash ?? '0x'),
        bytes_1.ByteUtils.hexToBytes(firstNullifier),
    ]);
    return bytes_1.ByteUtils.formatToByteLength((0, hash_1.keccak256)(combinedData), bytes_1.ByteLength.UINT_256, true);
};
exports.calculateRailgunTransactionVerificationHash = calculateRailgunTransactionVerificationHash;
//# sourceMappingURL=railgun-txid.js.map