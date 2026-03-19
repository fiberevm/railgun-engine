"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashBoundParamsV3 = exports.hashBoundParamsV2 = void 0;
const ethers_1 = require("ethers");
const utils_1 = require("../utils");
const constants_1 = require("../utils/constants");
const hash_1 = require("../utils/hash");
const abiCoder = ethers_1.AbiCoder.defaultAbiCoder();
const hashBoundParamsV2 = (boundParams) => {
    const hashed = (0, hash_1.keccak256)(abiCoder.encode([
        'tuple(uint16 treeNumber, uint48 minGasPrice, uint8 unshield, uint64 chainID, address adaptContract, bytes32 adaptParams, tuple(bytes32[4] ciphertext, bytes32 blindedSenderViewingKey, bytes32 blindedReceiverViewingKey, bytes annotationData, bytes memo)[] commitmentCiphertext) boundParams',
    ], [boundParams]));
    return utils_1.ByteUtils.hexToBigInt(hashed) % constants_1.SNARK_PRIME;
};
exports.hashBoundParamsV2 = hashBoundParamsV2;
const hashBoundParamsV3 = (boundParams) => {
    const hashed = (0, hash_1.keccak256)(abiCoder.encode([
        'tuple(tuple(uint32 treeNumber, tuple(bytes ciphertext, bytes32 blindedSenderViewingKey, bytes32 blindedReceiverViewingKey)[] commitmentCiphertext) local, tuple(uint128 minGasPrice, uint128 chainID, bytes senderCiphertext, address to, bytes data) global)',
    ], [boundParams]));
    return utils_1.ByteUtils.hexToBigInt(hashed) % constants_1.SNARK_PRIME;
};
exports.hashBoundParamsV3 = hashBoundParamsV3;
//# sourceMappingURL=bound-params.js.map