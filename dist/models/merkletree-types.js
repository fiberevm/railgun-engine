"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MERKLE_ZERO_VALUE = exports.MERKLE_ZERO_VALUE_BIGINT = exports.CommitmentProcessingGroupSize = exports.TREE_MAX_ITEMS = exports.TREE_DEPTH = void 0;
const bytes_1 = require("../utils/bytes");
const constants_1 = require("../utils/constants");
const hash_1 = require("../utils/hash");
exports.TREE_DEPTH = 16;
exports.TREE_MAX_ITEMS = 65_536; // 2^16
// Optimization: process leaves for a many commitment groups before checking merkleroot against contract.
// If merkleroot is invalid, scan leaves as medium batches, and individually as a final backup.
// For Txid merkletree on POI Nodes, re-calculate for every Single tree update, in order to capture its merkleroot.
var CommitmentProcessingGroupSize;
(function (CommitmentProcessingGroupSize) {
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["XXXXLarge"] = 10000] = "XXXXLarge";
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["XXXLarge"] = 8000] = "XXXLarge";
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["XXLarge"] = 1600] = "XXLarge";
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["XLarge"] = 800] = "XLarge";
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["Large"] = 200] = "Large";
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["Medium"] = 40] = "Medium";
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["Small"] = 10] = "Small";
    CommitmentProcessingGroupSize[CommitmentProcessingGroupSize["Single"] = 1] = "Single";
})(CommitmentProcessingGroupSize || (exports.CommitmentProcessingGroupSize = CommitmentProcessingGroupSize = {}));
// Calculate tree zero value
exports.MERKLE_ZERO_VALUE_BIGINT = bytes_1.ByteUtils.hexToBigInt((0, hash_1.keccak256)((0, bytes_1.fromUTF8String)('Railgun'))) % constants_1.SNARK_PRIME;
exports.MERKLE_ZERO_VALUE = bytes_1.ByteUtils.nToHex(exports.MERKLE_ZERO_VALUE_BIGINT, bytes_1.ByteLength.UINT_256);
//# sourceMappingURL=merkletree-types.js.map