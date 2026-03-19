"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BlindedCommitment = void 0;
const poseidon_1 = require("./poseidon");
const bytes_1 = require("./bytes");
const formatHash = (hash) => {
    return `0x${bytes_1.ByteUtils.nToHex(hash, bytes_1.ByteLength.UINT_256)}`;
};
class BlindedCommitment {
    static getForUnshield(railgunTxid) {
        return bytes_1.ByteUtils.formatToByteLength(railgunTxid, bytes_1.ByteLength.UINT_256, true);
    }
    static getForShieldOrTransact(commitmentHash, npk, globalTreePosition) {
        const hash = (0, poseidon_1.poseidon)([bytes_1.ByteUtils.hexToBigInt(commitmentHash), npk, globalTreePosition]);
        return formatHash(hash);
    }
}
exports.BlindedCommitment = BlindedCommitment;
//# sourceMappingURL=blinded-commitment.js.map