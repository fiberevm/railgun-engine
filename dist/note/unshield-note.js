"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnshieldNote = void 0;
const bytes_1 = require("../utils/bytes");
const note_util_1 = require("./note-util");
class UnshieldNote {
    toAddress;
    value;
    tokenData;
    hash;
    allowOverride;
    /**
     * Create Note object
     *
     * @param toAddress - address to unshield to
     * @param value - note value
     * @param tokenData
     */
    constructor(toAddress, value, tokenData, allowOverride) {
        (0, note_util_1.assertValidNoteToken)(tokenData, value);
        this.toAddress = toAddress;
        this.value = value;
        this.tokenData = tokenData;
        this.allowOverride = allowOverride;
        this.hash = (0, note_util_1.getNoteHash)(toAddress, tokenData, value);
    }
    get unshieldData() {
        return {
            toAddress: this.toAddress,
            value: this.value,
            tokenData: this.tokenData,
            allowOverride: this.allowOverride,
        };
    }
    get npk() {
        return this.toAddress;
    }
    get notePublicKey() {
        return BigInt(this.npk);
    }
    get hashHex() {
        return bytes_1.ByteUtils.nToHex(this.hash, bytes_1.ByteLength.UINT_256);
    }
    serialize(prefix = false) {
        return (0, note_util_1.serializePreImage)(this.toAddress, this.tokenData, this.value, prefix);
    }
    get preImage() {
        const { npk, tokenData, value } = this;
        return { npk, token: tokenData, value };
    }
    static getAmountFeeFromValue(value, feeBasisPoints) {
        const BASIS_POINTS = 10000n;
        const fee = (value * feeBasisPoints) / BASIS_POINTS;
        const amount = value - fee;
        return { amount, fee };
    }
}
exports.UnshieldNote = UnshieldNote;
//# sourceMappingURL=unshield-note.js.map