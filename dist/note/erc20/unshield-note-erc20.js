"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnshieldNoteERC20 = void 0;
const constants_1 = require("../../utils/constants");
const note_util_1 = require("../note-util");
const unshield_note_1 = require("../unshield-note");
class UnshieldNoteERC20 extends unshield_note_1.UnshieldNote {
    constructor(toAddress, value, tokenAddress, allowOverride = false) {
        const tokenData = (0, note_util_1.getTokenDataERC20)(tokenAddress);
        super(toAddress, value, tokenData, allowOverride);
    }
    static empty() {
        const toAddress = constants_1.ZERO_ADDRESS;
        const value = BigInt(0);
        const tokenAddress = constants_1.ZERO_ADDRESS;
        const allowOverride = false;
        return new UnshieldNoteERC20(toAddress, value, tokenAddress, allowOverride);
    }
}
exports.UnshieldNoteERC20 = UnshieldNoteERC20;
//# sourceMappingURL=unshield-note-erc20.js.map