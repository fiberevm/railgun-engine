"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ShieldNoteERC20 = void 0;
const note_util_1 = require("../note-util");
const shield_note_1 = require("../shield-note");
class ShieldNoteERC20 extends shield_note_1.ShieldNote {
    constructor(masterPublicKey, random, value, tokenAddress) {
        const tokenData = (0, note_util_1.getTokenDataERC20)(tokenAddress);
        super(masterPublicKey, random, value, tokenData);
    }
}
exports.ShieldNoteERC20 = ShieldNoteERC20;
//# sourceMappingURL=shield-note-erc20.js.map