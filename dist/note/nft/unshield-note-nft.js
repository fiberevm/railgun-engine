"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnshieldNoteNFT = void 0;
const note_util_1 = require("../note-util");
const unshield_note_1 = require("../unshield-note");
class UnshieldNoteNFT extends unshield_note_1.UnshieldNote {
    constructor(toAddress, tokenData, allowOverride = false) {
        super(toAddress, note_util_1.ERC721_NOTE_VALUE, tokenData, allowOverride);
    }
}
exports.UnshieldNoteNFT = UnshieldNoteNFT;
//# sourceMappingURL=unshield-note-nft.js.map