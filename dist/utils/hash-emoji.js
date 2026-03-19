"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.emojiHash = void 0;
const crypto_1 = __importDefault(require("crypto"));
const emojis_json_1 = __importDefault(require("./emojis.json"));
const emojiHash = (str, length) => {
    return hashEmoji(str, length);
};
exports.emojiHash = emojiHash;
const hashEmoji = (string, hashLength = 1) => {
    const hash = crypto_1.default.createHash('sha256');
    hash.update(`${string}`);
    const hexHash = hash.digest('hex');
    const decimalHash = parseInt(hexHash, 16);
    let emojiIndex = decimalHash % emojis_json_1.default.length ** hashLength;
    let emojiString = '';
    for (let ii = 0; ii < hashLength; ii += 1) {
        emojiString = `${emojis_json_1.default[emojiIndex % emojis_json_1.default.length]}${emojiString}`;
        emojiIndex = Math.floor(emojiIndex / emojis_json_1.default.length);
    }
    return emojiString;
};
//# sourceMappingURL=hash-emoji.js.map