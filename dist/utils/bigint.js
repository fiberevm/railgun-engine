"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stringToBigInt = exports.minBigInt = void 0;
const bytes_1 = require("./bytes");
const minBigInt = (a, b) => (a < b ? a : b);
exports.minBigInt = minBigInt;
const stringToBigInt = (str) => {
    const decimalPattern = /^[-+]?(\d+(\.\d*)?|\.\d+)$/;
    const isDecimalStr = decimalPattern.test(str);
    if (isDecimalStr) {
        return BigInt(str);
    }
    return bytes_1.ByteUtils.hexToBigInt(str);
};
exports.stringToBigInt = stringToBigInt;
//# sourceMappingURL=bigint.js.map