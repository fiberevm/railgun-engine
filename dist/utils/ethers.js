"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recursivelyDecodeResult = void 0;
const recursivelyDecodeResult = (result) => {
    if (typeof result !== 'object') {
        // End (primitive) value
        return result;
    }
    try {
        const obj = result.toObject();
        if ('_' in obj) {
            throw new Error('Decode as array, not object');
        }
        for (const key of Object.keys(obj)) {
            obj[key] = (0, exports.recursivelyDecodeResult)(obj[key]);
        }
        return obj;
    }
    catch (err) {
        // Result is array.
        return result.toArray().map((item) => (0, exports.recursivelyDecodeResult)(item));
    }
};
exports.recursivelyDecodeResult = recursivelyDecodeResult;
//# sourceMappingURL=ethers.js.map