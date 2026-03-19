"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stringifySafe = void 0;
/**
 * JSON.stringify does not handle bigint values out-of-the-box.
 * This handler will safely stringify bigints into decimal strings.
 */
const stringifySafe = (obj) => {
    return JSON.stringify(obj, (key, value) => typeof value === 'bigint' ? value.toString(10) : value);
};
exports.stringifySafe = stringifySafe;
//# sourceMappingURL=stringify.js.map