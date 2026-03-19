"use strict";
/**
 * CIRCUITS (V2)
 *
 * Valid, currently used:
 * All circuits with 1 - 10 inputs and 1 - 5 outputs, less the 10x5 circuit
 *
 * Valid, but currently unused:
 * 11x1, 12x1, 13x1
 * 1x10, 1x13
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.isValidNullifierCount = exports.MAX_INPUTS = exports.VALID_OUTPUT_COUNTS = exports.VALID_INPUT_COUNTS = void 0;
exports.VALID_INPUT_COUNTS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
exports.VALID_OUTPUT_COUNTS = [1, 2, 3, 4, 5];
exports.MAX_INPUTS = Math.max(...exports.VALID_INPUT_COUNTS);
const isValidNullifierCount = (utxoCount) => exports.VALID_INPUT_COUNTS.includes(utxoCount);
exports.isValidNullifierCount = isValidNullifierCount;
//# sourceMappingURL=nullifiers.js.map