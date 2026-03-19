"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getMasterKeyFromSeed = exports.childKeyDerivationHardened = exports.getPathSegments = void 0;
const bytes_1 = require("../utils/bytes");
const hash_1 = require("../utils/hash");
const CURVE_SEED = (0, bytes_1.fromUTF8String)('babyjubjub seed');
/**
 * Tests derivation path to see if it's valid
 * @param path - bath to test
 * @returns valid
 */
function isValidPath(path) {
    return /^m(\/[0-9]+')+$/g.test(path);
}
/**
 * Converts path string into segments
 * @param path - path string to parse
 * @returns array of indexes
 */
function getPathSegments(path) {
    // Throw if path is invalid
    if (!isValidPath(path))
        throw new Error('Invalid derivation path');
    // Split along '/' to get each component
    // Remove the first segment as it is the 'm'
    // Remove the ' from each segment
    // Parse each segment into an integer
    return path
        .split('/')
        .slice(1)
        .map((val) => val.replace("'", ''))
        .map((el) => parseInt(el, 10));
}
exports.getPathSegments = getPathSegments;
/**
 * Derive child KeyNode from KeyNode via hardened derivation
 * @param node - KeyNode to derive from
 * @param index - index of child
 */
function childKeyDerivationHardened(node, index, offset = 0x80000000) {
    // Convert index to bytes as 32bit big endian
    const indexFormatted = bytes_1.ByteUtils.padToLength(index + offset, 4);
    // Calculate HMAC preImage
    const preImage = `00${node.chainKey}${indexFormatted}`;
    // Calculate I
    const I = (0, hash_1.sha512HMAC)(node.chainCode, preImage);
    // Slice 32 bytes for IL and IR values, IL = key, IR = chainCode
    const chainKey = I.slice(0, 64);
    const chainCode = I.slice(64);
    // Return node
    return {
        chainKey,
        chainCode,
    };
}
exports.childKeyDerivationHardened = childKeyDerivationHardened;
/**
 * Creates KeyNode from seed
 * @param seed - bip32 seed
 * @returns BjjNode - babyjubjub BIP32Node
 */
function getMasterKeyFromSeed(seed) {
    // HMAC with seed to get I
    const I = (0, hash_1.sha512HMAC)(CURVE_SEED, seed);
    // Slice 32 bytes for IL and IR values, IL = key, IR = chainCode
    const chainKey = I.slice(0, 64);
    const chainCode = I.slice(64);
    // Return node
    return {
        chainKey,
        chainCode,
    };
}
exports.getMasterKeyFromSeed = getMasterKeyFromSeed;
//# sourceMappingURL=bip32.js.map