"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.keccak256 = exports.sha512HMAC = exports.sha512 = exports.sha256 = void 0;
const ethers_1 = require("ethers");
const bytes_1 = require("./bytes");
const bytesLikeify = (data) => {
    return new Uint8Array(bytes_1.ByteUtils.arrayify(data));
};
/**
 * Calculates sha256 hash of bytes
 * @returns hash
 */
function sha256(preImage) {
    // Hash and return
    return ethers_1.ethers.sha256(bytesLikeify(preImage)).slice(2);
}
exports.sha256 = sha256;
/**
 * Calculates sha512 hash of bytes
 * @param preImage - bytesdata
 * @returns hash
 */
function sha512(preImage) {
    return ethers_1.ethers.sha512(bytesLikeify(preImage)).slice(2);
}
exports.sha512 = sha512;
/**
 * Calculates sha512 hmac
 * @returns hmac
 */
function sha512HMAC(key, data) {
    return ethers_1.ethers.computeHmac('sha512', bytesLikeify(key), bytesLikeify(data)).slice(2);
}
exports.sha512HMAC = sha512HMAC;
/**
 * Calculates keccak256 hash of bytes
 * @returns hash
 */
function keccak256(preImage) {
    return ethers_1.ethers.keccak256(bytesLikeify(preImage)).slice(2);
}
exports.keccak256 = keccak256;
//# sourceMappingURL=hash.js.map