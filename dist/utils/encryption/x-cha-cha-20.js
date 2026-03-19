"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XChaCha20 = void 0;
const chacha_1 = require("@noble/ciphers/chacha");
const sha256_1 = require("@noble/hashes/sha256");
const bytes_1 = require("../bytes");
const formatted_types_1 = require("../../models/formatted-types");
class XChaCha20 {
    static getRandomIV() {
        const random = bytes_1.ByteUtils.randomHex(16);
        if (random.length !== 32) {
            throw new Error('Incorrect nonce length');
        }
        return random;
    }
    static encryptChaCha20(plaintext, key) {
        const nonce = this.getRandomIV();
        const nonceExtended = (0, sha256_1.sha256)(nonce).slice(0, 24);
        const plaintextFormatted = bytes_1.ByteUtils.fastHexToBytes(plaintext);
        const bundleBytes = (0, chacha_1.xchacha20)(key, nonceExtended, plaintextFormatted);
        const bundle = bytes_1.ByteUtils.fastBytesToHex(bundleBytes);
        return {
            algorithm: formatted_types_1.XChaChaEncryptionAlgorithm.XChaCha,
            nonce,
            bundle,
        };
    }
    static decryptChaCha20(ciphertext, key) {
        if (ciphertext.algorithm !== formatted_types_1.XChaChaEncryptionAlgorithm.XChaCha) {
            throw new Error(`Invalid ciphertext for XChaCha: ${ciphertext.algorithm}`);
        }
        const nonceExtended = (0, sha256_1.sha256)(ciphertext.nonce).slice(0, 24);
        const bytes = (0, chacha_1.xchacha20)(key, nonceExtended, bytes_1.ByteUtils.fastHexToBytes(ciphertext.bundle));
        const plaintext = bytes_1.ByteUtils.fastBytesToHex(bytes);
        return plaintext;
    }
    static encryptChaCha20Poly1305(plaintext, key) {
        const nonce = this.getRandomIV();
        const nonceExtended = (0, sha256_1.sha256)(nonce).slice(0, 24);
        const encrypter = (0, chacha_1.xchacha20poly1305)(key, nonceExtended);
        const plaintextFormatted = bytes_1.ByteUtils.fastHexToBytes(plaintext);
        const bundleBytes = encrypter.encrypt(plaintextFormatted);
        const bundle = bytes_1.ByteUtils.fastBytesToHex(bundleBytes);
        return {
            algorithm: formatted_types_1.XChaChaEncryptionAlgorithm.XChaChaPoly1305,
            nonce,
            bundle,
        };
    }
    static decryptChaCha20Poly1305(ciphertext, key) {
        if (ciphertext.algorithm !== formatted_types_1.XChaChaEncryptionAlgorithm.XChaChaPoly1305) {
            throw new Error(`Invalid ciphertext for XChaChaPoly1305: ${ciphertext.algorithm}`);
        }
        const nonceExtended = (0, sha256_1.sha256)(ciphertext.nonce).slice(0, 24);
        const encrypter = (0, chacha_1.xchacha20poly1305)(key, nonceExtended);
        const bundleFormatted = bytes_1.ByteUtils.fastHexToBytes(ciphertext.bundle);
        const plaintext = bytes_1.ByteUtils.fastBytesToHex(encrypter.decrypt(bundleFormatted));
        return plaintext;
    }
}
exports.XChaCha20 = XChaCha20;
//# sourceMappingURL=x-cha-cha-20.js.map