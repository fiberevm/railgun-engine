"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AES = void 0;
const bytes_1 = require("../bytes");
const runtime_1 = require("../runtime");
const { createCipheriv, createDecipheriv } = runtime_1.isNodejs
    ? // eslint-disable-next-line global-require, @typescript-eslint/no-var-requires
        require('crypto')
    : // eslint-disable-next-line global-require, @typescript-eslint/no-var-requires
        require('browserify-aes/browser');
class AES {
    static getRandomIV() {
        return bytes_1.ByteUtils.randomHex(16);
    }
    /**
     * Encrypt blocks of data with AES-256-GCM
     * @param plaintext - plaintext to encrypt
     * @param key - key to encrypt with
     * @returns ciphertext bundle
     */
    static encryptGCM(plaintext, key) {
        // If types are strings, convert to bytes array
        const keyFormatted = typeof key === 'string' ? bytes_1.ByteUtils.fastHexToBytes(key) : key;
        if (keyFormatted.byteLength !== 32) {
            throw new Error(`Invalid key length. Expected 32 bytes. Received ${keyFormatted.byteLength} bytes.`);
        }
        const iv = AES.getRandomIV();
        const ivFormatted = bytes_1.ByteUtils.fastHexToBytes(iv);
        // Initialize cipher
        const cipher = createCipheriv('aes-256-gcm', keyFormatted, ivFormatted, {
            authTagLength: 16,
        });
        // Loop through data blocks and encrypt
        const data = new Array(plaintext.length);
        for (let i = 0; i < plaintext.length; i += 1) {
            data[i] = bytes_1.ByteUtils.fastBytesToHex(cipher.update(bytes_1.ByteUtils.fastHexToBytes(bytes_1.ByteUtils.strip0x(plaintext[i]))));
        }
        cipher.final();
        const tag = cipher.getAuthTag();
        const tagFormatted = new Uint8Array(bytes_1.ByteUtils.arrayify(tag));
        // Return encrypted data bundle
        return {
            iv: bytes_1.ByteUtils.formatToByteLength(ivFormatted, bytes_1.ByteLength.UINT_128, false),
            tag: bytes_1.ByteUtils.formatToByteLength(tagFormatted, bytes_1.ByteLength.UINT_128, false),
            data,
        };
    }
    /**
     * Decrypts AES-256-GCM encrypted data
     * On failure, it throws `Unsupported state or unable to authenticate data`
     * @param ciphertext - ciphertext bundle to decrypt
     * @param key - key to decrypt with
     * @returns - plaintext
     */
    static decryptGCM(ciphertext, key) {
        try {
            // Ensure that inputs are Uint8Arrays of the correct length
            const keyFormatted = typeof key === 'string'
                ? bytes_1.ByteUtils.fastHexToBytes(bytes_1.ByteUtils.padToLength(key, 32))
                : key;
            if (keyFormatted.byteLength !== 32) {
                throw new Error(`Invalid key length. Expected 32 bytes. Received ${keyFormatted.byteLength} bytes.`);
            }
            const ivFormatted = bytes_1.ByteUtils.fastHexToBytes(bytes_1.ByteUtils.trim(ciphertext.iv, 16));
            const tagFormatted = bytes_1.ByteUtils.fastHexToBytes(bytes_1.ByteUtils.trim(ciphertext.tag, 16));
            if (ivFormatted.byteLength !== 16) {
                throw new Error(`Invalid iv length. Expected 16 bytes. Received ${ivFormatted.byteLength} bytes.`);
            }
            if (tagFormatted.byteLength !== 16) {
                throw new Error(`Invalid tag length. Expected 16 bytes. Received ${tagFormatted.byteLength} bytes.`);
            }
            // Initialize decipher
            const decipher = createDecipheriv('aes-256-gcm', keyFormatted, ivFormatted, {
                authTagLength: 16,
            });
            // It will throw exception if the decryption fails due to invalid key, iv, tag
            decipher.setAuthTag(tagFormatted);
            // Loop through ciphertext and decrypt then return
            const data = new Array(ciphertext.data.length);
            for (let i = 0; i < ciphertext.data.length; i += 1) {
                data[i] = bytes_1.ByteUtils.fastBytesToHex(decipher.update(bytes_1.ByteUtils.fastHexToBytes(ciphertext.data[i])));
            }
            decipher.final();
            return data;
        }
        catch (cause) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            throw new Error('Unable to decrypt ciphertext.', { cause });
        }
    }
    /**
     * Encrypt blocks of data with AES-256-CTR
     * @param plaintext - plaintext to encrypt
     * @param key - key to encrypt with
     * @returns ciphertext bundle
     */
    static encryptCTR(plaintext, key) {
        // If types are strings, convert to bytes array
        const keyFormatted = typeof key === 'string' ? bytes_1.ByteUtils.fastHexToBytes(key) : key;
        if (keyFormatted.byteLength !== 32) {
            throw new Error(`Invalid key length. Expected 32 bytes. Received ${keyFormatted.byteLength} bytes.`);
        }
        const iv = AES.getRandomIV();
        const ivFormatted = bytes_1.ByteUtils.fastHexToBytes(iv);
        // Initialize cipher
        const cipher = createCipheriv('aes-256-ctr', keyFormatted, ivFormatted);
        // Loop through data blocks and encrypt
        const data = new Array(plaintext.length);
        for (let i = 0; i < plaintext.length; i += 1) {
            data[i] = bytes_1.ByteUtils.fastBytesToHex(cipher.update(bytes_1.ByteUtils.fastHexToBytes(plaintext[i])));
        }
        cipher.final();
        // Return encrypted data bundle
        return {
            iv: bytes_1.ByteUtils.formatToByteLength(ivFormatted, bytes_1.ByteLength.UINT_128, false),
            data,
        };
    }
    /**
     * Decrypts AES-256-CTR encrypted data
     * On failure, it throws `Unsupported state or unable to authenticate data`
     * @param ciphertext - ciphertext bundle to decrypt
     * @param key - key to decrypt with
     * @returns - plaintext
     */
    static decryptCTR(ciphertext, key) {
        // If types are strings, convert to bytes array
        const keyFormatted = typeof key === 'string' ? bytes_1.ByteUtils.fastHexToBytes(key) : key;
        if (keyFormatted.byteLength !== 32) {
            throw new Error(`Invalid key length. Expected 32 bytes. Received ${keyFormatted.byteLength} bytes.`);
        }
        const ivFormatted = bytes_1.ByteUtils.fastHexToBytes(ciphertext.iv);
        if (ivFormatted.byteLength !== 16) {
            throw new Error(`Invalid iv length. Expected 16 bytes. Received ${ivFormatted.byteLength} bytes.`);
        }
        // Initialize decipher
        const decipher = createDecipheriv('aes-256-ctr', keyFormatted, ivFormatted);
        // Loop through ciphertext and decrypt then return
        const data = new Array(ciphertext.data.length);
        for (let i = 0; i < ciphertext.data.length; i += 1) {
            data[i] = bytes_1.ByteUtils.fastBytesToHex(decipher.update(bytes_1.ByteUtils.fastHexToBytes(ciphertext.data[i])));
        }
        decipher.final();
        return data;
    }
}
exports.AES = AES;
//# sourceMappingURL=aes.js.map