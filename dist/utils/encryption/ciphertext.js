"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptedDataToCiphertext = exports.ciphertextToEncryptedJSONData = exports.ciphertextToEncryptedRandomData = void 0;
const bytes_1 = require("../bytes");
const ciphertextToEncryptedRandomData = (ciphertext) => {
    const ivTag = bytes_1.ByteUtils.formatToByteLength(ciphertext.iv, bytes_1.ByteLength.UINT_128, true) +
        bytes_1.ByteUtils.formatToByteLength(ciphertext.tag, bytes_1.ByteLength.UINT_128, false);
    const data = bytes_1.ByteUtils.formatToByteLength(ciphertext.data[0], bytes_1.ByteLength.UINT_128, true);
    return [ivTag, data];
};
exports.ciphertextToEncryptedRandomData = ciphertextToEncryptedRandomData;
const ciphertextToEncryptedJSONData = (ciphertext) => {
    const ivTag = bytes_1.ByteUtils.formatToByteLength(ciphertext.iv, bytes_1.ByteLength.UINT_128, true) +
        bytes_1.ByteUtils.formatToByteLength(ciphertext.tag, bytes_1.ByteLength.UINT_128, false);
    const data = bytes_1.ByteUtils.combine(ciphertext.data);
    return [ivTag, `0x${data}`];
};
exports.ciphertextToEncryptedJSONData = ciphertextToEncryptedJSONData;
const encryptedDataToCiphertext = (encryptedData) => {
    const hexlifiedIvTag = bytes_1.ByteUtils.formatToByteLength(encryptedData[0], bytes_1.ByteLength.UINT_256, false);
    const ciphertext = {
        iv: hexlifiedIvTag.substring(0, 32),
        tag: hexlifiedIvTag.substring(32),
        data: bytes_1.ByteUtils.chunk(encryptedData[1], bytes_1.ByteLength.UINT_256),
    };
    return ciphertext;
};
exports.encryptedDataToCiphertext = encryptedDataToCiphertext;
//# sourceMappingURL=ciphertext.js.map