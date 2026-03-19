"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptJSONDataWithSharedKey = exports.tryDecryptJSONDataWithSharedKey = void 0;
const bytes_1 = require("./bytes");
const ciphertext_1 = require("./encryption/ciphertext");
const aes_1 = require("./encryption/aes");
const tryDecryptJSONDataWithSharedKey = (encryptedData, sharedKey) => {
    try {
        const ciphertext = (0, ciphertext_1.encryptedDataToCiphertext)(encryptedData);
        const chunkedData = aes_1.AES.decryptGCM(ciphertext, sharedKey);
        const dataString = (0, bytes_1.toUTF8String)(bytes_1.ByteUtils.combine(chunkedData));
        return JSON.parse(dataString);
    }
    catch (err) {
        // Data is not addressed to this user.
        return null;
    }
};
exports.tryDecryptJSONDataWithSharedKey = tryDecryptJSONDataWithSharedKey;
const encryptJSONDataWithSharedKey = (data, sharedKey) => {
    const dataString = JSON.stringify(data);
    const chunkedData = bytes_1.ByteUtils.chunk((0, bytes_1.fromUTF8String)(dataString));
    const ciphertext = aes_1.AES.encryptGCM(chunkedData, sharedKey);
    return (0, ciphertext_1.ciphertextToEncryptedJSONData)(ciphertext);
};
exports.encryptJSONDataWithSharedKey = encryptJSONDataWithSharedKey;
//# sourceMappingURL=ecies.js.map