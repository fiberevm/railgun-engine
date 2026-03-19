"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Memo = exports.LEGACY_MEMO_METADATA_BYTE_CHUNKS = void 0;
const debugger_1 = __importDefault(require("../debugger/debugger"));
const formatted_types_1 = require("../models/formatted-types");
const transaction_constants_1 = require("../models/transaction-constants");
const bytes_1 = require("../utils/bytes");
const aes_1 = require("../utils/encryption/aes");
const x_cha_cha_20_1 = require("../utils/encryption/x-cha-cha-20");
const is_defined_1 = require("../utils/is-defined");
const runtime_1 = require("../utils/runtime");
const wallet_info_1 = __importDefault(require("../wallet/wallet-info"));
// TextEncoder/TextDecoder (used in this file) needs to shimmed in React Native
if (runtime_1.isReactNative) {
    // eslint-disable-next-line global-require
    require('fast-text-encoding');
}
// Annotation Data used to be stored as the leading bytes in Memo field.
exports.LEGACY_MEMO_METADATA_BYTE_CHUNKS = 2;
class Memo {
    static decryptNoteAnnotationData(annotationData, viewingPrivateKey) {
        if (!annotationData || !annotationData.length) {
            return undefined;
        }
        try {
            // Remove 0x prefix.
            const hexlified = bytes_1.ByteUtils.hexlify(annotationData);
            const hasTwoBytes = hexlified.length > 64;
            const metadataCiphertext = {
                iv: hexlified.substring(0, 32),
                data: hasTwoBytes
                    ? [hexlified.substring(32, 64), hexlified.substring(64, 96), hexlified.substring(96, 128)]
                    : [hexlified.substring(32, 64)],
            };
            const decrypted = aes_1.AES.decryptCTR(metadataCiphertext, viewingPrivateKey);
            const walletSource = hasTwoBytes
                ? this.decodeWalletSource(decrypted[2])
                : undefined;
            const noteAnnotationData = {
                outputType: parseInt(decrypted[0].substring(0, 2), 16),
                senderRandom: decrypted[0].substring(2, 32),
                walletSource,
            };
            if (!Object.values(formatted_types_1.OutputType).includes(noteAnnotationData.outputType)) {
                throw new Error('Error decrypting note annotation data.');
            }
            return noteAnnotationData;
        }
        catch (cause) {
            debugger_1.default.error(new Error('Failed to decrypt node annotation data', { cause }));
            return undefined;
        }
    }
    static decryptSenderCiphertextV3(senderCiphertext, viewingPrivateKey, transactCommitmentBatchIndex) {
        if (!senderCiphertext || !senderCiphertext.length) {
            return undefined;
        }
        try {
            const strippedSenderCiphertext = bytes_1.ByteUtils.strip0x(senderCiphertext);
            const metadataCiphertext = {
                algorithm: formatted_types_1.XChaChaEncryptionAlgorithm.XChaCha,
                nonce: strippedSenderCiphertext.substring(0, 32),
                bundle: strippedSenderCiphertext.substring(32),
            };
            const decrypted = x_cha_cha_20_1.XChaCha20.decryptChaCha20(metadataCiphertext, viewingPrivateKey);
            const walletSource = this.decodeWalletSource(decrypted.substring(0, 32));
            const outputTypeByteOffset = 32 + transactCommitmentBatchIndex * 2;
            const outputType = parseInt(decrypted.substring(outputTypeByteOffset, outputTypeByteOffset + 2), 16);
            if (Number.isNaN(outputType)) {
                throw new Error('Invalid outputType for senderCiphertextData');
            }
            const senderAnnotation = {
                walletSource,
                outputType,
            };
            return senderAnnotation;
        }
        catch (cause) {
            debugger_1.default.error(new Error('Failed to decrypt sender ciphertext V3', { cause }));
            return undefined;
        }
    }
    static decryptSenderRandom = (annotationData, viewingPrivateKey) => {
        const noteAnnotationData = Memo.decryptNoteAnnotationData(annotationData, viewingPrivateKey);
        return noteAnnotationData ? noteAnnotationData.senderRandom : transaction_constants_1.MEMO_SENDER_RANDOM_NULL;
    };
    // static decryptSenderRandomV3 = (
    //   senderCiphertext: string,
    //   viewingPrivateKey: Uint8Array,
    //   transactCommitmentBatchIndex: number,
    // ): string => {
    //   const noteAnnotationData = Memo.decryptSenderCiphertextV3(
    //     senderCiphertext,
    //     viewingPrivateKey,
    //     transactCommitmentBatchIndex,
    //   );
    //   return noteAnnotationData ? noteAnnotationData.senderRandom : MEMO_SENDER_RANDOM_NULL;
    // };
    static decodeWalletSource(decryptedBytes) {
        try {
            const decoded = wallet_info_1.default.decodeWalletSource(decryptedBytes);
            return decoded;
        }
        catch (err) {
            return undefined;
        }
    }
    static createEncryptedNoteAnnotationDataV2(outputType, senderRandom, walletSource, viewingPrivateKey) {
        const outputTypeFormatted = bytes_1.ByteUtils.nToHex(BigInt(outputType), bytes_1.ByteLength.UINT_8); // 1 byte
        const senderRandomFormatted = senderRandom; // 15 bytes
        const metadataField0 = `${outputTypeFormatted}${senderRandomFormatted}`;
        if (metadataField0.length !== 32) {
            throw new Error('Metadata field 0 must be 16 bytes.');
        }
        const metadataField1 = new Array(30).fill('0').join(''); // 32 zeroes
        let metadataField2 = wallet_info_1.default.getEncodedWalletSource(walletSource);
        while (metadataField2.length < 30) {
            metadataField2 = `0${metadataField2}`;
        }
        const toEncrypt = [metadataField0, metadataField1, metadataField2];
        const metadataCiphertext = aes_1.AES.encryptCTR(toEncrypt, viewingPrivateKey);
        return (metadataCiphertext.iv + // ciphertext IV
            metadataCiphertext.data[0] + // outputType/senderRandom
            metadataCiphertext.data[1] + // 32 zeroes
            metadataCiphertext.data[2] // Wallet source, prepended with 0s
        );
    }
    static createSenderAnnotationEncryptedV3(walletSource, orderedOutputTypes, viewingPrivateKey) {
        let metadataField0 = wallet_info_1.default.getEncodedWalletSource(walletSource);
        while (metadataField0.length < 32) {
            metadataField0 = `0${metadataField0}`;
        }
        const outputTypesFormatted = orderedOutputTypes.map((outputType) => 
        // 1 byte each
        bytes_1.ByteUtils.nToHex(BigInt(outputType), bytes_1.ByteLength.UINT_8));
        const metadataField1 = outputTypesFormatted.join('');
        const toEncrypt = `${metadataField0}${metadataField1}`;
        const metadataCiphertext = x_cha_cha_20_1.XChaCha20.encryptChaCha20(toEncrypt, viewingPrivateKey);
        return bytes_1.ByteUtils.prefix0x(metadataCiphertext.nonce + metadataCiphertext.bundle);
    }
    static encodeMemoText(memoText) {
        if (!(0, is_defined_1.isDefined)(memoText)) {
            return '';
        }
        const encoded = bytes_1.ByteUtils.hexlify(new TextEncoder().encode(memoText));
        return encoded;
    }
    static decodeMemoText(encoded) {
        if (!encoded.length) {
            return undefined;
        }
        return new TextDecoder().decode(bytes_1.ByteUtils.fastHexToBytes(encoded));
    }
}
exports.Memo = Memo;
//# sourceMappingURL=memo.js.map