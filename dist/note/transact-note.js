"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransactNote = void 0;
const poseidon_1 = require("../utils/poseidon");
const bech32_1 = require("../key-derivation/bech32");
const formatted_types_1 = require("../models/formatted-types");
const transaction_constants_1 = require("../models/transaction-constants");
const bytes_1 = require("../utils/bytes");
const ciphertext_1 = require("../utils/encryption/ciphertext");
const aes_1 = require("../utils/encryption/aes");
const keys_utils_1 = require("../utils/keys-utils");
const keys_utils_legacy_1 = require("../utils/keys-utils-legacy");
const memo_1 = require("./memo");
const note_util_1 = require("./note-util");
const is_defined_1 = require("../utils/is-defined");
const wallet_info_1 = __importDefault(require("../wallet/wallet-info"));
const poi_types_1 = require("../models/poi-types");
const x_cha_cha_20_1 = require("../utils/encryption/x-cha-cha-20");
/**
 *
 * A Note on Encoded MPKs:
 *
 * The presence of senderRandom field, or an encoded/unencoded MPK in a decrypted note,
 * tells us whether or not the sender address was hidden or visible.
 *
 *          MPK               senderRandom                                Sender address
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * Value    Unencoded         Random hex (15)                             Hidden
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * Value    Encoded           undefined or MEMO_SENDER_RANDOM_NULL        Visible
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 */
class TransactNote {
    // address data of recipient
    receiverAddressData;
    // address data of sender
    senderAddressData;
    // 32 byte hash of token data
    tokenHash;
    tokenData;
    // 16 byte random
    random;
    // value to transfer as bigint
    value;
    notePublicKey;
    hash;
    outputType;
    walletSource;
    senderRandom;
    memoText;
    // Only used during serialization/storage of ShieldCommitments.
    shieldFee;
    blockNumber;
    /**
     * Create Note object from values
     * @param {BigInt} receiverAddressData - recipient wallet address data
     * @param {string} random - note randomness
     * @param {string} tokenData - note token ID
     * @param {BigInt} value - note value
     */
    constructor(receiverAddressData, senderAddressData, random, value, tokenData, outputType, walletSource, senderRandom, memoText, shieldFee, blockNumber) {
        (0, note_util_1.assertValidNoteRandom)(random);
        this.receiverAddressData = receiverAddressData;
        this.senderAddressData = senderAddressData;
        this.random = random;
        this.value = BigInt(value);
        this.tokenData = (0, note_util_1.serializeTokenData)(tokenData.tokenAddress, tokenData.tokenType, tokenData.tokenSubID);
        this.tokenHash = (0, note_util_1.getTokenDataHash)(tokenData);
        this.notePublicKey = this.getNotePublicKey();
        this.hash = TransactNote.getHash(this.notePublicKey, this.tokenHash, this.value);
        this.outputType = outputType;
        this.walletSource = walletSource;
        this.senderRandom = senderRandom;
        this.memoText = memoText;
        this.shieldFee = shieldFee;
        this.blockNumber = blockNumber;
    }
    static createTransfer(receiverAddressData, senderAddressData, value, tokenData, showSenderAddressToRecipient, outputType, memoText) {
        // See note at top of file.
        const shouldCreateSenderRandom = !showSenderAddressToRecipient;
        const senderRandom = shouldCreateSenderRandom
            ? TransactNote.getSenderRandom()
            : transaction_constants_1.MEMO_SENDER_RANDOM_NULL;
        const { walletSource } = wallet_info_1.default;
        return new TransactNote(receiverAddressData, senderAddressData, TransactNote.getNoteRandom(), value, tokenData, outputType, walletSource, senderRandom, memoText, undefined, // shieldFee
        undefined);
    }
    static createERC721Transfer(receiverAddressData, senderAddressData, tokenData, showSenderAddressToRecipient, memoText) {
        if (tokenData.tokenType !== formatted_types_1.TokenType.ERC721) {
            throw new Error(`Invalid token type for ERC721 transfer: ${tokenData.tokenType}`);
        }
        return TransactNote.createTransfer(receiverAddressData, senderAddressData, note_util_1.ERC721_NOTE_VALUE, tokenData, showSenderAddressToRecipient, formatted_types_1.OutputType.Transfer, memoText);
    }
    static createERC1155Transfer(receiverAddressData, senderAddressData, tokenData, amount, showSenderAddressToRecipient, memoText) {
        if (tokenData.tokenType !== formatted_types_1.TokenType.ERC1155) {
            throw new Error(`Invalid token type for ERC1155 transfer: ${tokenData.tokenType}`);
        }
        return TransactNote.createTransfer(receiverAddressData, senderAddressData, amount, tokenData, showSenderAddressToRecipient, formatted_types_1.OutputType.Transfer, memoText);
    }
    static getNoteRandom() {
        return bytes_1.ByteUtils.randomHex(16);
    }
    static getSenderRandom() {
        return bytes_1.ByteUtils.randomHex(15);
    }
    getNotePublicKey() {
        return (0, poseidon_1.poseidon)([this.receiverAddressData.masterPublicKey, bytes_1.ByteUtils.hexToBigInt(this.random)]);
    }
    getSenderAddress() {
        if (!this.senderAddressData) {
            return undefined;
        }
        return (0, bech32_1.encodeAddress)(this.senderAddressData);
    }
    /**
     * Get note hash
     * @returns {bigint} hash
     */
    static getHash(notePublicKey, tokenHash, value) {
        return (0, poseidon_1.poseidon)([notePublicKey, bytes_1.ByteUtils.hexToBigInt(tokenHash), value]);
    }
    /**
     * AES-256-GCM encrypts note data
     * @param sharedKey - key to encrypt with
     */
    encryptV2(txidVersion, sharedKey, senderMasterPublicKey, senderRandom, viewingPrivateKey) {
        if (txidVersion !== poi_types_1.TXIDVersion.V2_PoseidonMerkle) {
            throw new Error('Invalid txidVersion for V2 encryption');
        }
        const prefix = false;
        const { tokenHash, value, random } = this.formatFields(prefix);
        const receiverMasterPublicKey = this.receiverAddressData.masterPublicKey;
        // Encode the master public key only if the senderRandom is unset (sender wants address to be visible by receiver).
        const encodedMasterPublicKey = TransactNote.getEncodedMasterPublicKey(senderRandom, receiverMasterPublicKey, senderMasterPublicKey);
        const encodedMemoText = memo_1.Memo.encodeMemoText(this.memoText);
        const ciphertext = aes_1.AES.encryptGCM([
            bytes_1.ByteUtils.nToHex(encodedMasterPublicKey, bytes_1.ByteLength.UINT_256),
            tokenHash,
            `${random}${value}`,
            encodedMemoText,
        ], sharedKey);
        if (!(0, is_defined_1.isDefined)(this.outputType)) {
            throw new Error('Output type must be set for encrypted note annotation data');
        }
        if (!(0, is_defined_1.isDefined)(this.senderRandom)) {
            throw new Error('Sender random must be set for encrypted note annotation data');
        }
        if (!(0, is_defined_1.isDefined)(this.walletSource)) {
            throw new Error('Wallet source must be set for encrypted note annotation data');
        }
        const annotationData = memo_1.Memo.createEncryptedNoteAnnotationDataV2(this.outputType, this.senderRandom, this.walletSource, viewingPrivateKey);
        return {
            noteCiphertext: {
                ...ciphertext,
                data: ciphertext.data.slice(0, 3), // Remove encrypted memo text.
            },
            noteMemo: ciphertext.data[3],
            annotationData,
        };
    }
    /**
     * AES-256-GCM encrypts note data
     * @param sharedKey - key to encrypt with
     */
    encryptV3(txidVersion, sharedKey, senderMasterPublicKey) {
        if (txidVersion !== poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
            throw new Error('Invalid txidVersion for V3 encryption');
        }
        const prefix = false;
        const { tokenHash, value, random } = this.formatFields(prefix);
        const receiverMasterPublicKey = this.receiverAddressData.masterPublicKey;
        // Encode the master public key only if the senderRandom is unset (sender wants address to be visible by receiver).
        const encodedMasterPublicKey = TransactNote.getEncodedMasterPublicKey(this.senderRandom, receiverMasterPublicKey, senderMasterPublicKey);
        if (!(0, is_defined_1.isDefined)(this.senderRandom)) {
            throw new Error('Sender random must be set for V3 encrypted note annotation data');
        }
        if (this.senderRandom.length !== 30) {
            throw new Error('Invalid senderRandom length - expected 15 bytes (30 length)');
        }
        const encodedMemoText = memo_1.Memo.encodeMemoText(this.memoText);
        const plaintext = [
            bytes_1.ByteUtils.nToHex(encodedMasterPublicKey, bytes_1.ByteLength.UINT_256), // 64 length
            `${random}${value}`, // 64 length
            tokenHash, // 64 length
            this.senderRandom, // 30 length
            encodedMemoText, // variable length
        ].join('');
        return x_cha_cha_20_1.XChaCha20.encryptChaCha20Poly1305(plaintext, sharedKey);
    }
    static unblindViewingPublicKey(random, blindedViewingPublicKey, senderRandom, isLegacyDecryption) {
        if (blindedViewingPublicKey && (0, is_defined_1.isDefined)(senderRandom)) {
            const unblinded = isLegacyDecryption
                ? (0, keys_utils_legacy_1.unblindNoteKeyLegacy)(blindedViewingPublicKey, random, senderRandom)
                : (0, keys_utils_1.unblindNoteKey)(blindedViewingPublicKey, random, senderRandom);
            if (unblinded) {
                return unblinded;
            }
        }
        return new Uint8Array(); // dummy
    }
    /**
     * AES-256-GCM decrypts note data (V2)
     */
    static async decrypt(txidVersion, chain, currentWalletAddressData, noteCiphertext, sharedKey, memoV2, annotationData, viewingPrivateKey, blindedReceiverViewingKey, blindedSenderViewingKey, isSentNote, isLegacyDecryption, tokenDataGetter, blockNumber, transactCommitmentBatchIndexV3) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                if (!('tag' in noteCiphertext)) {
                    throw new Error('Invalid ciphertext for V2 decryption');
                }
                const ciphertextDataWithMemoText = [...noteCiphertext.data, bytes_1.ByteUtils.strip0x(memoV2)];
                const fullCiphertext = {
                    ...noteCiphertext,
                    data: ciphertextDataWithMemoText,
                };
                const decryptedCiphertext = aes_1.AES.decryptGCM(fullCiphertext, sharedKey).map((value) => bytes_1.ByteUtils.hexlify(value));
                const { random, value, memoText, tokenData, encodedMPK } = await this.getDecryptedValuesNoteCiphertextV2(txidVersion, chain, decryptedCiphertext, tokenDataGetter);
                const noteAnnotationData = isSentNote
                    ? memo_1.Memo.decryptNoteAnnotationData(annotationData, viewingPrivateKey)
                    : undefined;
                return this.noteFromDecryptedValues(currentWalletAddressData, noteAnnotationData?.outputType, noteAnnotationData?.walletSource, blindedReceiverViewingKey, blindedSenderViewingKey, noteAnnotationData?.senderRandom, isSentNote, isLegacyDecryption, blockNumber, random, value, memoText, tokenData, encodedMPK);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                if ('tag' in noteCiphertext) {
                    throw new Error('Invalid ciphertext for V3 decryption');
                }
                const decryptedCiphertext = x_cha_cha_20_1.XChaCha20.decryptChaCha20Poly1305(noteCiphertext, sharedKey);
                const { random, value, memoText, tokenData, encodedMPK, senderRandom } = await this.getDecryptedValuesNoteCiphertextV3(txidVersion, chain, decryptedCiphertext, tokenDataGetter);
                if (!(0, is_defined_1.isDefined)(transactCommitmentBatchIndexV3)) {
                    throw new Error('transactCommitmentBatchIndex must be defined for V3 decryption');
                }
                const senderCiphertext = annotationData;
                const senderCiphertextDecrypted = isSentNote
                    ? memo_1.Memo.decryptSenderCiphertextV3(senderCiphertext, viewingPrivateKey, transactCommitmentBatchIndexV3)
                    : undefined;
                return this.noteFromDecryptedValues(currentWalletAddressData, senderCiphertextDecrypted?.outputType, senderCiphertextDecrypted?.walletSource, blindedReceiverViewingKey, blindedSenderViewingKey, senderRandom, isSentNote, isLegacyDecryption, blockNumber, random, value, memoText, tokenData, encodedMPK);
            }
        }
        throw new Error('Invalid txidVersion for note decryption');
    }
    static getDecodedMasterPublicKey(currentWalletMasterPublicKey, encodedMasterPublicKey, senderRandom, isLegacyDecryption) {
        if (isLegacyDecryption ||
            ((0, is_defined_1.isDefined)(senderRandom) && senderRandom !== transaction_constants_1.MEMO_SENDER_RANDOM_NULL)) {
            return encodedMasterPublicKey; // Unencoded
        }
        return encodedMasterPublicKey ^ currentWalletMasterPublicKey;
    }
    static getEncodedMasterPublicKey(senderRandom, receiverMasterPublicKey, senderMasterPublicKey) {
        return (0, is_defined_1.isDefined)(senderRandom) && senderRandom !== transaction_constants_1.MEMO_SENDER_RANDOM_NULL
            ? receiverMasterPublicKey // Unencoded
            : receiverMasterPublicKey ^ senderMasterPublicKey;
    }
    static async getDecryptedValuesNoteCiphertextV2(txidVersion, chain, decryptedCiphertext, tokenDataGetter) {
        // Decrypted Values (V2):
        // 0: Master Public Key (Encoded)
        // 1: Token Address
        // 2: Value
        // 3 (+ more array values for legacy): Optional Memo string
        const random = decryptedCiphertext[2].substring(0, 32);
        const value = bytes_1.ByteUtils.hexToBigInt(decryptedCiphertext[2].substring(32, 64));
        const tokenHash = decryptedCiphertext[1];
        const memoText = memo_1.Memo.decodeMemoText(bytes_1.ByteUtils.combine(decryptedCiphertext.slice(3)));
        const tokenData = await tokenDataGetter.getTokenDataFromHash(txidVersion, chain, tokenHash);
        const encodedMPK = bytes_1.ByteUtils.hexToBigInt(decryptedCiphertext[0]);
        return { random, value, memoText, tokenData, encodedMPK };
    }
    static async getDecryptedValuesNoteCiphertextV3(txidVersion, chain, decryptedCiphertextV3, tokenDataGetter) {
        // Decrypted Values (V3):
        // - encodedMPK (senderMPK XOR receiverMPK - 32 bytes)
        const encodedMPK = bytes_1.ByteUtils.hexToBigInt(decryptedCiphertextV3.substring(0, 64));
        // - random & amount (16 bytes each)
        const random = decryptedCiphertextV3.substring(64, 96);
        const value = bytes_1.ByteUtils.hexToBigInt(decryptedCiphertextV3.substring(96, 128));
        // - token (32 bytes)
        const tokenHash = decryptedCiphertextV3.substring(128, 192);
        const tokenData = await tokenDataGetter.getTokenDataFromHash(txidVersion, chain, tokenHash);
        // - senderRandom (15 bytes)
        const senderRandom = decryptedCiphertextV3.substring(192, 222); // Note: 30 length for 15 bytes
        // - memo (variable bytes)
        const memoText = decryptedCiphertextV3.length > 222
            ? memo_1.Memo.decodeMemoText(decryptedCiphertextV3.substring(222))
            : undefined;
        return { random, value, memoText, tokenData, encodedMPK, senderRandom };
    }
    static async noteFromDecryptedValues(currentWalletAddressData, outputType, walletSource, blindedReceiverViewingKey, blindedSenderViewingKey, senderRandom, isSentNote, isLegacyDecryption, blockNumber, random, value, memoText, tokenData, encodedMPK) {
        if (isSentNote) {
            // SENT note.
            const receiverAddressData = {
                masterPublicKey: TransactNote.getDecodedMasterPublicKey(currentWalletAddressData.masterPublicKey, encodedMPK, senderRandom, isLegacyDecryption),
                viewingPublicKey: TransactNote.unblindViewingPublicKey(random, blindedReceiverViewingKey, senderRandom, isLegacyDecryption),
            };
            return new TransactNote(receiverAddressData, currentWalletAddressData, random, value, tokenData, outputType, walletSource, senderRandom, memoText, undefined, // shieldFee
            blockNumber);
        }
        // RECEIVE note.
        // Master public key will be encoded (different) if the sender wants address to be visible by receiver.
        const senderAddressVisible = encodedMPK !== currentWalletAddressData.masterPublicKey;
        const senderAddressData = senderAddressVisible
            ? {
                masterPublicKey: TransactNote.getDecodedMasterPublicKey(currentWalletAddressData.masterPublicKey, encodedMPK, undefined, // Sender is not blinded, null senderRandom.
                isLegacyDecryption),
                viewingPublicKey: TransactNote.unblindViewingPublicKey(random, blindedSenderViewingKey, transaction_constants_1.MEMO_SENDER_RANDOM_NULL, // Sender is not blinded, null senderRandom.
                isLegacyDecryption),
            }
            : undefined;
        return new TransactNote(currentWalletAddressData, senderAddressData, random, value, tokenData, outputType, walletSource, senderRandom, memoText, undefined, // shieldFee
        blockNumber);
    }
    formatFields(prefix = false) {
        return {
            npk: bytes_1.ByteUtils.nToHex(this.notePublicKey, bytes_1.ByteLength.UINT_256, prefix),
            tokenHash: bytes_1.ByteUtils.formatToByteLength(this.tokenHash, bytes_1.ByteLength.UINT_256, prefix),
            value: bytes_1.ByteUtils.nToHex(BigInt(this.value), bytes_1.ByteLength.UINT_128, prefix),
            random: bytes_1.ByteUtils.formatToByteLength(this.random, bytes_1.ByteLength.UINT_128, prefix),
            senderRandom: this.senderRandom ?? undefined,
            walletSource: this.walletSource ?? undefined,
            outputType: this.outputType ?? undefined,
            shieldFee: this.shieldFee ?? undefined,
        };
    }
    /**
     * Gets JSON serialized version of note
     * @returns serialized note
     */
    serialize(prefix) {
        const { npk, tokenHash, value, random, walletSource, senderRandom, outputType, shieldFee } = this.formatFields(prefix);
        return {
            npk,
            tokenHash,
            value,
            random,
            walletSource,
            senderRandom,
            outputType,
            recipientAddress: (0, bech32_1.encodeAddress)(this.receiverAddressData),
            senderAddress: this.senderAddressData ? (0, bech32_1.encodeAddress)(this.senderAddressData) : undefined,
            memoText: this.memoText,
            shieldFee,
            blockNumber: this.blockNumber,
        };
    }
    serializeLegacy(viewingPrivateKey, prefix) {
        const { npk, tokenHash, value, random } = this.formatFields(prefix);
        const memoField = [];
        const randomCiphertext = aes_1.AES.encryptGCM([random], viewingPrivateKey);
        const [ivTag, data] = (0, ciphertext_1.ciphertextToEncryptedRandomData)(randomCiphertext);
        return {
            npk,
            tokenHash,
            value,
            encryptedRandom: [ivTag, data].map((v) => bytes_1.ByteUtils.hexlify(v, prefix)),
            memoField,
            recipientAddress: (0, bech32_1.encodeAddress)(this.receiverAddressData),
            memoText: this.memoText,
            blockNumber: this.blockNumber,
        };
    }
    static isLegacyTransactNote(noteData) {
        return 'encryptedRandom' in noteData;
    }
    /**
     * Creates note from serialized note JSON
     * @param noteData - serialized note data
     * @param viewingPrivateKey - viewing private key for decryption
     * @returns TransactNote
     */
    static async deserialize(txidVersion, chain, noteData, viewingPrivateKey, tokenDataGetter) {
        if ('encryptedRandom' in noteData) {
            // LegacyNoteSerialized type.
            return TransactNote.deserializeLegacy(noteData, viewingPrivateKey);
        }
        const { tokenHash } = noteData;
        const tokenData = await tokenDataGetter.getTokenDataFromHash(txidVersion, chain, tokenHash);
        // NoteSerialized type.
        return new TransactNote((0, bech32_1.decodeAddress)(noteData.recipientAddress), (0, is_defined_1.isDefined)(noteData.senderAddress) ? (0, bech32_1.decodeAddress)(noteData.senderAddress) : undefined, noteData.random, bytes_1.ByteUtils.hexToBigInt(noteData.value), tokenData, noteData.outputType ?? undefined, noteData.walletSource ?? undefined, noteData.senderRandom ?? undefined, noteData.memoText ?? undefined, noteData.shieldFee ?? undefined, noteData.blockNumber ?? undefined);
    }
    /**
     * Creates note from serialized note JSON
     * @param noteData - serialized note data
     * @param viewingPrivateKey - viewing private key for decryption
     * @returns TransactNote
     */
    static deserializeLegacy(noteData, viewingPrivateKey) {
        const randomCiphertext = (0, ciphertext_1.encryptedDataToCiphertext)(noteData.encryptedRandom);
        const decryptedRandom = aes_1.AES.decryptGCM(randomCiphertext, viewingPrivateKey);
        // Legacy can only be erc20.
        const { tokenHash } = noteData;
        const tokenData = (0, note_util_1.getTokenDataERC20)(tokenHash);
        return new TransactNote((0, bech32_1.decodeAddress)(noteData.recipientAddress), undefined, // senderAddress
        bytes_1.ByteUtils.combine(decryptedRandom), bytes_1.ByteUtils.hexToBigInt(noteData.value), tokenData, undefined, // outputType
        undefined, // walletSource
        undefined, // senderRandom
        noteData.memoText ?? undefined, undefined, // shieldFee
        noteData.blockNumber ?? undefined);
    }
    /**
     * Calculates nullifier for a given note
     * @param nullifyingKey - nullifying key
     * @param leafIndex - Index of note's commitment in the Merkle tree
     * @returns nullifier (hex string)
     */
    static getNullifier(nullifyingKey, leafIndex) {
        return (0, poseidon_1.poseidon)([nullifyingKey, BigInt(leafIndex)]);
    }
    newProcessingNoteWithValue(value) {
        return new TransactNote(this.receiverAddressData, this.senderAddressData, TransactNote.getNoteRandom(), value, this.tokenData, this.outputType, this.walletSource, this.senderRandom, this.memoText, this.shieldFee, undefined);
    }
    static calculateTotalNoteValues = (notes) => notes.reduce((left, right) => left + right.value, BigInt(0));
    /**
     * TransactNote with tokenData and value, for a mimic Unshield Note during solution processing.
     * All other fields are placeholders.
     */
    static createNullUnshieldNote(tokenData, value) {
        const nullAddressData = {
            masterPublicKey: 0n,
            viewingPublicKey: bytes_1.ByteUtils.nToBytes(0n, bytes_1.ByteLength.UINT_256),
        };
        return new TransactNote(nullAddressData, undefined, // senderAddressData
        TransactNote.getNoteRandom(), value, tokenData, undefined, // outputType
        undefined, // walletSource
        undefined, // senderRandom
        undefined, // memoText
        undefined, // shieldFee
        undefined);
    }
}
exports.TransactNote = TransactNote;
//# sourceMappingURL=transact-note.js.map