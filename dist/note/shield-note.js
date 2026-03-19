"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ShieldNote = void 0;
const utils_1 = require("ethereum-cryptography/utils");
const poseidon_1 = require("../utils/poseidon");
const utils_2 = require("../utils");
const bytes_1 = require("../utils/bytes");
const note_util_1 = require("./note-util");
const keys_utils_1 = require("../utils/keys-utils");
const aes_1 = require("../utils/encryption/aes");
class ShieldNote {
    masterPublicKey;
    random;
    value;
    tokenData;
    tokenHash;
    notePublicKey;
    constructor(masterPublicKey, random, value, tokenData) {
        (0, note_util_1.assertValidNoteRandom)(random);
        (0, note_util_1.assertValidNoteToken)(tokenData, value);
        this.masterPublicKey = masterPublicKey;
        this.random = random;
        this.tokenData = tokenData;
        this.tokenHash = (0, note_util_1.getTokenDataHash)(tokenData);
        this.value = value;
        this.notePublicKey = ShieldNote.getNotePublicKey(masterPublicKey, random);
    }
    /**
     * Used to generate a shieldPrivateKey by signing this message with public wallet.
     * After shielding, the shieldPrivateKey can then be used to get the 0zk address of the receiver.
     */
    static getShieldPrivateKeySignatureMessage() {
        // DO NOT MODIFY THIS CONSTANT.
        return 'RAILGUN_SHIELD';
    }
    static getNotePublicKey(masterPublicKey, random) {
        return (0, poseidon_1.poseidon)([masterPublicKey, bytes_1.ByteUtils.hexToBigInt(random)]);
    }
    static getShieldNoteHash(notePublicKey, tokenHash, valueAfterFee) {
        return (0, poseidon_1.poseidon)([notePublicKey, bytes_1.ByteUtils.hexToBigInt(tokenHash), valueAfterFee]);
    }
    static decryptRandom(encryptedBundle, sharedKey) {
        const hexlified0 = bytes_1.ByteUtils.hexlify(encryptedBundle[0]);
        const hexlified1 = bytes_1.ByteUtils.hexlify(encryptedBundle[1]);
        const decrypted = aes_1.AES.decryptGCM({
            iv: hexlified0.slice(0, 32),
            tag: hexlified0.slice(32, 64),
            data: [hexlified1.slice(0, 32)],
        }, sharedKey)[0];
        return bytes_1.ByteUtils.hexlify(decrypted);
    }
    /**
     * Gets JSON serialized version of note
     * @param viewingPrivateKey - viewing private key for decryption
     * @param forContract - if we should 0x prefix the hex strings to make them ethers compatible
     * @returns serialized note
     */
    async serialize(shieldPrivateKey, receiverViewingPublicKey) {
        // Get shared key
        const sharedKey = await (0, keys_utils_1.getSharedSymmetricKey)(shieldPrivateKey, receiverViewingPublicKey);
        if (!sharedKey) {
            throw new Error('Could not generated shared symmetric key for shielding.');
        }
        // Encrypt random
        const encryptedRandom = aes_1.AES.encryptGCM([this.random], sharedKey);
        // Encrypt receiver public key
        const encryptedReceiver = aes_1.AES.encryptCTR([(0, utils_1.bytesToHex)(receiverViewingPublicKey)], shieldPrivateKey);
        const shieldKey = (0, utils_1.bytesToHex)(await (0, utils_2.getPublicViewingKey)(shieldPrivateKey));
        // Construct ciphertext
        const ciphertext = {
            encryptedBundle: [
                bytes_1.ByteUtils.hexlify(`${encryptedRandom.iv}${encryptedRandom.tag}`, true),
                bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.combine([...encryptedRandom.data, encryptedReceiver.iv]), true),
                bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.combine(encryptedReceiver.data), true),
            ],
            shieldKey: bytes_1.ByteUtils.hexlify(shieldKey, true),
        };
        return {
            preimage: {
                npk: bytes_1.ByteUtils.nToHex(this.notePublicKey, bytes_1.ByteLength.UINT_256, true),
                token: this.tokenData,
                value: this.value,
            },
            ciphertext,
        };
    }
}
exports.ShieldNote = ShieldNote;
//# sourceMappingURL=shield-note.js.map