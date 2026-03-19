"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getNoteBlindingKeysLegacy = exports.unblindNoteKeyLegacy = exports.getSharedSymmetricKeyLegacy = void 0;
const ed25519_1 = require("@noble/ed25519");
const utils_1 = require("ethereum-cryptography/utils");
const bytes_1 = require("./bytes");
const hash_1 = require("./hash");
const keys_utils_1 = require("./keys-utils");
const scalar_multiply_1 = require("./scalar-multiply");
function normalizeRandomLegacy(random) {
    // Hash with sha256 to get a uniform random 32 bytes of data
    const randomArray = bytes_1.ByteUtils.hexToBytes((0, hash_1.sha256)(random));
    // NOTE: The bits adjustment is no longer required to function as an X25519 integer is not used
    // These steps are still taken to preserve compatibility with older transactions
    const adjustedBytes = (0, keys_utils_1.adjustBytes25519)(randomArray, 'le');
    // Return mod n to fit to curve point
    return BigInt(`0x${(0, utils_1.bytesToHex)(adjustedBytes)}`) % ed25519_1.CURVE.n;
}
function getCommitmentBlindingKeyLegacy(random, senderRandom) {
    // XOR public and spender blinding key to get commitment blinding key
    // XOR is used because a 0 value on the sender blinding key will result in identical public and
    // commitment blinding keys, allowing the receiver to reverse the multiplier operation
    const commitmentBlindingKey = bytes_1.ByteUtils.hexToBigInt(random) ^ bytes_1.ByteUtils.hexToBigInt(senderRandom);
    const commitmentBlindingKeyHex = bytes_1.ByteUtils.nToHex(commitmentBlindingKey, bytes_1.ByteLength.UINT_256);
    // Adjust random value to use as blinding key to prevent external observers from being able to
    // reverse the multiplication. The random value here is a value only known to the sender and
    // receiver
    const commitmentBlindingKeyNormalized = normalizeRandomLegacy(commitmentBlindingKeyHex);
    // For each blinding operation both sender and receiver public viewing keys must be multiplied by
    // the same value to preserve symmetry in relation to the respective private key to allow shared
    // key generation
    return commitmentBlindingKeyNormalized;
}
function unblindNoteKeyLegacy(ephemeralKey, random, senderRandom) {
    try {
        const commitmentBlindingKey = getCommitmentBlindingKeyLegacy(random, senderRandom);
        // Create curve point instance from ephemeral key bytes
        const point = ed25519_1.Point.fromHex((0, utils_1.bytesToHex)(ephemeralKey));
        // Invert the scalar to undo blinding multiplication operation
        const inverse = ed25519_1.utils.invert(commitmentBlindingKey, ed25519_1.CURVE.n);
        // Unblind by multiplying by the inverted scalar
        const unblinded = point.multiply(inverse);
        return unblinded.toRawBytes();
    }
    catch {
        return undefined;
    }
}
exports.unblindNoteKeyLegacy = unblindNoteKeyLegacy;
function getNoteBlindingKeysLegacy(senderViewingPublicKey, receiverViewingPublicKey, random, senderBlindingKey) {
    const commitmentBlindingKey = getCommitmentBlindingKeyLegacy(random, senderBlindingKey);
    // Multiply both sender and receiver viewing public keys with the public blinding key
    // The pub blinding key is only known to the sender and receiver preventing external
    // observers from being able to invert and retrieve the original value
    const ephemeralKeyReceiver = ed25519_1.Point.fromHex((0, utils_1.bytesToHex)(senderViewingPublicKey))
        .multiply(commitmentBlindingKey)
        .toRawBytes();
    const ephemeralKeySender = ed25519_1.Point.fromHex((0, utils_1.bytesToHex)(receiverViewingPublicKey))
        .multiply(commitmentBlindingKey)
        .toRawBytes();
    // Return blinded keys
    return [ephemeralKeyReceiver, ephemeralKeySender];
}
exports.getNoteBlindingKeysLegacy = getNoteBlindingKeysLegacy;
async function getSharedSymmetricKeyLegacy(privateKeyPairA, blindedPublicKeyPairB) {
    try {
        // Retrieve private scalar from private key
        const scalar = await (0, keys_utils_1.getPrivateScalarFromPrivateKey)(privateKeyPairA);
        // Multiply ephemeral key by private scalar to get shared key
        return (0, scalar_multiply_1.scalarMultiplyWasmFallbackToJavascript)(blindedPublicKeyPairB, scalar);
    }
    catch (err) {
        return undefined;
    }
}
exports.getSharedSymmetricKeyLegacy = getSharedSymmetricKeyLegacy;
//# sourceMappingURL=keys-utils-legacy.js.map