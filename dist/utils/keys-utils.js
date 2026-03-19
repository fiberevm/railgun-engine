"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateNaiveRandomHex = exports.unblindNoteKey = exports.getNoteBlindingKeys = exports.adjustBytes25519 = exports.getPrivateScalarFromPrivateKey = exports.getSharedSymmetricKey = exports.verifyED25519 = exports.signED25519 = exports.verifyEDDSA = exports.signEDDSA = exports.getRandomScalar = exports.getPublicViewingKey = exports.getPublicSpendingKey = void 0;
const ed25519_1 = require("@noble/ed25519");
const circomlibjs_1 = require("@railgun-community/circomlibjs");
const poseidon_1 = require("./poseidon");
const bytes_1 = require("./bytes");
const hash_1 = require("./hash");
const scalar_multiply_1 = require("./scalar-multiply");
const { bytesToHex, randomBytes } = ed25519_1.utils;
function getPublicSpendingKey(privateKey) {
    if (privateKey.length !== 32)
        throw Error('Invalid private key length');
    return circomlibjs_1.eddsa.prv2pub(Buffer.from(privateKey));
}
exports.getPublicSpendingKey = getPublicSpendingKey;
async function getPublicViewingKey(privateViewingKey) {
    return (0, ed25519_1.getPublicKey)(privateViewingKey);
}
exports.getPublicViewingKey = getPublicViewingKey;
function getRandomScalar() {
    return bytes_1.ByteUtils.hexToBigInt((0, poseidon_1.poseidonHex)([bytes_1.ByteUtils.fastBytesToHex(randomBytes(32))]));
}
exports.getRandomScalar = getRandomScalar;
function signEDDSA(privateKey, message) {
    return circomlibjs_1.eddsa.signPoseidon(Buffer.from(privateKey), message);
}
exports.signEDDSA = signEDDSA;
function verifyEDDSA(message, signature, pubkey) {
    return circomlibjs_1.eddsa.verifyPoseidon(message, signature, pubkey);
}
exports.verifyEDDSA = verifyEDDSA;
async function signED25519(message, privateKey) {
    return (0, ed25519_1.sign)(message, privateKey);
}
exports.signED25519 = signED25519;
function verifyED25519(message, signature, pubkey) {
    return (0, ed25519_1.verify)(signature, message, pubkey);
}
exports.verifyED25519 = verifyED25519;
/**
 * Adjust bits to match the pattern xxxxx000...01xxxxxx for little endian and 01xxxxxx...xxxxx000 for big endian
 * This ensures that the bytes are a little endian representation of an integer of the form (2^254 + 8) * x where
 * 0 \< x \<= 2^251 - 1, which can be decoded as an X25519 integer.
 *
 * @param bytes - bytes to adjust
 * @param endian - what endian to use
 * @returns adjusted bytes
 */
function adjustBytes25519(bytes, endian) {
    // Create new array to prevent side effects
    const adjustedBytes = new Uint8Array(bytes);
    if (endian === 'be') {
        // BIG ENDIAN
        // AND operation to ensure the last 3 bits of the last byte are 0 leaving the rest unchanged
        adjustedBytes[31] &= 0b11111000;
        // AND operation to ensure the first bit of the first byte is 0 leaving the rest unchanged
        adjustedBytes[0] &= 0b01111111;
        // OR operation to ensure the second bit of the first byte is 0 leaving the rest unchanged
        adjustedBytes[0] |= 0b01000000;
    }
    else {
        // LITTLE ENDIAN
        // AND operation to ensure the last 3 bits of the first byte are 0 leaving the rest unchanged
        adjustedBytes[0] &= 0b11111000;
        // AND operation to ensure the first bit of the last byte is 0 leaving the rest unchanged
        adjustedBytes[31] &= 0b01111111;
        // OR operation to ensure the second bit of the last byte is 0 leaving the rest unchanged
        adjustedBytes[31] |= 0b01000000;
    }
    // Return adjusted bytes
    return adjustedBytes;
}
exports.adjustBytes25519 = adjustBytes25519;
async function getPrivateScalarFromPrivateKey(privateKey) {
    // Private key should be 32 bytes
    if (privateKey.length !== 32)
        throw new Error('Expected 32 bytes');
    // SHA512 hash private key
    const hash = await ed25519_1.utils.sha512(privateKey);
    // Get key head, this is the first 32 bytes of the hash
    // We aren't interested in the rest of the hash as we only want the scalar
    const head = adjustBytes25519(hash.slice(0, 32), 'le');
    // Convert head to scalar
    const scalar = BigInt(`0x${ed25519_1.utils.bytesToHex(head.reverse())}`) % ed25519_1.CURVE.l;
    return scalar > 0n ? scalar : ed25519_1.CURVE.l;
}
exports.getPrivateScalarFromPrivateKey = getPrivateScalarFromPrivateKey;
/**
 * Converts seed to curve scalar
 *
 * @param seed - seed to convert
 * @returns scalar
 */
function seedToScalar(seed) {
    // Hash to 512 bit value as per FIPS-186
    const seedHash = (0, hash_1.sha512)(seed);
    // Return (seedHash mod (n - 1)) + 1 to fit to range 0 < scalar < n
    return bytes_1.ByteUtils.nToBytes((bytes_1.ByteUtils.hexToBigInt(seedHash) % ed25519_1.CURVE.n) - 1n + 1n, 32);
}
/**
 * Generate blinding scalar value.
 * Combine sender and shared random via XOR
 * XOR is used because a 0 value senderRandom result in a no change to the sharedRandom
 * allowing the receiver to invert the blinding operation
 * Final random value is padded to 32 bytes
 * Get blinding scalar from random
 *
 * @param sharedRandom - random value shared by both parties
 * @param senderRandom - random value only known to sender
 * @returns ephemeral keys
 */
function getBlindingScalar(sharedRandom, senderRandom) {
    const finalRandom = bytes_1.ByteUtils.nToBytes(bytes_1.ByteUtils.hexToBigInt(sharedRandom) ^ bytes_1.ByteUtils.hexToBigInt(senderRandom), 32);
    return bytes_1.ByteUtils.bytesToN(seedToScalar(finalRandom));
}
/**
 * Blinds sender and receiver public keys
 *
 * @param senderViewingPublicKey - Sender's viewing public key
 * @param receiverViewingPublicKey - Receiver's viewing public key
 * @param sharedRandom - random value shared by both parties
 * @param senderRandom - random value only known to sender
 * @returns ephemeral keys
 */
function getNoteBlindingKeys(senderViewingPublicKey, receiverViewingPublicKey, sharedRandom, senderRandom) {
    const blindingScalar = getBlindingScalar(sharedRandom, senderRandom);
    // Get public key points
    const senderPublicKeyPoint = ed25519_1.Point.fromHex(senderViewingPublicKey);
    const receiverPublicKeyPoint = ed25519_1.Point.fromHex(receiverViewingPublicKey);
    // Multiply both public keys by blinding scalar
    const blindedSenderViewingKey = senderPublicKeyPoint.multiply(blindingScalar).toRawBytes();
    const blindedReceiverViewingKey = receiverPublicKeyPoint.multiply(blindingScalar).toRawBytes();
    // Return blinded keys
    return { blindedSenderViewingKey, blindedReceiverViewingKey };
}
exports.getNoteBlindingKeys = getNoteBlindingKeys;
function unblindNoteKey(blindedNoteKey, sharedRandom, senderRandom) {
    try {
        const blindingScalar = getBlindingScalar(sharedRandom, senderRandom);
        // Create curve point instance from ephemeral key bytes
        const point = ed25519_1.Point.fromHex(bytesToHex(blindedNoteKey));
        // Invert the scalar to undo blinding multiplication operation
        const inverse = ed25519_1.utils.invert(blindingScalar, ed25519_1.CURVE.n);
        // Unblind by multiplying by the inverted scalar
        const unblinded = point.multiply(inverse);
        return unblinded.toRawBytes();
    }
    catch {
        return undefined;
    }
}
exports.unblindNoteKey = unblindNoteKey;
async function getSharedSymmetricKey(privateKeyPairA, blindedPublicKeyPairB) {
    try {
        // Retrieve private scalar from private key
        const scalar = await getPrivateScalarFromPrivateKey(privateKeyPairA);
        // Multiply ephemeral key by private scalar to get shared key
        const keyPreimage = (0, scalar_multiply_1.scalarMultiplyWasmFallbackToJavascript)(blindedPublicKeyPairB, scalar);
        // SHA256 hash to get the final key
        const hashed = bytes_1.ByteUtils.hexStringToBytes((0, hash_1.sha256)(keyPreimage));
        return hashed;
    }
    catch (err) {
        return undefined;
    }
}
exports.getSharedSymmetricKey = getSharedSymmetricKey;
function generateNaiveRandomHex(length = 16) {
    const CHARSET = 'abcdefghijklnopqrstuvwxyz0123456789';
    let retVal = '';
    for (let i = 0; i < length; i += 1) {
        retVal += CHARSET.charAt(Math.floor(Math.random() * CHARSET.length));
    }
    return retVal;
}
exports.generateNaiveRandomHex = generateNaiveRandomHex;
//# sourceMappingURL=keys-utils.js.map