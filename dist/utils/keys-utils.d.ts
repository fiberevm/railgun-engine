/// <reference path="../../src/types/global.d.ts" />
import { Signature } from '@railgun-community/circomlibjs';
declare function getPublicSpendingKey(privateKey: Uint8Array): [bigint, bigint];
declare function getPublicViewingKey(privateViewingKey: Uint8Array): Promise<Uint8Array>;
declare function getRandomScalar(): bigint;
declare function signEDDSA(privateKey: Uint8Array, message: bigint): Signature;
declare function verifyEDDSA(message: bigint, signature: Signature, pubkey: [bigint, bigint]): boolean;
declare function signED25519(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
declare function verifyED25519(message: string | Uint8Array, signature: string | Uint8Array, pubkey: Uint8Array): Promise<boolean>;
/**
 * Adjust bits to match the pattern xxxxx000...01xxxxxx for little endian and 01xxxxxx...xxxxx000 for big endian
 * This ensures that the bytes are a little endian representation of an integer of the form (2^254 + 8) * x where
 * 0 \< x \<= 2^251 - 1, which can be decoded as an X25519 integer.
 *
 * @param bytes - bytes to adjust
 * @param endian - what endian to use
 * @returns adjusted bytes
 */
declare function adjustBytes25519(bytes: Uint8Array, endian: 'be' | 'le'): Uint8Array;
declare function getPrivateScalarFromPrivateKey(privateKey: Uint8Array): Promise<bigint>;
/**
 * Blinds sender and receiver public keys
 *
 * @param senderViewingPublicKey - Sender's viewing public key
 * @param receiverViewingPublicKey - Receiver's viewing public key
 * @param sharedRandom - random value shared by both parties
 * @param senderRandom - random value only known to sender
 * @returns ephemeral keys
 */
declare function getNoteBlindingKeys(senderViewingPublicKey: Uint8Array, receiverViewingPublicKey: Uint8Array, sharedRandom: string, senderRandom: string): {
    blindedSenderViewingKey: Uint8Array;
    blindedReceiverViewingKey: Uint8Array;
};
declare function unblindNoteKey(blindedNoteKey: Uint8Array, sharedRandom: string, senderRandom: string): Optional<Uint8Array>;
declare function getSharedSymmetricKey(privateKeyPairA: Uint8Array, blindedPublicKeyPairB: Uint8Array): Promise<Optional<Uint8Array>>;
declare function generateNaiveRandomHex(length?: number): string;
export { getPublicSpendingKey, getPublicViewingKey, getRandomScalar, signEDDSA, verifyEDDSA, signED25519, verifyED25519, getSharedSymmetricKey, getPrivateScalarFromPrivateKey, adjustBytes25519, getNoteBlindingKeys, unblindNoteKey, generateNaiveRandomHex, };
