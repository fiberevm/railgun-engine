declare function unblindNoteKeyLegacy(ephemeralKey: Uint8Array, random: string, senderRandom: string): Optional<Uint8Array>;
declare function getNoteBlindingKeysLegacy(senderViewingPublicKey: Uint8Array, receiverViewingPublicKey: Uint8Array, random: string, senderBlindingKey: string): [Uint8Array, Uint8Array];
declare function getSharedSymmetricKeyLegacy(privateKeyPairA: Uint8Array, blindedPublicKeyPairB: Uint8Array): Promise<Optional<Uint8Array>>;
export { getSharedSymmetricKeyLegacy, unblindNoteKeyLegacy, getNoteBlindingKeysLegacy };
