import { AddressData } from '../key-derivation/bech32';
import { Ciphertext, CiphertextXChaCha, LegacyNoteSerialized, NFTTokenData, NoteSerialized, OutputType, TokenData } from '../models/formatted-types';
import { TokenDataGetter } from '../token/token-data-getter';
import { TXIDVersion } from '../models/poi-types';
import { Chain } from '../models/engine-types';
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
export declare class TransactNote {
    readonly receiverAddressData: AddressData;
    readonly senderAddressData: Optional<AddressData>;
    readonly tokenHash: string;
    readonly tokenData: TokenData;
    readonly random: string;
    readonly value: bigint;
    readonly notePublicKey: bigint;
    readonly hash: bigint;
    readonly outputType: Optional<OutputType>;
    readonly walletSource: Optional<string>;
    readonly senderRandom: Optional<string>;
    readonly memoText: Optional<string>;
    readonly shieldFee: Optional<string>;
    readonly blockNumber: Optional<number>;
    /**
     * Create Note object from values
     * @param {BigInt} receiverAddressData - recipient wallet address data
     * @param {string} random - note randomness
     * @param {string} tokenData - note token ID
     * @param {BigInt} value - note value
     */
    private constructor();
    static createTransfer(receiverAddressData: AddressData, senderAddressData: Optional<AddressData>, value: bigint, tokenData: TokenData, showSenderAddressToRecipient: boolean, outputType: OutputType, memoText: Optional<string>): TransactNote;
    static createERC721Transfer(receiverAddressData: AddressData, senderAddressData: Optional<AddressData>, tokenData: NFTTokenData, showSenderAddressToRecipient: boolean, memoText: Optional<string>): TransactNote;
    static createERC1155Transfer(receiverAddressData: AddressData, senderAddressData: Optional<AddressData>, tokenData: NFTTokenData, amount: bigint, showSenderAddressToRecipient: boolean, memoText: Optional<string>): TransactNote;
    static getNoteRandom(): string;
    static getSenderRandom(): string;
    private getNotePublicKey;
    getSenderAddress(): Optional<string>;
    /**
     * Get note hash
     * @returns {bigint} hash
     */
    static getHash(notePublicKey: bigint, tokenHash: string, value: bigint): bigint;
    /**
     * AES-256-GCM encrypts note data
     * @param sharedKey - key to encrypt with
     */
    encryptV2(txidVersion: TXIDVersion, sharedKey: Uint8Array, senderMasterPublicKey: bigint, senderRandom: Optional<string>, viewingPrivateKey: Uint8Array): {
        noteCiphertext: Ciphertext;
        noteMemo: string;
        annotationData: string;
    };
    /**
     * AES-256-GCM encrypts note data
     * @param sharedKey - key to encrypt with
     */
    encryptV3(txidVersion: TXIDVersion, sharedKey: Uint8Array, senderMasterPublicKey: bigint): CiphertextXChaCha;
    private static unblindViewingPublicKey;
    /**
     * AES-256-GCM decrypts note data (V2)
     */
    static decrypt(txidVersion: TXIDVersion, chain: Chain, currentWalletAddressData: AddressData, noteCiphertext: Ciphertext | CiphertextXChaCha, sharedKey: Uint8Array, memoV2: string, annotationData: string, viewingPrivateKey: Uint8Array, blindedReceiverViewingKey: Optional<Uint8Array>, blindedSenderViewingKey: Optional<Uint8Array>, isSentNote: boolean, isLegacyDecryption: boolean, tokenDataGetter: TokenDataGetter, blockNumber: Optional<number>, transactCommitmentBatchIndexV3: Optional<number>): Promise<TransactNote>;
    static getDecodedMasterPublicKey(currentWalletMasterPublicKey: bigint, encodedMasterPublicKey: bigint, senderRandom: Optional<string>, isLegacyDecryption: boolean): bigint;
    static getEncodedMasterPublicKey(senderRandom: Optional<string>, receiverMasterPublicKey: bigint, senderMasterPublicKey: bigint): bigint;
    private static getDecryptedValuesNoteCiphertextV2;
    private static getDecryptedValuesNoteCiphertextV3;
    private static noteFromDecryptedValues;
    private formatFields;
    /**
     * Gets JSON serialized version of note
     * @returns serialized note
     */
    serialize(prefix?: boolean): NoteSerialized;
    serializeLegacy(viewingPrivateKey: Uint8Array, prefix?: boolean): LegacyNoteSerialized;
    static isLegacyTransactNote(noteData: NoteSerialized | LegacyNoteSerialized): boolean;
    /**
     * Creates note from serialized note JSON
     * @param noteData - serialized note data
     * @param viewingPrivateKey - viewing private key for decryption
     * @returns TransactNote
     */
    static deserialize(txidVersion: TXIDVersion, chain: Chain, noteData: NoteSerialized | LegacyNoteSerialized, viewingPrivateKey: Uint8Array, tokenDataGetter: TokenDataGetter): Promise<TransactNote>;
    /**
     * Creates note from serialized note JSON
     * @param noteData - serialized note data
     * @param viewingPrivateKey - viewing private key for decryption
     * @returns TransactNote
     */
    private static deserializeLegacy;
    /**
     * Calculates nullifier for a given note
     * @param nullifyingKey - nullifying key
     * @param leafIndex - Index of note's commitment in the Merkle tree
     * @returns nullifier (hex string)
     */
    static getNullifier(nullifyingKey: bigint, leafIndex: number): bigint;
    newProcessingNoteWithValue(value: bigint): TransactNote;
    static calculateTotalNoteValues: (notes: TransactNote[]) => bigint;
    /**
     * TransactNote with tokenData and value, for a mimic Unshield Note during solution processing.
     * All other fields are placeholders.
     */
    static createNullUnshieldNote(tokenData: TokenData, value: bigint): TransactNote;
}
