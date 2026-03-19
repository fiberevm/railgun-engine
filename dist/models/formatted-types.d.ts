import { TXIDVersion } from './poi-types';
export type BytesData = bigint | number | ArrayLike<number> | string;
export type AdaptID = {
    contract: string;
    parameters: string;
};
export type Ciphertext = {
    iv: string;
    tag: string;
    data: string[];
};
export type CiphertextCTR = {
    iv: string;
    data: string[];
};
export declare enum XChaChaEncryptionAlgorithm {
    XChaCha = "XChaCha",
    XChaChaPoly1305 = "XChaChaPoly1305"
}
export type CiphertextXChaCha = {
    algorithm: XChaChaEncryptionAlgorithm;
    nonce: string;
    bundle: string;
};
export declare enum TokenType {
    ERC20 = 0,
    ERC721 = 1,
    ERC1155 = 2
}
export type TransactionReceiptLog = {
    topics: string[];
    data: string;
};
export type TokenData = {
    tokenType: TokenType;
    tokenAddress: string;
    tokenSubID: string;
};
export type NFTTokenData = TokenData & {
    tokenType: TokenType.ERC721 | TokenType.ERC1155;
};
export type EncryptedData = [string, string];
export declare enum CommitmentType {
    LegacyEncryptedCommitment = "LegacyEncryptedCommitment",
    LegacyGeneratedCommitment = "LegacyGeneratedCommitment",
    ShieldCommitment = "ShieldCommitment",
    TransactCommitmentV2 = "TransactCommitmentV2",
    TransactCommitmentV3 = "TransactCommitmentV3"
}
export declare enum OutputType {
    Transfer = 0,
    BroadcasterFee = 1,
    Change = 2
}
export type NoteAnnotationData = {
    outputType: OutputType;
    senderRandom: string;
    walletSource: Optional<string>;
};
export type SenderAnnotationDecrypted = {
    walletSource: Optional<string>;
    outputType: OutputType;
};
export type EncryptedNoteAnnotationData = string;
export type NoteSerialized = {
    npk: string;
    value: string;
    tokenHash: string;
    random: string;
    recipientAddress: string;
    outputType: Optional<OutputType>;
    senderRandom: Optional<string>;
    walletSource: Optional<string>;
    senderAddress: Optional<string>;
    memoText: Optional<string>;
    shieldFee: Optional<string>;
    blockNumber: Optional<number>;
};
export type LegacyNoteSerialized = {
    npk: string;
    value: string;
    tokenHash: string;
    encryptedRandom: [string, string];
    memoField: string[];
    recipientAddress: string;
    memoText: Optional<string>;
    blockNumber: Optional<number>;
};
export type MerkleProof = {
    leaf: string;
    elements: string[];
    indices: string;
    root: string;
};
export type PreImage = {
    npk: string;
    token: TokenData;
    value: string;
};
export type ShieldCiphertext = {
    encryptedBundle: [string, string, string];
    shieldKey: string;
};
export type CommitmentCiphertextV2 = {
    ciphertext: Ciphertext;
    blindedSenderViewingKey: string;
    blindedReceiverViewingKey: string;
    annotationData: string;
    memo: string;
};
export type CommitmentCiphertextV3 = {
    ciphertext: CiphertextXChaCha;
    blindedSenderViewingKey: string;
    blindedReceiverViewingKey: string;
};
type CommitmentShared = {
    commitmentType: CommitmentType;
    hash: string;
    txid: string;
    blockNumber: number;
    timestamp: Optional<number>;
    utxoTree: number;
    utxoIndex: number;
};
export type ShieldCommitment = CommitmentShared & {
    commitmentType: CommitmentType.ShieldCommitment;
    preImage: PreImage;
    encryptedBundle: [string, string, string];
    shieldKey: string;
    fee: Optional<string>;
    from: Optional<string>;
};
export type TransactCommitmentV2 = CommitmentShared & {
    commitmentType: CommitmentType.TransactCommitmentV2;
    ciphertext: CommitmentCiphertextV2;
    railgunTxid: Optional<string>;
};
export type TransactCommitmentV3 = CommitmentShared & {
    commitmentType: CommitmentType.TransactCommitmentV3;
    ciphertext: CommitmentCiphertextV3;
    senderCiphertext: string;
    railgunTxid: Optional<string>;
    transactCommitmentBatchIndex: number;
};
export type UnshieldRailgunTransactionData = {
    tokenData: TokenData;
    toAddress: string;
    value: string;
};
export declare enum RailgunTransactionVersion {
    V2 = "V2",
    V3 = "V3"
}
export type RailgunTransactionV2 = {
    version: RailgunTransactionVersion.V2;
    graphID: string;
    /**
     * Array of commitment hashes (a.k.a. note hashes).
     * See TransactNote.getHash for more details.
     */
    commitments: string[];
    /**
     * Array of nullifiers (i.e. hash of nullifyingKey with leafIndex).
     * See TransactNote.getNullifier for more details.
     */
    nullifiers: string[];
    /**
     * For more details, see hashBoundParamsV2 in src/transaction/bound-params.ts
     * and BoundParamsStruct from the ABI.
     */
    boundParamsHash: string;
    /** EVM block number */
    blockNumber: number;
    /** EVM transaction ID */
    txid: string;
    unshield: Optional<UnshieldRailgunTransactionData>;
    /**
     * Index of the UTXO Merkletree where the "input UTXOs" (UTXOs about to be
     * spent) are located.
     */
    utxoTreeIn: number;
    /**
     * Index of the UTXO Merkletree where the "output UTXOs" (UTXOs about to be
     * created) are located.
     */
    utxoTreeOut: number;
    /**
     * Position in the "tree out" UTXO Merkletree where the new UTXOs are
     * sequentially inserted into.
     */
    utxoBatchStartPositionOut: number;
    timestamp: number;
    verificationHash: string;
};
export type RailgunTransactionV3 = {
    version: RailgunTransactionVersion.V3;
    /**
     * Array of commitment hashes (a.k.a. note hashes).
     * See TransactNote.getHash for more details.
     */
    commitments: string[];
    /**
     * Array of nullifiers (i.e. hash of nullifyingKey with leafIndex).
     * See TransactNote.getNullifier for more details.
     */
    nullifiers: string[];
    /**
     * For more details, see hashBoundParamsV3 in src/transaction/bound-params.ts
     * and BoundParamsStruct from the ABI.
     */
    boundParamsHash: string;
    /** EVM block number */
    blockNumber: number;
    /** EVM transaction ID */
    txid: string;
    unshield: Optional<UnshieldRailgunTransactionData>;
    /**
     * Index of the UTXO Merkletree where the "input UTXOs" (UTXOs about to be
     * spent) are located.
     */
    utxoTreeIn: number;
    /**
     * Index of the UTXO Merkletree where the "output UTXOs" (UTXOs about to be
     * created) are located.
     */
    utxoTreeOut: number;
    /**
     * Position in the "tree out" UTXO Merkletree where the new UTXOs are
     * sequentially inserted into.
     */
    utxoBatchStartPositionOut: number;
    verificationHash: Optional<string>;
};
export type RailgunTransaction = RailgunTransactionV2 | RailgunTransactionV3;
export type RailgunTransactionWithHash = RailgunTransaction & {
    /**
     * The ID of a railgun transaction (RailgunTX) is the poseidon hash of:
     * - poseidon hash of all nullifiers in this RailgunTX
     * - poseidon hash of all commitments in this RailgunTX
     * - boundParamsHash
     */
    railgunTxid: string;
    /**
     * This hash is the poseidon hash of:
     * - railgunTxid
     * - utxoTreeIn (index of the UTXO Merkletree where the input UTXOs are located)
     * - globalTreePosition (position in the "forest" for the output UTXOs)
     */
    hash: string;
};
export type TXIDMerkletreeData = {
    railgunTransaction: RailgunTransactionWithHash;
    currentMerkleProofForTree: MerkleProof;
    currentTxidIndexForTree: number;
};
export type Commitment = ShieldCommitment | TransactCommitmentV2 | TransactCommitmentV3 | LegacyGeneratedCommitment | LegacyEncryptedCommitment;
export type Nullifier = {
    nullifier: string;
    treeNumber: number;
    txid: string;
    blockNumber: number;
};
export type StoredReceiveCommitment = {
    txidVersion: TXIDVersion;
    spendtxid: string | false;
    txid: string;
    timestamp: Optional<number>;
    nullifier: string;
    blockNumber: number;
    decrypted: NoteSerialized | LegacyNoteSerialized;
    senderAddress: Optional<string>;
    commitmentType: CommitmentType;
    blindedCommitment: Optional<string>;
    transactCreationRailgunTxid: Optional<string>;
};
export type StoredSendCommitment = {
    txidVersion: TXIDVersion;
    txid: string;
    timestamp: Optional<number>;
    decrypted: NoteSerialized | LegacyNoteSerialized;
    commitmentType: CommitmentType;
    outputType: Optional<OutputType>;
    walletSource: Optional<string>;
    recipientAddress: string;
    railgunTxid: Optional<string>;
    blindedCommitment: Optional<string>;
};
/**
 * Legacy event types: Pre version 3.
 * Need to support these for legacy notes.
 */
export type LegacyGeneratedCommitment = CommitmentShared & {
    commitmentType: CommitmentType.LegacyGeneratedCommitment;
    preImage: PreImage;
    encryptedRandom: [string, string];
};
export type LegacyCommitmentCiphertext = {
    ciphertext: Ciphertext;
    ephemeralKeys: string[];
    memo: string[];
};
export type LegacyEncryptedCommitment = CommitmentShared & {
    commitmentType: CommitmentType.LegacyEncryptedCommitment;
    ciphertext: LegacyCommitmentCiphertext;
    railgunTxid: Optional<string>;
};
export type CommitmentSummary = {
    commitmentCiphertext: CommitmentCiphertextV2 | CommitmentCiphertextV3;
    commitmentHash: string;
};
export type RelayAdaptShieldERC20Recipient = {
    tokenAddress: string;
    recipientAddress: string;
};
export type RelayAdaptShieldNFTRecipient = {
    nftTokenData: NFTTokenData;
    recipientAddress: string;
};
export {};
