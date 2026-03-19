/// <reference path="../../src/types/global.d.ts" />
/// <reference types="node" />
import { Signature } from '@railgun-community/circomlibjs';
import EventEmitter from 'events';
import { ContractTransaction } from 'ethers';
import { Database } from '../database/database';
import { SpendingPublicKey, ViewingKeyPair } from '../key-derivation/wallet-node';
import { UnshieldStoredEvent } from '../models/event-types';
import { BytesData, Commitment } from '../models/formatted-types';
import { TXO, WalletBalanceBucket } from '../models/txo-types';
import { AddressKeys, TokenBalancesAllTxidVersions, TotalBalancesByTreeNumber, TokenBalances, TransactionHistoryEntry, TreeBalance, ViewOnlyWalletData, WalletData, WalletDetails, WalletDetailsMap } from '../models/wallet-types';
import { Chain } from '../models/engine-types';
import { PublicInputsRailgun } from '../models/prover-types';
import { UTXOMerkletree } from '../merkletree/utxo-merkletree';
import { TXIDMerkletree } from '../merkletree/txid-merkletree';
import { TXIDVersion } from '../models/poi-types';
import { Prover } from '../prover/prover';
declare abstract class AbstractWallet extends EventEmitter {
    protected readonly db: Database;
    private readonly tokenDataGetter;
    readonly id: string;
    readonly viewingKeyPair: ViewingKeyPair;
    readonly masterPublicKey: bigint;
    private readonly spendingPublicKey;
    readonly nullifyingKey: bigint;
    private readonly utxoMerkletrees;
    private readonly txidMerkletrees;
    private readonly prover;
    private readonly isClearingBalances;
    private readonly decryptBalancesKeyForChain;
    private creationBlockNumbers;
    private receiveCommitmentsCache;
    private sentCommitmentsCache;
    /**
     * Create Wallet controller
     * @param id - wallet ID
     * @param db - database
     */
    constructor(id: string, db: Database, viewingKeyPair: ViewingKeyPair, spendingPublicKey: SpendingPublicKey, creationBlockNumbers: Optional<number[][]>, prover: Prover);
    /**
     * Loads utxo merkle tree into wallet
     */
    loadUTXOMerkletree(txidVersion: TXIDVersion, utxoMerkletree: UTXOMerkletree): Promise<void>;
    /**
     * Unload utxo merkle tree by chain
     */
    unloadUTXOMerkletree(txidVersion: TXIDVersion, chain: Chain): void;
    /**
     * Loads txid merkle tree into wallet
     */
    loadRailgunTXIDMerkletree(txidVersion: TXIDVersion, txidMerkletree: TXIDMerkletree): void;
    /**
     * Unload txid merkle tree by chain
     */
    unloadRailgunTXIDMerkletree(txidVersion: TXIDVersion, chain: Chain): void;
    private getUTXOMerkletreeHistoryVersionDBPrefix;
    setUTXOMerkletreeHistoryVersion(chain: Chain, merkletreeHistoryVersion: number): Promise<void>;
    getUTXOMerkletreeHistoryVersion(chain: Chain): Promise<Optional<number>>;
    /**
     * Construct DB TXO path from chain
     * Prefix consists of ['wallet', id, chain]
     * May be appended with tree and position
     * @param chain - chain type/id
     * @optional tree - without this param, all trees
     * @optional position - without this param, all positions
     * @returns wallet DB prefix
     */
    getWalletDBPrefix(chain: Chain, tree?: number, position?: number): string[];
    /**
     * Construct DB received commitment path from chain
     * Prefix consists of ['wallet', id, chain]
     */
    getWalletReceiveCommitmentDBPrefix(chain: Chain, tree: number, position: number): string[];
    /**
     * Construct DB spent commitment path from chain
     * Prefix consists of ['wallet', id + "-spent", chain]
     * May be appended with tree and position
     * @param chain - chain type/id
     * @optional tree - without this param, all trees
     * @optional position - without this param, all positions
     * @returns wallet DB prefix
     */
    getWalletSentCommitmentDBPrefix(chain: Chain, tree?: number, position?: number): string[];
    /**
     * Construct DB path from chain
     * @returns wallet DB path
     */
    getWalletDetailsPath(chain: Chain): string[];
    /**
     * Return object of Viewing privateKey and pubkey
     * @returns {ViewingKeyPair}
     */
    getViewingKeyPair(): ViewingKeyPair;
    /**
     * Used only to sign Broadcaster fee messages.
     * Verified using Broadcaster's viewingPublicKey, which is encoded in its rail address.
     * @param {Uint8Array} message - message to sign as Uint8Array
     */
    signWithViewingKey(message: Uint8Array): Promise<Uint8Array>;
    /**
     * Nullifying Key (ie poseidon hash of Viewing Private Key) aka vpk derived on ed25519 curve
     * Used to decrypt and nullify notes
     * @returns {bigint}
     */
    getNullifyingKey(): bigint;
    /**
     * Get Viewing Public Key (VK)
     * @returns {Uint8Array}
     */
    get viewingPublicKey(): Uint8Array;
    /**
     * Return masterPublicKey and viewingPublicKey used to encode RAILGUN addresses
     * @returns {AddressKeys}
     */
    get addressKeys(): AddressKeys;
    /**
     * Encode address from (MPK, VK) + chain
     * @returns {string} bech32 encoded RAILGUN address
     */
    getAddress(chain?: Chain): string;
    getWalletDetailsMap(chain: Chain): Promise<WalletDetailsMap>;
    /**
     * Get encrypted wallet details for this wallet
     * @param chain - chain type/id
     * @returns walletDetails - including treeScannedHeight
     */
    getWalletDetails(txidVersion: TXIDVersion, chain: Chain): Promise<WalletDetails>;
    private decryptLeaf;
    private static getCommitmentType;
    private createScannedDBCommitments;
    /**
     * Scans wallet at index for new balances
     * Commitment index in array should be same as commitment index in tree
     * @param {Commitment[]} leaves - commitments from events to attempt parsing
     * @param {number} tree - tree number we're scanning
     * @param {number} chain - chain type/id we're scanning
     * @param {number} startScanHeight - starting position
     */
    scanLeaves(txidVersion: TXIDVersion, leaves: Optional<Commitment>[], tree: number, chain: Chain, startScanHeight: number, scanTicker: Optional<() => void>): Promise<void>;
    private keySplits;
    private queryAllStoredReceiveCommitments;
    private queryAllStoredSendCommitments;
    /**
     * Clears commitments cache
     */
    invalidateCommitmentsCache(chain: Chain): void;
    /**
     * Get TXOs list of a chain
     * @param chain - chain type/id to get UTXOs for
     * @returns UTXOs list
     */
    TXOs(txidVersion: TXIDVersion, chain: Chain): Promise<TXO[]>;
    /**
     * Get spent commitments of a chain
     * @param chain - chain type/id to get spent commitments for
     * @returns SentCommitment list
     */
    private getSentCommitments;
    private updateReceiveCommitmentInDB;
    private updateSentCommitmentInDB;
    getSpendableReceivedChainTxids(txidVersion: TXIDVersion, chain: Chain): Promise<string[]>;
    private static getPossibleChangeTokenAmounts;
    /**
     * Gets transactions history
     * @param chain - chain type/id to get transaction history for
     * @returns history
     */
    getTransactionHistory(chain: Chain, startingBlock: Optional<number>): Promise<TransactionHistoryEntry[]>;
    private getTransactionHistoryByTXIDVersion;
    private static filterTXOsByBlockNumber;
    extractFirstNoteERC20AmountMap(txidVersion: TXIDVersion, chain: Chain, transactionRequest: ContractTransaction, useRelayAdapt: boolean, contractAddress: string): Promise<Record<string, bigint>>;
    /**
     * Gets transactions history for "received" transactions
     * @param chain - chain type/id to get balances for
     * @returns history
     */
    private static getTransactionReceiveHistory;
    private static getTransactionHistoryItemVersion;
    /**
     * NOTE: There are no Unshield events pre-V2.
     */
    getUnshieldEventsFromSpentNullifiers(txidVersion: TXIDVersion, chain: Chain, filteredTXOs: TXO[]): Promise<UnshieldStoredEvent[]>;
    private static compareUnshieldEvents;
    private getTransactionSpendHistory;
    getUTXOMerkletree(txidVersion: TXIDVersion, chain: Chain): UTXOMerkletree;
    private hasUTXOMerkletree;
    getRailgunTXIDMerkletreeForChain(txidVersion: TXIDVersion, chain: Chain): TXIDMerkletree;
    getTokenBalancesAllTxidVersions(chain: Chain, balanceBucketFilter: WalletBalanceBucket[]): Promise<TokenBalancesAllTxidVersions>;
    getTokenBalances(txidVersion: TXIDVersion, chain: Chain, onlySpendable: boolean): Promise<TokenBalances>;
    getTokenBalancesForUnshieldToOrigin(txidVersion: TXIDVersion, chain: Chain, originShieldTxidForSpendabilityOverride?: string): Promise<TokenBalances>;
    getTokenBalancesByBucket(txidVersion: TXIDVersion, chain: Chain): Promise<Record<WalletBalanceBucket, TokenBalances>>;
    /**
     * Gets wallet balances
     * @param chain - chain type/id to get balances for
     * @returns balances
     */
    static getTokenBalancesByTxidVersion(TXOs: TXO[], balanceBucketFilter: WalletBalanceBucket[], originShieldTxidForSpendabilityOverride?: string): Promise<TokenBalances>;
    getBalanceERC20(txidVersion: TXIDVersion, chain: Chain, tokenAddress: string, balanceBucketFilter: WalletBalanceBucket[]): Promise<Optional<bigint>>;
    /**
     * Sort token balances by tree
     * @param chain - chain type/id of token
     * @returns balances by tree
     */
    getTotalBalancesByTreeNumber(txidVersion: TXIDVersion, chain: Chain, balanceBucketFilter: WalletBalanceBucket[], originShieldTxidForSpendabilityOverride?: string): Promise<TotalBalancesByTreeNumber>;
    balancesByTreeForToken(txidVersion: TXIDVersion, chain: Chain, tokenHash: string, balanceBucketFilter: WalletBalanceBucket[], originShieldTxidForSpendabilityOverride?: string): Promise<TreeBalance[]>;
    static tokenBalanceAcrossAllTrees(treeSortedBalances: TreeBalance[]): bigint;
    decryptBalances(txidVersion: TXIDVersion, chain: Chain, progressCallback: Optional<(progress: number) => void>, deferCompletionEvent: boolean): Promise<void>;
    /**
     * Searches for creation tree height for given merkletree based on creationBlockNumber.
     * Will return the latest position that is <= creationBlockNumber. May return an index that has blockNumber < creationBlockNumber,
     * but that is okay for purposes of creationTreeHeight. We just need to guarantee we don't return a position that misses some commitments in the creation block.
     * @param merkletree - Merkletree
     * @param latestTree - number
     */
    static getCreationTreeAndPosition(utxoMerkletree: UTXOMerkletree, latestTree: number, creationBlockNumber: number): Promise<Optional<{
        tree: number;
        position: number;
    }>>;
    /**
     * @warning This method is ONLY intended for testing purposes.
     */
    testSpecificSetCreationBlockNumbers(creationBlockNumbers: Optional<number[][]>): void;
    /**
     * Clears balances decrypted from merkletrees and stored to database.
     * @param chain - chain type/id to clear
     */
    clearDecryptedBalancesAllTXIDVersions(chain: Chain): Promise<void>;
    /**
     * Clears stored balances and re-decrypts fully.
     * @param chain - chain type/id to rescan
     */
    fullRedecryptBalancesAllTXIDVersions(chain: Chain, progressCallback: Optional<(progress: number) => void>): Promise<void>;
    abstract sign(publicInputs: PublicInputsRailgun, encryptionKey: string): Promise<Signature>;
    static dbPath(id: string): BytesData[];
    static read(db: Database, id: string, encryptionKey: string): Promise<WalletData | ViewOnlyWalletData>;
    static write(db: Database, id: string, encryptionKey: string, data: WalletData | ViewOnlyWalletData): Promise<void>;
    static delete(db: Database, id: string): Promise<void>;
    /**
     * Loads encrypted wallet data from database.
     * @param db - database
     * @param encryptionKey - encryption key to use with database
     * @param id - wallet id
     */
    static getEncryptedData(db: Database, encryptionKey: string, id: string): Promise<WalletData | ViewOnlyWalletData>;
    static getKeysFromShareableViewingKey(shareableViewingKey: string): {
        viewingPrivateKey: string;
        spendingPublicKey: SpendingPublicKey;
    };
    generateShareableViewingKey(): string;
}
export { AbstractWallet };
