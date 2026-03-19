/// <reference types="node" />
import type { AbstractLevelDOWN } from 'abstract-leveldown';
import EventEmitter from 'events';
import { FallbackProvider } from 'ethers';
import { RailgunSmartWalletContract } from './contracts/railgun-smart-wallet/V2/railgun-smart-wallet';
import { RelayAdaptV2Contract } from './contracts/relay-adapt/V2/relay-adapt-v2';
import { Database } from './database/database';
import { Prover } from './prover/prover';
import { encodeAddress, decodeAddress } from './key-derivation/bech32';
import { RailgunWallet } from './wallet/railgun-wallet';
import { Chain, EngineDebugger } from './models/engine-types';
import { LegacyGeneratedCommitment, ShieldCommitment } from './models/formatted-types';
import { GetLatestValidatedRailgunTxid, QuickSyncEvents, QuickSyncRailgunTransactionsV2 } from './models/event-types';
import { ViewOnlyWallet } from './wallet/view-only-wallet';
import { AbstractWallet } from './wallet/abstract-wallet';
import { ArtifactGetter } from './models/prover-types';
import { PollingJsonRpcProvider } from './provider/polling-json-rpc-provider';
import { UTXOMerkletree } from './merkletree/utxo-merkletree';
import { TXIDMerkletree } from './merkletree/txid-merkletree';
import { MerklerootValidator } from './models/merkletree-types';
import { TXIDVersion } from './models/poi-types';
import { Registry } from './utils/registry';
declare class RailgunEngine extends EventEmitter {
    readonly db: Database;
    private readonly utxoMerkletrees;
    private readonly txidMerkletrees;
    readonly prover: Prover;
    readonly wallets: {
        [key: string]: AbstractWallet;
    };
    readonly deploymentBlocks: Registry<number>;
    readonly quickSyncEvents: QuickSyncEvents;
    readonly quickSyncRailgunTransactionsV2: QuickSyncRailgunTransactionsV2;
    readonly validateRailgunTxidMerkleroot: MerklerootValidator;
    readonly getLatestValidatedRailgunTxid: GetLatestValidatedRailgunTxid;
    static walletSource: Optional<string>;
    private readonly skipMerkletreeScans;
    private readonly hasSyncedRailgunTransactionsV2;
    private constructor();
    /**
     * Create a RAILGUN Engine instance for a RAILGUN-compatible Wallet.
     * @param walletSource - string representing your wallet's name (16 char max, lowercase and numerals only)
     * @param leveldown - abstract-leveldown compatible store
     * @param artifactGetter - async function to retrieve artifacts
     * @param quickSync - quick sync function to speed up sync
     * @param engineDebugger - log and error callbacks for verbose logging
     * @param skipMerkletreeScans - whether to skip UTXO merkletree scans - useful for shield-only interfaces without Railgun wallets.
     */
    static initForWallet(walletSource: string, leveldown: AbstractLevelDOWN, artifactGetter: ArtifactGetter, quickSyncEvents: QuickSyncEvents, quickSyncRailgunTransactionsV2: QuickSyncRailgunTransactionsV2, validateRailgunTxidMerkleroot: MerklerootValidator, getLatestValidatedRailgunTxid: GetLatestValidatedRailgunTxid, engineDebugger: Optional<EngineDebugger>, skipMerkletreeScans?: boolean): Promise<RailgunEngine>;
    static setEngineDebugger: (engineDebugger: EngineDebugger) => void;
    /**
     * Handle new commitment events and kick off balance scan on wallets
     * @param chain - chain type/id for commitments
     * @param treeNumber - tree of commitments
     * @param startingIndex - starting index of commitments
     * @param leaves - commitment data from events
     */
    private commitmentListener;
    private triggerDelayedTXIDMerkletreeSyncV2;
    /**
     * Handle new nullifiers
     * @param chain - chain type/id for nullifiers
     * @param nullifiers - transaction info to nullify commitment
     */
    private nullifierListener;
    /**
     * Handle new unshield events
     * @param chain - chain type/id
     * @param unshields - unshield events
     */
    private unshieldListener;
    /**
     * Handle new railgun transaction events for V3
     * @param chain - chain type/id
     * @param railgunTransactions - railgun transaction events
     */
    private railgunTransactionsV3Listener;
    private getMostRecentValidCommitmentBlock;
    private getStartScanningBlock;
    private performQuickSync;
    private emitUTXOMerkletreeScanUpdateEvent;
    private emitTXIDMerkletreeScanUpdateEvent;
    private getNextStartingBlockSlowScan;
    /**
     * Scan contract history and sync
     * @param chain - chain type/id to scan
     * @param walletIdFilter - optional list of wallet ids to decrypt balances
     */
    scanContractHistory(chain: Chain, walletIdFilter: Optional<string[]>): Promise<void>;
    /**
     * Scan (via quick sync or slow sync) on-chain data for the UTXO merkletree.
     */
    private scanUTXOHistory;
    emitScanEventHistoryComplete(txidVersion: TXIDVersion, chain: Chain): void;
    private slowSyncV2;
    private slowSyncV3;
    /**
     * Scan subgraph data for railgun transactions to build the TXID merkletree.
     */
    private scanTXIDHistoryV2;
    /**
     * Sync Railgun txid merkletree.
     * @param chain - chain type/id to scan
     */
    syncRailgunTransactionsV2(chain: Chain, trigger: string): Promise<void>;
    private shouldAddNewRailgunTransactions;
    private getLatestValidatedTxidIndex;
    private performSyncRailgunTransactionsV2;
    private handleNewRailgunTransactionsV2;
    private handleNewRailgunTransactionsV3;
    getLatestRailgunTxidData(txidVersion: TXIDVersion, chain: Chain): Promise<{
        txidIndex: number;
        merkleroot: string;
    }>;
    /**
     * Clears all merkletree leaves stored in database.
     * @param chain - chain type/id to clear
     */
    private clearSyncedUTXOMerkletreeLeavesAllTXIDVersions;
    private clearUTXOMerkletreeAndLoadedWalletsAllTXIDVersions;
    private clearSyncedUnshieldEvents;
    private clearTXIDMerkletree;
    /**
     * Clears stored merkletree leaves and wallet balances, and re-scans fully.
     * @param chain - chain type/id to rescan
     * @param forceRescanDevOnly - can corrupt an existing scan, so only recommended in extreme cases (DEV only)
     */
    fullRescanUTXOMerkletreesAndWallets(chain: Chain, walletIdFilter: Optional<string[]>, forceRescanDevOnly?: boolean): Promise<void>;
    fullResetTXIDMerkletreesV2(chain: Chain): Promise<void>;
    private clearTXIDMerkletreeData;
    resetRailgunTxidsAfterTxidIndex(txidVersion: TXIDVersion, chain: Chain, txidIndex: number): Promise<void>;
    private static validateMerkleroot;
    /**
     * Load network
     * @param railgunSmartWalletContractAddress - address of railgun instance (proxy contract)
     * @param relayAdaptV2ContractAddress - address of railgun instance (proxy contract)
     * @param provider - ethers provider for network
     * @param deploymentBlock - block number to start scanning from
     */
    loadNetwork(chain: Chain, railgunSmartWalletContractAddress: string, relayAdaptV2ContractAddress: string, poseidonMerkleAccumulatorV3Address: string, poseidonMerkleVerifierV3Address: string, tokenVaultV3Address: string, defaultProvider: PollingJsonRpcProvider | FallbackProvider, pollingProvider: PollingJsonRpcProvider, deploymentBlocks: Record<TXIDVersion, number>, supportsV3: boolean): Promise<void>;
    /**
     * Unload network
     * @param chain - chainID of network to unload
     */
    private unloadNetwork;
    private static getLastSyncedBlockDBPrefix;
    /**
     * Sets last synced block to resume syncing on next load.
     * @param chain - chain type/id to store value for
     * @param lastSyncedBlock - last synced block
     */
    private setLastSyncedBlock;
    /**
     * Gets last synced block to resume syncing from.
     * @param chain - chain type/id to get value for
     * @returns lastSyncedBlock - last synced block
     */
    private getLastSyncedBlock;
    private static getUTXOMerkletreeHistoryVersionDBPrefix;
    private static getTxidV2MerkletreeHistoryVersionDBPrefix;
    private setUTXOMerkletreeHistoryVersion;
    private getUTXOMerkletreeHistoryVersion;
    private setTxidV2MerkletreeHistoryVersion;
    private getTxidV2MerkletreeHistoryVersion;
    getUTXOMerkletree(txidVersion: TXIDVersion, chain: Chain): UTXOMerkletree;
    private hasUTXOMerkletree;
    getTXIDMerkletree(txidVersion: TXIDVersion, chain: Chain): TXIDMerkletree;
    private hasTXIDMerkletree;
    getCompletedTxidFromNullifiers(txidVersion: TXIDVersion, chain: Chain, nullifiers: string[]): Promise<Optional<string>>;
    private decryptBalancesAllWallets;
    private invalidateTXOsCacheAllWallets;
    private allWallets;
    /**
     * Unload wallet
     * @param id - wallet id to unload
     */
    unloadWallet(id: string): void;
    /**
     * Unloads wallets, removes listeners and closes DB.
     */
    unload(): Promise<void>;
    private loadWallet;
    /**
     * Load existing wallet
     * @param {string} encryptionKey - encryption key of wallet
     * @param {string} id - wallet ID
     * @returns id
     */
    loadExistingWallet(encryptionKey: string, id: string): Promise<RailgunWallet>;
    /**
     * Load existing wallet
     * @param {string} encryptionKey - encryption key of wallet
     * @param {string} id - wallet ID
     * @returns id
     */
    loadExistingViewOnlyWallet(encryptionKey: string, id: string): Promise<ViewOnlyWallet>;
    deleteWallet(id: string): Promise<void>;
    /**
     * Creates wallet from mnemonic
     * @param {string} encryptionKey - encryption key of wallet
     * @param {string} mnemonic - mnemonic to load
     * @param {number} index - derivation index to load
     * @returns id
     */
    createWalletFromMnemonic(encryptionKey: string, mnemonic: string, index?: number, creationBlockNumbers?: Optional<number[][]>): Promise<RailgunWallet>;
    createViewOnlyWalletFromShareableViewingKey(encryptionKey: string, shareableViewingKey: string, creationBlockNumbers: Optional<number[][]>): Promise<ViewOnlyWallet>;
    getAllShieldCommitments(txidVersion: TXIDVersion, chain: Chain, startingBlock: number): Promise<(ShieldCommitment | LegacyGeneratedCommitment)[]>;
    static encodeAddress: typeof encodeAddress;
    static decodeAddress: typeof decodeAddress;
    railgunSmartWalletContracts: Registry<RailgunSmartWalletContract>;
    relayAdaptV2Contracts: Registry<RelayAdaptV2Contract>;
}
export { RailgunEngine };
