import { Database } from '../database/database';
import { Chain } from '../models/engine-types';
import { MerklerootValidator } from '../models/merkletree-types';
import { Merkletree } from './merkletree';
import { TXIDMerkletreeData, RailgunTransactionWithHash } from '../models/formatted-types';
import { TXIDVersion } from '../models';
export declare class TXIDMerkletree extends Merkletree<RailgunTransactionWithHash> {
    protected merkletreePrefix: string;
    protected merkletreeType: string;
    shouldStoreMerkleroots: boolean;
    private constructor();
    /**
     * Creates a TXIDMerkletree for wallet use.
     */
    static createForWallet(db: Database, chain: Chain, txidVersion: TXIDVersion, merklerootValidator: MerklerootValidator): Promise<TXIDMerkletree>;
    /**
     * Gets Railgun Transaction data from txid tree.
     */
    getRailgunTransaction(tree: number, index: number): Promise<Optional<RailgunTransactionWithHash>>;
    getGlobalUTXOTreePositionForRailgunTransactionCommitment(tree: number, index: number, commitmentHash: string): Promise<number>;
    getRailgunTxidCurrentMerkletreeData(railgunTxid: string): Promise<TXIDMerkletreeData>;
    railgunTxidOccurredBeforeBlockNumber(tree: number, index: number, blockNumber: number): Promise<boolean>;
    getLatestRailgunTransaction(): Promise<Optional<RailgunTransactionWithHash>>;
    queueRailgunTransactions(railgunTransactionsWithTxids: RailgunTransactionWithHash[], maxTxidIndex: Optional<number>): Promise<void>;
    static isOutOfBounds(tree: number, index: number, maxTxidIndex?: number): boolean;
    static nextTreeAndIndex(tree: number, index: number): {
        tree: number;
        index: number;
    };
    clearLeavesForInvalidVerificationHash(numLeavesToClear: number): Promise<void>;
    clearLeavesAfterTxidIndex(txidIndex: number): Promise<void>;
    getCurrentTxidIndex(): Promise<number>;
    protected validRootCallback(): Promise<void>;
    protected invalidRootCallback(): Promise<void>;
    private getRailgunTxidLookupDBPath;
    getTxidIndexByRailgunTxid(railgunTxid: string): Promise<Optional<number>>;
    getRailgunTransactionByTxid(railgunTxid: string): Promise<Optional<RailgunTransactionWithHash>>;
    private getHistoricalMerklerootDBPath;
    protected newLeafRootTrigger(tree: number, index: number, leaf: string, merkleroot: string): Promise<void>;
    getHistoricalMerkleroot(tree: number, index: number): Promise<Optional<string>>;
    getHistoricalMerklerootForTxidIndex(txidIndex: number): Promise<Optional<string>>;
}
