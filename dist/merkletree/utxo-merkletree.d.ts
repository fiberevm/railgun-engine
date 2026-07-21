import { Database } from '../database/database';
import { Chain } from '../models/engine-types';
import { MerklerootValidator } from '../models/merkletree-types';
import { Merkletree } from './merkletree';
import { Commitment, Nullifier, NullifierSpendMetadata } from '../models/formatted-types';
import { UnshieldStoredEvent } from '../models/event-types';
import { TXIDVersion } from '../models';
export declare class UTXOMerkletree extends Merkletree<Commitment> {
    protected merkletreePrefix: string;
    protected merkletreeType: string;
    private constructor();
    static create(db: Database, chain: Chain, txidVersion: TXIDVersion, merklerootValidator: MerklerootValidator): Promise<UTXOMerkletree>;
    /**
     * Gets Commitment from UTXO tree
     */
    getCommitment(tree: number, index: number): Promise<Commitment>;
    getCommitmentRange(tree: number, start: number, end: number): Promise<Commitment[]>;
    /**
     * Gets Commitment from UTXO tree
     */
    getCommitmentSafe(tree: number, index: number): Promise<Optional<Commitment>>;
    /**
     * Construct DB path from nullifier
     * @param tree - tree nullifier is for
     * @param nullifier - nullifier to get path for
     * @returns database path
     */
    getNullifierDBPath(tree: number, nullifier: string): string[];
    /** Stores spend height separately so existing nullifier txid records stay backward-compatible. */
    getNullifierSpendBlockDBPath(tree: number, nullifier: string): string[];
    private getNullifierBlockIndexDBPrefix;
    private getNullifierBlockIndexDBPath;
    /**
     * Construct DB path from unshield transaction
     * @param txid - unshield txid to get path for
     * @returns database path
     */
    getUnshieldEventsDBPath(txid: Optional<string>, eventLogIndex: Optional<number>, railgunTxid: Optional<string>): string[];
    /**
     * Gets nullifier by its id
     * @param {string} nullifier - nullifier to check
     * @param {number} treeIndex - optional tree to check
     * @returns Nullifier data, including txid of spent transaction
     */
    getNullifierTxid(nullifier: string, treeIndex?: number): Promise<Optional<string>>;
    private getNullifierSpendMetadataForTree;
    /** Gets spend identity and height, with a txid-only fallback for old databases. */
    getNullifierSpendMetadata(nullifier: string, treeIndex?: number): Promise<Optional<NullifierSpendMetadata>>;
    /**
     * Adds nullifiers to database
     * @param nullifiers - nullifiers to add to db
     */
    nullify(nullifiers: Nullifier[]): Promise<void>;
    private static parseNullifierBlockIndexKey;
    /** Atomically replaces nullifiers in a canonical replay range before its cursor advances. */
    reconcileNullifiers(startBlock: number, endBlock: number, canonicalNullifiers: Nullifier[], replaceAll: boolean): Promise<void>;
    /**
     * Adds unshield event to database
     * @param unshields - unshield events to add to db
     */
    addUnshieldEvents(unshields: UnshieldStoredEvent[], replaceExisting?: boolean): Promise<void>;
    hasExistingUnshieldEvent(unshield: UnshieldStoredEvent): Promise<boolean>;
    /**
     * Gets Unshield events
     */
    getAllUnshieldEventsForTxid(txid: string): Promise<UnshieldStoredEvent[]>;
    updateUnshieldEvent(unshieldEvent: UnshieldStoredEvent): Promise<void>;
    protected newLeafRootTrigger(): Promise<void>;
    protected validRootCallback(tree: number, lastValidLeafIndex: number): Promise<void>;
    protected invalidRootCallback(tree: number, lastKnownInvalidLeafIndex: number, lastKnownInvalidLeaf: Commitment): Promise<void>;
    updateInvalidMerklerootDetails(tree: number, lastKnownInvalidLeafIndex: number, lastKnownInvalidLeafBlockNumber: number): Promise<void>;
    removeInvalidMerklerootDetailsIfNecessary(tree: number, lastValidLeafIndex: number): Promise<void>;
    getFirstInvalidMerklerootTree(): Optional<number>;
}
