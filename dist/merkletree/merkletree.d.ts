import type { Database } from '../database/database';
import { MerkleProof } from '../models/formatted-types';
import { Chain } from '../models/engine-types';
import { InvalidMerklerootDetails, MerkletreeLeaf, MerkletreesMetadata, MerklerootValidator, CommitmentProcessingGroupSize } from '../models/merkletree-types';
import { TXIDVersion } from '../models';
export declare abstract class Merkletree<T extends MerkletreeLeaf> {
    protected abstract readonly merkletreePrefix: string;
    protected abstract readonly merkletreeType: string;
    protected readonly db: Database;
    readonly chain: Chain;
    readonly zeros: string[];
    private treeLengths;
    protected writeQueue: T[][][];
    private lockPromise;
    private lockResolve;
    private lockRefCount;
    txidVersion: TXIDVersion;
    merklerootValidator: MerklerootValidator;
    isScanning: boolean;
    private processingWriteQueueLock;
    invalidMerklerootDetailsByTree: {
        [tree: number]: InvalidMerklerootDetails;
    };
    private cachedNodeHashes;
    private defaultCommitmentProcessingSize;
    /**
     * Create Merkletree controller from database
     * @param db - database object to use
     * @param chain - Chain type/id
     * @param merklerootValidator - root validator callback
     */
    constructor(db: Database, chain: Chain, txidVersion: TXIDVersion, merklerootValidator: MerklerootValidator, defaultCommitmentProcessingSize: CommitmentProcessingGroupSize);
    protected init(): Promise<void>;
    protected waitForUpdatesLock(): Promise<void>;
    protected acquireUpdatesLock(): unknown;
    protected releaseUpdatesLock(): void;
    private isCurrentLock;
    /**
     * Gets merkle proof for leaf
     */
    getMerkleProof(tree: number, index: number): Promise<MerkleProof>;
    /**
     * Hash 2 elements together
     */
    static hashLeftRight(left: string, right: string): string;
    private getTXIDVersionPrefix;
    getMerkletreeDBPrefix(): string[];
    /**
     * Construct DB prefix from tree number
     */
    getTreeDBPrefix(tree: number): string[];
    /**
     * Construct node hash DB path from tree number and level
     */
    private getNodeHashLevelPath;
    /**
     * Construct node hash DB path from tree number, level, and index
     */
    getNodeHashDBPath(tree: number, level: number, index: number): string[];
    clearAllNodeHashes(tree: number): Promise<void>;
    static getGlobalPosition(tree: number, index: number): number;
    static getTreeAndIndexFromGlobalPosition(globalPosition: number): {
        tree: number;
        index: number;
    };
    /**
     * Construct data DB path from tree number and index
     */
    protected getDataDBPath(tree: number, index: number): string[];
    updateData(tree: number, index: number, data: T): Promise<void>;
    protected getData(tree: number, index: number): Promise<T>;
    protected getDataRange(tree: number, start: number, end: number): Promise<T[]>;
    sortMerkletreeDataByHash(array: T[]): T[];
    /**
     * Gets node from tree
     * @param tree - tree to get node from
     * @param level - tree level
     * @param index - index of node
     * @returns node
     */
    getNodeHash(tree: number, level: number, index: number): Promise<string>;
    private cacheNodeHash;
    getMetadataFromStorage(): Promise<void>;
    /**
     * Gets merkletrees metadata
     * @returns metadata
     */
    getMerkletreesMetadata(): Promise<Optional<MerkletreesMetadata>>;
    /**
     * Stores merkletrees metadata
     */
    storeMerkletreesMetadata(metadata: MerkletreesMetadata): Promise<void>;
    /**
     * Gets length of tree
     * @param treeIndex - tree to get length of
     * @returns tree length
     */
    getTreeLength(treeIndex: number): Promise<number>;
    updateStoredMerkletreesMetadata(treeIndex: number): Promise<void>;
    resetTreeLength(treeIndex: number): Promise<void>;
    /**
     * WARNING: This operation takes a long time.
     */
    private getTreeLengthFromDBCount;
    getLatestIndexForTree(tree: number): Promise<number>;
    getLatestTreeAndIndex(): Promise<{
        tree: number;
        index: number;
    }>;
    clearDataForMerkletree(): Promise<void>;
    /**
     * Gets node from tree
     * @param tree - tree to get root of
     * @returns tree root
     */
    getRoot(tree: number): Promise<string>;
    /**
     * Write tree to DB
     * @param treeIndex - tree to write
     */
    private writeTreeToDB;
    /**
     * Inserts array of leaves into tree
     * @param tree - Tree to insert leaves into
     * @param startIndex - Starting index of leaves to insert
     * @param leaves - Leaves to insert
     */
    private insertLeaves;
    /**
     * Rebuilds entire tree and writes to DB.
     */
    rebuildAndWriteTree(tree: number, lock?: unknown): Promise<void>;
    private static fillHashWriteGroup;
    protected abstract newLeafRootTrigger(tree: number, index: number, leaf: string, merkleroot: string): Promise<void>;
    protected abstract validRootCallback(tree: number, lastValidLeafIndex: number): Promise<void>;
    protected abstract invalidRootCallback(tree: number, lastKnownInvalidLeafIndex: number, lastKnownInvalidLeaf: T): Promise<void>;
    private processWriteQueueForTree;
    private static nextProcessingGroupSize;
    private processWriteQueue;
    static numNodesPerLevel(level: number): number;
    private treeIndicesFromWriteQueue;
    updateTreesFromWriteQueue(skipValidation?: boolean): Promise<void>;
    /**
     * Adds leaves to queue to be added to tree
     * @param tree - tree number to add to
     * @param leaves - leaves to add
     * @param startingIndex - index of first leaf
     */
    queueLeaves(tree: number, startingIndex: number, leaves: T[]): Promise<void>;
    /**
     * Gets latest tree
     * @returns latest tree
     */
    latestTree(): Promise<number>;
}
