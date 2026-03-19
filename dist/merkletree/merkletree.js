"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Merkletree = void 0;
const msgpack_lite_1 = __importDefault(require("msgpack-lite"));
const poseidon_1 = require("../utils/poseidon");
const bytes_1 = require("../utils/bytes");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const chain_1 = require("../chain/chain");
const is_defined_1 = require("../utils/is-defined");
const merkletree_types_1 = require("../models/merkletree-types");
const models_1 = require("../models");
const promises_1 = require("../utils/promises");
const INVALID_MERKLE_ROOT_ERROR_MESSAGE = 'Cannot insert leaves. Invalid merkle root.';
class Merkletree {
    db;
    chain;
    zeros = [];
    treeLengths = [];
    // {tree: {startingIndex: [leaves]}}
    writeQueue = [];
    lockPromise = null;
    lockResolve = null;
    lockRefCount = 0;
    txidVersion;
    // Check function to test if merkle root is valid
    merklerootValidator;
    isScanning = false;
    processingWriteQueueLock = {};
    invalidMerklerootDetailsByTree = {};
    cachedNodeHashes = {};
    defaultCommitmentProcessingSize;
    /**
     * Create Merkletree controller from database
     * @param db - database object to use
     * @param chain - Chain type/id
     * @param merklerootValidator - root validator callback
     */
    constructor(db, chain, txidVersion, merklerootValidator, defaultCommitmentProcessingSize) {
        // Set passed values
        this.db = db;
        this.chain = chain;
        this.txidVersion = txidVersion;
        this.merklerootValidator = merklerootValidator;
        this.defaultCommitmentProcessingSize = defaultCommitmentProcessingSize;
        // Calculate zero values
        this.zeros[0] = merkletree_types_1.MERKLE_ZERO_VALUE;
        for (let level = 1; level <= merkletree_types_1.TREE_DEPTH; level += 1) {
            this.zeros[level] = Merkletree.hashLeftRight(this.zeros[level - 1], this.zeros[level - 1]);
        }
    }
    async init() {
        await this.getMetadataFromStorage();
    }
    async waitForUpdatesLock() {
        if (this.lockPromise) {
            await this.lockPromise;
        }
    }
    acquireUpdatesLock() {
        this.lockPromise ??= new Promise((resolve) => {
            this.lockResolve = resolve;
        });
        this.lockRefCount += 1;
        return this.lockPromise;
    }
    releaseUpdatesLock() {
        this.lockRefCount -= 1;
        if (this.lockRefCount <= 0 && this.lockResolve) {
            const resolve = this.lockResolve;
            this.lockPromise = null;
            this.lockResolve = null;
            this.lockRefCount = 0;
            resolve();
        }
    }
    isCurrentLock(lock) {
        return (0, is_defined_1.isDefined)(lock) && lock === this.lockPromise;
    }
    /**
     * Gets merkle proof for leaf
     */
    async getMerkleProof(tree, index) {
        // Fetch leaf
        const leaf = await this.getNodeHash(tree, 0, index);
        // Get indexes of path elements to fetch
        const elementsIndices = [index ^ 1];
        // Loop through each level and calculate index
        while (elementsIndices.length < merkletree_types_1.TREE_DEPTH) {
            // Shift right and flip last bit
            elementsIndices.push((elementsIndices[elementsIndices.length - 1] >> 1) ^ 1);
        }
        // Fetch path elements
        const elements = await Promise.all(elementsIndices.map((elementIndex, level) => this.getNodeHash(tree, level, elementIndex)));
        // Convert index to bytes data, the binary representation is the indices of the merkle path
        // Pad to 32 bytes
        const indices = bytes_1.ByteUtils.nToHex(BigInt(index), bytes_1.ByteLength.UINT_256);
        // Fetch root
        const root = await this.getRoot(tree);
        // Return proof
        return {
            leaf,
            elements,
            indices,
            root,
        };
    }
    /**
     * Hash 2 elements together
     */
    static hashLeftRight(left, right) {
        return (0, poseidon_1.poseidonHex)([left, right]);
    }
    getTXIDVersionPrefix() {
        switch (this.txidVersion) {
            case models_1.TXIDVersion.V2_PoseidonMerkle:
                return 'V2';
            case models_1.TXIDVersion.V3_PoseidonMerkle:
                return 'V3';
        }
        throw new Error('Unrecognized txid version for merkletree');
    }
    getMerkletreeDBPrefix() {
        const merkletreePrefix = (0, bytes_1.fromUTF8String)(this.merkletreePrefix);
        const txidVersionPrefix = (0, bytes_1.fromUTF8String)(this.getTXIDVersionPrefix());
        return [merkletreePrefix, (0, chain_1.getChainFullNetworkID)(this.chain), txidVersionPrefix].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    /**
     * Construct DB prefix from tree number
     */
    getTreeDBPrefix(tree) {
        return [...this.getMerkletreeDBPrefix(), bytes_1.ByteUtils.hexlify(tree)].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    /**
     * Construct node hash DB path from tree number and level
     */
    getNodeHashLevelPath(tree, level) {
        return [...this.getTreeDBPrefix(tree), bytes_1.ByteUtils.hexlify(level)].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    /**
     * Construct node hash DB path from tree number, level, and index
     */
    getNodeHashDBPath(tree, level, index) {
        const dbPath = [...this.getNodeHashLevelPath(tree, level), bytes_1.ByteUtils.hexlify(index)];
        return dbPath.map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    async clearAllNodeHashes(tree) {
        this.acquireUpdatesLock();
        try {
            for (let level = 0; level < merkletree_types_1.TREE_DEPTH; level += 1) {
                // eslint-disable-next-line no-await-in-loop
                await this.db.clearNamespace(this.getNodeHashLevelPath(tree, level));
            }
            if ((0, is_defined_1.isDefined)(this.cachedNodeHashes[tree])) {
                this.cachedNodeHashes[tree] = {};
            }
        }
        finally {
            this.releaseUpdatesLock();
        }
    }
    static getGlobalPosition(tree, index) {
        return tree * merkletree_types_1.TREE_MAX_ITEMS + index;
    }
    static getTreeAndIndexFromGlobalPosition(globalPosition) {
        return {
            tree: Math.floor(globalPosition / merkletree_types_1.TREE_MAX_ITEMS),
            index: globalPosition % merkletree_types_1.TREE_MAX_ITEMS,
        };
    }
    /**
     * Construct data DB path from tree number and index
     */
    getDataDBPath(tree, index) {
        return [
            ...this.getTreeDBPrefix(tree),
            bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.FULL_32_BITS), // 2^32-1
            bytes_1.ByteUtils.hexlify(index),
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    async updateData(tree, index, data) {
        await this.waitForUpdatesLock();
        this.acquireUpdatesLock();
        try {
            const oldData = await this.getData(tree, index);
            if (oldData.hash !== data.hash) {
                throw new Error('Cannot update merkletree data with different hash.');
            }
            await this.db.put(this.getDataDBPath(tree, index), data, 'json');
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error thrown in Merkletree updateData', { cause });
            }
            throw new Error('Failed to update merkletree data', { cause });
        }
        finally {
            this.releaseUpdatesLock();
        }
    }
    async getData(tree, index) {
        try {
            const data = (await this.db.get(this.getDataDBPath(tree, index), 'json'));
            return data;
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error thrown in Merkletree getData', { cause });
            }
            throw new Error('Failed to get merkletree data', { cause });
        }
    }
    getDataRange(tree, start, end) {
        return new Promise((resolve, reject) => {
            const datas = [];
            try {
                this.db
                    .streamRange(this.getDataDBPath(tree, start), this.getDataDBPath(tree, end), 'json')
                    .on('data', (data) => {
                    datas.push(data);
                })
                    .on('error', (cause) => {
                    reject(new Error('Failed to stream merkletree data range', { cause }));
                })
                    .on('end', () => {
                    resolve(datas);
                });
            }
            catch (cause) {
                if (!(cause instanceof Error)) {
                    throw new Error('Non-error thrown in Merkletree getDataRange', { cause });
                }
                throw new Error('Failed to stream merkletree data range', { cause });
            }
        });
    }
    // eslint-disable-next-line class-methods-use-this
    sortMerkletreeDataByHash(array) {
        return array.sort((a, b) => (a.hash > b.hash ? 1 : -1));
    }
    /**
     * Gets node from tree
     * @param tree - tree to get node from
     * @param level - tree level
     * @param index - index of node
     * @returns node
     */
    async getNodeHash(tree, level, index) {
        if ((0, is_defined_1.isDefined)(this.cachedNodeHashes[tree]) &&
            (0, is_defined_1.isDefined)(this.cachedNodeHashes[tree][level]) &&
            this.cachedNodeHashes[tree][level][index]) {
            return this.cachedNodeHashes[tree][level][index];
        }
        try {
            const hash = (await this.db.get(this.getNodeHashDBPath(tree, level, index)));
            this.cacheNodeHash(tree, level, index, hash);
            return hash;
        }
        catch {
            return this.zeros[level];
        }
    }
    cacheNodeHash(tree, level, index, hash) {
        if (!(0, is_defined_1.isDefined)(this.cachedNodeHashes[tree])) {
            this.cachedNodeHashes[tree] = {};
        }
        if (!(0, is_defined_1.isDefined)(this.cachedNodeHashes[tree][level])) {
            this.cachedNodeHashes[tree][level] = {};
        }
        this.cachedNodeHashes[tree][level][index] = hash;
    }
    async getMetadataFromStorage() {
        const storedMetadata = await this.getMerkletreesMetadata();
        if (!storedMetadata) {
            return;
        }
        const treeKeys = Object.keys(storedMetadata.trees);
        for (const treeKey of treeKeys) {
            const tree = Number(treeKey);
            const treeMetadata = storedMetadata.trees[tree];
            this.treeLengths[tree] = treeMetadata.scannedHeight;
            if (treeMetadata.invalidMerklerootDetails) {
                this.invalidMerklerootDetailsByTree[tree] =
                    treeMetadata.invalidMerklerootDetails ?? undefined;
            }
        }
    }
    /**
     * Gets merkletrees metadata
     * @returns metadata
     */
    async getMerkletreesMetadata() {
        try {
            const metadata = msgpack_lite_1.default.decode(bytes_1.ByteUtils.arrayify((await this.db.get(this.getMerkletreeDBPrefix()))));
            return metadata;
        }
        catch {
            return undefined;
        }
    }
    /**
     * Stores merkletrees metadata
     */
    async storeMerkletreesMetadata(metadata) {
        try {
            await this.db.put(this.getMerkletreeDBPrefix(), msgpack_lite_1.default.encode(metadata));
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error thrown in Merkletree storeMerkletreesMetadata', { cause });
            }
            if (debugger_1.default.isTestRun()) {
                return;
            }
            throw new Error('Failed to store merkletrees metadata', { cause });
        }
    }
    /**
     * Gets length of tree
     * @param treeIndex - tree to get length of
     * @returns tree length
     */
    async getTreeLength(treeIndex) {
        if ((0, is_defined_1.isDefined)(this.treeLengths[treeIndex])) {
            return this.treeLengths[treeIndex];
        }
        const storedMetadata = await this.getMerkletreesMetadata();
        if ((0, is_defined_1.isDefined)(storedMetadata?.trees[treeIndex])) {
            this.treeLengths[treeIndex] = storedMetadata.trees[treeIndex].scannedHeight;
            return this.treeLengths[treeIndex];
        }
        this.treeLengths[treeIndex] = await this.getTreeLengthFromDBCount(treeIndex);
        if (this.treeLengths[treeIndex] > 0) {
            await this.updateStoredMerkletreesMetadata(treeIndex);
        }
        return this.treeLengths[treeIndex];
    }
    async updateStoredMerkletreesMetadata(treeIndex) {
        const treeLength = await this.getTreeLength(treeIndex);
        const storedMerkletreesMetadata = await this.getMerkletreesMetadata();
        const merkletreesMetadata = storedMerkletreesMetadata || {
            trees: {},
        };
        merkletreesMetadata.trees[treeIndex] = {
            scannedHeight: treeLength,
            invalidMerklerootDetails: this.invalidMerklerootDetailsByTree[treeIndex],
        };
        await this.storeMerkletreesMetadata(merkletreesMetadata);
    }
    async resetTreeLength(treeIndex) {
        delete this.treeLengths[treeIndex];
        const merkletreesMetadata = await this.getMerkletreesMetadata();
        if (!merkletreesMetadata) {
            return;
        }
        delete merkletreesMetadata.trees[treeIndex];
        await this.storeMerkletreesMetadata(merkletreesMetadata);
    }
    /**
     * WARNING: This operation takes a long time.
     */
    async getTreeLengthFromDBCount(tree) {
        return this.db.countNamespace([
            ...this.getTreeDBPrefix(tree),
            bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.FULL_32_BITS), // 2^32-1
        ]);
    }
    async getLatestIndexForTree(tree) {
        const treeLength = await this.getTreeLength(tree);
        return treeLength - 1;
    }
    async getLatestTreeAndIndex() {
        const latestTree = await this.latestTree();
        const index = await this.getLatestIndexForTree(latestTree);
        return { tree: latestTree, index };
    }
    async clearDataForMerkletree() {
        this.acquireUpdatesLock();
        try {
            await this.db.clearNamespace(this.getMerkletreeDBPrefix());
        }
        finally {
            this.releaseUpdatesLock();
            this.cachedNodeHashes = {};
            this.treeLengths = [];
        }
    }
    /**
     * Gets node from tree
     * @param tree - tree to get root of
     * @returns tree root
     */
    getRoot(tree) {
        return this.getNodeHash(tree, merkletree_types_1.TREE_DEPTH, 0);
    }
    /**
     * Write tree to DB
     * @param treeIndex - tree to write
     */
    async writeTreeToDB(treeIndex, hashWriteGroup, dataWriteGroup, lock) {
        const newTreeLength = hashWriteGroup[0].length;
        const nodeWriteBatch = [];
        for (const [level, levelNodes] of hashWriteGroup.entries()) {
            if (!(0, is_defined_1.isDefined)(levelNodes))
                continue;
            for (const [index, node] of levelNodes.entries()) {
                if (!(0, is_defined_1.isDefined)(node))
                    continue;
                nodeWriteBatch.push({
                    type: 'put',
                    key: this.getNodeHashDBPath(treeIndex, level, index).join(':'),
                    value: node,
                });
                this.cacheNodeHash(treeIndex, level, index, node);
            }
        }
        const dataWriteBatch = [];
        const globalHashLookupBatch = [];
        for (const [index, data] of dataWriteGroup.entries()) {
            if (!(0, is_defined_1.isDefined)(data))
                continue;
            dataWriteBatch.push({
                type: 'put',
                key: this.getDataDBPath(treeIndex, index).join(':'),
                value: data,
            });
        }
        if (!this.isCurrentLock(lock)) {
            await this.waitForUpdatesLock();
        }
        await Promise.all([
            this.db.batch(nodeWriteBatch),
            this.db.batch(dataWriteBatch, 'json'),
            this.db.batch(globalHashLookupBatch, 'utf8'),
        ]);
        // Call leaf/merkleroot storage (implemented in txid tree only)
        const lastIndex = newTreeLength - 1;
        const leaf = hashWriteGroup[0][lastIndex];
        const merkleroot = hashWriteGroup[merkletree_types_1.TREE_DEPTH][0];
        await this.newLeafRootTrigger(treeIndex, lastIndex, leaf, merkleroot);
        // Update tree length
        this.treeLengths[treeIndex] = newTreeLength;
        await this.updateStoredMerkletreesMetadata(treeIndex);
    }
    /**
     * Inserts array of leaves into tree
     * @param tree - Tree to insert leaves into
     * @param startIndex - Starting index of leaves to insert
     * @param leaves - Leaves to insert
     */
    async insertLeaves(tree, startIndex, leaves, skipValidation = false) {
        // Start insertion at startIndex
        let index = startIndex;
        // Calculate ending index
        const endIndex = startIndex + leaves.length;
        const firstLevelHashWriteGroup = [];
        const dataWriteGroup = [];
        firstLevelHashWriteGroup[0] = [];
        debugger_1.default.log(`insertLeaves: tree: ${tree} startIndex ${startIndex}, group length ${leaves.length}`);
        // Push values to leaves of write index
        for (const leaf of leaves) {
            // Set writecache value
            firstLevelHashWriteGroup[0][index] = leaf.hash;
            dataWriteGroup[index] = leaf;
            // Increment index
            index += 1;
        }
        const hashWriteGroup = await Merkletree.fillHashWriteGroup(firstLevelHashWriteGroup, tree, startIndex, endIndex, (level, nodeIndex) => this.getNodeHash(tree, level, nodeIndex));
        const leafIndex = leaves.length - 1;
        const lastLeafIndex = startIndex + leafIndex;
        const rootNode = hashWriteGroup[merkletree_types_1.TREE_DEPTH][0];
        const validRoot = await this.merklerootValidator(this.txidVersion, this.chain, tree, lastLeafIndex, rootNode);
        if (!skipValidation) {
            if (validRoot) {
                await this.validRootCallback(tree, lastLeafIndex);
            }
            else {
                await this.invalidRootCallback(tree, lastLeafIndex, leaves[leafIndex]);
                throw new Error(`${INVALID_MERKLE_ROOT_ERROR_MESSAGE} [${this.merkletreeType}] Tree ${tree}, startIndex ${startIndex}, group length ${leaves.length}.`);
            }
        }
        else {
            await this.validRootCallback(tree, lastLeafIndex);
        }
        // If new root is valid, write to DB.
        await this.writeTreeToDB(tree, hashWriteGroup, dataWriteGroup);
    }
    /**
     * Rebuilds entire tree and writes to DB.
     */
    async rebuildAndWriteTree(tree, lock) {
        const firstLevelHashWriteGroup = [];
        firstLevelHashWriteGroup[0] = [];
        // Cannot used cached treeLength value here because it is stale.
        const treeLength = await this.getTreeLengthFromDBCount(tree);
        const leaves = await this.getDataRange(tree, 0, treeLength - 1);
        // Push values to leaves of write index
        for (const [index, leaf] of leaves.entries()) {
            if (!(0, is_defined_1.isDefined)(leaf))
                continue;
            firstLevelHashWriteGroup[0][index] = leaf.hash ?? this.zeros[0];
        }
        const startIndex = 0;
        const endIndex = treeLength - 1;
        const hashWriteGroup = await Merkletree.fillHashWriteGroup(firstLevelHashWriteGroup, tree, startIndex, endIndex, async (level) => this.zeros[level]);
        const dataWriteGroup = [];
        await this.writeTreeToDB(tree, hashWriteGroup, dataWriteGroup, lock);
    }
    static async fillHashWriteGroup(firstLevelHashWriteGroup, tree, startIndex, endIndex, nodeHashLookup) {
        const hashWriteGroup = firstLevelHashWriteGroup;
        let level = 0;
        let index = startIndex;
        let nextLevelStartIndex = startIndex;
        let nextLevelEndIndex = endIndex;
        // Loop through each level and calculate values
        while (level < merkletree_types_1.TREE_DEPTH) {
            // Set starting index for this level
            index = nextLevelStartIndex;
            // Ensure writecache array exists for next level
            hashWriteGroup[level] = hashWriteGroup[level] ?? [];
            hashWriteGroup[level + 1] = hashWriteGroup[level + 1] ?? [];
            // Loop through every pair
            for (index; index <= nextLevelEndIndex + 1; index += 2) {
                if (index % 2 === 0) {
                    // Left
                    hashWriteGroup[level + 1][index >> 1] = Merkletree.hashLeftRight(hashWriteGroup[level][index] || (await nodeHashLookup(level, index)), hashWriteGroup[level][index + 1] || (await nodeHashLookup(level, index + 1)));
                }
                else {
                    // Right
                    hashWriteGroup[level + 1][index >> 1] = Merkletree.hashLeftRight(hashWriteGroup[level][index - 1] || (await nodeHashLookup(level, index - 1)), hashWriteGroup[level][index] || (await nodeHashLookup(level, index)));
                }
            }
            // Calculate starting and ending index for the next level
            nextLevelStartIndex >>= 1;
            nextLevelEndIndex >>= 1;
            // Increment level
            level += 1;
        }
        return hashWriteGroup;
    }
    async processWriteQueueForTree(treeIndex, skipValidation = false) {
        const previousPromise = this.processingWriteQueueLock[treeIndex] ?? Promise.resolve();
        let resolveLock = () => { };
        const myPromise = new Promise((resolve) => {
            resolveLock = resolve;
        });
        this.processingWriteQueueLock[treeIndex] = myPromise;
        try {
            await previousPromise;
        }
        catch {
            // Ignore error from previous promise
        }
        try {
            let processingGroupSize = this.defaultCommitmentProcessingSize;
            let currentTreeLength = await this.getTreeLength(treeIndex);
            const treeWriteQueue = this.writeQueue[treeIndex];
            if (!(0, is_defined_1.isDefined)(treeWriteQueue)) {
                return;
            }
            for (const writeQueueKey of Object.keys(treeWriteQueue)) {
                if (!(0, is_defined_1.isDefined)(writeQueueKey))
                    continue;
                const writeQueueIndex = Number(writeQueueKey);
                const alreadyAddedToTree = writeQueueIndex < currentTreeLength;
                if (alreadyAddedToTree) {
                    delete treeWriteQueue[writeQueueIndex];
                }
            }
            while ((0, is_defined_1.isDefined)(this.writeQueue[treeIndex])) {
                // Process leaves as a group until we hit an invalid merkleroot.
                // Then, process each single item.
                // This optimizes for fewer `merklerootValidator` calls, while still protecting
                // users against invalid roots and broken trees.
                currentTreeLength = await this.getTreeLength(treeIndex);
                const processWriteQueuePrefix = `[processWriteQueueForTree: ${this.chain.type}:${this.chain.id}]`;
                try {
                    const processedAny = await this.processWriteQueue(treeIndex, currentTreeLength, processingGroupSize, skipValidation);
                    if (!processedAny) {
                        debugger_1.default.log(`${processWriteQueuePrefix} No more events to process.`);
                        break;
                    }
                }
                catch (cause) {
                    if (!(cause instanceof Error)) {
                        debugger_1.default.log(`${processWriteQueuePrefix} Unknown error found. ${cause}`);
                        return;
                    }
                    const ignoreInTests = true;
                    const err = new Error('Failed to process merkletree write queue', { cause });
                    debugger_1.default.error(err, ignoreInTests);
                    if (cause.message.startsWith(INVALID_MERKLE_ROOT_ERROR_MESSAGE)) {
                        const nextProcessingGroupSize = Merkletree.nextProcessingGroupSize(processingGroupSize);
                        if (nextProcessingGroupSize) {
                            debugger_1.default.log(`${processWriteQueuePrefix} Invalid merkleroot found. Processing with group size ${nextProcessingGroupSize}.`);
                            processingGroupSize = nextProcessingGroupSize;
                        }
                        else {
                            debugger_1.default.log(`${processWriteQueuePrefix} Unable to process more events. Invalid merkleroot found.`);
                            break;
                        }
                    }
                    else {
                        // Unknown error.
                        debugger_1.default.log(`${processWriteQueuePrefix} Unable to process more events. Unknown error.`);
                        break;
                    }
                }
                // Delete queue for entire tree if necessary.
                const noElementsInTreeWriteQueue = treeWriteQueue.reduce((x) => x + 1, 0) === 0;
                if (noElementsInTreeWriteQueue) {
                    delete this.writeQueue[treeIndex];
                }
            }
        }
        finally {
            resolveLock();
            if (this.processingWriteQueueLock[treeIndex] === myPromise) {
                delete this.processingWriteQueueLock[treeIndex];
            }
        }
    }
    static nextProcessingGroupSize(processingGroupSize) {
        switch (processingGroupSize) {
            case merkletree_types_1.CommitmentProcessingGroupSize.XXXXLarge:
                return merkletree_types_1.CommitmentProcessingGroupSize.XXXLarge;
            case merkletree_types_1.CommitmentProcessingGroupSize.XXXLarge:
                // Process with smaller group.
                return merkletree_types_1.CommitmentProcessingGroupSize.XXLarge;
            case merkletree_types_1.CommitmentProcessingGroupSize.XXLarge:
                // Process with smaller group.
                return merkletree_types_1.CommitmentProcessingGroupSize.XLarge;
            case merkletree_types_1.CommitmentProcessingGroupSize.XLarge:
                // Process with smaller group.
                return merkletree_types_1.CommitmentProcessingGroupSize.Large;
            case merkletree_types_1.CommitmentProcessingGroupSize.Large:
                // Process with smaller group.
                return merkletree_types_1.CommitmentProcessingGroupSize.Medium;
            case merkletree_types_1.CommitmentProcessingGroupSize.Medium:
                // Process with smaller group.
                return merkletree_types_1.CommitmentProcessingGroupSize.Small;
            case merkletree_types_1.CommitmentProcessingGroupSize.Small:
                // Process by individual items.
                return merkletree_types_1.CommitmentProcessingGroupSize.Single;
            case merkletree_types_1.CommitmentProcessingGroupSize.Single:
                // Break out from scan.
                return undefined;
        }
        return undefined;
    }
    async processWriteQueue(treeIndex, currentTreeLength, maxCommitmentGroupsToProcess, skipValidation = false) {
        // If there is an element in the write queue equal to the tree length, process it.
        const nextCommitmentGroup = this.writeQueue[treeIndex][currentTreeLength];
        if (!(0, is_defined_1.isDefined)(nextCommitmentGroup)) {
            debugger_1.default.log(`[processWriteQueue: ${this.chain.type}:${this.chain.id}] No commitment group for index ${currentTreeLength}`);
            return false;
        }
        const commitmentGroupIndices = [currentTreeLength];
        let nextIndex = currentTreeLength + nextCommitmentGroup.length;
        const dataWriteGroups = [nextCommitmentGroup];
        while (maxCommitmentGroupsToProcess > dataWriteGroups.length &&
            (0, is_defined_1.isDefined)(this.writeQueue[treeIndex][nextIndex])) {
            commitmentGroupIndices.push(nextIndex);
            const next = this.writeQueue[treeIndex][nextIndex];
            dataWriteGroups.push(next);
            nextIndex += next.length;
        }
        await this.insertLeaves(treeIndex, currentTreeLength, dataWriteGroups.flat(), skipValidation);
        // Delete the batch after processing it.
        // Ensures bad batches are deleted, therefore halting update loop if one is found.
        for (const commitmentGroupIndex of commitmentGroupIndices) {
            delete this.writeQueue[treeIndex][commitmentGroupIndex];
        }
        return true;
    }
    static numNodesPerLevel(level) {
        return merkletree_types_1.TREE_MAX_ITEMS >> level;
    }
    treeIndicesFromWriteQueue() {
        return this.writeQueue
            .map((_tree, treeIndex) => treeIndex)
            .filter((index) => !Number.isNaN(index));
    }
    async updateTreesFromWriteQueue(skipValidation = false) {
        const treeIndices = this.treeIndicesFromWriteQueue();
        for (const treeIndex of treeIndices) {
            try {
                await this.processWriteQueueForTree(treeIndex, skipValidation);
            }
            catch {
                await (0, promises_1.delay)(2_000);
                await this.updateTreesFromWriteQueue(skipValidation);
                return;
            }
        }
    }
    /**
     * Adds leaves to queue to be added to tree
     * @param tree - tree number to add to
     * @param leaves - leaves to add
     * @param startingIndex - index of first leaf
     */
    async queueLeaves(tree, startingIndex, leaves) {
        // Get tree length
        const treeLength = await this.getTreeLength(tree);
        // Ensure write queue for tree exists
        if (!(0, is_defined_1.isDefined)(this.writeQueue[tree])) {
            this.writeQueue[tree] = [];
        }
        if (treeLength <= startingIndex) {
            // If starting index is greater or equal to tree length, insert to queue
            this.writeQueue[tree][startingIndex] = leaves;
            if (debugger_1.default.verboseScanLogging()) {
                debugger_1.default.log(`[${this.merkletreeType} queueLeaves: ${this.chain.type}:${this.chain.id}] treeLength ${treeLength}, startingIndex ${startingIndex}`);
            }
        }
    }
    /**
     * Gets latest tree
     * @returns latest tree
     */
    async latestTree() {
        let latestTree = 0;
        while ((await this.getTreeLength(latestTree)) > 0)
            latestTree += 1;
        return Math.max(0, latestTree - 1);
    }
}
exports.Merkletree = Merkletree;
//# sourceMappingURL=merkletree.js.map