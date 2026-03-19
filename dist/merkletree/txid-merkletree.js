"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TXIDMerkletree = void 0;
const merkletree_types_1 = require("../models/merkletree-types");
const merkletree_1 = require("./merkletree");
const bytes_1 = require("../utils/bytes");
const is_defined_1 = require("../utils/is-defined");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const merkle_proof_1 = require("./merkle-proof");
class TXIDMerkletree extends merkletree_1.Merkletree {
    // DO NOT MODIFY
    merkletreePrefix = 'railgun-transaction-ids';
    merkletreeType = 'TXID';
    shouldStoreMerkleroots;
    constructor(db, chain, txidVersion, merklerootValidator) {
        const commitmentProcessingGroupSize = merkletree_types_1.CommitmentProcessingGroupSize.XXLarge;
        super(db, chain, txidVersion, merklerootValidator, commitmentProcessingGroupSize);
        this.shouldStoreMerkleroots = false;
    }
    /**
     * Creates a TXIDMerkletree for wallet use.
     */
    static async createForWallet(db, chain, txidVersion, merklerootValidator) {
        const merkletree = new TXIDMerkletree(db, chain, txidVersion, merklerootValidator);
        await merkletree.init();
        return merkletree;
    }
    /**
     * Gets Railgun Transaction data from txid tree.
     */
    async getRailgunTransaction(tree, index) {
        try {
            if (tree < 0 || index < 0) {
                return undefined;
            }
            return await this.getData(tree, index);
        }
        catch (err) {
            debugger_1.default.log('Error getting railgun transaction');
            // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
            debugger_1.default.error(err);
            return undefined;
        }
    }
    async getGlobalUTXOTreePositionForRailgunTransactionCommitment(tree, index, commitmentHash) {
        const railgunTransaction = await this.getRailgunTransaction(tree, index);
        if (!railgunTransaction) {
            throw new Error('Railgun transaction for tree/index not found');
        }
        const commitmentIndex = railgunTransaction.commitments
            .map((c) => bytes_1.ByteUtils.formatToByteLength(c, bytes_1.ByteLength.UINT_256))
            .indexOf(bytes_1.ByteUtils.formatToByteLength(commitmentHash, bytes_1.ByteLength.UINT_256));
        if (commitmentIndex < 0) {
            throw new Error('Could not find commitmentHash for RailgunTransaction');
        }
        return railgunTransaction.utxoBatchStartPositionOut + commitmentIndex;
    }
    async getRailgunTxidCurrentMerkletreeData(railgunTxid) {
        const txidIndex = await this.getTxidIndexByRailgunTxid(railgunTxid);
        if (!(0, is_defined_1.isDefined)(txidIndex)) {
            throw new Error(`tree/index not found: railgun txid ${railgunTxid}`);
        }
        const { tree, index } = merkletree_1.Merkletree.getTreeAndIndexFromGlobalPosition(txidIndex);
        const railgunTransaction = await this.getRailgunTransaction(tree, index);
        if (!(0, is_defined_1.isDefined)(railgunTransaction)) {
            throw new Error('railgun transaction not found');
        }
        const currentMerkleProofForTree = await this.getMerkleProof(tree, index);
        if (!(0, merkle_proof_1.verifyMerkleProof)(currentMerkleProofForTree)) {
            throw new Error('Invalid merkle proof');
        }
        const currentIndex = await this.getLatestIndexForTree(tree);
        const currentTxidIndexForTree = TXIDMerkletree.getGlobalPosition(tree, currentIndex);
        return {
            railgunTransaction,
            currentMerkleProofForTree,
            currentTxidIndexForTree,
        };
    }
    async railgunTxidOccurredBeforeBlockNumber(tree, index, blockNumber) {
        const railgunTransaction = await this.getRailgunTransaction(tree, index);
        if (!railgunTransaction) {
            throw new Error(`Railgun transaction at Txid tree ${tree} and index ${index} not found.`);
        }
        return railgunTransaction.blockNumber < blockNumber;
    }
    async getLatestRailgunTransaction() {
        const { tree, index } = await this.getLatestTreeAndIndex();
        return this.getRailgunTransaction(tree, index);
    }
    async queueRailgunTransactions(railgunTransactionsWithTxids, maxTxidIndex) {
        if (!railgunTransactionsWithTxids.length) {
            return;
        }
        const { tree: latestTree, index: latestIndex } = await this.getLatestTreeAndIndex();
        let nextTree = latestTree;
        let nextIndex = latestIndex;
        const railgunTxidIndexLookupBatch = [];
        let batchTree = -1;
        let batchStartIndex = -1;
        let batchLeaves = [];
        for (const railgunTransactionWithTxid of railgunTransactionsWithTxids) {
            const { tree, index } = TXIDMerkletree.nextTreeAndIndex(nextTree, nextIndex);
            nextTree = tree;
            nextIndex = index;
            if (TXIDMerkletree.isOutOfBounds(nextTree, nextIndex, maxTxidIndex)) {
                break;
            }
            const txidIndex = TXIDMerkletree.getGlobalPosition(nextTree, nextIndex);
            // TODO-V3: We need a way to verify the txid tree position.
            // The following won't work, because the UTXO start position includes shields, and the TXID position doesn't have shields.
            // if (
            //   railgunTransactionWithTxid.version === RailgunTransactionVersion.V3 &&
            //   railgunTransactionWithTxid.txidTreeVerificationGlobalIndex !== txidIndex
            // ) {
            //   const isUnshieldOnly =
            //     isDefined(railgunTransactionWithTxid.unshield) &&
            //     railgunTransactionWithTxid.commitments.length === 1;
            //   if (isUnshieldOnly) {
            //     EngineDebug.log(
            //       `Warning: Skipping railgun transaction queueing: potentially out of order. Tried to insert ${railgunTransactionWithTxid.txidTreeVerificationGlobalIndex} at position ${txidIndex}. This is an unshield-only - if there are 2 unshield-onlys in a row, this is expected, because these events don't technically have a global UTXO tree position.`,
            //     );
            //   } else {
            //     EngineDebug.error(
            //       new Error(
            //         `Skipping railgun transaction queueing: out of order. Tried to insert ${railgunTransactionWithTxid.txidTreeVerificationGlobalIndex} at position ${txidIndex}`,
            //       ),
            //     );
            //     return;
            //   }
            // }
            const { railgunTxid } = railgunTransactionWithTxid;
            if (batchTree === -1) {
                batchTree = nextTree;
                batchStartIndex = nextIndex;
            }
            if (nextTree !== batchTree) {
                // eslint-disable-next-line no-await-in-loop
                await this.queueLeaves(batchTree, batchStartIndex, batchLeaves);
                batchLeaves = [];
                batchTree = nextTree;
                batchStartIndex = nextIndex;
            }
            batchLeaves.push(railgunTransactionWithTxid);
            if (this.shouldStoreMerkleroots) {
                // eslint-disable-next-line no-await-in-loop
                await this.queueLeaves(batchTree, batchStartIndex, batchLeaves);
                batchLeaves = [];
                batchTree = -1;
                batchStartIndex = -1;
            }
            railgunTxidIndexLookupBatch.push({
                type: 'put',
                key: this.getRailgunTxidLookupDBPath(railgunTxid).join(':'),
                value: String(txidIndex),
            });
        }
        if (batchLeaves.length > 0) {
            await this.queueLeaves(batchTree, batchStartIndex, batchLeaves);
        }
        await this.db.batch(railgunTxidIndexLookupBatch, 'utf8');
    }
    static isOutOfBounds(tree, index, maxTxidIndex) {
        if (!(0, is_defined_1.isDefined)(maxTxidIndex)) {
            return false;
        }
        return TXIDMerkletree.getGlobalPosition(tree, index) > maxTxidIndex;
    }
    static nextTreeAndIndex(tree, index) {
        if (index + 1 >= merkletree_types_1.TREE_MAX_ITEMS) {
            return { tree: tree + 1, index: 0 };
        }
        return { tree, index: index + 1 };
    }
    async clearLeavesForInvalidVerificationHash(numLeavesToClear) {
        const { tree: latestTree, index: latestIndex } = await this.getLatestTreeAndIndex();
        const latestTxidIndex = TXIDMerkletree.getGlobalPosition(latestTree, latestIndex);
        const clearToTxidIndex = Math.max(-1, latestTxidIndex - numLeavesToClear);
        await this.clearLeavesAfterTxidIndex(clearToTxidIndex);
    }
    async clearLeavesAfterTxidIndex(txidIndex) {
        const lock = this.acquireUpdatesLock();
        try {
            // Remove any queued items
            this.writeQueue = [];
            const { tree, index } = TXIDMerkletree.getTreeAndIndexFromGlobalPosition(txidIndex);
            const { tree: latestTree, index: latestIndex } = await this.getLatestTreeAndIndex();
            for (let currentTree = tree; currentTree <= latestTree; currentTree += 1) {
                const startIndex = currentTree === tree ? index + 1 : 0;
                const max = currentTree === latestTree ? latestIndex : merkletree_types_1.TREE_MAX_ITEMS - 1;
                for (let currentIndex = startIndex; currentIndex <= max; currentIndex += 1) {
                    // eslint-disable-next-line no-await-in-loop
                    await this.db.del(this.getHistoricalMerklerootDBPath(currentTree, currentIndex));
                    // eslint-disable-next-line no-await-in-loop
                    await this.db.del(this.getDataDBPath(currentTree, currentIndex));
                }
                // eslint-disable-next-line no-await-in-loop
                await this.clearAllNodeHashes(currentTree);
            }
            for (let currentTree = tree; currentTree <= latestTree; currentTree += 1) {
                // eslint-disable-next-line no-await-in-loop
                await this.rebuildAndWriteTree(currentTree, lock);
                // eslint-disable-next-line no-await-in-loop
                await this.resetTreeLength(currentTree);
                // eslint-disable-next-line no-await-in-loop
                await this.updateStoredMerkletreesMetadata(currentTree);
            }
        }
        finally {
            this.releaseUpdatesLock();
        }
    }
    async getCurrentTxidIndex() {
        const { tree, index } = await this.getLatestTreeAndIndex();
        return TXIDMerkletree.getGlobalPosition(tree, index);
    }
    // eslint-disable-next-line class-methods-use-this
    validRootCallback() {
        // Unused for Txid merkletree
        return Promise.resolve();
    }
    // eslint-disable-next-line class-methods-use-this
    invalidRootCallback() {
        // Unused for Txid merkletree
        return Promise.resolve();
    }
    getRailgunTxidLookupDBPath(railgunTxid) {
        const railgunTxidPrefix = (0, bytes_1.fromUTF8String)('railgun-txid-lookup');
        return [...this.getMerkletreeDBPrefix(), railgunTxidPrefix, railgunTxid].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    async getTxidIndexByRailgunTxid(railgunTxid) {
        try {
            return Number(await this.db.get(this.getRailgunTxidLookupDBPath(railgunTxid), 'utf8'));
        }
        catch (err) {
            return undefined;
        }
    }
    async getRailgunTransactionByTxid(railgunTxid) {
        try {
            const txidIndex = await this.getTxidIndexByRailgunTxid(railgunTxid);
            if (!(0, is_defined_1.isDefined)(txidIndex)) {
                return undefined;
            }
            const { tree, index } = TXIDMerkletree.getTreeAndIndexFromGlobalPosition(txidIndex);
            return await this.getData(tree, index);
        }
        catch (err) {
            debugger_1.default.log('Error getting railgun txid index');
            // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
            debugger_1.default.error(err);
            return undefined;
        }
    }
    getHistoricalMerklerootDBPath(tree, index) {
        const merklerootPrefix = (0, bytes_1.fromUTF8String)('merkleroots');
        return [
            ...this.getMerkletreeDBPrefix(),
            merklerootPrefix,
            bytes_1.ByteUtils.hexlify(tree),
            bytes_1.ByteUtils.hexlify(index),
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    async newLeafRootTrigger(tree, index, leaf, merkleroot) {
        if (!this.shouldStoreMerkleroots) {
            return;
        }
        await this.db.put(this.getHistoricalMerklerootDBPath(tree, index), merkleroot);
    }
    async getHistoricalMerkleroot(tree, index) {
        try {
            const merkleroot = (await this.db.get(this.getHistoricalMerklerootDBPath(tree, index)));
            return merkleroot;
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error thrown in getHistoricalMerkleroot', { cause });
            }
            return undefined;
        }
    }
    async getHistoricalMerklerootForTxidIndex(txidIndex) {
        const { tree, index } = TXIDMerkletree.getTreeAndIndexFromGlobalPosition(txidIndex);
        return this.getHistoricalMerkleroot(tree, index);
    }
}
exports.TXIDMerkletree = TXIDMerkletree;
//# sourceMappingURL=txid-merkletree.js.map