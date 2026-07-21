"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UTXOMerkletree = void 0;
const merkletree_types_1 = require("../models/merkletree-types");
const bytes_1 = require("../utils/bytes");
const merkletree_1 = require("./merkletree");
const is_defined_1 = require("../utils/is-defined");
class UTXOMerkletree extends merkletree_1.Merkletree {
    // DO NOT MODIFY
    merkletreePrefix = 'merkletree-erc20';
    merkletreeType = 'UTXO';
    constructor(db, chain, txidVersion, merklerootValidator) {
        super(db, chain, txidVersion, merklerootValidator, merkletree_types_1.CommitmentProcessingGroupSize.XXXXLarge);
    }
    static async create(db, chain, txidVersion, merklerootValidator) {
        const merkletree = new UTXOMerkletree(db, chain, txidVersion, merklerootValidator);
        await merkletree.init();
        return merkletree;
    }
    /**
     * Gets Commitment from UTXO tree
     */
    async getCommitment(tree, index) {
        return this.getData(tree, index);
    }
    async getCommitmentRange(tree, start, end) {
        return this.getDataRange(tree, start, end);
    }
    /**
     * Gets Commitment from UTXO tree
     */
    async getCommitmentSafe(tree, index) {
        try {
            return await this.getData(tree, index);
        }
        catch (err) {
            return undefined;
        }
    }
    /**
     * Construct DB path from nullifier
     * @param tree - tree nullifier is for
     * @param nullifier - nullifier to get path for
     * @returns database path
     */
    getNullifierDBPath(tree, nullifier) {
        return [
            ...this.getTreeDBPrefix(tree),
            bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.FULL_32_BITS - 1n), // 2^32-2
            bytes_1.ByteUtils.hexlify(nullifier),
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    /** Stores spend height separately so existing nullifier txid records stay backward-compatible. */
    getNullifierSpendBlockDBPath(tree, nullifier) {
        return [
            ...this.getTreeDBPrefix(tree),
            bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.FULL_32_BITS - 3n), // 2^32-4
            bytes_1.ByteUtils.hexlify(nullifier),
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    getNullifierBlockIndexDBPrefix() {
        return [
            ...this.getMerkletreeDBPrefix(),
            bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.FULL_32_BITS - 4n), // 2^32-5
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    getNullifierBlockIndexDBPath(blockNumber, tree, nullifier) {
        return [
            ...this.getNullifierBlockIndexDBPrefix(),
            bytes_1.ByteUtils.hexlify(blockNumber),
            bytes_1.ByteUtils.hexlify(tree),
            bytes_1.ByteUtils.hexlify(nullifier),
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    /**
     * Construct DB path from unshield transaction
     * @param txid - unshield txid to get path for
     * @returns database path
     */
    getUnshieldEventsDBPath(txid, eventLogIndex, railgunTxid) {
        const path = [
            ...this.getMerkletreeDBPrefix(),
            bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.FULL_32_BITS - 2n), // 2^32-3
        ];
        if (txid != null) {
            path.push(bytes_1.ByteUtils.hexlify(txid));
        }
        if (eventLogIndex != null) {
            path.push(eventLogIndex.toString(16));
        }
        else if (railgunTxid != null) {
            path.push(railgunTxid);
        }
        return path.map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
    }
    /**
     * Gets nullifier by its id
     * @param {string} nullifier - nullifier to check
     * @param {number} treeIndex - optional tree to check
     * @returns Nullifier data, including txid of spent transaction
     */
    async getNullifierTxid(nullifier, treeIndex) {
        return (await this.getNullifierSpendMetadata(nullifier, treeIndex))?.txid;
    }
    async getNullifierSpendMetadataForTree(nullifier, tree) {
        let txid;
        try {
            txid = (await this.db.get(this.getNullifierDBPath(tree, nullifier)));
        }
        catch {
            return undefined;
        }
        try {
            const blockNumberHex = (await this.db.get(this.getNullifierSpendBlockDBPath(tree, nullifier)));
            const blockNumber = Number.parseInt(blockNumberHex, 16);
            if (!Number.isSafeInteger(blockNumber) || blockNumber < 0) {
                throw new Error('Invalid stored nullifier spend block');
            }
            return { txid, blockNumber };
        }
        catch {
            // Old databases only retain txid. Callers can prove spend height from its canonical receipt.
            return { txid, blockNumber: undefined };
        }
    }
    /** Gets spend identity and height, with a txid-only fallback for old databases. */
    async getNullifierSpendMetadata(nullifier, treeIndex) {
        if ((0, is_defined_1.isDefined)(treeIndex)) {
            return this.getNullifierSpendMetadataForTree(nullifier, treeIndex);
        }
        const latestTree = await this.latestTree();
        for (let tree = latestTree; tree >= 0; tree -= 1) {
            // eslint-disable-next-line no-await-in-loop
            const metadata = await this.getNullifierSpendMetadataForTree(nullifier, tree);
            if ((0, is_defined_1.isDefined)(metadata)) {
                return metadata;
            }
        }
        return undefined;
    }
    /**
     * Adds nullifiers to database
     * @param nullifiers - nullifiers to add to db
     */
    async nullify(nullifiers) {
        for (const nullifier of nullifiers) {
            if (!Number.isSafeInteger(nullifier.blockNumber) || nullifier.blockNumber < 0) {
                throw new Error('Nullifier block number must be a non-negative safe integer');
            }
        }
        const existingMetadata = await Promise.all(nullifiers.map((nullifier) => this.getNullifierSpendMetadataForTree(nullifier.nullifier, nullifier.treeNumber)));
        const nullifierWriteBatch = nullifiers.flatMap((nullifier, index) => {
            const operations = [];
            const existingBlockNumber = existingMetadata[index]?.blockNumber;
            if ((0, is_defined_1.isDefined)(existingBlockNumber) && existingBlockNumber !== nullifier.blockNumber) {
                operations.push({
                    type: 'del',
                    key: this.getNullifierBlockIndexDBPath(existingBlockNumber, nullifier.treeNumber, nullifier.nullifier).join(':'),
                });
            }
            operations.push({
                type: 'put',
                key: this.getNullifierDBPath(nullifier.treeNumber, nullifier.nullifier).join(':'),
                value: nullifier.txid,
            }, {
                type: 'put',
                key: this.getNullifierSpendBlockDBPath(nullifier.treeNumber, nullifier.nullifier).join(':'),
                value: bytes_1.ByteUtils.hexlify(nullifier.blockNumber),
            }, {
                type: 'put',
                key: this.getNullifierBlockIndexDBPath(nullifier.blockNumber, nullifier.treeNumber, nullifier.nullifier).join(':'),
                value: '01',
            });
            return operations;
        });
        return this.db.batch(nullifierWriteBatch);
    }
    static parseNullifierBlockIndexKey(key) {
        const components = key.split(':');
        if (components.length < 3) {
            return undefined;
        }
        const [blockNumberHex, treeNumberHex, nullifier] = components.slice(-3);
        if (!/^[0-9a-f]{64}$/.test(blockNumberHex) || !/^[0-9a-f]{64}$/.test(treeNumberHex)) {
            return undefined;
        }
        const blockNumber = Number.parseInt(blockNumberHex, 16);
        const treeNumber = Number.parseInt(treeNumberHex, 16);
        if (!Number.isSafeInteger(blockNumber) ||
            blockNumber < 0 ||
            !Number.isSafeInteger(treeNumber) ||
            treeNumber < 0) {
            return undefined;
        }
        return { blockNumber, treeNumber, nullifier };
    }
    /** Atomically replaces nullifiers in a canonical replay range before its cursor advances. */
    async reconcileNullifiers(startBlock, endBlock, canonicalNullifiers, replaceAll) {
        if (!Number.isSafeInteger(startBlock) ||
            startBlock < 0 ||
            !Number.isSafeInteger(endBlock) ||
            endBlock < startBlock) {
            throw new Error('Nullifier reconciliation range is invalid');
        }
        for (const nullifier of canonicalNullifiers) {
            if (nullifier.blockNumber < startBlock || nullifier.blockNumber > endBlock) {
                throw new Error('Canonical nullifier is outside reconciliation range');
            }
        }
        const indexKeys = await this.db.getNamespaceKeys(this.getNullifierBlockIndexDBPrefix());
        const deleteKeys = new Set();
        const preservedDataKeys = new Set();
        for (const indexKey of indexKeys) {
            const index = UTXOMerkletree.parseNullifierBlockIndexKey(indexKey);
            if (!(0, is_defined_1.isDefined)(index)) {
                if (replaceAll) {
                    deleteKeys.add(indexKey);
                }
                continue;
            }
            const isInReplayRange = index.blockNumber >= startBlock && index.blockNumber <= endBlock;
            const shouldDelete = replaceAll ? index.blockNumber <= endBlock : isInReplayRange;
            if (shouldDelete) {
                deleteKeys.add(indexKey);
                deleteKeys.add(this.getNullifierDBPath(index.treeNumber, index.nullifier).join(':'));
                deleteKeys.add(this.getNullifierSpendBlockDBPath(index.treeNumber, index.nullifier).join(':'));
            }
            else if (replaceAll) {
                preservedDataKeys.add(this.getNullifierDBPath(index.treeNumber, index.nullifier).join(':'));
                preservedDataKeys.add(this.getNullifierSpendBlockDBPath(index.treeNumber, index.nullifier).join(':'));
            }
        }
        if (replaceAll) {
            const latestTree = await this.latestTree();
            for (let tree = 0; tree <= latestTree; tree += 1) {
                // Legacy databases have no block index, so first canonical replay removes both lanes.
                // eslint-disable-next-line no-await-in-loop
                const nullifierKeys = await this.db.getNamespaceKeys(this.getNullifierDBPath(tree, '').slice(0, -1));
                // eslint-disable-next-line no-await-in-loop
                const spendBlockKeys = await this.db.getNamespaceKeys(this.getNullifierSpendBlockDBPath(tree, '').slice(0, -1));
                nullifierKeys.forEach((key) => {
                    if (!preservedDataKeys.has(key)) {
                        deleteKeys.add(key);
                    }
                });
                spendBlockKeys.forEach((key) => {
                    if (!preservedDataKeys.has(key)) {
                        deleteKeys.add(key);
                    }
                });
            }
        }
        const reconcileBatch = Array.from(deleteKeys).map((key) => ({
            type: 'del',
            key,
        }));
        canonicalNullifiers.forEach((nullifier) => {
            reconcileBatch.push({
                type: 'put',
                key: this.getNullifierDBPath(nullifier.treeNumber, nullifier.nullifier).join(':'),
                value: nullifier.txid,
            }, {
                type: 'put',
                key: this.getNullifierSpendBlockDBPath(nullifier.treeNumber, nullifier.nullifier).join(':'),
                value: bytes_1.ByteUtils.hexlify(nullifier.blockNumber),
            }, {
                type: 'put',
                key: this.getNullifierBlockIndexDBPath(nullifier.blockNumber, nullifier.treeNumber, nullifier.nullifier).join(':'),
                value: '01',
            });
        });
        await this.db.batch(reconcileBatch);
    }
    /**
     * Adds unshield event to database
     * @param unshields - unshield events to add to db
     */
    async addUnshieldEvents(unshields, replaceExisting = false) {
        let newUnshields = unshields;
        if (!replaceExisting) {
            newUnshields = (0, is_defined_1.removeUndefineds)(await Promise.all(unshields.map(async (unshield) => {
                const hasExisting = await this.hasExistingUnshieldEvent(unshield);
                if (!hasExisting) {
                    return unshield;
                }
                return undefined;
            })));
        }
        // Build write batch for nullifiers
        const writeBatch = newUnshields.map((unshield) => ({
            type: 'put',
            key: this.getUnshieldEventsDBPath(unshield.txid, unshield.eventLogIndex, unshield.railgunTxid).join(':'),
            value: unshield,
        }));
        // Write to DB
        return this.db.batch(writeBatch, 'json');
    }
    async hasExistingUnshieldEvent(unshield) {
        const existingUnshieldEvents = await this.getAllUnshieldEventsForTxid(unshield.txid);
        return (0, is_defined_1.isDefined)(existingUnshieldEvents.find((existingUnshieldEvent) => existingUnshieldEvent.eventLogIndex === unshield.eventLogIndex));
    }
    /**
     * Gets Unshield events
     */
    async getAllUnshieldEventsForTxid(txid) {
        const strippedTxid = bytes_1.ByteUtils.formatToByteLength(txid, bytes_1.ByteLength.UINT_256, false);
        const namespace = this.getUnshieldEventsDBPath(strippedTxid, undefined, undefined);
        const keys = await this.db.getNamespaceKeys(namespace);
        const keySplits = keys.map((key) => key.split(':')).filter((keySplit) => keySplit.length === 6);
        return Promise.all(keySplits.map(async (keySplit) => {
            const unshieldEvent = (await this.db.get(keySplit, 'json'));
            unshieldEvent.timestamp = unshieldEvent.timestamp ?? undefined;
            return unshieldEvent;
        }));
    }
    async updateUnshieldEvent(unshieldEvent) {
        const replaceExisting = true;
        await this.addUnshieldEvents([unshieldEvent], replaceExisting);
    }
    // eslint-disable-next-line class-methods-use-this
    newLeafRootTrigger() {
        // Unused for UTXO merkletree
        return Promise.resolve();
    }
    validRootCallback(tree, lastValidLeafIndex) {
        return this.removeInvalidMerklerootDetailsIfNecessary(tree, lastValidLeafIndex);
    }
    invalidRootCallback(tree, lastKnownInvalidLeafIndex, lastKnownInvalidLeaf) {
        return this.updateInvalidMerklerootDetails(tree, lastKnownInvalidLeafIndex, lastKnownInvalidLeaf.blockNumber);
    }
    async updateInvalidMerklerootDetails(tree, lastKnownInvalidLeafIndex, lastKnownInvalidLeafBlockNumber) {
        const invalidMerklerootDetails = this.invalidMerklerootDetailsByTree[tree];
        if ((0, is_defined_1.isDefined)(invalidMerklerootDetails)) {
            if (invalidMerklerootDetails.position < lastKnownInvalidLeafIndex) {
                return;
            }
        }
        // Update invalid merkleroot details
        this.invalidMerklerootDetailsByTree[tree] = {
            position: lastKnownInvalidLeafIndex,
            blockNumber: lastKnownInvalidLeafBlockNumber,
        };
        await this.updateStoredMerkletreesMetadata(tree);
    }
    async removeInvalidMerklerootDetailsIfNecessary(tree, lastValidLeafIndex) {
        const invalidMerklerootDetails = this.invalidMerklerootDetailsByTree[tree];
        if (!(0, is_defined_1.isDefined)(invalidMerklerootDetails)) {
            return;
        }
        if (invalidMerklerootDetails.position > lastValidLeafIndex) {
            return;
        }
        delete this.invalidMerklerootDetailsByTree[tree];
        await this.updateStoredMerkletreesMetadata(tree);
    }
    getFirstInvalidMerklerootTree() {
        const invalidTrees = Object.keys(this.invalidMerklerootDetailsByTree);
        if (!invalidTrees.length) {
            return undefined;
        }
        return Number(invalidTrees.sort()[0]);
    }
}
exports.UTXOMerkletree = UTXOMerkletree;
//# sourceMappingURL=utxo-merkletree.js.map