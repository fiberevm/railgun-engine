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
        // Return if nullifier is set
        let nullifierTxid;
        // Check specific tree if provided
        if ((0, is_defined_1.isDefined)(treeIndex)) {
            try {
                nullifierTxid = (await this.db.get(this.getNullifierDBPath(treeIndex, nullifier)));
            }
            catch {
                nullifierTxid = undefined;
            }
            return nullifierTxid;
        }
        const latestTree = await this.latestTree();
        for (let tree = latestTree; tree >= 0; tree -= 1) {
            try {
                // eslint-disable-next-line no-await-in-loop
                nullifierTxid = (await this.db.get(this.getNullifierDBPath(tree, nullifier)));
                break;
            }
            catch {
                nullifierTxid = undefined;
            }
        }
        return nullifierTxid;
    }
    /**
     * Adds nullifiers to database
     * @param nullifiers - nullifiers to add to db
     */
    async nullify(nullifiers) {
        // Find railgunTxids per nullifier
        // Build write batch for nullifiers
        const nullifierWriteBatch = nullifiers.map((nullifier) => ({
            type: 'put',
            key: this.getNullifierDBPath(nullifier.treeNumber, nullifier.nullifier).join(':'),
            value: nullifier.txid,
        }));
        // Write to DB
        return this.db.batch(nullifierWriteBatch);
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