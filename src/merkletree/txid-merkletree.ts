import { PutBatch } from 'abstract-leveldown';
import { Database } from '../database/database';
import { Chain } from '../models/engine-types';
import {
  CommitmentProcessingGroupSize,
  MerklerootValidator,
  TREE_MAX_ITEMS,
} from '../models/merkletree-types';
import { Merkletree } from './merkletree';
import {
  TXIDMerkletreeData,
  RailgunTransactionWithHash,
} from '../models/formatted-types';
import { ByteLength, fromUTF8String, ByteUtils } from '../utils/bytes';
import { isDefined } from '../utils/is-defined';
import { TXIDVersion } from '../models';
import EngineDebug from '../debugger/debugger';
import { verifyMerkleProof } from './merkle-proof';

export class TXIDMerkletree extends Merkletree<RailgunTransactionWithHash> {
  // DO NOT MODIFY
  protected merkletreePrefix = 'railgun-transaction-ids';

  protected merkletreeType = 'TXID';

  shouldStoreMerkleroots: boolean;

  private constructor(
    db: Database,
    chain: Chain,
    txidVersion: TXIDVersion,
    merklerootValidator: MerklerootValidator,
  ) {
    const commitmentProcessingGroupSize = CommitmentProcessingGroupSize.XXLarge;

    super(db, chain, txidVersion, merklerootValidator, commitmentProcessingGroupSize);

    this.shouldStoreMerkleroots = false;
  }

  /**
   * Creates a TXIDMerkletree for wallet use.
   */
  static async createForWallet(
    db: Database,
    chain: Chain,
    txidVersion: TXIDVersion,
    merklerootValidator: MerklerootValidator,
  ): Promise<TXIDMerkletree> {
    const merkletree = new TXIDMerkletree(
      db,
      chain,
      txidVersion,
      merklerootValidator,
    );
    await merkletree.init();
    return merkletree;
  }

  /**
   * Gets Railgun Transaction data from txid tree.
   */
  async getRailgunTransaction(
    tree: number,
    index: number,
  ): Promise<Optional<RailgunTransactionWithHash>> {
    try {
      if (tree < 0 || index < 0) {
        return undefined;
      }
      return await this.getData(tree, index);
    } catch (err) {
      EngineDebug.log('Error getting railgun transaction');
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
      EngineDebug.error(err);
      return undefined;
    }
  }

  async getGlobalUTXOTreePositionForRailgunTransactionCommitment(
    tree: number,
    index: number,
    commitmentHash: string,
  ) {
    const railgunTransaction = await this.getRailgunTransaction(tree, index);
    if (!railgunTransaction) {
      throw new Error('Railgun transaction for tree/index not found');
    }
    const commitmentIndex = railgunTransaction.commitments
      .map((c) => ByteUtils.formatToByteLength(c, ByteLength.UINT_256))
      .indexOf(ByteUtils.formatToByteLength(commitmentHash, ByteLength.UINT_256));
    if (commitmentIndex < 0) {
      throw new Error('Could not find commitmentHash for RailgunTransaction');
    }
    return railgunTransaction.utxoBatchStartPositionOut + commitmentIndex;
  }

  async getRailgunTxidCurrentMerkletreeData(railgunTxid: string): Promise<TXIDMerkletreeData> {
    const txidIndex = await this.getTxidIndexByRailgunTxid(railgunTxid);
    if (!isDefined(txidIndex)) {
      throw new Error(`tree/index not found: railgun txid ${railgunTxid}`);
    }
    const { tree, index } = Merkletree.getTreeAndIndexFromGlobalPosition(txidIndex);
    const railgunTransaction = await this.getRailgunTransaction(tree, index);
    if (!isDefined(railgunTransaction)) {
      throw new Error('railgun transaction not found');
    }

    const currentMerkleProofForTree = await this.getMerkleProof(tree, index);
    if (!verifyMerkleProof(currentMerkleProofForTree)) {
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

  async railgunTxidOccurredBeforeBlockNumber(
    tree: number,
    index: number,
    blockNumber: number,
  ): Promise<boolean> {
    const railgunTransaction = await this.getRailgunTransaction(tree, index);
    if (!railgunTransaction) {
      throw new Error(`Railgun transaction at Txid tree ${tree} and index ${index} not found.`);
    }
    return railgunTransaction.blockNumber < blockNumber;
  }

  async getLatestRailgunTransaction(): Promise<Optional<RailgunTransactionWithHash>> {
    const { tree, index } = await this.getLatestTreeAndIndex();
    return this.getRailgunTransaction(tree, index);
  }

  async queueRailgunTransactions(
    railgunTransactionsWithTxids: RailgunTransactionWithHash[],
    maxTxidIndex: Optional<number>,
  ): Promise<void> {
    if (!railgunTransactionsWithTxids.length) {
      return;
    }

    const { tree: latestTree, index: latestIndex } = await this.getLatestTreeAndIndex();
    let nextTree = latestTree;
    let nextIndex = latestIndex; 

    const railgunTxidIndexLookupBatch: PutBatch[] = [];

    let batchTree = -1;
    let batchStartIndex = -1;
    let batchLeaves: RailgunTransactionWithHash[] = [];

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

  static isOutOfBounds(tree: number, index: number, maxTxidIndex?: number) {
    if (!isDefined(maxTxidIndex)) {
      return false;
    }
    return TXIDMerkletree.getGlobalPosition(tree, index) > maxTxidIndex;
  }

  static nextTreeAndIndex(tree: number, index: number): { tree: number; index: number } {
    if (index + 1 >= TREE_MAX_ITEMS) {
      return { tree: tree + 1, index: 0 };
    }
    return { tree, index: index + 1 };
  }

  async clearLeavesForInvalidVerificationHash(numLeavesToClear: number): Promise<void> {
    const { tree: latestTree, index: latestIndex } = await this.getLatestTreeAndIndex();
    const latestTxidIndex = TXIDMerkletree.getGlobalPosition(latestTree, latestIndex);
    const clearToTxidIndex = Math.max(-1, latestTxidIndex - numLeavesToClear);
    await this.clearLeavesAfterTxidIndex(clearToTxidIndex);
  }

  async clearLeavesAfterTxidIndex(txidIndex: number): Promise<void> {
    const lock = this.acquireUpdatesLock();
    try {
      // Remove any queued items
      this.writeQueue = [];

      const { tree, index } = TXIDMerkletree.getTreeAndIndexFromGlobalPosition(txidIndex);

      const { tree: latestTree, index: latestIndex } = await this.getLatestTreeAndIndex();

      for (let currentTree = tree; currentTree <= latestTree; currentTree += 1) {
        const startIndex = currentTree === tree ? index + 1 : 0;
        const max = currentTree === latestTree ? latestIndex : TREE_MAX_ITEMS - 1;
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
    } finally {
      this.releaseUpdatesLock();
    }
  }

  async getCurrentTxidIndex(): Promise<number> {
    const { tree, index } = await this.getLatestTreeAndIndex();
    return TXIDMerkletree.getGlobalPosition(tree, index);
  }

  // eslint-disable-next-line class-methods-use-this
  protected validRootCallback(): Promise<void> {
    // Unused for Txid merkletree
    return Promise.resolve();
  }

  // eslint-disable-next-line class-methods-use-this
  protected invalidRootCallback(): Promise<void> {
    // Unused for Txid merkletree
    return Promise.resolve();
  }

  private getRailgunTxidLookupDBPath(railgunTxid: string): string[] {
    const railgunTxidPrefix = fromUTF8String('railgun-txid-lookup');
    return [...this.getMerkletreeDBPrefix(), railgunTxidPrefix, railgunTxid].map((el) =>
      ByteUtils.formatToByteLength(el, ByteLength.UINT_256),
    );
  }

  async getTxidIndexByRailgunTxid(railgunTxid: string): Promise<Optional<number>> {
    try {
      return Number(await this.db.get(this.getRailgunTxidLookupDBPath(railgunTxid), 'utf8'));
    } catch (err) {
      return undefined;
    }
  }

  async getRailgunTransactionByTxid(
    railgunTxid: string,
  ): Promise<Optional<RailgunTransactionWithHash>> {
    try {
      const txidIndex = await this.getTxidIndexByRailgunTxid(railgunTxid);
      if (!isDefined(txidIndex)) {
        return undefined;
      }
      const { tree, index } = TXIDMerkletree.getTreeAndIndexFromGlobalPosition(txidIndex);
      return await this.getData(tree, index);
    } catch (err) {
      EngineDebug.log('Error getting railgun txid index');
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
      EngineDebug.error(err);
      return undefined;
    }
  }

  private getHistoricalMerklerootDBPath(tree: number, index: number): string[] {
    const merklerootPrefix = fromUTF8String('merkleroots');
    return [
      ...this.getMerkletreeDBPrefix(),
      merklerootPrefix,
      ByteUtils.hexlify(tree),
      ByteUtils.hexlify(index),
    ].map((el) => ByteUtils.formatToByteLength(el, ByteLength.UINT_256));
  }

  protected async newLeafRootTrigger(
    tree: number,
    index: number,
    leaf: string,
    merkleroot: string,
  ): Promise<void> {
    if (!this.shouldStoreMerkleroots) {
      return;
    }
    await this.db.put(this.getHistoricalMerklerootDBPath(tree, index), merkleroot);
  }

  async getHistoricalMerkleroot(tree: number, index: number): Promise<Optional<string>> {
    try {
      const merkleroot = (await this.db.get(
        this.getHistoricalMerklerootDBPath(tree, index),
      )) as string;
      return merkleroot;
    } catch (cause) {
      if (!(cause instanceof Error)) {
        throw new Error('Non-error thrown in getHistoricalMerkleroot', { cause });
      }
      return undefined;
    }
  }

  async getHistoricalMerklerootForTxidIndex(txidIndex: number): Promise<Optional<string>> {
    const { tree, index } = TXIDMerkletree.getTreeAndIndexFromGlobalPosition(txidIndex);
    return this.getHistoricalMerkleroot(tree, index);
  }
}
