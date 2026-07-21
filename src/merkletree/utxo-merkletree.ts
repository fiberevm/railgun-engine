import type { AbstractBatch, PutBatch } from 'abstract-leveldown';
import { Database } from '../database/database';
import { Chain } from '../models/engine-types';
import {
  CommitmentProcessingGroupSize,
  InvalidMerklerootDetails,
  MerklerootValidator,
} from '../models/merkletree-types';
import { ByteLength, ByteUtils } from '../utils/bytes';
import { Merkletree } from './merkletree';
import { Commitment, Nullifier, NullifierSpendMetadata } from '../models/formatted-types';
import { UnshieldStoredEvent } from '../models/event-types';
import { isDefined, removeUndefineds } from '../utils/is-defined';
import { TXIDVersion } from '../models';

export class UTXOMerkletree extends Merkletree<Commitment> {
  // DO NOT MODIFY
  protected merkletreePrefix = 'merkletree-erc20';

  protected merkletreeType = 'UTXO';

  private constructor(
    db: Database,
    chain: Chain,
    txidVersion: TXIDVersion,
    merklerootValidator: MerklerootValidator,
  ) {
    super(db, chain, txidVersion, merklerootValidator, CommitmentProcessingGroupSize.XXXXLarge);
  }

  static async create(
    db: Database,
    chain: Chain,
    txidVersion: TXIDVersion,
    merklerootValidator: MerklerootValidator,
  ): Promise<UTXOMerkletree> {
    const merkletree = new UTXOMerkletree(db, chain, txidVersion, merklerootValidator);
    await merkletree.init();
    return merkletree;
  }

  /**
   * Gets Commitment from UTXO tree
   */
  async getCommitment(tree: number, index: number): Promise<Commitment> {
    return this.getData(tree, index);
  }

  async getCommitmentRange(tree: number, start: number, end: number): Promise<Commitment[]> {
    return this.getDataRange(tree, start, end);
  }

  /**
   * Gets Commitment from UTXO tree
   */
  async getCommitmentSafe(tree: number, index: number): Promise<Optional<Commitment>> {
    try {
      return await this.getData(tree, index);
    } catch (err) {
      return undefined;
    }
  }

  /**
   * Construct DB path from nullifier
   * @param tree - tree nullifier is for
   * @param nullifier - nullifier to get path for
   * @returns database path
   */
  getNullifierDBPath(tree: number, nullifier: string): string[] {
    return [
      ...this.getTreeDBPrefix(tree),
      ByteUtils.hexlify(ByteUtils.FULL_32_BITS - 1n), // 2^32-2
      ByteUtils.hexlify(nullifier),
    ].map((el) => ByteUtils.formatToByteLength(el, ByteLength.UINT_256));
  }

  /** Stores spend height separately so existing nullifier txid records stay backward-compatible. */
  getNullifierSpendBlockDBPath(tree: number, nullifier: string): string[] {
    return [
      ...this.getTreeDBPrefix(tree),
      ByteUtils.hexlify(ByteUtils.FULL_32_BITS - 3n), // 2^32-4
      ByteUtils.hexlify(nullifier),
    ].map((el) => ByteUtils.formatToByteLength(el, ByteLength.UINT_256));
  }

  private getNullifierBlockIndexDBPrefix(): string[] {
    return [
      ...this.getMerkletreeDBPrefix(),
      ByteUtils.hexlify(ByteUtils.FULL_32_BITS - 4n), // 2^32-5
    ].map((el) => ByteUtils.formatToByteLength(el, ByteLength.UINT_256));
  }

  private getNullifierBlockIndexDBPath(
    blockNumber: number,
    tree: number,
    nullifier: string,
  ): string[] {
    return [
      ...this.getNullifierBlockIndexDBPrefix(),
      ByteUtils.hexlify(blockNumber),
      ByteUtils.hexlify(tree),
      ByteUtils.hexlify(nullifier),
    ].map((el) => ByteUtils.formatToByteLength(el, ByteLength.UINT_256));
  }

  /**
   * Construct DB path from unshield transaction
   * @param txid - unshield txid to get path for
   * @returns database path
   */
  getUnshieldEventsDBPath(
    txid: Optional<string>,
    eventLogIndex: Optional<number>,
    railgunTxid: Optional<string>,
  ): string[] {
    const path = [
      ...this.getMerkletreeDBPrefix(),
      ByteUtils.hexlify(ByteUtils.FULL_32_BITS - 2n), // 2^32-3
    ];
    if (txid != null) {
      path.push(ByteUtils.hexlify(txid));
    }
    if (eventLogIndex != null) {
      path.push(eventLogIndex.toString(16));
    } else if (railgunTxid != null) {
      path.push(railgunTxid);
    }
    return path.map((el) => ByteUtils.formatToByteLength(el, ByteLength.UINT_256));
  }

  /**
   * Gets nullifier by its id
   * @param {string} nullifier - nullifier to check
   * @param {number} treeIndex - optional tree to check
   * @returns Nullifier data, including txid of spent transaction
   */
  async getNullifierTxid(nullifier: string, treeIndex?: number): Promise<Optional<string>> {
    return (await this.getNullifierSpendMetadata(nullifier, treeIndex))?.txid;
  }

  private async getNullifierSpendMetadataForTree(
    nullifier: string,
    tree: number,
  ): Promise<Optional<NullifierSpendMetadata>> {
    let txid: string;
    try {
      txid = (await this.db.get(this.getNullifierDBPath(tree, nullifier))) as string;
    } catch {
      return undefined;
    }

    try {
      const blockNumberHex = (await this.db.get(
        this.getNullifierSpendBlockDBPath(tree, nullifier),
      )) as string;
      const blockNumber = Number.parseInt(blockNumberHex, 16);
      if (!Number.isSafeInteger(blockNumber) || blockNumber < 0) {
        throw new Error('Invalid stored nullifier spend block');
      }
      return { txid, blockNumber };
    } catch {
      // Old databases only retain txid. Callers can prove spend height from its canonical receipt.
      return { txid, blockNumber: undefined };
    }
  }

  /** Gets spend identity and height, with a txid-only fallback for old databases. */
  async getNullifierSpendMetadata(
    nullifier: string,
    treeIndex?: number,
  ): Promise<Optional<NullifierSpendMetadata>> {
    if (isDefined(treeIndex)) {
      return this.getNullifierSpendMetadataForTree(nullifier, treeIndex);
    }

    const latestTree = await this.latestTree();
    for (let tree = latestTree; tree >= 0; tree -= 1) {
      // eslint-disable-next-line no-await-in-loop
      const metadata = await this.getNullifierSpendMetadataForTree(nullifier, tree);
      if (isDefined(metadata)) {
        return metadata;
      }
    }
    return undefined;
  }

  /**
   * Adds nullifiers to database
   * @param nullifiers - nullifiers to add to db
   */
  async nullify(nullifiers: Nullifier[]): Promise<void> {
    for (const nullifier of nullifiers) {
      if (!Number.isSafeInteger(nullifier.blockNumber) || nullifier.blockNumber < 0) {
        throw new Error('Nullifier block number must be a non-negative safe integer');
      }
    }

    const existingMetadata = await Promise.all(
      nullifiers.map((nullifier) =>
        this.getNullifierSpendMetadataForTree(nullifier.nullifier, nullifier.treeNumber),
      ),
    );
    const nullifierWriteBatch: AbstractBatch[] = nullifiers.flatMap((nullifier, index) => {
      const operations: AbstractBatch[] = [];
      const existingBlockNumber = existingMetadata[index]?.blockNumber;
      if (isDefined(existingBlockNumber) && existingBlockNumber !== nullifier.blockNumber) {
        operations.push({
          type: 'del',
          key: this.getNullifierBlockIndexDBPath(
            existingBlockNumber,
            nullifier.treeNumber,
            nullifier.nullifier,
          ).join(':'),
        });
      }
      operations.push(
        {
          type: 'put',
          key: this.getNullifierDBPath(nullifier.treeNumber, nullifier.nullifier).join(':'),
          value: nullifier.txid,
        },
        {
          type: 'put',
          key: this.getNullifierSpendBlockDBPath(nullifier.treeNumber, nullifier.nullifier).join(
            ':',
          ),
          value: ByteUtils.hexlify(nullifier.blockNumber),
        },
        {
          type: 'put',
          key: this.getNullifierBlockIndexDBPath(
            nullifier.blockNumber,
            nullifier.treeNumber,
            nullifier.nullifier,
          ).join(':'),
          value: '01',
        },
      );
      return operations;
    });

    return this.db.batch(nullifierWriteBatch);
  }

  private static parseNullifierBlockIndexKey(
    key: string,
  ): Optional<{ blockNumber: number; treeNumber: number; nullifier: string }> {
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
    if (
      !Number.isSafeInteger(blockNumber) ||
      blockNumber < 0 ||
      !Number.isSafeInteger(treeNumber) ||
      treeNumber < 0
    ) {
      return undefined;
    }
    return { blockNumber, treeNumber, nullifier };
  }

  /** Atomically replaces nullifiers in a canonical replay range before its cursor advances. */
  async reconcileNullifiers(
    startBlock: number,
    endBlock: number,
    canonicalNullifiers: Nullifier[],
    replaceAll: boolean,
  ): Promise<void> {
    if (
      !Number.isSafeInteger(startBlock) ||
      startBlock < 0 ||
      !Number.isSafeInteger(endBlock) ||
      endBlock < startBlock
    ) {
      throw new Error('Nullifier reconciliation range is invalid');
    }
    for (const nullifier of canonicalNullifiers) {
      if (nullifier.blockNumber < startBlock || nullifier.blockNumber > endBlock) {
        throw new Error('Canonical nullifier is outside reconciliation range');
      }
    }

    const indexKeys = await this.db.getNamespaceKeys(this.getNullifierBlockIndexDBPrefix());
    const deleteKeys = new Set<string>();
    const preservedDataKeys = new Set<string>();
    for (const indexKey of indexKeys) {
      const index = UTXOMerkletree.parseNullifierBlockIndexKey(indexKey);
      if (!isDefined(index)) {
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
        deleteKeys.add(
          this.getNullifierSpendBlockDBPath(index.treeNumber, index.nullifier).join(':'),
        );
      } else if (replaceAll) {
        preservedDataKeys.add(this.getNullifierDBPath(index.treeNumber, index.nullifier).join(':'));
        preservedDataKeys.add(
          this.getNullifierSpendBlockDBPath(index.treeNumber, index.nullifier).join(':'),
        );
      }
    }

    if (replaceAll) {
      const latestTree = await this.latestTree();
      for (let tree = 0; tree <= latestTree; tree += 1) {
        // Legacy databases have no block index, so first canonical replay removes both lanes.
        // eslint-disable-next-line no-await-in-loop
        const nullifierKeys = await this.db.getNamespaceKeys(
          this.getNullifierDBPath(tree, '').slice(0, -1),
        );
        // eslint-disable-next-line no-await-in-loop
        const spendBlockKeys = await this.db.getNamespaceKeys(
          this.getNullifierSpendBlockDBPath(tree, '').slice(0, -1),
        );
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

    const reconcileBatch: AbstractBatch[] = Array.from(deleteKeys).map((key) => ({
      type: 'del',
      key,
    }));
    canonicalNullifiers.forEach((nullifier) => {
      reconcileBatch.push(
        {
          type: 'put',
          key: this.getNullifierDBPath(nullifier.treeNumber, nullifier.nullifier).join(':'),
          value: nullifier.txid,
        },
        {
          type: 'put',
          key: this.getNullifierSpendBlockDBPath(nullifier.treeNumber, nullifier.nullifier).join(
            ':',
          ),
          value: ByteUtils.hexlify(nullifier.blockNumber),
        },
        {
          type: 'put',
          key: this.getNullifierBlockIndexDBPath(
            nullifier.blockNumber,
            nullifier.treeNumber,
            nullifier.nullifier,
          ).join(':'),
          value: '01',
        },
      );
    });
    await this.db.batch(reconcileBatch);
  }

  /**
   * Adds unshield event to database
   * @param unshields - unshield events to add to db
   */
  async addUnshieldEvents(
    unshields: UnshieldStoredEvent[],
    replaceExisting = false,
  ): Promise<void> {
    let newUnshields: UnshieldStoredEvent[] = unshields;
    if (!replaceExisting) {
      newUnshields = removeUndefineds(
        await Promise.all(
          unshields.map(async (unshield) => {
            const hasExisting = await this.hasExistingUnshieldEvent(unshield);
            if (!hasExisting) {
              return unshield;
            }
            return undefined;
          }),
        ),
      );
    }

    // Build write batch for nullifiers
    const writeBatch: PutBatch[] = newUnshields.map((unshield) => ({
      type: 'put',
      key: this.getUnshieldEventsDBPath(
        unshield.txid,
        unshield.eventLogIndex,
        unshield.railgunTxid,
      ).join(':'),
      value: unshield,
    }));

    // Write to DB
    return this.db.batch(writeBatch, 'json');
  }

  async hasExistingUnshieldEvent(unshield: UnshieldStoredEvent): Promise<boolean> {
    const existingUnshieldEvents = await this.getAllUnshieldEventsForTxid(unshield.txid);
    return isDefined(
      existingUnshieldEvents.find(
        (existingUnshieldEvent) => existingUnshieldEvent.eventLogIndex === unshield.eventLogIndex,
      ),
    );
  }

  /**
   * Gets Unshield events
   */
  async getAllUnshieldEventsForTxid(txid: string): Promise<UnshieldStoredEvent[]> {
    const strippedTxid = ByteUtils.formatToByteLength(txid, ByteLength.UINT_256, false);
    const namespace = this.getUnshieldEventsDBPath(strippedTxid, undefined, undefined);
    const keys: string[] = await this.db.getNamespaceKeys(namespace);
    const keySplits = keys.map((key) => key.split(':')).filter((keySplit) => keySplit.length === 6);

    return Promise.all(
      keySplits.map(async (keySplit) => {
        const unshieldEvent = (await this.db.get(keySplit, 'json')) as UnshieldStoredEvent;
        unshieldEvent.timestamp = unshieldEvent.timestamp ?? undefined;
        return unshieldEvent;
      }),
    );
  }

  async updateUnshieldEvent(unshieldEvent: UnshieldStoredEvent): Promise<void> {
    const replaceExisting = true;
    await this.addUnshieldEvents([unshieldEvent], replaceExisting);
  }

  // eslint-disable-next-line class-methods-use-this
  protected newLeafRootTrigger(): Promise<void> {
    // Unused for UTXO merkletree
    return Promise.resolve();
  }

  protected validRootCallback(tree: number, lastValidLeafIndex: number): Promise<void> {
    return this.removeInvalidMerklerootDetailsIfNecessary(tree, lastValidLeafIndex);
  }

  protected invalidRootCallback(
    tree: number,
    lastKnownInvalidLeafIndex: number,
    lastKnownInvalidLeaf: Commitment,
  ): Promise<void> {
    return this.updateInvalidMerklerootDetails(
      tree,
      lastKnownInvalidLeafIndex,
      lastKnownInvalidLeaf.blockNumber,
    );
  }

  async updateInvalidMerklerootDetails(
    tree: number,
    lastKnownInvalidLeafIndex: number,
    lastKnownInvalidLeafBlockNumber: number,
  ): Promise<void> {
    const invalidMerklerootDetails: Optional<InvalidMerklerootDetails> =
      this.invalidMerklerootDetailsByTree[tree];
    if (isDefined(invalidMerklerootDetails)) {
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

  async removeInvalidMerklerootDetailsIfNecessary(tree: number, lastValidLeafIndex: number) {
    const invalidMerklerootDetails: Optional<InvalidMerklerootDetails> =
      this.invalidMerklerootDetailsByTree[tree];
    if (!isDefined(invalidMerklerootDetails)) {
      return;
    }
    if (invalidMerklerootDetails.position > lastValidLeafIndex) {
      return;
    }
    delete this.invalidMerklerootDetailsByTree[tree];
    await this.updateStoredMerkletreesMetadata(tree);
  }

  getFirstInvalidMerklerootTree(): Optional<number> {
    const invalidTrees = Object.keys(this.invalidMerklerootDetailsByTree);
    if (!invalidTrees.length) {
      return undefined;
    }
    return Number(invalidTrees.sort()[0]);
  }
}
