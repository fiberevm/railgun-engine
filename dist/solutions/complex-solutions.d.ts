import { SpendingSolutionGroup, TXO } from '../models/txo-types';
import { TreeBalance } from '../models/wallet-types';
import { TransactNote } from '../note/transact-note';
export declare const createSpendingSolutionsForValue: (treeSortedBalances: TreeBalance[], remainingOutputs: TransactNote[], excludedUTXOIDPositions: string[], isUnshield: boolean) => SpendingSolutionGroup[];
/**
 * Finds next valid nullifier count above the current nullifier count.
 */
export declare const nextNullifierTarget: (utxoCount: number) => Optional<number>;
export declare const shouldAddMoreUTXOsForSolutionBatch: (currentNullifierCount: number, totalNullifierCount: number, currentSpend: bigint, totalRequired: bigint) => boolean;
/**
 * 1. Filter out UTXOs with value 0.
 * 2. Use exact match UTXO for totalRequired value if it exists.
 * 3. Sort by smallest UTXO ascending.
 * 4. Add UTXOs to the batch until we hit the totalRequired value, or exceed the UTXO input count maximum.
 */
export declare const findNextSolutionBatch: (treeBalance: TreeBalance, totalRequired: bigint, excludedUTXOIDPositions: string[]) => Optional<TXO[]>;
