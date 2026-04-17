import { Prover } from '../prover/prover';
import { Transaction } from './transaction';
import { SpendingSolutionGroup, UnshieldData } from '../models/txo-types';
import { AdaptID, TokenData } from '../models/formatted-types';
import { TransactionStructV2, TransactionStructV3 } from '../models/transaction-types';
import { Chain } from '../models/engine-types';
import { TransactNote } from '../note/transact-note';
import { TXIDVersion, TreeBalance } from '../models';
import { AbstractWallet } from '../wallet';
export declare const GAS_ESTIMATE_VARIANCE_DUMMY_TO_ACTUAL_TRANSACTION = 9000;
export declare class TransactionBatch {
    private adaptID;
    private chain;
    private outputs;
    private unshieldDataMap;
    private overallBatchMinGasPrice;
    /**
     * Create TransactionBatch Object
     * @param chain - chain type/id of network
     */
    constructor(chain: Chain, overallBatchMinGasPrice?: bigint);
    addOutput(output: TransactNote): void;
    resetOutputs(): void;
    addUnshieldData(unshieldData: UnshieldData): void;
    resetUnshieldData(): void;
    private unshieldTotal;
    setAdaptID(adaptID: AdaptID): void;
    private getOutputTokenDatas;
    generateValidSpendingSolutionGroupsAllOutputs(wallet: AbstractWallet, txidVersion: TXIDVersion, originShieldTxidForSpendabilityOverride?: string): Promise<SpendingSolutionGroup[]>;
    /**
     * Generates spending solution groups for outputs
     * @param wallet - wallet to spend from
     */
    private generateValidSpendingSolutionGroups;
    private createSimpleSpendingSolutionGroupsIfPossible;
    /**
     * Finds exact group of UTXOs above required amount.
     */
    private static createSimpleSatisfyingUTXOGroup;
    /**
     * Finds array of UTXOs groups that satisfies the required amount, excluding an already-used array of UTXO IDs.
     */
    createComplexSatisfyingSpendingSolutionGroups(tokenData: TokenData, tokenOutputs: TransactNote[], treeSortedBalances: TreeBalance[]): SpendingSolutionGroup[];
    static getChangeOutput(wallet: AbstractWallet, spendingSolutionGroup: SpendingSolutionGroup): Optional<TransactNote>;
    /**
     * Generate proofs and return serialized transactions
     * @param prover - prover to use
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    generateTransactions(prover: Prover, wallet: AbstractWallet, txidVersion: TXIDVersion, encryptionKey: string, progressCallback: (progress: number, status: string) => void, _shouldGeneratePreTransactionPOIs?: boolean, originShieldTxidForSpendabilityOverride?: string): Promise<{
        provedTransactions: (TransactionStructV2 | TransactionStructV3)[];
    }>;
    private static logDummySpendingSolutionGroupsSummary;
    /**
     * Generate dummy proofs and return serialized transactions
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    generateDummyTransactions(prover: Prover, wallet: AbstractWallet, txidVersion: TXIDVersion, encryptionKey: string, originShieldTxidForSpendabilityOverride?: string): Promise<(TransactionStructV2 | TransactionStructV3)[]>;
    generateTransactionForSpendingSolutionGroup(spendingSolutionGroup: SpendingSolutionGroup, changeOutput: Optional<TransactNote>): Transaction;
}
