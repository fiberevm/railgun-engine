import { ContractTransaction } from 'ethers';
import { Prover } from '../prover/prover';
import { Transaction } from './transaction';
import { SpendingSolutionGroup, UnshieldData } from '../models/txo-types';
import { AdaptID, TokenData } from '../models/formatted-types';
import { TransactionStructV2, TransactionStructV3 } from '../models/transaction-types';
import { Chain } from '../models/engine-types';
import { TransactNote } from '../note/transact-note';
import { PreparedRailgunTransaction, PreparedRailgunTransactionV2, TXIDVersion, TreeBalance } from '../models';
import { AbstractWallet } from '../wallet';
import { type RelayAdaptActionData } from '../contracts/relay-adapt/relay-adapt-helper';
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
     * Prepare exact unsigned inputs without asking the wallet to sign or generating proofs.
     * Prepared data includes private witness fields and must be stored as sensitive data.
     * @param wallet - wallet to spend from
     * @param txidVersion - transaction protocol version
     * @param encryptionKey - encryption key for wallet
     * @returns prepared transactions that can be authorized and proved later
     */
    prepareTransactions(wallet: AbstractWallet, txidVersion: TXIDVersion, encryptionKey: string, originShieldTxidForSpendabilityOverride?: string): Promise<{
        preparedTransactions: PreparedRailgunTransaction[];
    }>;
    /**
     * Builds one independently submit-able RelayAdapt transaction per spending group. Each AdaptID
     * hashes only that transaction's nullifiers and exact calls, while every reprepare is checked
     * against the same baseline witness identity.
     */
    prepareTransactionsForIndependentRelayAdapt(wallet: AbstractWallet, txidVersion: TXIDVersion.V2_PoseidonMerkle, encryptionKey: string, actionDataForTransaction: (transaction: PreparedRailgunTransactionV2, index: number) => RelayAdaptActionData, originShieldTxidForSpendabilityOverride?: string): Promise<{
        transactions: Array<{
            preparedTransaction: PreparedRailgunTransactionV2;
            actionData: RelayAdaptActionData;
            adaptParams: string;
        }>;
        relayAdaptAddress: string;
    }>;
    /**
     * Sign and prove requests returned by prepareTransactions without rebuilding transaction data.
     */
    generateTransactionsFromPrepared(prover: Prover, wallet: AbstractWallet, encryptionKey: string, preparedTransactions: PreparedRailgunTransaction[], progressCallback: (progress: number, status: string) => void): Promise<{
        provedTransactions: (TransactionStructV2 | TransactionStructV3)[];
    }>;
    /** Validates exact action data before signing, then proves and populates its bound relay call. */
    generateRelayAdaptTransactionFromPrepared(prover: Prover, wallet: AbstractWallet, encryptionKey: string, preparedTransactions: PreparedRailgunTransactionV2[], actionData: RelayAdaptActionData, progressCallback: (progress: number, status: string) => void): Promise<{
        provedTransactions: TransactionStructV2[];
        relayTransaction: ContractTransaction;
    }>;
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
