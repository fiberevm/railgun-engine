import { RailgunWallet } from '../wallet/railgun-wallet';
import { Prover, ProverProgressCallback } from '../prover/prover';
import { AdaptID, TokenData } from '../models/formatted-types';
import { TXO, UnshieldData } from '../models/txo-types';
import { Chain } from '../models/engine-types';
import { TransactNote } from '../note/transact-note';
import { UnprovedTransactionInputs, RailgunTransactionRequest } from '../models/prover-types';
import { BoundParamsStruct } from '../abi/typechain/RailgunSmartWallet';
import { TXIDVersion } from '../models/poi-types';
import { PoseidonMerkleVerifier } from '../abi/typechain';
import { TransactionStructV2, TransactionStructV3 } from '../models/transaction-types';
declare class Transaction {
    private readonly adaptID;
    private readonly chain;
    private readonly tokenOutputs;
    private unshieldNote;
    private unshieldFlag;
    private readonly tokenData;
    private readonly tokenHash;
    private readonly spendingTree;
    private readonly utxos;
    /**
     * Create ERC20Transaction Object
     * @param tokenAddress - token address, unformatted
     * @param tokenType - enum of token type
     * @param chain - chain type/id of network
     * @param spendingTree - tree index to spend from
     * @param utxos - UTXOs to spend from
     */
    constructor(chain: Chain, tokenData: TokenData, spendingTree: number, utxos: TXO[], tokenOutputs: TransactNote[], adaptID: AdaptID);
    addUnshieldData(unshieldData: UnshieldData, unshieldValue: bigint): void;
    get unshieldValue(): bigint;
    /**
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key of wallet
     */
    generateTransactionRequest(wallet: RailgunWallet, txidVersion: TXIDVersion, encryptionKey: string, globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct): Promise<RailgunTransactionRequest>;
    /**
     * Generate proof and return serialized transaction
     * @param prover - prover to use
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    generateProvedTransaction(txidVersion: TXIDVersion, prover: Prover, unprovedTransactionInputs: UnprovedTransactionInputs, progressCallback: ProverProgressCallback): Promise<TransactionStructV2 | TransactionStructV3>;
    /**
     * Return serialized transaction with zero'd proof for gas estimates.
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    generateDummyProvedTransaction(prover: Prover, transactionRequest: RailgunTransactionRequest): Promise<TransactionStructV2 | TransactionStructV3>;
    private static assertCanProve;
    private static createTransactionStructV2;
    private static createTransactionStructV3;
    static getLocalBoundParams(transaction: TransactionStructV2 | TransactionStructV3): BoundParamsStruct | PoseidonMerkleVerifier.TransactionBoundParamsStruct;
}
export { Transaction };
