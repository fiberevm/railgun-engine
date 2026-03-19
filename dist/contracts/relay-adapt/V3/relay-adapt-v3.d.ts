import { ContractTransaction, Provider, TransactionRequest, Log } from 'ethers';
import { TransactionReceiptLog } from '../../../models/formatted-types';
import { ShieldRequestStruct } from '../../../abi/typechain/RailgunSmartWallet';
import { TransactionStructV2 } from '../../../models/transaction-types';
export declare const RETURN_DATA_RELAY_ADAPT_STRING_PREFIX = "0x5c0dee5d";
export declare const RETURN_DATA_STRING_PREFIX = "0x08c379a0";
export declare const MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT: bigint;
export declare class RelayAdaptV3Contract {
    private readonly contract;
    readonly address: string;
    /**
     * Connect to Railgun instance on network
     * @param relayAdaptV3ContractAddress - address of Railgun relay adapt contract
     * @param provider - Network provider
     */
    constructor(relayAdaptV3ContractAddress: string, provider: Provider);
    populateShieldBaseToken(shieldRequest: ShieldRequestStruct): Promise<ContractTransaction>;
    populateMulticall(calls: ContractTransaction[], shieldRequests: ShieldRequestStruct[]): Promise<ContractTransaction>;
    /**
     * @returns Populated transaction
     */
    private populateRelayShields;
    private getOrderedCallsForUnshieldBaseToken;
    getRelayAdaptParamsUnshieldBaseToken(dummyTransactions: TransactionStructV2[], unshieldAddress: string, random: string): Promise<string>;
    populateUnshieldBaseToken(transactions: TransactionStructV2[], unshieldAddress: string, random31Bytes: string): Promise<ContractTransaction>;
    /**
     * @returns Populated transaction
     */
    private populateRelayTransfers;
    private getOrderedCallsForCrossContractCalls;
    private static shouldRequireSuccessForCrossContractCalls;
    getRelayAdaptParamsCrossContractCalls(dummyUnshieldTransactions: TransactionStructV2[], crossContractCalls: ContractTransaction[], relayShieldRequests: ShieldRequestStruct[], random: string, isBroadcasterTransaction: boolean, minGasLimit?: bigint): Promise<string>;
    populateCrossContractCalls(unshieldTransactions: TransactionStructV2[], crossContractCalls: ContractTransaction[], relayShieldRequests: ShieldRequestStruct[], random31Bytes: string, isGasEstimate: boolean, isBroadcasterTransaction: boolean, minGasLimit?: bigint): Promise<ContractTransaction>;
    static getMinimumGasLimitForContract(minimumGasLimit: bigint): bigint;
    static estimateGasWithErrorHandler(provider: Provider, transaction: ContractTransaction | TransactionRequest): Promise<bigint>;
    static extractGasEstimateCallFailedIndexAndErrorText(errMessage: string): {
        callFailedIndexString: string;
        errorMessage: string;
    };
    /**
     * Generates Relay multicall given a list of ordered calls.
     * @returns populated transaction
     */
    private populateRelayMulticall;
    /**
     * Generates Relay multicall given a list of transactions and ordered calls.
     * @returns populated transaction
     */
    private populateRelay;
    private static getCallErrorTopic;
    static getRelayAdaptCallError(receiptLogs: TransactionReceiptLog[] | readonly Log[]): Optional<string>;
    static parseRelayAdaptReturnValue(returnValue: string): Optional<{
        callIndex?: number;
        error: string;
    }>;
    private static customRelayAdaptErrorParse;
    private static parseRelayAdaptStringError;
}
