import { ContractTransaction, Provider, TransactionRequest } from 'ethers';
import { Chain } from '../../models/engine-types';
import { TXIDVersion } from '../../models/poi-types';
import { ShieldRequestStruct } from '../../abi/typechain/RelayAdapt';
import { TransactionReceiptLog, TransactionStructV2, TransactionStructV3 } from '../../models';
import { RelayAdaptV2Contract } from './V2/relay-adapt-v2';
import { RelayAdaptV3Contract } from './V3/relay-adapt-v3';
export declare class RelayAdaptVersionedSmartContracts {
    static getRelayAdaptContract(txidVersion: TXIDVersion, chain: Chain): RelayAdaptV2Contract | RelayAdaptV3Contract;
    static populateShieldBaseToken(txidVersion: TXIDVersion, chain: Chain, shieldRequest: ShieldRequestStruct): Promise<ContractTransaction>;
    static populateUnshieldBaseToken(txidVersion: TXIDVersion, chain: Chain, transactions: (TransactionStructV2 | TransactionStructV3)[], unshieldAddress: string, random31Bytes: string, useDummyProof: boolean, sendWithPublicWallet: boolean): Promise<ContractTransaction>;
    static populateCrossContractCalls(txidVersion: TXIDVersion, chain: Chain, unshieldTransactions: (TransactionStructV2 | TransactionStructV3)[], crossContractCalls: ContractTransaction[], relayShieldRequests: ShieldRequestStruct[], random31Bytes: string, isGasEstimate: boolean, isBroadcasterTransaction: boolean, minGasLimit?: bigint): Promise<ContractTransaction>;
    static getRelayAdaptParamsUnshieldBaseToken(txidVersion: TXIDVersion, chain: Chain, dummyUnshieldTransactions: (TransactionStructV2 | TransactionStructV3)[], unshieldAddress: string, random31Bytes: string, sendWithPublicWallet: boolean): Promise<string>;
    static getRelayAdaptParamsCrossContractCalls(txidVersion: TXIDVersion, chain: Chain, dummyUnshieldTransactions: (TransactionStructV2 | TransactionStructV3)[], crossContractCalls: ContractTransaction[], relayShieldRequests: ShieldRequestStruct[], random: string, isBroadcasterTransaction: boolean, minGasLimit?: bigint): Promise<string>;
    static estimateGasWithErrorHandler(txidVersion: TXIDVersion, provider: Provider, transaction: ContractTransaction | TransactionRequest): Promise<bigint>;
    static getRelayAdaptCallError(txidVersion: TXIDVersion, receiptLogs: TransactionReceiptLog[]): Optional<string>;
    static parseRelayAdaptReturnValue(txidVersion: TXIDVersion, data: string): {
        callIndex?: number | undefined;
        error: string;
    } | undefined;
}
