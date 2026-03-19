import { ContractTransaction } from 'ethers';
import { Chain } from '../models/engine-types';
import { TXIDVersion } from '../models/poi-types';
import { AddressData } from '../key-derivation/bech32';
import { TokenDataGetter } from '../token/token-data-getter';
export declare const extractFirstNoteERC20AmountMapFromTransactionRequest: (txidVersion: TXIDVersion, chain: Chain, transactionRequest: ContractTransaction, useRelayAdapt: boolean, contractAddress: string, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<Record<string, bigint>>;
export declare const extractRailgunTransactionDataFromTransactionRequest: (txidVersion: TXIDVersion, chain: Chain, transactionRequest: ContractTransaction, useRelayAdapt: boolean, contractAddress: string, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<import("..").ExtractedRailgunTransactionData>;
