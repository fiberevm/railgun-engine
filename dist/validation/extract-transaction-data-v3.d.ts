import { ContractTransaction } from 'ethers';
import { Chain } from '../models/engine-types';
import { AddressData } from '../key-derivation';
import { ExtractedRailgunTransactionData } from '../models/transaction-types';
import { TokenDataGetter } from '../token/token-data-getter';
import { CommitmentCiphertextV3 } from '../models';
export declare const extractFirstNoteERC20AmountMapFromTransactionRequestV3: (chain: Chain, transactionRequest: ContractTransaction, contractAddress: string, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<Record<string, bigint>>;
export declare const extractRailgunTransactionDataFromTransactionRequestV3: (chain: Chain, transactionRequest: ContractTransaction, contractAddress: string, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<ExtractedRailgunTransactionData>;
export declare const extractNPKFromCommitmentCiphertextV3: (chain: Chain, commitmentCiphertext: CommitmentCiphertextV3, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<Optional<bigint>>;
