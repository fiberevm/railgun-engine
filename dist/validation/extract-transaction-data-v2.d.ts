import { ContractTransaction } from 'ethers';
import { Chain } from '../models/engine-types';
import { AddressData } from '../key-derivation';
import { CommitmentCiphertextV2 } from '../models/formatted-types';
import { ExtractedRailgunTransactionData } from '../models/transaction-types';
import { TransactNote } from '../note/transact-note';
import { TokenDataGetter } from '../token/token-data-getter';
export declare const extractFirstNoteERC20AmountMapFromTransactionRequestV2: (chain: Chain, transactionRequest: ContractTransaction, useRelayAdapt: boolean, contractAddress: string, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<Record<string, bigint>>;
export declare const extractRailgunTransactionDataFromTransactionRequestV2: (chain: Chain, transactionRequest: ContractTransaction, useRelayAdapt: boolean, contractAddress: string, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<ExtractedRailgunTransactionData>;
export declare const extractNPKFromCommitmentCiphertextV2: (chain: Chain, commitmentCiphertext: CommitmentCiphertextV2, receivingViewingPrivateKey: Uint8Array, receivingRailgunAddressData: AddressData, tokenDataGetter: TokenDataGetter) => Promise<Optional<bigint>>;
export declare const extractERC20AmountFromTransactNote: (decryptedReceiverNote: Optional<TransactNote>, commitmentHash: string, receivingRailgunAddressData: AddressData) => Promise<Optional<{
    tokenAddress: string;
    amount: bigint;
}>>;
