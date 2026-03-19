import { Commitment, CommitmentSummary, CommitmentType, LegacyEncryptedCommitment, StoredReceiveCommitment, TransactCommitmentV2 } from '../models/formatted-types';
import { TransactionStructV2, TransactionStructV3 } from '../models/transaction-types';
export declare const convertTransactionStructToCommitmentSummary: (transactionStruct: TransactionStructV2 | TransactionStructV3, commitmentIndex: number) => CommitmentSummary;
export declare const isShieldCommitmentType: (commitmentType: CommitmentType) => boolean;
export declare const isReceiveShieldCommitment: (receiveCommitment: StoredReceiveCommitment) => boolean;
export declare const isTransactCommitmentType: (commitmentType: CommitmentType) => boolean;
export declare const isTransactCommitment: (commitment: Commitment) => commitment is TransactCommitmentV2 | LegacyEncryptedCommitment;
