import { RailgunTransaction, RailgunTransactionWithHash } from '../models/formatted-types';
export declare const getRailgunTransactionID: (railgunTransaction: {
    nullifiers: string[];
    commitments: string[];
    boundParamsHash: string;
}) => bigint;
export declare const getRailgunTransactionIDFromBigInts: (nullifiers: bigint[], commitments: bigint[], boundParamsHash: bigint) => bigint;
export declare const getRailgunTransactionIDHex: (railgunTransaction: {
    nullifiers: string[];
    commitments: string[];
    boundParamsHash: string;
}) => string;
export declare const getRailgunTxidLeafHash: (railgunTxidBigInt: bigint, utxoTreeIn: bigint, globalTreePosition: bigint) => string;
export declare const createRailgunTransactionWithHash: (railgunTransaction: RailgunTransaction) => RailgunTransactionWithHash;
export declare const calculateRailgunTransactionVerificationHash: (previousVerificationHash: Optional<string>, firstNullifier: string) => string;
