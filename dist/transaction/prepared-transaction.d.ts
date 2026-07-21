import { PreparedRailgunTransactionV2 } from '../models/prover-types';
export declare const assertPreparedRailgunTransactionV2: (value: unknown) => asserts value is PreparedRailgunTransactionV2;
/** Produces stable JSON for KMS encryption. Plaintext includes private proof witness data. */
export declare const serializePreparedRailgunTransactionV2: (preparedTransaction: PreparedRailgunTransactionV2) => string;
/** Restores and validates a V2 witness. Corrupt or semantically inconsistent payloads fail closed. */
export declare const deserializePreparedRailgunTransactionV2: (serialized: string) => PreparedRailgunTransactionV2;
