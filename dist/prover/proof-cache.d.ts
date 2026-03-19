import { Proof, UnprovedTransactionInputs } from '../models/prover-types';
export declare class ProofCache {
    private static cache;
    static get(transactionRequest: UnprovedTransactionInputs): Optional<Proof>;
    static store(transactionRequest: UnprovedTransactionInputs, proof: Proof): void;
}
