/// <reference types="node" />
import { ArtifactGetter, FormattedCircuitInputsRailgun, UnprovedTransactionInputs, Proof, PublicInputsRailgun, SnarkProof, NativeProverFormattedJsonInputsRailgun } from '../models/prover-types';
import { TXIDVersion } from '../models';
type NativeProveRailgun = (circuitId: number, datBuffer: Buffer, zkeyBuffer: Buffer, inputJson: NativeProverFormattedJsonInputsRailgun, progressCallback: ProverProgressCallback) => Proof;
type Groth16FullProveRailgun = (formattedInputs: FormattedCircuitInputsRailgun, wasm: Optional<ArrayLike<number>>, zkey: ArrayLike<number>, logger: {
    debug: (log: string) => void;
}, dat: Optional<ArrayLike<number>>, progressCallback: ProverProgressCallback) => Promise<{
    proof: Proof;
    publicSignals?: string[];
}>;
type Groth16Verify = Optional<(vkey: object, publicSignals: bigint[], proof: Proof) => Promise<boolean>>;
export type SnarkJSGroth16 = {
    fullProve: (formattedInputs: Partial<Record<string, bigint | bigint[] | bigint[][]>>, wasm: Optional<ArrayLike<number>>, zkey: ArrayLike<number>, logger: {
        debug: (log: string) => void;
    }, wtnsCalcOptions?: {
        singleThread?: boolean;
    }, proverOptions?: {
        singleThread?: boolean;
    }) => Promise<{
        proof: Proof;
        publicSignals: string[];
    }>;
    verify: Groth16Verify;
};
export type Groth16Implementation = {
    fullProveRailgun: Groth16FullProveRailgun;
    verify: Groth16Verify;
};
export type ProverProgressCallback = (progress: number) => void;
export declare class Prover {
    private artifactGetter;
    groth16: Optional<Groth16Implementation>;
    constructor(artifactGetter: ArtifactGetter);
    /**
     * Used to set Groth16 implementation from snarkjs.min.js or snarkjs.
     */
    setSnarkJSGroth16(snarkJSGroth16: SnarkJSGroth16): void;
    /**
     * Used to set Groth16 implementation from RAILGUN Native Prover.
     */
    setNativeProverGroth16(nativeProveRailgun: NativeProveRailgun, circuits: {
        [name: string]: number;
    }): void;
    verifyRailgunProof(publicInputs: PublicInputsRailgun, proof: Proof, artifacts: Artifact): Promise<boolean>;
    private static get zeroProof();
    dummyProveRailgun(publicInputs: PublicInputsRailgun): Proof;
    proveRailgun(txidVersion: TXIDVersion, unprovedTransactionInputs: UnprovedTransactionInputs, progressCallback: ProverProgressCallback): Promise<{
        proof: Proof;
        publicInputs: PublicInputsRailgun;
    }>;
    static formatProof(proof: Proof): SnarkProof;
    private static formatRailgunInputs;
}
export {};
