import { PoseidonMerkleVerifier } from '../abi/typechain';
import { CommitmentPreimageStruct } from '../abi/typechain/PoseidonMerkleAccumulator';
import { BoundParamsStruct } from '../abi/typechain/RailgunSmartWallet';
import { TXIDVersion } from './poi-types';
export declare const enum Circuits {
    OneTwo = 0,
    OneThree = 1,
    TwoTwo = 2,
    TwoThree = 3,
    EightTwo = 4
}
export type G1Point = {
    x: bigint;
    y: bigint;
};
export type G2Point = {
    x: [bigint, bigint];
    y: [bigint, bigint];
};
export type SnarkProof = {
    a: G1Point;
    b: G2Point;
    c: G1Point;
};
export type Proof = {
    pi_a: [string, string];
    pi_b: [[string, string], [string, string]];
    pi_c: [string, string];
};
export type PublicInputsRailgun = {
    merkleRoot: bigint;
    boundParamsHash: bigint;
    nullifiers: bigint[];
    commitmentsOut: bigint[];
};
export type PrivateInputsRailgun = {
    tokenAddress: bigint;
    publicKey: [bigint, bigint];
    randomIn: bigint[];
    valueIn: bigint[];
    pathElements: bigint[][];
    leavesIndices: bigint[];
    nullifyingKey: bigint;
    npkOut: bigint[];
    valueOut: bigint[];
};
export type RailgunTransactionRequestV2 = {
    txidVersion: TXIDVersion.V2_PoseidonMerkle;
    privateInputs: PrivateInputsRailgun;
    publicInputs: PublicInputsRailgun;
    boundParams: BoundParamsStruct;
};
export type RailgunTransactionRequestV3 = {
    txidVersion: TXIDVersion.V3_PoseidonMerkle;
    privateInputs: PrivateInputsRailgun;
    publicInputs: PublicInputsRailgun;
    boundParams: PoseidonMerkleVerifier.BoundParamsStruct;
};
export type RailgunTransactionRequest = RailgunTransactionRequestV2 | RailgunTransactionRequestV3;
export type PreparedRailgunTransactionV2 = RailgunTransactionRequestV2 & {
    unshieldPreimage: CommitmentPreimageStruct;
};
export type PreparedRailgunTransactionV3 = RailgunTransactionRequestV3 & {
    unshieldPreimage: CommitmentPreimageStruct;
};
/**
 * Complete unsigned transaction witness. Keep this data private: it contains note inputs and the
 * nullifying key. Preparing once lets an external signer authorize exact public semantics before
 * this same witness is proved later.
 */
export type PreparedRailgunTransaction = PreparedRailgunTransactionV2 | PreparedRailgunTransactionV3;
export type RailgunTransactionSigningDataV2 = Omit<PreparedRailgunTransactionV2, 'privateInputs'>;
export type RailgunTransactionSigningDataV3 = Omit<PreparedRailgunTransactionV3, 'privateInputs'>;
/** Exact public semantics supplied to delegated signers before a proof is generated. */
export type RailgunTransactionSigningData = RailgunTransactionSigningDataV2 | RailgunTransactionSigningDataV3;
export type UnprovedTransactionInputs = RailgunTransactionRequest & {
    signature: [bigint, bigint, bigint];
};
export type FormattedCircuitInputsRailgun = {
    merkleRoot: bigint;
    boundParamsHash: bigint;
    nullifiers: bigint[];
    commitmentsOut: bigint[];
    token: bigint;
    publicKey: bigint[];
    signature: bigint[];
    randomIn: bigint[];
    valueIn: bigint[];
    pathElements: bigint[];
    leavesIndices: bigint[];
    nullifyingKey: bigint;
    npkOut: bigint[];
    valueOut: bigint[];
};
export type NativeProverFormattedJsonInputsRailgun = {
    merkleRoot: string;
    boundParamsHash: string;
    nullifiers: string[];
    commitmentsOut: string[];
    token: string;
    publicKey: string[];
    signature: string[];
    randomIn: string[];
    valueIn: string[];
    pathElements: string[];
    leavesIndices: string[];
    nullifyingKey: string;
    npkOut: string[];
    valueOut: string[];
};
export type ArtifactGetter = {
    assertArtifactExists: (nullifiers: number, commitments: number) => void;
    getArtifacts: (publicInputs: PublicInputsRailgun) => Promise<Artifact>;
};
