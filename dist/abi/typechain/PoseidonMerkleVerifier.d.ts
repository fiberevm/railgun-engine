import type { BaseContract, BigNumberish, BytesLike, FunctionFragment, Result, Interface, EventFragment, AddressLike, ContractRunner, ContractMethod, Listener } from "ethers";
import type { TypedContractEvent, TypedDeferredTopicFilter, TypedEventLog, TypedLogDescription, TypedListener, TypedContractMethod } from "./common";
export type BN254G1PointStruct = {
    x: BigNumberish;
    y: BigNumberish;
};
export type BN254G1PointStructOutput = [x: bigint, y: bigint] & {
    x: bigint;
    y: bigint;
};
export type BN254G2PointStruct = {
    x: [BigNumberish, BigNumberish];
    y: [BigNumberish, BigNumberish];
};
export type BN254G2PointStructOutput = [
    x: [bigint, bigint],
    y: [bigint, bigint]
] & {
    x: [bigint, bigint];
    y: [bigint, bigint];
};
export type TokenDataStruct = {
    tokenType: BigNumberish;
    tokenAddress: AddressLike;
    tokenSubID: BigNumberish;
};
export type TokenDataStructOutput = [
    tokenType: bigint,
    tokenAddress: string,
    tokenSubID: bigint
] & {
    tokenType: bigint;
    tokenAddress: string;
    tokenSubID: bigint;
};
export type CommitmentPreimageStruct = {
    npk: BytesLike;
    token: TokenDataStruct;
    value: BigNumberish;
};
export type CommitmentPreimageStructOutput = [
    npk: string,
    token: TokenDataStructOutput,
    value: bigint
] & {
    npk: string;
    token: TokenDataStructOutput;
    value: bigint;
};
export declare namespace Groth16 {
    type VerifyingKeyStruct = {
        alpha1: BN254G1PointStruct;
        beta2: BN254G2PointStruct;
        gamma2: BN254G2PointStruct;
        delta2: BN254G2PointStruct;
        ic: BN254G1PointStruct[];
    };
    type VerifyingKeyStructOutput = [
        alpha1: BN254G1PointStructOutput,
        beta2: BN254G2PointStructOutput,
        gamma2: BN254G2PointStructOutput,
        delta2: BN254G2PointStructOutput,
        ic: BN254G1PointStructOutput[]
    ] & {
        alpha1: BN254G1PointStructOutput;
        beta2: BN254G2PointStructOutput;
        gamma2: BN254G2PointStructOutput;
        delta2: BN254G2PointStructOutput;
        ic: BN254G1PointStructOutput[];
    };
    type ProofStruct = {
        a: BN254G1PointStruct;
        b: BN254G2PointStruct;
        c: BN254G1PointStruct;
    };
    type ProofStructOutput = [
        a: BN254G1PointStructOutput,
        b: BN254G2PointStructOutput,
        c: BN254G1PointStructOutput
    ] & {
        a: BN254G1PointStructOutput;
        b: BN254G2PointStructOutput;
        c: BN254G1PointStructOutput;
    };
}
export declare namespace PoseidonMerkleVerifier {
    type VerifyingKeyArtifactStruct = {
        artifactsIPFSHash: string;
        verifyingKey: Groth16.VerifyingKeyStruct;
    };
    type VerifyingKeyArtifactStructOutput = [
        artifactsIPFSHash: string,
        verifyingKey: Groth16.VerifyingKeyStructOutput
    ] & {
        artifactsIPFSHash: string;
        verifyingKey: Groth16.VerifyingKeyStructOutput;
    };
    type TransactionBoundParamsStruct = {
        treeNumber: BigNumberish;
        commitmentCiphertext: PoseidonMerkleAccumulator.CommitmentCiphertextStruct[];
    };
    type TransactionBoundParamsStructOutput = [
        treeNumber: bigint,
        commitmentCiphertext: PoseidonMerkleAccumulator.CommitmentCiphertextStructOutput[]
    ] & {
        treeNumber: bigint;
        commitmentCiphertext: PoseidonMerkleAccumulator.CommitmentCiphertextStructOutput[];
    };
    type TransactionStruct = {
        proof: Groth16.ProofStruct;
        merkleRoot: BytesLike;
        nullifiers: BytesLike[];
        commitments: BytesLike[];
        boundParams: PoseidonMerkleVerifier.TransactionBoundParamsStruct;
        unshieldPreimage: CommitmentPreimageStruct;
    };
    type TransactionStructOutput = [
        proof: Groth16.ProofStructOutput,
        merkleRoot: string,
        nullifiers: string[],
        commitments: string[],
        boundParams: PoseidonMerkleVerifier.TransactionBoundParamsStructOutput,
        unshieldPreimage: CommitmentPreimageStructOutput
    ] & {
        proof: Groth16.ProofStructOutput;
        merkleRoot: string;
        nullifiers: string[];
        commitments: string[];
        boundParams: PoseidonMerkleVerifier.TransactionBoundParamsStructOutput;
        unshieldPreimage: CommitmentPreimageStructOutput;
    };
    type ShieldRequestStruct = {
        ciphertext: PoseidonMerkleAccumulator.ShieldCiphertextStruct;
        preimage: CommitmentPreimageStruct;
    };
    type ShieldRequestStructOutput = [
        ciphertext: PoseidonMerkleAccumulator.ShieldCiphertextStructOutput,
        preimage: CommitmentPreimageStructOutput
    ] & {
        ciphertext: PoseidonMerkleAccumulator.ShieldCiphertextStructOutput;
        preimage: CommitmentPreimageStructOutput;
    };
    type GlobalBoundParamsStruct = {
        minGasPrice: BigNumberish;
        chainID: BigNumberish;
        senderCiphertext: BytesLike;
        to: AddressLike;
        data: BytesLike;
    };
    type GlobalBoundParamsStructOutput = [
        minGasPrice: bigint,
        chainID: bigint,
        senderCiphertext: string,
        to: string,
        data: string
    ] & {
        minGasPrice: bigint;
        chainID: bigint;
        senderCiphertext: string;
        to: string;
        data: string;
    };
    type BoundParamsStruct = {
        local: PoseidonMerkleVerifier.TransactionBoundParamsStruct;
        global: PoseidonMerkleVerifier.GlobalBoundParamsStruct;
    };
    type BoundParamsStructOutput = [
        local: PoseidonMerkleVerifier.TransactionBoundParamsStructOutput,
        global: PoseidonMerkleVerifier.GlobalBoundParamsStructOutput
    ] & {
        local: PoseidonMerkleVerifier.TransactionBoundParamsStructOutput;
        global: PoseidonMerkleVerifier.GlobalBoundParamsStructOutput;
    };
}
export declare namespace PoseidonMerkleAccumulator {
    type CommitmentCiphertextStruct = {
        ciphertext: BytesLike;
        blindedSenderViewingKey: BytesLike;
        blindedReceiverViewingKey: BytesLike;
    };
    type CommitmentCiphertextStructOutput = [
        ciphertext: string,
        blindedSenderViewingKey: string,
        blindedReceiverViewingKey: string
    ] & {
        ciphertext: string;
        blindedSenderViewingKey: string;
        blindedReceiverViewingKey: string;
    };
    type ShieldCiphertextStruct = {
        encryptedBundle: [BytesLike, BytesLike, BytesLike];
        shieldKey: BytesLike;
    };
    type ShieldCiphertextStructOutput = [
        encryptedBundle: [string, string, string],
        shieldKey: string
    ] & {
        encryptedBundle: [string, string, string];
        shieldKey: string;
    };
}
export interface PoseidonMerkleVerifierInterface extends Interface {
    getFunction(nameOrSignature: "accumulator" | "addVector" | "checkSafetyVectors" | "execute" | "getVerificationKey" | "hashBoundParams" | "hashCommitment" | "initialize" | "owner" | "removeVector" | "renounceOwnership" | "safetyVector" | "setVerificationKey" | "tokenVault" | "transferOwnership" | "validateCommitmentPreimage" | "validateGlobalBoundParams" | "validateTransaction" | "verifyTransactionProof"): FunctionFragment;
    getEvent(nameOrSignatureOrTopic: "Initialized" | "OwnershipTransferred" | "VerifyingKeySet"): EventFragment;
    encodeFunctionData(functionFragment: "accumulator", values?: undefined): string;
    encodeFunctionData(functionFragment: "addVector", values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: "checkSafetyVectors", values?: undefined): string;
    encodeFunctionData(functionFragment: "execute", values: [
        PoseidonMerkleVerifier.TransactionStruct[],
        PoseidonMerkleVerifier.ShieldRequestStruct[],
        PoseidonMerkleVerifier.GlobalBoundParamsStruct,
        PoseidonMerkleAccumulator.ShieldCiphertextStruct
    ]): string;
    encodeFunctionData(functionFragment: "getVerificationKey", values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: "hashBoundParams", values: [PoseidonMerkleVerifier.BoundParamsStruct]): string;
    encodeFunctionData(functionFragment: "hashCommitment", values: [CommitmentPreimageStruct]): string;
    encodeFunctionData(functionFragment: "initialize", values: [AddressLike, AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: "owner", values?: undefined): string;
    encodeFunctionData(functionFragment: "removeVector", values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: "renounceOwnership", values?: undefined): string;
    encodeFunctionData(functionFragment: "safetyVector", values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: "setVerificationKey", values: [
        BigNumberish,
        BigNumberish,
        PoseidonMerkleVerifier.VerifyingKeyArtifactStruct
    ]): string;
    encodeFunctionData(functionFragment: "tokenVault", values?: undefined): string;
    encodeFunctionData(functionFragment: "transferOwnership", values: [AddressLike]): string;
    encodeFunctionData(functionFragment: "validateCommitmentPreimage", values: [CommitmentPreimageStruct]): string;
    encodeFunctionData(functionFragment: "validateGlobalBoundParams", values: [PoseidonMerkleVerifier.GlobalBoundParamsStruct]): string;
    encodeFunctionData(functionFragment: "validateTransaction", values: [
        PoseidonMerkleVerifier.TransactionStruct,
        PoseidonMerkleVerifier.GlobalBoundParamsStruct
    ]): string;
    encodeFunctionData(functionFragment: "verifyTransactionProof", values: [PoseidonMerkleVerifier.TransactionStruct, BytesLike]): string;
    decodeFunctionResult(functionFragment: "accumulator", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "addVector", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "checkSafetyVectors", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "execute", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "getVerificationKey", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "hashBoundParams", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "hashCommitment", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "initialize", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "owner", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "removeVector", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "renounceOwnership", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "safetyVector", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "setVerificationKey", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "tokenVault", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "transferOwnership", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "validateCommitmentPreimage", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "validateGlobalBoundParams", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "validateTransaction", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "verifyTransactionProof", data: BytesLike): Result;
}
export declare namespace InitializedEvent {
    type InputTuple = [version: BigNumberish];
    type OutputTuple = [version: bigint];
    interface OutputObject {
        version: bigint;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace OwnershipTransferredEvent {
    type InputTuple = [previousOwner: AddressLike, newOwner: AddressLike];
    type OutputTuple = [previousOwner: string, newOwner: string];
    interface OutputObject {
        previousOwner: string;
        newOwner: string;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace VerifyingKeySetEvent {
    type InputTuple = [
        nullifiers: BigNumberish,
        commitments: BigNumberish,
        verifyingKey: PoseidonMerkleVerifier.VerifyingKeyArtifactStruct
    ];
    type OutputTuple = [
        nullifiers: bigint,
        commitments: bigint,
        verifyingKey: PoseidonMerkleVerifier.VerifyingKeyArtifactStructOutput
    ];
    interface OutputObject {
        nullifiers: bigint;
        commitments: bigint;
        verifyingKey: PoseidonMerkleVerifier.VerifyingKeyArtifactStructOutput;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export interface PoseidonMerkleVerifier extends BaseContract {
    connect(runner?: ContractRunner | null): BaseContract;
    attach(addressOrName: AddressLike): this;
    deployed(): Promise<this>;
    interface: PoseidonMerkleVerifierInterface;
    queryFilter<TCEvent extends TypedContractEvent>(event: TCEvent, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog<TCEvent>>>;
    queryFilter<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog<TCEvent>>>;
    on<TCEvent extends TypedContractEvent>(event: TCEvent, listener: TypedListener<TCEvent>): Promise<this>;
    on<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, listener: TypedListener<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent>(event: TCEvent, listener: TypedListener<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, listener: TypedListener<TCEvent>): Promise<this>;
    listeners<TCEvent extends TypedContractEvent>(event: TCEvent): Promise<Array<TypedListener<TCEvent>>>;
    listeners(eventName?: string): Promise<Array<Listener>>;
    removeAllListeners<TCEvent extends TypedContractEvent>(event?: TCEvent): Promise<this>;
    accumulator: TypedContractMethod<[], [string], "view">;
    addVector: TypedContractMethod<[vector: BigNumberish], [void], "nonpayable">;
    checkSafetyVectors: TypedContractMethod<[], [void], "nonpayable">;
    execute: TypedContractMethod<[
        _transactions: PoseidonMerkleVerifier.TransactionStruct[],
        _shieldRequests: PoseidonMerkleVerifier.ShieldRequestStruct[],
        _globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct,
        unshieldChangeCiphertext: PoseidonMerkleAccumulator.ShieldCiphertextStruct
    ], [
        void
    ], "nonpayable">;
    getVerificationKey: TypedContractMethod<[
        _nullifiers: BigNumberish,
        _commitments: BigNumberish
    ], [
        PoseidonMerkleVerifier.VerifyingKeyArtifactStructOutput
    ], "view">;
    hashBoundParams: TypedContractMethod<[
        _boundParams: PoseidonMerkleVerifier.BoundParamsStruct
    ], [
        string
    ], "view">;
    hashCommitment: TypedContractMethod<[
        _commitmentPreimage: CommitmentPreimageStruct
    ], [
        string
    ], "view">;
    initialize: TypedContractMethod<[
        _accumulator: AddressLike,
        _tokenVault: AddressLike,
        _owner: AddressLike
    ], [
        void
    ], "nonpayable">;
    owner: TypedContractMethod<[], [string], "view">;
    removeVector: TypedContractMethod<[
        vector: BigNumberish
    ], [
        void
    ], "nonpayable">;
    renounceOwnership: TypedContractMethod<[], [void], "nonpayable">;
    safetyVector: TypedContractMethod<[arg0: BigNumberish], [boolean], "view">;
    setVerificationKey: TypedContractMethod<[
        _nullifiers: BigNumberish,
        _commitments: BigNumberish,
        _verifyingKey: PoseidonMerkleVerifier.VerifyingKeyArtifactStruct
    ], [
        void
    ], "nonpayable">;
    tokenVault: TypedContractMethod<[], [string], "view">;
    transferOwnership: TypedContractMethod<[
        newOwner: AddressLike
    ], [
        void
    ], "nonpayable">;
    validateCommitmentPreimage: TypedContractMethod<[
        _preimage: CommitmentPreimageStruct
    ], [
        void
    ], "view">;
    validateGlobalBoundParams: TypedContractMethod<[
        _globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct
    ], [
        void
    ], "view">;
    validateTransaction: TypedContractMethod<[
        _transaction: PoseidonMerkleVerifier.TransactionStruct,
        _globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct
    ], [
        [bigint, string]
    ], "view">;
    verifyTransactionProof: TypedContractMethod<[
        _transaction: PoseidonMerkleVerifier.TransactionStruct,
        _boundParamsHash: BytesLike
    ], [
        boolean
    ], "view">;
    getFunction<T extends ContractMethod = ContractMethod>(key: string | FunctionFragment): T;
    getFunction(nameOrSignature: "accumulator"): TypedContractMethod<[], [string], "view">;
    getFunction(nameOrSignature: "addVector"): TypedContractMethod<[vector: BigNumberish], [void], "nonpayable">;
    getFunction(nameOrSignature: "checkSafetyVectors"): TypedContractMethod<[], [void], "nonpayable">;
    getFunction(nameOrSignature: "execute"): TypedContractMethod<[
        _transactions: PoseidonMerkleVerifier.TransactionStruct[],
        _shieldRequests: PoseidonMerkleVerifier.ShieldRequestStruct[],
        _globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct,
        unshieldChangeCiphertext: PoseidonMerkleAccumulator.ShieldCiphertextStruct
    ], [
        void
    ], "nonpayable">;
    getFunction(nameOrSignature: "getVerificationKey"): TypedContractMethod<[
        _nullifiers: BigNumberish,
        _commitments: BigNumberish
    ], [
        PoseidonMerkleVerifier.VerifyingKeyArtifactStructOutput
    ], "view">;
    getFunction(nameOrSignature: "hashBoundParams"): TypedContractMethod<[
        _boundParams: PoseidonMerkleVerifier.BoundParamsStruct
    ], [
        string
    ], "view">;
    getFunction(nameOrSignature: "hashCommitment"): TypedContractMethod<[
        _commitmentPreimage: CommitmentPreimageStruct
    ], [
        string
    ], "view">;
    getFunction(nameOrSignature: "initialize"): TypedContractMethod<[
        _accumulator: AddressLike,
        _tokenVault: AddressLike,
        _owner: AddressLike
    ], [
        void
    ], "nonpayable">;
    getFunction(nameOrSignature: "owner"): TypedContractMethod<[], [string], "view">;
    getFunction(nameOrSignature: "removeVector"): TypedContractMethod<[vector: BigNumberish], [void], "nonpayable">;
    getFunction(nameOrSignature: "renounceOwnership"): TypedContractMethod<[], [void], "nonpayable">;
    getFunction(nameOrSignature: "safetyVector"): TypedContractMethod<[arg0: BigNumberish], [boolean], "view">;
    getFunction(nameOrSignature: "setVerificationKey"): TypedContractMethod<[
        _nullifiers: BigNumberish,
        _commitments: BigNumberish,
        _verifyingKey: PoseidonMerkleVerifier.VerifyingKeyArtifactStruct
    ], [
        void
    ], "nonpayable">;
    getFunction(nameOrSignature: "tokenVault"): TypedContractMethod<[], [string], "view">;
    getFunction(nameOrSignature: "transferOwnership"): TypedContractMethod<[newOwner: AddressLike], [void], "nonpayable">;
    getFunction(nameOrSignature: "validateCommitmentPreimage"): TypedContractMethod<[_preimage: CommitmentPreimageStruct], [void], "view">;
    getFunction(nameOrSignature: "validateGlobalBoundParams"): TypedContractMethod<[
        _globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct
    ], [
        void
    ], "view">;
    getFunction(nameOrSignature: "validateTransaction"): TypedContractMethod<[
        _transaction: PoseidonMerkleVerifier.TransactionStruct,
        _globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct
    ], [
        [bigint, string]
    ], "view">;
    getFunction(nameOrSignature: "verifyTransactionProof"): TypedContractMethod<[
        _transaction: PoseidonMerkleVerifier.TransactionStruct,
        _boundParamsHash: BytesLike
    ], [
        boolean
    ], "view">;
    getEvent(key: "Initialized"): TypedContractEvent<InitializedEvent.InputTuple, InitializedEvent.OutputTuple, InitializedEvent.OutputObject>;
    getEvent(key: "OwnershipTransferred"): TypedContractEvent<OwnershipTransferredEvent.InputTuple, OwnershipTransferredEvent.OutputTuple, OwnershipTransferredEvent.OutputObject>;
    getEvent(key: "VerifyingKeySet"): TypedContractEvent<VerifyingKeySetEvent.InputTuple, VerifyingKeySetEvent.OutputTuple, VerifyingKeySetEvent.OutputObject>;
    filters: {
        "Initialized(uint8)": TypedContractEvent<InitializedEvent.InputTuple, InitializedEvent.OutputTuple, InitializedEvent.OutputObject>;
        Initialized: TypedContractEvent<InitializedEvent.InputTuple, InitializedEvent.OutputTuple, InitializedEvent.OutputObject>;
        "OwnershipTransferred(address,address)": TypedContractEvent<OwnershipTransferredEvent.InputTuple, OwnershipTransferredEvent.OutputTuple, OwnershipTransferredEvent.OutputObject>;
        OwnershipTransferred: TypedContractEvent<OwnershipTransferredEvent.InputTuple, OwnershipTransferredEvent.OutputTuple, OwnershipTransferredEvent.OutputObject>;
        "VerifyingKeySet(uint256,uint256,tuple)": TypedContractEvent<VerifyingKeySetEvent.InputTuple, VerifyingKeySetEvent.OutputTuple, VerifyingKeySetEvent.OutputObject>;
        VerifyingKeySet: TypedContractEvent<VerifyingKeySetEvent.InputTuple, VerifyingKeySetEvent.OutputTuple, VerifyingKeySetEvent.OutputObject>;
    };
}
