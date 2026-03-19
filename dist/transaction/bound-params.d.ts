import { BoundParamsStruct } from '../abi/typechain/RailgunSmartWallet';
import { PoseidonMerkleVerifier } from '../abi/typechain';
export declare const hashBoundParamsV2: (boundParams: BoundParamsStruct) => bigint;
export declare const hashBoundParamsV3: (boundParams: PoseidonMerkleVerifier.BoundParamsStruct) => bigint;
