import { ContractTransaction, FallbackProvider } from 'ethers';
import { PollingJsonRpcProvider } from '../../../provider/polling-json-rpc-provider';
import { PoseidonMerkleVerifier } from '../../../abi/typechain/PoseidonMerkleVerifier';
import { ShieldCiphertextStruct } from '../../../abi/typechain/RailgunSmartWallet';
export declare class PoseidonMerkleVerifierContract {
    readonly contract: PoseidonMerkleVerifier;
    readonly address: string;
    constructor(address: string, provider: PollingJsonRpcProvider | FallbackProvider);
    generateExecute(transactions: PoseidonMerkleVerifier.TransactionStruct[], shields: PoseidonMerkleVerifier.ShieldRequestStruct[], globalBoundParams: PoseidonMerkleVerifier.GlobalBoundParamsStruct, unshieldChangeCiphertext: ShieldCiphertextStruct): Promise<ContractTransaction>;
}
