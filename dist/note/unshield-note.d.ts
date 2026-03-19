import { CommitmentPreimageStruct } from '../abi/typechain/RailgunSmartWallet';
import { UnshieldData } from '../models';
import { TokenData } from '../models/formatted-types';
export declare abstract class UnshieldNote {
    readonly toAddress: string;
    readonly value: bigint;
    readonly tokenData: TokenData;
    readonly hash: bigint;
    readonly allowOverride: boolean;
    /**
     * Create Note object
     *
     * @param toAddress - address to unshield to
     * @param value - note value
     * @param tokenData
     */
    constructor(toAddress: string, value: bigint, tokenData: TokenData, allowOverride: boolean);
    get unshieldData(): UnshieldData;
    get npk(): string;
    get notePublicKey(): bigint;
    get hashHex(): string;
    serialize(prefix?: boolean): {
        npk: string;
        token: TokenData;
        value: string;
    };
    get preImage(): CommitmentPreimageStruct;
    static getAmountFeeFromValue(value: bigint, feeBasisPoints: bigint): {
        amount: bigint;
        fee: bigint;
    };
}
