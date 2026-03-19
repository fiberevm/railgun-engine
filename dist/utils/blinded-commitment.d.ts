export declare class BlindedCommitment {
    static getForUnshield(railgunTxid: string): string;
    static getForShieldOrTransact(commitmentHash: string, npk: bigint, globalTreePosition: bigint): string;
}
