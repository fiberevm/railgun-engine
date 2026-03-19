import { UnshieldNote } from '../unshield-note';
export declare class UnshieldNoteERC20 extends UnshieldNote {
    constructor(toAddress: string, value: bigint, tokenAddress: string, allowOverride?: boolean);
    static empty(): UnshieldNote;
}
