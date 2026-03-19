import { NFTTokenData } from '../../models';
import { UnshieldNote } from '../unshield-note';
export declare class UnshieldNoteNFT extends UnshieldNote {
    constructor(toAddress: string, tokenData: NFTTokenData, allowOverride?: boolean);
}
