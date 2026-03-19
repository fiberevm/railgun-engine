import { NFTTokenData } from '../../models/formatted-types';
import { ShieldNote } from '../shield-note';
export declare class ShieldNoteNFT extends ShieldNote {
    constructor(masterPublicKey: bigint, random: string, value: bigint, tokenData: NFTTokenData);
}
