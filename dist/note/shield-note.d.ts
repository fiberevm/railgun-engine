import { TokenData } from '../models/formatted-types';
import { ShieldRequestStruct } from '../abi/typechain/RailgunSmartWallet';
export declare abstract class ShieldNote {
    readonly masterPublicKey: bigint;
    readonly random: string;
    readonly value: bigint;
    readonly tokenData: TokenData;
    readonly tokenHash: string;
    readonly notePublicKey: bigint;
    constructor(masterPublicKey: bigint, random: string, value: bigint, tokenData: TokenData);
    /**
     * Used to generate a shieldPrivateKey by signing this message with public wallet.
     * After shielding, the shieldPrivateKey can then be used to get the 0zk address of the receiver.
     */
    static getShieldPrivateKeySignatureMessage(): string;
    static getNotePublicKey(masterPublicKey: bigint, random: string): bigint;
    static getShieldNoteHash(notePublicKey: bigint, tokenHash: string, valueAfterFee: bigint): bigint;
    static decryptRandom(encryptedBundle: [string, string, string], sharedKey: Uint8Array): string;
    /**
     * Gets JSON serialized version of note
     * @param viewingPrivateKey - viewing private key for decryption
     * @param forContract - if we should 0x prefix the hex strings to make them ethers compatible
     * @returns serialized note
     */
    serialize(shieldPrivateKey: Uint8Array, receiverViewingPublicKey: Uint8Array): Promise<ShieldRequestStruct>;
}
