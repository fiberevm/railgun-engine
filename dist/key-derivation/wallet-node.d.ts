import { KeyNode } from '../models/engine-types';
export type WalletNodes = {
    spending: WalletNode;
    viewing: WalletNode;
};
export declare const deriveNodes: (mnemonic: string, index?: number) => WalletNodes;
export type SpendingPublicKey = [bigint, bigint];
export type SpendingKeyPair = {
    privateKey: Uint8Array;
    pubkey: SpendingPublicKey;
};
export type ViewingKeyPair = {
    privateKey: Uint8Array;
    pubkey: Uint8Array;
};
export declare class WalletNode {
    private chainKey;
    private chainCode;
    constructor(keyNode: KeyNode);
    /**
     * Create BIP32 node from mnemonic
     * @returns {WalletNode}
     */
    static fromMnemonic(mnemonic: string): WalletNode;
    /**
     * Derives new BIP32Node along path
     * @param {string} path - path to derive along
     * @returns {BIP32Node} - new BIP32 implementation Node
     */
    derive(path: string): WalletNode;
    /**
     * Get spending key-pair
     * @returns keypair
     */
    getSpendingKeyPair(): SpendingKeyPair;
    static getMasterPublicKey(spendingPublicKey: [bigint, bigint], nullifyingKey: bigint): bigint;
    getViewingKeyPair(): Promise<ViewingKeyPair>;
    getNullifyingKey(): Promise<bigint>;
}
