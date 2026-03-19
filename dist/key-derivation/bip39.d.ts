export declare class Mnemonic {
    static generate(strength?: 128 | 192 | 256): string;
    static validate(mnemonic: string): boolean;
    static toSeed(mnemonic: string, password?: string): string;
    static toEntropy(mnemonic: string): string;
    static fromEntropy(entropy: string): string;
    /**
     * For deriving 0x private key from mnemonic and derivation index. Not for use with 0zk.
     */
    static to0xPrivateKey(mnemonic: string, derivationIndex?: number): string;
    static to0xAddress(mnemonic: string, derivationIndex?: number): string;
}
