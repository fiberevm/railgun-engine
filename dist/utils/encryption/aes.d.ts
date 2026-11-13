import { BytesData, Ciphertext, CiphertextCTR } from '../../models/formatted-types';
/** A GCM ciphertext's iv, tag and blocks, parsed once. */
export type PreparedGCM = {
    iv: Uint8Array;
    tag: Uint8Array;
    data: Uint8Array[];
};
export declare class AES {
    static getRandomIV(): string;
    /**
     * Encrypt blocks of data with AES-256-GCM
     * @param plaintext - plaintext to encrypt
     * @param key - key to encrypt with
     * @returns ciphertext bundle
     */
    static encryptGCM(plaintext: string[], key: string | Uint8Array): Ciphertext;
    /**
     * Decrypts AES-256-GCM encrypted data
     * On failure, it throws `Unsupported state or unable to authenticate data`
     * @param ciphertext - ciphertext bundle to decrypt
     * @param key - key to decrypt with
     * @returns - plaintext
     */
    static decryptGCM(ciphertext: Ciphertext, key: string | Uint8Array): BytesData[];
    /**
     * Parses a GCM ciphertext the way `decryptGCM` does, once, for trying several keys.
     * Undefined when `decryptGCM` would reject it whatever the key.
     */
    static prepareGCM(ciphertext: Ciphertext): Optional<PreparedGCM>;
    /**
     * Whether `decryptGCM` would succeed with this key, without building its plaintext or its
     * error. A wallet scan tries the wrong key on almost every leaf, and a thrown error with a
     * cause costs several times the decryption itself.
     */
    static gcmOpens(prepared: PreparedGCM, key: Uint8Array): boolean;
    /**
     * Encrypt blocks of data with AES-256-CTR
     * @param plaintext - plaintext to encrypt
     * @param key - key to encrypt with
     * @returns ciphertext bundle
     */
    static encryptCTR(plaintext: string[], key: string | Uint8Array): CiphertextCTR;
    /**
     * Decrypts AES-256-CTR encrypted data
     * On failure, it throws `Unsupported state or unable to authenticate data`
     * @param ciphertext - ciphertext bundle to decrypt
     * @param key - key to decrypt with
     * @returns - plaintext
     */
    static decryptCTR(ciphertext: CiphertextCTR, key: string | Uint8Array): string[];
}
