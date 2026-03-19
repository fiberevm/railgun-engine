import { BytesData, Ciphertext, CiphertextCTR } from '../../models/formatted-types';
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
