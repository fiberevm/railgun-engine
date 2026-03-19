import { CiphertextXChaCha } from '../../models/formatted-types';
export declare class XChaCha20 {
    static getRandomIV(): string;
    static encryptChaCha20(plaintext: string, key: Uint8Array): CiphertextXChaCha;
    static decryptChaCha20(ciphertext: CiphertextXChaCha, key: Uint8Array): string;
    static encryptChaCha20Poly1305(plaintext: string, key: Uint8Array): CiphertextXChaCha;
    static decryptChaCha20Poly1305(ciphertext: CiphertextXChaCha, key: Uint8Array): string;
}
