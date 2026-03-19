import { Ciphertext, EncryptedData } from '../../models/formatted-types';
export declare const ciphertextToEncryptedRandomData: (ciphertext: Ciphertext) => EncryptedData;
export declare const ciphertextToEncryptedJSONData: (ciphertext: Ciphertext) => EncryptedData;
export declare const encryptedDataToCiphertext: (encryptedData: EncryptedData) => Ciphertext;
