import { EncryptedData } from '../models/formatted-types';
export declare const tryDecryptJSONDataWithSharedKey: (encryptedData: EncryptedData, sharedKey: Uint8Array) => object | null;
export declare const encryptJSONDataWithSharedKey: (data: object, sharedKey: Uint8Array) => EncryptedData;
