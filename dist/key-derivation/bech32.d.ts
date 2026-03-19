import { Chain } from '../models/engine-types';
export type AddressData = {
    masterPublicKey: bigint;
    viewingPublicKey: Uint8Array;
    chain?: Chain;
    version?: number;
};
declare const ADDRESS_LENGTH_LIMIT = 127;
declare const ALL_CHAINS_NETWORK_ID = "ffffffffffffffff";
/**
 * Bech32 encodes address
 * @param addressData - AddressData to encode
 */
declare function encodeAddress(addressData: AddressData): string;
/**
 * @param address - RAILGUN encoded address
 * @returns
 */
declare function decodeAddress(address: string): AddressData;
export { encodeAddress, decodeAddress, ADDRESS_LENGTH_LIMIT, ALL_CHAINS_NETWORK_ID };
