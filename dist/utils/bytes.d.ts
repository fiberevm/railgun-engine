import { hexToBytes } from 'ethereum-cryptography/utils';
import { BytesData } from '../models/formatted-types';
declare class ByteUtils {
    static readonly FULL_32_BITS: bigint;
    static prefix0x: (str: string) => string;
    static strip0x: (str: string) => string;
    static hexToBytes: typeof hexToBytes;
    /**
     * convert hex string to BigInt, prefixing with 0x if necessary
     * @param {string} str
     * @returns {bigint}
     */
    static hexToBigInt(str: string): bigint;
    static u8ToBigInt(u8: Uint8Array): bigint;
    /**
     * Coerces BytesData into hex string format
     * @param data - bytes data to coerce
     * @param prefix - prefix with 0x
     * @returns hex string
     */
    static hexlify(data: BytesData, prefix?: boolean): string;
    /**
     * Coerces BytesData into array of bytes
     * @param data - bytes data to coerce
     * @returns byte array
     */
    static arrayify(data: BytesData): number[];
    /**
     * Pads BytesData to specified length
     * @param data - bytes data
     * @param length - length in bytes to pad to
     * @param side - whether to pad left or right
     * @returns padded bytes data
     */
    static padToLength(data: BytesData, length: number, side?: 'left' | 'right'): string | number[];
    /**
     * Split bytes into array of chunks
     * @param data - data to chunk
     * @param size - size of chunks
     * @returns chunked data
     */
    static chunk(data: BytesData, size?: ByteLength): string[];
    /**
     * Combines array of BytesData into single BytesData
     * @param data - data to combine
     * @returns combined data
     */
    static combine(data: BytesData[]): string;
    /**
     * Trim to length of bytes
     * @param data - data to trim
     * @param length - length to trim to
     * @param side - side to trim from
     * @returns trimmed data
     */
    static trim(data: BytesData, length: number, side?: 'left' | 'right'): BytesData;
    /**
     * Format through hexlify, trim and padToLength given a number of bytes.
     * @param data - data to format
     * @param length - length to format to
     * @returns formatted data
     */
    static formatToByteLength(data: BytesData, length: ByteLength, prefix?: boolean): string;
    /**
     * Convert bigint to hex string, 0-padded to even length
     * @param {bigint} n - a bigint
     * @param {boolean} prefix - prefix hex with 0x
     * @return {string} even-length hex
     */
    static nToHex(n: bigint, byteLength: ByteLength, prefix?: boolean): string;
    /**
     * Convert bigint to Uint8Array
     * @param {bigint} value
     * @returns {Uint8Array}
     */
    static nToBytes(n: bigint, byteLength: ByteLength): Uint8Array;
    /**
     * Convert Uint8Array to bigint
     * @param {Uint8Array} bytes
     * @returns {bigint}
     */
    static bytesToN(bytes: Uint8Array): bigint;
    /**
     * Convert hex string to Uint8Array. Handles prefixed or non-prefixed.
     * @param {bigint} value
     * @returns {Uint8Array}
     */
    static hexStringToBytes(hex: string): Uint8Array;
    /**
     * Convert hex string to Uint8Array. Does not handle 0x prefixes, and assumes
     * your string has an even number of characters.
     * @param {string} str
     * @returns {Uint8Array}
     */
    static fastHexToBytes(str: string): Uint8Array;
    /**
     * Convert Uint8Array to hex string. Does not output 0x prefixes.
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    static fastBytesToHex(bytes: Uint8Array): string;
    /**
     * Generates random bytes
     * @param length - number of bytes to generate
     * @returns random bytes hex string
     */
    static randomHex(length?: number): string;
}
declare enum ByteLength {
    UINT_8 = 1,
    UINT_56 = 7,
    UINT_120 = 15,
    UINT_128 = 16,
    Address = 20,
    UINT_192 = 24,
    UINT_248 = 31,
    UINT_256 = 32
}
/**
 * Converts bytes to string
 * @param data - bytes data to convert
 * @param encoding - string encoding to use
 */
declare function toUTF8String(data: string): string;
/**
 * Converts string to bytes
 * @param string - string to convert to bytes
 * @param encoding - string encoding to use
 */
declare function fromUTF8String(string: string): string;
declare const HashZero: string;
export { ByteLength, HashZero, ByteUtils, toUTF8String, fromUTF8String };
