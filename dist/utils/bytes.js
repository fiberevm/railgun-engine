"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromUTF8String = exports.toUTF8String = exports.ByteUtils = exports.HashZero = exports.ByteLength = void 0;
const utils_1 = require("ethereum-cryptography/utils");
const random_1 = require("ethereum-cryptography/random");
const crypto_1 = __importDefault(require("crypto"));
const runtime_1 = require("./runtime");
// TextEncoder/TextDecoder (used in this file) needs to shimmed in React Native
if (runtime_1.isReactNative) {
    // eslint-disable-next-line global-require
    require('fast-text-encoding');
}
// returns true if string is prefixed with '0x'
const isPrefixed = (str) => str.startsWith('0x');
/**
 * check each character for commonly unsupported codepoints above 0xD800
 * @param string - string to check
 * @throws if invalid character found
 */
function assertBytesWithinRange(string) {
    for (let i = 0; i < string.length; i += 1) {
        if (string.charCodeAt(i) > 0xd800) {
            throw new Error('Invalid Unicode codepoint > 0xD800');
        }
    }
}
class ByteUtils {
    static FULL_32_BITS = BigInt(2 ** 32 - 1);
    // add 0x if it str isn't already prefixed
    static prefix0x = (str) => (isPrefixed(str) ? str : `0x${str}`);
    // remove 0x prefix if it exists
    static strip0x = (str) => (isPrefixed(str) ? str.slice(2) : str);
    static hexToBytes = utils_1.hexToBytes;
    /**
     * convert hex string to BigInt, prefixing with 0x if necessary
     * @param {string} str
     * @returns {bigint}
     */
    static hexToBigInt(str) {
        return BigInt(ByteUtils.prefix0x(str));
    }
    static u8ToBigInt(u8) {
        // eslint-disable-next-line no-use-before-define
        return ByteUtils.hexToBigInt(ByteUtils.hexlify(u8));
    }
    /**
     * Coerces BytesData into hex string format
     * @param data - bytes data to coerce
     * @param prefix - prefix with 0x
     * @returns hex string
     */
    static hexlify(data, prefix = false) {
        let hexString = '';
        if (typeof data === 'string') {
            // If we're already a string return the string
            // Strip leading 0x if it exists before returning
            hexString = ByteUtils.strip0x(data);
        }
        else if (typeof data === 'bigint' || typeof data === 'number') {
            hexString = data.toString(16);
            if (hexString.length % 2 === 1) {
                hexString = `0${hexString}`;
            }
        }
        else {
            // We're an ArrayLike
            // Coerce ArrayLike to Array
            const dataArray = Array.from(data);
            // Convert array of bytes to hex string
            hexString = dataArray.map((byte) => byte.toString(16).padStart(2, '0')).join('');
        }
        // Return 0x prefixed hex string if specified
        if (prefix) {
            return `0x${hexString}`.toLowerCase();
        }
        // Else return plain hex string
        return hexString.toLowerCase();
    }
    /**
     * Coerces BytesData into array of bytes
     * @param data - bytes data to coerce
     * @returns byte array
     */
    static arrayify(data) {
        // If we're already a byte array return array coerced data
        if (typeof data !== 'string' && typeof data !== 'bigint' && typeof data !== 'number') {
            return Array.from(data);
        }
        // Remove leading 0x if exists
        const dataFormatted = typeof data === 'bigint' || typeof data === 'number'
            ? ByteUtils.hexlify(data)
            : ByteUtils.strip0x(data);
        // Create empty array
        const bytesArray = [];
        // Loop through each byte and push to array
        for (let i = 0; i < dataFormatted.length; i += 2) {
            const number = parseInt(dataFormatted.substr(i, 2), 16);
            if (Number.isNaN(number)) {
                throw new Error('Invalid BytesData');
            }
            else {
                bytesArray.push(number);
            }
        }
        // Return bytes array
        return bytesArray;
    }
    /**
     * Pads BytesData to specified length
     * @param data - bytes data
     * @param length - length in bytes to pad to
     * @param side - whether to pad left or right
     * @returns padded bytes data
     */
    static padToLength(data, length, side = 'left') {
        if (typeof data === 'bigint' || typeof data === 'number') {
            if (side === 'left') {
                return data.toString(16).padStart(length * 2, '0');
            }
            return data.toString(16).padEnd(length * 2, '0');
        }
        if (typeof data === 'string') {
            const dataFormattedString = ByteUtils.strip0x(data);
            // If we're requested to pad to left, pad left and return
            if (side === 'left') {
                return data.startsWith('0x')
                    ? `0x${dataFormattedString.padStart(length * 2, '0')}`
                    : dataFormattedString.padStart(length * 2, '0');
            }
            // Else pad right and return
            return data.startsWith('0x')
                ? `0x${dataFormattedString.padEnd(length * 2, '0')}`
                : dataFormattedString.padEnd(length * 2, '0');
        }
        // Coerce data into array
        const dataArray = Array.from(data);
        if (side === 'left') {
            // If side is left, unshift till length
            while (dataArray.length < length) {
                dataArray.unshift(0);
            }
        }
        else {
            // If side is right, push till length
            while (dataArray.length < length) {
                dataArray.push(0);
            }
        }
        // Return dataArray
        return dataArray;
    }
    /**
     * Split bytes into array of chunks
     * @param data - data to chunk
     * @param size - size of chunks
     * @returns chunked data
     */
    static chunk(data, size = ByteLength.UINT_256) {
        // Convert to hex string
        const dataFormatted = ByteUtils.hexlify(data);
        // Split into byte chunks and return
        return dataFormatted.match(new RegExp(`.{1,${size * 2}}`, 'g')) || [];
    }
    /**
     * Combines array of BytesData into single BytesData
     * @param data - data to combine
     * @returns combined data
     */
    static combine(data) {
        // Convert all chunks into hex strings
        const dataFormatted = data.map((element) => ByteUtils.hexlify(element));
        // Combine and return
        return dataFormatted.join('');
    }
    /**
     * Trim to length of bytes
     * @param data - data to trim
     * @param length - length to trim to
     * @param side - side to trim from
     * @returns trimmed data
     */
    static trim(data, length, side = 'left') {
        if (typeof data === 'bigint' || typeof data === 'number') {
            const stringData = data.toString(16);
            const trimmedString = ByteUtils.trim(stringData, length, side);
            return BigInt(`0x${trimmedString}`);
        }
        if (typeof data === 'string') {
            const dataFormatted = data.startsWith('0x') ? data.slice(2) : data;
            if (side === 'left') {
                // If side is left return the last length bytes
                return data.startsWith('0x')
                    ? `0x${dataFormatted.slice(dataFormatted.length - length * 2)}`
                    : dataFormatted.slice(dataFormatted.length - length * 2);
            }
            // Side is right, return the start of the string to length
            return data.startsWith('0x')
                ? `0x${dataFormatted.slice(0, length * 2)}`
                : dataFormatted.slice(0, length * 2);
        }
        // Coerce to array
        const dataFormatted = Array.from(data);
        if (side === 'left') {
            // If side is left return the last length bytes
            return dataFormatted.slice(data.length - length);
        }
        // Side is right, return the start of the array to length
        return dataFormatted.slice(0, length);
    }
    /**
     * Format through hexlify, trim and padToLength given a number of bytes.
     * @param data - data to format
     * @param length - length to format to
     * @returns formatted data
     */
    static formatToByteLength(data, length, prefix = false) {
        const hex = ByteUtils.hexlify(data, prefix);
        const padded = ByteUtils.padToLength(hex, length);
        const trimmed = ByteUtils.trim(padded, length);
        return trimmed;
    }
    /**
     * Convert bigint to hex string, 0-padded to even length
     * @param {bigint} n - a bigint
     * @param {boolean} prefix - prefix hex with 0x
     * @return {string} even-length hex
     */
    static nToHex(n, byteLength, prefix = false) {
        if (n < 0)
            throw new Error('bigint must be positive');
        const hex = ByteUtils.formatToByteLength(n.toString(16), byteLength, prefix);
        return prefix ? ByteUtils.prefix0x(hex) : hex;
    }
    /**
     * Convert bigint to Uint8Array
     * @param {bigint} value
     * @returns {Uint8Array}
     */
    static nToBytes(n, byteLength) {
        return ByteUtils.hexToBytes(ByteUtils.nToHex(n, byteLength));
    }
    /**
     * Convert Uint8Array to bigint
     * @param {Uint8Array} bytes
     * @returns {bigint}
     */
    static bytesToN(bytes) {
        const prefix = true;
        return BigInt(ByteUtils.hexlify(bytes, prefix));
    }
    /**
     * Convert hex string to Uint8Array. Handles prefixed or non-prefixed.
     * @param {bigint} value
     * @returns {Uint8Array}
     */
    static hexStringToBytes(hex) {
        return ByteUtils.hexToBytes(ByteUtils.strip0x(hex));
    }
    /**
     * Convert hex string to Uint8Array. Does not handle 0x prefixes, and assumes
     * your string has an even number of characters.
     * @param {string} str
     * @returns {Uint8Array}
     */
    static fastHexToBytes(str) {
        const bytes = new Uint8Array(str.length / 2);
        for (let i = 0; i < bytes.length; i += 1) {
            const c1 = str.charCodeAt(i * 2);
            const c2 = str.charCodeAt(i * 2 + 1);
            const n1 = c1 - (c1 < 58 ? 48 : 87);
            const n2 = c2 - (c2 < 58 ? 48 : 87);
            bytes[i] = n1 * 16 + n2;
        }
        return bytes;
    }
    /**
     * Convert Uint8Array to hex string. Does not output 0x prefixes.
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    static fastBytesToHex(bytes) {
        const hex = new Array(bytes.length * 2);
        for (let i = 0; i < bytes.length; i += 1) {
            const n = bytes[i];
            const c1 = (n / 16) | 0;
            const c2 = n % 16;
            hex[2 * i] = String.fromCharCode(c1 + (c1 < 10 ? 48 : 87));
            hex[2 * i + 1] = String.fromCharCode(c2 + (c2 < 10 ? 48 : 87));
        }
        return hex.join('');
    }
    /**
     * Generates random bytes
     * @param length - number of bytes to generate
     * @returns random bytes hex string
     */
    static randomHex(length = 32) {
        return runtime_1.isNodejs
            ? crypto_1.default.randomBytes(length).toString('hex')
            : (0, utils_1.bytesToHex)((0, random_1.getRandomBytesSync)(length));
    }
}
exports.ByteUtils = ByteUtils;
var ByteLength;
(function (ByteLength) {
    ByteLength[ByteLength["UINT_8"] = 1] = "UINT_8";
    ByteLength[ByteLength["UINT_56"] = 7] = "UINT_56";
    ByteLength[ByteLength["UINT_120"] = 15] = "UINT_120";
    ByteLength[ByteLength["UINT_128"] = 16] = "UINT_128";
    ByteLength[ByteLength["Address"] = 20] = "Address";
    ByteLength[ByteLength["UINT_192"] = 24] = "UINT_192";
    ByteLength[ByteLength["UINT_248"] = 31] = "UINT_248";
    ByteLength[ByteLength["UINT_256"] = 32] = "UINT_256";
})(ByteLength || (exports.ByteLength = ByteLength = {}));
/**
 * Converts bytes to string
 * @param data - bytes data to convert
 * @param encoding - string encoding to use
 */
function toUTF8String(data) {
    const string = new TextDecoder().decode(ByteUtils.fastHexToBytes(data));
    assertBytesWithinRange(string);
    return string;
}
exports.toUTF8String = toUTF8String;
/**
 * Converts string to bytes
 * @param string - string to convert to bytes
 * @param encoding - string encoding to use
 */
function fromUTF8String(string) {
    assertBytesWithinRange(string);
    // Return hexlified string
    return ByteUtils.hexlify(new TextEncoder().encode(string));
}
exports.fromUTF8String = fromUTF8String;
const HashZero = ByteUtils.formatToByteLength('00', 32, true);
exports.HashZero = HashZero;
//# sourceMappingURL=bytes.js.map