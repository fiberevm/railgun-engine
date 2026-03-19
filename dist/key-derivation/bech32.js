"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ALL_CHAINS_NETWORK_ID = exports.ADDRESS_LENGTH_LIMIT = exports.decodeAddress = exports.encodeAddress = void 0;
const base_1 = require("@scure/base");
const buffer_xor_1 = __importDefault(require("buffer-xor"));
const chain_1 = require("../chain/chain");
const bytes_1 = require("../utils/bytes");
const constants_1 = require("../utils/constants");
const ADDRESS_LENGTH_LIMIT = 127;
exports.ADDRESS_LENGTH_LIMIT = ADDRESS_LENGTH_LIMIT;
const ALL_CHAINS_NETWORK_ID = 'ffffffffffffffff';
exports.ALL_CHAINS_NETWORK_ID = ALL_CHAINS_NETWORK_ID;
const PREFIX = '0zk';
/**
 * @param chainID - hex value of chainID
 * @returns - chainID XOR'd with 'railgun' to make address prettier
 */
const xorNetworkID = (chainID) => {
    const chainIDBuffer = Buffer.from(chainID, 'hex');
    const railgunBuffer = Buffer.from('railgun', 'utf8');
    return (0, buffer_xor_1.default)(chainIDBuffer, railgunBuffer).toString('hex');
};
const chainToNetworkID = (chain) => {
    if (chain == null) {
        return ALL_CHAINS_NETWORK_ID;
    }
    const networkID = (0, chain_1.getChainFullNetworkID)(chain);
    return networkID;
};
const networkIDToChain = (networkID) => {
    if (networkID === ALL_CHAINS_NETWORK_ID) {
        return undefined;
    }
    const chain = {
        type: parseInt(networkID.slice(0, 2), 16),
        id: parseInt(networkID.slice(2, 16), 16),
    };
    return chain;
};
/**
 * Bech32 encodes address
 * @param addressData - AddressData to encode
 */
function encodeAddress(addressData) {
    const masterPublicKey = bytes_1.ByteUtils.nToHex(addressData.masterPublicKey, bytes_1.ByteLength.UINT_256, false);
    const viewingPublicKey = bytes_1.ByteUtils.formatToByteLength(addressData.viewingPublicKey, bytes_1.ByteLength.UINT_256);
    const { chain } = addressData;
    const networkID = xorNetworkID(chainToNetworkID(chain));
    const version = '01';
    const addressString = `${version}${masterPublicKey}${networkID}${viewingPublicKey}`;
    // Create 73 byte address buffer
    const addressBuffer = Buffer.from(addressString, 'hex');
    // Encode address
    const address = base_1.bech32m.encode(PREFIX, base_1.bech32m.toWords(addressBuffer), ADDRESS_LENGTH_LIMIT);
    return address;
}
exports.encodeAddress = encodeAddress;
/**
 * @param address - RAILGUN encoded address
 * @returns
 */
function decodeAddress(address) {
    try {
        if (!address) {
            throw new Error('No address to decode');
        }
        const decoded = base_1.bech32m.decode(address, ADDRESS_LENGTH_LIMIT);
        if (decoded.prefix !== PREFIX) {
            throw new Error('Invalid address prefix');
        }
        // Hexlify data
        const data = bytes_1.ByteUtils.hexlify(base_1.bech32m.fromWords(decoded.words));
        // Get version
        const version = parseInt(data.slice(0, 2), 16);
        const masterPublicKey = bytes_1.ByteUtils.hexToBigInt(data.slice(2, 66));
        const networkID = xorNetworkID(data.slice(66, 82));
        const viewingPublicKey = bytes_1.ByteUtils.hexStringToBytes(data.slice(82, 146));
        const chain = networkIDToChain(networkID);
        // Throw if address version is not supported
        if (version !== constants_1.ADDRESS_VERSION)
            throw new Error('Incorrect address version');
        const result = {
            masterPublicKey,
            viewingPublicKey,
            version,
            chain,
        };
        return result;
    }
    catch (cause) {
        if (cause instanceof Error && cause.message && cause.message.includes('Invalid checksum')) {
            throw new Error('Invalid checksum');
        }
        throw new Error('Failed to decode bech32 address', { cause });
    }
}
exports.decodeAddress = decodeAddress;
//# sourceMappingURL=bech32.js.map