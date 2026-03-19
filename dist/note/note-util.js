"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getReadableTokenAddress = exports.getTokenDataHash = exports.getTokenDataNFT = exports.getTokenDataERC20 = exports.getTokenDataHashERC20 = exports.getUnshieldTokenHash = exports.getUnshieldPreImageNoteHash = exports.getUnshieldEventNoteHash = exports.getNoteHash = exports.serializeTokenData = exports.extractTokenHashFromCommitmentPreImageV3 = exports.serializePreImage = exports.assertValidNoteRandom = exports.assertValidNoteToken = exports.ERC721_NOTE_VALUE = void 0;
const poseidon_1 = require("../utils/poseidon");
const formatted_types_1 = require("../models/formatted-types");
const transaction_constants_1 = require("../models/transaction-constants");
const constants_1 = require("../utils/constants");
const bytes_1 = require("../utils/bytes");
const hash_1 = require("../utils/hash");
const is_defined_1 = require("../utils/is-defined");
exports.ERC721_NOTE_VALUE = BigInt(1);
const assertValidNoteToken = (tokenData, value) => {
    const tokenAddressLength = bytes_1.ByteUtils.hexlify(tokenData.tokenAddress, false).length;
    switch (tokenData.tokenType) {
        case formatted_types_1.TokenType.ERC20: {
            if (tokenAddressLength !== 40 && tokenAddressLength !== 64) {
                throw new Error(`ERC20 address must be length 40 (20 bytes) or 64 (32 bytes). Got ${bytes_1.ByteUtils.hexlify(tokenData.tokenAddress, false)}.`);
            }
            if (BigInt(tokenData.tokenSubID) !== 0n) {
                throw new Error('ERC20 note cannot have tokenSubID parameter.');
            }
            return;
        }
        case formatted_types_1.TokenType.ERC721: {
            if (tokenAddressLength !== 40) {
                throw new Error(`ERC721 address must be length 40 (20 bytes). Got ${bytes_1.ByteUtils.hexlify(tokenData.tokenAddress, false)}.`);
            }
            if (!tokenData.tokenSubID.length) {
                throw new Error('ERC721 note must have tokenSubID parameter.');
            }
            if (value !== BigInt(1)) {
                throw new Error('ERC721 note must have value of 1.');
            }
            return;
        }
        case formatted_types_1.TokenType.ERC1155: {
            if (tokenAddressLength !== 40) {
                throw new Error(`ERC1155 address must be length 40 (20 bytes). Got ${bytes_1.ByteUtils.hexlify(tokenData.tokenAddress, false)}.`);
            }
            if (!tokenData.tokenSubID.length) {
                throw new Error('ERC1155 note must have tokenSubID parameter.');
            }
        }
    }
};
exports.assertValidNoteToken = assertValidNoteToken;
const assertValidNoteRandom = (random) => {
    if (bytes_1.ByteUtils.hexlify(random, false).length !== 32) {
        throw new Error(`Random must be length 32 (16 bytes). Got ${bytes_1.ByteUtils.hexlify(random, false)}.`);
    }
};
exports.assertValidNoteRandom = assertValidNoteRandom;
const serializePreImage = (address, tokenData, value, prefix = false) => {
    return {
        npk: bytes_1.ByteUtils.formatToByteLength(address, bytes_1.ByteLength.UINT_256, prefix),
        token: tokenData,
        value: formatValue(value, prefix),
    };
};
exports.serializePreImage = serializePreImage;
const extractTokenHashFromCommitmentPreImageV3 = (preimage) => {
    if (!(0, is_defined_1.isDefined)(preimage)) {
        throw new Error('Invalid preimage.');
    }
    const tokenData = (0, exports.serializeTokenData)(preimage.token.tokenAddress, preimage.token.tokenType, preimage.token.tokenSubID.toString());
    const tokenHash = (0, exports.getTokenDataHash)(tokenData);
    return tokenHash;
};
exports.extractTokenHashFromCommitmentPreImageV3 = extractTokenHashFromCommitmentPreImageV3;
const serializeTokenData = (tokenAddress, tokenType, tokenSubID) => {
    return {
        tokenAddress: bytes_1.ByteUtils.formatToByteLength(tokenAddress, bytes_1.ByteLength.Address, true),
        tokenType: Number(tokenType),
        tokenSubID: bytes_1.ByteUtils.nToHex(BigInt(tokenSubID), bytes_1.ByteLength.UINT_256, true),
    };
};
exports.serializeTokenData = serializeTokenData;
const formatValue = (value, prefix = false) => {
    return bytes_1.ByteUtils.nToHex(value, bytes_1.ByteLength.UINT_128, prefix);
};
const getNoteHash = (address, tokenData, value) => {
    const tokenHash = (0, exports.getTokenDataHash)(tokenData);
    return (0, poseidon_1.poseidon)([bytes_1.ByteUtils.hexToBigInt(address), bytes_1.ByteUtils.hexToBigInt(tokenHash), value]);
};
exports.getNoteHash = getNoteHash;
const getUnshieldEventNoteHash = (unshieldEvent) => {
    return (0, exports.getNoteHash)(unshieldEvent.toAddress, getUnshieldTokenData(unshieldEvent), BigInt(unshieldEvent.amount) + BigInt(unshieldEvent.fee));
};
exports.getUnshieldEventNoteHash = getUnshieldEventNoteHash;
const getUnshieldPreImageNoteHash = (unshieldPreimage) => {
    return (0, exports.getNoteHash)(unshieldPreimage.npk, (0, exports.serializeTokenData)(unshieldPreimage.token.tokenAddress, unshieldPreimage.token.tokenType, unshieldPreimage.token.tokenSubID.toString()), unshieldPreimage.value);
};
exports.getUnshieldPreImageNoteHash = getUnshieldPreImageNoteHash;
const getUnshieldTokenData = (unshieldEvent) => {
    return (0, exports.serializeTokenData)(unshieldEvent.tokenAddress, unshieldEvent.tokenType, unshieldEvent.tokenSubID);
};
const getUnshieldTokenHash = (unshieldEvent) => {
    return (0, exports.getTokenDataHash)(getUnshieldTokenData(unshieldEvent));
};
exports.getUnshieldTokenHash = getUnshieldTokenHash;
const getTokenDataHashERC20 = (tokenAddress) => {
    return bytes_1.ByteUtils.formatToByteLength(bytes_1.ByteUtils.hexToBytes(tokenAddress), bytes_1.ByteLength.UINT_256);
};
exports.getTokenDataHashERC20 = getTokenDataHashERC20;
const getTokenDataHashNFT = (tokenData) => {
    // keccak256 hash of the token data.
    const combinedData = bytes_1.ByteUtils.combine([
        bytes_1.ByteUtils.nToBytes(BigInt(tokenData.tokenType), bytes_1.ByteLength.UINT_256),
        bytes_1.ByteUtils.hexToBytes(bytes_1.ByteUtils.formatToByteLength(tokenData.tokenAddress, bytes_1.ByteLength.UINT_256)),
        bytes_1.ByteUtils.nToBytes(BigInt(tokenData.tokenSubID), bytes_1.ByteLength.UINT_256),
    ]);
    const hashed = (0, hash_1.keccak256)(combinedData);
    const modulo = bytes_1.ByteUtils.hexToBigInt(hashed) % constants_1.SNARK_PRIME;
    return bytes_1.ByteUtils.nToHex(modulo, bytes_1.ByteLength.UINT_256);
};
const getTokenDataERC20 = (tokenAddress) => {
    return {
        tokenAddress: bytes_1.ByteUtils.formatToByteLength(tokenAddress, bytes_1.ByteLength.Address, true),
        tokenType: formatted_types_1.TokenType.ERC20,
        tokenSubID: bytes_1.ByteUtils.formatToByteLength(transaction_constants_1.TOKEN_SUB_ID_NULL, bytes_1.ByteLength.UINT_256, true),
    };
};
exports.getTokenDataERC20 = getTokenDataERC20;
const getTokenDataNFT = (nftAddress, tokenType, tokenSubID) => {
    return {
        tokenAddress: bytes_1.ByteUtils.formatToByteLength(nftAddress, bytes_1.ByteLength.Address, true),
        tokenType,
        tokenSubID: bytes_1.ByteUtils.formatToByteLength(tokenSubID, bytes_1.ByteLength.UINT_256, true),
    };
};
exports.getTokenDataNFT = getTokenDataNFT;
const getTokenDataHash = (tokenData) => {
    switch (tokenData.tokenType) {
        case formatted_types_1.TokenType.ERC20:
            return (0, exports.getTokenDataHashERC20)(tokenData.tokenAddress);
        case formatted_types_1.TokenType.ERC721:
        case formatted_types_1.TokenType.ERC1155:
            return getTokenDataHashNFT(tokenData);
    }
    throw new Error('Unrecognized token type.');
};
exports.getTokenDataHash = getTokenDataHash;
const getReadableTokenAddress = (tokenData) => {
    switch (tokenData.tokenType) {
        case formatted_types_1.TokenType.ERC20:
            return `0x${bytes_1.ByteUtils.trim(tokenData.tokenAddress, bytes_1.ByteLength.Address)}`;
        case formatted_types_1.TokenType.ERC721:
        case formatted_types_1.TokenType.ERC1155:
            return `${tokenData.tokenAddress} (${tokenData.tokenSubID})`;
    }
    throw new Error('Unrecognized token type.');
};
exports.getReadableTokenAddress = getReadableTokenAddress;
//# sourceMappingURL=note-util.js.map