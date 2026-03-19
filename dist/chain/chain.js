"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getChainFullNetworkID = exports.addChainSupportsV3 = exports.assertChainSupportsV3 = exports.getChainSupportsV3 = void 0;
const bytes_1 = require("../utils/bytes");
const chainsSupportingV3 = [];
const getChainFullNetworkID = (chain) => {
    // 1 byte: chainType.
    const formattedChainType = bytes_1.ByteUtils.formatToByteLength(bytes_1.ByteUtils.hexlify(chain.type), bytes_1.ByteLength.UINT_8);
    // 7 bytes: chainID.
    const formattedChainID = bytes_1.ByteUtils.formatToByteLength(bytes_1.ByteUtils.hexlify(chain.id), bytes_1.ByteLength.UINT_56);
    return `${formattedChainType}${formattedChainID}`;
};
exports.getChainFullNetworkID = getChainFullNetworkID;
const getChainSupportsV3 = (chain) => {
    for (const supportingV3Chain of chainsSupportingV3) {
        if (chain.id === supportingV3Chain.id && chain.type === supportingV3Chain.type) {
            return true;
        }
    }
    return false;
};
exports.getChainSupportsV3 = getChainSupportsV3;
const assertChainSupportsV3 = (chain) => {
    if (!(0, exports.getChainSupportsV3)(chain)) {
        throw new Error(`Chain does not support V3: ${chain.type}:${chain.id}. Set supportsV3 'true' in loadNetwork.`);
    }
};
exports.assertChainSupportsV3 = assertChainSupportsV3;
const addChainSupportsV3 = (chain) => {
    chainsSupportingV3.push(chain);
};
exports.addChainSupportsV3 = addChainSupportsV3;
//# sourceMappingURL=chain.js.map