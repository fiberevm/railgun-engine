"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WalletNode = exports.deriveNodes = void 0;
const utils_1 = require("ethereum-cryptography/utils");
const poseidon_1 = require("../utils/poseidon");
const bip32_1 = require("./bip32");
const bytes_1 = require("../utils/bytes");
const bip39_1 = require("./bip39");
const keys_utils_1 = require("../utils/keys-utils");
const HARDENED_OFFSET = 0x80000000;
/**
 * constant defining the derivation path prefixes for spending and viewing keys
 * must be appended with index' to form a complete path
 */
const DERIVATION_PATH_PREFIXES = {
    SPENDING: "m/44'/1984'/0'/0'/",
    VIEWING: "m/420'/1984'/0'/0'/",
};
/**
 * Helper to append DERIVATION_PATH_PREFIXES with index'
 */
const derivePathsForIndex = (index = 0) => {
    return {
        spending: `${DERIVATION_PATH_PREFIXES.SPENDING}${index}'`,
        viewing: `${DERIVATION_PATH_PREFIXES.VIEWING}${index}'`,
    };
};
const deriveNodes = (mnemonic, index = 0) => {
    const paths = derivePathsForIndex(index);
    return {
        // eslint-disable-next-line no-use-before-define
        spending: WalletNode.fromMnemonic(mnemonic).derive(paths.spending),
        // eslint-disable-next-line no-use-before-define
        viewing: WalletNode.fromMnemonic(mnemonic).derive(paths.viewing),
    };
};
exports.deriveNodes = deriveNodes;
class WalletNode {
    chainKey;
    chainCode;
    constructor(keyNode) {
        this.chainKey = keyNode.chainKey;
        this.chainCode = keyNode.chainCode;
    }
    /**
     * Create BIP32 node from mnemonic
     * @returns {WalletNode}
     */
    static fromMnemonic(mnemonic) {
        const seed = bip39_1.Mnemonic.toSeed(mnemonic);
        return new WalletNode((0, bip32_1.getMasterKeyFromSeed)(seed));
    }
    /**
     * Derives new BIP32Node along path
     * @param {string} path - path to derive along
     * @returns {BIP32Node} - new BIP32 implementation Node
     */
    derive(path) {
        // Get path segments
        const segments = (0, bip32_1.getPathSegments)(path);
        // Calculate new key node
        const keyNode = segments.reduce((parentKeys, segment) => (0, bip32_1.childKeyDerivationHardened)(parentKeys, segment, HARDENED_OFFSET), {
            chainKey: this.chainKey,
            chainCode: this.chainCode,
        });
        return new WalletNode(keyNode);
    }
    /**
     * Get spending key-pair
     * @returns keypair
     */
    getSpendingKeyPair() {
        const privateKey = bytes_1.ByteUtils.hexStringToBytes(this.chainKey);
        const pubkey = (0, keys_utils_1.getPublicSpendingKey)(privateKey);
        return {
            privateKey,
            pubkey,
        };
    }
    static getMasterPublicKey(spendingPublicKey, nullifyingKey) {
        return (0, poseidon_1.poseidon)([...spendingPublicKey, nullifyingKey]);
    }
    async getViewingKeyPair() {
        // TODO: THIS should be a separate node chainkey
        const privateKey = bytes_1.ByteUtils.hexStringToBytes(this.chainKey);
        const pubkey = await (0, keys_utils_1.getPublicViewingKey)(privateKey);
        return { privateKey, pubkey };
    }
    async getNullifyingKey() {
        const { privateKey } = await this.getViewingKeyPair();
        return (0, poseidon_1.poseidon)([bytes_1.ByteUtils.hexToBigInt((0, utils_1.bytesToHex)(privateKey))]);
    }
}
exports.WalletNode = WalletNode;
//# sourceMappingURL=wallet-node.js.map