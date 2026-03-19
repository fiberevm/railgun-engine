"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Mnemonic = void 0;
const hdkey_1 = require("ethereum-cryptography/hdkey");
const bip39 = __importStar(require("ethereum-cryptography/bip39"));
const english_1 = require("ethereum-cryptography/bip39/wordlists/english");
const utils_1 = require("ethereum-cryptography/utils");
const bip39_1 = require("ethereum-cryptography/bip39");
const ethers_1 = require("ethers");
const bytes_1 = require("../utils/bytes");
const getPath = (index = 0) => {
    return `m/44'/60'/0'/0/${index}`;
};
class Mnemonic {
    static generate(strength = 128) {
        return bip39.generateMnemonic(english_1.wordlist, strength);
    }
    static validate(mnemonic) {
        return bip39.validateMnemonic(mnemonic, english_1.wordlist);
    }
    static toSeed(mnemonic, password = '') {
        return (0, utils_1.toHex)(bip39.mnemonicToSeedSync(mnemonic, password));
    }
    static toEntropy(mnemonic) {
        return (0, utils_1.toHex)(bip39.mnemonicToEntropy(mnemonic, english_1.wordlist));
    }
    static fromEntropy(entropy) {
        return bip39.entropyToMnemonic(bytes_1.ByteUtils.hexStringToBytes(entropy), english_1.wordlist);
    }
    /**
     * For deriving 0x private key from mnemonic and derivation index. Not for use with 0zk.
     */
    static to0xPrivateKey(mnemonic, derivationIndex) {
        const seed = (0, bip39_1.mnemonicToSeedSync)(mnemonic);
        const path = getPath(derivationIndex);
        const node = hdkey_1.HDKey.fromMasterSeed(seed).derive(path);
        const privateKey = (0, utils_1.bytesToHex)(node.privateKey);
        return privateKey;
    }
    static to0xAddress(mnemonic, derivationIndex) {
        const path = getPath(derivationIndex);
        const wallet = ethers_1.HDNodeWallet.fromMnemonic(ethers_1.Mnemonic.fromPhrase(mnemonic), path);
        return wallet.address;
    }
}
exports.Mnemonic = Mnemonic;
//# sourceMappingURL=bip39.js.map