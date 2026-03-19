"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenVaultContract = void 0;
const ethers_1 = require("ethers");
const abi_1 = require("../../../abi/abi");
const bytes_1 = require("../../../utils/bytes");
const debugger_1 = __importDefault(require("../../../debugger/debugger"));
class TokenVaultContract {
    contract;
    address;
    constructor(address, provider) {
        this.address = address;
        this.contract = new ethers_1.Contract(address, abi_1.ABITokenVault, provider);
    }
    /**
     * Gets transaction fees in basis points.
     */
    async fees() {
        const [shieldFee, unshieldFee] = await Promise.all([
            this.contract.shieldFee(),
            this.contract.unshieldFee(),
        ]);
        return {
            shield: shieldFee,
            unshield: unshieldFee,
        };
    }
    /**
     * Gets NFT token data from tokenHash.
     */
    async getNFTTokenData(tokenHash) {
        try {
            const formattedTokenHash = bytes_1.ByteUtils.formatToByteLength(tokenHash, bytes_1.ByteLength.UINT_256, true);
            return await this.contract.tokenIDMapping(formattedTokenHash);
        }
        catch (cause) {
            const err = new Error('Failed to get V3 NFT token data', { cause });
            debugger_1.default.error(err);
            throw err;
        }
    }
}
exports.TokenVaultContract = TokenVaultContract;
//# sourceMappingURL=token-vault-contract.js.map