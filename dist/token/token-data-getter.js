"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenDataGetter = void 0;
const railgun_versioned_smart_contracts_1 = require("../contracts/railgun-smart-wallet/railgun-versioned-smart-contracts");
const note_util_1 = require("../note/note-util");
const utils_1 = require("../utils");
const bytes_1 = require("../utils/bytes");
// 12 empty bytes.
const ERC20_TOKEN_HASH_PREFIX = '000000000000000000000000';
class TokenDataGetter {
    db;
    constructor(db) {
        this.db = db;
    }
    async getTokenDataFromHash(txidVersion, chain, tokenHash) {
        const formatted = utils_1.ByteUtils.formatToByteLength(tokenHash, utils_1.ByteLength.UINT_256);
        const isERC20 = formatted.startsWith(ERC20_TOKEN_HASH_PREFIX);
        if (isERC20) {
            // tokenHash is erc20 tokenAddress.
            return (0, note_util_1.getTokenDataERC20)(tokenHash);
        }
        const tokenDataNFT = await this.getNFTTokenData(txidVersion, chain, tokenHash);
        return tokenDataNFT;
    }
    async getNFTTokenData(txidVersion, chain, tokenHash) {
        const formattedTokenHash = utils_1.ByteUtils.formatToByteLength(tokenHash, utils_1.ByteLength.UINT_256, false);
        const cachedData = await this.getCachedNFTTokenData(formattedTokenHash);
        if (cachedData) {
            return cachedData;
        }
        const contractData = await railgun_versioned_smart_contracts_1.RailgunVersionedSmartContracts.getNFTTokenData(txidVersion, chain, formattedTokenHash);
        const tokenData = TokenDataGetter.structToTokenData(contractData);
        await this.cacheNFTTokenData(tokenHash, tokenData);
        return tokenData;
    }
    static structToTokenData(struct) {
        return (0, note_util_1.serializeTokenData)(struct.tokenAddress, struct.tokenType, struct.tokenSubID);
    }
    static getNFTTokenDataPrefix() {
        const nftTokenDataPrefix = (0, bytes_1.fromUTF8String)('nft-token-data-map');
        return [nftTokenDataPrefix];
    }
    static getNFTTokenDataPath(tokenHash) {
        return [...TokenDataGetter.getNFTTokenDataPrefix(), tokenHash].map((el) => utils_1.ByteUtils.formatToByteLength(el, utils_1.ByteLength.UINT_256));
    }
    async cacheNFTTokenData(tokenHash, tokenData) {
        await this.db.put(TokenDataGetter.getNFTTokenDataPath(tokenHash), tokenData, 'json');
    }
    async getCachedNFTTokenData(tokenHash) {
        try {
            const tokenData = (await this.db.get(TokenDataGetter.getNFTTokenDataPath(tokenHash), 'json'));
            return tokenData;
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error thrown from getCachedNFTTokenData', { cause });
            }
            return undefined;
        }
    }
}
exports.TokenDataGetter = TokenDataGetter;
//# sourceMappingURL=token-data-getter.js.map