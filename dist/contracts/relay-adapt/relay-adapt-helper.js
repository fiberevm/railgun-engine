"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RelayAdaptHelper = void 0;
const ethers_1 = require("ethers");
const bytes_1 = require("../../utils/bytes");
const shield_note_erc20_1 = require("../../note/erc20/shield-note-erc20");
const key_derivation_1 = require("../../key-derivation");
const formatted_types_1 = require("../../models/formatted-types");
const shield_note_nft_1 = require("../../note/nft/shield-note-nft");
const note_util_1 = require("../../note/note-util");
class RelayAdaptHelper {
    static async generateRelayShieldRequests(random, shieldERC20Recipients, shieldNFTRecipients) {
        return Promise.all([
            ...(await RelayAdaptHelper.createRelayShieldRequestsERC20s(random, shieldERC20Recipients)),
            ...(await RelayAdaptHelper.createRelayShieldRequestsNFTs(random, shieldNFTRecipients)),
        ]);
    }
    static async createRelayShieldRequestsERC20s(random, shieldERC20Recipients) {
        return Promise.all(shieldERC20Recipients.map(({ tokenAddress, recipientAddress }) => {
            const addressData = (0, key_derivation_1.decodeAddress)(recipientAddress);
            const shieldERC20 = new shield_note_erc20_1.ShieldNoteERC20(addressData.masterPublicKey, random, 0n, // 0n will automatically shield entire balance.
            tokenAddress);
            // Random private key for Relay Adapt shield.
            const shieldPrivateKey = bytes_1.ByteUtils.hexToBytes(bytes_1.ByteUtils.randomHex(32));
            return shieldERC20.serialize(shieldPrivateKey, addressData.viewingPublicKey);
        }));
    }
    static async createRelayShieldRequestsNFTs(random, shieldNFTRecipients) {
        return Promise.all(shieldNFTRecipients.map(({ nftTokenData, recipientAddress }) => {
            const value = RelayAdaptHelper.valueForNFTShield(nftTokenData);
            const addressData = (0, key_derivation_1.decodeAddress)(recipientAddress);
            const shieldNFT = new shield_note_nft_1.ShieldNoteNFT(addressData.masterPublicKey, random, value, nftTokenData);
            // Random private key for Relay Adapt shield.
            const shieldPrivateKey = bytes_1.ByteUtils.hexToBytes(bytes_1.ByteUtils.randomHex(32));
            return shieldNFT.serialize(shieldPrivateKey, addressData.viewingPublicKey);
        }));
    }
    static valueForNFTShield(nftTokenData) {
        switch (nftTokenData.tokenType) {
            case formatted_types_1.TokenType.ERC721:
                return note_util_1.ERC721_NOTE_VALUE;
            case formatted_types_1.TokenType.ERC1155:
                return 0n; // 0n will automatically shield entire balance.
        }
        throw new Error('Unhandled NFT token type.');
    }
    /**
     * Format action data field for relay call.
     */
    static getActionData(random, requireSuccess, calls, minGasLimit) {
        const formattedRandom = RelayAdaptHelper.formatRandom(random);
        return {
            random: formattedRandom,
            requireSuccess,
            minGasLimit,
            calls: RelayAdaptHelper.formatCalls(calls),
        };
    }
    /**
     * Get relay adapt params hash.
     * Hashes transaction data and params to ensure that transaction is not modified by MITM.
     *
     * @param transactions - serialized transactions
     * @param random - random value
     * @param requireSuccess - require success on calls
     * @param calls - calls list
     * @returns adapt params
     */
    static getRelayAdaptParams(transactions, random, requireSuccess, calls, minGasLimit = BigInt(0)) {
        const nullifiers = transactions.map((transaction) => transaction.nullifiers);
        const actionData = RelayAdaptHelper.getActionData(random, requireSuccess, calls, minGasLimit);
        const preimage = ethers_1.AbiCoder.defaultAbiCoder().encode([
            'bytes32[][] nullifiers',
            'uint256 transactionsLength',
            'tuple(bytes31 random, bool requireSuccess, uint256 minGasLimit, tuple(address to, bytes data, uint256 value)[] calls) actionData',
        ], [nullifiers, transactions.length, actionData]);
        return (0, ethers_1.keccak256)(bytes_1.ByteUtils.hexToBytes(preimage));
    }
    /**
     * Strips all unnecessary fields from populated transactions
     *
     * @param {object[]} calls - calls list
     * @returns {object[]} formatted calls
     */
    static formatCalls(calls) {
        return calls.map((call) => ({
            to: call.to || '',
            data: call.data || '',
            value: call.value ?? 0n,
        }));
    }
    static formatRandom(random) {
        if (random.length !== 62) {
            throw new Error('Relay Adapt random parameter must be a hex string of length 62 (31 bytes).');
        }
        return bytes_1.ByteUtils.hexToBytes(random);
    }
}
exports.RelayAdaptHelper = RelayAdaptHelper;
//# sourceMappingURL=relay-adapt-helper.js.map