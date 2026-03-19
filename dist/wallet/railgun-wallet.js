"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RailgunWallet = void 0;
const poseidon_1 = require("../utils/poseidon");
const wallet_node_1 = require("../key-derivation/wallet-node");
const bytes_1 = require("../utils/bytes");
const hash_1 = require("../utils/hash");
const abstract_wallet_1 = require("./abstract-wallet");
const bip39_1 = require("../key-derivation/bip39");
const keys_utils_1 = require("../utils/keys-utils");
class RailgunWallet extends abstract_wallet_1.AbstractWallet {
    /**
     * Load encrypted spending key Node from database
     * Spending key should be kept private and only accessed on demand
     * @returns {Promise<SpendingKeyPair>}
     */
    async getSpendingKeyPair(encryptionKey) {
        const node = await this.loadSpendingKey(encryptionKey);
        return node.getSpendingKeyPair();
    }
    async sign(publicInputs, encryptionKey) {
        const spendingKeyPair = await this.getSpendingKeyPair(encryptionKey);
        const msg = (0, poseidon_1.poseidon)([publicInputs.merkleRoot, publicInputs.boundParamsHash, ...publicInputs.nullifiers, ...publicInputs.commitmentsOut]);
        return (0, keys_utils_1.signEDDSA)(spendingKeyPair.privateKey, msg);
    }
    /**
     * Load encrypted node from database with encryption key
     * @param {BytesData} encryptionKey
     * @returns {Node} BabyJubJub node
     */
    async loadSpendingKey(encryptionKey) {
        const { mnemonic, index } = (await RailgunWallet.read(this.db, this.id, encryptionKey));
        return (0, wallet_node_1.deriveNodes)(mnemonic, index).spending;
    }
    /**
     * Helper to get the ethereum/whatever address is associated with this wallet
     */
    async getChainAddress(encryptionKey) {
        const { mnemonic, index } = (await abstract_wallet_1.AbstractWallet.read(this.db, this.id, encryptionKey));
        return bip39_1.Mnemonic.to0xAddress(mnemonic, index);
    }
    /**
     * Calculate Wallet ID from mnemonic and derivation path index
     * @returns {string} hash of mnemonic and index
     */
    static generateID(mnemonic, index) {
        return (0, hash_1.sha256)(bytes_1.ByteUtils.combine([bip39_1.Mnemonic.toSeed(mnemonic), index.toString(16)]));
    }
    static async createWallet(id, db, mnemonic, index, creationBlockNumbers, prover) {
        const nodes = (0, wallet_node_1.deriveNodes)(mnemonic, index);
        const viewingKeyPair = await nodes.viewing.getViewingKeyPair();
        const spendingPublicKey = nodes.spending.getSpendingKeyPair().pubkey;
        return new RailgunWallet(id, db, viewingKeyPair, spendingPublicKey, creationBlockNumbers, prover);
    }
    /**
     * Create a wallet from mnemonic
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} mnemonic - mnemonic to load wallet from
     * @param {number} index - index of derivation path to derive if not 0
     * @returns {RailgunWallet} Wallet
     */
    static async fromMnemonic(db, encryptionKey, mnemonic, index, creationBlockNumbers, prover) {
        const id = RailgunWallet.generateID(mnemonic, index);
        // Write encrypted mnemonic to DB
        await abstract_wallet_1.AbstractWallet.write(db, id, encryptionKey, { mnemonic, index, creationBlockNumbers });
        return this.createWallet(id, db, mnemonic, index, creationBlockNumbers, prover);
    }
    /**
     * Loads wallet data from database and creates wallet object
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} id - wallet id
     * @returns {RailgunWallet} Wallet
     */
    static async loadExisting(db, encryptionKey, id, prover) {
        // Get encrypted mnemonic and index from DB
        const { mnemonic, index, creationBlockNumbers } = (await abstract_wallet_1.AbstractWallet.read(db, id, encryptionKey));
        if (!mnemonic) {
            throw new Error('Incorrect wallet type.');
        }
        return this.createWallet(id, db, mnemonic, index, creationBlockNumbers, prover);
    }
}
exports.RailgunWallet = RailgunWallet;
//# sourceMappingURL=railgun-wallet.js.map