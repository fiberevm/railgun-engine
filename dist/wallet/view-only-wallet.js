"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ViewOnlyWallet = void 0;
const bytes_1 = require("../utils/bytes");
const hash_1 = require("../utils/hash");
const keys_utils_1 = require("../utils/keys-utils");
const abstract_wallet_1 = require("./abstract-wallet");
class ViewOnlyWallet extends abstract_wallet_1.AbstractWallet {
    // eslint-disable-next-line class-methods-use-this, @typescript-eslint/no-unused-vars
    sign(_publicInputs, _encryptionKey) {
        throw new Error('View-Only wallet cannot generate signatures.');
    }
    /**
     * Calculate Wallet ID from mnemonic and derivation path index
     * @returns {string} hash of mnemonic and index
     */
    static generateID(shareableViewingKey) {
        return (0, hash_1.sha256)(shareableViewingKey);
    }
    static async getViewingKeyPair(viewingPrivateKey) {
        const vpk = bytes_1.ByteUtils.hexStringToBytes(viewingPrivateKey);
        return {
            privateKey: vpk,
            pubkey: await (0, keys_utils_1.getPublicViewingKey)(vpk),
        };
    }
    static async createWallet(id, db, shareableViewingKey, creationBlockNumbers, prover) {
        const { viewingPrivateKey, spendingPublicKey } = abstract_wallet_1.AbstractWallet.getKeysFromShareableViewingKey(shareableViewingKey);
        const viewingKeyPair = await ViewOnlyWallet.getViewingKeyPair(viewingPrivateKey);
        return new ViewOnlyWallet(id, db, viewingKeyPair, spendingPublicKey, creationBlockNumbers, prover);
    }
    /**
     * Create a wallet from mnemonic
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} shareableViewingKey - encoded keys to load wallet from
     * @returns {Wallet} Wallet
     */
    static async fromShareableViewingKey(db, encryptionKey, shareableViewingKey, creationBlockNumbers, prover) {
        const id = ViewOnlyWallet.generateID(shareableViewingKey);
        // Write encrypted shareableViewingKey to DB
        await abstract_wallet_1.AbstractWallet.write(db, id, encryptionKey, {
            shareableViewingKey,
            creationBlockNumbers,
        });
        return this.createWallet(id, db, shareableViewingKey, creationBlockNumbers, prover);
    }
    /**
     * Loads wallet data from database and creates wallet object
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} id - wallet id
     * @returns {Wallet} Wallet
     */
    static async loadExisting(db, encryptionKey, id, prover) {
        // Get encrypted shareableViewingKey from DB
        const { shareableViewingKey, creationBlockNumbers } = (await abstract_wallet_1.AbstractWallet.read(db, id, encryptionKey));
        if (!shareableViewingKey) {
            throw new Error('Incorrect wallet type: ViewOnly wallet requires stored shareableViewingKey.');
        }
        return this.createWallet(id, db, shareableViewingKey, creationBlockNumbers, prover);
    }
}
exports.ViewOnlyWallet = ViewOnlyWallet;
//# sourceMappingURL=view-only-wallet.js.map