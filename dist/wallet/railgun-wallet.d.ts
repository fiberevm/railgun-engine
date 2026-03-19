/// <reference path="../../src/types/global.d.ts" />
import { Signature } from '@railgun-community/circomlibjs';
import { Database } from '../database/database';
import { SpendingKeyPair } from '../key-derivation/wallet-node';
import { AbstractWallet } from './abstract-wallet';
import { PublicInputsRailgun } from '../models';
import { Prover } from '../prover/prover';
declare class RailgunWallet extends AbstractWallet {
    /**
     * Load encrypted spending key Node from database
     * Spending key should be kept private and only accessed on demand
     * @returns {Promise<SpendingKeyPair>}
     */
    getSpendingKeyPair(encryptionKey: string): Promise<SpendingKeyPair>;
    sign(publicInputs: PublicInputsRailgun, encryptionKey: string): Promise<Signature>;
    /**
     * Load encrypted node from database with encryption key
     * @param {BytesData} encryptionKey
     * @returns {Node} BabyJubJub node
     */
    private loadSpendingKey;
    /**
     * Helper to get the ethereum/whatever address is associated with this wallet
     */
    getChainAddress(encryptionKey: string): Promise<string>;
    /**
     * Calculate Wallet ID from mnemonic and derivation path index
     * @returns {string} hash of mnemonic and index
     */
    private static generateID;
    private static createWallet;
    /**
     * Create a wallet from mnemonic
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} mnemonic - mnemonic to load wallet from
     * @param {number} index - index of derivation path to derive if not 0
     * @returns {RailgunWallet} Wallet
     */
    static fromMnemonic(db: Database, encryptionKey: string, mnemonic: string, index: number, creationBlockNumbers: Optional<number[][]>, prover: Prover): Promise<RailgunWallet>;
    /**
     * Loads wallet data from database and creates wallet object
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} id - wallet id
     * @returns {RailgunWallet} Wallet
     */
    static loadExisting(db: Database, encryptionKey: string, id: string, prover: Prover): Promise<RailgunWallet>;
}
export { RailgunWallet };
