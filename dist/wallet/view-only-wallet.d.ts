/// <reference path="../../src/types/global.d.ts" />
import { Signature } from '@railgun-community/circomlibjs';
import { Database } from '../database/database';
import { PublicInputsRailgun } from '../models';
import { AbstractWallet } from './abstract-wallet';
import { Prover } from '../prover/prover';
declare class ViewOnlyWallet extends AbstractWallet {
    sign(_publicInputs: PublicInputsRailgun, _encryptionKey: string): Promise<Signature>;
    /**
     * Calculate Wallet ID from mnemonic and derivation path index
     * @returns {string} hash of mnemonic and index
     */
    private static generateID;
    private static getViewingKeyPair;
    private static createWallet;
    /**
     * Create a wallet from mnemonic
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} shareableViewingKey - encoded keys to load wallet from
     * @returns {Wallet} Wallet
     */
    static fromShareableViewingKey(db: Database, encryptionKey: string, shareableViewingKey: string, creationBlockNumbers: Optional<number[][]>, prover: Prover): Promise<AbstractWallet>;
    /**
     * Loads wallet data from database and creates wallet object
     * @param {Database} db - database
     * @param {BytesData} encryptionKey - encryption key to use with database
     * @param {string} id - wallet id
     * @returns {Wallet} Wallet
     */
    static loadExisting(db: Database, encryptionKey: string, id: string, prover: Prover): Promise<AbstractWallet>;
}
export { ViewOnlyWallet };
