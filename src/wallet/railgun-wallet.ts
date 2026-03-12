import { Signature } from '@railgun-community/circomlibjs';
import { poseidon } from '../utils/poseidon';
import { Database } from '../database/database';
import { deriveNodes, SpendingKeyPair, SpendingPublicKey, ViewingKeyPair, WalletNode } from '../key-derivation/wallet-node';
import { KeysWalletData, WalletData } from '../models/wallet-types';
import { ByteLength, ByteUtils } from '../utils/bytes';
import { sha256 } from '../utils/hash';
import { AbstractWallet } from './abstract-wallet';
import { Mnemonic } from '../key-derivation/bip39';
import { PublicInputsRailgun } from '../models';
import { signEDDSA, getPublicViewingKey } from '../utils/keys-utils';
import { Prover } from '../prover/prover';

class RailgunWallet extends AbstractWallet {
  /**
   * Load encrypted spending key Node from database
   * Spending key should be kept private and only accessed on demand
   * @returns {Promise<SpendingKeyPair>}
   */
  async getSpendingKeyPair(encryptionKey: string): Promise<SpendingKeyPair> {
    const node = await this.loadSpendingKey(encryptionKey);
    return node.getSpendingKeyPair();
  }

  async sign(publicInputs: PublicInputsRailgun, encryptionKey: string): Promise<Signature> {
    const spendingKeyPair = await this.getSpendingKeyPair(encryptionKey);
    const msg = poseidon([publicInputs.merkleRoot, publicInputs.boundParamsHash, ...publicInputs.nullifiers, ...publicInputs.commitmentsOut]);
    return signEDDSA(spendingKeyPair.privateKey, msg);
  }

  /**
   * Load encrypted node from database with encryption key
   * @param {BytesData} encryptionKey
   * @returns {Node} BabyJubJub node
   */
  private async loadSpendingKey(encryptionKey: string): Promise<WalletNode> {
    const { mnemonic, index } = (await RailgunWallet.read(
      this.db,
      this.id,
      encryptionKey,
    )) as WalletData;
    return deriveNodes(mnemonic, index).spending;
  }

  /**
   * Helper to get the ethereum/whatever address is associated with this wallet
   */
  async getChainAddress(encryptionKey: string): Promise<string> {
    const { mnemonic, index } = (await AbstractWallet.read(
      this.db,
      this.id,
      encryptionKey,
    )) as WalletData;
    return Mnemonic.to0xAddress(mnemonic, index);
  }

  /**
   * Calculate Wallet ID from mnemonic and derivation path index
   * @returns {string} hash of mnemonic and index
   */
  private static generateID(mnemonic: string, index: number): string {
    return sha256(ByteUtils.combine([Mnemonic.toSeed(mnemonic), index.toString(16)]));
  }

  private static async createWallet(
    id: string,
    db: Database,
    mnemonic: string,
    index: number,
    creationBlockNumbers: Optional<number[][]>,
    prover: Prover,
  ) {
    const nodes = deriveNodes(mnemonic, index);

    const viewingKeyPair = await nodes.viewing.getViewingKeyPair();
    const spendingPublicKey = nodes.spending.getSpendingKeyPair().pubkey;
    return new RailgunWallet(
      id,
      db,
      viewingKeyPair,
      spendingPublicKey,
      creationBlockNumbers,
      prover,
    );
  }

  /**
   * Create a wallet from mnemonic
   * @param {Database} db - database
   * @param {BytesData} encryptionKey - encryption key to use with database
   * @param {string} mnemonic - mnemonic to load wallet from
   * @param {number} index - index of derivation path to derive if not 0
   * @returns {RailgunWallet} Wallet
   */
  static async fromMnemonic(
    db: Database,
    encryptionKey: string,
    mnemonic: string,
    index: number,
    creationBlockNumbers: Optional<number[][]>,
    prover: Prover,
  ): Promise<RailgunWallet> {
    const id = RailgunWallet.generateID(mnemonic, index);

    // Write encrypted mnemonic to DB
    await AbstractWallet.write(db, id, encryptionKey, { mnemonic, index, creationBlockNumbers });

    return this.createWallet(id, db, mnemonic, index, creationBlockNumbers, prover);
  }

  /**
   * Loads wallet data from database and creates wallet object
   * @param {Database} db - database
   * @param {BytesData} encryptionKey - encryption key to use with database
   * @param {string} id - wallet id
   * @returns {RailgunWallet} Wallet
   */
  static async loadExisting(
    db: Database,
    encryptionKey: string,
    id: string,
    prover: Prover,
  ): Promise<RailgunWallet> {
    // Get encrypted mnemonic and index from DB
    const { mnemonic, index, creationBlockNumbers } = (await AbstractWallet.read(
      db,
      id,
      encryptionKey,
    )) as WalletData;
    if (!mnemonic) {
      throw new Error('Incorrect wallet type.');
    }

    return this.createWallet(id, db, mnemonic, index, creationBlockNumbers, prover);
  }
}

export type SignDelegate = (publicInputs: PublicInputsRailgun) => Promise<Signature>;

class DelegatedSignWallet extends AbstractWallet {
  private readonly signDelegate: SignDelegate;

  constructor(
    id: string,
    db: Database,
    viewingKeyPair: ViewingKeyPair,
    spendingPublicKey: SpendingPublicKey,
    creationBlockNumbers: Optional<number[][]>,
    prover: Prover,
    signDelegate: SignDelegate,
  ) {
    super(id, db, viewingKeyPair, spendingPublicKey, creationBlockNumbers, prover);
    this.signDelegate = signDelegate;
  }

  async sign(publicInputs: PublicInputsRailgun, _encryptionKey: string): Promise<Signature> {
    return this.signDelegate(publicInputs);
  }

  private static generateID(spendingPublicKey: SpendingPublicKey): string {
    const combined = ByteUtils.nToHex(spendingPublicKey[0], ByteLength.UINT_256)
      + ByteUtils.nToHex(spendingPublicKey[1], ByteLength.UINT_256);
    return sha256(combined);
  }

  static async fromKeys(
    db: Database,
    encryptionKey: string,
    viewingKeyPair: ViewingKeyPair,
    spendingPublicKey: SpendingPublicKey,
    creationBlockNumbers: Optional<number[][]>,
    prover: Prover,
    signDelegate: SignDelegate,
  ): Promise<DelegatedSignWallet> {
    const id = DelegatedSignWallet.generateID(spendingPublicKey);

    const viewingPrivateKey = ByteUtils.fastBytesToHex(viewingKeyPair.privateKey);
    const spendingPubStr = JSON.stringify(spendingPublicKey.map(String));

    await AbstractWallet.write(db, id, encryptionKey, {
      viewingPrivateKey,
      spendingPublicKey: spendingPubStr,
      creationBlockNumbers,
    });

    return new DelegatedSignWallet(
      id,
      db,
      viewingKeyPair,
      spendingPublicKey,
      creationBlockNumbers,
      prover,
      signDelegate,
    );
  }

  static async loadExisting(
    db: Database,
    encryptionKey: string,
    id: string,
    prover: Prover,
    signDelegate: SignDelegate,
  ): Promise<DelegatedSignWallet> {
    const { viewingPrivateKey, spendingPublicKey: spendingPubStr, creationBlockNumbers } =
      (await AbstractWallet.read(db, id, encryptionKey)) as KeysWalletData;
    if (!viewingPrivateKey) {
      throw new Error('Incorrect wallet type: DelegatedSign wallet requires stored viewingPrivateKey.');
    }

    const vpk = ByteUtils.hexStringToBytes(viewingPrivateKey);
    const viewingKeyPair: ViewingKeyPair = {
      privateKey: vpk,
      pubkey: await getPublicViewingKey(vpk),
    };
    const spendingPublicKey = (JSON.parse(spendingPubStr) as string[]).map(BigInt) as [bigint, bigint];

    return new DelegatedSignWallet(
      id,
      db,
      viewingKeyPair,
      spendingPublicKey,
      creationBlockNumbers,
      prover,
      signDelegate,
    );
  }
}

export { RailgunWallet, DelegatedSignWallet };
