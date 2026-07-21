"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AbstractWallet = void 0;
const events_1 = __importDefault(require("events"));
const msgpack_lite_1 = __importDefault(require("msgpack-lite"));
const poseidon_1 = require("../utils/poseidon");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const bech32_1 = require("../key-derivation/bech32");
const wallet_node_1 = require("../key-derivation/wallet-node");
const event_types_1 = require("../models/event-types");
const formatted_types_1 = require("../models/formatted-types");
const txo_types_1 = require("../models/txo-types");
const memo_1 = require("../note/memo");
const bytes_1 = require("../utils/bytes");
const keys_utils_1 = require("../utils/keys-utils");
const wallet_types_1 = require("../models/wallet-types");
const babyjubjub_1 = require("../key-derivation/babyjubjub");
const chain_1 = require("../chain/chain");
const transact_note_1 = require("../note/transact-note");
const keys_utils_legacy_1 = require("../utils/keys-utils-legacy");
const note_1 = require("../note");
const note_util_1 = require("../note/note-util");
const token_data_getter_1 = require("../token/token-data-getter");
const is_defined_1 = require("../utils/is-defined");
const commitment_1 = require("../utils/commitment");
const blinded_commitment_1 = require("../utils/blinded-commitment");
const poi_types_1 = require("../models/poi-types");
const global_tree_position_1 = require("../utils/global-tree-position");
const extract_transaction_data_1 = require("../validation/extract-transaction-data");
const registry_1 = require("../utils/registry");
const constants_1 = require("../utils/constants");
const merkletree_types_1 = require("../models/merkletree-types");
class AbstractWallet extends events_1.default {
    db;
    tokenDataGetter;
    id;
    viewingKeyPair;
    masterPublicKey;
    spendingPublicKey;
    nullifyingKey;
    utxoMerkletrees = new registry_1.Registry();
    txidMerkletrees = new registry_1.Registry();
    prover;
    isClearingBalances = new registry_1.Registry();
    decryptBalancesKeyForChain = new registry_1.Registry();
    // Not a `Registry` because these come from the database as nested arrays and
    // we don't want to take risks associated with migrating the data format.
    creationBlockNumbers;
    receiveCommitmentsCache = new registry_1.Registry();
    sentCommitmentsCache = new registry_1.Registry();
    /**
     * Create Wallet controller
     * @param id - wallet ID
     * @param db - database
     */
    constructor(id, db, viewingKeyPair, spendingPublicKey, creationBlockNumbers, prover) {
        super();
        this.id = bytes_1.ByteUtils.hexlify(id);
        this.db = db;
        this.tokenDataGetter = new token_data_getter_1.TokenDataGetter(db);
        this.viewingKeyPair = viewingKeyPair;
        this.spendingPublicKey = spendingPublicKey;
        this.nullifyingKey = bytes_1.ByteUtils.hexToBigInt((0, poseidon_1.poseidonHex)([bytes_1.ByteUtils.fastBytesToHex(this.viewingKeyPair.privateKey)]));
        this.masterPublicKey = wallet_node_1.WalletNode.getMasterPublicKey(spendingPublicKey, this.nullifyingKey);
        this.creationBlockNumbers = creationBlockNumbers;
        this.prover = prover;
    }
    /**
     * Loads utxo merkle tree into wallet
     */
    async loadUTXOMerkletree(txidVersion, utxoMerkletree) {
        // Remove balances if the UTXO merkletree is out of date for this wallet.
        const { chain } = utxoMerkletree;
        const utxoMerkletreeHistoryVersion = await this.getUTXOMerkletreeHistoryVersion(chain);
        if (!(0, is_defined_1.isDefined)(utxoMerkletreeHistoryVersion) ||
            utxoMerkletreeHistoryVersion < constants_1.CURRENT_UTXO_MERKLETREE_HISTORY_VERSION) {
            await this.clearDecryptedBalancesAllTXIDVersions(chain);
            await this.setUTXOMerkletreeHistoryVersion(chain, constants_1.CURRENT_UTXO_MERKLETREE_HISTORY_VERSION);
            this.utxoMerkletrees.set(txidVersion, utxoMerkletree.chain, utxoMerkletree);
            return;
        }
        this.utxoMerkletrees.set(txidVersion, utxoMerkletree.chain, utxoMerkletree);
    }
    /**
     * Unload utxo merkle tree by chain
     */
    unloadUTXOMerkletree(txidVersion, chain) {
        this.utxoMerkletrees.del(txidVersion, chain);
    }
    /**
     * Loads txid merkle tree into wallet
     */
    loadRailgunTXIDMerkletree(txidVersion, txidMerkletree) {
        this.txidMerkletrees.set(txidVersion, txidMerkletree.chain, txidMerkletree);
    }
    /**
     * Unload txid merkle tree by chain
     */
    unloadRailgunTXIDMerkletree(txidVersion, chain) {
        this.txidMerkletrees.del(txidVersion, chain);
    }
    getUTXOMerkletreeHistoryVersionDBPrefix(chain) {
        const path = [...this.getWalletDBPrefix(chain), 'merkleetree_history_version'];
        if (chain != null) {
            path.push((0, chain_1.getChainFullNetworkID)(chain));
        }
        return path;
    }
    setUTXOMerkletreeHistoryVersion(chain, merkletreeHistoryVersion) {
        return this.db.put(this.getUTXOMerkletreeHistoryVersionDBPrefix(chain), merkletreeHistoryVersion, 'utf8');
    }
    getUTXOMerkletreeHistoryVersion(chain) {
        return this.db
            .get(this.getUTXOMerkletreeHistoryVersionDBPrefix(chain), 'utf8')
            .then((val) => parseInt(val, 10))
            .catch(() => Promise.resolve(undefined));
    }
    /**
     * Construct DB TXO path from chain
     * Prefix consists of ['wallet', id, chain]
     * May be appended with tree and position
     * @param chain - chain type/id
     * @optional tree - without this param, all trees
     * @optional position - without this param, all positions
     * @returns wallet DB prefix
     */
    getWalletDBPrefix(chain, tree, position) {
        const path = [
            (0, bytes_1.fromUTF8String)('wallet'),
            bytes_1.ByteUtils.hexlify(this.id),
            (0, chain_1.getChainFullNetworkID)(chain),
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
        if (tree != null) {
            path.push(bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.padToLength(tree, 32)));
        }
        if (position != null) {
            path.push(bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.padToLength(position, 32)));
        }
        return path;
    }
    /**
     * Construct DB received commitment path from chain
     * Prefix consists of ['wallet', id, chain]
     */
    getWalletReceiveCommitmentDBPrefix(chain, tree, position) {
        return this.getWalletDBPrefix(chain, tree, position);
    }
    /**
     * Construct DB spent commitment path from chain
     * Prefix consists of ['wallet', id + "-spent", chain]
     * May be appended with tree and position
     * @param chain - chain type/id
     * @optional tree - without this param, all trees
     * @optional position - without this param, all positions
     * @returns wallet DB prefix
     */
    getWalletSentCommitmentDBPrefix(chain, tree, position) {
        const path = [
            (0, bytes_1.fromUTF8String)('wallet'),
            `${bytes_1.ByteUtils.hexlify(this.id)}-spent`,
            (0, chain_1.getChainFullNetworkID)(chain),
        ].map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
        if (tree != null) {
            path.push(bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.padToLength(tree, 32)));
        }
        if (position != null) {
            path.push(bytes_1.ByteUtils.hexlify(bytes_1.ByteUtils.padToLength(position, 32)));
        }
        return path;
    }
    /**
     * Construct DB path from chain
     * @returns wallet DB path
     */
    getWalletDetailsPath(chain) {
        const detailsPath = (0, bytes_1.fromUTF8String)('details');
        return [...this.getWalletDBPrefix(chain), detailsPath];
    }
    /**
     * Return object of Viewing privateKey and pubkey
     * @returns {ViewingKeyPair}
     */
    getViewingKeyPair() {
        return this.viewingKeyPair;
    }
    /**
     * Used only to sign Broadcaster fee messages.
     * Verified using Broadcaster's viewingPublicKey, which is encoded in its rail address.
     * @param {Uint8Array} message - message to sign as Uint8Array
     */
    async signWithViewingKey(message) {
        const viewingPrivateKey = this.getViewingKeyPair().privateKey;
        return (0, keys_utils_1.signED25519)(message, viewingPrivateKey);
    }
    /**
     * Nullifying Key (ie poseidon hash of Viewing Private Key) aka vpk derived on ed25519 curve
     * Used to decrypt and nullify notes
     * @returns {bigint}
     */
    getNullifyingKey() {
        return this.nullifyingKey;
    }
    /**
     * Get Viewing Public Key (VK)
     * @returns {Uint8Array}
     */
    get viewingPublicKey() {
        return this.viewingKeyPair.pubkey;
    }
    /**
     * Return masterPublicKey and viewingPublicKey used to encode RAILGUN addresses
     * @returns {AddressKeys}
     */
    get addressKeys() {
        return {
            masterPublicKey: this.masterPublicKey,
            viewingPublicKey: this.viewingPublicKey,
        };
    }
    /**
     * Encode address from (MPK, VK) + chain
     * @returns {string} bech32 encoded RAILGUN address
     */
    getAddress(chain) {
        return (0, bech32_1.encodeAddress)({ ...this.addressKeys, chain });
    }
    async getWalletDetailsMap(chain) {
        try {
            // Try fetching from database
            const walletDetailsMapEncoded = (await this.db.get(this.getWalletDetailsPath(chain)));
            const walletDetailsMap = msgpack_lite_1.default.decode(bytes_1.ByteUtils.arrayify(walletDetailsMapEncoded));
            return walletDetailsMap;
        }
        catch {
            return {};
        }
    }
    /**
     * Get encrypted wallet details for this wallet
     * @param chain - chain type/id
     * @returns walletDetails - including treeScannedHeight
     */
    async getWalletDetails(txidVersion, chain) {
        try {
            const walletDetailsMap = await this.getWalletDetailsMap(chain);
            const walletDetails = walletDetailsMap[txidVersion];
            if (!(0, is_defined_1.isDefined)(walletDetails)) {
                throw new Error('No wallet details stored for txid version');
            }
            if (walletDetails.creationTree == null) {
                walletDetails.creationTree = undefined;
            }
            if (walletDetails.creationTreeHeight == null) {
                walletDetails.creationTreeHeight = undefined;
            }
            return walletDetails;
        }
        catch {
            // If details don't exist yet, return defaults
            const walletDetails = {
                treeScannedHeights: [],
                creationTree: undefined,
                creationTreeHeight: undefined,
            };
            return walletDetails;
        }
    }
    async decryptLeaf(txidVersion, chain, ciphertext, memoV2, annotationData, sharedKey, blindedReceiverViewingKey, blindedSenderViewingKey, isSentNote, isLegacyDecryption, blockNumber, transactCommitmentBatchIndexV3) {
        try {
            const decrypted = await transact_note_1.TransactNote.decrypt(txidVersion, chain, this.addressKeys, ciphertext, sharedKey, memoV2, annotationData, this.viewingKeyPair.privateKey, blindedReceiverViewingKey, blindedSenderViewingKey, isSentNote, isLegacyDecryption, this.tokenDataGetter, blockNumber, transactCommitmentBatchIndexV3);
            return decrypted;
        }
        catch (err) {
            // Expect error if leaf not addressed to this wallet.
            return undefined;
        }
    }
    static getCommitmentType(commitment) {
        if ((0, is_defined_1.isDefined)(commitment.commitmentType)) {
            // New or legacy commitment.
            return commitment.commitmentType;
        }
        // Legacy commitments pre-v3 only.
        return 'ciphertext' in commitment
            ? formatted_types_1.CommitmentType.LegacyEncryptedCommitment
            : formatted_types_1.CommitmentType.LegacyGeneratedCommitment;
    }
    async createScannedDBCommitments(txidVersion, leaf, viewingPrivateKey, tree, chain, position, totalLeaves) {
        let noteReceive;
        let noteSend;
        let serializedNoteReceive;
        let serializedNoteSend;
        if (debugger_1.default.verboseScanLogging()) {
            debugger_1.default.log(`Trying to decrypt commitment. Current index ${position}/${totalLeaves - 1}.`);
        }
        const walletAddress = this.getAddress();
        const commitmentType = AbstractWallet.getCommitmentType(leaf);
        switch (commitmentType) {
            case formatted_types_1.CommitmentType.TransactCommitmentV2: {
                const commitment = leaf;
                const blindedSenderViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitment.ciphertext.blindedSenderViewingKey);
                const blindedReceiverViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitment.ciphertext.blindedReceiverViewingKey);
                const [sharedKeyReceiver, sharedKeySender] = await Promise.all([
                    (0, keys_utils_1.getSharedSymmetricKey)(viewingPrivateKey, blindedSenderViewingKey),
                    (0, keys_utils_1.getSharedSymmetricKey)(viewingPrivateKey, blindedReceiverViewingKey),
                ]);
                if (sharedKeyReceiver) {
                    noteReceive = await this.decryptLeaf(txidVersion, chain, commitment.ciphertext.ciphertext, commitment.ciphertext.memo, commitment.ciphertext.annotationData, sharedKeyReceiver, blindedReceiverViewingKey, blindedSenderViewingKey, false, // isSentNote
                    false, // isLegacyDecryption
                    leaf.blockNumber, undefined);
                    serializedNoteReceive = noteReceive ? noteReceive.serialize() : undefined;
                }
                if (sharedKeySender) {
                    noteSend = await this.decryptLeaf(txidVersion, chain, commitment.ciphertext.ciphertext, commitment.ciphertext.memo, commitment.ciphertext.annotationData, sharedKeySender, blindedReceiverViewingKey, blindedSenderViewingKey, true, // isSentNote
                    false, // isLegacyDecryption
                    leaf.blockNumber, undefined);
                    serializedNoteSend = noteSend ? noteSend.serialize() : undefined;
                }
                break;
            }
            case formatted_types_1.CommitmentType.ShieldCommitment: {
                const commitment = leaf;
                const sharedKey = await (0, keys_utils_1.getSharedSymmetricKey)(viewingPrivateKey, bytes_1.ByteUtils.hexToBytes(commitment.shieldKey));
                try {
                    if (!sharedKey) {
                        throw new Error('No sharedKey from shield note');
                    }
                    const random = note_1.ShieldNote.decryptRandom(commitment.encryptedBundle, sharedKey);
                    const serialized = {
                        npk: commitment.preImage.npk,
                        random,
                        tokenHash: (0, note_util_1.getTokenDataHash)(commitment.preImage.token),
                        value: commitment.preImage.value,
                        outputType: undefined, // not used for non-private txs
                        senderRandom: undefined, // not used for non-private txs
                        walletSource: undefined, // not used for non-private txs
                        recipientAddress: walletAddress,
                        senderAddress: undefined,
                        memoText: undefined,
                        shieldFee: commitment.fee,
                        blockNumber: leaf.blockNumber,
                    };
                    noteReceive = await transact_note_1.TransactNote.deserialize(txidVersion, chain, serialized, viewingPrivateKey, this.tokenDataGetter);
                    serializedNoteReceive = serialized;
                }
                catch (err) {
                    // Expect error if leaf not addressed to this wallet.
                }
                break;
            }
            case formatted_types_1.CommitmentType.TransactCommitmentV3: {
                const commitment = leaf;
                const blindedSenderViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitment.ciphertext.blindedSenderViewingKey);
                const blindedReceiverViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitment.ciphertext.blindedReceiverViewingKey);
                const [sharedKeyReceiver, sharedKeySender] = await Promise.all([
                    (0, keys_utils_1.getSharedSymmetricKey)(viewingPrivateKey, blindedSenderViewingKey),
                    (0, keys_utils_1.getSharedSymmetricKey)(viewingPrivateKey, blindedReceiverViewingKey),
                ]);
                if (sharedKeyReceiver) {
                    noteReceive = await this.decryptLeaf(txidVersion, chain, commitment.ciphertext.ciphertext, '', // memoV2
                    commitment.senderCiphertext, // annotationData
                    sharedKeyReceiver, blindedReceiverViewingKey, blindedSenderViewingKey, false, // isSentNote
                    false, // isLegacyDecryption
                    leaf.blockNumber, commitment.transactCommitmentBatchIndex);
                    serializedNoteReceive = noteReceive ? noteReceive.serialize() : undefined;
                }
                if (sharedKeySender) {
                    noteSend = await this.decryptLeaf(txidVersion, chain, commitment.ciphertext.ciphertext, '', // memoV2
                    commitment.senderCiphertext, // annotationData
                    sharedKeySender, blindedReceiverViewingKey, blindedSenderViewingKey, true, // isSentNote
                    false, // isLegacyDecryption
                    leaf.blockNumber, commitment.transactCommitmentBatchIndex);
                    serializedNoteSend = noteSend ? noteSend.serialize() : undefined;
                }
                break;
            }
            case formatted_types_1.CommitmentType.LegacyEncryptedCommitment: {
                const commitment = leaf;
                const blindedSenderViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitment.ciphertext.ephemeralKeys[0]);
                const blindedReceiverViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitment.ciphertext.ephemeralKeys[1]);
                const [sharedKeyReceiver, sharedKeySender] = await Promise.all([
                    (0, keys_utils_legacy_1.getSharedSymmetricKeyLegacy)(viewingPrivateKey, blindedSenderViewingKey),
                    (0, keys_utils_legacy_1.getSharedSymmetricKeyLegacy)(viewingPrivateKey, blindedReceiverViewingKey),
                ]);
                const annotationData = bytes_1.ByteUtils.combine(commitment.ciphertext.memo.slice(0, memo_1.LEGACY_MEMO_METADATA_BYTE_CHUNKS));
                const memo = bytes_1.ByteUtils.combine(commitment.ciphertext.memo.slice(memo_1.LEGACY_MEMO_METADATA_BYTE_CHUNKS));
                if (sharedKeyReceiver) {
                    noteReceive = await this.decryptLeaf(txidVersion, chain, commitment.ciphertext.ciphertext, memo, annotationData, sharedKeyReceiver, blindedReceiverViewingKey, blindedSenderViewingKey, false, // isSentNote
                    true, // isLegacyDecryption
                    leaf.blockNumber, undefined);
                    serializedNoteReceive = noteReceive
                        ? noteReceive.serializeLegacy(viewingPrivateKey)
                        : undefined;
                }
                if (sharedKeySender) {
                    noteSend = await this.decryptLeaf(txidVersion, chain, commitment.ciphertext.ciphertext, memo, annotationData, sharedKeySender, blindedReceiverViewingKey, blindedSenderViewingKey, true, // isSentNote
                    true, // isLegacyDecryption
                    leaf.blockNumber, undefined);
                    serializedNoteSend = noteSend ? noteSend.serializeLegacy(viewingPrivateKey) : undefined;
                }
                break;
            }
            case formatted_types_1.CommitmentType.LegacyGeneratedCommitment: {
                const commitment = leaf;
                const serialized = {
                    npk: commitment.preImage.npk,
                    encryptedRandom: commitment.encryptedRandom,
                    tokenHash: (0, note_util_1.getTokenDataHashERC20)(commitment.preImage.token.tokenAddress),
                    value: commitment.preImage.value,
                    recipientAddress: walletAddress,
                    memoField: [],
                    memoText: undefined,
                    blockNumber: leaf.blockNumber,
                };
                try {
                    noteReceive = await transact_note_1.TransactNote.deserialize(txidVersion, chain, serialized, viewingPrivateKey, this.tokenDataGetter);
                    serializedNoteReceive = serialized;
                }
                catch (err) {
                    // Expect error if leaf not addressed to us.
                }
                break;
            }
        }
        const scannedCommitments = [];
        if ((noteReceive && !serializedNoteReceive) || (noteSend && !serializedNoteSend)) {
            throw new Error('Scan requires a serialized note.');
        }
        if (noteReceive && serializedNoteReceive) {
            const nullifier = transact_note_1.TransactNote.getNullifier(this.nullifyingKey, position);
            const storedReceiveCommitment = {
                txidVersion,
                spendtxid: false,
                txid: leaf.txid,
                timestamp: leaf.timestamp,
                blockNumber: leaf.blockNumber,
                nullifier: bytes_1.ByteUtils.nToHex(nullifier, bytes_1.ByteLength.UINT_256),
                decrypted: noteReceive.serialize(),
                senderAddress: noteReceive.senderAddressData
                    ? (0, bech32_1.encodeAddress)(noteReceive.senderAddressData)
                    : undefined,
                commitmentType: leaf.commitmentType,
                blindedCommitment: blinded_commitment_1.BlindedCommitment.getForShieldOrTransact(leaf.hash, noteReceive.notePublicKey, (0, global_tree_position_1.getGlobalTreePosition)(leaf.utxoTree, leaf.utxoIndex)),
                transactCreationRailgunTxid: 'railgunTxid' in leaf ? leaf.railgunTxid : undefined,
            };
            debugger_1.default.log(`Adding RECEIVE commitment at ${position} (Wallet ${this.id}). Chain: ${chain.id}`);
            scannedCommitments.push({
                type: 'put',
                key: this.getWalletReceiveCommitmentDBPrefix(chain, tree, position).join(':'),
                value: msgpack_lite_1.default.encode(storedReceiveCommitment),
            });
        }
        if (noteSend && serializedNoteSend) {
            const storedSendCommitment = {
                txidVersion,
                txid: leaf.txid,
                timestamp: leaf.timestamp,
                decrypted: serializedNoteSend,
                commitmentType: leaf.commitmentType,
                walletSource: noteSend.walletSource,
                outputType: noteSend.outputType,
                recipientAddress: (0, bech32_1.encodeAddress)(noteSend.receiverAddressData),
                blindedCommitment: blinded_commitment_1.BlindedCommitment.getForShieldOrTransact(leaf.hash, noteSend.notePublicKey, (0, global_tree_position_1.getGlobalTreePosition)(leaf.utxoTree, leaf.utxoIndex)),
                railgunTxid: 'railgunTxid' in leaf ? leaf.railgunTxid : undefined,
            };
            debugger_1.default.log(`Adding SPEND commitment at ${position} (Wallet ${this.id}). Chain: ${chain.id}`);
            scannedCommitments.push({
                type: 'put',
                key: this.getWalletSentCommitmentDBPrefix(chain, tree, position).join(':'),
                value: msgpack_lite_1.default.encode(storedSendCommitment),
            });
        }
        return scannedCommitments;
    }
    /**
     * Scans wallet at index for new balances
     * Commitment index in array should be same as commitment index in tree
     * @param {Commitment[]} leaves - commitments from events to attempt parsing
     * @param {number} tree - tree number we're scanning
     * @param {number} chain - chain type/id we're scanning
     * @param {number} startScanHeight - starting position
     */
    async scanLeaves(txidVersion, leaves, tree, chain, startScanHeight, scanTicker) {
        debugger_1.default.log(`wallet:scanLeaves tree:${tree} chain:${chain.type}:${chain.id} leaves:${leaves.length}, startScanHeight:${startScanHeight}`);
        const vpk = this.getViewingKeyPair().privateKey;
        const leafSyncPromises = [];
        for (let i = 0; i < leaves.length; i += 1) {
            const leaf = leaves[i];
            const position = startScanHeight + i;
            if (leaf == null) {
                if (scanTicker) {
                    scanTicker();
                }
                continue;
            }
            const scanPromiseWithTicker = async () => {
                const scanned = await this.createScannedDBCommitments(txidVersion, leaf, vpk, tree, chain, position, leaves.length);
                if (scanTicker) {
                    scanTicker();
                }
                return scanned;
            };
            leafSyncPromises.push(scanPromiseWithTicker());
        }
        const writeBatch = (await Promise.all(leafSyncPromises)).flat();
        // Write to DB
        await this.db.batch(writeBatch);
        this.invalidateCommitmentsCache(chain);
    }
    async keySplits(namespace, fieldCount) {
        const keys = await this.db.getNamespaceKeys(namespace);
        const keySplits = keys
            .map((key) => key.split(':'))
            .filter((keySplit) => keySplit.length === fieldCount);
        return keySplits;
    }
    async queryAllStoredReceiveCommitments(txidVersion, chain) {
        const namespace = this.getWalletDBPrefix(chain);
        const keySplits = await this.keySplits(namespace, 5);
        const dbStoredReceiveCommitments = (0, is_defined_1.removeUndefineds)(await Promise.all(keySplits.map(async (keySplit) => {
            const data = (await this.db.get(keySplit));
            const storedReceiveCommitment = msgpack_lite_1.default.decode(bytes_1.ByteUtils.arrayify(data));
            if (storedReceiveCommitment.txidVersion !== txidVersion) {
                return undefined;
            }
            const tree = parseInt(keySplit[3], 16);
            const position = parseInt(keySplit[4], 16);
            return { storedReceiveCommitment, tree, position };
        })));
        return dbStoredReceiveCommitments;
    }
    async queryAllStoredSendCommitments(txidVersion, chain) {
        const namespace = this.getWalletSentCommitmentDBPrefix(chain);
        const keySplits = await this.keySplits(namespace, 5);
        const dbStoredSendCommitments = (0, is_defined_1.removeUndefineds)(await Promise.all(keySplits.map(async (keySplit) => {
            const data = (await this.db.get(keySplit));
            const storedSendCommitment = msgpack_lite_1.default.decode(bytes_1.ByteUtils.arrayify(data));
            if (storedSendCommitment.txidVersion !== txidVersion) {
                return undefined;
            }
            const tree = parseInt(keySplit[3], 16);
            const position = parseInt(keySplit[4], 16);
            return { storedSendCommitment, tree, position };
        })));
        return dbStoredSendCommitments;
    }
    /**
     * Clears commitments cache
     */
    invalidateCommitmentsCache(chain) {
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            this.receiveCommitmentsCache.del(txidVersion, chain);
            this.sentCommitmentsCache.del(txidVersion, chain);
        }
    }
    /**
     * Get TXOs list of a chain
     * @param chain - chain type/id to get UTXOs for
     * @returns UTXOs list
     */
    async TXOs(txidVersion, chain) {
        if (!this.hasUTXOMerkletree(txidVersion, chain)) {
            return [];
        }
        const cachedTXOs = this.receiveCommitmentsCache.get(txidVersion, chain);
        if ((0, is_defined_1.isDefined)(cachedTXOs)) {
            return cachedTXOs;
        }
        const recipientAddress = (0, bech32_1.encodeAddress)(this.addressKeys);
        const vpk = this.getViewingKeyPair().privateKey;
        const merkletree = this.getUTXOMerkletree(txidVersion, chain);
        const storedReceiveCommitments = await this.queryAllStoredReceiveCommitments(txidVersion, chain);
        const TXOs = await Promise.all(storedReceiveCommitments.map(async ({ storedReceiveCommitment, tree, position }) => {
            const receiveCommitment = storedReceiveCommitment;
            const note = await transact_note_1.TransactNote.deserialize(txidVersion, chain, {
                ...receiveCommitment.decrypted,
                recipientAddress,
            }, vpk, this.tokenDataGetter);
            // Reconcile persisted spend state so a canonical replay can remove orphaned nullifiers.
            const nullifierSpendMetadata = await merkletree.getNullifierSpendMetadata(receiveCommitment.nullifier, tree);
            const canonicalSpendtxid = nullifierSpendMetadata?.txid ?? false;
            if (receiveCommitment.spendtxid !== canonicalSpendtxid) {
                receiveCommitment.spendtxid = canonicalSpendtxid;
                await this.updateReceiveCommitmentInDB(chain, tree, position, receiveCommitment);
            }
            // Look up blinded commitment.
            if (!(0, is_defined_1.isDefined)(receiveCommitment.blindedCommitment) ||
                (!(0, is_defined_1.isDefined)(receiveCommitment.transactCreationRailgunTxid) &&
                    (0, commitment_1.isTransactCommitmentType)(receiveCommitment.commitmentType))) {
                const globalTreePosition = (0, global_tree_position_1.getGlobalTreePosition)(tree, position);
                const commitment = await merkletree.getCommitment(tree, position);
                if ((0, commitment_1.isTransactCommitment)(commitment) &&
                    !(0, commitment_1.isTransactCommitmentType)(receiveCommitment.commitmentType)) {
                    // Should never happen
                    throw new Error('Fatal - Invalid commitment type');
                }
                let hasUpdate = false;
                if ((0, commitment_1.isTransactCommitment)(commitment) &&
                    ((0, is_defined_1.isDefined)(receiveCommitment.transactCreationRailgunTxid) ||
                        (0, is_defined_1.isDefined)(commitment.railgunTxid)) &&
                    receiveCommitment.transactCreationRailgunTxid !== commitment.railgunTxid) {
                    receiveCommitment.transactCreationRailgunTxid = commitment.railgunTxid;
                    hasUpdate = true;
                }
                const blindedCommitment = blinded_commitment_1.BlindedCommitment.getForShieldOrTransact(commitment.hash, note.notePublicKey, globalTreePosition);
                if (((0, is_defined_1.isDefined)(receiveCommitment.blindedCommitment) || (0, is_defined_1.isDefined)(blindedCommitment)) &&
                    receiveCommitment.blindedCommitment !== blindedCommitment) {
                    receiveCommitment.blindedCommitment = blindedCommitment;
                    hasUpdate = true;
                }
                if (hasUpdate) {
                    await this.updateReceiveCommitmentInDB(chain, tree, position, receiveCommitment);
                }
            }
            const txo = {
                tree,
                position,
                blockNumber: receiveCommitment.blockNumber,
                txid: receiveCommitment.txid,
                timestamp: receiveCommitment.timestamp,
                spendtxid: receiveCommitment.spendtxid,
                spendBlockNumber: receiveCommitment.spendtxid !== false &&
                    nullifierSpendMetadata?.txid === receiveCommitment.spendtxid
                    ? nullifierSpendMetadata.blockNumber
                    : undefined,
                nullifier: receiveCommitment.nullifier,
                note,
                blindedCommitment: receiveCommitment.blindedCommitment,
                commitmentType: receiveCommitment.commitmentType,
                transactCreationRailgunTxid: receiveCommitment.transactCreationRailgunTxid,
            };
            return txo;
        }));
        this.receiveCommitmentsCache.set(txidVersion, chain, TXOs);
        return TXOs;
    }
    /**
     * Get spent commitments of a chain
     * @param chain - chain type/id to get spent commitments for
     * @returns SentCommitment list
     */
    async getSentCommitments(txidVersion, chain, startingBlock) {
        if (!this.hasUTXOMerkletree(txidVersion, chain)) {
            return [];
        }
        // We have a cache invalidation problem elsewhere, so this is disabled for now:
        // const cachedSentCommitments = this.sentCommitmentsCache.get(txidVersion, chain);
        // if (isDefined(cachedSentCommitments)) {
        //   return cachedSentCommitments;
        // }
        const vpk = this.getViewingKeyPair().privateKey;
        const sentCommitments = [];
        const storedSendCommitments = await this.queryAllStoredSendCommitments(txidVersion, chain);
        await Promise.all(storedSendCommitments.map(async ({ storedSendCommitment, tree, position }) => {
            const sentCommitment = storedSendCommitment;
            const note = await transact_note_1.TransactNote.deserialize(txidVersion, chain, sentCommitment.decrypted, vpk, this.tokenDataGetter);
            if (!(0, is_defined_1.isDefined)(note.blockNumber)) {
                return;
            }
            if (startingBlock != null && note.blockNumber < startingBlock) {
                return;
            }
            // Look up railgunTxid.
            if (!(0, is_defined_1.isDefined)(sentCommitment.railgunTxid) ||
                !(0, is_defined_1.isDefined)(sentCommitment.blindedCommitment)) {
                const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
                const commitment = await utxoMerkletree.getCommitment(tree, position);
                if ((0, commitment_1.isTransactCommitment)(commitment) && (0, is_defined_1.isDefined)(commitment.railgunTxid)) {
                    sentCommitment.blindedCommitment = blinded_commitment_1.BlindedCommitment.getForShieldOrTransact(commitment.hash, note.notePublicKey, (0, global_tree_position_1.getGlobalTreePosition)(commitment.utxoTree, commitment.utxoIndex));
                    sentCommitment.railgunTxid = commitment.railgunTxid;
                    await this.updateSentCommitmentInDB(chain, tree, position, sentCommitment);
                }
            }
            sentCommitments.push({
                tree,
                position,
                txid: sentCommitment.txid,
                timestamp: sentCommitment.timestamp,
                note,
                walletSource: sentCommitment.walletSource,
                outputType: sentCommitment.outputType,
                isLegacyTransactNote: transact_note_1.TransactNote.isLegacyTransactNote(sentCommitment.decrypted),
                railgunTxid: sentCommitment.railgunTxid,
                blindedCommitment: sentCommitment.blindedCommitment,
                commitmentType: sentCommitment.commitmentType,
            });
        }));
        this.sentCommitmentsCache.set(txidVersion, chain, sentCommitments);
        return sentCommitments;
    }
    async updateReceiveCommitmentInDB(chain, tree, position, receiveCommitment) {
        await this.db.put(this.getWalletReceiveCommitmentDBPrefix(chain, tree, position), msgpack_lite_1.default.encode(receiveCommitment));
        this.invalidateCommitmentsCache(chain);
    }
    async updateSentCommitmentInDB(chain, tree, position, sentCommitment) {
        await this.db.put(this.getWalletSentCommitmentDBPrefix(chain, tree, position), msgpack_lite_1.default.encode(sentCommitment));
        this.invalidateCommitmentsCache(chain);
    }
    async getSpendableReceivedChainTxids(txidVersion, chain) {
        const TXOs = await this.TXOs(txidVersion, chain);
        const spendableTXOs = TXOs.filter((txo) => txo.spendtxid === false);
        const txids = spendableTXOs.map((item) => item.txid);
        return (0, is_defined_1.removeDuplicates)(txids);
    }
    static getPossibleChangeTokenAmounts(historyItem) {
        switch (historyItem.version) {
            case wallet_types_1.TransactionHistoryItemVersion.Unknown:
            case wallet_types_1.TransactionHistoryItemVersion.Legacy:
                // Legacy versions don't have change token amounts.
                return historyItem.transferTokenAmounts;
            case wallet_types_1.TransactionHistoryItemVersion.UpdatedAug2022:
            case wallet_types_1.TransactionHistoryItemVersion.UpdatedNov2022:
                return historyItem.changeTokenAmounts;
        }
        throw new Error('Unrecognized history item version');
    }
    /**
     * Gets transactions history
     * @param chain - chain type/id to get transaction history for
     * @returns history
     */
    async getTransactionHistory(chain, startingBlock) {
        const transactionHistory = [];
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            transactionHistory.push(...(await this.getTransactionHistoryByTXIDVersion(txidVersion, chain, startingBlock)));
        }
        return transactionHistory;
    }
    async getTransactionHistoryByTXIDVersion(txidVersion, chain, startingBlock) {
        const TXOs = await this.TXOs(txidVersion, chain);
        const filteredTXOs = AbstractWallet.filterTXOsByBlockNumber(TXOs, startingBlock);
        const [receiveHistory, spendHistory] = await Promise.all([
            AbstractWallet.getTransactionReceiveHistory(txidVersion, filteredTXOs),
            this.getTransactionSpendHistory(txidVersion, chain, filteredTXOs, startingBlock),
        ]);
        const history = spendHistory.map((sendItem) => ({
            ...sendItem,
            receiveTokenAmounts: [],
        }));
        // Merge "spent" history with "receive" history items.
        // We have to remove all "receive" items that are change outputs.
        for (const receiveItem of receiveHistory) {
            let alreadyExistsInHistory = false;
            for (const existingHistoryItem of history) {
                if (receiveItem.txid === existingHistoryItem.txid) {
                    alreadyExistsInHistory = true;
                    const changeTokenAmounts = AbstractWallet.getPossibleChangeTokenAmounts(existingHistoryItem);
                    for (const receiveTokenAmount of receiveItem.receiveTokenAmounts) {
                        const matchingChangeOutput = changeTokenAmounts.find((ta) => ta.tokenHash === receiveTokenAmount.tokenHash &&
                            ta.amount === receiveTokenAmount.amount);
                        if (matchingChangeOutput &&
                            [
                                wallet_types_1.TransactionHistoryItemVersion.Unknown,
                                wallet_types_1.TransactionHistoryItemVersion.Legacy,
                            ].includes(existingHistoryItem.version)) {
                            // Remove change output (stored in transferTokenAmounts in legacy history items)
                            // Move to change outputs
                            const index = existingHistoryItem.transferTokenAmounts.findIndex((ta) => ta.tokenHash === receiveTokenAmount.tokenHash &&
                                ta.amount === receiveTokenAmount.amount);
                            existingHistoryItem.transferTokenAmounts.splice(index, 1);
                            existingHistoryItem.changeTokenAmounts.push(matchingChangeOutput);
                        }
                        else if (!matchingChangeOutput) {
                            // Receive token amount is not a "change" output.
                            // Add it to the history item.
                            existingHistoryItem.receiveTokenAmounts.push(receiveTokenAmount);
                        }
                    }
                }
            }
            if (!alreadyExistsInHistory) {
                history.unshift({
                    ...receiveItem,
                    transferTokenAmounts: [],
                    changeTokenAmounts: [],
                    unshieldTokenAmounts: [],
                    version: wallet_types_1.TransactionHistoryItemVersion.Unknown,
                });
            }
        }
        return history;
    }
    static filterTXOsByBlockNumber(txos, startingBlock) {
        if (startingBlock == null) {
            return txos;
        }
        let hasShownNoBlockNumbersError = false;
        return txos.filter((txo) => {
            if (!(0, is_defined_1.isDefined)(txo.note.blockNumber)) {
                if (!hasShownNoBlockNumbersError) {
                    // This will occur for legacy scanned notes.
                    // New notes will have block number, and will optimize the history response.
                    debugger_1.default.error(new Error('No blockNumbers for TXOs'));
                    hasShownNoBlockNumbersError = true;
                }
                return true;
            }
            return txo.note.blockNumber >= startingBlock;
        });
    }
    async extractFirstNoteERC20AmountMap(txidVersion, chain, transactionRequest, useRelayAdapt, contractAddress) {
        return (0, extract_transaction_data_1.extractFirstNoteERC20AmountMapFromTransactionRequest)(txidVersion, chain, transactionRequest, useRelayAdapt, contractAddress, this.getViewingKeyPair().privateKey, this.addressKeys, this.tokenDataGetter);
    }
    /**
     * Gets transactions history for "received" transactions
     * @param chain - chain type/id to get balances for
     * @returns history
     */
    static getTransactionReceiveHistory(txidVersion, filteredTXOs) {
        const txidTransactionMap = {};
        for (const txo of filteredTXOs) {
            const { txid, timestamp, note } = txo;
            if (note.value === 0n) {
                continue;
            }
            if (!(0, is_defined_1.isDefined)(txidTransactionMap[txid])) {
                txidTransactionMap[txid] = {
                    txidVersion,
                    txid,
                    timestamp,
                    blockNumber: note.blockNumber,
                    receiveTokenAmounts: [],
                };
            }
            const tokenHash = bytes_1.ByteUtils.formatToByteLength(note.tokenHash, bytes_1.ByteLength.UINT_256, false);
            txidTransactionMap[txid].receiveTokenAmounts.push({
                tokenHash,
                tokenData: note.tokenData,
                amount: note.value,
                memoText: note.memoText,
                senderAddress: note.getSenderAddress(),
                shieldFee: note.shieldFee,
                balanceBucket: txo_types_1.WalletBalanceBucket.Spendable,
            });
        }
        const history = Object.values(txidTransactionMap);
        return history;
    }
    static getTransactionHistoryItemVersion(outputType, isLegacyTransactNote) {
        if (!(0, is_defined_1.isDefined)(outputType)) {
            return wallet_types_1.TransactionHistoryItemVersion.Legacy;
        }
        if (isLegacyTransactNote) {
            return wallet_types_1.TransactionHistoryItemVersion.UpdatedAug2022;
        }
        return wallet_types_1.TransactionHistoryItemVersion.UpdatedNov2022;
    }
    /**
     * NOTE: There are no Unshield events pre-V2.
     */
    async getUnshieldEventsFromSpentNullifiers(txidVersion, chain, filteredTXOs) {
        if (!this.hasUTXOMerkletree(txidVersion, chain)) {
            return [];
        }
        const merkletree = this.getUTXOMerkletree(txidVersion, chain);
        const unshieldEvents = [];
        const seenSpentTxids = [];
        const spentTXOs = filteredTXOs.filter((txo) => (0, is_defined_1.isDefined)(txo.spendtxid) && txo.spendtxid !== false);
        await Promise.all(spentTXOs.map(async ({ spendtxid, note }) => {
            if (note.value === 0n) {
                return;
            }
            if (spendtxid === false || !spendtxid) {
                return;
            }
            if (seenSpentTxids.includes(spendtxid)) {
                return;
            }
            seenSpentTxids.push(spendtxid);
            // Nullifier exists. Find unshield events from txid.
            // NOTE: There are no Unshield events pre-V2.
            const unshieldEventsForNullifier = await merkletree.getAllUnshieldEventsForTxid(spendtxid);
            const filteredUnshieldEventsForNullifier = unshieldEventsForNullifier.filter((event) => unshieldEvents.find((existingUnshieldEvent) => AbstractWallet.compareUnshieldEvents(existingUnshieldEvent, event)) == null);
            unshieldEvents.push(...filteredUnshieldEventsForNullifier);
        }));
        return unshieldEvents;
    }
    static compareUnshieldEvents(a, b) {
        return (a.txid === b.txid &&
            (a.eventLogIndex === b.eventLogIndex ||
                ((0, is_defined_1.isDefined)(a.railgunTxid) && a.railgunTxid === b.railgunTxid)));
    }
    async getTransactionSpendHistory(txidVersion, chain, filteredTXOs, startingBlock) {
        const [allUnshieldEvents, sentCommitments] = await Promise.all([
            this.getUnshieldEventsFromSpentNullifiers(txidVersion, chain, filteredTXOs),
            this.getSentCommitments(txidVersion, chain, startingBlock),
        ]);
        const txidTransactionMap = {};
        for (const sentCommitment of sentCommitments) {
            const { txid, timestamp, note, isLegacyTransactNote, outputType, walletSource } = sentCommitment;
            if (note.value === 0n) {
                continue;
            }
            if (!(0, is_defined_1.isDefined)(txidTransactionMap[txid])) {
                txidTransactionMap[txid] = {
                    txid,
                    timestamp,
                    blockNumber: note.blockNumber,
                    tokenAmounts: [],
                    unshieldEvents: [],
                    version: AbstractWallet.getTransactionHistoryItemVersion(outputType, isLegacyTransactNote),
                };
            }
            const tokenHash = bytes_1.ByteUtils.formatToByteLength(note.tokenHash, bytes_1.ByteLength.UINT_256, false);
            const tokenAmount = {
                tokenHash,
                tokenData: note.tokenData,
                amount: note.value,
                outputType,
                walletSource,
                memoText: note.memoText,
            };
            const isNonLegacyTransfer = !isLegacyTransactNote && outputType === formatted_types_1.OutputType.Transfer;
            if (isNonLegacyTransfer) {
                tokenAmount.recipientAddress = (0, bech32_1.encodeAddress)(note.receiverAddressData);
            }
            txidTransactionMap[txid].tokenAmounts.push(tokenAmount);
        }
        // Add unshield events to txidTransactionMap
        for (const unshieldEvent of allUnshieldEvents) {
            const foundUnshieldTransactionInTransactCommitments = txidTransactionMap[unshieldEvent.txid];
            if (!(0, is_defined_1.isDefined)(foundUnshieldTransactionInTransactCommitments)) {
                // This will occur on a self-signed unshield.
                // There is no commitment (or tokenAmounts) for this kind of unshield transaction.
                txidTransactionMap[unshieldEvent.txid] = {
                    txid: unshieldEvent.txid,
                    timestamp: unshieldEvent.timestamp,
                    blockNumber: unshieldEvent.blockNumber,
                    unshieldEvents: [unshieldEvent],
                    tokenAmounts: [],
                    version: wallet_types_1.TransactionHistoryItemVersion.UpdatedNov2022,
                };
                continue;
            }
            // Unshield event exists. Add to its amount rather than creating a new event.
            // Multiple unshields of the same token can occur in cases of complex circuits. (More than 10 inputs to the unshield).
            const existingUnshieldEvent = txidTransactionMap[unshieldEvent.txid].unshieldEvents.find((existingEvent) => AbstractWallet.compareUnshieldEvents(existingEvent, unshieldEvent));
            if (existingUnshieldEvent) {
                // Add amount to existing unshield event.
                existingUnshieldEvent.amount = (BigInt(existingUnshieldEvent.amount) + BigInt(unshieldEvent.amount)).toString();
                continue;
            }
            txidTransactionMap[unshieldEvent.txid].unshieldEvents.push(unshieldEvent);
        }
        const preProcessHistory = Object.values(txidTransactionMap);
        const history = preProcessHistory.map(({ txid, timestamp, blockNumber, tokenAmounts, unshieldEvents, version }) => {
            const transferTokenAmounts = [];
            let broadcasterFeeTokenAmount;
            const changeTokenAmounts = [];
            for (const tokenAmount of tokenAmounts) {
                if (!(0, is_defined_1.isDefined)(tokenAmount.outputType)) {
                    // Legacy notes without extra data, consider as a simple "transfer".
                    transferTokenAmounts.push(tokenAmount);
                    continue;
                }
                switch (tokenAmount.outputType) {
                    case formatted_types_1.OutputType.Transfer:
                        transferTokenAmounts.push(
                        // NOTE: recipientAddress is set during pre-process for all non-legacy Transfers.
                        tokenAmount);
                        break;
                    case formatted_types_1.OutputType.BroadcasterFee:
                        broadcasterFeeTokenAmount = tokenAmount;
                        break;
                    case formatted_types_1.OutputType.Change:
                        changeTokenAmounts.push(tokenAmount);
                        break;
                }
            }
            const unshieldTokenAmounts = unshieldEvents.map((unshieldEvent) => {
                const tokenData = (0, note_util_1.serializeTokenData)(unshieldEvent.tokenAddress, unshieldEvent.tokenType, unshieldEvent.tokenSubID);
                const tokenHash = (0, note_util_1.getTokenDataHash)(tokenData);
                return {
                    tokenHash,
                    tokenData,
                    amount: BigInt(unshieldEvent.amount),
                    memoText: undefined,
                    recipientAddress: unshieldEvent.toAddress,
                    senderAddress: undefined,
                    unshieldFee: unshieldEvent.fee,
                };
            });
            const historyEntry = {
                txidVersion,
                txid,
                timestamp,
                blockNumber,
                transferTokenAmounts,
                broadcasterFeeTokenAmount,
                changeTokenAmounts,
                unshieldTokenAmounts,
                version,
            };
            return historyEntry;
        });
        return history;
    }
    getUTXOMerkletree(txidVersion, chain) {
        if (txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
            (0, chain_1.assertChainSupportsV3)(chain);
        }
        const merkletree = this.utxoMerkletrees.get(txidVersion, chain);
        if (!(0, is_defined_1.isDefined)(merkletree)) {
            throw new Error(`No utxo merkletree for chain ${chain.type}:${chain.id}, ${txidVersion}`);
        }
        return merkletree;
    }
    hasUTXOMerkletree(txidVersion, chain) {
        try {
            this.getUTXOMerkletree(txidVersion, chain);
            return true;
        }
        catch {
            return false;
        }
    }
    getRailgunTXIDMerkletreeForChain(txidVersion, chain) {
        const merkletree = this.txidMerkletrees.get(txidVersion, chain);
        if (!(0, is_defined_1.isDefined)(merkletree)) {
            throw new Error(`No txid merkletree for chain ${chain.type}:${chain.id}`);
        }
        return merkletree;
    }
    async getTokenBalancesAllTxidVersions(chain, balanceBucketFilter) {
        const balances = {};
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            const TXOs = await this.TXOs(txidVersion, chain);
            const balancesByTxidVersion = await AbstractWallet.getTokenBalancesByTxidVersion(TXOs, balanceBucketFilter);
            for (const tokenHash of Object.keys(balancesByTxidVersion)) {
                balances[txidVersion] ??= {};
                balances[txidVersion][tokenHash] = balancesByTxidVersion[tokenHash];
            }
        }
        return balances;
    }
    async getTokenBalances(txidVersion, chain, onlySpendable) {
        const balanceBucketFilter = onlySpendable
            ? [txo_types_1.WalletBalanceBucket.Spendable]
            : Object.values(txo_types_1.WalletBalanceBucket);
        const TXOs = await this.TXOs(txidVersion, chain);
        return AbstractWallet.getTokenBalancesByTxidVersion(TXOs, balanceBucketFilter);
    }
    async getTokenBalancesForUnshieldToOrigin(txidVersion, chain, originShieldTxidForSpendabilityOverride) {
        const TXOs = await this.TXOs(txidVersion, chain);
        return AbstractWallet.getTokenBalancesByTxidVersion(TXOs, [], originShieldTxidForSpendabilityOverride);
    }
    async getTokenBalancesByBucket(txidVersion, chain) {
        const TXOs = await this.TXOs(txidVersion, chain);
        const balancesByBucket = {};
        for (const balanceBucket of Object.values(txo_types_1.WalletBalanceBucket)) {
            const balanceBucketFilter = [balanceBucket];
            balancesByBucket[balanceBucket] = await AbstractWallet.getTokenBalancesByTxidVersion(TXOs, balanceBucketFilter);
        }
        return balancesByBucket;
    }
    /**
     * Gets wallet balances
     * @param chain - chain type/id to get balances for
     * @returns balances
     */
    static async getTokenBalancesByTxidVersion(TXOs, balanceBucketFilter, originShieldTxidForSpendabilityOverride) {
        const tokenBalances = {};
        // Loop through each TXO and add to balances if unspent
        for (const txo of TXOs) {
            const tokenHash = bytes_1.ByteUtils.formatToByteLength(txo.note.tokenHash, bytes_1.ByteLength.UINT_256, false);
            // If we don't have an entry for this token yet, create one
            if (!(0, is_defined_1.isDefined)(tokenBalances[tokenHash])) {
                tokenBalances[tokenHash] = {
                    balance: BigInt(0),
                    utxos: [],
                    tokenData: txo.note.tokenData,
                };
            }
            const isSpent = txo.spendtxid !== false;
            if (isSpent) {
                continue;
            }
            const balanceBucket = txo_types_1.WalletBalanceBucket.Spendable;
            if ((0, is_defined_1.isDefined)(originShieldTxidForSpendabilityOverride)) {
                // Only for Unshield-To-Origin transactions. Filter TXOs by the provided shield txid.
                if (!(0, commitment_1.isShieldCommitmentType)(txo.commitmentType) ||
                    bytes_1.ByteUtils.formatToByteLength(txo.txid, bytes_1.ByteLength.UINT_256) !==
                        bytes_1.ByteUtils.formatToByteLength(originShieldTxidForSpendabilityOverride, bytes_1.ByteLength.UINT_256)) {
                    // Skip if txid doesn't match.
                    continue;
                }
            }
            else if (!balanceBucketFilter.includes(balanceBucket)) {
                if (debugger_1.default.isTestRun() && balanceBucket === txo_types_1.WalletBalanceBucket.Spendable) {
                    // WARNING FOR TESTS ONLY
                    debugger_1.default.error(new Error('WARNING: Missing SPENDABLE balance - unexpected balance bucket mismatch'));
                }
                continue;
            }
            // Store utxo
            tokenBalances[tokenHash].utxos.push(txo);
            // Increment balance
            tokenBalances[tokenHash].balance += txo.note.value;
        }
        return tokenBalances;
    }
    async getBalanceERC20(txidVersion, chain, tokenAddress, balanceBucketFilter) {
        const TXOs = await this.TXOs(txidVersion, chain);
        const balances = await AbstractWallet.getTokenBalancesByTxidVersion(TXOs, balanceBucketFilter);
        const tokenHash = (0, note_util_1.getTokenDataHash)((0, note_util_1.getTokenDataERC20)(tokenAddress));
        const balanceForToken = balances[tokenHash];
        return (0, is_defined_1.isDefined)(balanceForToken) ? balanceForToken.balance : undefined;
    }
    /**
     * Sort token balances by tree
     * @param chain - chain type/id of token
     * @returns balances by tree
     */
    async getTotalBalancesByTreeNumber(txidVersion, chain, balanceBucketFilter, originShieldTxidForSpendabilityOverride) {
        const TXOs = await this.TXOs(txidVersion, chain);
        const tokenBalances = await AbstractWallet.getTokenBalancesByTxidVersion(TXOs, balanceBucketFilter, originShieldTxidForSpendabilityOverride);
        // Sort token balances by tree
        const totalBalancesByTreeNumber = {};
        // Loop through each token
        for (const tokenHash of Object.keys(tokenBalances)) {
            // Create balances tree array
            totalBalancesByTreeNumber[tokenHash] = [];
            // Loop through each TXO and sort by tree
            for (const utxo of tokenBalances[tokenHash].utxos) {
                if (!(0, is_defined_1.isDefined)(totalBalancesByTreeNumber[tokenHash][utxo.tree])) {
                    totalBalancesByTreeNumber[tokenHash][utxo.tree] = {
                        balance: utxo.note.value,
                        utxos: [utxo],
                        tokenData: utxo.note.tokenData,
                    };
                }
                else {
                    totalBalancesByTreeNumber[tokenHash][utxo.tree].balance += utxo.note.value;
                    totalBalancesByTreeNumber[tokenHash][utxo.tree].utxos.push(utxo);
                }
            }
        }
        return totalBalancesByTreeNumber;
    }
    async balancesByTreeForToken(txidVersion, chain, tokenHash, balanceBucketFilter, originShieldTxidForSpendabilityOverride) {
        const totalBalancesByTreeNumber = await this.getTotalBalancesByTreeNumber(txidVersion, chain, balanceBucketFilter, originShieldTxidForSpendabilityOverride);
        const treeSortedBalances = totalBalancesByTreeNumber[tokenHash] ?? [];
        return treeSortedBalances;
    }
    static tokenBalanceAcrossAllTrees(treeSortedBalances) {
        const tokenBalance = treeSortedBalances.reduce((left, right) => left + right.balance, BigInt(0));
        return tokenBalance;
    }
    async decryptBalances(txidVersion, chain, progressCallback, deferCompletionEvent) {
        try {
            if (this.isClearingBalances.get(null, chain) === true) {
                debugger_1.default.log('Clearing balances... cannot scan wallet balances.');
                return;
            }
            debugger_1.default.log(`scan wallet balances: chain ${chain.type}:${chain.id}`);
            // Set a simple key for this run of decryptBalances, so we can return early if it changes
            // This will change if another decryptBalances is called for this chain, and we don't need multiple running at once
            const decryptingBalancesKey = (0, keys_utils_1.generateNaiveRandomHex)();
            this.decryptBalancesKeyForChain.set(null, chain, decryptingBalancesKey);
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            // Fetch wallet details and latest tree.
            const [walletDetails, latestTree] = await Promise.all([
                this.getWalletDetails(txidVersion, chain),
                utxoMerkletree.latestTree(),
            ]);
            // Fill list of tree heights with 0s up to # of trees
            while (walletDetails.treeScannedHeights.length <= latestTree) {
                walletDetails.treeScannedHeights.push(0);
            }
            if (this.creationBlockNumbers &&
                this.creationBlockNumbers[chain.type] != null &&
                this.creationBlockNumbers[chain.type][chain.id] != null &&
                (walletDetails.creationTree == null || walletDetails.creationTreeHeight == null)) {
                const creationBlockNumber = this.creationBlockNumbers[chain.type][chain.id];
                const creationTreeInfo = await AbstractWallet.getCreationTreeAndPosition(utxoMerkletree, latestTree, creationBlockNumber);
                if (creationTreeInfo != null) {
                    walletDetails.creationTree = creationTreeInfo.tree;
                    walletDetails.creationTreeHeight = creationTreeInfo.position;
                }
            }
            const startScanTree = walletDetails.creationTree ?? 0;
            const treesToScan = latestTree - startScanTree + 1;
            // Loop through each tree and scan
            for (let treeIndex = startScanTree; treeIndex <= latestTree; treeIndex += 1) {
                // Get scanned height
                let startScanHeight = walletDetails.treeScannedHeights[treeIndex];
                // If creationTreeHeight exists, check if it is higher than default startScanHeight and start there if needed
                if (treeIndex === walletDetails.creationTree &&
                    (0, is_defined_1.isDefined)(walletDetails.creationTreeHeight)) {
                    startScanHeight = Math.max(walletDetails.creationTreeHeight, startScanHeight);
                }
                // Create sparse array of tree
                const treeHeight = await utxoMerkletree.getTreeLength(treeIndex);
                const batchSize = merkletree_types_1.CommitmentProcessingGroupSize.XXLarge;
                const totalLeavesToScan = treeHeight - startScanHeight;
                const totalBatches = Math.ceil(totalLeavesToScan / batchSize);
                for (let batchIndex = 0; batchIndex < totalBatches; batchIndex += 1) {
                    const batchStart = startScanHeight + batchIndex * batchSize;
                    const batchEnd = Math.min(batchStart + batchSize, treeHeight);
                    const leaves = await utxoMerkletree.getCommitmentRange(treeIndex, batchStart, batchEnd - 1);
                    const finishedTreeCount = treeIndex - startScanTree;
                    const finishedTreesProgress = finishedTreeCount / treesToScan;
                    const afterFetchLeavesProgress = 0.5; // After Promise.all to get leaves, say we are 50% done with this batch.
                    let newTreeProgress = (batchIndex + afterFetchLeavesProgress) / totalBatches / treesToScan;
                    if (progressCallback) {
                        progressCallback(finishedTreesProgress + newTreeProgress);
                    }
                    await this.scanLeaves(txidVersion, leaves, treeIndex, chain, batchStart, undefined);
                    const afterScanLeavesProgress = 1.0;
                    newTreeProgress = (batchIndex + afterScanLeavesProgress) / totalBatches / treesToScan;
                    if (progressCallback) {
                        progressCallback(finishedTreesProgress + newTreeProgress);
                    }
                    if (this.decryptBalancesKeyForChain.get(null, chain) !== decryptingBalancesKey) {
                        // Key changed because some other decryptBalances run has started.
                        // No need to run multiple decrypt balances at once, return early.
                        debugger_1.default.log(`wallet: decryptBalances key changed, returning early. ${chain.type}:${chain.id}`);
                        return;
                    }
                    // Commit new scanned height
                    const walletDetailsMap = await this.getWalletDetailsMap(chain);
                    walletDetails.treeScannedHeights[treeIndex] = batchEnd;
                    walletDetailsMap[txidVersion] = walletDetails;
                    // Write new wallet details to db
                    await this.db.put(this.getWalletDetailsPath(chain), msgpack_lite_1.default.encode(walletDetailsMap));
                }
            }
            // Reset decryptBalancesKeyForChain
            this.decryptBalancesKeyForChain.del(null, chain);
            // Emit scanned event for this chain
            debugger_1.default.log(`wallet: scanned ${chain.type}:${chain.id}`);
            if (!deferCompletionEvent) {
                const walletScannedEventData = { txidVersion, chain };
                this.emit(event_types_1.EngineEvent.WalletDecryptBalancesComplete, walletScannedEventData);
            }
        }
        catch (err) {
            // Reset decryptBalancesKeyForChain
            this.decryptBalancesKeyForChain.del(null, chain);
            if (err instanceof Error) {
                debugger_1.default.log(`wallet.scan error: ${err.message}`);
                debugger_1.default.error(err, true /* ignoreInTests */);
            }
        }
    }
    /**
     * Searches for creation tree height for given merkletree based on creationBlockNumber.
     * Will return the latest position that is <= creationBlockNumber. May return an index that has blockNumber < creationBlockNumber,
     * but that is okay for purposes of creationTreeHeight. We just need to guarantee we don't return a position that misses some commitments in the creation block.
     * @param merkletree - Merkletree
     * @param latestTree - number
     */
    static async getCreationTreeAndPosition(utxoMerkletree, latestTree, creationBlockNumber) {
        if (!(0, is_defined_1.isDefined)(creationBlockNumber)) {
            return undefined;
        }
        // Loop through each tree, descending, and search commitments for creation tree height <= block number
        for (let tree = latestTree; tree > -1; tree -= 1) {
            const treeHeight = await utxoMerkletree.getTreeLength(tree);
            const batchSize = 2000;
            const totalBatches = Math.ceil(treeHeight / batchSize);
            let earliestCommitmentIndex; // Store the earliest commitment index found for this tree with <= creationBlockNumber.
            let creationBlockIndexBlockNumber = 0; // Store the blockNumber of the earliest commitment index found for this tree with <= creationBlockNumber.
            for (let batchIndex = 0; batchIndex < totalBatches; batchIndex += 1) {
                // Start batches at the end of the tree and work backwards
                const batchStart = Math.max(0, treeHeight - (batchIndex + 1) * batchSize);
                const batchEnd = treeHeight - batchIndex * batchSize;
                const leaves = await utxoMerkletree.getCommitmentRange(tree, batchStart, batchEnd - 1);
                if (!(0, is_defined_1.isDefined)(earliestCommitmentIndex)) {
                    // Search through leaves (descending) for first blockNumber before creation.
                    // Do this linearly, as we don't expect many commitments in a single block.
                    for (let index = batchEnd - 1; index >= batchStart; index -= 1) {
                        const commitment = leaves[index - batchStart];
                        if ((0, is_defined_1.isDefined)(commitment?.blockNumber)) {
                            if (commitment.blockNumber <= creationBlockNumber) {
                                earliestCommitmentIndex = index;
                                creationBlockIndexBlockNumber = commitment.blockNumber;
                                break;
                            }
                        }
                    }
                }
                if ((0, is_defined_1.isDefined)(earliestCommitmentIndex)) {
                    // Check if any commitments earlier in the leaves array are also equal to creationBlockIndex's blockNumber.
                    // This can happen if there are multiple commitments in the same block.
                    // If so, return the earliest one.
                    for (let index = earliestCommitmentIndex - 1; index > -1; index -= 1) {
                        if (index < batchStart) {
                            // We've gone too far, stop.
                            break;
                        }
                        const commitment = leaves[index];
                        if ((0, is_defined_1.isDefined)(commitment?.blockNumber)) {
                            if (commitment.blockNumber === creationBlockIndexBlockNumber) {
                                earliestCommitmentIndex = index;
                            }
                            else if (commitment.blockNumber < creationBlockIndexBlockNumber) {
                                // We've gone too far, stop.
                                break;
                            }
                        }
                    }
                    if (earliestCommitmentIndex > batchStart) {
                        return { tree, position: earliestCommitmentIndex };
                    }
                }
            }
        }
        return undefined;
    }
    /**
     * @warning This method is ONLY intended for testing purposes.
     */
    testSpecificSetCreationBlockNumbers(creationBlockNumbers) {
        this.creationBlockNumbers = creationBlockNumbers;
    }
    /**
     * Clears balances decrypted from merkletrees and stored to database.
     * @param chain - chain type/id to clear
     */
    async clearDecryptedBalancesAllTXIDVersions(chain) {
        const walletDetailsMap = await this.getWalletDetailsMap(chain);
        // Clear wallet namespace, including decrypted TXOs and all details
        const namespace = this.getWalletDBPrefix(chain);
        this.isClearingBalances.set(null, chain, true);
        await this.db.clearNamespace(namespace);
        this.isClearingBalances.set(null, chain, false);
        for (const txidVersion of Object.values(poi_types_1.TXIDVersion)) {
            if (walletDetailsMap[txidVersion]) {
                // @ts-expect-error
                walletDetailsMap[txidVersion].treeScannedHeights = [];
            }
        }
        await this.db.put(this.getWalletDetailsPath(chain), msgpack_lite_1.default.encode(walletDetailsMap));
        this.invalidateCommitmentsCache(chain);
    }
    /** Clears balances for one TXID version without removing sibling-version data. */
    async clearDecryptedBalances(txidVersion, chain) {
        this.isClearingBalances.set(null, chain, true);
        try {
            const [walletDetailsMap, receivedCommitments, sentCommitments] = await Promise.all([
                this.getWalletDetailsMap(chain),
                this.queryAllStoredReceiveCommitments(txidVersion, chain),
                this.queryAllStoredSendCommitments(txidVersion, chain),
            ]);
            const deleteBatch = [
                ...receivedCommitments.map(({ tree, position }) => ({
                    type: 'del',
                    key: this.getWalletReceiveCommitmentDBPrefix(chain, tree, position).join(':'),
                })),
                ...sentCommitments.map(({ tree, position }) => ({
                    type: 'del',
                    key: this.getWalletSentCommitmentDBPrefix(chain, tree, position).join(':'),
                })),
            ];
            await this.db.batch(deleteBatch);
            const walletDetails = walletDetailsMap[txidVersion];
            if ((0, is_defined_1.isDefined)(walletDetails)) {
                walletDetails.treeScannedHeights = [];
                walletDetails.creationTree = undefined;
                walletDetails.creationTreeHeight = undefined;
                await this.db.put(this.getWalletDetailsPath(chain), msgpack_lite_1.default.encode(walletDetailsMap));
            }
            this.receiveCommitmentsCache.del(txidVersion, chain);
            this.sentCommitmentsCache.del(txidVersion, chain);
        }
        finally {
            this.isClearingBalances.set(null, chain, false);
        }
    }
    /**
     * Clears stored balances and re-decrypts fully.
     * @param chain - chain type/id to rescan
     */
    async fullRedecryptBalancesAllTXIDVersions(chain, progressCallback) {
        await this.clearDecryptedBalancesAllTXIDVersions(chain);
        for (const txidVersion of Object.values(poi_types_1.TXIDVersion)) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            await this.decryptBalances(txidVersion, chain, progressCallback, false);
        }
    }
    static dbPath(id) {
        return [(0, bytes_1.fromUTF8String)('wallet'), id];
    }
    static async read(db, id, encryptionKey) {
        return msgpack_lite_1.default.decode(bytes_1.ByteUtils.fastHexToBytes(await db.getEncrypted(AbstractWallet.dbPath(id), encryptionKey)));
    }
    static async write(db, id, encryptionKey, data) {
        await db.putEncrypted(AbstractWallet.dbPath(id), encryptionKey, msgpack_lite_1.default.encode(data));
    }
    static async delete(db, id) {
        return db.del(AbstractWallet.dbPath(id));
    }
    /**
     * Loads encrypted wallet data from database.
     * @param db - database
     * @param encryptionKey - encryption key to use with database
     * @param id - wallet id
     */
    static async getEncryptedData(db, encryptionKey, id) {
        return msgpack_lite_1.default.decode(bytes_1.ByteUtils.fastHexToBytes(await db.getEncrypted([(0, bytes_1.fromUTF8String)('wallet'), id], encryptionKey)));
    }
    static getKeysFromShareableViewingKey(shareableViewingKey) {
        try {
            const { vpriv: viewingPrivateKey, spub: spendingPublicKeyString } = msgpack_lite_1.default.decode(Buffer.from(shareableViewingKey, 'hex'));
            const spendingPublicKey = babyjubjub_1.Babyjubjub.unpackPoint(Buffer.from(spendingPublicKeyString, 'hex'));
            return { viewingPrivateKey, spendingPublicKey };
        }
        catch (cause) {
            throw new Error('Invalid shareable private key.', { cause });
        }
    }
    generateShareableViewingKey() {
        const spendingPublicKeyString = babyjubjub_1.Babyjubjub.packPoint(this.spendingPublicKey).toString('hex');
        const data = {
            vpriv: bytes_1.ByteUtils.formatToByteLength(this.viewingKeyPair.privateKey, bytes_1.ByteLength.UINT_256),
            spub: spendingPublicKeyString,
        };
        return msgpack_lite_1.default.encode(data).toString('hex');
    }
}
exports.AbstractWallet = AbstractWallet;
//# sourceMappingURL=abstract-wallet.js.map