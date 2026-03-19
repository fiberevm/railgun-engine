"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = void 0;
const prover_1 = require("../prover/prover");
const bytes_1 = require("../utils/bytes");
const formatted_types_1 = require("../models/formatted-types");
const transaction_constants_1 = require("../models/transaction-constants");
const keys_utils_1 = require("../utils/keys-utils");
const transact_note_1 = require("../note/transact-note");
const bound_params_1 = require("./bound-params");
const chain_1 = require("../chain/chain");
const unshield_note_erc20_1 = require("../note/erc20/unshield-note-erc20");
const unshield_note_nft_1 = require("../note/nft/unshield-note-nft");
const note_1 = require("../note");
const is_defined_1 = require("../utils/is-defined");
const poi_types_1 = require("../models/poi-types");
class Transaction {
    adaptID;
    chain;
    tokenOutputs = [];
    unshieldNote = unshield_note_erc20_1.UnshieldNoteERC20.empty();
    unshieldFlag = transaction_constants_1.UnshieldFlag.NO_UNSHIELD;
    tokenData;
    tokenHash;
    spendingTree;
    utxos;
    /**
     * Create ERC20Transaction Object
     * @param tokenAddress - token address, unformatted
     * @param tokenType - enum of token type
     * @param chain - chain type/id of network
     * @param spendingTree - tree index to spend from
     * @param utxos - UTXOs to spend from
     */
    constructor(chain, tokenData, spendingTree, utxos, tokenOutputs, adaptID) {
        if (tokenOutputs.length > 5) {
            throw new Error('Can not add more than 5 outputs.');
        }
        this.chain = chain;
        this.tokenData = tokenData;
        this.tokenHash = (0, note_1.getTokenDataHash)(tokenData);
        this.spendingTree = spendingTree;
        this.utxos = utxos;
        this.tokenOutputs = tokenOutputs;
        this.adaptID = adaptID;
    }
    addUnshieldData(unshieldData, unshieldValue) {
        if (this.unshieldFlag !== transaction_constants_1.UnshieldFlag.NO_UNSHIELD) {
            throw new Error('You may only call .unshield once for a given transaction.');
        }
        const tokenHashUnshield = (0, note_1.getTokenDataHash)(unshieldData.tokenData);
        if (tokenHashUnshield !== this.tokenHash) {
            throw new Error('Unshield token does not match Transaction token.');
        }
        const { tokenData, allowOverride } = unshieldData;
        const { tokenAddress, tokenType, tokenSubID } = tokenData;
        switch (tokenType) {
            case formatted_types_1.TokenType.ERC20:
                this.unshieldNote = new unshield_note_erc20_1.UnshieldNoteERC20(unshieldData.toAddress, unshieldValue, tokenAddress, allowOverride);
                break;
            case formatted_types_1.TokenType.ERC721:
            case formatted_types_1.TokenType.ERC1155: {
                const nftTokenData = {
                    tokenAddress,
                    tokenType,
                    tokenSubID,
                };
                this.unshieldNote = new unshield_note_nft_1.UnshieldNoteNFT(unshieldData.toAddress, nftTokenData, allowOverride);
                break;
            }
        }
        this.unshieldFlag =
            (0, is_defined_1.isDefined)(allowOverride) && allowOverride ? transaction_constants_1.UnshieldFlag.OVERRIDE : transaction_constants_1.UnshieldFlag.UNSHIELD;
    }
    get unshieldValue() {
        return (0, is_defined_1.isDefined)(this.unshieldNote) ? this.unshieldNote.value : BigInt(0);
    }
    /**
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key of wallet
     */
    async generateTransactionRequest(wallet, txidVersion, encryptionKey, globalBoundParams) {
        const merkletree = wallet.getUTXOMerkletree(txidVersion, this.chain);
        const merkleRoot = await merkletree.getRoot(this.spendingTree);
        const spendingKey = await wallet.getSpendingKeyPair(encryptionKey);
        const nullifyingKey = wallet.getNullifyingKey();
        const senderViewingKeys = wallet.getViewingKeyPair();
        // Get values
        const nullifiers = [];
        const pathElements = [];
        const pathIndices = [];
        const { utxos } = this;
        for (const utxo of utxos) {
            // Push spending key and nullifier
            nullifiers.push(transact_note_1.TransactNote.getNullifier(nullifyingKey, utxo.position));
            // Push path elements
            // eslint-disable-next-line no-await-in-loop
            const merkleProof = await merkletree.getMerkleProof(this.spendingTree, utxo.position);
            pathElements.push(merkleProof.elements.map((element) => bytes_1.ByteUtils.hexToBigInt(element)));
            // Push path indices
            pathIndices.push(BigInt(utxo.position));
        }
        const allOutputs = [...this.tokenOutputs];
        // Push unshield output if unshield is requested
        const hasUnshield = this.unshieldFlag !== transaction_constants_1.UnshieldFlag.NO_UNSHIELD && (0, is_defined_1.isDefined)(this.unshieldNote);
        if (hasUnshield) {
            allOutputs.push(this.unshieldNote);
        }
        if (allOutputs.length > 5) {
            // TODO: Support circuits 1x10 and 1x13.
            throw new Error('Cannot create a transaction with >5 outputs.');
        }
        const onlyInternalOutputs = allOutputs.filter((note) => note instanceof transact_note_1.TransactNote);
        const noteBlindedKeys = await Promise.all(onlyInternalOutputs.map((note) => {
            if (!(0, is_defined_1.isDefined)(note.senderRandom)) {
                throw new Error('Sender random is not defined for transact note.');
            }
            return (0, keys_utils_1.getNoteBlindingKeys)(senderViewingKeys.pubkey, note.receiverAddressData.viewingPublicKey, note.random, note.senderRandom);
        }));
        // Calculate shared keys using sender privateKey and recipient blinding key.
        const sharedKeys = await Promise.all(noteBlindedKeys.map(({ blindedReceiverViewingKey }) => (0, keys_utils_1.getSharedSymmetricKey)(senderViewingKeys.privateKey, blindedReceiverViewingKey)));
        const privateInputs = {
            tokenAddress: bytes_1.ByteUtils.hexToBigInt(this.tokenHash),
            randomIn: utxos.map((utxo) => bytes_1.ByteUtils.hexToBigInt(utxo.note.random)),
            valueIn: utxos.map((utxo) => utxo.note.value),
            pathElements,
            leavesIndices: pathIndices,
            valueOut: allOutputs.map((note) => note.value),
            publicKey: spendingKey.pubkey,
            npkOut: allOutputs.map((x) => x.notePublicKey),
            nullifyingKey,
        };
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const commitmentCiphertext = onlyInternalOutputs.map((note, index) => {
                    const sharedKey = sharedKeys[index];
                    if (!sharedKey) {
                        throw new Error('Shared symmetric key is not defined.');
                    }
                    const { noteCiphertext, noteMemo, annotationData } = note.encryptV2(txidVersion, sharedKey, wallet.addressKeys.masterPublicKey, note.senderRandom, wallet.viewingKeyPair.privateKey);
                    if (noteCiphertext.data.length !== 3) {
                        throw new Error('Note ciphertext data must have length 3.');
                    }
                    const ciphertext = [
                        bytes_1.ByteUtils.hexlify(`${noteCiphertext.iv}${noteCiphertext.tag}`, true),
                        bytes_1.ByteUtils.hexlify(noteCiphertext.data[0], true),
                        bytes_1.ByteUtils.hexlify(noteCiphertext.data[1], true),
                        bytes_1.ByteUtils.hexlify(noteCiphertext.data[2], true),
                    ];
                    return {
                        ciphertext,
                        blindedSenderViewingKey: bytes_1.ByteUtils.hexlify(noteBlindedKeys[index].blindedSenderViewingKey, true),
                        blindedReceiverViewingKey: bytes_1.ByteUtils.hexlify(noteBlindedKeys[index].blindedReceiverViewingKey, true),
                        memo: bytes_1.ByteUtils.hexlify(noteMemo, true),
                        annotationData: bytes_1.ByteUtils.hexlify(annotationData, true),
                    };
                });
                const boundParams = {
                    treeNumber: this.spendingTree,
                    minGasPrice: globalBoundParams.minGasPrice,
                    unshield: this.unshieldFlag,
                    chainID: bytes_1.ByteUtils.hexlify((0, chain_1.getChainFullNetworkID)(this.chain), true),
                    adaptContract: this.adaptID.contract,
                    adaptParams: this.adaptID.parameters,
                    commitmentCiphertext,
                };
                const publicInputs = {
                    merkleRoot: bytes_1.ByteUtils.hexToBigInt(merkleRoot),
                    boundParamsHash: (0, bound_params_1.hashBoundParamsV2)(boundParams),
                    nullifiers,
                    commitmentsOut: allOutputs.map((note) => note.hash),
                };
                const railgunTransactionRequest = {
                    txidVersion,
                    privateInputs,
                    publicInputs,
                    boundParams,
                };
                return railgunTransactionRequest;
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const commitmentCiphertext = onlyInternalOutputs.map((note, index) => {
                    const sharedKey = sharedKeys[index];
                    if (!sharedKey) {
                        throw new Error('Shared symmetric key is not defined.');
                    }
                    if (!(0, is_defined_1.isDefined)(note.senderRandom)) {
                        throw new Error('Note must have senderRandom for V3 encryption');
                    }
                    const noteCiphertext = note.encryptV3(txidVersion, sharedKey, wallet.addressKeys.masterPublicKey);
                    const ciphertext = bytes_1.ByteUtils.prefix0x(`${noteCiphertext.nonce}${noteCiphertext.bundle}`);
                    return {
                        ciphertext,
                        blindedSenderViewingKey: bytes_1.ByteUtils.formatToByteLength(noteBlindedKeys[index].blindedSenderViewingKey, bytes_1.ByteLength.UINT_256, true),
                        blindedReceiverViewingKey: bytes_1.ByteUtils.formatToByteLength(noteBlindedKeys[index].blindedReceiverViewingKey, bytes_1.ByteLength.UINT_256, true),
                    };
                });
                const boundParams = {
                    local: {
                        treeNumber: this.spendingTree,
                        commitmentCiphertext,
                    },
                    global: globalBoundParams,
                };
                const publicInputs = {
                    merkleRoot: bytes_1.ByteUtils.hexToBigInt(merkleRoot),
                    boundParamsHash: (0, bound_params_1.hashBoundParamsV3)(boundParams),
                    nullifiers,
                    commitmentsOut: allOutputs.map((note) => note.hash),
                };
                const railgunTransactionRequest = {
                    txidVersion,
                    privateInputs,
                    publicInputs,
                    boundParams,
                };
                return railgunTransactionRequest;
            }
        }
        throw new Error('Invalid txidVersion.');
    }
    /**
     * Generate proof and return serialized transaction
     * @param prover - prover to use
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    async generateProvedTransaction(txidVersion, prover, unprovedTransactionInputs, progressCallback) {
        const { publicInputs, privateInputs, boundParams } = unprovedTransactionInputs;
        Transaction.assertCanProve(privateInputs);
        const { proof } = await prover.proveRailgun(txidVersion, unprovedTransactionInputs, progressCallback);
        switch (unprovedTransactionInputs.txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return Transaction.createTransactionStructV2(unprovedTransactionInputs.txidVersion, proof, publicInputs, boundParams, this.unshieldNote.preImage);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return Transaction.createTransactionStructV3(unprovedTransactionInputs.txidVersion, proof, publicInputs, boundParams, this.unshieldNote.preImage);
            }
        }
        throw new Error('Invalid txidVersion.');
    }
    /**
     * Return serialized transaction with zero'd proof for gas estimates.
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    async generateDummyProvedTransaction(prover, transactionRequest) {
        const { publicInputs, boundParams } = transactionRequest;
        const dummyProof = prover.dummyProveRailgun(publicInputs);
        switch (transactionRequest.txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return Transaction.createTransactionStructV2(transactionRequest.txidVersion, dummyProof, publicInputs, boundParams, this.unshieldNote.preImage);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return Transaction.createTransactionStructV3(transactionRequest.txidVersion, dummyProof, publicInputs, boundParams, this.unshieldNote.preImage);
            }
        }
        throw new Error('Invalid txidVersion.');
    }
    static assertCanProve(privateInputs) {
        if (privateInputs.valueIn.length === 1 &&
            privateInputs.valueOut.length === 1 &&
            privateInputs.valueIn[0] === 0n &&
            privateInputs.valueOut[0] === 0n) {
            throw new Error('Cannot prove transaction with null (zero value) inputs and outputs.');
        }
    }
    static createTransactionStructV2(txidVersion, proof, publicInputs, boundParams, unshieldPreimage) {
        return {
            txidVersion,
            proof: prover_1.Prover.formatProof(proof),
            merkleRoot: bytes_1.ByteUtils.nToHex(publicInputs.merkleRoot, bytes_1.ByteLength.UINT_256, true),
            nullifiers: publicInputs.nullifiers.map((n) => bytes_1.ByteUtils.nToHex(n, bytes_1.ByteLength.UINT_256, true)),
            boundParams,
            commitments: publicInputs.commitmentsOut.map((n) => bytes_1.ByteUtils.nToHex(n, bytes_1.ByteLength.UINT_256, true)),
            unshieldPreimage: {
                npk: bytes_1.ByteUtils.formatToByteLength(unshieldPreimage.npk, bytes_1.ByteLength.UINT_256, true),
                token: unshieldPreimage.token,
                value: unshieldPreimage.value,
            },
        };
    }
    static createTransactionStructV3(txidVersion, proof, publicInputs, boundParams, unshieldPreimage) {
        return {
            txidVersion,
            proof: prover_1.Prover.formatProof(proof),
            merkleRoot: bytes_1.ByteUtils.nToHex(publicInputs.merkleRoot, bytes_1.ByteLength.UINT_256, true),
            nullifiers: publicInputs.nullifiers.map((n) => bytes_1.ByteUtils.nToHex(n, bytes_1.ByteLength.UINT_256, true)),
            boundParams,
            commitments: publicInputs.commitmentsOut.map((n) => bytes_1.ByteUtils.nToHex(n, bytes_1.ByteLength.UINT_256, true)),
            unshieldPreimage: {
                npk: bytes_1.ByteUtils.formatToByteLength(unshieldPreimage.npk, bytes_1.ByteLength.UINT_256, true),
                token: unshieldPreimage.token,
                value: unshieldPreimage.value,
            },
        };
    }
    static getLocalBoundParams(transaction) {
        switch (transaction.txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle:
                return transaction.boundParams;
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle:
                return transaction.boundParams.local;
        }
        throw new Error('Invalid txidVersion.');
    }
}
exports.Transaction = Transaction;
//# sourceMappingURL=transaction.js.map