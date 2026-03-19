"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractERC20AmountFromTransactNote = exports.extractNPKFromCommitmentCiphertextV2 = exports.extractRailgunTransactionDataFromTransactionRequestV2 = exports.extractFirstNoteERC20AmountMapFromTransactionRequestV2 = void 0;
const ethers_1 = require("ethers");
const abi_1 = require("../abi/abi");
const is_defined_1 = require("../utils/is-defined");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const V2_events_1 = require("../contracts/railgun-smart-wallet/V2/V2-events");
const bytes_1 = require("../utils/bytes");
const formatted_types_1 = require("../models/formatted-types");
const ethers_2 = require("../utils/ethers");
const bound_params_1 = require("../transaction/bound-params");
const railgun_txid_1 = require("../transaction/railgun-txid");
const transact_note_1 = require("../note/transact-note");
const keys_utils_1 = require("../utils/keys-utils");
const poi_types_1 = require("../models/poi-types");
var TransactionName;
(function (TransactionName) {
    TransactionName["RailgunSmartWallet"] = "transact";
    TransactionName["RelayAdapt"] = "relay";
})(TransactionName || (TransactionName = {}));
const getABIForTransaction = (transactionName) => {
    switch (transactionName) {
        case TransactionName.RailgunSmartWallet:
            return abi_1.ABIRailgunSmartWallet;
        case TransactionName.RelayAdapt:
            return abi_1.ABIRelayAdapt;
    }
    throw new Error('Unsupported transactionName');
};
const extractFirstNoteERC20AmountMapFromTransactionRequestV2 = (chain, transactionRequest, useRelayAdapt, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const transactionName = useRelayAdapt
        ? TransactionName.RelayAdapt
        : TransactionName.RailgunSmartWallet;
    return extractFirstNoteERC20AmountMapV2(chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
};
exports.extractFirstNoteERC20AmountMapFromTransactionRequestV2 = extractFirstNoteERC20AmountMapFromTransactionRequestV2;
const extractRailgunTransactionDataFromTransactionRequestV2 = (chain, transactionRequest, useRelayAdapt, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const transactionName = useRelayAdapt
        ? TransactionName.RelayAdapt
        : TransactionName.RailgunSmartWallet;
    return extractRailgunTransactionDataV2(chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
};
exports.extractRailgunTransactionDataFromTransactionRequestV2 = extractRailgunTransactionDataFromTransactionRequestV2;
const getRailgunTransactionRequestsV2 = (chain, transactionRequest, transactionName, contractAddress) => {
    const abi = getABIForTransaction(transactionName);
    if (!transactionRequest.to ||
        transactionRequest.to.toLowerCase() !== contractAddress.toLowerCase()) {
        throw new Error(`Invalid contract address: got ${transactionRequest.to}, expected ${contractAddress} for network ${chain.type}:${chain.id}`);
    }
    const contract = new ethers_1.Contract(contractAddress, abi);
    const parsedTransaction = contract.interface.parseTransaction({
        data: transactionRequest.data ?? '',
        value: transactionRequest.value,
    });
    if (!parsedTransaction) {
        throw new Error('No transaction parsable from request');
    }
    if (parsedTransaction.name !== transactionName) {
        throw new Error(`Contract method ${parsedTransaction.name} invalid: expected ${transactionName}`);
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const args = (0, ethers_2.recursivelyDecodeResult)(parsedTransaction.args);
    // eslint-disable-next-line no-underscore-dangle
    const railgunTxs = args._transactions;
    for (const railgunTx of railgunTxs) {
        if (!('length' in railgunTx.boundParams.commitmentCiphertext)) {
            // 'commitmentCiphertext' is potentially parsed as an object.
            railgunTx.boundParams.commitmentCiphertext = [];
        }
    }
    return railgunTxs;
};
const extractFirstNoteERC20AmountMapV2 = async (chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const erc20PaymentAmounts = {};
    const railgunTxs = getRailgunTransactionRequestsV2(chain, transactionRequest, transactionName, contractAddress);
    await Promise.all(railgunTxs.map(async (railgunTx) => {
        const { commitments, boundParams } = railgunTx;
        // Extract first commitment (index 0)
        const index = 0;
        const commitmentCiphertextStructOutput = boundParams.commitmentCiphertext[index];
        const commitmentHash = commitments[index];
        if (!(0, is_defined_1.isDefined)(commitmentCiphertextStructOutput)) {
            debugger_1.default.log('no ciphertext found for commitment at index 0');
            return;
        }
        const commitmentCiphertext = V2_events_1.V2Events.formatCommitmentCiphertext(commitmentCiphertextStructOutput);
        const decryptedReceiverNote = await decryptReceiverNoteSafeV2(chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
        const erc20PaymentAmount = await (0, exports.extractERC20AmountFromTransactNote)(decryptedReceiverNote, commitmentHash, receivingRailgunAddressData);
        if (!(0, is_defined_1.isDefined)(erc20PaymentAmount)) {
            return;
        }
        const { tokenAddress, amount } = erc20PaymentAmount;
        erc20PaymentAmounts[tokenAddress] ??= 0n;
        erc20PaymentAmounts[tokenAddress] += amount;
    }));
    return erc20PaymentAmounts;
};
const extractRailgunTransactionDataV2 = async (chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const railgunTxs = getRailgunTransactionRequestsV2(chain, transactionRequest, transactionName, contractAddress);
    const extractedRailgunTransactionData = await Promise.all(railgunTxs.map(async (railgunTx, railgunTxIndex) => {
        const { commitments, nullifiers, boundParams } = railgunTx;
        const boundParamsHash = bytes_1.ByteUtils.nToHex((0, bound_params_1.hashBoundParamsV2)(boundParams), bytes_1.ByteLength.UINT_256, true);
        const railgunTxid = (0, railgun_txid_1.getRailgunTransactionIDHex)({
            nullifiers,
            commitments,
            boundParamsHash,
        });
        if (railgunTxIndex > 0) {
            return {
                railgunTxid,
                utxoTreeIn: boundParams.treeNumber,
                firstCommitmentNotePublicKey: undefined,
                firstCommitment: commitments[0],
            };
        }
        // Extract first commitment (index 0)
        const index = 0;
        const commitmentCiphertextStructOutput = boundParams.commitmentCiphertext[index];
        if (!(0, is_defined_1.isDefined)(commitmentCiphertextStructOutput)) {
            throw new Error('No ciphertext found for commitment at index 0');
        }
        const commitmentCiphertext = V2_events_1.V2Events.formatCommitmentCiphertext(commitmentCiphertextStructOutput);
        // Get NPK for first note, if addressed to current wallet.
        const firstCommitmentNotePublicKey = await (0, exports.extractNPKFromCommitmentCiphertextV2)(chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
        return {
            railgunTxid,
            utxoTreeIn: boundParams.treeNumber,
            firstCommitmentNotePublicKey,
            firstCommitment: commitments[0],
        };
    }));
    return extractedRailgunTransactionData;
};
const decryptReceiverNoteSafeV2 = async (chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    try {
        const blindedSenderViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitmentCiphertext.blindedSenderViewingKey);
        const blindedReceiverViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitmentCiphertext.blindedReceiverViewingKey);
        const sharedKey = await (0, keys_utils_1.getSharedSymmetricKey)(receivingViewingPrivateKey, blindedSenderViewingKey);
        if (!sharedKey) {
            debugger_1.default.log('invalid sharedKey');
            return undefined;
        }
        const note = await transact_note_1.TransactNote.decrypt(poi_types_1.TXIDVersion.V2_PoseidonMerkle, chain, receivingRailgunAddressData, commitmentCiphertext.ciphertext, sharedKey, commitmentCiphertext.memo, commitmentCiphertext.annotationData, blindedReceiverViewingKey, // blindedReceiverViewingKey
        blindedSenderViewingKey, // blindedSenderViewingKey
        undefined, // senderRandom - not used
        false, // isSentNote
        false, // isLegacyDecryption
        tokenDataGetter, undefined, // blockNumber - not used
        undefined);
        return note;
    }
    catch (cause) {
        const ignoreInTests = true;
        debugger_1.default.error(new Error('Failed to decrypt receiver note safe V2', { cause }), ignoreInTests);
        return undefined;
    }
};
const extractNPKFromCommitmentCiphertextV2 = async (chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const decryptedReceiverNote = await decryptReceiverNoteSafeV2(chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
    return decryptedReceiverNote?.notePublicKey;
};
exports.extractNPKFromCommitmentCiphertextV2 = extractNPKFromCommitmentCiphertextV2;
const extractERC20AmountFromTransactNote = async (decryptedReceiverNote, commitmentHash, receivingRailgunAddressData) => {
    if (!decryptedReceiverNote) {
        // Addressed to us, but different note than fee.
        debugger_1.default.log('invalid decryptedReceiverNote');
        return undefined;
    }
    if (decryptedReceiverNote.receiverAddressData.masterPublicKey !==
        receivingRailgunAddressData.masterPublicKey) {
        debugger_1.default.log('invalid masterPublicKey');
        return undefined;
    }
    const noteHash = bytes_1.ByteUtils.nToHex(decryptedReceiverNote.hash, bytes_1.ByteLength.UINT_256);
    const commitHash = bytes_1.ByteUtils.formatToByteLength(commitmentHash, bytes_1.ByteLength.UINT_256);
    if (noteHash !== commitHash) {
        debugger_1.default.log('invalid commitHash');
        return undefined;
    }
    const { tokenData } = decryptedReceiverNote;
    if (tokenData.tokenType !== formatted_types_1.TokenType.ERC20) {
        debugger_1.default.log('not an erc20');
        return undefined;
    }
    const tokenAddress = bytes_1.ByteUtils.formatToByteLength(tokenData.tokenAddress, bytes_1.ByteLength.Address, true).toLowerCase();
    const amount = decryptedReceiverNote.value;
    return {
        tokenAddress,
        amount,
    };
};
exports.extractERC20AmountFromTransactNote = extractERC20AmountFromTransactNote;
//# sourceMappingURL=extract-transaction-data-v2.js.map