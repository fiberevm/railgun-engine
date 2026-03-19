"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractNPKFromCommitmentCiphertextV3 = exports.extractRailgunTransactionDataFromTransactionRequestV3 = exports.extractFirstNoteERC20AmountMapFromTransactionRequestV3 = void 0;
const ethers_1 = require("ethers");
const is_defined_1 = require("../utils/is-defined");
const bytes_1 = require("../utils/bytes");
const ethers_2 = require("../utils/ethers");
const railgun_txid_1 = require("../transaction/railgun-txid");
const transact_note_1 = require("../note/transact-note");
const keys_utils_1 = require("../utils/keys-utils");
const poi_types_1 = require("../models/poi-types");
const abi_1 = require("../abi/abi");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const V3_events_1 = require("../contracts/railgun-smart-wallet/V3/V3-events");
const extract_transaction_data_v2_1 = require("./extract-transaction-data-v2");
const bound_params_1 = require("../transaction/bound-params");
var TransactionName;
(function (TransactionName) {
    TransactionName["Execute"] = "execute";
})(TransactionName || (TransactionName = {}));
const getABIForTransaction = (transactionName) => {
    switch (transactionName) {
        case TransactionName.Execute:
            return abi_1.ABIPoseidonMerkleVerifier;
    }
    throw new Error('Unsupported transactionName');
};
const extractFirstNoteERC20AmountMapFromTransactionRequestV3 = (chain, transactionRequest, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const transactionName = TransactionName.Execute;
    return extractFirstNoteERC20AmountMapV3(chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
};
exports.extractFirstNoteERC20AmountMapFromTransactionRequestV3 = extractFirstNoteERC20AmountMapFromTransactionRequestV3;
const extractRailgunTransactionDataFromTransactionRequestV3 = (chain, transactionRequest, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const transactionName = TransactionName.Execute;
    return extractRailgunTransactionDataV3(chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
};
exports.extractRailgunTransactionDataFromTransactionRequestV3 = extractRailgunTransactionDataFromTransactionRequestV3;
const getRailgunTransactionRequestsV3 = (chain, transactionRequest, transactionName, contractAddress) => {
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
    const railgunTxs = 
    // eslint-disable-next-line no-underscore-dangle
    args._transactions;
    for (const railgunTx of railgunTxs) {
        if (!('length' in railgunTx.boundParams.commitmentCiphertext)) {
            // 'commitmentCiphertext' is potentially parsed as an object.
            railgunTx.boundParams.commitmentCiphertext = [];
        }
    }
    const globalBoundParams = 
    // eslint-disable-next-line no-underscore-dangle
    args._globalBoundParams;
    return { railgunTxs, globalBoundParams };
};
const extractFirstNoteERC20AmountMapV3 = async (chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const erc20PaymentAmounts = {};
    const { railgunTxs } = getRailgunTransactionRequestsV3(chain, transactionRequest, transactionName, contractAddress);
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
        const commitmentCiphertext = V3_events_1.V3Events.formatCommitmentCiphertext(commitmentCiphertextStructOutput);
        const decryptedReceiverNote = await decryptReceiverNoteSafeV3(chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter, index);
        const erc20PaymentAmount = await (0, extract_transaction_data_v2_1.extractERC20AmountFromTransactNote)(decryptedReceiverNote, commitmentHash, receivingRailgunAddressData);
        if (!erc20PaymentAmount) {
            return;
        }
        const { tokenAddress, amount } = erc20PaymentAmount;
        erc20PaymentAmounts[tokenAddress] ??= 0n;
        erc20PaymentAmounts[tokenAddress] += amount;
    }));
    return erc20PaymentAmounts;
};
const extractRailgunTransactionDataV3 = async (chain, transactionRequest, transactionName, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const { railgunTxs, globalBoundParams } = getRailgunTransactionRequestsV3(chain, transactionRequest, transactionName, contractAddress);
    const extractedRailgunTransactionData = await Promise.all(railgunTxs.map(async (railgunTx, railgunTxIndex) => {
        const { commitments, nullifiers, boundParams } = railgunTx;
        const boundParamsHash = bytes_1.ByteUtils.nToHex((0, bound_params_1.hashBoundParamsV3)({
            global: globalBoundParams,
            local: boundParams,
        }), bytes_1.ByteLength.UINT_256, true);
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
        const commitmentCiphertext = V3_events_1.V3Events.formatCommitmentCiphertext(commitmentCiphertextStructOutput);
        // Get NPK for first note, if addressed to current wallet.
        const firstCommitmentNotePublicKey = await (0, exports.extractNPKFromCommitmentCiphertextV3)(chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
        return {
            railgunTxid,
            utxoTreeIn: boundParams.treeNumber,
            firstCommitmentNotePublicKey,
            firstCommitment: commitments[0],
        };
    }));
    return extractedRailgunTransactionData;
};
const extractNPKFromCommitmentCiphertextV3 = async (chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    const decryptedReceiverNote = await decryptReceiverNoteSafeV3(chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter, 0);
    return decryptedReceiverNote?.notePublicKey;
};
exports.extractNPKFromCommitmentCiphertextV3 = extractNPKFromCommitmentCiphertextV3;
const decryptReceiverNoteSafeV3 = async (chain, commitmentCiphertext, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter, transactCommitmentBatchIndexV3) => {
    try {
        const blindedSenderViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitmentCiphertext.blindedSenderViewingKey);
        const blindedReceiverViewingKey = bytes_1.ByteUtils.hexStringToBytes(commitmentCiphertext.blindedReceiverViewingKey);
        const sharedKey = await (0, keys_utils_1.getSharedSymmetricKey)(receivingViewingPrivateKey, blindedSenderViewingKey);
        if (!sharedKey) {
            debugger_1.default.log('invalid sharedKey');
            return undefined;
        }
        const note = await transact_note_1.TransactNote.decrypt(poi_types_1.TXIDVersion.V3_PoseidonMerkle, chain, receivingRailgunAddressData, commitmentCiphertext.ciphertext, sharedKey, '', // memoV2
        '', // annotationData - not used
        blindedReceiverViewingKey, // blindedReceiverViewingKey
        blindedSenderViewingKey, // blindedSenderViewingKey
        undefined, // senderRandom - not used
        false, // isSentNote
        false, // isLegacyDecryption
        tokenDataGetter, undefined, // blockNumber - not used
        transactCommitmentBatchIndexV3);
        return note;
    }
    catch (cause) {
        debugger_1.default.error(new Error('Failed to decrypt receiver note safe V3', { cause }));
        return undefined;
    }
};
//# sourceMappingURL=extract-transaction-data-v3.js.map