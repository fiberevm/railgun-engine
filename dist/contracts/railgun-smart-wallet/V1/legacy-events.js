"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.processLegacyNullifierEvents = exports.processLegacyCommitmentBatchEvents = exports.processLegacyGeneratedCommitmentEvents = exports.formatLegacyNullifierEvents = exports.processCommitmentBatchEvents = exports.processGeneratedCommitmentEvents = exports.formatLegacyCommitmentBatchEvent = exports.formatLegacyCommitmentBatchCommitments = exports.formatLegacyGeneratedCommitmentBatchEvent = exports.formatLegacyGeneratedCommitmentBatchCommitments = void 0;
const formatted_types_1 = require("../../../models/formatted-types");
const note_util_1 = require("../../../note/note-util");
const utils_1 = require("../../../utils");
const debugger_1 = __importDefault(require("../../../debugger/debugger"));
function formatLegacyGeneratedCommitmentBatchCommitments(transactionHash, preImages, encryptedRandoms, blockNumber, utxoTree, utxoStartingIndex) {
    const randomFormatted = encryptedRandoms.map((encryptedRandom) => [
        utils_1.ByteUtils.nToHex(encryptedRandom[0], utils_1.ByteLength.UINT_256),
        utils_1.ByteUtils.nToHex(encryptedRandom[1], utils_1.ByteLength.UINT_128),
    ]);
    return preImages.map((commitmentPreImage, index) => {
        const npk = utils_1.ByteUtils.formatToByteLength(commitmentPreImage.npk.toString(), utils_1.ByteLength.UINT_256);
        const tokenData = (0, note_util_1.serializeTokenData)(commitmentPreImage.token.tokenAddress, commitmentPreImage.token.tokenType, commitmentPreImage.token.tokenSubID.toString());
        const { value } = commitmentPreImage;
        const preImage = (0, note_util_1.serializePreImage)(npk, tokenData, value);
        const noteHash = (0, note_util_1.getNoteHash)(npk, tokenData, value);
        return {
            commitmentType: formatted_types_1.CommitmentType.LegacyGeneratedCommitment,
            hash: utils_1.ByteUtils.nToHex(noteHash, utils_1.ByteLength.UINT_256),
            txid: transactionHash,
            timestamp: undefined,
            blockNumber,
            preImage,
            encryptedRandom: randomFormatted[index],
            utxoTree,
            utxoIndex: utxoStartingIndex + index,
        };
    });
}
exports.formatLegacyGeneratedCommitmentBatchCommitments = formatLegacyGeneratedCommitmentBatchCommitments;
function formatLegacyGeneratedCommitmentBatchEvent(commitmentBatchArgs, transactionHash, blockNumber) {
    const { treeNumber, startPosition, commitments, encryptedRandom } = commitmentBatchArgs;
    if (treeNumber == null ||
        startPosition == null ||
        commitments == null ||
        encryptedRandom == null) {
        const err = new Error('Invalid GeneratedCommitmentBatchEventArgs');
        debugger_1.default.error(err);
        throw err;
    }
    const utxoTree = Number(treeNumber);
    const utxoStartingIndex = Number(startPosition);
    const formattedCommitments = formatLegacyGeneratedCommitmentBatchCommitments(transactionHash, commitments, encryptedRandom, blockNumber, utxoTree, utxoStartingIndex);
    return {
        txid: utils_1.ByteUtils.formatToByteLength(transactionHash, utils_1.ByteLength.UINT_256),
        treeNumber: utxoTree,
        startPosition: utxoStartingIndex,
        commitments: formattedCommitments,
        blockNumber,
    };
}
exports.formatLegacyGeneratedCommitmentBatchEvent = formatLegacyGeneratedCommitmentBatchEvent;
function formatLegacyCommitmentCiphertext(commitment) {
    const { ephemeralKeys, memo } = commitment;
    const ciphertext = commitment.ciphertext.map((el) => utils_1.ByteUtils.nToHex(el, utils_1.ByteLength.UINT_256));
    const ivTag = ciphertext[0];
    return {
        ciphertext: {
            iv: ivTag.substring(0, 32),
            tag: ivTag.substring(32),
            data: ciphertext.slice(1),
        },
        ephemeralKeys: ephemeralKeys.map((key) => utils_1.ByteUtils.nToHex(key, utils_1.ByteLength.UINT_256)),
        memo: (memo ?? []).map((el) => utils_1.ByteUtils.nToHex(el, utils_1.ByteLength.UINT_256)),
    };
}
function formatLegacyCommitmentBatchCommitments(transactionHash, hash, commitments, blockNumber, utxoTree, utxoStartingIndex) {
    return commitments.map((commitment, index) => {
        return {
            commitmentType: formatted_types_1.CommitmentType.LegacyEncryptedCommitment,
            hash: utils_1.ByteUtils.nToHex(hash[index], utils_1.ByteLength.UINT_256),
            txid: transactionHash,
            timestamp: undefined,
            blockNumber,
            ciphertext: formatLegacyCommitmentCiphertext(commitment),
            utxoTree,
            utxoIndex: utxoStartingIndex + index,
            railgunTxid: undefined,
        };
    });
}
exports.formatLegacyCommitmentBatchCommitments = formatLegacyCommitmentBatchCommitments;
function formatLegacyCommitmentBatchEvent(commitmentBatchArgs, transactionHash, blockNumber) {
    const { treeNumber, startPosition, hash, ciphertext } = commitmentBatchArgs;
    if (treeNumber == null || startPosition == null || hash == null || ciphertext == null) {
        const err = new Error('Invalid CommitmentBatchEventArgs');
        debugger_1.default.error(err);
        throw err;
    }
    const utxoTree = Number(treeNumber);
    const utxoStartingIndex = Number(startPosition);
    const formattedCommitments = formatLegacyCommitmentBatchCommitments(transactionHash, hash, ciphertext, blockNumber, utxoTree, utxoStartingIndex);
    return {
        txid: utils_1.ByteUtils.formatToByteLength(transactionHash, utils_1.ByteLength.UINT_256),
        treeNumber: utxoTree,
        startPosition: utxoStartingIndex,
        commitments: formattedCommitments,
        blockNumber,
    };
}
exports.formatLegacyCommitmentBatchEvent = formatLegacyCommitmentBatchEvent;
async function processGeneratedCommitmentEvents(txidVersion, eventsListener, logs) {
    const filtered = logs.filter((log) => log.args);
    await Promise.all(filtered.map(async (log) => {
        const { args, transactionHash, blockNumber } = log;
        return eventsListener(txidVersion, [
            formatLegacyGeneratedCommitmentBatchEvent(args, transactionHash, blockNumber),
        ]);
    }));
}
exports.processGeneratedCommitmentEvents = processGeneratedCommitmentEvents;
async function processCommitmentBatchEvents(txidVersion, eventsListener, logs) {
    const filtered = logs.filter((log) => log.args);
    await Promise.all(filtered.map(async (log) => {
        const { args, transactionHash, blockNumber } = log;
        return eventsListener(txidVersion, [
            formatLegacyCommitmentBatchEvent(args, transactionHash, blockNumber),
        ]);
    }));
}
exports.processCommitmentBatchEvents = processCommitmentBatchEvents;
function formatLegacyNullifierEvents(nullifierEventArgs, transactionHash, blockNumber) {
    const nullifiers = [];
    for (const nullifier of nullifierEventArgs.nullifier) {
        nullifiers.push({
            txid: utils_1.ByteUtils.formatToByteLength(transactionHash, utils_1.ByteLength.UINT_256),
            nullifier: utils_1.ByteUtils.nToHex(nullifier, utils_1.ByteLength.UINT_256),
            treeNumber: Number(nullifierEventArgs.treeNumber),
            blockNumber,
        });
    }
    return nullifiers;
}
exports.formatLegacyNullifierEvents = formatLegacyNullifierEvents;
async function processLegacyGeneratedCommitmentEvents(txidVersion, eventsListener, logs) {
    const filtered = logs.filter((log) => log.args);
    await Promise.all(filtered.map(async (log) => {
        const { args, transactionHash, blockNumber } = log;
        return eventsListener(txidVersion, [
            formatLegacyGeneratedCommitmentBatchEvent(args, transactionHash, blockNumber),
        ]);
    }));
}
exports.processLegacyGeneratedCommitmentEvents = processLegacyGeneratedCommitmentEvents;
async function processLegacyCommitmentBatchEvents(txidVersion, eventsListener, logs) {
    const filtered = logs.filter((log) => log.args);
    await Promise.all(filtered.map(async (log) => {
        const { args, transactionHash, blockNumber } = log;
        return eventsListener(txidVersion, [
            formatLegacyCommitmentBatchEvent(args, transactionHash, blockNumber),
        ]);
    }));
}
exports.processLegacyCommitmentBatchEvents = processLegacyCommitmentBatchEvents;
async function processLegacyNullifierEvents(txidVersion, eventsNullifierListener, logs) {
    const nullifiers = [];
    const filtered = logs.filter((log) => log.args);
    for (const event of filtered) {
        const { args, transactionHash, blockNumber } = event;
        nullifiers.push(...formatLegacyNullifierEvents(args, transactionHash, blockNumber));
    }
    await eventsNullifierListener(txidVersion, nullifiers);
}
exports.processLegacyNullifierEvents = processLegacyNullifierEvents;
//# sourceMappingURL=legacy-events.js.map