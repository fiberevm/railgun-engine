"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.V2Events = void 0;
const ethers_1 = require("ethers");
const formatted_types_1 = require("../../../models/formatted-types");
const bytes_1 = require("../../../utils/bytes");
const debugger_1 = __importDefault(require("../../../debugger/debugger"));
const note_util_1 = require("../../../note/note-util");
const abi_1 = require("../../../abi/abi");
class V2Events {
    static formatShieldCommitments(transactionHash, preImages, shieldCiphertext, blockNumber, utxoTree, utxoStartingIndex, fees, timestamp) {
        const shieldCommitments = (preImages.length ? preImages : []).map((commitmentPreImage, index) => {
            const npk = bytes_1.ByteUtils.formatToByteLength(commitmentPreImage.npk, bytes_1.ByteLength.UINT_256);
            const tokenData = (0, note_util_1.serializeTokenData)(commitmentPreImage.token.tokenAddress, commitmentPreImage.token.tokenType, commitmentPreImage.token.tokenSubID.toString());
            const { value } = commitmentPreImage;
            const preImage = (0, note_util_1.serializePreImage)(npk, tokenData, value);
            const noteHash = (0, note_util_1.getNoteHash)(npk, tokenData, value);
            const commitment = {
                commitmentType: formatted_types_1.CommitmentType.ShieldCommitment,
                hash: bytes_1.ByteUtils.nToHex(noteHash, bytes_1.ByteLength.UINT_256),
                txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
                timestamp,
                blockNumber,
                preImage,
                encryptedBundle: shieldCiphertext[index].encryptedBundle,
                shieldKey: shieldCiphertext[index].shieldKey,
                fee: fees && fees[index] ? fees[index].toString() : undefined,
                utxoTree,
                utxoIndex: utxoStartingIndex + index,
                from: undefined,
            };
            return commitment;
        });
        return shieldCommitments;
    }
    static formatShieldEvent(shieldEventArgs, transactionHash, blockNumber, fees, timestamp) {
        const { treeNumber, startPosition, commitments, shieldCiphertext } = shieldEventArgs;
        if (treeNumber == null ||
            startPosition == null ||
            commitments == null ||
            shieldCiphertext == null) {
            const err = new Error('Invalid ShieldEventArgs');
            debugger_1.default.error(err);
            throw err;
        }
        const utxoTree = Number(treeNumber);
        const utxoStartingIndex = Number(startPosition);
        const formattedCommitments = V2Events.formatShieldCommitments(transactionHash, commitments, shieldCiphertext, blockNumber, utxoTree, utxoStartingIndex, fees, timestamp);
        return {
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            treeNumber: utxoTree,
            startPosition: utxoStartingIndex,
            commitments: formattedCommitments,
            blockNumber,
        };
    }
    static formatCommitmentCiphertext(commitmentCiphertext) {
        const { blindedSenderViewingKey, blindedReceiverViewingKey, annotationData, memo } = commitmentCiphertext;
        const ciphertext = commitmentCiphertext.ciphertext.map((el) => bytes_1.ByteUtils.formatToByteLength(el, bytes_1.ByteLength.UINT_256));
        const ivTag = ciphertext[0];
        return {
            ciphertext: {
                iv: ivTag.substring(0, 32),
                tag: ivTag.substring(32),
                data: ciphertext.slice(1),
            },
            blindedSenderViewingKey: bytes_1.ByteUtils.formatToByteLength(blindedSenderViewingKey, bytes_1.ByteLength.UINT_256), // 32 bytes each.
            blindedReceiverViewingKey: bytes_1.ByteUtils.formatToByteLength(blindedReceiverViewingKey, bytes_1.ByteLength.UINT_256), // 32 bytes each.
            annotationData,
            memo,
        };
    }
    static formatTransactCommitments(transactionHash, hash, commitments, blockNumber, utxoTree, utxoStartingIndex, timestamp) {
        return commitments.map((commitment, index) => {
            return {
                commitmentType: formatted_types_1.CommitmentType.TransactCommitmentV2,
                hash: bytes_1.ByteUtils.formatToByteLength(hash[index], bytes_1.ByteLength.UINT_256),
                txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
                timestamp,
                blockNumber,
                ciphertext: V2Events.formatCommitmentCiphertext(commitment),
                utxoTree,
                utxoIndex: utxoStartingIndex + index,
                railgunTxid: undefined,
            };
        });
    }
    static formatTransactEvent(transactEventArgs, transactionHash, blockNumber, timestamp) {
        const { treeNumber, startPosition, hash, ciphertext } = transactEventArgs;
        if (treeNumber == null || startPosition == null || hash == null || ciphertext == null) {
            const err = new Error('Invalid TransactEventObject');
            debugger_1.default.error(err);
            throw err;
        }
        const utxoTree = Number(treeNumber);
        const utxoStartingIndex = Number(startPosition);
        const formattedCommitments = V2Events.formatTransactCommitments(transactionHash, hash, ciphertext, blockNumber, utxoTree, utxoStartingIndex, timestamp);
        return {
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            treeNumber: utxoTree,
            startPosition: utxoStartingIndex,
            commitments: formattedCommitments,
            blockNumber,
        };
    }
    static formatUnshieldEvent(unshieldEventArgs, transactionHash, blockNumber, eventLogIndex, timestamp) {
        const { to, token, amount, fee } = unshieldEventArgs;
        return {
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            timestamp,
            toAddress: to,
            tokenType: Number(token.tokenType),
            tokenAddress: token.tokenAddress,
            tokenSubID: token.tokenSubID.toString(),
            amount: amount.toString(),
            fee: fee.toString(),
            blockNumber,
            eventLogIndex,
            railgunTxid: undefined,
        };
    }
    static async processShieldEvents(txidVersion, eventsListener, logs) {
        const filtered = logs.filter((log) => log.args);
        if (logs.length !== filtered.length) {
            throw new Error('Args required for Shield events');
        }
        for (const event of filtered) {
            const { args, transactionHash, blockNumber } = event;
            const { fees } = args;
            const formattedEvents = V2Events.formatShieldEvent(args, transactionHash, blockNumber, fees, undefined);
            // eslint-disable-next-line no-await-in-loop
            await eventsListener(txidVersion, [formattedEvents]);
        }
    }
    static async processShieldEvents_LegacyShield_PreMar23(txidVersion, eventsListener, logs) {
        // NOTE: Legacy "Shield" event of the same name conflicts with the current ABI's Shield event.
        // It seems that the first ABI to load, with "Shield" event, for a given contract address,
        // sets a cached version of the ABI interface.
        // So, we need to custom-decode the legacy Shield event here.
        const iface = new ethers_1.Interface(abi_1.ABIRailgunSmartWallet_Legacy_PreMar23.filter((fragment) => fragment.type === 'event'));
        for (const log of logs) {
            const args = iface.decodeEventLog('Shield', log.data);
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            log.args = args;
        }
        const filtered = logs.filter((log) => log.args);
        if (logs.length !== filtered.length) {
            throw new Error('Args required for Legacy Shield events');
        }
        for (const event of filtered) {
            const { args, transactionHash, blockNumber } = event;
            const fees = undefined;
            const formattedEvents = V2Events.formatShieldEvent(args, transactionHash, blockNumber, fees, undefined);
            // eslint-disable-next-line no-await-in-loop
            await eventsListener(txidVersion, [formattedEvents]);
        }
    }
    static async processTransactEvents(txidVersion, eventsListener, logs) {
        const filtered = logs.filter((log) => log.args);
        if (logs.length !== filtered.length) {
            throw new Error('Args required for Transact events');
        }
        for (const event of filtered) {
            const { args, transactionHash, blockNumber } = event;
            const formattedEvent = V2Events.formatTransactEvent(args, transactionHash, blockNumber, undefined);
            // eslint-disable-next-line no-await-in-loop
            await eventsListener(txidVersion, [formattedEvent]);
        }
    }
    static async processUnshieldEvents(txidVersion, eventsUnshieldListener, logs) {
        const filtered = logs.filter((log) => log.args);
        if (logs.length !== filtered.length) {
            throw new Error('Args required for Unshield events');
        }
        for (const event of filtered) {
            const { args, transactionHash, blockNumber } = event;
            const formattedEvents = V2Events.formatUnshieldEvent(args, transactionHash, blockNumber, event.index, undefined);
            // eslint-disable-next-line no-await-in-loop
            await eventsUnshieldListener(txidVersion, [formattedEvents]);
        }
    }
    static formatNullifiedEvents(nullifierEventArgs, transactionHash, blockNumber) {
        const nullifiers = [];
        for (const nullifier of nullifierEventArgs.nullifier) {
            nullifiers.push({
                txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
                nullifier: bytes_1.ByteUtils.formatToByteLength(nullifier, bytes_1.ByteLength.UINT_256),
                treeNumber: Number(nullifierEventArgs.treeNumber),
                blockNumber,
            });
        }
        return nullifiers;
    }
    static async processNullifiedEvents(txidVersion, eventsNullifierListener, logs) {
        const nullifiers = [];
        const filtered = logs.filter((log) => log.args);
        if (logs.length !== filtered.length) {
            throw new Error('Args required for Nullified events');
        }
        for (const log of filtered) {
            const { args, transactionHash, blockNumber } = log;
            nullifiers.push(...V2Events.formatNullifiedEvents(args, transactionHash, blockNumber));
        }
        await eventsNullifierListener(txidVersion, nullifiers);
    }
}
exports.V2Events = V2Events;
//# sourceMappingURL=V2-events.js.map