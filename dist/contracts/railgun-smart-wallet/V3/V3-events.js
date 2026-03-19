"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.V3Events = void 0;
const formatted_types_1 = require("../../../models/formatted-types");
const merkletree_types_1 = require("../../../models/merkletree-types");
const note_util_1 = require("../../../note/note-util");
const is_defined_1 = require("../../../utils/is-defined");
const bytes_1 = require("../../../utils/bytes");
const ethers_1 = require("../../../utils/ethers");
const debugger_1 = __importDefault(require("../../../debugger/debugger"));
const railgun_txid_1 = require("../../../transaction/railgun-txid");
const global_tree_position_1 = require("../../../utils/global-tree-position");
class V3Events {
    static formatTransactEvent(transactionHash, blockNumber, commitmentHashes, commitmentCiphertexts, utxoTree, utxoStartingIndex, transactIndex, senderCiphertext, railgunTxid) {
        const formattedCommitments = V3Events.formatTransactCommitments(transactionHash, blockNumber, commitmentHashes, commitmentCiphertexts, utxoTree, utxoStartingIndex, transactIndex, senderCiphertext, railgunTxid);
        return {
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            treeNumber: utxoTree,
            startPosition: utxoStartingIndex,
            commitments: formattedCommitments,
            blockNumber,
        };
    }
    static formatTransactCommitments(transactionHash, blockNumber, commitmentHashes, commitmentCiphertexts, utxoTree, utxoStartingIndex, transactIndex, senderCiphertext, railgunTxid) {
        return commitmentCiphertexts.map((commitmentCiphertext, index) => {
            return {
                commitmentType: formatted_types_1.CommitmentType.TransactCommitmentV3,
                hash: bytes_1.ByteUtils.formatToByteLength(commitmentHashes[index], bytes_1.ByteLength.UINT_256),
                txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
                timestamp: undefined,
                blockNumber,
                ciphertext: V3Events.formatCommitmentCiphertext(commitmentCiphertext),
                utxoTree,
                utxoIndex: utxoStartingIndex + index,
                transactCommitmentBatchIndex: transactIndex + index, // global index of commitment in the entire transaction batch (used to decrypt OutputType)
                railgunTxid,
                senderCiphertext,
            };
        });
    }
    static formatCommitmentCiphertext(commitmentCiphertext) {
        const { blindedSenderViewingKey, blindedReceiverViewingKey } = commitmentCiphertext;
        const strippedCiphertext = bytes_1.ByteUtils.strip0x(commitmentCiphertext.ciphertext);
        const nonce = strippedCiphertext.slice(0, 32);
        const bundle = strippedCiphertext.slice(32);
        return {
            ciphertext: {
                algorithm: formatted_types_1.XChaChaEncryptionAlgorithm.XChaChaPoly1305,
                nonce,
                bundle,
            },
            blindedSenderViewingKey: bytes_1.ByteUtils.formatToByteLength(blindedSenderViewingKey, bytes_1.ByteLength.UINT_256), // 32 bytes each.
            blindedReceiverViewingKey: bytes_1.ByteUtils.formatToByteLength(blindedReceiverViewingKey, bytes_1.ByteLength.UINT_256), // 32 bytes each.
        };
    }
    static formatUnshieldEvent(transactionHash, blockNumber, unshieldPreimage, transactIndex, fee, railgunTxid) {
        return {
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            toAddress: bytes_1.ByteUtils.formatToByteLength(unshieldPreimage.npk, bytes_1.ByteLength.Address, true),
            tokenType: Number(unshieldPreimage.token.tokenType),
            tokenAddress: unshieldPreimage.token.tokenAddress,
            tokenSubID: unshieldPreimage.token.tokenSubID.toString(),
            amount: (unshieldPreimage.value - fee).toString(),
            fee: fee.toString(),
            blockNumber,
            eventLogIndex: transactIndex,
            railgunTxid,
            timestamp: undefined,
        };
    }
    static formatNullifiedEvents(transactionHash, blockNumber, spendAccumulatorNumber, nullifierHashes) {
        const nullifiers = [];
        for (const nullifierHash of nullifierHashes) {
            nullifiers.push({
                txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
                nullifier: bytes_1.ByteUtils.formatToByteLength(nullifierHash, bytes_1.ByteLength.UINT_256),
                treeNumber: spendAccumulatorNumber,
                blockNumber,
            });
        }
        return nullifiers;
    }
    static formatRailgunTransactionEvent(transactionHash, blockNumber, commitments, nullifiers, unshieldPreimage, boundParamsHash, utxoTreeIn, utxoTree, utxoBatchStartPosition, verificationHash) {
        const hasUnshield = unshieldPreimage.value > 0n;
        const unshield = hasUnshield
            ? {
                toAddress: bytes_1.ByteUtils.formatToByteLength(unshieldPreimage.npk, bytes_1.ByteLength.Address, true),
                tokenData: (0, note_util_1.serializeTokenData)(unshieldPreimage.token.tokenAddress, unshieldPreimage.token.tokenType, unshieldPreimage.token.tokenSubID.toString()),
                value: unshieldPreimage.value.toString(),
            }
            : undefined;
        // Unshield-only transactions must have hardcoded utxoTreeOut and utxoBatchStartPositionOut of 99999.
        const isUnshieldOnly = commitments.length === 1 && hasUnshield;
        return {
            version: formatted_types_1.RailgunTransactionVersion.V3,
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            blockNumber,
            commitments,
            nullifiers,
            boundParamsHash,
            unshield,
            utxoTreeIn,
            utxoTreeOut: isUnshieldOnly ? global_tree_position_1.GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE : utxoTree,
            utxoBatchStartPositionOut: isUnshieldOnly
                ? global_tree_position_1.GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE
                : utxoBatchStartPosition,
            verificationHash,
        };
    }
    static formatShieldEvent(transactionHash, blockNumber, from, shieldPreImage, shieldCiphertext, utxoTree, utxoIndex, fee) {
        const formattedCommitment = V3Events.formatShieldCommitment(transactionHash, blockNumber, from, shieldPreImage, shieldCiphertext, utxoTree, utxoIndex, fee);
        return {
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            treeNumber: utxoTree,
            startPosition: utxoIndex,
            commitments: [formattedCommitment],
            blockNumber,
        };
    }
    static formatShieldCommitment(transactionHash, blockNumber, from, shieldPreImage, shieldCiphertext, utxoTree, utxoIndex, fee) {
        const npk = bytes_1.ByteUtils.formatToByteLength(shieldPreImage.npk, bytes_1.ByteLength.UINT_256);
        const tokenData = (0, note_util_1.serializeTokenData)(shieldPreImage.token.tokenAddress, shieldPreImage.token.tokenType, shieldPreImage.token.tokenSubID.toString());
        const { value } = shieldPreImage;
        const preImage = (0, note_util_1.serializePreImage)(npk, tokenData, value);
        const noteHash = (0, note_util_1.getNoteHash)(npk, tokenData, value);
        const commitment = {
            commitmentType: formatted_types_1.CommitmentType.ShieldCommitment,
            hash: bytes_1.ByteUtils.nToHex(noteHash, bytes_1.ByteLength.UINT_256),
            txid: bytes_1.ByteUtils.formatToByteLength(transactionHash, bytes_1.ByteLength.UINT_256),
            timestamp: undefined,
            blockNumber,
            preImage,
            encryptedBundle: shieldCiphertext.encryptedBundle,
            shieldKey: shieldCiphertext.shieldKey,
            fee: fee?.toString(),
            utxoTree,
            utxoIndex,
            from,
        };
        return commitment;
    }
    static async processAccumulatorUpdateEvents(txidVersion, logs, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener) {
        const filtered = logs.filter((log) => log.args);
        if (logs.length !== filtered.length) {
            throw new Error('Args required for Nullified events');
        }
        await Promise.all(filtered.map(async (log) => {
            const { args, transactionHash, blockNumber } = log;
            await V3Events.processAccumulatorEvent(txidVersion, args, transactionHash, blockNumber, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, async () => { });
        }));
    }
    static async processAccumulatorEvent(txidVersion, args, transactionHash, blockNumber, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, triggerWalletBalanceDecryptions) {
        try {
            const { update, accumulatorNumber, startPosition } = getAccumulatorEventObject(args);
            const { commitments: unformattedCommitments, transactions: unformattedTransactions, shields: unformattedShields, commitmentCiphertext: unformattedCommitmentCiphertext, treasuryFees: unformattedTreasuryFees, senderCiphertext, } = recusivelyDecodeAccumulatorUpdateObject(update);
            // 'commitments' is potentially parsed as an object.
            const commitments = 'length' in unformattedCommitments ? unformattedCommitments : [];
            // 'transactions' is potentially parsed as an object.
            const transactions = 'length' in unformattedTransactions ? unformattedTransactions : [];
            // 'shields' is potentially parsed as an object.
            const shields = 'length' in unformattedShields ? unformattedShields : [];
            // 'commitmentCiphertext' is potentially parsed as an object.
            const commitmentCiphertext = 'length' in unformattedCommitmentCiphertext ? unformattedCommitmentCiphertext : [];
            // 'treasuryFees' is potentially parsed as an object.
            const treasuryFees = 'length' in unformattedTreasuryFees ? unformattedTreasuryFees : [];
            const treasuryFeeMap = {};
            for (const { tokenID, fee } of treasuryFees) {
                const strippedTokenID = bytes_1.ByteUtils.strip0x(tokenID);
                const unshield = transactions.find((transaction) => {
                    const unshieldTokenHash = (0, note_util_1.extractTokenHashFromCommitmentPreImageV3)(transaction.unshieldPreimage);
                    return unshieldTokenHash === strippedTokenID;
                });
                const unshieldValue = unshield?.unshieldPreimage.value ?? 0n;
                const shield = shields.find(({ preimage }) => {
                    const shieldTokenHash = (0, note_util_1.extractTokenHashFromCommitmentPreImageV3)(preimage);
                    return shieldTokenHash === strippedTokenID;
                });
                const shieldValue = shield?.preimage.value ?? 0n;
                let shieldFeePortion;
                let unshieldFeePortion;
                // TODO: This calculation assumes that the shield and unshield fees are equal.
                if (unshieldValue < shieldValue) {
                    unshieldFeePortion = (unshieldValue * fee) / (unshieldValue + shieldValue);
                    shieldFeePortion = fee - unshieldFeePortion;
                }
                else {
                    shieldFeePortion = (shieldValue * fee) / (shieldValue + unshieldValue);
                    unshieldFeePortion = fee - shieldFeePortion;
                }
                treasuryFeeMap[strippedTokenID] = {
                    shield: shieldFeePortion,
                    unshield: unshieldFeePortion,
                };
            }
            let commitmentsStartIndex = 0;
            let utxoTree = Number(accumulatorNumber);
            let utxoStartingIndex = Number(startPosition);
            const allCommitmentEvents = [];
            for (let i = 0; i < transactions.length; i += 1) {
                const { nullifiers, commitmentsCount, spendAccumulatorNumber, unshieldPreimage, boundParamsHash, } = transactions[i];
                const commitmentsEndIndex = commitmentsStartIndex + Number(commitmentsCount);
                const commitmentHashes = commitments.slice(commitmentsStartIndex, commitmentsEndIndex);
                const commitmentCiphertexts = commitmentCiphertext.slice(commitmentsStartIndex, commitmentsEndIndex);
                if (commitmentHashes.length !== Number(commitmentsCount)) {
                    throw new Error('Expected commitmentHashes length to match commitmentsCount');
                }
                if (commitmentCiphertexts.length !== Number(commitmentsCount)) {
                    throw new Error('Expected commitmentCiphertexts length to match commitmentsCount');
                }
                commitmentsStartIndex = commitmentsEndIndex;
                const hasUnshield = unshieldPreimage.value > 0n;
                const commitmentsWithUnshieldHash = hasUnshield
                    ? [
                        ...commitmentHashes,
                        bytes_1.ByteUtils.nToHex((0, note_util_1.getUnshieldPreImageNoteHash)(unshieldPreimage), bytes_1.ByteLength.UINT_256, true),
                    ]
                    : commitmentHashes;
                const formattedBoundParamsHash = bytes_1.ByteUtils.formatToByteLength(boundParamsHash, bytes_1.ByteLength.UINT_256, false);
                const railgunTransaction = V3Events.formatRailgunTransactionEvent(transactionHash, blockNumber, commitmentsWithUnshieldHash, nullifiers, unshieldPreimage, formattedBoundParamsHash, Number(spendAccumulatorNumber), // utxoTreeIn
                utxoTree, utxoStartingIndex, undefined);
                // eslint-disable-next-line no-await-in-loop
                await eventsRailgunTransactionsV3Listener(txidVersion, [railgunTransaction]);
                const railgunTxid = (0, railgun_txid_1.getRailgunTransactionIDHex)(railgunTransaction);
                const transactEvent = V3Events.formatTransactEvent(transactionHash, blockNumber, commitmentHashes, commitmentCiphertexts, utxoTree, utxoStartingIndex, i, // transactCommitmentBatchIndex
                senderCiphertext, railgunTxid);
                allCommitmentEvents.push(transactEvent);
                const nullifiedEvents = V3Events.formatNullifiedEvents(transactionHash, blockNumber, Number(spendAccumulatorNumber), nullifiers);
                // eslint-disable-next-line no-await-in-loop
                await eventsNullifierListener(txidVersion, nullifiedEvents);
                if (hasUnshield) {
                    const isERC20 = unshieldPreimage.token.tokenType === 0n;
                    const totalUnshieldValuesForToken = transactions.reduce((acc, curr) => {
                        return acc + curr.unshieldPreimage.value;
                    }, 0n);
                    const unshieldTokenHash = (0, note_util_1.extractTokenHashFromCommitmentPreImageV3)(unshieldPreimage);
                    if (isERC20 && !(0, is_defined_1.isDefined)(treasuryFeeMap[unshieldTokenHash])) {
                        throw new Error('Expected unshield token hash in treasuryFeeMap');
                    }
                    const unshieldFee = totalUnshieldValuesForToken > 0n
                        ? (treasuryFeeMap[unshieldTokenHash].unshield * unshieldPreimage.value) /
                            totalUnshieldValuesForToken
                        : 0n;
                    if (isERC20 &&
                        unshieldPreimage.value >= 400n && // TODO: This will need to change if the unshield fee is different than 0.25%.
                        (!(0, is_defined_1.isDefined)(unshieldFee) || unshieldFee === 0n)) {
                        throw new Error('Expected an unshield fee in treasuryFeeMap');
                    }
                    const unshieldEvent = V3Events.formatUnshieldEvent(transactionHash, blockNumber, unshieldPreimage, i, // transaction index
                    unshieldFee, railgunTxid);
                    // eslint-disable-next-line no-await-in-loop
                    await eventsUnshieldListener(txidVersion, [unshieldEvent]);
                }
                utxoStartingIndex += Number(commitmentsCount);
                if (utxoStartingIndex >= merkletree_types_1.TREE_MAX_ITEMS) {
                    utxoStartingIndex = 0;
                    utxoTree += 1;
                }
            }
            for (const shield of shields) {
                const totalShieldValuesForToken = shields.reduce((acc, curr) => {
                    return acc + curr.preimage.value;
                }, 0n);
                const { from, preimage, ciphertext } = shield;
                const shieldTokenHash = (0, note_util_1.extractTokenHashFromCommitmentPreImageV3)(preimage);
                const isERC20 = preimage.token.tokenType === 0n;
                if (isERC20 && !(0, is_defined_1.isDefined)(treasuryFeeMap[shieldTokenHash])) {
                    throw new Error('Expected shield token hash in treasuryFeeMap');
                }
                // Assume equal shield fees across each shield for this token.
                const shieldFee = totalShieldValuesForToken > 0n
                    ? (treasuryFeeMap[shieldTokenHash].shield * shield.preimage.value) /
                        totalShieldValuesForToken
                    : 0n;
                if (isERC20 &&
                    shield.preimage.value >= 400n && // TODO: This will need to change if the unshield fee is different than 0.25%.
                    (!(0, is_defined_1.isDefined)(shieldFee) || shieldFee === 0n)) {
                    throw new Error('Expected a shield fee in treasuryFeeMap');
                }
                const shieldEvent = V3Events.formatShieldEvent(transactionHash, blockNumber, from, preimage, ciphertext, utxoTree, utxoStartingIndex, shieldFee);
                allCommitmentEvents.push(shieldEvent);
                utxoStartingIndex += 1;
                if (utxoStartingIndex >= merkletree_types_1.TREE_MAX_ITEMS) {
                    utxoStartingIndex = 0;
                    utxoTree += 1;
                }
            }
            await eventsCommitmentListener(txidVersion, allCommitmentEvents);
            // Trigger wallet scans after all events are processed.
            await triggerWalletBalanceDecryptions(txidVersion);
        }
        catch (cause) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const err = new Error('Failed to process V3 accumulator update event', { cause });
            debugger_1.default.error(err);
            throw err;
        }
    }
}
exports.V3Events = V3Events;
const getAccumulatorEventObject = (args) => {
    try {
        return args.toObject();
    }
    catch (err) {
        return args;
    }
};
const recusivelyDecodeAccumulatorUpdateObject = (args) => {
    try {
        return (0, ethers_1.recursivelyDecodeResult)(args);
    }
    catch (err) {
        return args;
    }
};
//# sourceMappingURL=V3-events.js.map