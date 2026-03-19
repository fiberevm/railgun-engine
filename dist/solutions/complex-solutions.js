"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.findNextSolutionBatch = exports.shouldAddMoreUTXOsForSolutionBatch = exports.nextNullifierTarget = exports.createSpendingSolutionsForValue = void 0;
const bigint_1 = require("../utils/bigint");
const nullifiers_1 = require("./nullifiers");
const utxos_1 = require("./utxos");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const utils_1 = require("../utils");
const is_defined_1 = require("../utils/is-defined");
const formatted_types_1 = require("../models/formatted-types");
const constants_1 = require("../utils/constants");
const logTreeSortedBalancesMetadata = (treeSortedBalances) => {
    debugger_1.default.log('treeSortedBalances metadata:');
    for (const treeBalance of treeSortedBalances) {
        if (!(0, is_defined_1.isDefined)(treeBalance))
            continue;
        debugger_1.default.log(`Token: ${treeBalance.tokenData.tokenAddress}`);
        debugger_1.default.log(`Total balance: ${treeBalance.balance.toString()}`);
        debugger_1.default.log(`UTXOs: ${(0, utxos_1.filterZeroUTXOs)(treeBalance.utxos)
            .map((utxo) => utxo.note.value.toString())
            .join(', ')}`);
    }
};
const createSpendingSolutionGroup = (output, tree, solutionValue, utxos, isUnshield) => {
    if (isUnshield) {
        return {
            spendingTree: tree,
            utxos,
            tokenOutputs: [],
            unshieldValue: solutionValue,
            tokenData: output.tokenData,
        };
    }
    const solutionOutput = output.newProcessingNoteWithValue(solutionValue);
    return {
        spendingTree: tree,
        utxos,
        tokenOutputs: [solutionOutput],
        unshieldValue: 0n,
        tokenData: output.tokenData,
    };
};
/**
 * UTXO with value 0n. All other fields are placeholders.
 * The circuit will ignore fields if value is 0.
 */
const createNullUTXO = (nullNote) => {
    const nullTxid = utils_1.ByteUtils.formatToByteLength('0x00', utils_1.ByteLength.UINT_256, true);
    return {
        tree: 0,
        position: 100000, // out of bounds position - so we don't have collisions on nullifiers
        blockNumber: 100,
        timestamp: undefined,
        spendtxid: false,
        note: nullNote,
        txid: nullTxid,
        blindedCommitment: undefined,
        transactCreationRailgunTxid: undefined,
        commitmentType: formatted_types_1.CommitmentType.TransactCommitmentV3,
        nullifier: constants_1.ZERO_32_BYTE_VALUE,
    };
};
const getUTXOIDPosition = (utxo) => {
    return `${utxo.txid}-${utxo.position}`;
};
const replaceOrRemoveRemainingOutput = (remainingOutputs, amountToFill) => {
    // Remove the "used" output note.
    const [deletedOutput] = remainingOutputs.splice(0, 1);
    // Insert another remaining output note for any Amount Left.
    if (amountToFill > 0n) {
        remainingOutputs.splice(0, 0, deletedOutput.newProcessingNoteWithValue(amountToFill));
    }
};
const createSpendingSolutionsForValue = (treeSortedBalances, remainingOutputs, excludedUTXOIDPositions, isUnshield) => {
    // Primary output to find UTXOs for.
    const primaryOutput = remainingOutputs[0];
    // Secondary output is used as the backup note for any change.
    const secondaryOutput = remainingOutputs.length > 1 ? remainingOutputs[1] : undefined;
    const { value } = primaryOutput;
    debugger_1.default.log('createSpendingSolutionsForValue');
    debugger_1.default.log(`totalRequired: ${value.toString()}`);
    debugger_1.default.log(`excludedUTXOIDPositions: ${excludedUTXOIDPositions.join(', ')}`);
    logTreeSortedBalancesMetadata(treeSortedBalances);
    if (value === 0n) {
        replaceOrRemoveRemainingOutput(remainingOutputs, 0n);
        // Create a 0-value spending solution group.
        // This is used when simulating a circuit transaction, without requiring an input note.
        // Helpful for initial dummy Broadcaster Fee with recursive gas estimator.
        const nullNote = primaryOutput.newProcessingNoteWithValue(0n);
        const nullUtxo = createNullUTXO(nullNote);
        const utxos = [nullUtxo];
        const nullSpendingSolutionGroup = createSpendingSolutionGroup(nullNote, nullUtxo.tree, nullNote.value, utxos, isUnshield);
        return [nullSpendingSolutionGroup];
    }
    let amountToFill = value;
    const spendingSolutionGroups = [];
    for (const [tree, treeBalance] of treeSortedBalances.entries()) {
        if (!(0, is_defined_1.isDefined)(treeBalance))
            continue;
        while (amountToFill > 0n) {
            const utxos = (0, exports.findNextSolutionBatch)(treeBalance, amountToFill, excludedUTXOIDPositions);
            if (!utxos) {
                // No more solutions in this tree.
                break;
            }
            // Don't allow these UTXOs to be used twice.
            excludedUTXOIDPositions.push(...utxos.map(getUTXOIDPosition));
            // Decrement amount left by total spend in UTXOs.
            const totalSpend = (0, utxos_1.calculateTotalSpend)(utxos);
            // Solution Value is the smaller of Solution spend value, or required output value.
            const solutionValue = (0, bigint_1.minBigInt)(totalSpend, amountToFill);
            // Generate spending solution group, which will be used to create a Transaction.
            const spendingSolutionGroup = createSpendingSolutionGroup(primaryOutput, tree, solutionValue, utxos, isUnshield);
            spendingSolutionGroups.push(spendingSolutionGroup);
            amountToFill -= totalSpend;
            replaceOrRemoveRemainingOutput(remainingOutputs, amountToFill);
            if (amountToFill <= 0n) {
                // Use any remaining change to fill the secondary output.
                const change = 0n - amountToFill;
                if (change > 0n && secondaryOutput && !isUnshield) {
                    let secondaryNoteValue;
                    let finalAmountToFill;
                    if (secondaryOutput.value < change) {
                        secondaryNoteValue = secondaryOutput.value;
                        finalAmountToFill = 0n;
                    }
                    else {
                        secondaryNoteValue = change;
                        finalAmountToFill = secondaryOutput.value - change;
                    }
                    const secondaryNote = secondaryOutput.newProcessingNoteWithValue(secondaryNoteValue);
                    const finalSpendingSolutionGroup = spendingSolutionGroups[spendingSolutionGroups.length - 1];
                    finalSpendingSolutionGroup.tokenOutputs.push(secondaryNote);
                    // NOTE: Primary output is already removed from remainingOutputs.
                    // This will remove the secondary output, or update the value.
                    replaceOrRemoveRemainingOutput(remainingOutputs, finalAmountToFill);
                }
            }
        }
    }
    if (amountToFill > 0n) {
        // Could not find enough solutions.
        throw new Error('Balance too low: requires additional UTXOs to satisfy spending solution.');
    }
    return spendingSolutionGroups;
};
exports.createSpendingSolutionsForValue = createSpendingSolutionsForValue;
/**
 * Finds next valid nullifier count above the current nullifier count.
 */
const nextNullifierTarget = (utxoCount) => nullifiers_1.VALID_INPUT_COUNTS.find((n) => n > utxoCount);
exports.nextNullifierTarget = nextNullifierTarget;
const shouldAddMoreUTXOsForSolutionBatch = (currentNullifierCount, totalNullifierCount, currentSpend, totalRequired) => {
    if (currentSpend >= totalRequired) {
        // We've hit the target required.
        return false;
    }
    const nullifierTarget = (0, exports.nextNullifierTarget)(currentNullifierCount);
    if (!(0, is_defined_1.isDefined)(nullifierTarget)) {
        // No next nullifier target.
        return false;
    }
    if (nullifierTarget > totalNullifierCount) {
        // Next target is not reachable. Don't add any more UTXOs.
        return false;
    }
    // Total spend < total required, and next nullifier target is reachable.
    // Continue adding nullifiers.
    return true;
};
exports.shouldAddMoreUTXOsForSolutionBatch = shouldAddMoreUTXOsForSolutionBatch;
/**
 * 1. Filter out UTXOs with value 0.
 * 2. Use exact match UTXO for totalRequired value if it exists.
 * 3. Sort by smallest UTXO ascending.
 * 4. Add UTXOs to the batch until we hit the totalRequired value, or exceed the UTXO input count maximum.
 */
const findNextSolutionBatch = (treeBalance, totalRequired, excludedUTXOIDPositions) => {
    const removedZeroUTXOs = (0, utxos_1.filterZeroUTXOs)(treeBalance.utxos);
    const filteredUTXOs = removedZeroUTXOs.filter((utxo) => !excludedUTXOIDPositions.includes(getUTXOIDPosition(utxo)));
    if (!filteredUTXOs.length) {
        // No more solutions in this tree.
        return undefined;
    }
    // Use exact match if it exists.
    // TODO: Use exact matches from any tree, not just the first tree examined.
    const exactMatch = filteredUTXOs.find((utxo) => utxo.note.value === totalRequired);
    if (exactMatch) {
        return [exactMatch];
    }
    // Sort UTXOs by smallest size
    (0, utxos_1.sortUTXOsByAscendingValue)(filteredUTXOs);
    // Accumulate UTXOs until we hit the target value
    const utxos = [];
    // Check if sum of UTXOs selected is greater than target
    while ((0, exports.shouldAddMoreUTXOsForSolutionBatch)(utxos.length, filteredUTXOs.length, (0, utxos_1.calculateTotalSpend)(utxos), totalRequired)) {
        utxos.push(filteredUTXOs[utxos.length]);
    }
    if (!(0, nullifiers_1.isValidNullifierCount)(utxos.length)) {
        return undefined;
    }
    return utxos;
};
exports.findNextSolutionBatch = findNextSolutionBatch;
//# sourceMappingURL=complex-solutions.js.map