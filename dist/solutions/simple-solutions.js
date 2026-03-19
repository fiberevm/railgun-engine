"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.findExactSolutionsOverTargetValue = void 0;
const nullifiers_1 = require("./nullifiers");
const utxos_1 = require("./utxos");
const shouldAddMoreUTXOs = (utxos, totalRequired) => (0, utxos_1.calculateTotalSpend)(utxos) < totalRequired;
function findExactSolutionsOverTargetValue(treeBalance, totalRequired) {
    // If this tree doesn't have enough to cover this transaction, return false
    if (treeBalance.balance < totalRequired)
        return [];
    // Remove utxos with 0 value.
    const filteredUTXOs = (0, utxos_1.filterZeroUTXOs)(treeBalance.utxos);
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
    while (filteredUTXOs.length > utxos.length && shouldAddMoreUTXOs(utxos, totalRequired)) {
        // If sum is not greater than target, push the next largest UTXO
        utxos.push(filteredUTXOs[utxos.length]);
    }
    if (totalRequired > (0, utxos_1.calculateTotalSpend)(utxos)) {
        // Fallback to next tree, or complex transaction batch.
        return undefined;
    }
    if (!(0, nullifiers_1.isValidNullifierCount)(utxos.length)) {
        // Fallback to next tree, or complex transaction batch.
        return undefined;
    }
    return utxos;
}
exports.findExactSolutionsOverTargetValue = findExactSolutionsOverTargetValue;
//# sourceMappingURL=simple-solutions.js.map