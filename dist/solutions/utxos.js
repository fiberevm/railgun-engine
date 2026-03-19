"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sortUTXOsByAscendingValue = exports.filterZeroUTXOs = exports.calculateTotalSpend = void 0;
const calculateTotalSpend = (utxos) => utxos.reduce((left, right) => left + right.note.value, BigInt(0));
exports.calculateTotalSpend = calculateTotalSpend;
const filterZeroUTXOs = (utxos) => {
    return utxos.filter((utxo) => utxo.note.value !== 0n);
};
exports.filterZeroUTXOs = filterZeroUTXOs;
const sortUTXOsByAscendingValue = (utxos) => {
    utxos.sort((left, right) => {
        const leftNum = left.note.value;
        const rightNum = right.note.value;
        if (leftNum < rightNum)
            return -1;
        if (leftNum > rightNum)
            return 1;
        return 0;
    });
};
exports.sortUTXOsByAscendingValue = sortUTXOsByAscendingValue;
//# sourceMappingURL=utxos.js.map