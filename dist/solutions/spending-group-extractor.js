"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractSpendingSolutionGroupsData = exports.serializeExtractedSpendingSolutionGroupsData = void 0;
const railgun_engine_1 = require("../railgun-engine");
const note_util_1 = require("../note/note-util");
const serializeExtractedSpendingSolutionGroupsData = (datas) => {
    return datas.map((data) => {
        return {
            utxoTxids: data.utxoTxids,
            utxoValues: data.utxoValues.map((val) => val.toString(10)),
            outputValues: data.outputValues.map((val) => val.toString(10)),
            outputAddresses: data.outputAddressDatas.map(railgun_engine_1.RailgunEngine.encodeAddress),
            tokenAddress: data.tokenData.tokenAddress,
            tokenType: data.tokenData.tokenType,
            tokenSubID: data.tokenData.tokenSubID,
            tokenHash: (0, note_util_1.getTokenDataHash)(data.tokenData),
        };
    });
};
exports.serializeExtractedSpendingSolutionGroupsData = serializeExtractedSpendingSolutionGroupsData;
const extractSpendingSolutionGroupsData = (spendingSolutionGroups) => {
    return spendingSolutionGroups.map((spendingSolutionGroup) => ({
        utxoTxids: spendingSolutionGroup.utxos.map((utxo) => utxo.txid),
        utxoValues: spendingSolutionGroup.utxos.map((utxo) => utxo.note.value),
        outputValues: spendingSolutionGroup.tokenOutputs.map((note) => note.value),
        outputAddressDatas: spendingSolutionGroup.tokenOutputs.map((note) => note.receiverAddressData),
        tokenData: spendingSolutionGroup.tokenData,
    }));
};
exports.extractSpendingSolutionGroupsData = extractSpendingSolutionGroupsData;
//# sourceMappingURL=spending-group-extractor.js.map