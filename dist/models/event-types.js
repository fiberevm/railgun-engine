"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MerkletreeScanStatus = exports.EngineEvent = void 0;
var EngineEvent;
(function (EngineEvent) {
    EngineEvent["WalletDecryptBalancesComplete"] = "decrypted-balances";
    EngineEvent["ContractNullifierReceived"] = "nullified";
    EngineEvent["UTXOMerkletreeHistoryScanUpdate"] = "utxo-merkletree-history-scan-update";
    EngineEvent["TXIDMerkletreeHistoryScanUpdate"] = "txid-merkletree-history-scan-update";
    EngineEvent["UTXOScanDecryptBalancesComplete"] = "UTXOScanDecryptBalancesComplete";
})(EngineEvent || (exports.EngineEvent = EngineEvent = {}));
var MerkletreeScanStatus;
(function (MerkletreeScanStatus) {
    MerkletreeScanStatus["Started"] = "Started";
    MerkletreeScanStatus["Updated"] = "Updated";
    MerkletreeScanStatus["Complete"] = "Complete";
    MerkletreeScanStatus["Incomplete"] = "Incomplete";
})(MerkletreeScanStatus || (exports.MerkletreeScanStatus = MerkletreeScanStatus = {}));
//# sourceMappingURL=event-types.js.map