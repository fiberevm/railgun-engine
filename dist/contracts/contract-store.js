"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContractStore = void 0;
const registry_1 = require("../utils/registry");
class ContractStore {
    static railgunSmartWalletContracts = new registry_1.Registry();
    static relayAdaptV2Contracts = new registry_1.Registry();
    static poseidonMerkleAccumulatorV3Contracts = new registry_1.Registry();
    static poseidonMerkleVerifierV3Contracts = new registry_1.Registry();
    static tokenVaultV3Contracts = new registry_1.Registry();
    static relayAdaptV3Contracts = new registry_1.Registry();
}
exports.ContractStore = ContractStore;
//# sourceMappingURL=contract-store.js.map