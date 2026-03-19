"use strict";
// TXIDVersion is kept from the original poi-types.ts as it's used throughout the codebase.
// All POI-specific types have been removed.
Object.defineProperty(exports, "__esModule", { value: true });
exports.ACTIVE_TXID_VERSIONS = exports.ACTIVE_UTXO_MERKLETREE_TXID_VERSIONS = exports.TXIDVersion = void 0;
var TXIDVersion;
(function (TXIDVersion) {
    TXIDVersion["V2_PoseidonMerkle"] = "V2_PoseidonMerkle";
    TXIDVersion["V3_PoseidonMerkle"] = "V3_PoseidonMerkle";
})(TXIDVersion || (exports.TXIDVersion = TXIDVersion = {}));
exports.ACTIVE_UTXO_MERKLETREE_TXID_VERSIONS = [
    TXIDVersion.V2_PoseidonMerkle,
    TXIDVersion.V3_PoseidonMerkle,
];
exports.ACTIVE_TXID_VERSIONS = [
    TXIDVersion.V2_PoseidonMerkle,
    TXIDVersion.V3_PoseidonMerkle,
];
//# sourceMappingURL=poi-types.js.map