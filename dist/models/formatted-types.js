"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RailgunTransactionVersion = exports.OutputType = exports.CommitmentType = exports.TokenType = exports.XChaChaEncryptionAlgorithm = void 0;
var XChaChaEncryptionAlgorithm;
(function (XChaChaEncryptionAlgorithm) {
    XChaChaEncryptionAlgorithm["XChaCha"] = "XChaCha";
    XChaChaEncryptionAlgorithm["XChaChaPoly1305"] = "XChaChaPoly1305";
})(XChaChaEncryptionAlgorithm || (exports.XChaChaEncryptionAlgorithm = XChaChaEncryptionAlgorithm = {}));
var TokenType;
(function (TokenType) {
    TokenType[TokenType["ERC20"] = 0] = "ERC20";
    TokenType[TokenType["ERC721"] = 1] = "ERC721";
    TokenType[TokenType["ERC1155"] = 2] = "ERC1155";
})(TokenType || (exports.TokenType = TokenType = {}));
var CommitmentType;
(function (CommitmentType) {
    // V1
    CommitmentType["LegacyEncryptedCommitment"] = "LegacyEncryptedCommitment";
    CommitmentType["LegacyGeneratedCommitment"] = "LegacyGeneratedCommitment";
    // V2
    CommitmentType["ShieldCommitment"] = "ShieldCommitment";
    CommitmentType["TransactCommitmentV2"] = "TransactCommitmentV2";
    // V3
    CommitmentType["TransactCommitmentV3"] = "TransactCommitmentV3";
})(CommitmentType || (exports.CommitmentType = CommitmentType = {}));
var OutputType;
(function (OutputType) {
    OutputType[OutputType["Transfer"] = 0] = "Transfer";
    OutputType[OutputType["BroadcasterFee"] = 1] = "BroadcasterFee";
    OutputType[OutputType["Change"] = 2] = "Change";
})(OutputType || (exports.OutputType = OutputType = {}));
var RailgunTransactionVersion;
(function (RailgunTransactionVersion) {
    RailgunTransactionVersion["V2"] = "V2";
    RailgunTransactionVersion["V3"] = "V3";
})(RailgunTransactionVersion || (exports.RailgunTransactionVersion = RailgunTransactionVersion = {}));
//# sourceMappingURL=formatted-types.js.map