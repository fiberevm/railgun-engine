"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isTransactCommitment = exports.isTransactCommitmentType = exports.isReceiveShieldCommitment = exports.isShieldCommitmentType = exports.convertTransactionStructToCommitmentSummary = void 0;
const V2_events_1 = require("../contracts/railgun-smart-wallet/V2/V2-events");
const V3_events_1 = require("../contracts/railgun-smart-wallet/V3/V3-events");
const formatted_types_1 = require("../models/formatted-types");
const poi_types_1 = require("../models/poi-types");
const is_defined_1 = require("./is-defined");
const convertTransactionStructToCommitmentSummary = (transactionStruct, commitmentIndex) => {
    let commitmentCiphertext;
    if (!(0, is_defined_1.isDefined)(transactionStruct.txidVersion)) {
        throw new Error('txidVersion is not defined in TransactionStruct');
    }
    switch (transactionStruct.txidVersion) {
        case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
            const commitmentCiphertextStruct = transactionStruct.boundParams.commitmentCiphertext[commitmentIndex];
            commitmentCiphertext = V2_events_1.V2Events.formatCommitmentCiphertext(commitmentCiphertextStruct);
            break;
        }
        case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
            const commitmentCiphertextStruct = transactionStruct.boundParams.local.commitmentCiphertext[commitmentIndex];
            commitmentCiphertext = V3_events_1.V3Events.formatCommitmentCiphertext(commitmentCiphertextStruct);
            break;
        }
    }
    const commitmentHash = transactionStruct.commitments[commitmentIndex];
    return {
        commitmentCiphertext,
        commitmentHash,
    };
};
exports.convertTransactionStructToCommitmentSummary = convertTransactionStructToCommitmentSummary;
const isShieldCommitmentType = (commitmentType) => {
    switch (commitmentType) {
        case formatted_types_1.CommitmentType.ShieldCommitment:
        case formatted_types_1.CommitmentType.LegacyGeneratedCommitment:
            return true;
        case formatted_types_1.CommitmentType.TransactCommitmentV2:
        case formatted_types_1.CommitmentType.TransactCommitmentV3:
        case formatted_types_1.CommitmentType.LegacyEncryptedCommitment:
            return false;
    }
    return false;
};
exports.isShieldCommitmentType = isShieldCommitmentType;
const isReceiveShieldCommitment = (receiveCommitment) => {
    return (0, exports.isShieldCommitmentType)(receiveCommitment.commitmentType);
};
exports.isReceiveShieldCommitment = isReceiveShieldCommitment;
const isTransactCommitmentType = (commitmentType) => {
    switch (commitmentType) {
        case formatted_types_1.CommitmentType.TransactCommitmentV2:
        case formatted_types_1.CommitmentType.TransactCommitmentV3:
        case formatted_types_1.CommitmentType.LegacyEncryptedCommitment:
            return true;
        case formatted_types_1.CommitmentType.ShieldCommitment:
        case formatted_types_1.CommitmentType.LegacyGeneratedCommitment:
            return false;
    }
    return false;
};
exports.isTransactCommitmentType = isTransactCommitmentType;
const isTransactCommitment = (commitment) => {
    return (0, exports.isTransactCommitmentType)(commitment.commitmentType);
};
exports.isTransactCommitment = isTransactCommitment;
//# sourceMappingURL=commitment.js.map