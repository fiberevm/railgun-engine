"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractRailgunTransactionDataFromTransactionRequest = exports.extractFirstNoteERC20AmountMapFromTransactionRequest = void 0;
const poi_types_1 = require("../models/poi-types");
const extract_transaction_data_v2_1 = require("./extract-transaction-data-v2");
const extract_transaction_data_v3_1 = require("./extract-transaction-data-v3");
const extractFirstNoteERC20AmountMapFromTransactionRequest = (txidVersion, chain, transactionRequest, useRelayAdapt, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    switch (txidVersion) {
        case poi_types_1.TXIDVersion.V2_PoseidonMerkle:
            return (0, extract_transaction_data_v2_1.extractFirstNoteERC20AmountMapFromTransactionRequestV2)(chain, transactionRequest, useRelayAdapt, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
        case poi_types_1.TXIDVersion.V3_PoseidonMerkle:
            return (0, extract_transaction_data_v3_1.extractFirstNoteERC20AmountMapFromTransactionRequestV3)(chain, transactionRequest, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
    }
    throw new Error('Unsupported txidVersion');
};
exports.extractFirstNoteERC20AmountMapFromTransactionRequest = extractFirstNoteERC20AmountMapFromTransactionRequest;
const extractRailgunTransactionDataFromTransactionRequest = (txidVersion, chain, transactionRequest, useRelayAdapt, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter) => {
    switch (txidVersion) {
        case poi_types_1.TXIDVersion.V2_PoseidonMerkle:
            return (0, extract_transaction_data_v2_1.extractRailgunTransactionDataFromTransactionRequestV2)(chain, transactionRequest, useRelayAdapt, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
        case poi_types_1.TXIDVersion.V3_PoseidonMerkle:
            return (0, extract_transaction_data_v3_1.extractRailgunTransactionDataFromTransactionRequestV3)(chain, transactionRequest, contractAddress, receivingViewingPrivateKey, receivingRailgunAddressData, tokenDataGetter);
    }
    throw new Error('Unsupported txidVersion');
};
exports.extractRailgunTransactionDataFromTransactionRequest = extractRailgunTransactionDataFromTransactionRequest;
//# sourceMappingURL=extract-transaction-data.js.map