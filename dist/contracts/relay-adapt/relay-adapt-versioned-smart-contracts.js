"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RelayAdaptVersionedSmartContracts = void 0;
const contract_store_1 = require("../contract-store");
const poi_types_1 = require("../../models/poi-types");
const relay_adapt_v2_1 = require("./V2/relay-adapt-v2");
const relay_adapt_v3_1 = require("./V3/relay-adapt-v3");
class RelayAdaptVersionedSmartContracts {
    static getRelayAdaptContract(txidVersion, chain) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return contract_store_1.ContractStore.relayAdaptV2Contracts.getOrThrow(null, chain);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return contract_store_1.ContractStore.relayAdaptV3Contracts.getOrThrow(null, chain);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static populateShieldBaseToken(txidVersion, chain, shieldRequest) {
        return this.getRelayAdaptContract(txidVersion, chain).populateShieldBaseToken(shieldRequest);
    }
    static populateUnshieldBaseToken(txidVersion, chain, transactions, unshieldAddress, random31Bytes, useDummyProof, sendWithPublicWallet) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.relayAdaptV2Contracts.getOrThrow(null, chain);
                return contractV2.populateUnshieldBaseToken(transactions, unshieldAddress, random31Bytes, useDummyProof, sendWithPublicWallet);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractV3 = contract_store_1.ContractStore.relayAdaptV3Contracts.getOrThrow(null, chain);
                return contractV3.populateUnshieldBaseToken(transactions, unshieldAddress, random31Bytes);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static populateCrossContractCalls(txidVersion, chain, unshieldTransactions, crossContractCalls, relayShieldRequests, random31Bytes, isGasEstimate, isBroadcasterTransaction, minGasLimit) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.relayAdaptV2Contracts.getOrThrow(null, chain);
                return contractV2.populateCrossContractCalls(unshieldTransactions, crossContractCalls, relayShieldRequests, random31Bytes, isGasEstimate, isBroadcasterTransaction, minGasLimit);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractV3 = contract_store_1.ContractStore.relayAdaptV3Contracts.getOrThrow(null, chain);
                return contractV3.populateCrossContractCalls(unshieldTransactions, crossContractCalls, relayShieldRequests, random31Bytes, isGasEstimate, isBroadcasterTransaction, minGasLimit);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static populateRelayWithActionData(txidVersion, chain, transactions, actionData) {
        if (txidVersion !== poi_types_1.TXIDVersion.V2_PoseidonMerkle) {
            throw new Error('Prepared RelayAdapt transactions currently support only V2.');
        }
        return contract_store_1.ContractStore.relayAdaptV2Contracts
            .getOrThrow(null, chain)
            .populateRelayWithActionData(transactions, actionData);
    }
    static getRelayAdaptParamsUnshieldBaseToken(txidVersion, chain, dummyUnshieldTransactions, unshieldAddress, random31Bytes, sendWithPublicWallet) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.relayAdaptV2Contracts.getOrThrow(null, chain);
                return contractV2.getRelayAdaptParamsUnshieldBaseToken(dummyUnshieldTransactions, unshieldAddress, random31Bytes, sendWithPublicWallet);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractV3 = contract_store_1.ContractStore.relayAdaptV3Contracts.getOrThrow(null, chain);
                return contractV3.getRelayAdaptParamsUnshieldBaseToken(dummyUnshieldTransactions, unshieldAddress, random31Bytes);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static getRelayAdaptParamsCrossContractCalls(txidVersion, chain, dummyUnshieldTransactions, crossContractCalls, relayShieldRequests, random, isBroadcasterTransaction, minGasLimit) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.relayAdaptV2Contracts.getOrThrow(null, chain);
                return contractV2.getRelayAdaptParamsCrossContractCalls(dummyUnshieldTransactions, crossContractCalls, relayShieldRequests, random, isBroadcasterTransaction, minGasLimit);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractV3 = contract_store_1.ContractStore.relayAdaptV3Contracts.getOrThrow(null, chain);
                return contractV3.getRelayAdaptParamsCrossContractCalls(dummyUnshieldTransactions, crossContractCalls, relayShieldRequests, random, isBroadcasterTransaction, minGasLimit);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static estimateGasWithErrorHandler(txidVersion, provider, transaction) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return relay_adapt_v2_1.RelayAdaptV2Contract.estimateGasWithErrorHandler(provider, transaction);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return relay_adapt_v3_1.RelayAdaptV3Contract.estimateGasWithErrorHandler(provider, transaction);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static getRelayAdaptCallError(txidVersion, receiptLogs) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return relay_adapt_v2_1.RelayAdaptV2Contract.getRelayAdaptCallError(receiptLogs);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return relay_adapt_v3_1.RelayAdaptV3Contract.getRelayAdaptCallError(receiptLogs);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static parseRelayAdaptReturnValue(txidVersion, data) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return relay_adapt_v2_1.RelayAdaptV2Contract.parseRelayAdaptReturnValue(data);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return relay_adapt_v3_1.RelayAdaptV3Contract.parseRelayAdaptReturnValue(data);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
}
exports.RelayAdaptVersionedSmartContracts = RelayAdaptVersionedSmartContracts;
//# sourceMappingURL=relay-adapt-versioned-smart-contracts.js.map