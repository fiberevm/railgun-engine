"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RailgunVersionedSmartContracts = void 0;
const constants_1 = require("../../utils/constants");
const contract_store_1 = require("../contract-store");
const poi_types_1 = require("../../models/poi-types");
class RailgunVersionedSmartContracts {
    static zeroUnshieldChangeCiphertext = {
        encryptedBundle: [constants_1.ZERO_32_BYTE_VALUE, constants_1.ZERO_32_BYTE_VALUE, constants_1.ZERO_32_BYTE_VALUE],
        shieldKey: constants_1.ZERO_32_BYTE_VALUE,
    };
    static getAccumulator(txidVersion, chain) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.getOrThrow(null, chain);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static getVerifier(txidVersion, chain) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
                return contractV2;
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return contract_store_1.ContractStore.poseidonMerkleVerifierV3Contracts.getOrThrow(null, chain);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static getShieldApprovalContract(txidVersion, chain) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                return contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                return contract_store_1.ContractStore.tokenVaultV3Contracts.getOrThrow(null, chain);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
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
    static getHistoricalEvents(txidVersion, chain, initialStartBlock, latestBlock, getNextStartBlockFromValidMerkletree, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, setLastSyncedBlock) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
                return contractV2.getHistoricalEvents(initialStartBlock, latestBlock, getNextStartBlockFromValidMerkletree, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, setLastSyncedBlock);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractV3 = contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.getOrThrow(null, chain);
                return contractV3.getHistoricalEvents(initialStartBlock, latestBlock, getNextStartBlockFromValidMerkletree, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, setLastSyncedBlock);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static setTreeUpdateListeners(txidVersion, chain, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, triggerWalletBalanceDecryptions) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
                return contractV2.setTreeUpdateListeners(eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractV3 = contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.getOrThrow(null, chain);
                return contractV3.setTreeUpdateListeners(eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, triggerWalletBalanceDecryptions);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static fees(txidVersion, chain) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
                return contractV2.fees();
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractTokenVaultV3 = contract_store_1.ContractStore.tokenVaultV3Contracts.getOrThrow(null, chain);
                return contractTokenVaultV3.fees();
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static getNFTTokenData(txidVersion, chain, tokenHash) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
                return contractV2.getNFTTokenData(tokenHash);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractTokenVaultV3 = contract_store_1.ContractStore.tokenVaultV3Contracts.getOrThrow(null, chain);
                return contractTokenVaultV3.getNFTTokenData(tokenHash);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static generateShield(txidVersion, chain, shieldRequests) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
                return contractV2.generateShield(shieldRequests);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const contractV3PoseidonMerkleVerifier = contract_store_1.ContractStore.poseidonMerkleVerifierV3Contracts.getOrThrow(null, chain);
                const emptyGlobalBoundParams = {
                    minGasPrice: 0n,
                    chainID: chain.id,
                    senderCiphertext: '0x',
                    to: constants_1.ZERO_ADDRESS,
                    data: '0x',
                };
                return contractV3PoseidonMerkleVerifier.generateExecute([], shieldRequests, emptyGlobalBoundParams, this.zeroUnshieldChangeCiphertext);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static generateTransact(txidVersion, chain, transactions) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle: {
                const contractV2 = contract_store_1.ContractStore.railgunSmartWalletContracts.getOrThrow(null, chain);
                return contractV2.generateTransact(transactions);
            }
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle: {
                const transactionsV3 = RailgunVersionedSmartContracts.convertToV3TransactStructs(transactions);
                if (!transactions.length) {
                    throw new Error('No transactions to transact');
                }
                const globalBoundParams = transactions[0].boundParams.global;
                const contractV3PoseidonMerkleVerifier = contract_store_1.ContractStore.poseidonMerkleVerifierV3Contracts.getOrThrow(null, chain);
                return contractV3PoseidonMerkleVerifier.generateExecute(transactionsV3, [], globalBoundParams, this.zeroUnshieldChangeCiphertext);
            }
        }
        throw new Error('Unsupported txidVersion');
    }
    static convertToV3TransactStructs(transactions) {
        return transactions.map((transaction) => ({
            proof: transaction.proof,
            merkleRoot: transaction.merkleRoot,
            nullifiers: transaction.nullifiers,
            commitments: transaction.commitments,
            unshieldPreimage: transaction.unshieldPreimage,
            boundParams: {
                treeNumber: transaction.boundParams.local.treeNumber,
                commitmentCiphertext: transaction.boundParams.local.commitmentCiphertext,
            },
        }));
    }
}
exports.RailgunVersionedSmartContracts = RailgunVersionedSmartContracts;
//# sourceMappingURL=railgun-versioned-smart-contracts.js.map