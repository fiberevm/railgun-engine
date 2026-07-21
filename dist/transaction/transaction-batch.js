"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransactionBatch = exports.GAS_ESTIMATE_VARIANCE_DUMMY_TO_ACTUAL_TRANSACTION = void 0;
const bytes_1 = require("../utils/bytes");
const simple_solutions_1 = require("../solutions/simple-solutions");
const transaction_1 = require("./transaction");
const txo_types_1 = require("../models/txo-types");
const formatted_types_1 = require("../models/formatted-types");
const complex_solutions_1 = require("../solutions/complex-solutions");
const utxos_1 = require("../solutions/utxos");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const spending_group_extractor_1 = require("../solutions/spending-group-extractor");
const stringify_1 = require("../utils/stringify");
const transact_note_1 = require("../note/transact-note");
const models_1 = require("../models");
const note_util_1 = require("../note/note-util");
const wallet_1 = require("../wallet");
const is_defined_1 = require("../utils/is-defined");
const memo_1 = require("../note/memo");
const wallet_info_1 = __importDefault(require("../wallet/wallet-info"));
const constants_1 = require("../utils/constants");
const prepared_transaction_1 = require("./prepared-transaction");
exports.GAS_ESTIMATE_VARIANCE_DUMMY_TO_ACTUAL_TRANSACTION = 9000;
class TransactionBatch {
    adaptID = {
        contract: '0x0000000000000000000000000000000000000000',
        parameters: bytes_1.HashZero,
    };
    chain;
    outputs = [];
    unshieldDataMap = {};
    overallBatchMinGasPrice;
    /**
     * Create TransactionBatch Object
     * @param chain - chain type/id of network
     */
    constructor(chain, overallBatchMinGasPrice = BigInt(0)) {
        this.chain = chain;
        this.overallBatchMinGasPrice = overallBatchMinGasPrice;
    }
    addOutput(output) {
        this.outputs.push(output);
    }
    resetOutputs() {
        this.outputs = [];
    }
    addUnshieldData(unshieldData) {
        const tokenHash = (0, note_util_1.getTokenDataHash)(unshieldData.tokenData);
        if ((0, is_defined_1.isDefined)(this.unshieldDataMap[tokenHash])) {
            throw new Error('You may only call .addUnshieldData once per token for a given TransactionBatch.');
        }
        if (unshieldData.value === 0n) {
            throw new Error('Unshield value must be greater than 0.');
        }
        this.unshieldDataMap[tokenHash] = unshieldData;
    }
    resetUnshieldData() {
        this.unshieldDataMap = {};
    }
    unshieldTotal(tokenHash) {
        return (0, is_defined_1.isDefined)(this.unshieldDataMap[tokenHash])
            ? this.unshieldDataMap[tokenHash].value
            : BigInt(0);
    }
    setAdaptID(adaptID) {
        this.adaptID = adaptID;
    }
    getOutputTokenDatas() {
        const tokenHashes = [];
        const tokenDatas = [];
        const outputTokenDatas = this.outputs.map((output) => output.tokenData);
        const unshieldTokenDatas = Object.values(this.unshieldDataMap).map((output) => output.tokenData);
        for (const tokenData of [...outputTokenDatas, ...unshieldTokenDatas]) {
            const tokenHash = (0, note_util_1.getTokenDataHash)(tokenData);
            if (!tokenHashes.includes(tokenHash)) {
                tokenHashes.push(tokenHash);
                tokenDatas.push(tokenData);
            }
        }
        return tokenDatas;
    }
    async generateValidSpendingSolutionGroupsAllOutputs(wallet, txidVersion, originShieldTxidForSpendabilityOverride) {
        const tokenDatas = this.getOutputTokenDatas();
        const spendingSolutionGroupsPerToken = await Promise.all(tokenDatas.map((tokenData) => this.generateValidSpendingSolutionGroups(wallet, txidVersion, tokenData, originShieldTxidForSpendabilityOverride)));
        return spendingSolutionGroupsPerToken.flat();
    }
    /**
     * Generates spending solution groups for outputs
     * @param wallet - wallet to spend from
     */
    async generateValidSpendingSolutionGroups(wallet, txidVersion, tokenData, originShieldTxidForSpendabilityOverride) {
        const tokenHash = (0, note_util_1.getTokenDataHash)(tokenData);
        const tokenOutputs = this.outputs.filter((output) => output.tokenHash === tokenHash);
        const outputTotal = transact_note_1.TransactNote.calculateTotalNoteValues(tokenOutputs);
        // Calculate total required to be supplied by UTXOs
        const totalRequired = outputTotal + this.unshieldTotal(tokenHash);
        const balanceBucketFilter = [txo_types_1.WalletBalanceBucket.Spendable];
        const treeSortedBalances = await wallet.balancesByTreeForToken(txidVersion, this.chain, tokenHash, balanceBucketFilter, originShieldTxidForSpendabilityOverride);
        const tokenBalance = wallet_1.AbstractWallet.tokenBalanceAcrossAllTrees(treeSortedBalances);
        // Check if wallet balance is enough to cover this transaction
        if (totalRequired > tokenBalance) {
            debugger_1.default.log(`Token balance too low: token hash ${tokenHash}`);
            debugger_1.default.log(`totalRequired: ${totalRequired}`);
            debugger_1.default.log(`tokenBalance: ${tokenBalance}`);
            switch (tokenData.tokenType) {
                case formatted_types_1.TokenType.ERC20: {
                    const broadcasterFeeOutput = tokenOutputs.find((output) => output.outputType === formatted_types_1.OutputType.BroadcasterFee);
                    const amountRequiredMessage = broadcasterFeeOutput
                        ? `${totalRequired.toString()} (includes ${broadcasterFeeOutput.value.toString()} Broadcaster Fee)`
                        : totalRequired.toString();
                    if ((0, is_defined_1.isDefined)(originShieldTxidForSpendabilityOverride)) {
                        throw new Error(`RAILGUN balance too low for ${tokenData.tokenAddress} from shield origin txid ${originShieldTxidForSpendabilityOverride}. Amount required: ${amountRequiredMessage}. Amount available: ${tokenBalance.toString()}.`);
                    }
                    throw new Error(`RAILGUN spendable private balance too low for ${tokenData.tokenAddress}. Amount required: ${amountRequiredMessage}. Balance: ${tokenBalance.toString()}.`);
                }
                case formatted_types_1.TokenType.ERC721:
                case formatted_types_1.TokenType.ERC1155:
                    throw new Error(`RAILGUN spendable private NFT balance too low.`);
            }
        }
        // If single group possible, return it.
        const singleSpendingSolutionGroup = this.createSimpleSpendingSolutionGroupsIfPossible(tokenData, tokenHash, tokenOutputs, treeSortedBalances, totalRequired);
        if (singleSpendingSolutionGroup) {
            return [singleSpendingSolutionGroup];
        }
        // Single group not possible - need a more complex model.
        return this.createComplexSatisfyingSpendingSolutionGroups(tokenData, tokenOutputs, treeSortedBalances);
    }
    createSimpleSpendingSolutionGroupsIfPossible(tokenData, tokenHash, tokenOutputs, treeSortedBalances, totalRequired) {
        try {
            const { utxos, spendingTree, amount } = TransactionBatch.createSimpleSatisfyingUTXOGroup(treeSortedBalances, totalRequired);
            if (amount < totalRequired) {
                throw new Error('Could not find UTXOs to satisfy required amount.');
            }
            const unshieldValue = this.unshieldTotal(tokenHash);
            const spendingSolutionGroup = {
                utxos,
                spendingTree,
                unshieldValue,
                tokenOutputs,
                tokenData,
            };
            return spendingSolutionGroup;
        }
        catch (err) {
            return undefined;
        }
    }
    /**
     * Finds exact group of UTXOs above required amount.
     */
    static createSimpleSatisfyingUTXOGroup(treeSortedBalances, amountRequired) {
        let spendingTree;
        let utxos;
        // Find first tree with spending solutions.
        for (const [tree, treeBalance] of treeSortedBalances.entries()) {
            if (!(0, is_defined_1.isDefined)(treeBalance))
                continue;
            const solutions = (0, simple_solutions_1.findExactSolutionsOverTargetValue)(treeBalance, amountRequired);
            if (!(0, is_defined_1.isDefined)(solutions))
                continue;
            spendingTree = tree;
            utxos = solutions;
        }
        if (utxos == null || spendingTree == null) {
            throw new Error('No spending solutions found. Must use complex UTXO aggregator.');
        }
        return {
            utxos,
            spendingTree,
            amount: (0, utxos_1.calculateTotalSpend)(utxos),
        };
    }
    /**
     * Finds array of UTXOs groups that satisfies the required amount, excluding an already-used array of UTXO IDs.
     */
    createComplexSatisfyingSpendingSolutionGroups(tokenData, tokenOutputs, treeSortedBalances) {
        const spendingSolutionGroups = [];
        const excludedUTXOIDPositions = [];
        const remainingTokenOutputs = [...tokenOutputs];
        while (remainingTokenOutputs.length > 0) {
            const transactSpendingSolutionGroups = (0, complex_solutions_1.createSpendingSolutionsForValue)(treeSortedBalances, remainingTokenOutputs, excludedUTXOIDPositions, false);
            if (!transactSpendingSolutionGroups.length) {
                break;
            }
            spendingSolutionGroups.push(...transactSpendingSolutionGroups);
        }
        if (remainingTokenOutputs.length > 0) {
            throw new Error('Could not find enough UTXOs to satisfy transfer.');
        }
        const tokenHash = (0, note_util_1.getTokenDataHash)(tokenData);
        if ((0, is_defined_1.isDefined)(this.unshieldDataMap[tokenHash])) {
            const value = this.unshieldTotal(tokenHash);
            const nullUnshieldNote = transact_note_1.TransactNote.createNullUnshieldNote(tokenData, value);
            const unshieldTokenOutputs = [nullUnshieldNote];
            const unshieldSpendingSolutionGroups = (0, complex_solutions_1.createSpendingSolutionsForValue)(treeSortedBalances, unshieldTokenOutputs, excludedUTXOIDPositions, true);
            if (!unshieldSpendingSolutionGroups.length) {
                throw new Error('Could not find enough UTXOs to satisfy unshield.');
            }
            spendingSolutionGroups.push(...unshieldSpendingSolutionGroups);
        }
        return spendingSolutionGroups;
    }
    static getChangeOutput(wallet, spendingSolutionGroup) {
        const totalIn = (0, utxos_1.calculateTotalSpend)(spendingSolutionGroup.utxos);
        const totalOutputNoteValues = transact_note_1.TransactNote.calculateTotalNoteValues(spendingSolutionGroup.tokenOutputs);
        const totalOut = totalOutputNoteValues + spendingSolutionGroup.unshieldValue;
        const change = totalIn - totalOut;
        if (change < 0n) {
            throw new Error('Negative change value - transaction not possible.');
        }
        const requiresChangeOutput = change > 0n;
        const changeOutput = requiresChangeOutput
            ? transact_note_1.TransactNote.createTransfer(wallet.addressKeys, // Receiver
            wallet.addressKeys, // Sender
            change, spendingSolutionGroup.tokenData, true, // showSenderAddressToRecipient
            formatted_types_1.OutputType.Change, undefined)
            : undefined;
        return changeOutput;
    }
    /**
     * Prepare exact unsigned inputs without asking the wallet to sign or generating proofs.
     * Prepared data includes private witness fields and must be stored as sensitive data.
     * @param wallet - wallet to spend from
     * @param txidVersion - transaction protocol version
     * @param encryptionKey - encryption key for wallet
     * @returns prepared transactions that can be authorized and proved later
     */
    async prepareTransactions(wallet, txidVersion, encryptionKey, originShieldTxidForSpendabilityOverride) {
        const spendingSolutionGroups = await this.generateValidSpendingSolutionGroupsAllOutputs(wallet, txidVersion, originShieldTxidForSpendabilityOverride);
        debugger_1.default.log('Actual spending solution groups:');
        debugger_1.default.log((0, stringify_1.stringifySafe)((0, spending_group_extractor_1.serializeExtractedSpendingSolutionGroupsData)((0, spending_group_extractor_1.extractSpendingSolutionGroupsData)(spendingSolutionGroups))));
        const transactionDatas = spendingSolutionGroups.map((spendingSolutionGroup) => {
            const changeOutput = TransactionBatch.getChangeOutput(wallet, spendingSolutionGroup);
            const transaction = this.generateTransactionForSpendingSolutionGroup(spendingSolutionGroup, changeOutput);
            const outputTypes = spendingSolutionGroup.tokenOutputs.map((output) => output.outputType);
            if (changeOutput) {
                outputTypes.push(formatted_types_1.OutputType.Change);
            }
            return { transaction, outputTypes };
        });
        const { walletSource } = wallet_info_1.default;
        const orderedOutputTypes = transactionDatas.map(({ outputTypes }) => outputTypes).flat();
        const globalBoundParams = {
            minGasPrice: this.overallBatchMinGasPrice,
            chainID: this.chain.id,
            senderCiphertext: memo_1.Memo.createSenderAnnotationEncryptedV3(walletSource, orderedOutputTypes, wallet.viewingKeyPair.privateKey),
            to: constants_1.ZERO_ADDRESS, // TODO-V3: Add RelayAdapt contract address
            data: '0x', // TODO-V3: Add RelayAdapt encoded calldata
        };
        const preparedTransactions = [];
        for (const { transaction } of transactionDatas) {
            // Preparing serially preserves existing output and progress ordering.
            // eslint-disable-next-line no-await-in-loop
            const preparedTransaction = await transaction.generatePreparedTransaction(wallet, txidVersion, encryptionKey, globalBoundParams);
            preparedTransactions.push(preparedTransaction);
        }
        return { preparedTransactions };
    }
    /**
     * Sign and prove requests returned by prepareTransactions without rebuilding transaction data.
     */
    // eslint-disable-next-line class-methods-use-this
    async generateTransactionsFromPrepared(prover, wallet, encryptionKey, preparedTransactions, progressCallback) {
        const provedTransactions = [];
        for (let index = 0; index < preparedTransactions.length; index += 1) {
            const preparedTransaction = preparedTransactions[index];
            if (preparedTransaction.txidVersion === models_1.TXIDVersion.V2_PoseidonMerkle) {
                (0, prepared_transaction_1.assertPreparedRailgunTransactionV2)(preparedTransaction);
            }
            const signingData = transaction_1.Transaction.getSigningData(preparedTransaction);
            // Delegated signers can now bind the signature to exact bound params and unshield output.
            // eslint-disable-next-line no-await-in-loop
            const signature = await wallet.sign(preparedTransaction.publicInputs, encryptionKey, signingData);
            const preTransactionProofProgressStatus = `Generating transaction proof ${index + 1}/${preparedTransactions.length}...`;
            // eslint-disable-next-line no-await-in-loop
            const provedTransaction = await transaction_1.Transaction.generateProvedTransactionFromPrepared(prover, preparedTransaction, signature, (progress) => progressCallback(progress, preTransactionProofProgressStatus));
            provedTransactions.push(provedTransaction);
        }
        return { provedTransactions };
    }
    /**
     * Generate proofs and return serialized transactions
     * @param prover - prover to use
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    async generateTransactions(prover, wallet, txidVersion, encryptionKey, progressCallback, _shouldGeneratePreTransactionPOIs, originShieldTxidForSpendabilityOverride) {
        const { preparedTransactions } = await this.prepareTransactions(wallet, txidVersion, encryptionKey, originShieldTxidForSpendabilityOverride);
        return this.generateTransactionsFromPrepared(prover, wallet, encryptionKey, preparedTransactions, progressCallback);
    }
    static logDummySpendingSolutionGroupsSummary(spendingSolutionGroups) {
        const spendingSolutionGroupsSummaries = spendingSolutionGroups.map((spendingSolutionGroup) => {
            const nullifiers = spendingSolutionGroup.utxos.length;
            const commitments = spendingSolutionGroup.tokenOutputs.length;
            return `${nullifiers}x${commitments}`;
        });
        debugger_1.default.log(`Dummy spending solution groups - circuits ${spendingSolutionGroupsSummaries.join(', ')} (excluding unshields)`);
        debugger_1.default.log((0, stringify_1.stringifySafe)((0, spending_group_extractor_1.serializeExtractedSpendingSolutionGroupsData)((0, spending_group_extractor_1.extractSpendingSolutionGroupsData)(spendingSolutionGroups))));
    }
    /**
     * Generate dummy proofs and return serialized transactions
     * @param wallet - wallet to spend from
     * @param encryptionKey - encryption key for wallet
     * @returns serialized transaction
     */
    async generateDummyTransactions(prover, wallet, txidVersion, encryptionKey, originShieldTxidForSpendabilityOverride) {
        const spendingSolutionGroups = await this.generateValidSpendingSolutionGroupsAllOutputs(wallet, txidVersion, originShieldTxidForSpendabilityOverride);
        TransactionBatch.logDummySpendingSolutionGroupsSummary(spendingSolutionGroups);
        const globalBoundParams = {
            minGasPrice: this.overallBatchMinGasPrice,
            chainID: this.chain.id,
            senderCiphertext: '0x',
            to: constants_1.ZERO_ADDRESS, // TODO-V3: Add RelayAdapt contract address
            data: '0x', // TODO-V3: Add RelayAdapt encoded calldata
        };
        const dummyProvedTransactions = [];
        for (const spendingSolutionGroup of spendingSolutionGroups) {
            const changeOutput = TransactionBatch.getChangeOutput(wallet, spendingSolutionGroup);
            const transaction = this.generateTransactionForSpendingSolutionGroup(spendingSolutionGroup, changeOutput);
            // eslint-disable-next-line no-await-in-loop
            const transactionRequest = await transaction.generateTransactionRequest(wallet, txidVersion, encryptionKey, globalBoundParams);
            // eslint-disable-next-line no-await-in-loop
            const dummyProvedTransaction = await transaction.generateDummyProvedTransaction(prover, transactionRequest);
            dummyProvedTransactions.push(dummyProvedTransaction);
        }
        return dummyProvedTransactions;
    }
    generateTransactionForSpendingSolutionGroup(spendingSolutionGroup, changeOutput) {
        const { spendingTree, utxos, tokenOutputs, unshieldValue, tokenData } = spendingSolutionGroup;
        const allOutputs = changeOutput ? [...tokenOutputs, changeOutput] : tokenOutputs;
        const transaction = new transaction_1.Transaction(this.chain, tokenData, spendingTree, utxos, allOutputs, this.adaptID);
        const tokenHash = (0, note_util_1.getTokenDataHash)(tokenData);
        if ((0, is_defined_1.isDefined)(this.unshieldDataMap[tokenHash]) && unshieldValue > 0) {
            transaction.addUnshieldData(this.unshieldDataMap[tokenHash], unshieldValue);
        }
        return transaction;
    }
}
exports.TransactionBatch = TransactionBatch;
//# sourceMappingURL=transaction-batch.js.map