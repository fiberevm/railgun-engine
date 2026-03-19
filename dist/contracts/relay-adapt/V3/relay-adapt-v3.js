"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RelayAdaptV3Contract = exports.MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT = exports.RETURN_DATA_STRING_PREFIX = exports.RETURN_DATA_RELAY_ADAPT_STRING_PREFIX = void 0;
const ethers_1 = require("ethers");
const abi_1 = require("../../../abi/abi");
const note_util_1 = require("../../../note/note-util");
const constants_1 = require("../../../utils/constants");
const relay_adapt_helper_1 = require("../relay-adapt-helper");
const debugger_1 = __importDefault(require("../../../debugger/debugger"));
var RelayAdaptEvent;
(function (RelayAdaptEvent) {
    RelayAdaptEvent["CallError"] = "CallError";
})(RelayAdaptEvent || (RelayAdaptEvent = {}));
exports.RETURN_DATA_RELAY_ADAPT_STRING_PREFIX = '0x5c0dee5d';
exports.RETURN_DATA_STRING_PREFIX = '0x08c379a0';
// A low (or undefined) gas limit can cause the Relay Adapt module to fail.
// Set a high default that can be overridden by a developer.
exports.MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT = BigInt(3_200_000);
class RelayAdaptV3Contract {
    contract;
    address;
    /**
     * Connect to Railgun instance on network
     * @param relayAdaptV3ContractAddress - address of Railgun relay adapt contract
     * @param provider - Network provider
     */
    constructor(relayAdaptV3ContractAddress, provider) {
        this.address = relayAdaptV3ContractAddress;
        this.contract = new ethers_1.Contract(relayAdaptV3ContractAddress, abi_1.ABIRelayAdapt, // TODO-V3
        provider);
    }
    async populateShieldBaseToken(shieldRequest) {
        throw new Error('Not implemented.');
        const orderedCalls = await Promise.all([
            this.contract.wrapBase.populateTransaction(shieldRequest.preimage.value),
            this.populateRelayShields([shieldRequest]),
        ]);
        return this.populateRelayMulticall(orderedCalls, {
            value: shieldRequest.preimage.value,
        });
    }
    async populateMulticall(calls, shieldRequests) {
        throw new Error('Not implemented.');
        const orderedCalls = await this.getOrderedCallsForCrossContractCalls(calls, shieldRequests);
        return this.populateRelayMulticall(orderedCalls, {});
    }
    /**
     * @returns Populated transaction
     */
    populateRelayShields(shieldRequests) {
        throw new Error('Not implemented.');
        return this.contract.shield.populateTransaction(shieldRequests);
    }
    async getOrderedCallsForUnshieldBaseToken(unshieldAddress) {
        throw new Error('Not implemented.');
        // Use 0x00 address ERC20 to represent base token.
        const baseTokenData = (0, note_util_1.getTokenDataERC20)(constants_1.ZERO_ADDRESS);
        // Automatically unwraps and unshields all tokens.
        const value = 0n;
        const baseTokenTransfer = {
            token: baseTokenData,
            to: unshieldAddress,
            value,
        };
        return Promise.all([
            this.contract.unwrapBase.populateTransaction(value),
            this.populateRelayTransfers([baseTokenTransfer]),
        ]);
    }
    async getRelayAdaptParamsUnshieldBaseToken(dummyTransactions, unshieldAddress, random) {
        throw new Error('Not implemented.');
        const orderedCalls = await this.getOrderedCallsForUnshieldBaseToken(unshieldAddress);
        const requireSuccess = true;
        return relay_adapt_helper_1.RelayAdaptHelper.getRelayAdaptParams(dummyTransactions, random, requireSuccess, orderedCalls);
    }
    async populateUnshieldBaseToken(transactions, unshieldAddress, random31Bytes) {
        throw new Error('Not implemented.');
        const orderedCalls = await this.getOrderedCallsForUnshieldBaseToken(unshieldAddress);
        const requireSuccess = true;
        return this.populateRelay(transactions, random31Bytes, requireSuccess, orderedCalls, {});
    }
    /**
     * @returns Populated transaction
     */
    populateRelayTransfers(transfersData) {
        throw new Error('Not implemented.');
        return this.contract.transfer.populateTransaction(transfersData);
    }
    async getOrderedCallsForCrossContractCalls(crossContractCalls, relayShieldRequests) {
        throw new Error('Not implemented.');
        const orderedCallPromises = [...crossContractCalls];
        if (relayShieldRequests.length) {
            orderedCallPromises.push(await this.populateRelayShields(relayShieldRequests));
        }
        return orderedCallPromises;
    }
    static shouldRequireSuccessForCrossContractCalls(isGasEstimate, isBroadcasterTransaction) {
        throw new Error('Not implemented.');
        // If the cross contract calls (multicalls) fail, the Broadcaster Fee and Shields should continue to process.
        // We should only !requireSuccess for production broadcaster transactions (not gas estimates).
        const continueAfterMulticallFailure = isBroadcasterTransaction && !isGasEstimate;
        return !continueAfterMulticallFailure;
    }
    async getRelayAdaptParamsCrossContractCalls(dummyUnshieldTransactions, crossContractCalls, relayShieldRequests, random, isBroadcasterTransaction, minGasLimit) {
        throw new Error('Not implemented.');
        const orderedCalls = await this.getOrderedCallsForCrossContractCalls(crossContractCalls, relayShieldRequests);
        // Adapt params not required for gas estimates.
        const isGasEstimate = false;
        const requireSuccess = RelayAdaptV3Contract.shouldRequireSuccessForCrossContractCalls(isGasEstimate, isBroadcasterTransaction);
        const minimumGasLimit = minGasLimit ?? exports.MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT;
        const minGasLimitForContract = RelayAdaptV3Contract.getMinimumGasLimitForContract(minimumGasLimit);
        return relay_adapt_helper_1.RelayAdaptHelper.getRelayAdaptParams(dummyUnshieldTransactions, random, requireSuccess, orderedCalls, minGasLimitForContract);
    }
    async populateCrossContractCalls(unshieldTransactions, crossContractCalls, relayShieldRequests, random31Bytes, isGasEstimate, isBroadcasterTransaction, minGasLimit) {
        throw new Error('Not implemented.');
        const orderedCalls = await this.getOrderedCallsForCrossContractCalls(crossContractCalls, relayShieldRequests);
        const requireSuccess = RelayAdaptV3Contract.shouldRequireSuccessForCrossContractCalls(isGasEstimate, isBroadcasterTransaction);
        const minimumGasLimit = minGasLimit ?? exports.MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT;
        const minGasLimitForContract = RelayAdaptV3Contract.getMinimumGasLimitForContract(minimumGasLimit);
        const populatedTransaction = await this.populateRelay(unshieldTransactions, random31Bytes, requireSuccess, orderedCalls, {}, minGasLimitForContract);
        // Set default gas limit for cross-contract calls.
        populatedTransaction.gasLimit = minimumGasLimit;
        return populatedTransaction;
    }
    static getMinimumGasLimitForContract(minimumGasLimit) {
        throw new Error('Not implemented.');
        // Contract call needs ~50,000-150,000 less gas than the gasLimit setting.
        // This can be more if there are complex UTXO sets for the unshield.
        return minimumGasLimit - 150000n;
    }
    static async estimateGasWithErrorHandler(provider, transaction) {
        throw new Error('Not implemented.');
        try {
            const gasEstimate = await provider.estimateGas(transaction);
            return gasEstimate;
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error thrown from estimateGas', { cause });
            }
            const { callFailedIndexString, errorMessage } = RelayAdaptV3Contract.extractGasEstimateCallFailedIndexAndErrorText(cause.message);
            throw new Error(`RelayAdapt multicall failed at index ${callFailedIndexString} with ${errorMessage}`);
        }
    }
    static extractGasEstimateCallFailedIndexAndErrorText(errMessage) {
        throw new Error('Not implemented.');
        try {
            // Sample error text from ethers v6.4.0: 'execution reverted (unknown custom error) (action="estimateGas", data="0x5c0dee5d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000", reason=null, transaction={ "data": "0x28223a77000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000…00000000004640cd6086ade3e984b011b4e8c7cab9369b90499ab88222e673ec1ae4d2c3bf78ae96e95f9171653e5b1410273269edd64a0ab792a5d355093caa9cb92406125c7803a48028503783f2ab5e84f0ea270ce770860e436b77c942ed904a5d577d021cf0fd936183e0298175679d63d73902e116484e10c7b558d4dc84e113380500000000000000000000000000000000000000000000000000000000", "from": "0x000000000000000000000000000000000000dEaD", "to": "0x0355B7B8cb128fA5692729Ab3AAa199C1753f726" }, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.4.0)'
            const prefixSplit = ` (action="estimateGas", data="`;
            const splitResult = errMessage.split(prefixSplit);
            const callFailedMessage = splitResult[0]; // execution reverted (unknown custom error)
            const dataMessage = splitResult[1].split(`"`)[0]; // 0x5c0dee5d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000
            const parsedDataMessage = this.parseRelayAdaptReturnValue(dataMessage);
            const callFailedIndexString = parsedDataMessage?.callIndex?.toString() ?? 'UNKNOWN';
            return {
                callFailedIndexString,
                errorMessage: `'${callFailedMessage}': ${parsedDataMessage?.error ?? dataMessage}`,
            };
        }
        catch (err) {
            return {
                callFailedIndexString: 'UNKNOWN',
                errorMessage: `error: ${errMessage}`,
            };
        }
    }
    /**
     * Generates Relay multicall given a list of ordered calls.
     * @returns populated transaction
     */
    async populateRelayMulticall(calls, overrides) {
        throw new Error('Not implemented.');
        // Always requireSuccess when there is no Broadcaster payment.
        const requireSuccess = true;
        const populatedTransaction = await this.contract.multicall.populateTransaction(requireSuccess, relay_adapt_helper_1.RelayAdaptHelper.formatCalls(calls), overrides);
        return populatedTransaction;
    }
    /**
     * Generates Relay multicall given a list of transactions and ordered calls.
     * @returns populated transaction
     */
    async populateRelay(transactions, random31Bytes, requireSuccess, calls, overrides, minimumGasLimit = BigInt(0)) {
        throw new Error('Not implemented.');
        const actionData = relay_adapt_helper_1.RelayAdaptHelper.getActionData(random31Bytes, requireSuccess, calls, minimumGasLimit);
        const populatedTransaction = await this.contract.relay.populateTransaction(transactions, actionData, overrides);
        return populatedTransaction;
    }
    static getCallErrorTopic() {
        throw new Error('Not implemented.');
        const iface = new ethers_1.Interface(abi_1.ABIRelayAdapt);
        return iface.encodeFilterTopics(RelayAdaptEvent.CallError, [])[0];
    }
    static getRelayAdaptCallError(receiptLogs) {
        const topic = this.getCallErrorTopic();
        try {
            for (const log of receiptLogs) {
                if (log.topics[0] === topic) {
                    const parsed = this.customRelayAdaptErrorParse(log.data);
                    if (parsed) {
                        return parsed.error;
                    }
                }
            }
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error thrown from getRelayAdaptCallError.', { cause });
            }
            const err = new Error('Relay Adapt log parsing error', { cause });
            debugger_1.default.error(err);
            throw err;
        }
        return undefined;
    }
    static parseRelayAdaptReturnValue(returnValue) {
        if (returnValue.match(exports.RETURN_DATA_RELAY_ADAPT_STRING_PREFIX)) {
            const strippedReturnValue = returnValue.replace(exports.RETURN_DATA_RELAY_ADAPT_STRING_PREFIX, '0x');
            return this.customRelayAdaptErrorParse(strippedReturnValue);
        }
        if (returnValue.match(exports.RETURN_DATA_STRING_PREFIX)) {
            return { error: this.parseRelayAdaptStringError(returnValue) };
        }
        return {
            error: `Not a RelayAdapt return value: must be prefixed with ${exports.RETURN_DATA_RELAY_ADAPT_STRING_PREFIX} or ${exports.RETURN_DATA_STRING_PREFIX}`,
        };
    }
    static customRelayAdaptErrorParse(data) {
        // Force parse as bytes
        const decoded = ethers_1.AbiCoder.defaultAbiCoder().decode(['uint256 callIndex', 'bytes revertReason'], data);
        const callIndex = Number(decoded[0]);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        const revertReasonBytes = decoded[1];
        // Map function to try parsing bytes as string
        const error = this.parseRelayAdaptStringError(revertReasonBytes);
        return { callIndex, error };
    }
    static parseRelayAdaptStringError(revertReason) {
        if (revertReason.match(exports.RETURN_DATA_STRING_PREFIX)) {
            const strippedReturnValue = revertReason.replace(exports.RETURN_DATA_STRING_PREFIX, '0x');
            const result = ethers_1.AbiCoder.defaultAbiCoder().decode(['string'], strippedReturnValue);
            return result[0];
        }
        try {
            const utf8 = (0, ethers_1.toUtf8String)(revertReason);
            if (utf8.length === 0) {
                throw new Error('No utf8 string parsed from revert reason.');
            }
            return utf8;
        }
        catch (err) {
            // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
            return `Unknown Relay Adapt error: ${err?.message ?? err}`;
        }
    }
}
exports.RelayAdaptV3Contract = RelayAdaptV3Contract;
//# sourceMappingURL=relay-adapt-v3.js.map