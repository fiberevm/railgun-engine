"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createPollingJsonRpcProviderForListeners = exports.assertIsPollingProvider = void 0;
const ethers_1 = require("ethers");
const polling_json_rpc_provider_1 = require("./polling-json-rpc-provider");
const assertIsPollingProvider = (provider) => {
    if (!isPollingProvider(provider)) {
        throw new Error('The JsonRpcProvider must have polling enabled. Use PollingJsonRpcProvider to instantiate.');
    }
};
exports.assertIsPollingProvider = assertIsPollingProvider;
const isPollingProvider = (provider) => {
    return provider.isPollingProvider !== undefined;
};
/**
 * Fallback Providers don't poll correctly for events.
 * This function creates a PollingJsonRpcProvider from the first provider in the FallbackProvider.
 */
const createPollingJsonRpcProviderForListeners = async (provider, chainId, pollingInterval) => {
    if (isPollingProvider(provider)) {
        return provider;
    }
    if (provider instanceof ethers_1.JsonRpcProvider) {
        // eslint-disable-next-line no-underscore-dangle
        const { url } = provider._getConnection();
        return new polling_json_rpc_provider_1.PollingJsonRpcProvider(url, chainId, pollingInterval);
    }
    const { providerConfigs } = provider;
    if (!providerConfigs.length) {
        throw new Error("Need to supply at least one fallback provider");
    }
    const [{ provider: firstProviderConfig }] = providerConfigs;
    const firstProvider = firstProviderConfig;
    // eslint-disable-next-line no-underscore-dangle
    const { url } = firstProvider._getConnection();
    // eslint-disable-next-line no-underscore-dangle
    const maxLogsPerBatch = firstProvider._getOption('batchMaxCount');
    return new polling_json_rpc_provider_1.PollingJsonRpcProvider(url, chainId, pollingInterval, maxLogsPerBatch);
};
exports.createPollingJsonRpcProviderForListeners = createPollingJsonRpcProviderForListeners;
//# sourceMappingURL=polling-util.js.map