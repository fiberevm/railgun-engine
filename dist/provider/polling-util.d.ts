import { AbstractProvider, FallbackProvider, JsonRpcProvider } from 'ethers';
import { PollingJsonRpcProvider } from './polling-json-rpc-provider';
export declare const assertIsPollingProvider: (provider: AbstractProvider) => void;
/**
 * Fallback Providers don't poll correctly for events.
 * This function creates a PollingJsonRpcProvider from the first provider in the FallbackProvider.
 */
export declare const createPollingJsonRpcProviderForListeners: (provider: JsonRpcProvider | FallbackProvider, chainId: number, pollingInterval?: number) => Promise<PollingJsonRpcProvider>;
