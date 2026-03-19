import { Chain } from '../models/engine-types';
declare const getChainFullNetworkID: (chain: Chain) => string;
export declare const getChainSupportsV3: (chain: Chain) => boolean;
export declare const assertChainSupportsV3: (chain: Chain) => void;
export declare const addChainSupportsV3: (chain: Chain) => void;
export { getChainFullNetworkID };
