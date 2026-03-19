import { Chain } from '../models/engine-types';
import { TXIDVersion } from '../models/poi-types';
/**
 * A simple nested datastructure that holds information per-chain and per
 * RailgunTXIDVersion.
 */
export declare class Registry<T> {
    private v2Map;
    private v3Map;
    private anyMap;
    constructor();
    private selectMap;
    private static serializeChain;
    private static deserializeChain;
    set(txidVersion: TXIDVersion | null, chain: Chain, value: T): void;
    has(txidVersion: TXIDVersion | null, chain: Chain): boolean;
    get(txidVersion: TXIDVersion | null, chain: Chain): Optional<T>;
    getOrThrow(txidVersion: TXIDVersion | null, chain: Chain): T;
    del(txidVersion: TXIDVersion | null, chain: Chain): void;
    forEach(callback: (value: T, txidVersion: TXIDVersion | null, chain: Chain) => void): void;
    map<R>(callback: (value: T, txidVersion: TXIDVersion | null, chain: Chain) => R): R[];
}
