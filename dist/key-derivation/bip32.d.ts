import { KeyNode } from '../models/engine-types';
/**
 * Converts path string into segments
 * @param path - path string to parse
 * @returns array of indexes
 */
export declare function getPathSegments(path: string): number[];
/**
 * Derive child KeyNode from KeyNode via hardened derivation
 * @param node - KeyNode to derive from
 * @param index - index of child
 */
export declare function childKeyDerivationHardened(node: KeyNode, index: number, offset?: number): KeyNode;
/**
 * Creates KeyNode from seed
 * @param seed - bip32 seed
 * @returns BjjNode - babyjubjub BIP32Node
 */
export declare function getMasterKeyFromSeed(seed: string): KeyNode;
