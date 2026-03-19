import { Chain } from './engine-types';
import { TXIDVersion } from './poi-types';
export declare const TREE_DEPTH = 16;
export declare const TREE_MAX_ITEMS = 65536;
export type MerklerootValidator = (txidVersion: TXIDVersion, chain: Chain, tree: number, index: number, merkleroot: string) => Promise<boolean>;
export type MerkletreeLeaf = {
    hash: string;
};
export type InvalidMerklerootDetails = {
    position: number;
    blockNumber: number;
};
export declare enum CommitmentProcessingGroupSize {
    XXXXLarge = 10000,
    XXXLarge = 8000,
    XXLarge = 1600,
    XLarge = 800,
    Large = 200,
    Medium = 40,
    Small = 10,
    Single = 1
}
type TreeMetadata = {
    scannedHeight: number;
    invalidMerklerootDetails: InvalidMerklerootDetails | null;
};
export type MerkletreesMetadata = {
    trees: {
        [tree: number]: TreeMetadata;
    };
};
export declare const MERKLE_ZERO_VALUE_BIGINT: bigint;
export declare const MERKLE_ZERO_VALUE: string;
export {};
