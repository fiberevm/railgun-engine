import { TREE_MAX_ITEMS } from '../models/merkletree-types';

export const GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE = 99999;
export const GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE = 99999;

export const getGlobalTreePosition = (tree: number, index: number): bigint => {
  return BigInt(tree * TREE_MAX_ITEMS + index);
};
