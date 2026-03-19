export declare const SNARK_PRIME: bigint;
export declare const ADDRESS_VERSION = 1;
export declare const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
export declare const ZERO_32_BYTE_VALUE = "0x0000000000000000000000000000000000000000000000000000000000000000";
/**
 * Block number per EVM chain designating when events changed for RAILGUN V2 upgrade.
 * This is when Unshield events became available.
 */
export declare const ENGINE_V2_START_BLOCK_NUMBERS_EVM: {
    [chainID: number]: number;
};
/**
 * Block number per EVM chain designating when the shield event changed on Mar 9, 2023.
 */
export declare const ENGINE_V2_SHIELD_EVENT_UPDATE_03_09_23_BLOCK_NUMBERS_EVM: {
    [chainID: number]: number;
};
/**
 * Increment to issue fresh utxo merkletree rescan on next launch.
 * Also will rescan TXIDs for V3 (which use the same data source as V3 UTXOs).
 * WARNING: When updating for V2 data, make sure to update TXID V2 version as well.
 */
export declare const CURRENT_UTXO_MERKLETREE_HISTORY_VERSION = 13;
/**
 * Increment to issue fresh V2 txid merkletree rescan on next launch.
 */
export declare const CURRENT_TXID_V2_MERKLETREE_HISTORY_VERSION = 16;
