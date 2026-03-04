// TXIDVersion is kept from the original poi-types.ts as it's used throughout the codebase.
// All POI-specific types have been removed.

export enum TXIDVersion {
  V2_PoseidonMerkle = 'V2_PoseidonMerkle',
  V3_PoseidonMerkle = 'V3_PoseidonMerkle',
}

export const ACTIVE_UTXO_MERKLETREE_TXID_VERSIONS: TXIDVersion[] = [
  TXIDVersion.V2_PoseidonMerkle,
  TXIDVersion.V3_PoseidonMerkle,
];

export const ACTIVE_TXID_VERSIONS: TXIDVersion[] = [
  TXIDVersion.V2_PoseidonMerkle,
  TXIDVersion.V3_PoseidonMerkle,
];
