/**
 * Converts engine-formatted circuit inputs to the prover's standard format
 * (TransactionCircuitInputs / POICircuitInputs).
 */

import { ByteLength, ByteUtils } from '../utils/bytes';
import type { FormattedCircuitInputsRailgun, FormattedCircuitInputsPOI } from '../models/prover-types';
import type { TransactionCircuitInputs, POICircuitInputs } from '@railgun-reloaded/prover';

const FIELD_BYTE_LEN = ByteLength.UINT_256;
const RANDOM_BYTE_LEN = ByteLength.UINT_128;

function bigintToUint8Array(n: bigint, byteLength: number = FIELD_BYTE_LEN): Uint8Array {
  return ByteUtils.nToBytes(n, byteLength);
}

/**
 * Convert engine FormattedCircuitInputsRailgun (bigint) to prover standard
 * TransactionCircuitInputs (Uint8Array).
 */
export function engineFormattedRailgunToTransactionCircuitInputs(
  formatted: FormattedCircuitInputsRailgun,
): TransactionCircuitInputs {
  const numInputs = formatted.nullifiers.length;
  const pathElementsPerInput = numInputs > 0 ? Math.floor(formatted.pathElements.length / numInputs) : 16;

  return {
    merkleRoot: bigintToUint8Array(formatted.merkleRoot),
    boundParamsHash: bigintToUint8Array(formatted.boundParamsHash),
    token: bigintToUint8Array(formatted.token),
    publicKey: formatted.publicKey.map((p) => bigintToUint8Array(p)),
    signature: formatted.signature.map((s) => bigintToUint8Array(s)),
    nullifyingKey: bigintToUint8Array(formatted.nullifyingKey),
    inputTXOs: formatted.nullifiers.map((_, i) => {
      const start = i * pathElementsPerInput;
      return {
        nullifier: bigintToUint8Array(formatted.nullifiers[i]),
        randomIn: bigintToUint8Array(formatted.randomIn[i]),
        valueIn: formatted.valueIn[i],
        merkleleafPosition: Number(formatted.leavesIndices[i]),
        pathElements: formatted.pathElements
          .slice(start, start + pathElementsPerInput)
          .map((el) => bigintToUint8Array(el)),
      };
    }),
    outputTXOs: formatted.commitmentsOut.map((_, i) => ({
      commitment: bigintToUint8Array(formatted.commitmentsOut[i]),
      npk: bigintToUint8Array(formatted.npkOut[i]),
      value: formatted.valueOut[i],
    })),
  };
}

/**
 * Convert engine FormattedCircuitInputsPOI (bigint) to prover standard
 * POICircuitInputs (Uint8Array).
 */
export function engineFormattedPOIToPOICircuitInputs(
  formatted: FormattedCircuitInputsPOI,
): POICircuitInputs {
  return {
    anyRailgunTxidMerklerootAfterTransaction: bigintToUint8Array(
      formatted.anyRailgunTxidMerklerootAfterTransaction,
    ),
    poiMerkleroots: formatted.poiMerkleroots.map((p) => bigintToUint8Array(p)),
    boundParamsHash: bigintToUint8Array(formatted.boundParamsHash),
    nullifiers: formatted.nullifiers.map((n) => bigintToUint8Array(n)),
    commitmentsOut: formatted.commitmentsOut.map((c) => bigintToUint8Array(c)),
    spendingPublicKey: formatted.spendingPublicKey.map((p) => bigintToUint8Array(p)),
    nullifyingKey: bigintToUint8Array(formatted.nullifyingKey),
    token: bigintToUint8Array(formatted.token),
    randomsIn: formatted.randomsIn.map((r) => bigintToUint8Array(r, RANDOM_BYTE_LEN)),
    valuesIn: formatted.valuesIn,
    utxoPositionsIn: formatted.utxoPositionsIn.map(Number),
    utxoTreeIn: Number(formatted.utxoTreeIn),
    npksOut: formatted.npksOut.map((n) => bigintToUint8Array(n)),
    valuesOut: formatted.valuesOut,
    utxoBatchGlobalStartPositionOut: bigintToUint8Array(
      formatted.utxoBatchGlobalStartPositionOut,
    ),
    railgunTxidIfHasUnshield: bigintToUint8Array(formatted.railgunTxidIfHasUnshield),
    railgunTxidMerkleProofIndices: Number(formatted.railgunTxidMerkleProofIndices),
    railgunTxidMerkleProofPathElements: formatted.railgunTxidMerkleProofPathElements.map((e) =>
      bigintToUint8Array(e),
    ),
    poiInMerkleProofIndices: formatted.poiInMerkleProofIndices.map(Number),
    poiInMerkleProofPathElements: formatted.poiInMerkleProofPathElements.map((path) =>
      path.map((e) => bigintToUint8Array(e)),
    ),
  };
}
