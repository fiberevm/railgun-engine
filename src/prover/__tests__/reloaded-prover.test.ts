import { expect } from 'chai';
import { Prover } from '../prover';
import { testArtifactsGetter } from '../../test/helper.test';
import TestVectorPOI from '../../test/test-vector-poi.json';
import type {
  ProverArtifacts,
  POICircuitInputs,
  TransactionCircuitInputs,
} from '@railgun-reloaded/prover';
import {
  createGroth16FromPOIProver,
  createGroth16FromTransactionProver,
  SnarkjsPoiProver,
  SnarkjsTransactionProver,
  standardToSnarkJSPOIInput,
  standardToSnarkJSTransactionInput,
} from '@railgun-reloaded/prover';
import { ByteLength, ByteUtils } from '../../utils';
import { POI } from '../../poi/poi';
import { Chain } from '../../models/engine-types';
import { ProofCachePOI } from '../proof-cache-poi';
import { MERKLE_ZERO_VALUE_BIGINT } from '../../models/merkletree-types';
import { TXIDVersion } from '../../models/poi-types';
import type { UnprovedTransactionInputs } from '../../models/prover-types';
import type { POIEngineProofInputs } from '../../models/poi-types';
import { BoundParamsStruct } from '../../abi/typechain/RailgunSmartWallet';
import { PublicInputsPOI } from '../../models';

const chain: Chain = {
  type: 0,
  id: 1,
};

const MERKLE_ZERO_BYTES = ByteUtils.nToBytes(MERKLE_ZERO_VALUE_BIGINT, 32);

const convertPOIArtifactToProverArtifacts = async (
  maxInputs: number,
  maxOutputs: number,
): Promise<ProverArtifacts> => {
  const artifact = await testArtifactsGetter.getArtifactsPOI(maxInputs, maxOutputs);
  if (!artifact.wasm) {
    throw new Error('WASM artifact is required but was undefined');
  }
  return {
    vkey: artifact.vkey as ProverArtifacts['vkey'],
    zkey: new Uint8Array(artifact.zkey),
    wasm: new Uint8Array(artifact.wasm),
  };
};

const convertTxArtifactToProverArtifacts = async (
  nullifiers: number,
  commitments: number,
): Promise<ProverArtifacts> => {
  const artifact = await testArtifactsGetter.getArtifacts({
    nullifiers: Array(nullifiers).fill(0n),
    commitmentsOut: Array(commitments).fill(0n),
    merkleRoot: 0n,
    boundParamsHash: 0n,
  });
  if (!artifact.wasm) {
    throw new Error('WASM artifact is required but was undefined');
  }
  return {
    vkey: artifact.vkey as ProverArtifacts['vkey'],
    zkey: new Uint8Array(artifact.zkey as ArrayLike<number>),
    wasm: new Uint8Array(artifact.wasm as ArrayLike<number>),
  };
};

const padArray = <T>(array: T[], max: number, zeroValue: T): T[] => {
  const padded = [...array];
  while (padded.length < max) {
    padded.push(zeroValue);
  }
  return padded;
};

const hexToFieldElement = (hex: string, size: number = 32): Uint8Array => {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const paddedHex = cleanHex.padStart(size * 2, '0');
  return ByteUtils.hexToBytes(paddedHex);
};

const decimalToFieldElement = (decimal: string, size: number = 32): Uint8Array => {
  const bigintVal = BigInt(decimal);
  const hex = bigintVal.toString(16).padStart(size * 2, '0');
  return ByteUtils.hexToBytes(hex);
};

/**
 * Transaction test vector for 1x2 circuit (1 input, 2 outputs).
 */
const TransactionTestVector1x2 = {
  merkleRoot: '0x14a4f4001199b05fa5e3bd4ca9bd191084c891feac99be79272cdd671d5275b8',
  boundParamsHash: '0x1d64d5e8131bfc3fc3d10343fd3daf7798ae637302501b9058085eb0c2fd2fa1',
  nullifiers: ['0x0bee1c05c9921260085974c1b47e1b0ca39d5b3dfd40cc217a97e43c8595e299'],
  commitmentsOut: [
    '0x20a3de4307607d219d43d4ecb6f732c5f41d5d2ea1773325d44eba6833db88a8',
    '0x1acf333c90ef6d2845cf61c8bef557ad7a78885ad6f8cc84b8d8cc6d5c8c1191',
  ],
  token: '0x0000000000000000000000000000000000000000000000000000000000000000',
  publicKey: [
    '0x0ab643966862eed77019d5d727dfd33503f760280079a02ecbff2728e359c832',
    '0x07151d539ec1fa7269b5521e3bc6a807b1228986434b289434333745888a1b3b',
  ],
  signature: [
    '0x059aa001a731044b2e8616835a3ac2bd546e4ae01d65c5310ae2ab2d8035c917',
    '0x0690127598e397fc02e84c39344b35504c3159614cd11682bd96d50a08740e93',
    '0x0342eb28a3c786f8d29384b8e5231623fdb0a46aed370f8536165dde2770dd7c',
  ],
  nullifyingKey: '0x10723748ec5f3c372795b09ff836a01c2d8912dbdf326e675bd2cce508f85249',
  inputTXOs: [
    {
      nullifier: '0x0bee1c05c9921260085974c1b47e1b0ca39d5b3dfd40cc217a97e43c8595e299',
      randomIn: '0x000000000000000000000000000000003df8b0f35478acf7bca5a9501776b86a',
      valueIn: '2',
      merkleleafPosition: 0,
      pathElements: [
        '0x0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc',
        '0x01c405064436affeae1fc8e30b2e417b4243bbb819adca3b55bb32efc3e43a4f',
        '0x0888d37652d10d1781db54b70af87b42a2916e87118f507218f9a42a58e85ed2',
        '0x183f531ead7217ebc316b4c02a2aad5ad87a1d56d4fb9ed81bf84f644549eaf5',
        '0x093c48f1ecedf2baec231f0af848a57a76c6cf05b290a396707972e1defd17df',
        '0x1437bb465994e0453357c17a676b9fdba554e215795ebc17ea5012770dfb77c7',
        '0x12359ef9572912b49f44556b8bbbfa69318955352f54cfa35cb0f41309ed445a',
        '0x2dc656dadc82cf7a4707786f4d682b0f130b6515f7927bde48214d37ec25a46c',
        '0x2500bdfc1592791583acefd050bc439a87f1d8e8697eb773e8e69b44973e6fdc',
        '0x244ae3b19397e842778b254cd15c037ed49190141b288ff10eb1390b34dc2c31',
        '0x0ca2b107491c8ca6e5f7e22403ea8529c1e349a1057b8713e09ca9f5b9294d46',
        '0x18593c75a9e42af27b5e5b56b99c4c6a5d7e7d6e362f00c8e3f69aeebce52313',
        '0x17aca915b237b04f873518947a1f440f0c1477a6ac79299b3be46858137d4bfb',
        '0x2726c22ad3d9e23414887e8233ee83cc51603f58c48a9c9e33cb1f306d4365c0',
        '0x08c5bd0f85cef2f8c3c1412a2b69ee943c6925ecf79798bb2b84e1b76d26871f',
        '0x27f7c465045e0a4d8bec7c13e41d793734c50006ca08920732ce8c3096261435',
      ],
    },
  ],
  outputTXOs: [
    {
      commitment: '0x20a3de4307607d219d43d4ecb6f732c5f41d5d2ea1773325d44eba6833db88a8',
      npk: '0x2f7932a1cdf8f59676f69477a095b0eccf0863f7def1d7d9d0de0c3cb2db2f7a',
      value: '1',
    },
    {
      commitment: '0x1acf333c90ef6d2845cf61c8bef557ad7a78885ad6f8cc84b8d8cc6d5c8c1191',
      npk: '0x10501d009bb1adc975a4f9de0ea9f2827cf033a51c807db6906debcc78eb5b5b',
      value: '1',
    },
  ],
};

const convertTestVectorToTransactionInputs = (
  testVector: typeof TransactionTestVector1x2,
): TransactionCircuitInputs => ({
  merkleRoot: hexToFieldElement(testVector.merkleRoot),
  boundParamsHash: hexToFieldElement(testVector.boundParamsHash),
  token: hexToFieldElement(testVector.token),
  publicKey: testVector.publicKey.map((h) => hexToFieldElement(h)),
  signature: testVector.signature.map((h) => hexToFieldElement(h)),
  nullifyingKey: hexToFieldElement(testVector.nullifyingKey),
  inputTXOs: testVector.inputTXOs.map((txo) => ({
    nullifier: hexToFieldElement(txo.nullifier),
    randomIn: hexToFieldElement(txo.randomIn),
    valueIn: BigInt(txo.valueIn),
    merkleleafPosition: txo.merkleleafPosition,
    pathElements: txo.pathElements.map((h) => hexToFieldElement(h)),
  })),
  outputTXOs: testVector.outputTXOs.map((txo) => ({
    commitment: hexToFieldElement(txo.commitment),
    npk: hexToFieldElement(txo.npk),
    value: BigInt(txo.value),
  })),
});

const convertTestVectorToPOICircuitInputs = (
  testVector: typeof TestVectorPOI,
  maxInputs: number,
  maxOutputs: number,
): POICircuitInputs => {
  return {
    anyRailgunTxidMerklerootAfterTransaction: hexToFieldElement(
      testVector.anyRailgunTxidMerklerootAfterTransaction,
    ),
    poiMerkleroots: padArray(
      testVector.poiMerkleroots.map((h) => hexToFieldElement(h)),
      maxInputs,
      MERKLE_ZERO_BYTES,
    ),
    boundParamsHash: hexToFieldElement(testVector.boundParamsHash),
    nullifiers: padArray(
      testVector.nullifiers.map((h) => hexToFieldElement(h)),
      maxInputs,
      MERKLE_ZERO_BYTES,
    ),
    commitmentsOut: padArray(
      testVector.commitmentsOut.map((h) => hexToFieldElement(h)),
      maxOutputs,
      MERKLE_ZERO_BYTES,
    ),
    spendingPublicKey: [
      decimalToFieldElement(String(testVector.spendingPublicKey[0])),
      decimalToFieldElement(String(testVector.spendingPublicKey[1])),
    ],
    nullifyingKey: decimalToFieldElement(String(testVector.nullifyingKey)),
    token: hexToFieldElement(testVector.token),
    randomsIn: padArray(
      testVector.randomsIn.map((h) => hexToFieldElement(h, 16)),
      maxInputs,
      ByteUtils.nToBytes(MERKLE_ZERO_VALUE_BIGINT, 16),
    ),
    valuesIn: padArray(
      testVector.valuesIn.map((x) => BigInt(x)),
      maxOutputs,
      0n,
    ),
    utxoPositionsIn: padArray(
      testVector.utxoPositionsIn.map(Number),
      maxInputs,
      Number(MERKLE_ZERO_VALUE_BIGINT),
    ),
    utxoTreeIn: Number(testVector.utxoTreeIn),
    npksOut: padArray(
      testVector.npksOut?.length
        ? testVector.npksOut.map((h: string) => hexToFieldElement(h))
        : [],
      maxOutputs,
      MERKLE_ZERO_BYTES,
    ),
    valuesOut: padArray(
      testVector.valuesOut.map((x) => BigInt(x)),
      maxOutputs,
      0n,
    ),
    utxoBatchGlobalStartPositionOut: decimalToFieldElement(
      String(testVector.utxoBatchGlobalStartPositionOut),
    ),
    railgunTxidIfHasUnshield: hexToFieldElement(testVector.railgunTxidIfHasUnshield),
    railgunTxidMerkleProofIndices: Number(testVector.railgunTxidMerkleProofIndices),
    railgunTxidMerkleProofPathElements: (
      testVector.railgunTxidMerkleProofPathElements as string[]
    ).map((h) => hexToFieldElement(h)),
    poiInMerkleProofIndices: padArray(
      (testVector.poiInMerkleProofIndices as string[]).map((x) => Number(x)),
      maxInputs,
      0,
    ),
    poiInMerkleProofPathElements: padArray(
      (testVector.poiInMerkleProofPathElements as string[][]).map((pathElements) =>
        pathElements.map((h) => hexToFieldElement(h)),
      ),
      maxInputs,
      Array.from({ length: 16 }, () => new Uint8Array(MERKLE_ZERO_BYTES)),
    ),
  };
};

function buildUnprovedTransactionInputs1x2(): UnprovedTransactionInputs {
  const zeroHex = ByteUtils.formatToByteLength('00', ByteLength.UINT_256, true);
  const boundParams: BoundParamsStruct = {
    treeNumber: BigInt(0),
    minGasPrice: BigInt(0),
    unshield: BigInt(0),
    chainID: chain.id,
    adaptContract: ByteUtils.formatToByteLength('00', 20, true),
    adaptParams: ByteUtils.formatToByteLength('00', 32, true),
    commitmentCiphertext: [
      {
        ciphertext: [zeroHex, zeroHex, zeroHex, zeroHex],
        memo: zeroHex,
        blindedReceiverViewingKey: zeroHex,
        blindedSenderViewingKey: zeroHex,
        annotationData: zeroHex,
      },
      {
        ciphertext: [zeroHex, zeroHex, zeroHex, zeroHex],
        memo: zeroHex,
        blindedReceiverViewingKey: zeroHex,
        blindedSenderViewingKey: zeroHex,
        annotationData: zeroHex,
      },
    ],
  };

  return {
    txidVersion: TXIDVersion.V2_PoseidonMerkle,
    publicInputs: {
      merkleRoot: ByteUtils.hexToBigInt(TransactionTestVector1x2.merkleRoot),
      boundParamsHash: ByteUtils.hexToBigInt(TransactionTestVector1x2.boundParamsHash),
      nullifiers: TransactionTestVector1x2.nullifiers.map((h) => ByteUtils.hexToBigInt(h)),
      commitmentsOut: TransactionTestVector1x2.commitmentsOut.map((h) => ByteUtils.hexToBigInt(h)),
    },
    privateInputs: {
      tokenAddress: ByteUtils.hexToBigInt(TransactionTestVector1x2.token),
      publicKey: TransactionTestVector1x2.publicKey.map((h) => ByteUtils.hexToBigInt(h)) as [bigint, bigint],
      randomIn: TransactionTestVector1x2.inputTXOs.map((txo) => ByteUtils.hexToBigInt(txo.randomIn)),
      valueIn: TransactionTestVector1x2.inputTXOs.map((txo) => BigInt(txo.valueIn)),
      pathElements: TransactionTestVector1x2.inputTXOs.map((txo) =>
        txo.pathElements.map((h) => ByteUtils.hexToBigInt(h)),
      ),
      leavesIndices: TransactionTestVector1x2.inputTXOs.map((txo) => BigInt(txo.merkleleafPosition)),
      nullifyingKey: ByteUtils.hexToBigInt(TransactionTestVector1x2.nullifyingKey),
      npkOut: TransactionTestVector1x2.outputTXOs.map((o) => ByteUtils.hexToBigInt(o.npk)),
      valueOut: TransactionTestVector1x2.outputTXOs.map((o) => BigInt(o.value)),
    },
    boundParams,
    signature: TransactionTestVector1x2.signature.map((h) => ByteUtils.hexToBigInt(h)) as [bigint, bigint, bigint],
  };
}

function testVectorToPOIEngineProofInputs(
  testVector: typeof TestVectorPOI,
  maxInputs: number,
  maxOutputs: number,
): POIEngineProofInputs {
  const padStr = (arr: string[], len: number, zeroHex: string) =>
    padArray(arr, len, zeroHex);
  const zeroHex = ByteUtils.nToHex(MERKLE_ZERO_VALUE_BIGINT, 32, false);

  return {
    anyRailgunTxidMerklerootAfterTransaction: testVector.anyRailgunTxidMerklerootAfterTransaction.startsWith('0x')
      ? testVector.anyRailgunTxidMerklerootAfterTransaction
      : `0x${testVector.anyRailgunTxidMerklerootAfterTransaction}`,
    poiMerkleroots: padStr(
      testVector.poiMerkleroots.map((h) => (h.startsWith('0x') ? h : `0x${h}`)),
      maxInputs,
      `0x${zeroHex}`,
    ),
    boundParamsHash: testVector.boundParamsHash.startsWith('0x') ? testVector.boundParamsHash : `0x${testVector.boundParamsHash}`,
    nullifiers: padStr(
      testVector.nullifiers.map((h) => (h.startsWith('0x') ? h : `0x${h}`)),
      maxInputs,
      `0x${zeroHex}`,
    ),
    commitmentsOut: padStr(
      testVector.commitmentsOut.map((h) => (h.startsWith('0x') ? h : `0x${h}`)),
      maxOutputs,
      `0x${zeroHex}`,
    ),
    spendingPublicKey: testVector.spendingPublicKey.map((x) => BigInt(x)) as [bigint, bigint],
    nullifyingKey: BigInt(testVector.nullifyingKey),
    token: testVector.token.startsWith('0x') ? testVector.token : `0x${testVector.token}`,
    randomsIn: padStr(testVector.randomsIn, maxInputs, '0x00'),
    valuesIn: padArray(
      testVector.valuesIn.map((x) => BigInt(x)),
      maxOutputs,
      0n,
    ),
    utxoPositionsIn: padArray(testVector.utxoPositionsIn.map(Number), maxInputs, 0),
    utxoTreeIn: Number(testVector.utxoTreeIn),
    npksOut: padArray(
      (testVector.npksOut || []).map((x: string) => BigInt(x)),
      maxOutputs,
      MERKLE_ZERO_VALUE_BIGINT,
    ),
    valuesOut: padArray(
      testVector.valuesOut.map((x) => BigInt(x)),
      maxOutputs,
      0n,
    ),
    utxoBatchGlobalStartPositionOut: BigInt(testVector.utxoBatchGlobalStartPositionOut),
    railgunTxidIfHasUnshield: testVector.railgunTxidIfHasUnshield,
    railgunTxidMerkleProofIndices: testVector.railgunTxidMerkleProofIndices,
    railgunTxidMerkleProofPathElements: testVector.railgunTxidMerkleProofPathElements as string[],
    poiInMerkleProofIndices: padArray(
      (testVector.poiInMerkleProofIndices as string[]).map((x) => x),
      maxInputs,
      '0',
    ),
    poiInMerkleProofPathElements: padArray(
      testVector.poiInMerkleProofPathElements as string[][],
      maxInputs,
      Array(16).fill('0'),
    ),
  };
}

const suppressDebugLogger = { debug: () => {}, info: () => {} };

describe('reloaded-prover', () => {
  beforeEach(() => {
    ProofCachePOI.clear_TEST_ONLY();
    POI.launchBlocks.set(null, chain, 0);
  });

  describe('setGroth16FromReloadedProver / setUseGroth16Adapter', () => {
    it('Should set groth16 implementation with fullProveRailgun and fullProvePOI', () => {
      const prover = new Prover(testArtifactsGetter);
      expect(prover.groth16).to.equal(undefined);

      prover.setGroth16FromReloadedProver();

      expect(prover.groth16).to.be.an('object');
      expect(prover.groth16?.fullProveRailgun).to.be.a('function');
      expect(prover.groth16?.fullProvePOI).to.be.a('function');
    });

    it('Should set groth16 implementation via setUseGroth16Adapter (alias)', () => {
      const prover = new Prover(testArtifactsGetter);
      prover.setUseGroth16Adapter();

      expect(prover.groth16).to.be.an('object');
      expect(prover.groth16?.fullProveRailgun).to.be.a('function');
      expect(prover.groth16?.fullProvePOI).to.be.a('function');
    });
  });

  /**
   * Tests for prover.ts lines 182-303: engineArtifactToProverArtifacts,
   * setGroth16FromReloadedProver, setUseGroth16Adapter, setGroth16FromReloadedProverImpl
   * (fullProveRailgun, fullProvePOI, verify: undefined).
   */
  describe('Implemenatation test for -> setGroth16FromReloadedProverImpl)', () => {
    it('engineArtifactToProverArtifacts: should throw when artifact has no wasm', async () => {
      const artifactGetterNoWasm = {
        getArtifacts: async () => ({
          vkey: {},
          zkey: new Uint8Array(1),
          wasm: undefined,
          dat: new Uint8Array(1),
        }),
        getArtifactsPOI: async () => ({
          vkey: {},
          zkey: new Uint8Array(1),
          wasm: undefined,
          dat: new Uint8Array(1),
        }),
        assertArtifactExists: () => {},
      };

      const prover = new Prover(artifactGetterNoWasm);
      prover.setGroth16FromReloadedProver();

      const unprovedInputs = buildUnprovedTransactionInputs1x2();
      try {
        await prover.proveRailgun(TXIDVersion.V2_PoseidonMerkle, unprovedInputs, () => {});
        expect.fail('Should have thrown');
      } catch (err: any) {
        const outer = err?.message ?? '';
        const causeMsg = err?.cause?.message ?? '';
        const hasExpected =
          outer.includes('@railgun-reloaded/prover failed to fullProveRailgun') &&
          causeMsg.includes('WASM artifact is required for @railgun-reloaded/prover');
        expect(hasExpected, `Expected WASM error in cause; got: ${outer} / cause: ${causeMsg}`).to.equal(true);
      }
    });

    it('fullProveRailgun: proveRailgun after setGroth16FromReloadedProver returns proof and publicInputs', async () => {
      const prover = new Prover(testArtifactsGetter);
      prover.setGroth16FromReloadedProver();

      const unprovedInputs = buildUnprovedTransactionInputs1x2();
      const progressValues: number[] = [];
      const { proof, publicInputs } = await prover.proveRailgun(
        TXIDVersion.V2_PoseidonMerkle,
        unprovedInputs,
        (p) => progressValues.push(p),
      );

      expect(proof).to.be.an('object');
      expect(proof.pi_a).to.have.lengthOf(2);
      expect(proof.pi_b).to.have.lengthOf(2);
      expect(proof.pi_c).to.have.lengthOf(2);
      expect(publicInputs.merkleRoot).to.equal(ByteUtils.hexToBigInt(TransactionTestVector1x2.merkleRoot));
      expect(publicInputs.nullifiers).to.have.lengthOf(1);
      expect(publicInputs.commitmentsOut).to.have.lengthOf(2);
      expect(progressValues.length).to.be.greaterThan(0);
    }).timeout(60000);

    it('fullProvePOI: provePOI after setGroth16FromReloadedProver returns proof and publicInputs', async () => {
      const prover = new Prover(testArtifactsGetter);
      prover.setGroth16FromReloadedProver();

      const testVector = TestVectorPOI;
      const poiInputs = testVectorToPOIEngineProofInputs(testVector, 3, 3);
      const progressValues: number[] = [];
      const { proof, publicInputs } = await prover.provePOI(
        poiInputs,
        testVector.listKey,
        [],
        testVector.blindedCommitmentsOut,
        (p) => progressValues.push(p),
      );

      expect(proof).to.be.an('object');
      expect(proof.pi_a).to.have.lengthOf(2);
      expect(proof.pi_b).to.have.lengthOf(2);
      expect(proof.pi_c).to.have.lengthOf(2);

      const expectedPublicInputs: PublicInputsPOI = prover.getPublicInputsPOI(
        testVector.anyRailgunTxidMerklerootAfterTransaction.startsWith('0x')
          ? testVector.anyRailgunTxidMerklerootAfterTransaction
          : `0x${testVector.anyRailgunTxidMerklerootAfterTransaction}`,
        testVector.blindedCommitmentsOut,
        testVector.poiMerkleroots.map((h) => (h.startsWith('0x') ? h : `0x${h}`)),
        testVector.railgunTxidIfHasUnshield,
        3,
        3,
      );
      expect(publicInputs.blindedCommitmentsOut.length).to.equal(expectedPublicInputs.blindedCommitmentsOut.length);
      expect(publicInputs.poiMerkleroots.length).to.equal(3);
      expect(progressValues.length).to.be.greaterThan(0);
    }).timeout(60000);

    it('groth16.verify is undefined after setGroth16FromReloadedProver', () => {
      const prover = new Prover(testArtifactsGetter);
      prover.setGroth16FromReloadedProver();
      expect(prover.groth16?.verify).to.equal(undefined);
    });

    it('setUseGroth16Adapter behaves same as setGroth16FromReloadedProver (alias)', async () => {
      const proverAdapter = new Prover(testArtifactsGetter);
      proverAdapter.setGroth16FromReloadedProver();

      const proverAlias = new Prover(testArtifactsGetter);
      proverAlias.setUseGroth16Adapter();

      expect(proverAlias.groth16).to.be.an('object');
      expect(proverAlias.groth16?.fullProveRailgun).to.be.a('function');
      expect(proverAlias.groth16?.fullProvePOI).to.be.a('function');
      expect(proverAlias.groth16?.verify).to.equal(undefined);

      const unprovedInputs = buildUnprovedTransactionInputs1x2();
      const { proof } = await proverAlias.proveRailgun(
        TXIDVersion.V2_PoseidonMerkle,
        unprovedInputs,
        () => {},
      );
      expect(proof).to.be.an('object');
      expect(proof.pi_a).to.have.lengthOf(2);
    }).timeout(60000);

    it('wraps adapter errors with @railgun-reloaded/prover failed message', async () => {
      const badArtifactGetter = {
        getArtifacts: testArtifactsGetter.getArtifacts,
        getArtifactsPOI: async () => {
          const a = await testArtifactsGetter.getArtifactsPOI(3, 3);
          return { ...a, wasm: new Uint8Array(0), zkey: new Uint8Array(0) };
        },
        assertArtifactExists: testArtifactsGetter.assertArtifactExists,
      };

      const prover = new Prover(badArtifactGetter);
      prover.setGroth16FromReloadedProver();

      const poiInputs = testVectorToPOIEngineProofInputs(TestVectorPOI, 3, 3);
      try {
        await prover.provePOI(
          poiInputs,
          TestVectorPOI.listKey,
          [],
          TestVectorPOI.blindedCommitmentsOut,
          () => {},
        );
        expect.fail('Should have thrown');
      } catch (err: any) {
        expect(err.message).to.include('Unable to generate POI proof');
        const causeMsg = err?.cause?.message ?? '';
        expect(causeMsg).to.include('@railgun-reloaded/prover failed to fullProvePOI');
        expect(err.cause).to.be.an('Error');
      }
    }).timeout(10000);
  });

  describe('POI proofs via @railgun-reloaded/prover', () => {
    it('Should generate and validate POI proof - 3x3', async () => {
      const poiArtifacts = await convertPOIArtifactToProverArtifacts(3, 3);
      const poiProver = new SnarkjsPoiProver(poiArtifacts);
      const adapter = createGroth16FromPOIProver(poiProver);
      const testVector = TestVectorPOI;
      const poiInputs = convertTestVectorToPOICircuitInputs(testVector, 3, 3);
      const snarkjsInputs = standardToSnarkJSPOIInput(poiInputs);

      const result = await adapter.fullProve(
        snarkjsInputs,
        poiArtifacts.wasm,
        poiArtifacts.zkey,
        suppressDebugLogger,
      );

      expect(result).to.be.an('object');
      expect(result.proof).to.be.an('object');
      expect(result.publicSignals).to.be.an('array');

      const isValid = await adapter.verify(
        poiArtifacts.vkey,
        result.publicSignals,
        result.proof,
        suppressDebugLogger,
      );
      expect(isValid).to.equal(true);
    }).timeout(60000);

    it('Should generate and validate POI proof - 13x13', async () => {
      const poiArtifacts = await convertPOIArtifactToProverArtifacts(13, 13);
      const poiProver = new SnarkjsPoiProver(poiArtifacts);
      const adapter = createGroth16FromPOIProver(poiProver);
      const testVector = TestVectorPOI;
      const poiInputs = convertTestVectorToPOICircuitInputs(testVector, 13, 13);
      const snarkjsInputs = standardToSnarkJSPOIInput(poiInputs);

      const result = await adapter.fullProve(
        snarkjsInputs,
        poiArtifacts.wasm,
        poiArtifacts.zkey,
        suppressDebugLogger,
      );

      expect(result).to.be.an('object');
      expect(result.proof).to.be.an('object');
      expect(result.publicSignals).to.be.an('array');

      const isValid = await adapter.verify(
        poiArtifacts.vkey,
        result.publicSignals,
        result.proof,
        suppressDebugLogger,
      );
      expect(isValid).to.equal(true);
    }).timeout(120000);
  });

  describe('Transaction proofs via @railgun-reloaded/prover', () => {
    it('Should generate and validate transaction proof - 1x2', async () => {
      const txArtifacts = await convertTxArtifactToProverArtifacts(1, 2);
      const txProver = new SnarkjsTransactionProver(txArtifacts);
      const adapter = createGroth16FromTransactionProver(txProver);
      const txInputs = convertTestVectorToTransactionInputs(TransactionTestVector1x2);
      const snarkjsInputs = standardToSnarkJSTransactionInput(txInputs);

      const result = await adapter.fullProve(
        snarkjsInputs,
        txArtifacts.wasm,
        txArtifacts.zkey,
        suppressDebugLogger,
      );

      expect(result).to.be.an('object');
      expect(result.proof).to.be.an('object');
      expect(result.publicSignals).to.be.an('array');

      const isValid = await adapter.verify(
        txArtifacts.vkey,
        result.publicSignals,
        result.proof,
        suppressDebugLogger,
      );
      expect(isValid).to.equal(true);
    }).timeout(60000);
  });
});
