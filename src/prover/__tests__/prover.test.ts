import { expect } from 'chai';
import memdown from 'memdown';
import TestVectorPOI from '../../test/test-vector-poi.json';
import { createRailgunTransactionWithHash } from '../../transaction/railgun-txid';
import { verifyMerkleProof } from '../../merkletree/merkle-proof';
import { Chain } from '../../models/engine-types';
import {
  MerkleProof,
  RailgunTransactionVersion,
  RailgunTransactionWithHash,
} from '../../models/formatted-types';
import { TXIDVersion } from '../../models/poi-types';
import { TXIDMerkletree } from '../../merkletree/txid-merkletree';
import { Database } from '../../database/database';
import { ShieldNote, TransactNote, getTokenDataERC20 } from '../../note';
import { ByteLength, ByteUtils } from '../../utils';
import { WalletNode } from '../../key-derivation/wallet-node';
import { getGlobalTreePosition } from '../../utils/global-tree-position';
import { BlindedCommitment } from '../../utils/blinded-commitment';
import { config } from '../../test/config.test';

const chain: Chain = {
  type: 0,
  id: 1,
};

describe('prover', () => {
  it('Should verify input vector', async () => {
    const testVector = TestVectorPOI;

    const railgunTransaction: RailgunTransactionWithHash = createRailgunTransactionWithHash({
      version: RailgunTransactionVersion.V2,
      graphID: '',
      boundParamsHash: testVector.boundParamsHash,
      commitments: testVector.commitmentsOut,
      nullifiers: testVector.nullifiers,
      unshield: {
        tokenData: getTokenDataERC20(config.contracts.rail),
        toAddress: '0x1234',
        value: '0x01',
      },
      timestamp: 1_000_000,
      txid: '00',
      blockNumber: 0,
      utxoTreeIn: 0,
      utxoTreeOut: 0,
      utxoBatchStartPositionOut: 1,
      verificationHash: 'todo',
    });
    expect(ByteUtils.hexToBigInt(railgunTransaction.railgunTxid)).to.equal(
      BigInt(testVector.railgunTxidIfHasUnshield),
    );

    const txidMerkletree = await TXIDMerkletree.createForWallet(
      new Database(memdown()),
      chain,
      TXIDVersion.V2_PoseidonMerkle,
      async () => true,
    );
    await txidMerkletree.queueRailgunTransactions([railgunTransaction], undefined);
    await txidMerkletree.updateTreesFromWriteQueue();
    const railgunTxidMerkleproof = await txidMerkletree.getMerkleProof(0, 0);
    const inputMerkleProof: MerkleProof = {
      root: testVector.anyRailgunTxidMerklerootAfterTransaction,
      indices: testVector.railgunTxidMerkleProofIndices,
      elements: testVector.railgunTxidMerkleProofPathElements,
      leaf: railgunTransaction.hash,
    };
    expect(railgunTxidMerkleproof).to.deep.equal(inputMerkleProof);
    expect(verifyMerkleProof(inputMerkleProof)).to.equal(true);

    const nullifier = TransactNote.getNullifier(
      BigInt(testVector.nullifyingKey),
      testVector.utxoPositionsIn[0],
    );
    expect(nullifier).to.equal(ByteUtils.hexToBigInt(testVector.nullifiers[0]));

    // Verify shield note details
    const masterPublicKey = WalletNode.getMasterPublicKey(
      [BigInt(testVector.spendingPublicKey[0]), BigInt(testVector.spendingPublicKey[1])],
      BigInt(testVector.nullifyingKey),
    );
    expect(masterPublicKey).to.equal(
      20060431504059690749153982049210720252589378133547582826474262520121417617087n,
    );
    const notePublicKey = ShieldNote.getNotePublicKey(masterPublicKey, testVector.randomsIn[0]);
    expect(notePublicKey).to.equal(
      6401386539363233023821237080626891507664131047949709897410333742190241828916n,
    );
    const shieldCommitment = ShieldNote.getShieldNoteHash(
      notePublicKey,
      testVector.token,
      BigInt(testVector.valuesIn[0]),
    );
    expect(shieldCommitment).to.equal(
      6442080113031815261226726790601252395803415545769290265212232865825296902085n,
    );
    const blindedCommitmentForShield = ByteUtils.hexToBigInt(
      BlindedCommitment.getForShieldOrTransact(
        ByteUtils.nToHex(shieldCommitment, ByteLength.UINT_256),
        notePublicKey,
        getGlobalTreePosition(0, 0),
      ),
    );
    expect(blindedCommitmentForShield).to.equal(
      12151255948031648278500231754672666576376002857793985290167262750766640136930n,
    );
    expect(blindedCommitmentForShield).to.equal(
      ByteUtils.hexToBigInt(testVector.blindedCommitmentsIn[0]),
    );
  });
});
