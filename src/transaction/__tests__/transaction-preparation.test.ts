import chai from 'chai';
import { Interface, JsonRpcProvider } from 'ethers';
import memdown from 'memdown';
import { ABIRelayAdapt } from '../../abi/abi';
import { ContractStore } from '../../contracts/contract-store';
import { RELAY_ADAPT_ACTION_MIN_GAS_LIMIT_V2 } from '../../contracts/relay-adapt/constants';
import { RelayAdaptV2Contract } from '../../contracts/relay-adapt/V2/relay-adapt-v2';
import { CommitmentType, LegacyGeneratedCommitment } from '../../models/formatted-types';
import { Chain, ChainType } from '../../models/engine-types';
import { TXIDVersion } from '../../models/poi-types';
import { getTokenDataERC20 } from '../../note/note-util';
import { Prover } from '../../prover/prover';
import { config } from '../../test/config.test';
import { getEthersWallet, testArtifactsGetter } from '../../test/helper.test';
import { ByteLength, ByteUtils } from '../../utils/bytes';
import { Database } from '../../database/database';
import { deriveNodes } from '../../key-derivation/wallet-node';
import { UTXOMerkletree } from '../../merkletree/utxo-merkletree';
import {
  DelegatedSignWallet,
  RailgunWallet,
  SignDelegate,
} from '../../wallet/railgun-wallet';
import WalletInfo from '../../wallet/wallet-info';
import {
  deserializePreparedRailgunTransactionV2,
  serializePreparedRailgunTransactionV2,
} from '../prepared-transaction';
import { TransactionBatch } from '../transaction-batch';

const { expect } = chai;

const chain: Chain = { type: ChainType.EVM, id: 1 };
const txidVersion = TXIDVersion.V2_PoseidonMerkle;
const tokenData = getTokenDataERC20('0x5FbDB2315678afecb367f032d93F642f64180aa3');
const destinationAddress = '0x2222222222222222222222222222222222222222';
const relayRandom = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd';
const shieldLeaf: LegacyGeneratedCommitment = {
  commitmentType: CommitmentType.LegacyGeneratedCommitment,
  hash: '10c139398677d31020ddf97e0c73239710c956a52a7ea082a1e84815582bfb5f',
  txid: '0xc97a2d06ceb87f81752bd58310e4aca822ae18a747e4dde752020e0b308a3aee',
  timestamp: undefined,
  preImage: {
    npk: '1d73bae2faf4ff18e1cd22d22cb9c05bc08878dc8fa4907257ce1a7ad51933f7',
    token: tokenData,
    value: '000000000000021cbfcc6fd98333b5f1',
  },
  encryptedRandom: [
    '0x7797f244fc1c60af03f25cbe9a798080b920733cc2de2456af21ee7c9eb1ca0c',
    '0x118beef50353ab8512be871c0473e219',
  ],
  blockNumber: 0,
  utxoTree: 0,
  utxoIndex: 0,
};

describe('transaction preparation', () => {
  let db: Database;
  let merkletree: UTXOMerkletree;
  let wallet: RailgunWallet;

  before(async () => {
    db = new Database(memdown());
    merkletree = await UTXOMerkletree.create(db, chain, txidVersion, async () => true);
    wallet = await RailgunWallet.fromMnemonic(
      db,
      config.encryptionKey,
      config.mnemonic,
      0,
      undefined,
      new Prover(testArtifactsGetter),
    );
    WalletInfo.setWalletSource('preparetest');
    await wallet.loadUTXOMerkletree(txidVersion, merkletree);
    merkletree.merklerootValidator = () => Promise.resolve(true);
    await merkletree.queueLeaves(0, 0, [shieldLeaf]);
    await merkletree.updateTreesFromWriteQueue();
    await wallet.decryptBalances(txidVersion, chain, undefined, false);
    ContractStore.relayAdaptV2Contracts.set(
      null,
      chain,
      new RelayAdaptV2Contract(config.contracts.relayAdapt, new JsonRpcProvider(config.rpc)),
    );
  });

  it('prepares and proves an exact require-success RelayAdapt action without rebuilding signed data', async () => {
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      // RelayAdapt must receive the unshield before its bound calls can distribute it.
      toAddress: config.contracts.relayAdapt,
      value: BigInt(`0x${shieldLeaf.preImage.value}`),
      tokenData,
    });
    const minimumAmount = BigInt(`0x${shieldLeaf.preImage.value}`) - 10n;
    const relayInterface = new Interface(ABIRelayAdapt);
    const transferData = (value: bigint) =>
      relayInterface.encodeFunctionData('transfer', [
        [
          {
            token: tokenData,
            to: destinationAddress,
            value,
          },
        ],
      ]);
    const actionData = {
      random: relayRandom,
      requireSuccess: true,
      minGasLimit: RELAY_ADAPT_ACTION_MIN_GAS_LIMIT_V2,
      calls: [
        { to: config.contracts.relayAdapt, data: transferData(minimumAmount), value: 0n },
        { to: config.contracts.relayAdapt, data: transferData(0n), value: 0n },
      ],
    };

    let signCalls = 0;
    const originalSign = wallet.sign.bind(wallet);
    wallet.sign = async (...args) => {
      signCalls += 1;
      return originalSign(...args);
    };

    try {
      const prepared = await transactionBatch.prepareTransactionsForIndependentRelayAdapt(
        wallet,
        txidVersion,
        config.encryptionKey,
        () => actionData,
      );
      expect(signCalls).to.equal(0);
      expect(prepared.relayAdaptAddress).to.equal(config.contracts.relayAdapt);
      expect(prepared.transactions).to.have.length(1);
      expect(prepared.transactions[0].preparedTransaction.boundParams.adaptContract).to.equal(
        config.contracts.relayAdapt,
      );
      expect(prepared.transactions[0].preparedTransaction.boundParams.adaptParams).to.equal(
        prepared.transactions[0].adaptParams,
      );

      const prover = new Prover(testArtifactsGetter);
      prover.proveRailgun = async (_version, inputs, progressCallback) => {
        progressCallback(100);
        return {
          proof: prover.dummyProveRailgun(inputs.publicInputs),
          publicInputs: inputs.publicInputs,
        };
      };
      const proved = await transactionBatch.generateRelayAdaptTransactionFromPrepared(
        prover,
        wallet,
        config.encryptionKey,
        [prepared.transactions[0].preparedTransaction],
        actionData,
        () => {},
      );
      expect(signCalls).to.equal(1);
      const decoded = relayInterface.decodeFunctionData(
        'relay',
        proved.relayTransaction.data,
      );
      expect(decoded[1].requireSuccess).to.equal(true);
      expect(decoded[1].minGasLimit).to.equal(RELAY_ADAPT_ACTION_MIN_GAS_LIMIT_V2);
      expect(decoded[1].calls).to.have.length(2);
      expect(decoded[1].calls[0].to).to.equal(config.contracts.relayAdapt);
      expect(decoded[1].calls[0].data).to.equal(transferData(minimumAmount));
      expect(decoded[1].calls[1].data).to.equal(transferData(0n));

      const tamperedAction = {
        ...actionData,
        calls: [
          ...actionData.calls.slice(0, 1),
          { ...actionData.calls[1], data: transferData(1n) },
        ],
      };
      let tamperError: Error | undefined;
      try {
        await transactionBatch.generateRelayAdaptTransactionFromPrepared(
          prover,
          wallet,
          config.encryptionKey,
          [prepared.transactions[0].preparedTransaction],
          tamperedAction,
          () => {},
        );
      } catch (cause) {
        tamperError = cause as Error;
      }
      expect(tamperError?.message).to.equal(
        'Prepared transaction RelayAdapt parameters mismatch.',
      );
      expect(signCalls).to.equal(1);
    } finally {
      wallet.sign = originalSign;
    }
  });

  it('captures exact V2 semantics before signing and proves the prepared request later', async () => {
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      toAddress: getEthersWallet(config.mnemonic).address,
      value: BigInt(`0x${shieldLeaf.preImage.value}`),
      tokenData,
    });

    let signCalls = 0;
    let capturedSigningData: Parameters<RailgunWallet['sign']>[2];
    const originalSign = wallet.sign.bind(wallet);
    wallet.sign = async (publicInputs, encryptionKey, signingData) => {
      signCalls += 1;
      capturedSigningData = signingData;
      return originalSign(publicInputs, encryptionKey, signingData);
    };

    try {
      const { preparedTransactions } = await transactionBatch.prepareTransactions(
        wallet,
        txidVersion,
        config.encryptionKey,
      );

      expect(signCalls).to.equal(0);
      expect(preparedTransactions).to.have.length(1);
      const [prepared] = preparedTransactions;
      expect(prepared.txidVersion).to.equal(TXIDVersion.V2_PoseidonMerkle);
      expect(prepared.publicInputs.commitmentsOut).to.have.length(1);
      expect(prepared.unshieldPreimage.value).to.equal(BigInt(`0x${shieldLeaf.preImage.value}`));

      const prover = new Prover(testArtifactsGetter);
      prover.proveRailgun = async (_version, inputs, progressCallback) => {
        progressCallback(100);
        return {
          proof: prover.dummyProveRailgun(inputs.publicInputs),
          publicInputs: inputs.publicInputs,
        };
      };

      const { provedTransactions } = await transactionBatch.generateTransactionsFromPrepared(
        prover,
        wallet,
        config.encryptionKey,
        preparedTransactions,
        () => {},
      );

      expect(signCalls).to.equal(1);
      expect(capturedSigningData).to.deep.equal({
        txidVersion: prepared.txidVersion,
        publicInputs: prepared.publicInputs,
        boundParams: prepared.boundParams,
        unshieldPreimage: prepared.unshieldPreimage,
      });
      expect(capturedSigningData).to.not.have.property('privateInputs');
      expect(provedTransactions).to.have.length(1);
      expect(provedTransactions[0].boundParams).to.deep.equal(prepared.boundParams);
      expect(provedTransactions[0].unshieldPreimage).to.deep.equal(prepared.unshieldPreimage);
      expect(provedTransactions[0].nullifiers).to.deep.equal(
        prepared.publicInputs.nullifiers.map((nullifier) =>
          ByteUtils.nToHex(nullifier, ByteLength.UINT_256, true),
        ),
      );
    } finally {
      wallet.sign = originalSign;
    }
  });

  it('serializes prepared V2 witnesses deterministically and restores bigint and byte fields', async () => {
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      toAddress: getEthersWallet(config.mnemonic).address,
      value: BigInt(`0x${shieldLeaf.preImage.value}`),
      tokenData,
    });
    const { preparedTransactions } = await transactionBatch.prepareTransactions(
      wallet,
      txidVersion,
      config.encryptionKey,
    );
    const [prepared] = preparedTransactions;
    if (prepared.txidVersion !== TXIDVersion.V2_PoseidonMerkle) {
      throw new Error('Expected prepared V2 transaction.');
    }

    prepared.unshieldPreimage.npk = ByteUtils.hexStringToBytes(
      ByteUtils.hexlify(prepared.unshieldPreimage.npk, true),
    );

    const serialized = serializePreparedRailgunTransactionV2(prepared);
    expect(serializePreparedRailgunTransactionV2(prepared)).to.equal(serialized);

    const restored = deserializePreparedRailgunTransactionV2(serialized);
    expect(restored).to.deep.equal(prepared);
    expect(restored.privateInputs.nullifyingKey).to.be.a('bigint');
    expect(restored.unshieldPreimage.npk).to.be.instanceOf(Uint8Array);

    const prover = new Prover(testArtifactsGetter);
    prover.proveRailgun = async (_version, inputs, progressCallback) => {
      progressCallback(100);
      return {
        proof: prover.dummyProveRailgun(inputs.publicInputs),
        publicInputs: inputs.publicInputs,
      };
    };
    const { provedTransactions } = await transactionBatch.generateTransactionsFromPrepared(
      prover,
      wallet,
      config.encryptionKey,
      [restored],
      () => {},
    );
    expect(provedTransactions[0].boundParams).to.deep.equal(restored.boundParams);
    expect(provedTransactions[0].unshieldPreimage.token).to.deep.equal(
      restored.unshieldPreimage.token,
    );
    expect(provedTransactions[0].unshieldPreimage.value).to.equal(restored.unshieldPreimage.value);
    expect(ByteUtils.hexlify(provedTransactions[0].unshieldPreimage.npk, true)).to.equal(
      ByteUtils.hexlify(restored.unshieldPreimage.npk, true),
    );

    restored.boundParams.minGasPrice = 1n;
    expect(() => serializePreparedRailgunTransactionV2(restored)).to.throw(
      'Prepared transaction boundParamsHash mismatch.',
    );
    let executionError: Error | undefined;
    try {
      await transactionBatch.generateTransactionsFromPrepared(
        prover,
        wallet,
        config.encryptionKey,
        [restored],
        () => {},
      );
    } catch (cause) {
      executionError = cause as Error;
    }
    expect(executionError?.message).to.equal('Prepared transaction boundParamsHash mismatch.');
  });

  it('forwards exact prepared semantics through a delegated signer', async () => {
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      toAddress: getEthersWallet(config.mnemonic).address,
      value: BigInt(`0x${shieldLeaf.preImage.value}`),
      tokenData,
    });
    const { preparedTransactions } = await transactionBatch.prepareTransactions(
      wallet,
      txidVersion,
      config.encryptionKey,
    );
    const [prepared] = preparedTransactions;
    if (prepared.txidVersion !== TXIDVersion.V2_PoseidonMerkle) {
      throw new Error('Expected prepared V2 transaction.');
    }
    const signingData = {
      txidVersion: prepared.txidVersion,
      publicInputs: prepared.publicInputs,
      boundParams: prepared.boundParams,
      unshieldPreimage: prepared.unshieldPreimage,
    };

    const nodes = deriveNodes(config.mnemonic, 7);
    let capturedSigningData: Parameters<SignDelegate>[1];
    const delegatedWallet = await DelegatedSignWallet.fromKeys(
      db,
      config.encryptionKey,
      await nodes.viewing.getViewingKeyPair(),
      nodes.spending.getSpendingKeyPair().pubkey,
      undefined,
      new Prover(testArtifactsGetter),
      async (_publicInputs, context) => {
        capturedSigningData = context;
        return { R8: [0n, 0n], S: 0n };
      },
    );

    await delegatedWallet.sign(prepared.publicInputs, config.encryptionKey, signingData);
    expect(capturedSigningData).to.deep.equal(signingData);
  });

  after(async () => {
    wallet.unloadUTXOMerkletree(txidVersion, chain);
    ContractStore.relayAdaptV2Contracts.del(null, chain);
    await db.close();
  });
});
