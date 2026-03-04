import chai, { expect } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Contract, Wallet } from 'ethers';
import memdown from 'memdown';
import { groth16 } from 'snarkjs';
import sinon, { SinonStub } from 'sinon';
import { RailgunEngine } from '../railgun-engine';
import { abi as erc20Abi } from '../test/test-erc20-abi.test';
import { config } from '../test/config.test';
import { abi as erc721Abi } from '../test/test-erc721-abi.test';
import { RailgunWallet } from '../wallet/railgun-wallet';
import {
  awaitMultipleScans,
  awaitScan,
  DECIMALS_18,
  getEthersWallet,
  getTestTXIDVersion,
  isV2Test,
  mockGetLatestValidatedRailgunTxid,
  mockQuickSyncEvents,
  mockQuickSyncRailgunTransactionsV2,
  mockRailgunTxidMerklerootValidator,
  sendTransactionWithLatestNonce,
  testArtifactsGetter,
} from '../test/helper.test';
import { ShieldNoteERC20 } from '../note/erc20/shield-note-erc20';
import { ByteLength, ByteUtils } from '../utils/bytes';
import {
  CommitmentType,
  LegacyGeneratedCommitment,
  NFTTokenData,
  OutputType,
  TokenType,
} from '../models/formatted-types';
import { SnarkJSGroth16 } from '../prover/prover';
import { TestERC20 } from '../test/abi/typechain/TestERC20';
import { TestERC721 } from '../test/abi/typechain/TestERC721';
import { promiseTimeout } from '../utils/promises';
import { Chain, ChainType } from '../models/engine-types';
import { TransactNote } from '../note/transact-note';
import { TOKEN_SUB_ID_NULL } from '../models/transaction-constants';
import { getTokenDataERC20, getTokenDataHash, getTokenDataNFT } from '../note/note-util';
import { TransactionBatch } from '../transaction/transaction-batch';
import { UnshieldNoteNFT } from '../note/nft/unshield-note-nft';
import { mintNFTsID01ForTest, shieldNFTForTest } from '../test/shared-test.test';
import { createPollingJsonRpcProviderForListeners } from '../provider/polling-util';
import { isDefined } from '../utils/is-defined';
import { PollingJsonRpcProvider } from '../provider/polling-json-rpc-provider';
import { UTXOMerkletree } from '../merkletree/utxo-merkletree';
import { TXIDMerkletree } from '../merkletree/txid-merkletree';
import { TXIDVersion } from '../models/poi-types';
import { AES } from '../utils/encryption/aes';
import { RailgunVersionedSmartContracts } from '../contracts/railgun-smart-wallet/railgun-versioned-smart-contracts';
import { WalletBalanceBucket } from '../models/txo-types';
import { XChaCha20 } from '../utils/encryption/x-cha-cha-20';

chai.use(chaiAsPromised);

const txidVersion = getTestTXIDVersion();

let provider: PollingJsonRpcProvider;
let chain: Chain;
let engine: RailgunEngine;
let ethersWallet: Wallet;
let snapshot: number;
let token: TestERC20;
let nft: TestERC721;
let wallet: RailgunWallet;
let wallet2: RailgunWallet;
let utxoMerkletree: UTXOMerkletree;
let txidMerkletree: TXIDMerkletree;
let tokenAddress: string;

let transactNoteRandomStub: SinonStub;
let transactSenderRandomStub: SinonStub;
let aesGetRandomIVStub: SinonStub;
let xChaChaGetRandomIVStub: SinonStub;

const erc20Address = config.contracts.rail;
const nftAddress = config.contracts.testERC721;

const testMnemonic = config.mnemonic;
const testEncryptionKey = config.encryptionKey;

const random = '67c600e777b86d3a1e72a53092e9fe85';

describe('railgun-engine', function test() {
  this.timeout(20000);

  const shieldTestTokens = async (
    railgunAddress: string,
    value: bigint,
  ): Promise<ShieldNoteERC20> => {
    const mpk = RailgunEngine.decodeAddress(railgunAddress).masterPublicKey;
    const receiverViewingPublicKey = wallet.getViewingKeyPair().pubkey;
    const shield = new ShieldNoteERC20(mpk, random, value, tokenAddress);

    const shieldPrivateKey = ByteUtils.hexToBytes(ByteUtils.randomHex(32));
    const shieldInput = await shield.serialize(shieldPrivateKey, receiverViewingPublicKey);

    const erc20Token = new Contract(erc20Address, erc20Abi, ethersWallet) as unknown as TestERC20;
    const spender = RailgunVersionedSmartContracts.getShieldApprovalContract(
      txidVersion,
      chain,
    ).address;
    const balance = await erc20Token.balanceOf(ethersWallet.address);
    const approval = await erc20Token.approve.populateTransaction(spender, balance);
    const approvalTx = await sendTransactionWithLatestNonce(ethersWallet, approval);
    await approvalTx.wait();
    const allowance = await erc20Token.allowance(ethersWallet.address, spender);
    expect(allowance).to.equal(balance);
    expect(allowance > value).to.equal(true);

    // Create shield
    const shieldTx = await RailgunVersionedSmartContracts.generateShield(txidVersion, chain, [
      shieldInput,
    ]);

    // Send shield on chain
    const tx = await sendTransactionWithLatestNonce(ethersWallet, shieldTx);
    await Promise.all([
      tx.wait(),
      promiseTimeout(awaitScan(wallet, chain), 10000, 'Timed out scanning after test token shield'),
    ]);

    const balancePost = await erc20Token.balanceOf(ethersWallet.address);
    expect(balancePost).to.equal(balance - value);

    return shield;
  };

  beforeEach(async () => {
    engine = await RailgunEngine.initForWallet(
      'Test Wallet',
      memdown(),
      testArtifactsGetter,
      mockQuickSyncEvents,
      mockQuickSyncRailgunTransactionsV2,
      mockRailgunTxidMerklerootValidator,
      mockGetLatestValidatedRailgunTxid,
      undefined, // engineDebugger
      undefined, // skipMerkletreeScans
    );
    engine.prover.setSnarkJSGroth16(groth16 as SnarkJSGroth16);

    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      return;
    }

    transactNoteRandomStub = sinon
      .stub(TransactNote, 'getNoteRandom')
      .returns('123456789012345678901234567890ab'); // 16 bytes
    transactSenderRandomStub = sinon
      .stub(TransactNote, 'getSenderRandom')
      .returns('098765432109876543210987654321'); // 15 bytes
    aesGetRandomIVStub = sinon.stub(AES, 'getRandomIV').returns('abcdef1234567890abcdef1234567890');
    xChaChaGetRandomIVStub = sinon
      .stub(XChaCha20, 'getRandomIV')
      .returns('abcdef1234567890abcdef1234567890');
    // EngineDebug.init(console); // uncomment for logs
    provider = new PollingJsonRpcProvider(config.rpc, config.chainId);
    chain = {
      type: ChainType.EVM,
      id: Number((await provider.getNetwork()).chainId),
    };

    ethersWallet = getEthersWallet(config.mnemonic, provider);

    snapshot = (await provider.send('evm_snapshot', [])) as number;
    token = new Contract(erc20Address, erc20Abi, ethersWallet) as unknown as TestERC20;
    tokenAddress = ByteUtils.formatToByteLength(erc20Address, ByteLength.UINT_256, false);

    nft = new Contract(nftAddress, erc721Abi, ethersWallet) as unknown as TestERC721;

    wallet = await engine.createWalletFromMnemonic(testEncryptionKey, testMnemonic);
    wallet2 = await engine.createWalletFromMnemonic(testEncryptionKey, testMnemonic, 1);
    const pollingProvider = await createPollingJsonRpcProviderForListeners(provider, chain.id);
    await engine.loadNetwork(
      chain,
      config.contracts.proxy,
      config.contracts.relayAdapt,
      config.contracts.poseidonMerkleAccumulatorV3,
      config.contracts.poseidonMerkleVerifierV3,
      config.contracts.tokenVaultV3,
      provider,
      pollingProvider,
      { [TXIDVersion.V2_PoseidonMerkle]: 24, [TXIDVersion.V3_PoseidonMerkle]: 24 },
      0,
      !isV2Test(), // supportsV3
    );

    const balance = await token.balanceOf(ethersWallet.address);
    await token.approve(
      RailgunVersionedSmartContracts.getShieldApprovalContract(txidVersion, chain).address,
      balance,
    );

    await engine.scanContractHistory(
      chain,
      undefined, // walletIdFilter
    );
    utxoMerkletree = engine.getUTXOMerkletree(txidVersion, chain);
    txidMerkletree = engine.getTXIDMerkletree(txidVersion, chain);
  });

  it('[HH] Should load existing wallets', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    engine.unloadWallet(wallet.id);
    await engine.loadExistingWallet(testEncryptionKey, wallet.id);
    expect(engine.wallets[wallet.id].id).to.equal(wallet.id);
  });

  it('Should delete wallet', async () => {
    const walletForDeletion = await engine.createWalletFromMnemonic(
      testEncryptionKey,
      testMnemonic,
      5, // index
    );

    await engine.deleteWallet(walletForDeletion.id);
    await expect(
      engine.loadExistingWallet(testEncryptionKey, walletForDeletion.id),
    ).to.be.rejectedWith(
      'Key not found in database [000000000000000000000000000000000000000000000000000077616c6c6574:4e562d7b2e7cd11d98309031e1697540b51647fa67c9621f74bbd8ef45312443]',
    );
  });

  it('[HH] Should get balances after shield and rescan', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const shieldsPre = await engine.getAllShieldCommitments(txidVersion, chain, 0);
    expect(shieldsPre.length).to.equal(0);

    const commitment: LegacyGeneratedCommitment = {
      commitmentType: CommitmentType.LegacyGeneratedCommitment,
      hash: '14308448bcb19ecff96805fe3d00afecf82b18fa6f8297b42cf2aadc23f412e6',
      txid: '0x0543be0699a7eac2b75f23b33d435aacaeb0061f63e336230bcc7559a1852f33',
      timestamp: undefined,
      preImage: {
        npk: '0xc24ea33942c0fb9acce5dbada73137ad3257a6f2e1be8f309c1fe9afc5410a',
        token: {
          tokenType: TokenType.ERC20,
          tokenAddress: `0x${tokenAddress}`,
          tokenSubID: TOKEN_SUB_ID_NULL,
        },
        value: '9138822709a9fc231cba6',
      },
      encryptedRandom: [
        '0xb47a353e294711ff73cf086f97ee1ed29b853b67c353bc2371b87fe72c716cc6',
        '0x3d321af08b8fa7a8f70379407706b752',
      ],
      blockNumber: 0,
      utxoTree: 0,
      utxoIndex: 0,
    };

    // Override root validator
    utxoMerkletree.merklerootValidator = () => Promise.resolve(true);
    await utxoMerkletree.queueLeaves(0, 0, [commitment]);
    await utxoMerkletree.updateTreesFromWriteQueue();

    await wallet.decryptBalances(
      txidVersion,
      chain,
      undefined, // progressCallback
      false, // deferCompletionEvent
    );
    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    const value = ByteUtils.hexToBigInt(commitment.preImage.value);
    expect(balance).to.equal(value);

    await wallet.fullRedecryptBalancesAllTXIDVersions(chain, undefined);
    const balanceRescan = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(balanceRescan).to.equal(value);

    await wallet.clearDecryptedBalancesAllTXIDVersions(chain);
    const balanceClear = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(balanceClear).to.equal(undefined);

    const shieldsPost = await engine.getAllShieldCommitments(txidVersion, chain, 0);
    expect(shieldsPost.length).to.equal(1);
  });

  it('[HH] With a creation block number provided, should show balance after shield and rescan', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    // [[chain.type]: [[chain.id]: 0]]
    const creationBlockNumbers: number[][] = [];
    creationBlockNumbers[chain.type] = [];
    creationBlockNumbers[chain.type][chain.id] = 0;
    wallet.testSpecificSetCreationBlockNumbers(creationBlockNumbers);

    const commitment: LegacyGeneratedCommitment = {
      commitmentType: CommitmentType.LegacyGeneratedCommitment,
      hash: '14308448bcb19ecff96805fe3d00afecf82b18fa6f8297b42cf2aadc23f412e6',
      txid: '0x0543be0699a7eac2b75f23b33d435aacaeb0061f63e336230bcc7559a1852f33',
      timestamp: undefined,
      preImage: {
        npk: '0xc24ea33942c0fb9acce5dbada73137ad3257a6f2e1be8f309c1fe9afc5410a',
        token: {
          tokenType: TokenType.ERC20,
          tokenAddress: `0x${tokenAddress}`,
          tokenSubID: TOKEN_SUB_ID_NULL,
        },
        value: '9138822709a9fc231cba6',
      },
      encryptedRandom: [
        '0xb47a353e294711ff73cf086f97ee1ed29b853b67c353bc2371b87fe72c716cc6',
        '0x3d321af08b8fa7a8f70379407706b752',
      ],
      blockNumber: 0,
      utxoTree: 0,
      utxoIndex: 0,
    };
    // Override root validator
    utxoMerkletree.merklerootValidator = () => Promise.resolve(true);
    await utxoMerkletree.queueLeaves(0, 0, [commitment]);
    await utxoMerkletree.updateTreesFromWriteQueue();

    await wallet.decryptBalances(
      txidVersion,
      chain,
      undefined, // progressCallback
      false, // deferCompletionEvent
    );
    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    const value = ByteUtils.hexToBigInt(commitment.preImage.value);
    expect(balance).to.equal(value);

    const walletDetails = await wallet.getWalletDetails(txidVersion, chain);
    // `undefined` because test wallet was not given `creationBlockNumbers`:
    expect(walletDetails.creationTree).to.equal(undefined);
    expect(walletDetails.creationTreeHeight).to.equal(undefined);

    await wallet.fullRedecryptBalancesAllTXIDVersions(chain, undefined);
    const balanceRescan = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(balanceRescan).to.equal(value);

    await wallet.clearDecryptedBalancesAllTXIDVersions(chain);
    const balanceCleared = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(balanceCleared).to.equal(undefined);

    const walletDetailsCleared = await wallet.getWalletDetails(txidVersion, chain);
    // `undefined` because test wallet was not given `creationBlockNumbers`:
    expect(walletDetailsCleared.creationTree).to.equal(undefined);
    expect(walletDetailsCleared.creationTreeHeight).to.equal(undefined);
    expect(walletDetailsCleared.treeScannedHeights.length).to.equal(0);
  });

  it('[HH] Should shield, unshield w/ broadcaster and update balance, and pull formatted spend/receive transaction history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const initialBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(initialBalance).to.equal(undefined);

    const address = wallet.getAddress(chain);
    await shieldTestTokens(address, BigInt(110000) * DECIMALS_18);

    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(balance).to.equal(BigInt('109725000000000000000000'));

    const tokenData = getTokenDataERC20(tokenAddress);

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      toAddress: ethersWallet.address,
      value: BigInt(300) * DECIMALS_18,
      tokenData,
    });

    // Add output for mock Broadcaster
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        1n,
        tokenData,
        false, // showSenderAddressToRecipient
        OutputType.BroadcasterFee,
        undefined, // memoText
      ),
    );

    const { provedTransactions } =
      await transactionBatch.generateTransactions(
        engine.prover,
        wallet,
        txidVersion,
        testEncryptionKey,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        (progress: number, status: string) => {
          // console.log(progress, status);
        },
      );

    const transact = await RailgunVersionedSmartContracts.generateTransact(
      txidVersion,
      chain,
      provedTransactions,
    );

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);
    const transactReceipt = await transactTx.wait();

    if (!transactReceipt) {
      throw new Error('Failed to get transact receipt');
    }
    if (isV2Test()) {
      await Promise.all([
        promiseTimeout(awaitMultipleScans(wallet, chain, 2), 15000, 'Timed out wallet1 scan'),
        promiseTimeout(awaitMultipleScans(wallet2, chain, 2), 15000, 'Timed out wallet2 scan'),
      ]);
    } else {
      await Promise.all([
        promiseTimeout(awaitScan(wallet, chain), 15000, 'Timed out wallet1 scan'),
        promiseTimeout(awaitScan(wallet2, chain), 15000, 'Timed out wallet2 scan'),
      ]);
    }

    // BALANCE = shielded amount - 300(decimals) - 1
    const newBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(newBalance).to.equal(109424999999999999999999n, 'Failed to receive expected balance');

    const newBalance2 = await wallet2.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(newBalance2).to.equal(BigInt(1));

    // check the transactions log
    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(2);

    const tokenFormatted = ByteUtils.formatToByteLength(tokenAddress, ByteLength.UINT_256, false);

    // Make sure nullifier events map to completed txid.
    const nullifiers = provedTransactions
      .map((transaction) => transaction.nullifiers)
      .flat() as string[];
    const completedTxid = await engine.getCompletedTxidFromNullifiers(
      txidVersion,
      chain,
      nullifiers,
    );
    expect(completedTxid).to.equal(transactTx.hash);

    // Check first output: Shield (receive only).
    expect(history[0].txidVersion).to.equal(txidVersion);
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109725000000000000000000'),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: '275000000000000000000',
        balanceBucket: WalletBalanceBucket.Spent,
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].broadcasterFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Check second output: Unshield (broadcaster fee + change).
    // NOTE: No receive token amounts should be logged by history.

    // TODO: The stubs for sinon random cause this expectation to fail:
    // expect(history[1].receiveTokenAmounts).deep.eq(
    //   [],
    //   "Receive amount should be filtered out - it's the same as change output.",
    // );

    expect(history[1].transferTokenAmounts).deep.eq([]);
    expect(history[1].broadcasterFeeTokenAmount).deep.eq({
      tokenData: getTokenDataERC20(tokenAddress),
      tokenHash: tokenFormatted,
      amount: BigInt(1),
      outputType: OutputType.BroadcasterFee,
      walletSource: 'test wallet',
      memoText: undefined,
    });
    expect(history[1].changeTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109424999999999999999999'),
        outputType: OutputType.Change,
        walletSource: 'test wallet',
        memoText: undefined,
      },
    ]);
    expect(history[1].unshieldTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('299250000000000000000'), // 300 minus fee
        recipientAddress: isV2Test() ? ethersWallet.address : ethersWallet.address.toLowerCase(),
        memoText: undefined,
        senderAddress: undefined,
        unshieldFee: '750000000000000000',
      },
    ]);

    // Check that no history exists for a high starting block.
    const historyHighStartingBlock = await wallet.getTransactionHistory(chain, 10000000);
    expect(historyHighStartingBlock.length).to.equal(0);
  }).timeout(90000);

  it('[HH] Should shield, max-unshield without broadcaster, and pull formatted spend/receive transaction history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const initialBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(initialBalance).to.equal(undefined);

    const address = wallet.getAddress(chain);
    await shieldTestTokens(address, BigInt(110000) * DECIMALS_18);

    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(balance).to.equal(BigInt('109725000000000000000000'));

    const tokenData = getTokenDataERC20(tokenAddress);

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      toAddress: ethersWallet.address,
      value: BigInt('109725000000000000000000'),
      tokenData,
    });

    const { provedTransactions } =
      await transactionBatch.generateTransactions(
        engine.prover,
        wallet,
        txidVersion,
        testEncryptionKey,
        () => {},
      );
    expect(provedTransactions.length).to.equal(1);
    expect(provedTransactions[0].nullifiers.length).to.equal(1);
    expect(provedTransactions[0].commitments.length).to.equal(1);

    const transact = await RailgunVersionedSmartContracts.generateTransact(
      txidVersion,
      chain,
      provedTransactions,
    );

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);
    const [transactReceipt] = await Promise.all([
      transactTx.wait(),
      promiseTimeout(awaitScan(wallet, chain), 15000, 'Timed out wallet1 scan'),
    ]);
    if (!transactReceipt) {
      throw new Error('No transaction receipt');
    }

    const newBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(newBalance).to.equal(0n, 'Failed to receive expected balance');

    // check the transactions log
    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(2);

    const tokenFormatted = ByteUtils.formatToByteLength(tokenAddress, ByteLength.UINT_256, false);

    // Make sure nullifier events map to completed txid.
    const nullifiers = provedTransactions
      .map((transaction) => transaction.nullifiers)
      .flat() as string[];
    const completedTxid = await engine.getCompletedTxidFromNullifiers(
      txidVersion,
      chain,
      nullifiers,
    );
    expect(completedTxid).to.equal(transactTx.hash);

    // Check first output: Shield (receive only).
    expect(history[0].txidVersion).to.equal(txidVersion);
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109725000000000000000000'),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: '275000000000000000000',
        balanceBucket: WalletBalanceBucket.Spent,
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].broadcasterFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Check second output: Unshield (broadcaster fee + change).
    // NOTE: No receive token amounts should be logged by history.
    expect(history[1].receiveTokenAmounts).deep.eq(
      [],
      "Receive amount should be filtered out - it's the same as change output.",
    );
    expect(history[1].transferTokenAmounts).deep.eq([]);
    expect(history[1].broadcasterFeeTokenAmount).eq(undefined);
    expect(history[1].changeTokenAmounts).deep.eq([]); // No change output
    expect(history[1].unshieldTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109450687500000000000000'), // balance minus fee
        recipientAddress: isV2Test() ? ethersWallet.address : ethersWallet.address.toLowerCase(),
        memoText: undefined,
        senderAddress: undefined,
        unshieldFee: '274312500000000000000',
      },
    ]);
  }).timeout(120000);

  it('[HH] Should shield, transfer and update balance, and pull formatted spend/receive transaction history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const initialBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(initialBalance).to.equal(undefined);

    const address = wallet.getAddress(chain);
    await shieldTestTokens(address, BigInt(110000) * DECIMALS_18);

    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(balance).to.equal(BigInt('109725000000000000000000'));

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);

    const memoText =
      'A really long memo with emojis 😐 👩🏾‍🔧 and other text, in order to test a major memo for a real live production use case.';

    const tokenData = getTokenDataERC20(tokenAddress);

    // Add output for Transfer
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        10n,
        tokenData,
        true, // showSenderAddressToRecipient
        OutputType.Transfer,
        memoText,
      ),
    );

    const broadcasterMemoText = 'A short memo with only 32 chars.';

    // Add output for mock Broadcaster
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        1n,
        tokenData,
        false, // showSenderAddressToRecipient
        OutputType.BroadcasterFee,
        broadcasterMemoText, // memoText
      ),
    );

    const { provedTransactions } =
      await transactionBatch.generateTransactions(
        engine.prover,
        wallet,
        txidVersion,
        testEncryptionKey,
        () => {},
      );
    const transact = await RailgunVersionedSmartContracts.generateTransact(
      txidVersion,
      chain,
      provedTransactions,
    );

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);
    await transactTx.wait();
    if (isV2Test()) {
      await Promise.all([
        promiseTimeout(awaitMultipleScans(wallet, chain, 2), 15000, 'Timed out wallet1 scan'),
        promiseTimeout(awaitMultipleScans(wallet2, chain, 2), 15000, 'Timed out wallet2 scan'),
      ]);
    } else {
      await Promise.all([
        promiseTimeout(awaitScan(wallet, chain), 15000, 'Timed out wallet1 scan'),
        promiseTimeout(awaitScan(wallet2, chain), 15000, 'Timed out wallet2 scan'),
      ]);
    }

    // BALANCE = shielded amount - 300(decimals) - 1
    const newBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(newBalance).to.equal(109724999999999999999989n, 'Failed to receive expected balance');

    const newBalance2 = await wallet2.getBalanceERC20(txidVersion, chain, tokenAddress, [
      WalletBalanceBucket.Spendable,
    ]);
    expect(newBalance2).to.equal(BigInt(10));

    // check the transactions log
    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(2);

    const tokenFormatted = ByteUtils.formatToByteLength(tokenAddress, ByteLength.UINT_256, false);

    // Check first output: Shield (receive only).
    expect(history[0].txidVersion).to.equal(txidVersion);
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109725000000000000000000'),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: '275000000000000000000',
        balanceBucket: WalletBalanceBucket.Spent,
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].broadcasterFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Check second output: Unshield (broadcaster fee + change).
    // NOTE: No receive token amounts should be logged by history.
    expect(history[1].receiveTokenAmounts).deep.eq(
      [],
      "Receive amount should be filtered out - it's the same as change output.",
    );
    expect(history[1].transferTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt(10),
        outputType: OutputType.Transfer,
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        walletSource: 'test wallet',
        recipientAddress: wallet2.getAddress(),
        memoText,
        // eslint-disable-next-line no-unneeded-ternary
      },
    ]);
    expect(history[1].broadcasterFeeTokenAmount).deep.eq({
      tokenData: getTokenDataERC20(tokenAddress),
      tokenHash: tokenFormatted,
      amount: BigInt(1),
      outputType: OutputType.BroadcasterFee,
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      walletSource: 'test wallet',
      memoText: broadcasterMemoText,
      // eslint-disable-next-line no-unneeded-ternary
    });
    expect(history[1].changeTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109724999999999999999989'),
        outputType: OutputType.Change,
        walletSource: 'test wallet',
        memoText: undefined,
        // eslint-disable-next-line no-unneeded-ternary
      },
    ]);
    expect(history[1].unshieldTokenAmounts).deep.eq([]);

    const history2 = await wallet2.getTransactionHistory(chain, undefined);
    expect(history2.length).to.equal(1);
    expect(history2[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt(10),
        memoText,
        senderAddress: wallet.getAddress(),
        shieldFee: undefined,
        balanceBucket: WalletBalanceBucket.Spendable,
      },
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt(1),
        memoText: broadcasterMemoText,
        senderAddress: undefined,
        shieldFee: undefined,
        balanceBucket: WalletBalanceBucket.Spendable,
      },
    ]);
    expect(history2[0].transferTokenAmounts).deep.eq([]);
    expect(history2[0].broadcasterFeeTokenAmount).eq(undefined);
    expect(history2[0].changeTokenAmounts).deep.eq([]);
    expect(history2[0].unshieldTokenAmounts).deep.eq([]);
  }).timeout(90000);

  it('[HH] Should shield NFTs, transfer & unshield NFTs, and pull formatted spend/receive NFT history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    // Mint NFTs
    await mintNFTsID01ForTest(nft, ethersWallet);

    // Approve shields
    const approval = await nft.setApprovalForAll(
      RailgunVersionedSmartContracts.getShieldApprovalContract(txidVersion, chain).address,
      true,
    );
    await approval.wait();

    // Shield first NFT
    await shieldNFTForTest(txidVersion, wallet, ethersWallet, chain, random, nftAddress, '1');

    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(1);

    const tokenDataNFT0 = getTokenDataNFT(nftAddress, TokenType.ERC721, BigInt(0).toString());
    const tokenHashNFT0 = getTokenDataHash(tokenDataNFT0);

    const tokenDataNFT1 = getTokenDataNFT(nftAddress, TokenType.ERC721, BigInt(1).toString());
    const tokenHashNFT1 = getTokenDataHash(tokenDataNFT1);

    // Check first output: Shield (receive only).
    expect(history[0].txidVersion).to.equal(txidVersion);
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: tokenDataNFT1,
        tokenHash: tokenHashNFT1,
        amount: BigInt(1),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: isV2Test() ? undefined : '0',
        balanceBucket: WalletBalanceBucket.Spendable,
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].broadcasterFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Shield another NFT.
    const shield2 = await shieldNFTForTest(
      txidVersion,
      wallet,
      ethersWallet,
      chain,
      random,
      nftAddress,
      '0',
    );

    // Shield tokens for Broadcaster Fee.
    await shieldTestTokens(wallet.getAddress(), BigInt(110000) * DECIMALS_18);

    // Transfer NFT to another wallet.

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);

    const memoText =
      'A really long memo with emojis 😐 👩🏾‍🔧 and other text, in order to test a major memo for a real live production use case.';

    // Add output for Transfer
    transactionBatch.addOutput(
      TransactNote.createERC721Transfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        tokenDataNFT1,
        true, // showSenderAddressToRecipient
        memoText,
      ),
    );

    // Add output for NFT Unshield
    const unshieldNote = new UnshieldNoteNFT(
      ethersWallet.address,
      shield2.tokenData as NFTTokenData,
    );
    transactionBatch.addUnshieldData(unshieldNote.unshieldData);

    const broadcasterMemoText = 'A short memo with only 32 chars.';

    const tokenDataBroadcasterFee = getTokenDataERC20(erc20Address);

    // Add output for mock Broadcaster
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        20n,
        tokenDataBroadcasterFee,
        false, // showSenderAddressToRecipient
        OutputType.BroadcasterFee,
        broadcasterMemoText, // memoText
      ),
    );

    const { provedTransactions } =
      await transactionBatch.generateTransactions(
        engine.prover,
        wallet,
        txidVersion,
        testEncryptionKey,
        () => {},
      );

    const transact = await RailgunVersionedSmartContracts.generateTransact(
      txidVersion,
      chain,
      provedTransactions,
    );

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);

    await transactTx.wait();
    if (isV2Test()) {
      await Promise.all([
        promiseTimeout(awaitMultipleScans(wallet, chain, 4), 15000, 'Timed out wallet1 scan'),
        promiseTimeout(awaitMultipleScans(wallet2, chain, 2), 15000, 'Timed out wallet2 scan'),
      ]);
    } else {
      await Promise.all([
        promiseTimeout(awaitScan(wallet, chain), 15000, 'Timed out wallet1 scan'),
        promiseTimeout(awaitScan(wallet2, chain), 15000, 'Timed out wallet2 scan'),
      ]);
    }

    const historyAfterTransfer = await wallet.getTransactionHistory(chain, undefined);
    expect(historyAfterTransfer.length).to.equal(4);

    const broadcasterFeeTokenData = getTokenDataERC20(tokenAddress);
    const broadcasterFeeTokenHash = getTokenDataHash(broadcasterFeeTokenData);

    expect(historyAfterTransfer.length).to.equal(4, 'Expected 4 history records');
    expect(historyAfterTransfer[3].transferTokenAmounts.length).to.equal(1, 'Expected 1 transfer');

    expect(historyAfterTransfer[3].receiveTokenAmounts).deep.eq([]);
    expect(historyAfterTransfer[3].transferTokenAmounts).deep.eq([
      {
        tokenData: tokenDataNFT1,
        tokenHash: tokenHashNFT1,
        amount: BigInt(1),
        outputType: OutputType.Transfer,
        walletSource: 'test wallet',
        recipientAddress: wallet2.getAddress(),
        memoText,
      },
    ]);
    expect(historyAfterTransfer[3].broadcasterFeeTokenAmount).deep.eq({
      tokenData: broadcasterFeeTokenData,
      tokenHash: broadcasterFeeTokenHash,
      amount: BigInt(20),
      outputType: OutputType.BroadcasterFee,
      walletSource: 'test wallet',
      memoText: broadcasterMemoText,
    });
    expect(historyAfterTransfer[3].changeTokenAmounts).deep.eq([
      {
        tokenData: broadcasterFeeTokenData,
        tokenHash: broadcasterFeeTokenHash,
        amount: BigInt('109724999999999999999980'),
        outputType: OutputType.Change,
        walletSource: 'test wallet',
        memoText: undefined,
      },
    ]);
    expect(historyAfterTransfer[3].unshieldTokenAmounts).deep.eq([
      {
        tokenData: tokenDataNFT0,
        tokenHash: tokenHashNFT0,
        amount: BigInt(1),
        recipientAddress: isV2Test() ? ethersWallet.address : ethersWallet.address.toLowerCase(),
        memoText: undefined,
        senderAddress: undefined,
        unshieldFee: '0',
      },
    ]);
  }).timeout(300_000);

  it('Should set/get last synced block', async () => {
    const chainForSyncedBlock = {
      type: ChainType.EVM,
      id: 10010,
    };
    // eslint-disable-next-line dot-notation
    let lastSyncedBlock = await engine['getLastSyncedBlock'](txidVersion, chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(undefined);
    // eslint-disable-next-line dot-notation
    await engine['setLastSyncedBlock'](txidVersion, chainForSyncedBlock, 100);
    // eslint-disable-next-line dot-notation
    lastSyncedBlock = await engine['getLastSyncedBlock'](txidVersion, chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100);
    // eslint-disable-next-line dot-notation
    await engine['setLastSyncedBlock'](txidVersion, chainForSyncedBlock, 100000);
    // eslint-disable-next-line dot-notation
    lastSyncedBlock = await engine['getLastSyncedBlock'](txidVersion, chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100000);
  });

  it('Should set/get utxo merkletree history version', async () => {
    const chainForSyncedBlock = {
      type: ChainType.EVM,
      id: 10010,
    };
    // eslint-disable-next-line dot-notation
    let lastSyncedBlock = await engine['getLastSyncedBlock'](txidVersion, chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(undefined);
    // eslint-disable-next-line dot-notation
    await engine['setUTXOMerkletreeHistoryVersion'](chainForSyncedBlock, 100);
    // eslint-disable-next-line dot-notation
    lastSyncedBlock = await engine['getUTXOMerkletreeHistoryVersion'](chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100);
    // eslint-disable-next-line dot-notation
    await engine['setUTXOMerkletreeHistoryVersion'](chainForSyncedBlock, 100000);
    // eslint-disable-next-line dot-notation
    lastSyncedBlock = await engine['getUTXOMerkletreeHistoryVersion'](chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100000);
  });

  it('Should set/get txid merkletree history version', async () => {
    const chainForSyncedBlock = {
      type: ChainType.EVM,
      id: 10010,
    };
    // eslint-disable-next-line dot-notation
    let lastSyncedBlock = await engine['getLastSyncedBlock'](txidVersion, chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(undefined);
    // eslint-disable-next-line dot-notation
    await engine['setTxidV2MerkletreeHistoryVersion'](chainForSyncedBlock, 100);
    // eslint-disable-next-line dot-notation
    lastSyncedBlock = await engine['getTxidV2MerkletreeHistoryVersion'](chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100);
    // eslint-disable-next-line dot-notation
    await engine['setTxidV2MerkletreeHistoryVersion'](chainForSyncedBlock, 100000);
    // eslint-disable-next-line dot-notation
    lastSyncedBlock = await engine['getTxidV2MerkletreeHistoryVersion'](chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100000);
  });

  afterEach(async () => {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      return;
    }

    await provider.send('evm_revert', [snapshot]);

    await txidMerkletree?.clearDataForMerkletree();

    transactNoteRandomStub?.restore();
    transactSenderRandomStub?.restore();
    aesGetRandomIVStub?.restore();
    xChaChaGetRandomIVStub?.restore();

    await engine?.unload();
  });
});
