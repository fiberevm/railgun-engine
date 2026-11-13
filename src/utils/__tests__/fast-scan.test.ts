import { expect } from 'chai';
import { ExtendedPoint, Point } from '@noble/ed25519';
import memdown from 'memdown';
import { Database } from '../../database/database';
import { Mnemonic } from '../../key-derivation/bip39';
import { Chain, ChainType } from '../../models/engine-types';
import { Commitment, OutputType } from '../../models/formatted-types';
import { TXIDVersion } from '../../models/poi-types';
import { ShieldNoteERC20 } from '../../note/erc20/shield-note-erc20';
import { getTokenDataERC20 } from '../../note/note-util';
import { TransactNote } from '../../note/transact-note';
import { Prover } from '../../prover/prover';
import { V2Events } from '../../contracts/railgun-smart-wallet/V2/V2-events';
import { testArtifactsGetter } from '../../test/helper.test';
import { RailgunWallet } from '../../wallet/railgun-wallet';
import WalletInfo from '../../wallet/wallet-info';
import { ByteLength, ByteUtils } from '../bytes';
import {
  clearFastScanCache,
  isTorsionFreePoint,
  LeafPrefilter,
  setFastScanEnabled,
} from '../fast-scan';
import { getNoteBlindingKeys, getSharedSymmetricKey } from '../keys-utils';

const txidVersion = TXIDVersion.V2_PoseidonMerkle;
const chain: Chain = { type: ChainType.EVM, id: 8453 };
const TOKEN = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
// A point of order 8 on ed25519.
const TORSION_POINT = '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05';

type Writes = { key: string; value: string }[];

const createWallet = async (): Promise<{ wallet: RailgunWallet; writes: Writes }> => {
  const db = new Database(memdown());
  const writes: Writes = [];
  const batch = db.batch.bind(db);
  db.batch = async (ops, encoding) => {
    for (const op of ops) {
      if (op.type === 'put') {
        writes.push({
          key: String(op.key),
          value: Buffer.from(op.value as Uint8Array).toString('hex'),
        });
      }
    }
    return batch(ops, encoding);
  };
  const wallet = await RailgunWallet.fromMnemonic(
    db,
    '00'.repeat(32),
    Mnemonic.generate(),
    0,
    undefined,
    new Prover(testArtifactsGetter),
  );
  return { wallet, writes };
};

const shieldLeaf = async (receiver: RailgunWallet): Promise<Commitment> => {
  const note = new ShieldNoteERC20(
    receiver.masterPublicKey,
    ByteUtils.randomHex(16),
    1_000_000n,
    TOKEN,
  );
  const request = await note.serialize(
    ByteUtils.hexToBytes(ByteUtils.randomHex(32)),
    receiver.getViewingKeyPair().pubkey,
  );
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [commitment] = (V2Events as any).formatShieldCommitments(
    `0x${'ab'.repeat(32)}`,
    [
      {
        npk: ByteUtils.hexToBigInt(ByteUtils.hexlify(request.preimage.npk)),
        token: { ...request.preimage.token, tokenSubID: 0n },
        value: request.preimage.value,
      },
    ],
    [request.ciphertext],
    1,
    0,
    0,
    [0n],
    undefined,
  ) as Commitment[];
  return commitment;
};

/**
 * A transfer note from `sender` to `receiver`, built as Transaction.generateTransactionRequest
 * does. With `torsionedSenderKey`, the blinded sender key carries a small-order component and
 * the note is encrypted to the key the engine's own multiplication derives from it.
 */
const transferLeaf = async (
  sender: RailgunWallet,
  receiver: RailgunWallet,
  torsionedSenderKey = false,
): Promise<Commitment> => {
  const note = TransactNote.createTransfer(
    receiver.addressKeys,
    sender.addressKeys,
    2_500n,
    getTokenDataERC20(TOKEN),
    false,
    OutputType.Transfer,
    'memo',
  );
  const blinded = await getNoteBlindingKeys(
    sender.getViewingKeyPair().pubkey,
    receiver.getViewingKeyPair().pubkey,
    note.random,
    note.senderRandom as string,
  );
  let { blindedSenderViewingKey } = blinded;
  let sharedKey = await getSharedSymmetricKey(
    sender.getViewingKeyPair().privateKey,
    blinded.blindedReceiverViewingKey,
  );
  if (torsionedSenderKey) {
    blindedSenderViewingKey = ExtendedPoint.fromAffine(Point.fromHex(blindedSenderViewingKey))
      .add(ExtendedPoint.fromAffine(Point.fromHex(TORSION_POINT)))
      .toAffine()
      .toRawBytes();
    sharedKey = await getSharedSymmetricKey(
      receiver.getViewingKeyPair().privateKey,
      blindedSenderViewingKey,
    );
  }
  if (!sharedKey) throw new Error('No shared key');
  const { noteCiphertext, noteMemo, annotationData } = note.encryptV2(
    txidVersion,
    sharedKey,
    sender.addressKeys.masterPublicKey,
    note.senderRandom,
    sender.getViewingKeyPair().privateKey,
  );
  const event = V2Events.formatTransactEvent(
    {
      treeNumber: 0n,
      startPosition: 0n,
      hash: [ByteUtils.nToHex(note.hash, ByteLength.UINT_256, true)],
      ciphertext: [
        {
          ciphertext: [
            ByteUtils.hexlify(`${noteCiphertext.iv}${noteCiphertext.tag}`, true),
            ByteUtils.hexlify(noteCiphertext.data[0], true),
            ByteUtils.hexlify(noteCiphertext.data[1], true),
            ByteUtils.hexlify(noteCiphertext.data[2], true),
          ],
          blindedSenderViewingKey: ByteUtils.hexlify(blindedSenderViewingKey, true),
          blindedReceiverViewingKey: ByteUtils.hexlify(blinded.blindedReceiverViewingKey, true),
          memo: ByteUtils.hexlify(noteMemo, true),
          annotationData: ByteUtils.hexlify(annotationData, true),
        },
      ],
    } as never,
    `0x${'cd'.repeat(32)}`,
    2,
    undefined,
  );
  return event.commitments[0];
};

const leafPoints = (leaf: Optional<Commitment>): Uint8Array[] => {
  if (!leaf) return [];
  if ('shieldKey' in leaf) return [ByteUtils.hexToBytes(leaf.shieldKey)];
  if ('ciphertext' in leaf && 'blindedSenderViewingKey' in leaf.ciphertext) {
    return [
      ByteUtils.hexStringToBytes(leaf.ciphertext.blindedSenderViewingKey),
      ByteUtils.hexStringToBytes(leaf.ciphertext.blindedReceiverViewingKey),
    ];
  }
  return [];
};

/** What a cold scan of `leaves` writes for the wallet, with and without the fast pass. */
const scanBothWays = async (
  build: (wallets: RailgunWallet[]) => Promise<Optional<Commitment>[]>,
  walletCount: number,
) => {
  const fastWallets = await Promise.all(Array.from({ length: walletCount }, createWallet));
  const leaves = await build(fastWallets.map(({ wallet }) => wallet));

  setFastScanEnabled(true);
  for (const { wallet } of fastWallets) {
    // eslint-disable-next-line no-await-in-loop
    await wallet.scanLeaves(txidVersion, leaves, 0, chain, 0, undefined);
  }
  const fast = fastWallets.map(({ writes }) => [...writes]);
  for (const { writes } of fastWallets) writes.length = 0;

  setFastScanEnabled(false);
  try {
    for (const { wallet } of fastWallets) {
      // eslint-disable-next-line no-await-in-loop
      await wallet.scanLeaves(txidVersion, leaves, 0, chain, 0, undefined);
    }
  } finally {
    setFastScanEnabled(true);
  }
  const engine = fastWallets.map(({ writes }) => [...writes]);
  return { fast, engine, wallets: fastWallets.map(({ wallet }) => wallet), leaves };
};

describe('fast-scan', function run() {
  this.timeout(60_000);

  before(() => {
    WalletInfo.setWalletSource('fast scan test');
  });

  beforeEach(() => {
    clearFastScanCache();
  });

  it('finds the same shield and transfer notes as the engine, for receiver and sender', async () => {
    const { fast, engine, leaves } = await scanBothWays(async ([alice, bob, carol]) => {
      const strangers = await Promise.all([createWallet(), createWallet()]);
      const [s1, s2] = strangers.map(({ wallet }) => wallet);
      return [
        await shieldLeaf(s1),
        await shieldLeaf(alice),
        undefined,
        await transferLeaf(s1, s2),
        await transferLeaf(alice, bob),
        await shieldLeaf(s2),
        await transferLeaf(carol, alice),
      ];
    }, 3);
    // Every honest point takes the fast path; otherwise this test proves nothing.
    for (const leaf of leaves) {
      for (const point of leafPoints(leaf)) expect(isTorsionFreePoint(point)).to.equal(true);
    }
    const [alice, bob, carol] = fast;
    // alice: her shield (receive), her send to bob (sent), carol's send to her (receive).
    expect(alice.length).to.equal(3);
    // bob: alice's send to him. carol: her send to alice.
    expect(bob.length).to.equal(1);
    expect(carol.length).to.equal(1);
    expect(fast).to.deep.equal(engine);
  });

  it('falls back to the engine for a point with a small-order component', async () => {
    const { fast, engine, leaves } = await scanBothWays(async ([alice, bob]) => {
      return [await transferLeaf(alice, bob, true)];
    }, 2);
    const leaf = leaves[0] as Commitment & { ciphertext: { blindedSenderViewingKey: string } };
    expect(
      isTorsionFreePoint(ByteUtils.hexStringToBytes(leaf.ciphertext.blindedSenderViewingKey)),
    ).to.equal(false);
    // bob receives it only through the engine's multiplication of the torsioned key.
    expect(engine[1].length).to.equal(1);
    expect(fast).to.deep.equal(engine);
  });

  it('flags nothing for leaves addressed to other wallets', async () => {
    const { wallet } = await createWallet();
    const others = await Promise.all([createWallet(), createWallet()]);
    const [a, b] = others.map(({ wallet: other }) => other);
    const leaves = [await shieldLeaf(a), await transferLeaf(a, b), await transferLeaf(b, a)];
    const prefilter = await LeafPrefilter.create(wallet.getViewingKeyPair().privateKey);
    expect(prefilter).to.not.equal(undefined);
    expect(await prefilter?.mightBeMine(leaves)).to.deep.equal([false, false, false]);
  });

  it('keeps the batch correct when a leaf carries the identity or a non-canonical point', async () => {
    const { fast, engine } = await scanBothWays(async ([alice, bob]) => {
      const strangers = await Promise.all([createWallet(), createWallet()]);
      const [s1, s2] = strangers.map(({ wallet }) => wallet);
      const identity = await transferLeaf(s1, s2);
      const nonCanonical = await transferLeaf(s2, s1);
      // y = 1 (identity), and y = p + 1 (a non-canonical encoding of it).
      (
        identity as unknown as { ciphertext: { blindedSenderViewingKey: string } }
      ).ciphertext.blindedSenderViewingKey = `01${'00'.repeat(31)}`;
      (
        nonCanonical as unknown as { ciphertext: { blindedReceiverViewingKey: string } }
      ).ciphertext.blindedReceiverViewingKey = `ee${'ff'.repeat(30)}7f`;
      return [identity, await transferLeaf(alice, bob), nonCanonical, await shieldLeaf(bob)];
    }, 2);
    expect(fast[0].length).to.equal(1);
    expect(fast[1].length).to.equal(2);
    expect(fast).to.deep.equal(engine);
  });

  it('flags leaf types it does not handle', async () => {
    const { wallet } = await createWallet();
    const prefilter = await LeafPrefilter.create(wallet.getViewingKeyPair().privateKey);
    const unknown = { commitmentType: 'LegacyGeneratedCommitment' } as unknown as Commitment;
    expect(await prefilter?.mightBeMine([unknown])).to.deep.equal([true]);
  });

  it('checks torsion for valid, torsioned and invalid points', () => {
    expect(isTorsionFreePoint(new Uint8Array(32).fill(0xff))).to.equal(false);
    expect(isTorsionFreePoint(Point.BASE.toRawBytes())).to.equal(true);
    expect(isTorsionFreePoint(Point.BASE.multiply(123456789n).toRawBytes())).to.equal(true);
    expect(isTorsionFreePoint(Point.fromHex(TORSION_POINT).toRawBytes())).to.equal(false);
  });
});
