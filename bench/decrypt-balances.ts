/**
 * End-to-end cold balance check: pool history in a UTXOMerkletree (memdown), then a fresh
 * wallet's decryptBalances, which reads every leaf back from the tree and scans it.
 *   npx ts-node --transpile-only bench/decrypt-balances.ts [snapshotDir] [chain...]
 */
import path from 'path';
import memdown from 'memdown';
import { loadLeaves } from './scan-bench';
import { Database } from '../src/database/database';
import { UTXOMerkletree } from '../src/merkletree/utxo-merkletree';
import { RailgunWallet } from '../src/wallet/railgun-wallet';
import { Prover } from '../src/prover/prover';
import { Mnemonic } from '../src/key-derivation/bip39';
import { ByteUtils } from '../src/utils/bytes';
import { ChainType } from '../src/models/engine-types';
import { TXIDVersion } from '../src/models/poi-types';
import { setFastScanEnabled } from '../src/utils/fast-scan';
import { addChainSupportsV3 } from '../src/chain/chain';

const SNAPSHOT_DIR = process.argv[2] ?? path.join(process.env.HOME as string, 'code/recovery/src/snapshots');
const CHAINS = process.argv.length > 3 ? process.argv.slice(3) : ['ethereum', 'arbitrum', 'base', 'bnb'];
const txidVersion = TXIDVersion.V2_PoseidonMerkle;
const now = () => Number(process.hrtime.bigint()) / 1e6;
const fmt = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms.toFixed(1)} ms`);

(async () => {
  for (const name of CHAINS) {
    const { trees } = await loadLeaves(path.join(SNAPSHOT_DIR, `${name}.json`));
    const chain = { type: ChainType.EVM, id: 1 };
    addChainSupportsV3(chain);
    const db = new Database(memdown());
    const merkletree = await UTXOMerkletree.create(db, chain, txidVersion, async () => true);
    let t = now();
    for (let tree = 0; tree < trees.length; tree += 1) {
      await merkletree.queueLeaves(tree, 0, trees[tree]);
    }
    await merkletree.updateTreesFromWriteQueue(true);
    const leafCount = trees.reduce((n, tr) => n + tr.length, 0);
    console.log(`\n=== ${name}: ${leafCount} leaves; build merkle tree (poseidon + db writes): ${fmt(now() - t)}`);

    t = now();
    for (let tree = 0; tree < trees.length; tree += 1) {
      const len = await merkletree.getTreeLength(tree);
      for (let s = 0; s < len; s += 1600) await merkletree.getCommitmentRange(tree, s, Math.min(s + 1600, len) - 1);
    }
    console.log(`read all leaves back (getCommitmentRange, 1600/batch): ${fmt(now() - t)}`);

    for (const fast of [false, true, true]) {
      setFastScanEnabled(fast);
      const wallet = await RailgunWallet.fromMnemonic(db, ByteUtils.randomHex(32), Mnemonic.generate(), 0, undefined, new Prover({} as never));
      await wallet.loadUTXOMerkletree(txidVersion, merkletree);
      t = now();
      await wallet.decryptBalances(txidVersion, chain, undefined, true);
      const scan = now() - t;
      t = now();
      const balances = await wallet.getTokenBalances(txidVersion, chain, false);
      console.log(`decryptBalances fast=${fast}: ${fmt(scan)}; getTokenBalances: ${fmt(now() - t)} (${Object.keys(balances).length} tokens)`);
    }
  }
})().catch((e) => { console.error(e); process.exit(1); });
