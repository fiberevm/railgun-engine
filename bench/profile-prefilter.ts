import path from 'path';
import { randomBytes } from 'crypto';
import { loadLeaves } from './scan-bench';
import { LeafPrefilter, setFastScanPoolEnabled } from '../src/utils/fast-scan';
const now = () => Number(process.hrtime.bigint()) / 1e6;
(async () => {
  const { trees } = await loadLeaves(path.join(process.env.HOME as string, 'code/recovery/src/snapshots/base.json'));
  const p = (await LeafPrefilter.create(randomBytes(32)))!;
  for (const pool of [false, true]) {
    setFastScanPoolEnabled(pool);
    for (let i = 0; i < 3; i += 1) { const t = now(); await p.mightBeMine(trees[0]); console.log(`pool=${pool} run${i}: ${(now() - t).toFixed(1)} ms`); }
  }
})();
