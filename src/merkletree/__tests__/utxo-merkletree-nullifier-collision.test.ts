import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import memdown from 'memdown';
import { Database } from '../../database/database';
import { UTXOMerkletree } from '../utxo-merkletree';
import { Chain } from '../../models/engine-types';
import { getTestTXIDVersion } from '../../test/helper.test';

chai.use(chaiAsPromised);
const { expect } = chai;

const txidVersion = getTestTXIDVersion();

describe('utxo-merkletree-nullifier-collision', () => {
    let db: Database;
    let merkletree: UTXOMerkletree;
    const chain: Chain = { type: 0, id: 0 };

    beforeEach(async () => {
        db = new Database(memdown());
        merkletree = await UTXOMerkletree.create(db, chain, txidVersion, async () => true);
        
        // @ts-ignore
        merkletree.latestTree = async () => 1;
    });

    it('Should retrieve nullifier txid from specific tree', async () => {
        await merkletree.nullify([{ nullifier: 'COLLISION', treeNumber: 0, txid: '1000', blockNumber: 0 }]);
        await merkletree.nullify([{ nullifier: 'COLLISION', treeNumber: 1, txid: '1001', blockNumber: 0 }]);

        expect(await merkletree.getNullifierTxid('COLLISION', 0)).to.equal('1000');
        expect(await merkletree.getNullifierTxid('COLLISION', 1)).to.equal('1001');
    });

    it('Should return correct txid when searching without tree parameter (latest tree priority)', async () => {
        await merkletree.nullify([{ nullifier: 'COLLISION', treeNumber: 0, txid: '1000', blockNumber: 0 }]);
        await merkletree.nullify([{ nullifier: 'COLLISION', treeNumber: 1, txid: '1001', blockNumber: 0 }]);

        // Should return '1001' because it searches tree 1 first (latestTree = 1)
        expect(await merkletree.getNullifierTxid('COLLISION')).to.equal('1001');
    });

    it('Should find nullifiers that exist only in older trees', async () => {
        await merkletree.nullify([{ nullifier: 'UNIQUE0', treeNumber: 0, txid: '2000', blockNumber: 0 }]);

        // Should start at tree 1 (empty), fail, then go to tree 0 and find it
        expect(await merkletree.getNullifierTxid('UNIQUE0')).to.equal('2000');
    });

    it('Should return undefined for non-existent nullifiers', async () => {
        // eslint-disable-next-line no-unused-expressions
        expect(await merkletree.getNullifierTxid('NONEXISTENT')).to.be.undefined;
        // eslint-disable-next-line no-unused-expressions
        expect(await merkletree.getNullifierTxid('NONEXISTENT', 0)).to.be.undefined;
        // eslint-disable-next-line no-unused-expressions
        expect(await merkletree.getNullifierTxid('NONEXISTENT', 1)).to.be.undefined;
    });

    it('Should handle batch insertion of nullifiers', async () => {
        await merkletree.nullify([
            { nullifier: 'A', treeNumber: 0, txid: '00A0', blockNumber: 0 },
            { nullifier: 'B', treeNumber: 0, txid: '00B0', blockNumber: 0 },
            { nullifier: 'C', treeNumber: 1, txid: '00C0', blockNumber: 0 }
        ]);

        expect(await merkletree.getNullifierTxid('A', 0)).to.equal('00a0');
        expect(await merkletree.getNullifierTxid('B', 0)).to.equal('00b0');
        expect(await merkletree.getNullifierTxid('C', 1)).to.equal('00c0');
        
        // Also check via iteration
        expect(await merkletree.getNullifierTxid('A')).to.equal('00a0');
        expect(await merkletree.getNullifierTxid('C')).to.equal('00c0');
    });

    it('Should overwrite nullifier txid if added again to same tree', async () => {
        await merkletree.nullify([{ nullifier: 'OVERWRITE', treeNumber: 0, txid: '1111', blockNumber: 0 }]);
        expect(await merkletree.getNullifierTxid('OVERWRITE', 0)).to.equal('1111');

        await merkletree.nullify([{ nullifier: 'OVERWRITE', treeNumber: 0, txid: '2222', blockNumber: 1 }]);
        expect(await merkletree.getNullifierTxid('OVERWRITE', 0)).to.equal('2222');
    });

    it('Should respect sparse tree usage', async () => {
        // If we have data in Tree 0 and Tree 2, but skip Tree 1
        
        // @ts-ignore
        merkletree.latestTree = async () => 2;

        await merkletree.nullify([{ nullifier: 'SPARSE', treeNumber: 0, txid: '3000', blockNumber: 0 }]);
        await merkletree.nullify([{ nullifier: 'SPARSE', treeNumber: 2, txid: '3002', blockNumber: 0 }]);

        // Search from 2 -> 0
        expect(await merkletree.getNullifierTxid('SPARSE')).to.equal('3002');
        
        // Specific checks
        expect(await merkletree.getNullifierTxid('SPARSE', 0)).to.equal('3000');
        // eslint-disable-next-line no-unused-expressions
        expect(await merkletree.getNullifierTxid('SPARSE', 1)).to.be.undefined;
        expect(await merkletree.getNullifierTxid('SPARSE', 2)).to.equal('3002');
    });
});
