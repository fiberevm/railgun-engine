import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import memdown from 'memdown';
import sinon from 'sinon';
import { RailgunEngine } from '../railgun-engine';
import { UTXOMerkletree } from '../merkletree/utxo-merkletree';
import { Database } from '../database/database';
import { Chain, ChainType } from '../models/engine-types';
import { TXIDVersion } from '../models/poi-types';
import { ByteLength, ByteUtils } from '../utils/bytes';

chai.use(chaiAsPromised);
const { expect } = chai;

const txidVersion = TXIDVersion.V2_PoseidonMerkle;
const chain: Chain = { type: ChainType.EVM, id: 1 };

describe('railgun-engine-nullifier-collision', () => {
    let engine: RailgunEngine;
    let db: Database;
    let utxoMerkletree: UTXOMerkletree;

    beforeEach(async () => {
        const artifactGetter = {
            assertArtifactExists: () => {},
            getArtifacts: async () => ({ zkey: [], wasm: undefined, dat: undefined, vkey: {} }),
            getArtifactsPOI: async () => ({ zkey: [], wasm: undefined, dat: undefined, vkey: {} }),
        };
        const quickSyncEvents = async () => ({
            commitmentEvents: [],
            nullifierEvents: [],
            unshieldEvents: [],
        });
        const quickSyncRailgunTransactionsV2 = async () => [];
        
        engine = await RailgunEngine.initForWallet(
            'testwallet',
            memdown(),
            artifactGetter,
            quickSyncEvents,
            quickSyncRailgunTransactionsV2,
            async () => true, // validateRailgunTxidMerkleroot
            async () => ({ txidIndex: undefined, merkleroot: undefined }), // getLatestValidatedRailgunTxid
            undefined, // engineDebugger
            false, // skipMerkletreeScans
        );

        db = new Database(memdown());
        utxoMerkletree = await UTXOMerkletree.create(db, chain, txidVersion, async () => true);
        
        sinon.stub(engine as any, 'getUTXOMerkletree').returns(utxoMerkletree);
        sinon.stub(utxoMerkletree, 'latestTree').resolves(1);
    });

    afterEach(() => {
        sinon.restore();
    });

    it('Should find completed txid across trees correctly', async () => {
        // Scenario:
        // Transaction 0 (TxID 1000): Nullifiers A, B in Tree 0
        // Transaction 1 (TxID 1001): Nullifiers A, B in Tree 1
        
        await utxoMerkletree.nullify([
            { nullifier: 'A', treeNumber: 0, txid: '1000', blockNumber: 0 },
            { nullifier: 'B', treeNumber: 0, txid: '1000', blockNumber: 0 },
            { nullifier: 'A', treeNumber: 1, txid: '1001', blockNumber: 0 },
            { nullifier: 'B', treeNumber: 1, txid: '1001', blockNumber: 0 },
        ]);

        const result = await engine.getCompletedTxidFromNullifiers(txidVersion, chain, ['A', 'B']);
        
        const expected = ByteUtils.formatToByteLength('1001', ByteLength.UINT_256, true);
        expect(result).to.equal(expected);
    });

    it('Should fallback to older trees if nullifiers match there', async () => {
        // Scenario:
        // Tree 1: A->1001, B->undefined (Partial / Mismatch)
        // Tree 0: A->1000, B->1000 (Complete match)
        
        await utxoMerkletree.nullify([
            { nullifier: 'A', treeNumber: 0, txid: '1000', blockNumber: 0 },
            { nullifier: 'B', treeNumber: 0, txid: '1000', blockNumber: 0 },
            { nullifier: 'A', treeNumber: 1, txid: '1001', blockNumber: 0 },
        ]);

        const result = await engine.getCompletedTxidFromNullifiers(txidVersion, chain, ['A', 'B']);
        const expected = ByteUtils.formatToByteLength('1000', ByteLength.UINT_256, true);
        
        expect(result).to.equal(expected);
    });

    it('Should return undefined if nullifiers match in different trees but not same tree', async () => {
        // Scenario:
        // Nullifier A in Tree 1 (1001)
        // Nullifier B in Tree 0 (1000)
        
        await utxoMerkletree.nullify([
            { nullifier: 'B', treeNumber: 0, txid: '1000', blockNumber: 0 },
            { nullifier: 'A', treeNumber: 1, txid: '1001', blockNumber: 0 },
        ]);

        const result = await engine.getCompletedTxidFromNullifiers(txidVersion, chain, ['A', 'B']);
        // eslint-disable-next-line no-unused-expressions
        expect(result).to.be.undefined;
    });

    it('Should handle sparse trees correctly (skip empty trees)', async () => {
        // Scenario:
        // Tree 2: Empty / Undefined (mocked via latestTree=2)
        // Tree 1: Match found
        
        (utxoMerkletree.latestTree as sinon.SinonStub).resolves(2);
        
        await utxoMerkletree.nullify([
            { nullifier: 'A', treeNumber: 1, txid: '1001', blockNumber: 0 },
            { nullifier: 'B', treeNumber: 1, txid: '1001', blockNumber: 0 },
        ]);

        const result = await engine.getCompletedTxidFromNullifiers(txidVersion, chain, ['A', 'B']);
        const expected = ByteUtils.formatToByteLength('1001', ByteLength.UINT_256, true);
        expect(result).to.equal(expected);
    });

    it('Should fail if nullifiers map to different TXIDs within the same tree', async () => {
        // Scenario:
        // Tree 1: A -> 1001, B -> 1002 (Different transactions in same tree)
        
        await utxoMerkletree.nullify([
            { nullifier: 'A', treeNumber: 1, txid: '1001', blockNumber: 0 },
            { nullifier: 'B', treeNumber: 1, txid: '1002', blockNumber: 0 },
        ]);

        const result = await engine.getCompletedTxidFromNullifiers(txidVersion, chain, ['A', 'B']);
        // eslint-disable-next-line no-unused-expressions
        expect(result).to.be.undefined;
    });
});
