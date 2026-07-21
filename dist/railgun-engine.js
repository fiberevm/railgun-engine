"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RailgunEngine = void 0;
const events_1 = __importDefault(require("events"));
const railgun_smart_wallet_1 = require("./contracts/railgun-smart-wallet/V2/railgun-smart-wallet");
const relay_adapt_v2_1 = require("./contracts/relay-adapt/V2/relay-adapt-v2");
const database_1 = require("./database/database");
const prover_1 = require("./prover/prover");
const bech32_1 = require("./key-derivation/bech32");
const bytes_1 = require("./utils/bytes");
const railgun_wallet_1 = require("./wallet/railgun-wallet");
const debugger_1 = __importDefault(require("./debugger/debugger"));
const formatted_types_1 = require("./models/formatted-types");
const event_types_1 = require("./models/event-types");
const view_only_wallet_1 = require("./wallet/view-only-wallet");
const abstract_wallet_1 = require("./wallet/abstract-wallet");
const wallet_info_1 = __importDefault(require("./wallet/wallet-info"));
const chain_1 = require("./chain/chain");
const contract_store_1 = require("./contracts/contract-store");
const constants_1 = require("./utils/constants");
const polling_util_1 = require("./provider/polling-util");
const is_defined_1 = require("./utils/is-defined");
const utxo_merkletree_1 = require("./merkletree/utxo-merkletree");
const txid_merkletree_1 = require("./merkletree/txid-merkletree");
const promises_1 = require("./utils/promises");
const poseidon_1 = require("./utils/poseidon");
const scalar_multiply_1 = require("./utils/scalar-multiply");
const railgun_txid_1 = require("./transaction/railgun-txid");
const poi_types_1 = require("./models/poi-types");
const note_util_1 = require("./note/note-util");
const note_1 = require("./note");
const poseidon_merkle_accumulator_1 = require("./contracts/railgun-smart-wallet/V3/poseidon-merkle-accumulator");
const poseidon_merkle_verifier_1 = require("./contracts/railgun-smart-wallet/V3/poseidon-merkle-verifier");
const token_vault_contract_1 = require("./contracts/railgun-smart-wallet/V3/token-vault-contract");
const registry_1 = require("./utils/registry");
const bigint_1 = require("./utils/bigint");
const commitment_1 = require("./utils/commitment");
class RailgunEngine extends events_1.default {
    db;
    utxoMerkletrees = new registry_1.Registry();
    txidMerkletrees = new registry_1.Registry();
    prover;
    wallets = {};
    deploymentBlocks = new registry_1.Registry();
    quickSyncEvents;
    quickSyncRailgunTransactionsV2;
    validateRailgunTxidMerkleroot;
    getLatestValidatedRailgunTxid;
    static walletSource;
    skipMerkletreeScans;
    hasSyncedRailgunTransactionsV2 = new registry_1.Registry();
    constructor(walletSource, leveldown, artifactGetter, quickSyncEvents, quickSyncRailgunTransactionsV2, validateRailgunTxidMerkleroot, getLatestValidatedRailgunTxid, engineDebugger, skipMerkletreeScans) {
        super();
        wallet_info_1.default.setWalletSource(walletSource);
        this.db = new database_1.Database(leveldown);
        this.prover = new prover_1.Prover(artifactGetter);
        this.quickSyncEvents = quickSyncEvents;
        this.quickSyncRailgunTransactionsV2 = quickSyncRailgunTransactionsV2;
        this.validateRailgunTxidMerkleroot = validateRailgunTxidMerkleroot ?? (async () => true);
        this.getLatestValidatedRailgunTxid =
            getLatestValidatedRailgunTxid ??
                (async () => ({ txidIndex: undefined, merkleroot: undefined }));
        if (engineDebugger) {
            debugger_1.default.init(engineDebugger);
        }
        this.skipMerkletreeScans = skipMerkletreeScans;
    }
    /**
     * Create a RAILGUN Engine instance for a RAILGUN-compatible Wallet.
     * @param walletSource - string representing your wallet's name (16 char max, lowercase and numerals only)
     * @param leveldown - abstract-leveldown compatible store
     * @param artifactGetter - async function to retrieve artifacts
     * @param quickSync - quick sync function to speed up sync
     * @param engineDebugger - log and error callbacks for verbose logging
     * @param skipMerkletreeScans - whether to skip UTXO merkletree scans - useful for shield-only interfaces without Railgun wallets.
     */
    static async initForWallet(walletSource, leveldown, artifactGetter, quickSyncEvents, quickSyncRailgunTransactionsV2, validateRailgunTxidMerkleroot, getLatestValidatedRailgunTxid, engineDebugger, skipMerkletreeScans = false) {
        await poseidon_1.initPoseidonPromise;
        await scalar_multiply_1.initCurve25519Promise;
        return new RailgunEngine(walletSource, leveldown, artifactGetter, quickSyncEvents, quickSyncRailgunTransactionsV2, validateRailgunTxidMerkleroot, getLatestValidatedRailgunTxid, engineDebugger, skipMerkletreeScans);
    }
    static setEngineDebugger = (engineDebugger) => {
        debugger_1.default.init(engineDebugger);
    };
    /**
     * Handle new commitment events and kick off balance scan on wallets
     * @param chain - chain type/id for commitments
     * @param treeNumber - tree of commitments
     * @param startingIndex - starting index of commitments
     * @param leaves - commitment data from events
     */
    async commitmentListener(txidVersion, chain, events, shouldUpdateTrees, shouldTriggerV2TxidSync, skipValidation = false) {
        if (this.db.isClosed()) {
            return;
        }
        if (!events.length) {
            return;
        }
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        for (const event of events) {
            const { treeNumber, startPosition, commitments } = event;
            if (debugger_1.default.verboseScanLogging()) {
                debugger_1.default.log(`[commitmentListener: ${chain.type}:${chain.id}]: ${commitments.length} leaves at ${startPosition}`);
            }
            for (const commitment of commitments) {
                commitment.txid = bytes_1.ByteUtils.formatToByteLength(commitment.txid, bytes_1.ByteLength.UINT_256, false);
            }
            // Queue leaves to merkle tree
            for (const commitment of commitments) {
                const normalizedIndex = commitment.utxoIndex % 2 ** 16;
                const normalizedTreeNumber = commitment.utxoTree + (commitment.utxoIndex >> 16);
                // eslint-disable-next-line no-await-in-loop
                await utxoMerkletree.queueLeaves(normalizedTreeNumber, normalizedIndex, [commitment]);
            }
        }
        if (shouldUpdateTrees) {
            await utxoMerkletree.updateTreesFromWriteQueue(skipValidation);
        }
        if (shouldTriggerV2TxidSync) {
            // eslint-disable-next-line @typescript-eslint/no-floating-promises
            this.triggerDelayedTXIDMerkletreeSyncV2(chain);
        }
    }
    async triggerDelayedTXIDMerkletreeSyncV2(chain, scanCount = 0) {
        // Delay and then trigger a Railgun Txid Merkletree sync.
        if (scanCount === 0) {
            // Delay for 10 seconds on first scan for wallet
            await (0, promises_1.delay)(10000);
        }
        else {
            // Delay for 5 seconds on for subsequent scans for wallet
            await (0, promises_1.delay)(5000);
        }
        await this.syncRailgunTransactionsV2(chain, 'delayed sync after new utxo');
        // Scan for 2 times total
        if (scanCount < 1) {
            // eslint-disable-next-line @typescript-eslint/no-floating-promises
            this.triggerDelayedTXIDMerkletreeSyncV2(chain, scanCount + 1);
        }
    }
    /**
     * Handle new nullifiers
     * @param chain - chain type/id for nullifiers
     * @param nullifiers - transaction info to nullify commitment
     */
    async nullifierListener(txidVersion, chain, nullifiers) {
        if (this.db.isClosed()) {
            return;
        }
        if (!nullifiers.length) {
            return;
        }
        debugger_1.default.log(`engine.nullifierListener[${chain.type}:${chain.id}] ${nullifiers.length}`);
        for (const nullifier of nullifiers) {
            nullifier.txid = bytes_1.ByteUtils.formatToByteLength(nullifier.txid, bytes_1.ByteLength.UINT_256, false);
            nullifier.nullifier = bytes_1.ByteUtils.formatToByteLength(nullifier.nullifier, bytes_1.ByteLength.UINT_256, false);
        }
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        await utxoMerkletree.nullify(nullifiers);
        this.invalidateTXOsCacheAllWallets(chain);
    }
    /**
     * Handle new unshield events
     * @param chain - chain type/id
     * @param unshields - unshield events
     */
    async unshieldListener(txidVersion, chain, unshields) {
        if (this.db.isClosed()) {
            return;
        }
        if (!unshields.length) {
            return;
        }
        debugger_1.default.log(`engine.unshieldListener[${chain.type}:${chain.id}] ${unshields.length}`);
        for (const unshield of unshields) {
            unshield.txid = bytes_1.ByteUtils.formatToByteLength(unshield.txid, bytes_1.ByteLength.UINT_256, false);
        }
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        await utxoMerkletree.addUnshieldEvents(unshields);
        this.invalidateTXOsCacheAllWallets(chain);
    }
    /**
     * Handle new railgun transaction events for V3
     * @param chain - chain type/id
     * @param railgunTransactions - railgun transaction events
     */
    async railgunTransactionsV3Listener(txidVersion, chain, railgunTransactions) {
        if (this.db.isClosed()) {
            return;
        }
        if (!railgunTransactions.length) {
            return;
        }
        if (txidVersion !== poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
            throw new Error('Railgun transactions listener only supported for V3 Poseidon Merkle');
        }
        debugger_1.default.log(`engine.railgunTransactions[${chain.type}:${chain.id}] ${railgunTransactions.length}`);
        await this.handleNewRailgunTransactionsV3(txidVersion, chain, railgunTransactions);
    }
    async getMostRecentValidCommitmentBlock(txidVersion, chain) {
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        const railgunSmartWalletContract = contract_store_1.ContractStore.railgunSmartWalletContracts.get(null, chain);
        if (!(0, is_defined_1.isDefined)(railgunSmartWalletContract)) {
            throw new Error('No RailgunSmartWalletContract loaded.');
        }
        const provider = railgunSmartWalletContract.contract.runner?.provider;
        if (!provider) {
            throw new Error('Requires provider for commitment block lookup');
        }
        // Get latest tree
        const firstInvalidMerklerootTree = utxoMerkletree.getFirstInvalidMerklerootTree();
        const searchTree = firstInvalidMerklerootTree ?? (await utxoMerkletree.latestTree());
        // Get latest synced event
        const treeLength = await utxoMerkletree.getTreeLength(searchTree);
        debugger_1.default.log(`scanHistory: searchTree ${searchTree}, treeLength ${treeLength}`);
        let startScanningBlock;
        let latestEventIndex = treeLength - 1;
        while (latestEventIndex >= 0 && !(0, is_defined_1.isDefined)(startScanningBlock)) {
            // Get block number of last scanned event
            // eslint-disable-next-line no-await-in-loop
            const latestEvent = await utxoMerkletree.getCommitment(searchTree, latestEventIndex);
            if ((0, is_defined_1.isDefined)(latestEvent)) {
                if (latestEvent.blockNumber) {
                    startScanningBlock = latestEvent.blockNumber;
                }
                else {
                    // eslint-disable-next-line no-await-in-loop
                    const txReceipt = await provider.getTransactionReceipt(bytes_1.ByteUtils.hexlify(latestEvent.txid, true));
                    if (txReceipt) {
                        startScanningBlock = txReceipt.blockNumber;
                    }
                }
            }
            else {
                debugger_1.default.log(`Could not find latest event for index ${latestEventIndex}. Trying prior index.`);
            }
            latestEventIndex -= 1;
        }
        return startScanningBlock;
    }
    async getStartScanningBlock(txidVersion, chain) {
        let startScanningBlock = await this.getMostRecentValidCommitmentBlock(txidVersion, chain);
        debugger_1.default.log(`[${txidVersion}] most recent valid commitment block: ${startScanningBlock ?? 'unknown'}`);
        if (startScanningBlock == null) {
            // If we haven't scanned anything yet, start scanning at deployment block
            startScanningBlock = this.deploymentBlocks.get(txidVersion, chain);
            if (!(0, is_defined_1.isDefined)(startScanningBlock)) {
                throw new Error(`Deployment block not defined for ${txidVersion} and chain ${chain.type}:${chain.id}`);
            }
        }
        return startScanningBlock;
    }
    async performQuickSync(txidVersion, chain, endProgress, retryCount = 0, throwOnFailure = false) {
        try {
            debugger_1.default.log(`[${txidVersion}] quickSync: chain ${chain.type}:${chain.id}`);
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            const startScanningBlockQuickSync = await this.getStartScanningBlock(txidVersion, chain);
            debugger_1.default.log(`[${txidVersion}] Start scanning block for QuickSync: ${startScanningBlockQuickSync}`);
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, endProgress * 0.2); // 10% / 50%
            // Fetch events
            const { commitmentEvents, unshieldEvents, nullifierEvents, railgunTransactionEvents } = await this.quickSyncEvents(txidVersion, chain, startScanningBlockQuickSync);
            if (railgunTransactionEvents) {
                debugger_1.default.log(`[${txidVersion}] QuickSync railgunTransactionEvents: ${railgunTransactionEvents.length}`);
                await this.handleNewRailgunTransactionsV3(txidVersion, chain, railgunTransactionEvents);
            }
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, endProgress * 0.3); // 15% / 50%
            await this.unshieldListener(txidVersion, chain, unshieldEvents);
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, endProgress * 0.5); // 25% / 50%
            await this.nullifierListener(txidVersion, chain, nullifierEvents);
            debugger_1.default.log(`[${txidVersion}] QuickSync commitments: ${commitmentEvents.length}`);
            // Make sure commitments are scanned after Unshields and Nullifiers.
            await this.commitmentListener(txidVersion, chain, commitmentEvents, false, // shouldUpdateTrees - wait until after all commitments added
            false);
            // Scan after all leaves added.
            if (commitmentEvents.length) {
                this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, endProgress * 0.6); // 30% / 50%
                await utxoMerkletree.updateTreesFromWriteQueue(true);
                this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, endProgress * 0.8); // 40% / 50%
            }
        }
        catch (cause) {
            if (retryCount < 1) {
                await this.performQuickSync(txidVersion, chain, endProgress, retryCount + 1, throwOnFailure);
                return;
            }
            if (throwOnFailure) {
                throw new Error('Failed to quick sync', { cause });
            }
            debugger_1.default.error(new Error('Failed to quick sync', { cause }));
        }
    }
    emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, progress) {
        const updateData = {
            scanStatus: event_types_1.MerkletreeScanStatus.Updated,
            txidVersion,
            chain,
            progress,
        };
        this.emit(event_types_1.EngineEvent.UTXOMerkletreeHistoryScanUpdate, updateData);
    }
    emitTXIDMerkletreeScanUpdateEvent(txidVersion, chain, progress) {
        const updateData = {
            scanStatus: event_types_1.MerkletreeScanStatus.Updated,
            txidVersion,
            chain,
            progress,
        };
        this.emit(event_types_1.EngineEvent.TXIDMerkletreeHistoryScanUpdate, updateData);
    }
    async getNextStartingBlockSlowScan(txidVersion, chain) {
        // Get updated start-scanning block from new valid utxoMerkletree.
        let startScanningBlockSlowScan = await this.getStartScanningBlock(txidVersion, chain);
        const lastSyncedBlock = await this.getLastSyncedBlock(txidVersion, chain);
        debugger_1.default.log(`[${txidVersion}] lastSyncedBlock: ${lastSyncedBlock ?? 'unknown'}`);
        if ((0, is_defined_1.isDefined)(lastSyncedBlock) && lastSyncedBlock > startScanningBlockSlowScan) {
            startScanningBlockSlowScan = lastSyncedBlock;
        }
        return startScanningBlockSlowScan;
    }
    /**
     * Scan contract history and sync
     * @param chain - chain type/id to scan
     * @param walletIdFilter - optional list of wallet ids to decrypt balances
     */
    async scanContractHistory(chain, walletIdFilter) {
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            // eslint-disable-next-line no-await-in-loop
            await this.scanUTXOHistory(txidVersion, chain, walletIdFilter);
        }
        await this.scanTXIDHistoryV2(chain);
    }
    /** Scans V2 history and proves selected wallet balances cover a minimum block. */
    async scanWalletBalancesThroughBlock(txidVersion, chain, walletIdFilter, minimumBlockNumber) {
        if (txidVersion !== poi_types_1.TXIDVersion.V2_PoseidonMerkle) {
            throw new Error('Wallet balance scan proof only supports V2 trees');
        }
        if (!Number.isSafeInteger(minimumBlockNumber) || minimumBlockNumber < 0) {
            throw new Error('Minimum scan block must be a non-negative safe integer');
        }
        if (walletIdFilter.length === 0) {
            throw new Error('Wallet balance scan proof requires at least one wallet');
        }
        let scannedThroughBlock;
        await this.scanUTXOHistory(txidVersion, chain, walletIdFilter, {
            minimumBlock: minimumBlockNumber,
            throwOnFailure: true,
            onValidatedScan: (blockNumber) => {
                scannedThroughBlock = blockNumber;
            },
        });
        if (!(0, is_defined_1.isDefined)(scannedThroughBlock) || scannedThroughBlock < minimumBlockNumber) {
            throw new Error('Wallet balance scan did not reach its minimum block');
        }
        return { scannedThroughBlock };
    }
    /**
     * Scan (via quick sync or slow sync) on-chain data for the UTXO merkletree.
     */
    async scanUTXOHistory(txidVersion, chain, walletIdFilter, options = {}) {
        if (this.skipMerkletreeScans) {
            if (options.throwOnFailure === true) {
                throw new Error('Cannot prove wallet balances: merkletree scans are disabled');
            }
            debugger_1.default.log(`Skipping merkletree scan: skipMerkletreeScans set on RAILGUN Engine.`);
            return;
        }
        if (!this.hasUTXOMerkletree(txidVersion, chain)) {
            if (options.throwOnFailure === true) {
                throw new Error('Cannot prove wallet balances: UTXO merkletree is not loaded');
            }
            debugger_1.default.log(`Cannot scan history. UTXO merkletree not yet loaded for ${txidVersion}, chain ${chain.type}:${chain.id}.`);
            return;
        }
        if (!(0, is_defined_1.isDefined)(contract_store_1.ContractStore.railgunSmartWalletContracts.get(null, chain))) {
            if (options.throwOnFailure === true) {
                throw new Error('Cannot prove wallet balances: Railgun contract is not loaded');
            }
            debugger_1.default.log(`Cannot scan history. Proxy contract not yet loaded for chain ${chain.type}:${chain.id}.`);
            return;
        }
        const utxoMerkletreeHistoryVersion = await this.getUTXOMerkletreeHistoryVersion(chain);
        if (!(0, is_defined_1.isDefined)(utxoMerkletreeHistoryVersion) ||
            utxoMerkletreeHistoryVersion < constants_1.CURRENT_UTXO_MERKLETREE_HISTORY_VERSION) {
            await this.clearUTXOMerkletreeAndLoadedWalletsAllTXIDVersions(chain);
            await this.setUTXOMerkletreeHistoryVersion(chain, constants_1.CURRENT_UTXO_MERKLETREE_HISTORY_VERSION);
        }
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        if (utxoMerkletree.isScanning) {
            // Do not allow multiple simultaneous scans.
            if (options.throwOnFailure === true) {
                throw new Error('Cannot prove wallet balances while another scan is running');
            }
            debugger_1.default.log('Already scanning. Stopping additional re-scan.');
            return;
        }
        utxoMerkletree.isScanning = true;
        try {
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, 0.03); // 3%
            const postQuickSyncProgress = 0.5;
            let durableStrictCursor;
            if (options.throwOnFailure === true) {
                if (!(0, is_defined_1.isDefined)(options.minimumBlock) ||
                    !Number.isSafeInteger(options.minimumBlock) ||
                    options.minimumBlock < 0) {
                    throw new Error('Strict wallet balance scan requires a valid minimum block');
                }
                durableStrictCursor = await this.getLastSyncedBlock(txidVersion, chain);
                if ((0, is_defined_1.isDefined)(durableStrictCursor) &&
                    (!Number.isSafeInteger(durableStrictCursor) || durableStrictCursor < 0)) {
                    throw new Error('Wallet balance scan has an invalid durable cursor');
                }
            }
            const strictHistoryAlreadyCovered = options.throwOnFailure === true &&
                (0, is_defined_1.isDefined)(options.minimumBlock) &&
                (0, is_defined_1.isDefined)(durableStrictCursor) &&
                durableStrictCursor >= options.minimumBlock;
            if (!strictHistoryAlreadyCovered) {
                await this.performQuickSync(txidVersion, chain, postQuickSyncProgress, 0, options.throwOnFailure);
            }
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, postQuickSyncProgress); // 50%
            const railgunSmartWalletContract = contract_store_1.ContractStore.railgunSmartWalletContracts.get(null, chain);
            if (!railgunSmartWalletContract?.contract.runner?.provider) {
                throw new Error('Requires RailgunSmartWalletContract with provider');
            }
            const providerLatestBlock = await railgunSmartWalletContract.contract.runner.provider.getBlockNumber();
            if ((0, is_defined_1.isDefined)(options.minimumBlock) && providerLatestBlock < options.minimumBlock) {
                throw new Error('Provider has not reached the minimum wallet scan block');
            }
            if (!strictHistoryAlreadyCovered) {
                let startScanningBlockSlowScan;
                if (options.throwOnFailure === true) {
                    // Strict scans resume from durable history, not a quick-sync commitment height.
                    const strictStartBlock = durableStrictCursor ?? this.deploymentBlocks.get(txidVersion, chain);
                    if (!(0, is_defined_1.isDefined)(strictStartBlock)) {
                        throw new Error('Cannot prove wallet balances without a scan start block');
                    }
                    startScanningBlockSlowScan = strictStartBlock;
                }
                else {
                    // Get updated start-scanning block from new valid utxoMerkletree.
                    startScanningBlockSlowScan = await this.getNextStartingBlockSlowScan(txidVersion, chain);
                }
                debugger_1.default.log(`[${txidVersion}] startScanningBlockSlowScan: ${startScanningBlockSlowScan}`);
                // Strict callers need finalized coverage only; do not make unfinalized tip part of proof.
                const scanEndBlock = options.minimumBlock ?? providerLatestBlock;
                switch (txidVersion) {
                    case poi_types_1.TXIDVersion.V2_PoseidonMerkle:
                        await this.slowSyncV2(chain, utxoMerkletree, startScanningBlockSlowScan, scanEndBlock, postQuickSyncProgress);
                        break;
                    case poi_types_1.TXIDVersion.V3_PoseidonMerkle:
                        await this.slowSyncV3(chain, utxoMerkletree, startScanningBlockSlowScan, scanEndBlock, postQuickSyncProgress);
                        break;
                }
            }
            const { tree: latestTree } = await utxoMerkletree.getLatestTreeAndIndex();
            // check roots for trees up to this tree on 'scan'
            for (let treeIndex = 0; treeIndex <= latestTree; treeIndex += 1) {
                const index = await utxoMerkletree.getLatestIndexForTree(treeIndex);
                const root = await utxoMerkletree.getRoot(treeIndex);
                const isValid = await RailgunEngine.validateMerkleroot(txidVersion, chain, treeIndex, index, root);
                debugger_1.default.log(`[${txidVersion}] MerkleRootValid (Tree ${treeIndex}): ${isValid}`);
                if (!isValid) {
                    throw new Error(`Invalid merkleroot: ${root}. Tree: ${treeIndex}. Index: ${index}.`);
                }
            }
            // Final balance decryption after all leaves added.
            const decryptStartingProgress = 0.7;
            await this.decryptBalancesAllWallets(txidVersion, chain, walletIdFilter, (progress) => {
                const overallProgress = progress * (0.97 - decryptStartingProgress) + decryptStartingProgress;
                this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, overallProgress); // 90-97%
            }, true);
            if (options.throwOnFailure === true) {
                if (!(0, is_defined_1.isDefined)(options.minimumBlock)) {
                    throw new Error('Strict wallet balance scan requires a minimum block');
                }
                await this.assertWalletBalancesDecrypted(txidVersion, chain, walletIdFilter ?? []);
                const validatedCursor = await this.getValidatedWalletScanCursor(txidVersion, chain, options.minimumBlock, providerLatestBlock);
                options.onValidatedScan?.(validatedCursor);
            }
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, 0.97); // 97%
            // The handler of EngineEvent.UTXOScanDecryptBalancesComplete will
            // call emitScanEventHistoryComplete when it is done processing balances since that can take some time.
            // This is better UX than calling MerkletreeScanStatus.Complete 5-10 sec before balances are actually passed to front end.
            const decryptBalancesCompleteEventData = {
                txidVersion,
                chain,
                walletIdFilter,
            };
            this.emit(event_types_1.EngineEvent.UTXOScanDecryptBalancesComplete, decryptBalancesCompleteEventData);
        }
        catch (err) {
            if (err instanceof Error) {
                debugger_1.default.log(`Scan incomplete for chain ${chain.type}:${chain.id}`);
                debugger_1.default.error(err);
            }
            await this.decryptBalancesAllWallets(txidVersion, chain, walletIdFilter, undefined, // progressCallback
            false);
            const scanIncompleteData = {
                scanStatus: event_types_1.MerkletreeScanStatus.Incomplete,
                txidVersion,
                chain,
            };
            this.emit(event_types_1.EngineEvent.UTXOMerkletreeHistoryScanUpdate, scanIncompleteData);
            if (options.throwOnFailure === true) {
                throw err;
            }
        }
        finally {
            utxoMerkletree.isScanning = false;
        }
    }
    emitScanEventHistoryComplete(txidVersion, chain) {
        this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, 1.0); // 100%
        const scanCompleteData = {
            scanStatus: event_types_1.MerkletreeScanStatus.Complete,
            txidVersion,
            chain,
        };
        this.emit(event_types_1.EngineEvent.UTXOMerkletreeHistoryScanUpdate, scanCompleteData);
    }
    async slowSyncV2(chain, utxoMerkletree, startScanningBlockSlowScan, latestBlock, postQuickSyncProgress) {
        const txidVersion = poi_types_1.TXIDVersion.V2_PoseidonMerkle;
        const railgunSmartWalletContract = contract_store_1.ContractStore.railgunSmartWalletContracts.get(null, chain);
        if (!(0, is_defined_1.isDefined)(railgunSmartWalletContract)) {
            throw new Error('Requires RailgunSmartWallet contract');
        }
        const totalBlocksToScan = latestBlock - startScanningBlockSlowScan;
        debugger_1.default.log(`[${txidVersion}] Total blocks to SlowScan: ${totalBlocksToScan}`);
        await railgunSmartWalletContract.getHistoricalEvents(startScanningBlockSlowScan, latestBlock, async () => startScanningBlockSlowScan, async (_txidVersion, commitmentEvents) => {
            await this.commitmentListener(txidVersion, chain, commitmentEvents, true, // shouldUpdateTrees
            false);
        }, async (_txidVersion, nullifiers) => {
            await this.nullifierListener(txidVersion, chain, nullifiers);
        }, async (_txidVersion, unshields) => {
            await this.unshieldListener(txidVersion, chain, unshields);
        }, async (syncedBlock) => {
            const scannedBlocks = syncedBlock - startScanningBlockSlowScan;
            const progress = postQuickSyncProgress +
                ((1 - postQuickSyncProgress - 0.3) * scannedBlocks) / totalBlocksToScan;
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, progress);
            if (utxoMerkletree.getFirstInvalidMerklerootTree() != null) {
                // Do not save lastSyncedBlock in case of merkleroot error.
                // This will force a scan from the last valid commitment on next run.
                return;
            }
            await this.setLastSyncedBlock(txidVersion, chain, syncedBlock);
        });
    }
    async slowSyncV3(chain, utxoMerkletree, startScanningBlockSlowScan, latestBlock, postQuickSyncProgress) {
        const txidVersion = poi_types_1.TXIDVersion.V3_PoseidonMerkle;
        const poseidonMerkleAccumulatorV3Contract = contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.get(null, chain);
        if (!(0, is_defined_1.isDefined)(poseidonMerkleAccumulatorV3Contract)) {
            throw new Error('Requires V3PoseidonMerkleAccumulator contract');
        }
        const totalBlocksToScan = latestBlock - startScanningBlockSlowScan;
        debugger_1.default.log(`[${txidVersion}] Total blocks to SlowScan: ${totalBlocksToScan}`);
        await poseidonMerkleAccumulatorV3Contract.getHistoricalEvents(startScanningBlockSlowScan, latestBlock, () => this.getNextStartingBlockSlowScan(txidVersion, chain), async (_txidVersion, commitmentEvents) => {
            await this.commitmentListener(txidVersion, chain, commitmentEvents, true, // shouldUpdateTrees
            false);
        }, async (_txidVersion, nullifiers) => {
            await this.nullifierListener(txidVersion, chain, nullifiers);
        }, async (_txidVersion, unshields) => {
            await this.unshieldListener(txidVersion, chain, unshields);
        }, async (_txidVersion, railgunTransactions) => {
            await this.railgunTransactionsV3Listener(txidVersion, chain, railgunTransactions);
        }, async (syncedBlock) => {
            const scannedBlocks = syncedBlock - startScanningBlockSlowScan;
            const progress = postQuickSyncProgress +
                ((1 - postQuickSyncProgress - 0.3) * scannedBlocks) / totalBlocksToScan;
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, progress);
            if (utxoMerkletree.getFirstInvalidMerklerootTree() != null) {
                // Do not save lastSyncedBlock in case of merkleroot error.
                // This will force a scan from the last valid commitment on next run.
                return;
            }
            await this.setLastSyncedBlock(txidVersion, chain, syncedBlock);
        });
    }
    /**
     * Scan subgraph data for railgun transactions to build the TXID merkletree.
     */
    async scanTXIDHistoryV2(chain) {
        const txidVersion = poi_types_1.TXIDVersion.V2_PoseidonMerkle;
        if (!this.hasTXIDMerkletree(txidVersion, chain)) {
            debugger_1.default.log(`Cannot sync txids. Txid merkletree not yet loaded for chain ${chain.type}:${chain.id}.`);
            return;
        }
        this.hasSyncedRailgunTransactionsV2.set(null, chain, true);
        await this.syncRailgunTransactionsV2(chain, 'poller');
    }
    /**
     * Sync Railgun txid merkletree.
     * @param chain - chain type/id to scan
     */
    async syncRailgunTransactionsV2(chain, trigger) {
        const txidVersion = poi_types_1.TXIDVersion.V2_PoseidonMerkle;
        if (!this.hasTXIDMerkletree(txidVersion, chain)) {
            debugger_1.default.log(`Cannot sync txids. Txid merkletree not yet loaded for chain ${chain.type}:${chain.id}.`);
            return;
        }
        const txidV2MerkletreeHistoryVersion = await this.getTxidV2MerkletreeHistoryVersion(chain);
        if (!(0, is_defined_1.isDefined)(txidV2MerkletreeHistoryVersion) ||
            txidV2MerkletreeHistoryVersion < constants_1.CURRENT_TXID_V2_MERKLETREE_HISTORY_VERSION) {
            await this.clearTXIDMerkletree(txidVersion, chain);
            await this.setTxidV2MerkletreeHistoryVersion(chain, constants_1.CURRENT_TXID_V2_MERKLETREE_HISTORY_VERSION);
        }
        const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
        if (txidMerkletree.isScanning) {
            // Do not allow multiple simultaneous scans.
            debugger_1.default.log('[Txid] Already syncing. Stopping additional re-sync.');
            return;
        }
        txidMerkletree.isScanning = true;
        await this.performSyncRailgunTransactionsV2(chain, trigger);
        txidMerkletree.isScanning = false;
    }
    async shouldAddNewRailgunTransactions(txidVersion, chain, latestValidatedTxidIndex) {
        if (!(0, is_defined_1.isDefined)(latestValidatedTxidIndex)) {
            return true;
        }
        const { txidIndex: latestTxidIndex } = await this.getLatestRailgunTxidData(txidVersion, chain);
        const isAheadOfValidatedTxids = !(0, is_defined_1.isDefined)(latestValidatedTxidIndex) || latestTxidIndex >= latestValidatedTxidIndex;
        return !isAheadOfValidatedTxids;
    }
    async getLatestValidatedTxidIndex(txidVersion, chain) {
        // TODO: Optimization - use this merkleroot from validated railgun txid to auto-validate merkletree.
        const { txidIndex: latestValidatedTxidIndex /* merkleroot */ } = await this.getLatestValidatedRailgunTxid(txidVersion, chain);
        return latestValidatedTxidIndex;
    }
    async performSyncRailgunTransactionsV2(chain, trigger) {
        const txidVersion = poi_types_1.TXIDVersion.V2_PoseidonMerkle;
        try {
            debugger_1.default.log(`sync railgun txids: chain ${chain.type}:${chain.id}: triggered by ${trigger}`);
            this.emitTXIDMerkletreeScanUpdateEvent(txidVersion, chain, 0.03); // 3%
            this.emitTXIDMerkletreeScanUpdateEvent(txidVersion, chain, 0.15); // 15%
            const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
            // while loop to handle multiple queries
            let isLooping = true;
            const txidMerkletreeHistoryStartScanPercentage = 0.4; // 40%
            const txidMerkletreeEndScanPercentage = 0.99; // 99%
            const railgunTransactions = [];
            const latestRailgunTransaction = await txidMerkletree.getLatestRailgunTransaction();
            if (latestRailgunTransaction &&
                latestRailgunTransaction.version !== formatted_types_1.RailgunTransactionVersion.V2) {
                // Should never happen
                return;
            }
            let latestTranasction = latestRailgunTransaction;
            let txidMerkletreeStartScanPercentage = 0.2; // 20%
            while (isLooping) {
                const railgunTransactionsRAW = await this.quickSyncRailgunTransactionsV2(chain, latestTranasction?.graphID);
                railgunTransactions.push(...railgunTransactionsRAW);
                latestTranasction = railgunTransactionsRAW[railgunTransactionsRAW.length - 1];
                this.emitTXIDMerkletreeScanUpdateEvent(txidVersion, chain, txidMerkletreeStartScanPercentage);
                txidMerkletreeStartScanPercentage += 0.005;
                if (txidMerkletreeStartScanPercentage > 1) {
                    txidMerkletreeStartScanPercentage = 0.95;
                }
                isLooping = railgunTransactionsRAW.length === 10000;
            }
            await this.handleNewRailgunTransactionsV2(txidVersion, chain, railgunTransactions, latestRailgunTransaction?.verificationHash, txidMerkletreeHistoryStartScanPercentage, txidMerkletreeEndScanPercentage);
            const scanCompleteData = {
                scanStatus: event_types_1.MerkletreeScanStatus.Complete,
                txidVersion,
                chain,
            };
            if (railgunTransactions.length) {
                // Only scan wallets if utxoMerkletree is not currently scanning
                const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
                if (!utxoMerkletree.isScanning) {
                    // Decrypt balances for all wallets.
                    await this.decryptBalancesAllWallets(txidVersion, chain, undefined, // walletIdFilter
                    undefined, // progressCallback
                    false);
                }
            }
            // Finish
            this.emit(event_types_1.EngineEvent.TXIDMerkletreeHistoryScanUpdate, scanCompleteData);
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw cause;
            }
            debugger_1.default.error(new Error('Failed to sync Railgun transactions V2', { cause }));
            const scanIncompleteData = {
                scanStatus: event_types_1.MerkletreeScanStatus.Incomplete,
                txidVersion,
                chain,
            };
            this.emit(event_types_1.EngineEvent.TXIDMerkletreeHistoryScanUpdate, scanIncompleteData);
        }
    }
    async handleNewRailgunTransactionsV2(txidVersion, chain, railgunTransactions, latestVerificationHash, startScanPercentage, endScanPercentage) {
        const latestValidatedTxidIndex = await this.getLatestValidatedTxidIndex(txidVersion, chain);
        debugger_1.default.log(`syncing railgun transactions to validated index (Chain: ${chain.id}. txidVersion: ${txidVersion}): ${latestValidatedTxidIndex ?? 'NOT FOUND'}`);
        const shouldAddNewRailgunTransactions = await this.shouldAddNewRailgunTransactions(txidVersion, chain, latestValidatedTxidIndex);
        if (!shouldAddNewRailgunTransactions) {
            debugger_1.default.log(`Skipping queue of Railgun TXIDs - already synced to validated index: ${latestValidatedTxidIndex ?? 0}`);
            this.emitTXIDMerkletreeScanUpdateEvent(txidVersion, chain, 1);
            return;
        }
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
        const v2BlockNumber = railgun_smart_wallet_1.RailgunSmartWalletContract.getEngineV2StartBlockNumber(chain);
        const toQueue = [];
        let previousVerificationHash = latestVerificationHash;
        const emitNewRailgunTransactionsProgress = (progress) => {
            const overallProgress = progress * (endScanPercentage - startScanPercentage) + startScanPercentage;
            this.emitTXIDMerkletreeScanUpdateEvent(txidVersion, chain, overallProgress);
        };
        const railgunTransactionsLength = railgunTransactions.length;
        for (const [index, railgunTransaction] of railgunTransactions.entries()) {
            const railgunTransactionWithTxid = (0, railgun_txid_1.createRailgunTransactionWithHash)(railgunTransaction);
            if (railgunTransactionWithTxid.version !== formatted_types_1.RailgunTransactionVersion.V2) {
                continue;
            }
            const { commitments, nullifiers, txid, unshield, railgunTxid, utxoTreeOut: tree, utxoBatchStartPositionOut, blockNumber, timestamp, verificationHash, } = railgunTransactionWithTxid;
            // Update existing commitments/unshield events.
            // If any commitments are missing, wait for UTXO tree to sync first.
            const unshieldCommitment = unshield
                ? commitments[commitments.length - 1]
                : undefined;
            const standardCommitments = unshield ? commitments.slice(0, -1) : commitments;
            let missingAnyCommitments = false;
            // No Unshield events exist pre-V2.
            const isPreV2 = blockNumber < v2BlockNumber;
            if ((0, is_defined_1.isDefined)(unshieldCommitment) && unshield) {
                const unshieldTokenHash = (0, note_util_1.getTokenDataHash)(unshield.tokenData);
                if (isPreV2) {
                    // V2 does not have unshield events. Add a new stored Unshield event.
                    // Pre-V2 always had a 25n basis points fee for unshields.
                    const preV2FeeBasisPoints = 25n;
                    const { fee, amount } = note_1.UnshieldNote.getAmountFeeFromValue(bytes_1.ByteUtils.hexToBigInt(unshield.value), preV2FeeBasisPoints);
                    const unshieldEvent = {
                        txid,
                        tokenAddress: unshield.tokenData.tokenAddress,
                        tokenType: unshield.tokenData.tokenType,
                        tokenSubID: unshield.tokenData.tokenSubID,
                        toAddress: unshield.toAddress,
                        amount: amount.toString(),
                        fee: fee.toString(),
                        blockNumber,
                        railgunTxid,
                        timestamp,
                        eventLogIndex: undefined, // Does not exist for txid subgraph, which is generated through calldata
                    };
                    // eslint-disable-next-line no-await-in-loop
                    await utxoMerkletree.addUnshieldEvents([unshieldEvent]);
                    this.invalidateTXOsCacheAllWallets(chain);
                }
                else {
                    // V2 has unshield events. Map to existing event.
                    // eslint-disable-next-line no-await-in-loop
                    const unshieldEventsForTxid = await utxoMerkletree.getAllUnshieldEventsForTxid(txid);
                    const matchingUnshieldEvent = unshieldEventsForTxid.find((unshieldEvent) => {
                        // Check if tokenHash matches, if toAddress matches, and if amount matches
                        const tokenHash = (0, note_util_1.getUnshieldTokenHash)(unshieldEvent);
                        const tokenHasMatch = tokenHash === unshieldTokenHash;
                        const toAddressHasMatch = unshieldEvent.toAddress.toLowerCase() === unshield.toAddress.toLowerCase();
                        const amountHasMatch = ((0, bigint_1.stringToBigInt)(unshieldEvent.amount) + (0, bigint_1.stringToBigInt)(unshieldEvent.fee)).toString() === unshield.value;
                        return tokenHasMatch && toAddressHasMatch && amountHasMatch;
                    });
                    if (matchingUnshieldEvent) {
                        if (matchingUnshieldEvent.railgunTxid !== railgunTxid) {
                            matchingUnshieldEvent.railgunTxid = railgunTxid;
                            // eslint-disable-next-line no-await-in-loop
                            await utxoMerkletree.updateUnshieldEvent(matchingUnshieldEvent);
                            this.invalidateTXOsCacheAllWallets(chain);
                        }
                    }
                    else {
                        debugger_1.default.log(`Missing unshield from TXID scan: txid ${txid}, token ${unshieldTokenHash ?? 'UNKNOWN'}`);
                        missingAnyCommitments = true;
                    }
                }
            }
            for (let i = 0; i < standardCommitments.length; i += 1) {
                const position = utxoBatchStartPositionOut + i;
                // eslint-disable-next-line no-await-in-loop
                const commitment = await utxoMerkletree.getCommitmentSafe(tree, position);
                if ((0, is_defined_1.isDefined)(commitment)) {
                    if ((0, commitment_1.isTransactCommitment)(commitment) && commitment.railgunTxid !== railgunTxid) {
                        commitment.railgunTxid = railgunTxid;
                        // eslint-disable-next-line no-await-in-loop
                        await utxoMerkletree.updateData(tree, position, commitment);
                    }
                }
                else {
                    missingAnyCommitments = true;
                    debugger_1.default.log(`Missing commitment from TXID scan: UTXO ${tree}:${position}.`);
                    break;
                }
            }
            if (missingAnyCommitments) {
                debugger_1.default.error(new Error(`Stopping queue of Railgun TXIDs - missing a commitment or unshield. This will occur whenever the TXIDs are further than the UTXOs data source.`));
                break;
            }
            const expectedVerificationHash = (0, railgun_txid_1.calculateRailgunTransactionVerificationHash)(previousVerificationHash, nullifiers[0]);
            if (expectedVerificationHash !== verificationHash) {
                debugger_1.default.error(new Error(`Stopping queue of Railgun TXIDs - Invalid verification hash. This occurs very rarely during a chain re-org and will resolve itself in minutes.`));
                // Clear 10 leaves to allow for re-org to resolve.
                const numLeavesToClear = 10;
                // eslint-disable-next-line no-await-in-loop
                await txidMerkletree.clearLeavesForInvalidVerificationHash(numLeavesToClear);
                break;
            }
            previousVerificationHash = expectedVerificationHash;
            toQueue.push(railgunTransactionWithTxid);
            // Only emit progress every 100 TXIDs.
            if (index % 100 === 0) {
                const progress = index / railgunTransactionsLength;
                emitNewRailgunTransactionsProgress(progress);
            }
        }
        await txidMerkletree.queueRailgunTransactions(toQueue, latestValidatedTxidIndex);
        await txidMerkletree.updateTreesFromWriteQueue();
    }
    async handleNewRailgunTransactionsV3(txidVersion, chain, railgunTransactions) {
        const latestValidatedTxidIndex = await this.getLatestValidatedTxidIndex(txidVersion, chain);
        debugger_1.default.log(`syncing railgun transactions to validated index: ${latestValidatedTxidIndex ?? 'NOT FOUND'}`);
        const shouldAddNewRailgunTransactions = await this.shouldAddNewRailgunTransactions(txidVersion, chain, latestValidatedTxidIndex);
        if (!shouldAddNewRailgunTransactions) {
            debugger_1.default.log(`Skipping queue of Railgun TXIDs - already synced to validated index: ${latestValidatedTxidIndex ?? 0}`);
            const scanCompleteData = {
                scanStatus: event_types_1.MerkletreeScanStatus.Complete,
                progress: 1,
                txidVersion,
                chain,
            };
            this.emit(event_types_1.EngineEvent.TXIDMerkletreeHistoryScanUpdate, scanCompleteData);
            return;
        }
        const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
        const toQueue = [];
        for (const railgunTransaction of railgunTransactions) {
            const railgunTransactionWithTxid = (0, railgun_txid_1.createRailgunTransactionWithHash)(railgunTransaction);
            // TODO-V3: Calculate and verify verificationHash on RailgunTransactionV3.
            toQueue.push(railgunTransactionWithTxid);
        }
        await txidMerkletree.queueRailgunTransactions(toQueue, latestValidatedTxidIndex);
        await txidMerkletree.updateTreesFromWriteQueue();
    }
    async getLatestRailgunTxidData(txidVersion, chain) {
        const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
        const { tree, index } = await txidMerkletree.getLatestTreeAndIndex();
        const merkleroot = await txidMerkletree.getRoot(tree);
        const txidIndex = txid_merkletree_1.TXIDMerkletree.getGlobalPosition(tree, index);
        return { txidIndex, merkleroot };
    }
    /**
     * Clears all merkletree leaves stored in database.
     * @param chain - chain type/id to clear
     */
    async clearSyncedUTXOMerkletreeLeavesAllTXIDVersions(chain) {
        for (const txidVersion of Object.values(poi_types_1.TXIDVersion)) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            // eslint-disable-next-line no-await-in-loop
            await utxoMerkletree.clearDataForMerkletree();
            // eslint-disable-next-line no-await-in-loop
            await this.db.clearNamespace(RailgunEngine.getLastSyncedBlockDBPrefix(txidVersion, chain));
        }
    }
    async clearUTXOMerkletreeAndLoadedWalletsAllTXIDVersions(chain) {
        await this.clearSyncedUTXOMerkletreeLeavesAllTXIDVersions(chain);
        await Promise.all(this.allWallets().map((wallet) => wallet.clearDecryptedBalancesAllTXIDVersions(chain)));
    }
    async clearSyncedUnshieldEvents(txidVersion, chain) {
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        await this.db.clearNamespace(
        // All Unshields
        utxoMerkletree.getUnshieldEventsDBPath(undefined, undefined, undefined));
    }
    async clearTXIDMerkletree(txidVersion, chain) {
        const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
        await txidMerkletree.clearDataForMerkletree();
    }
    /**
     * Clears stored merkletree leaves and wallet balances, and re-scans fully.
     * @param chain - chain type/id to rescan
     * @param forceRescanDevOnly - can corrupt an existing scan, so only recommended in extreme cases (DEV only)
     */
    async fullRescanUTXOMerkletreesAndWallets(chain, walletIdFilter, forceRescanDevOnly = false) {
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            if (!this.hasUTXOMerkletree(txidVersion, chain)) {
                const err = new Error(`Cannot re-scan history. Merkletree not yet loaded for ${txidVersion}, chain ${chain.type}:${chain.id}.`);
                debugger_1.default.error(err);
                throw err;
            }
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            if (utxoMerkletree.isScanning && !forceRescanDevOnly) {
                const err = new Error(`Full rescan already in progress.`);
                debugger_1.default.error(err);
                throw err;
            }
        }
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            this.emitUTXOMerkletreeScanUpdateEvent(txidVersion, chain, 0.01); // 1%
            utxoMerkletree.isScanning = true; // Don't allow scans while removing leaves.
            // eslint-disable-next-line no-await-in-loop
            await this.clearUTXOMerkletreeAndLoadedWalletsAllTXIDVersions(chain);
            // eslint-disable-next-line no-await-in-loop
            await this.clearSyncedUnshieldEvents(txidVersion, chain);
            utxoMerkletree.isScanning = false; // Clear before calling scanHistory.
            if (txidVersion !== poi_types_1.TXIDVersion.V2_PoseidonMerkle) {
                // Clear TXID data before syncing fresh from Event History (V3).
                // eslint-disable-next-line no-await-in-loop
                await this.clearTXIDMerkletreeData(txidVersion, chain);
            }
            // eslint-disable-next-line no-await-in-loop
            await this.scanUTXOHistory(txidVersion, chain, walletIdFilter);
            if (txidVersion === poi_types_1.TXIDVersion.V2_PoseidonMerkle) {
                // Must reset txid merkletree which is mapped to UTXO commitments in V2.
                // eslint-disable-next-line no-await-in-loop
                await this.fullResetTXIDMerkletreesV2(chain);
            }
        }
    }
    async fullResetTXIDMerkletreesV2(chain) {
        const txidVersion = poi_types_1.TXIDVersion.V2_PoseidonMerkle;
        if (!this.hasTXIDMerkletree(txidVersion, chain)) {
            return;
        }
        if (this.hasSyncedRailgunTransactionsV2.get(null, chain) !== true) {
            const err = new Error(`Cannot re-scan railgun txids. Must get UTXO history first. Please wait and try again.`);
            debugger_1.default.error(err);
            throw err;
        }
        await this.clearTXIDMerkletreeData(txidVersion, chain);
        await this.syncRailgunTransactionsV2(chain, 'full txid reset');
    }
    async clearTXIDMerkletreeData(txidVersion, chain) {
        if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
            return;
        }
        const hasMerkletree = this.hasTXIDMerkletree(txidVersion, chain);
        if (!hasMerkletree) {
            const err = new Error(`Cannot re-scan railgun txids. Merkletree not yet loaded for chain ${chain.type}:${chain.id}.`);
            debugger_1.default.error(err);
            throw err;
        }
        const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
        if (txidMerkletree.isScanning) {
            const err = new Error(`Full reset of txids already in progress.`);
            debugger_1.default.error(err);
            throw err;
        }
        txidMerkletree.isScanning = true; // Don't allow scans while removing leaves.
        // eslint-disable-next-line no-await-in-loop
        await txidMerkletree.clearDataForMerkletree();
        txidMerkletree.isScanning = false; // Clear before calling syncRailgunTransactions.
        // eslint-disable-next-line no-await-in-loop
        if (txidVersion !== poi_types_1.TXIDVersion.V2_PoseidonMerkle) {
            // For V3, clear the last-synced block to force a full quicksync scan.
            await this.db.clearNamespace(RailgunEngine.getLastSyncedBlockDBPrefix(txidVersion, chain));
        }
    }
    async resetRailgunTxidsAfterTxidIndex(txidVersion, chain, txidIndex) {
        const txidMerkletree = this.getTXIDMerkletree(txidVersion, chain);
        txidMerkletree.isScanning = true; // Don't allow scans while removing leaves.
        await txidMerkletree.clearLeavesAfterTxidIndex(txidIndex);
        txidMerkletree.isScanning = false; // Clear before calling syncRailgunTransactions.
        await this.syncRailgunTransactionsV2(chain, 'reset after txid index');
    }
    static async validateMerkleroot(txidVersion, chain, tree, _index, merkleroot) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle:
                return contract_store_1.ContractStore.railgunSmartWalletContracts
                    .getOrThrow(null, chain)
                    .validateMerkleroot(tree, merkleroot);
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle:
                return contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts
                    .getOrThrow(null, chain)
                    .validateMerkleroot(tree, merkleroot);
        }
        return false;
    }
    /**
     * Load network
     * @param railgunSmartWalletContractAddress - address of railgun instance (proxy contract)
     * @param relayAdaptV2ContractAddress - optional relay adapt contract address
     * @param provider - ethers provider for network
     * @param deploymentBlock - block number to start scanning from
     */
    async loadNetwork(chain, railgunSmartWalletContractAddress, relayAdaptV2ContractAddress, poseidonMerkleAccumulatorV3Address, poseidonMerkleVerifierV3Address, tokenVaultV3Address, defaultProvider, pollingProvider, deploymentBlocks, supportsV3) {
        debugger_1.default.log(`loadNetwork: ${chain.type}:${chain.id}`);
        try {
            await (0, promises_1.promiseTimeout)(defaultProvider.getBlockNumber(), 60_000, 'Timed out waiting for default RPC provider to connect.');
        }
        catch (cause) {
            const err = new Error('Failed to get block number from default provider when loading network', { cause });
            debugger_1.default.error(err);
            throw err;
        }
        (0, polling_util_1.assertIsPollingProvider)(pollingProvider);
        try {
            await (0, promises_1.promiseTimeout)(pollingProvider.getBlockNumber(), 60_000, 'Timed out waiting for polling RPC provider to connect.');
        }
        catch (cause) {
            const err = new Error('Failed to get block number from polling provider when loading network', {
                cause,
            });
            debugger_1.default.error(cause);
            throw err;
        }
        if (supportsV3) {
            (0, chain_1.addChainSupportsV3)(chain);
        }
        const hasAnyMerkletree = poi_types_1.ACTIVE_TXID_VERSIONS.every((txidVersion) => !this.hasUTXOMerkletree(txidVersion, chain) && !this.hasTXIDMerkletree(txidVersion, chain));
        const hasSmartWalletContract = contract_store_1.ContractStore.railgunSmartWalletContracts.has(null, chain);
        const hasRelayAdaptV2Contract = contract_store_1.ContractStore.relayAdaptV2Contracts.has(null, chain);
        const hasPoseidonMerkleAccumulatorV3Contract = contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.has(null, chain);
        const hasPoseidonMerkleVerifierV3Contract = contract_store_1.ContractStore.poseidonMerkleVerifierV3Contracts.has(null, chain);
        const hasTokenVaultV3Contract = contract_store_1.ContractStore.tokenVaultV3Contracts.has(null, chain);
        if (hasAnyMerkletree ||
            hasSmartWalletContract ||
            hasRelayAdaptV2Contract ||
            hasPoseidonMerkleAccumulatorV3Contract ||
            hasPoseidonMerkleVerifierV3Contract ||
            hasTokenVaultV3Contract) {
            // If a network with this chainID exists, unload it and load the provider as a new network
            await this.unloadNetwork(chain);
        }
        // Create contract instances
        contract_store_1.ContractStore.railgunSmartWalletContracts.set(null, chain, new railgun_smart_wallet_1.RailgunSmartWalletContract(railgunSmartWalletContractAddress, defaultProvider, pollingProvider, chain));
        if (relayAdaptV2ContractAddress) {
            contract_store_1.ContractStore.relayAdaptV2Contracts.set(null, chain, new relay_adapt_v2_1.RelayAdaptV2Contract(relayAdaptV2ContractAddress, defaultProvider));
        }
        if (supportsV3) {
            contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.set(null, chain, new poseidon_merkle_accumulator_1.PoseidonMerkleAccumulatorContract(poseidonMerkleAccumulatorV3Address, defaultProvider, pollingProvider, chain));
            contract_store_1.ContractStore.poseidonMerkleVerifierV3Contracts.set(null, chain, new poseidon_merkle_verifier_1.PoseidonMerkleVerifierContract(poseidonMerkleVerifierV3Address, defaultProvider));
            contract_store_1.ContractStore.tokenVaultV3Contracts.set(null, chain, new token_vault_contract_1.TokenVaultContract(tokenVaultV3Address, defaultProvider));
        }
        for (const txidVersion of poi_types_1.ACTIVE_UTXO_MERKLETREE_TXID_VERSIONS) {
            // eslint-disable-next-line no-await-in-loop
            const utxoMerkletree = await utxo_merkletree_1.UTXOMerkletree.create(this.db, chain, txidVersion, 
            // eslint-disable-next-line @typescript-eslint/no-shadow
            (txidVersion, chain, tree, index, merkleroot) => RailgunEngine.validateMerkleroot(txidVersion, chain, tree, index, merkleroot));
            this.utxoMerkletrees.set(txidVersion, chain, utxoMerkletree);
            // Load utxo merkletree to all wallets
            // eslint-disable-next-line no-await-in-loop
            await Promise.all(Object.values(this.wallets).map(async (wallet) => {
                await wallet.loadUTXOMerkletree(txidVersion, utxoMerkletree);
            }));
            const autoValidate = async () => true;
            // eslint-disable-next-line no-await-in-loop
            const txidMerkletree = await txid_merkletree_1.TXIDMerkletree.createForWallet(this.db, chain, txidVersion, 
            // For V3, we receive events in realtime, and validation is done via on-chain verificationHash field.
            supportsV3 ? autoValidate : this.validateRailgunTxidMerkleroot);
            this.txidMerkletrees.set(txidVersion, chain, txidMerkletree);
            // Load txid merkletree to all wallets
            for (const wallet of Object.values(this.wallets)) {
                wallet.loadRailgunTXIDMerkletree(txidVersion, txidMerkletree);
            }
            this.deploymentBlocks.set(txidVersion, chain, deploymentBlocks[txidVersion]);
        }
        if (this.skipMerkletreeScans) {
            return;
        }
        // Set up listeners
        const commitmentListener = async (txidVersion, commitmentEvents) => {
            // Only start wallet balance decryption if utxoMerkletree is not already scanning
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            if (!utxoMerkletree.isScanning) {
                await this.commitmentListener(txidVersion, chain, commitmentEvents, true, // shouldUpdateTrees
                txidVersion === poi_types_1.TXIDVersion.V2_PoseidonMerkle);
                await this.decryptBalancesAllWallets(txidVersion, chain, undefined, // walletIdFilter
                undefined, // progressCallback
                false);
            }
        };
        const nullifierListener = async (txidVersion, nullifiers) => {
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            if (!utxoMerkletree.isScanning) {
                await this.nullifierListener(txidVersion, chain, nullifiers);
                // Only start wallet balance decryption if utxoMerkletree is not already scanning
                await this.decryptBalancesAllWallets(txidVersion, chain, undefined, // walletIdFilter
                undefined, // progressCallback
                false);
            }
        };
        const unshieldListener = async (txidVersion, unshields) => {
            const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
            if (!utxoMerkletree.isScanning) {
                await this.unshieldListener(txidVersion, chain, unshields);
            }
        };
        await contract_store_1.ContractStore.railgunSmartWalletContracts
            .get(null, chain)
            ?.setTreeUpdateListeners(commitmentListener, nullifierListener, unshieldListener);
        if (supportsV3) {
            const railgunTransactionsV3Listener = async (txidVersion, railgunTransactions) => {
                await this.railgunTransactionsV3Listener(txidVersion, chain, railgunTransactions);
            };
            const commitmentListenerV3 = async (txidVersion, commitmentEvents) => {
                await this.commitmentListener(txidVersion, chain, commitmentEvents, true, // shouldUpdateTrees
                txidVersion === poi_types_1.TXIDVersion.V2_PoseidonMerkle);
            };
            const nullifierListenerV3 = async (txidVersion, nullifiers) => {
                await this.nullifierListener(txidVersion, chain, nullifiers);
            };
            const triggerWalletBalanceDecryptions = async (txidVersion) => {
                const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
                if (!utxoMerkletree.isScanning) {
                    await this.decryptBalancesAllWallets(txidVersion, chain, undefined, // walletIdFilter
                    undefined, // progressCallback
                    false);
                }
            };
            await contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts
                .get(null, chain)
                ?.setTreeUpdateListeners(commitmentListenerV3, // No wallet scans
            nullifierListenerV3, // No wallet scans
            unshieldListener, railgunTransactionsV3Listener, triggerWalletBalanceDecryptions);
        }
    }
    /**
     * Unload network
     * @param chain - chainID of network to unload
     */
    async unloadNetwork(chain) {
        // Unload merkletrees from wallets
        for (const wallet of Object.values(this.wallets)) {
            for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
                if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                    continue;
                }
                wallet.unloadUTXOMerkletree(txidVersion, chain);
                wallet.unloadRailgunTXIDMerkletree(txidVersion, chain);
            }
        }
        // Unload listeners
        await contract_store_1.ContractStore.railgunSmartWalletContracts.get(null, chain)?.unload();
        await contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.get(null, chain)?.unload();
        // Delete contracts
        contract_store_1.ContractStore.railgunSmartWalletContracts.del(null, chain);
        contract_store_1.ContractStore.relayAdaptV2Contracts.del(null, chain);
        contract_store_1.ContractStore.poseidonMerkleAccumulatorV3Contracts.del(null, chain);
        contract_store_1.ContractStore.poseidonMerkleVerifierV3Contracts.del(null, chain);
        contract_store_1.ContractStore.tokenVaultV3Contracts.del(null, chain);
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            if (!(0, chain_1.getChainSupportsV3)(chain) && txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
                continue;
            }
            this.utxoMerkletrees.del(txidVersion, chain);
            this.txidMerkletrees.del(txidVersion, chain);
        }
    }
    static getLastSyncedBlockDBPrefix(txidVersion, chain) {
        const path = [
            database_1.DatabaseNamespace.ChainSyncInfo,
            'last_synced_block',
            txidVersion,
            (0, chain_1.getChainFullNetworkID)(chain),
        ];
        return path;
    }
    /**
     * Sets last synced block to resume syncing on next load.
     * @param chain - chain type/id to store value for
     * @param lastSyncedBlock - last synced block
     */
    setLastSyncedBlock(txidVersion, chain, lastSyncedBlock) {
        return this.db.put(RailgunEngine.getLastSyncedBlockDBPrefix(txidVersion, chain), lastSyncedBlock, 'utf8');
    }
    /**
     * Gets last synced block to resume syncing from.
     * @param chain - chain type/id to get value for
     * @returns lastSyncedBlock - last synced block
     */
    getLastSyncedBlock(txidVersion, chain) {
        return this.db
            .get(RailgunEngine.getLastSyncedBlockDBPrefix(txidVersion, chain), 'utf8')
            .then((val) => parseInt(val, 10))
            .catch(() => Promise.resolve(undefined));
    }
    /** Confirms the durable slow-scan cursor covers the requested block and current provider view. */
    async getValidatedWalletScanCursor(txidVersion, chain, minimumBlock, providerBlock) {
        const cursor = await this.getLastSyncedBlock(txidVersion, chain);
        if (!(0, is_defined_1.isDefined)(cursor) || !Number.isSafeInteger(cursor)) {
            throw new Error('Wallet balance scan has no valid durable cursor');
        }
        if (cursor < minimumBlock) {
            throw new Error('Wallet balance scan cursor is below the minimum block');
        }
        if (cursor > providerBlock) {
            throw new Error('Wallet balance scan cursor is ahead of the provider');
        }
        return cursor;
    }
    static getUTXOMerkletreeHistoryVersionDBPrefix(chain) {
        const path = [database_1.DatabaseNamespace.ChainSyncInfo, 'merkleetree_history_version'];
        if (chain != null) {
            path.push((0, chain_1.getChainFullNetworkID)(chain));
        }
        return path;
    }
    static getTxidV2MerkletreeHistoryVersionDBPrefix(chain) {
        const path = [database_1.DatabaseNamespace.ChainSyncInfo, 'txid_merkletree_history_version'];
        if (chain != null) {
            path.push((0, chain_1.getChainFullNetworkID)(chain));
        }
        return path;
    }
    setUTXOMerkletreeHistoryVersion(chain, merkletreeHistoryVersion) {
        return this.db.put(RailgunEngine.getUTXOMerkletreeHistoryVersionDBPrefix(chain), merkletreeHistoryVersion, 'utf8');
    }
    getUTXOMerkletreeHistoryVersion(chain) {
        return this.db
            .get(RailgunEngine.getUTXOMerkletreeHistoryVersionDBPrefix(chain), 'utf8')
            .then((val) => parseInt(val, 10))
            .catch(() => Promise.resolve(undefined));
    }
    setTxidV2MerkletreeHistoryVersion(chain, merkletreeHistoryVersion) {
        return this.db.put(RailgunEngine.getTxidV2MerkletreeHistoryVersionDBPrefix(chain), merkletreeHistoryVersion, 'utf8');
    }
    getTxidV2MerkletreeHistoryVersion(chain) {
        return this.db
            .get(RailgunEngine.getTxidV2MerkletreeHistoryVersionDBPrefix(chain), 'utf8')
            .then((val) => parseInt(val, 10))
            .catch(() => Promise.resolve(undefined));
    }
    getUTXOMerkletree(txidVersion, chain) {
        if (txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
            (0, chain_1.assertChainSupportsV3)(chain);
        }
        const merkletree = this.utxoMerkletrees.get(txidVersion, chain);
        if (!(0, is_defined_1.isDefined)(merkletree)) {
            throw new Error(`No utxo merkletree for txidVersion ${txidVersion}, chain ${chain.type}:${chain.id}`);
        }
        return merkletree;
    }
    hasUTXOMerkletree(txidVersion, chain) {
        try {
            this.getUTXOMerkletree(txidVersion, chain);
            return true;
        }
        catch {
            return false;
        }
    }
    getTXIDMerkletree(txidVersion, chain) {
        if (txidVersion === poi_types_1.TXIDVersion.V3_PoseidonMerkle) {
            (0, chain_1.assertChainSupportsV3)(chain);
        }
        const merkletree = this.txidMerkletrees.get(txidVersion, chain);
        if (!(0, is_defined_1.isDefined)(merkletree)) {
            throw new Error(`No railgun txid merkletree for txidVersion ${txidVersion}, chain ${chain.type}:${chain.id}`);
        }
        return merkletree;
    }
    hasTXIDMerkletree(txidVersion, chain) {
        try {
            this.getTXIDMerkletree(txidVersion, chain);
            return true;
        }
        catch {
            return false;
        }
    }
    async getCompletedTxidFromNullifiers(txidVersion, chain, nullifiers) {
        if (!nullifiers.length) {
            return undefined;
        }
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        // Iterating backwards from latest tree to find valid txid with matching nullifiers
        const latestTree = await utxoMerkletree.latestTree();
        for (let tree = latestTree; tree >= 0; tree -= 1) {
            // eslint-disable-next-line no-await-in-loop
            const txids = await Promise.all(nullifiers.map((nullifier) => utxoMerkletree.getNullifierTxid(nullifier, tree)));
            const firstTxid = txids[0];
            if (!(0, is_defined_1.isDefined)(firstTxid)) {
                continue;
            }
            const allMatch = txids.every((txid) => txid === firstTxid);
            if (allMatch) {
                return bytes_1.ByteUtils.formatToByteLength(firstTxid, bytes_1.ByteLength.UINT_256, true);
            }
        }
        return undefined;
    }
    async decryptBalancesAllWallets(txidVersion, chain, walletIdFilter, progressCallback, deferCompletionEvent) {
        const wallets = this.allWallets();
        for (let i = 0; i < wallets.length; i += 1) {
            if ((0, is_defined_1.isDefined)(walletIdFilter) && !walletIdFilter.includes(wallets[i].id)) {
                // Skip wallets not in filter
                continue;
            }
            // eslint-disable-next-line no-await-in-loop
            await wallets[i].decryptBalances(txidVersion, chain, (walletProgress) => {
                if (progressCallback) {
                    const finishedWalletsProgress = i / wallets.length;
                    const newWalletProgress = walletProgress / wallets.length;
                    progressCallback(finishedWalletsProgress + newWalletProgress);
                }
            }, deferCompletionEvent);
        }
    }
    /** Makes balance decryption errors visible to callers that need a complete snapshot. */
    async assertWalletBalancesDecrypted(txidVersion, chain, walletIdFilter) {
        const requestedWalletIds = new Set(walletIdFilter);
        const wallets = this.allWallets().filter((wallet) => requestedWalletIds.has(wallet.id));
        if (wallets.length !== requestedWalletIds.size) {
            throw new Error('Cannot prove balances for an unloaded wallet');
        }
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        const { tree: latestTree } = await utxoMerkletree.getLatestTreeAndIndex();
        for (const wallet of wallets) {
            // Wallet decryption catches internal errors, so verify its saved scan heights here.
            // eslint-disable-next-line no-await-in-loop
            const walletDetails = await wallet.getWalletDetails(txidVersion, chain);
            const firstWalletTree = walletDetails.creationTree ?? 0;
            for (let tree = firstWalletTree; tree <= latestTree; tree += 1) {
                // eslint-disable-next-line no-await-in-loop
                const treeLength = await utxoMerkletree.getTreeLength(tree);
                const walletScannedHeight = walletDetails.treeScannedHeights[tree] ?? 0;
                if (walletScannedHeight < treeLength) {
                    throw new Error(`Wallet balance decryption is incomplete for tree ${tree}`);
                }
            }
        }
    }
    invalidateTXOsCacheAllWallets(chain) {
        const wallets = this.allWallets();
        for (const wallet of wallets) {
            wallet.invalidateCommitmentsCache(chain);
        }
    }
    allWallets() {
        return Object.values(this.wallets);
    }
    /**
     * Unload wallet
     * @param id - wallet id to unload
     */
    unloadWallet(id) {
        delete this.wallets[id];
    }
    /**
     * Unloads wallets, removes listeners and closes DB.
     */
    async unload() {
        // Unload chains
        await Promise.all(contract_store_1.ContractStore.railgunSmartWalletContracts.map(async (contract, txidVersion, chain) => {
            debugger_1.default.log(`unload network ${chain.type}:${chain.id}`);
            await this.unloadNetwork(chain);
        }));
        // Unload wallets
        for (const walletID of Object.keys(this.wallets)) {
            this.unloadWallet(walletID);
        }
        await this.db.close();
    }
    async loadWallet(wallet) {
        // Store wallet against ID
        this.wallets[wallet.id] = wallet;
        if (this.skipMerkletreeScans) {
            throw new Error('Cannot load wallet: skipMerkletreeScans set to true. Wallets require merkle scans to load balances and history.');
        }
        for (const txidVersion of poi_types_1.ACTIVE_TXID_VERSIONS) {
            // Load UTXO and TXID merkletrees for wallet
            // eslint-disable-next-line no-await-in-loop
            await Promise.all(this.utxoMerkletrees.map(async (utxoMerkletree, thisTxidVersion) => {
                if (thisTxidVersion === txidVersion) {
                    await wallet.loadUTXOMerkletree(txidVersion, utxoMerkletree);
                }
            }));
            this.txidMerkletrees.forEach((txidMerkletree, thisTxidVersion) => {
                if (thisTxidVersion === txidVersion) {
                    wallet.loadRailgunTXIDMerkletree(txidVersion, txidMerkletree);
                }
            });
        }
    }
    /**
     * Load existing wallet
     * @param {string} encryptionKey - encryption key of wallet
     * @param {string} id - wallet ID
     * @returns id
     */
    async loadExistingWallet(encryptionKey, id) {
        if ((0, is_defined_1.isDefined)(this.wallets[id])) {
            return this.wallets[id];
        }
        const wallet = await railgun_wallet_1.RailgunWallet.loadExisting(this.db, encryptionKey, id, this.prover);
        await this.loadWallet(wallet);
        return wallet;
    }
    async loadExistingDelegatedSignWallet(encryptionKey, id, signDelegate) {
        if ((0, is_defined_1.isDefined)(this.wallets[id])) {
            const existingWallet = this.wallets[id];
            if (!(existingWallet instanceof railgun_wallet_1.DelegatedSignWallet)) {
                throw new Error('Incorrect wallet type.');
            }
            return existingWallet;
        }
        const wallet = await railgun_wallet_1.DelegatedSignWallet.loadExisting(this.db, encryptionKey, id, this.prover, signDelegate);
        await this.loadWallet(wallet);
        return wallet;
    }
    /**
     * Load existing wallet
     * @param {string} encryptionKey - encryption key of wallet
     * @param {string} id - wallet ID
     * @returns id
     */
    async loadExistingViewOnlyWallet(encryptionKey, id) {
        if ((0, is_defined_1.isDefined)(this.wallets[id])) {
            return this.wallets[id];
        }
        const wallet = await view_only_wallet_1.ViewOnlyWallet.loadExisting(this.db, encryptionKey, id, this.prover);
        await this.loadWallet(wallet);
        return wallet;
    }
    async deleteWallet(id) {
        this.unloadWallet(id);
        return abstract_wallet_1.AbstractWallet.delete(this.db, id);
    }
    /**
     * Creates wallet from mnemonic
     * @param {string} encryptionKey - encryption key of wallet
     * @param {string} mnemonic - mnemonic to load
     * @param {number} index - derivation index to load
     * @returns id
     */
    async createWalletFromMnemonic(encryptionKey, mnemonic, index = 0, creationBlockNumbers = undefined) {
        const wallet = await railgun_wallet_1.RailgunWallet.fromMnemonic(this.db, encryptionKey, mnemonic, index, creationBlockNumbers, this.prover);
        await this.loadWallet(wallet);
        return wallet;
    }
    async createViewOnlyWalletFromShareableViewingKey(encryptionKey, shareableViewingKey, creationBlockNumbers) {
        const wallet = await view_only_wallet_1.ViewOnlyWallet.fromShareableViewingKey(this.db, encryptionKey, shareableViewingKey, creationBlockNumbers, this.prover);
        await this.loadWallet(wallet);
        return wallet;
    }
    async createWalletFromKeys(encryptionKey, viewingKeyPair, spendingPublicKey, creationBlockNumbers, signDelegate) {
        const wallet = await railgun_wallet_1.DelegatedSignWallet.fromKeys(this.db, encryptionKey, viewingKeyPair, spendingPublicKey, creationBlockNumbers, this.prover, signDelegate);
        await this.loadWallet(wallet);
        return wallet;
    }
    async getAllShieldCommitments(txidVersion, chain, startingBlock) {
        const utxoMerkletree = this.getUTXOMerkletree(txidVersion, chain);
        const latestTree = await utxoMerkletree.latestTree();
        // TODO: use blockNumber to find exact starting position... But the logic is currently broken.
        // const treeInfo = await AbstractWallet.getCreationTreeAndPosition(
        //   merkletree,
        //   latestTree,
        //   startingBlock,
        // );
        const shieldCommitments = [];
        const startScanTree = 0;
        for (let treeIndex = startScanTree; treeIndex <= latestTree; treeIndex += 1) {
            // eslint-disable-next-line no-await-in-loop
            const treeHeight = await utxoMerkletree.getTreeLength(treeIndex);
            // const isInitialTree = treeIndex === startScanTree;
            // const startScanHeight = isInitialTree && treeInfo ? treeInfo.position : 0;
            const startScanHeight = 0;
            // eslint-disable-next-line no-await-in-loop
            const leaves = await utxoMerkletree.getCommitmentRange(treeIndex, startScanHeight, treeHeight - 1);
            for (const leaf of leaves) {
                if (!(0, is_defined_1.isDefined)(leaf)) {
                    continue;
                }
                if (leaf.blockNumber < startingBlock) {
                    continue;
                }
                if (leaf.commitmentType === formatted_types_1.CommitmentType.LegacyGeneratedCommitment ||
                    leaf.commitmentType === formatted_types_1.CommitmentType.ShieldCommitment) {
                    shieldCommitments.push(leaf);
                }
            }
        }
        return shieldCommitments;
    }
    // Top-level exports:
    static encodeAddress = bech32_1.encodeAddress;
    static decodeAddress = bech32_1.decodeAddress;
    railgunSmartWalletContracts = contract_store_1.ContractStore.railgunSmartWalletContracts;
    relayAdaptV2Contracts = contract_store_1.ContractStore.relayAdaptV2Contracts;
}
exports.RailgunEngine = RailgunEngine;
//# sourceMappingURL=railgun-engine.js.map