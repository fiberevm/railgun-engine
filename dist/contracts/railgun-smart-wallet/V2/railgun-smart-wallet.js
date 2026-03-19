"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RailgunSmartWalletContract = void 0;
const ethers_1 = require("ethers");
const events_1 = __importDefault(require("events"));
const debugger_1 = __importDefault(require("../../../debugger/debugger"));
const event_types_1 = require("../../../models/event-types");
const bytes_1 = require("../../../utils/bytes");
const promises_1 = require("../../../utils/promises");
const abi_1 = require("../../../abi/abi");
const V2_events_1 = require("./V2-events");
const legacy_events_1 = require("../V1/legacy-events");
const constants_1 = require("../../../utils/constants");
const engine_types_1 = require("../../../models/engine-types");
const polling_util_1 = require("../../../provider/polling-util");
const poi_types_1 = require("../../../models/poi-types");
const ethers_2 = require("../../../utils/ethers");
const SCAN_CHUNKS = 499;
const MAX_SCAN_RETRIES = 30;
const EVENTS_SCAN_TIMEOUT = 5000;
const SCAN_TIMEOUT_ERROR_MESSAGE = 'getLogs request timed out after 5 seconds.';
class RailgunSmartWalletContract extends events_1.default {
    contract;
    contractForListeners;
    address;
    chain;
    txidVersion = poi_types_1.TXIDVersion.V2_PoseidonMerkle;
    /**
     * Connect to Railgun instance on network
     * @param railgunSmartWalletContractAddress - address of Railgun instance (Proxy contract)
     * @param provider - Network provider
     */
    constructor(railgunSmartWalletContractAddress, defaultProvider, pollingProvider, chain) {
        super();
        this.address = railgunSmartWalletContractAddress;
        this.contract = new ethers_1.Contract(railgunSmartWalletContractAddress, abi_1.ABIRailgunSmartWallet, defaultProvider);
        // Because of a 'stallTimeout' bug in Ethers v6, all providers in a FallbackProvider will get called simultaneously.
        // So, we'll use a single json rpc (the first in the FallbackProvider) to poll for the event listeners.
        (0, polling_util_1.assertIsPollingProvider)(pollingProvider);
        this.contractForListeners = new ethers_1.Contract(railgunSmartWalletContractAddress, abi_1.ABIRailgunSmartWallet, pollingProvider);
        this.chain = chain;
    }
    /**
     * Get current merkle root
     * @returns merkle root
     */
    async merkleRoot() {
        return bytes_1.ByteUtils.hexlify(await this.contract.merkleRoot());
    }
    /**
     * Gets transaction fees
     * Shield and unshield fees are in basis points, NFT is in wei.
     */
    async fees() {
        const [shieldFee, unshieldFee, nftFee] = await Promise.all([
            this.contract.shieldFee(),
            this.contract.unshieldFee(),
            this.contract.nftFee(),
        ]);
        return {
            shield: shieldFee,
            unshield: unshieldFee,
            nft: nftFee,
        };
    }
    /**
     * Validate root
     * @param root - root to validate
     * @returns isValid
     */
    async validateMerkleroot(tree, root) {
        try {
            const isValidMerkleroot = await this.contract.rootHistory(tree, bytes_1.ByteUtils.formatToByteLength(root, bytes_1.ByteLength.UINT_256, true));
            // if (!isValidMerkleroot && EngineDebug.isTestRun()) {
            //   EngineDebug.error(
            //     new Error(`[TEST] Last valid merkleroot: ${await this.contract.merkleRoot()}`),
            //   );
            // }
            return isValidMerkleroot;
        }
        catch (cause) {
            const err = new Error('Failed to validate V2 merkleroot', { cause });
            debugger_1.default.error(err);
            throw err;
        }
    }
    /**
     * Get NFT token data from tokenHash.
     * @param tokenHash - tokenHash
     * @returns token data
     */
    async getNFTTokenData(tokenHash) {
        try {
            const formattedTokenHash = bytes_1.ByteUtils.formatToByteLength(tokenHash, bytes_1.ByteLength.UINT_256, true);
            return await this.contract.tokenIDMapping(formattedTokenHash);
        }
        catch (cause) {
            const err = new Error('Failed to get NFT token data', { cause });
            debugger_1.default.error(err);
            throw err;
        }
    }
    async handleNullifiedEvent(event, eventsNullifierListener) {
        const { treeNumber, nullifier } = event.args.toObject();
        const nullifierDecoded = (0, ethers_2.recursivelyDecodeResult)(nullifier);
        const args = {
            treeNumber,
            nullifier: nullifierDecoded,
        };
        const nullifiers = V2_events_1.V2Events.formatNullifiedEvents(args, event.log.transactionHash, event.log.blockNumber);
        await eventsNullifierListener(this.txidVersion, nullifiers);
        this.emit(event_types_1.EngineEvent.ContractNullifierReceived, nullifiers);
    }
    async handleShieldEvent(event, eventsCommitmentListener) {
        const { treeNumber, startPosition, commitments, shieldCiphertext, fees } = event.args.toObject();
        const commitmentsDecoded = (0, ethers_2.recursivelyDecodeResult)(commitments);
        const shieldCiphertextDecoded = (0, ethers_2.recursivelyDecodeResult)(shieldCiphertext);
        const feesDecoded = (0, ethers_2.recursivelyDecodeResult)(fees);
        const args = {
            treeNumber,
            startPosition,
            commitments: commitmentsDecoded,
            shieldCiphertext: shieldCiphertextDecoded,
            fees: feesDecoded,
        };
        const shieldEvent = V2_events_1.V2Events.formatShieldEvent(args, event.log.transactionHash, event.log.blockNumber, args.fees, Date.now() / 1000);
        await eventsCommitmentListener(this.txidVersion, [shieldEvent]);
    }
    async handleTransactEvent(event, eventsCommitmentListener) {
        const { treeNumber, startPosition, hash, ciphertext } = event.args.toObject();
        const hashDecoded = (0, ethers_2.recursivelyDecodeResult)(hash);
        const ciphertextDecoded = (0, ethers_2.recursivelyDecodeResult)(ciphertext);
        const args = {
            treeNumber,
            startPosition,
            hash: hashDecoded,
            ciphertext: ciphertextDecoded,
        };
        const transactEvent = V2_events_1.V2Events.formatTransactEvent(args, event.log.transactionHash, event.log.blockNumber, Date.now() / 1000);
        await eventsCommitmentListener(this.txidVersion, [transactEvent]);
    }
    async handleUnshieldEvent(event, eventsUnshieldListener) {
        const { to, token, amount, fee } = event.args.toObject();
        const tokenDecoded = (0, ethers_2.recursivelyDecodeResult)(token);
        const args = {
            to,
            token: tokenDecoded,
            amount,
            fee,
        };
        const unshieldEvent = V2_events_1.V2Events.formatUnshieldEvent(args, event.log.transactionHash, event.log.blockNumber, event.log.index, Date.now() / 1000);
        await eventsUnshieldListener(this.txidVersion, [unshieldEvent]);
    }
    /**
     * Listens for tree update events
     * @param eventsCommitmentListener - commitment listener callback
     * @param eventsNullifierListener - nullifier listener callback
     * @param eventsUnshieldListener - unshield listener callback
     */
    async setTreeUpdateListeners(eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener) {
        const nullifiedTopic = this.contract.getEvent('Nullified').getFragment().topicHash;
        const shieldTopic = this.contract.getEvent('Shield').getFragment().topicHash;
        const transactTopic = this.contract.getEvent('Transact').getFragment().topicHash;
        const unshieldTopic = this.contract.getEvent('Unshield').getFragment().topicHash;
        await this.contractForListeners.on(
        // @ts-expect-error - Use * to request all events
        '*', // All Events
        (event) => {
            try {
                if (event.log.topics.length !== 1) {
                    throw new Error('Requires one topic for railgun events');
                }
                switch (event.log.topics[0]) {
                    case nullifiedTopic:
                        // eslint-disable-next-line @typescript-eslint/no-floating-promises
                        this.handleNullifiedEvent(event, eventsNullifierListener);
                        return;
                    case shieldTopic:
                        // eslint-disable-next-line @typescript-eslint/no-floating-promises
                        this.handleShieldEvent(event, eventsCommitmentListener);
                        return;
                    case transactTopic:
                        // eslint-disable-next-line @typescript-eslint/no-floating-promises
                        this.handleTransactEvent(event, eventsCommitmentListener);
                        return;
                    case unshieldTopic:
                        // eslint-disable-next-line @typescript-eslint/no-floating-promises
                        this.handleUnshieldEvent(event, eventsUnshieldListener);
                        return;
                }
                throw new Error('Event topic not recognized');
            }
            catch (err) {
                if (err instanceof Error) {
                    debugger_1.default.error(err);
                }
                if (debugger_1.default.isTestRun()) {
                    throw err;
                }
            }
        });
    }
    async scanAllEvents(startBlock, endBlock, retryCount = 0) {
        try {
            const events = await (0, promises_1.promiseTimeout)(
            // @ts-expect-error - Use * to request all events
            this.contract.queryFilter('*', startBlock, endBlock), EVENTS_SCAN_TIMEOUT, SCAN_TIMEOUT_ERROR_MESSAGE);
            const eventsWithDecodedArgs = events.map((event) => ({
                ...event,
                args: (0, ethers_2.recursivelyDecodeResult)(event.args),
            }));
            return eventsWithDecodedArgs;
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error was thrown during scanAllEvents', { cause });
            }
            const err = new Error('Failed to scan V2 events', { cause });
            if (retryCount < MAX_SCAN_RETRIES && cause.message === SCAN_TIMEOUT_ERROR_MESSAGE) {
                const retry = retryCount + 1;
                debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: Scan query error at block ${startBlock}. Retrying ${MAX_SCAN_RETRIES - retry} times.`);
                debugger_1.default.error(err);
                return this.scanAllEvents(startBlock, endBlock, retry);
            }
            debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: Scan failed at block ${startBlock}. No longer retrying.`);
            debugger_1.default.error(err);
            throw err;
        }
    }
    static getEngineV2StartBlockNumber(chain) {
        if (chain.type === engine_types_1.ChainType.EVM) {
            return constants_1.ENGINE_V2_START_BLOCK_NUMBERS_EVM[chain.id] || 0;
        }
        return 0;
    }
    static getEngineV2ShieldEventUpdate030923BlockNumber(chain) {
        if (chain.type === engine_types_1.ChainType.EVM) {
            return constants_1.ENGINE_V2_SHIELD_EVENT_UPDATE_03_09_23_BLOCK_NUMBERS_EVM[chain.id] || 0;
        }
        return 0;
    }
    static getShieldPreMar23EventFilter() {
        // Cannot use `this.contract`, because the "Shield" named event has changed. (It has a different topic).
        const ifaceLegacyShieldPreMar23 = new ethers_1.Interface(abi_1.ABIRailgunSmartWallet_Legacy_PreMar23.filter((fragment) => fragment.type === 'event'));
        const shieldPreMar23EventFragment = ifaceLegacyShieldPreMar23.getEvent('Shield');
        if (!shieldPreMar23EventFragment) {
            throw new Error('Requires shield event fragment - Legacy, pre mar 23');
        }
        const legacyPreMar23EventFilterShield = {
            getTopicFilter: async () => ifaceLegacyShieldPreMar23.encodeFilterTopics('Shield', []),
            fragment: shieldPreMar23EventFragment,
        };
        return legacyPreMar23EventFilterShield;
    }
    static filterEventsByTopic(events, eventFilter) {
        return events.filter((event) => event.topics.length === 1 && eventFilter.fragment.topicHash === event.topics[0]);
    }
    /**
     * Gets historical events from block
     * @param startBlock - block to scan from
     * @param latestBlock - block to scan to
     */
    async getHistoricalEvents(initialStartBlock, latestBlock, getNextStartBlockFromValidMerkletree, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, setLastSyncedBlock) {
        const engineV3StartBlockNumber = RailgunSmartWalletContract.getEngineV2StartBlockNumber(this.chain);
        const engineV3ShieldEventUpdate030923BlockNumber = RailgunSmartWalletContract.getEngineV2ShieldEventUpdate030923BlockNumber(this.chain);
        // TODO: Possible data integrity issue in using commitment block numbers.
        // Unshields and Nullifiers are scanned from the latest commitment block.
        // Unshields/Nullifiers are not validated using the same merkleroot validation.
        // If we miss an unshield/nullifier for some reason, we won't pick it up .
        // For missed unshields, this will affect the way transaction history is displayed (no balance impact).
        // For missed nullifiers, this will incorrectly show a balance for a spent note.
        let currentStartBlock = initialStartBlock;
        const { txidVersion } = this;
        // Current live events - post V2 update
        const eventFilterNullified = this.contract.filters.Nullified();
        const eventFilterTransact = this.contract.filters.Transact();
        const eventFilterUnshield = this.contract.filters.Unshield();
        // Current live Shield - Mar 2023
        const eventFilterShield = this.contract.filters.Shield();
        // This type includes legacy event types and filters, from before the v3 update.
        // We need to scan prior commitments from these past events, before engineV3StartBlockNumber.
        const legacyEventsContract = this.contract;
        const legacyEventFilterNullifiers = legacyEventsContract.filters.Nullifiers();
        const legacyEventFilterGeneratedCommitmentBatch = legacyEventsContract.filters.GeneratedCommitmentBatch();
        const legacyEventFilterEncryptedCommitmentBatch = legacyEventsContract.filters.CommitmentBatch();
        // This type includes legacy Shield event types and filters, from before the Mar 2023 update.
        const legacyPreMar23EventFilterShield = RailgunSmartWalletContract.getShieldPreMar23EventFilter();
        debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: [${txidVersion}] Scanning historical events from block ${currentStartBlock} to ${latestBlock}`);
        let startBlockForNext10000 = initialStartBlock;
        while (currentStartBlock < latestBlock) {
            // Process chunks of blocks for all events, serially.
            const endBlock = Math.min(latestBlock, currentStartBlock + SCAN_CHUNKS);
            const withinLegacyEventRange = currentStartBlock <= engineV3StartBlockNumber;
            const withinV3EventRange = endBlock >= engineV3StartBlockNumber;
            const withinLegacyV3ShieldEventRange = currentStartBlock <= engineV3ShieldEventUpdate030923BlockNumber;
            const withinNewV3ShieldEventRange = endBlock >= engineV3ShieldEventUpdate030923BlockNumber;
            if (withinLegacyEventRange && withinV3EventRange) {
                debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: Changing from legacy events to new events...`);
            }
            if ((currentStartBlock - startBlockForNext10000) % 10000 === 0) {
                debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: [${txidVersion}] Scanning next 10,000 events (${withinLegacyEventRange ? 'V1' : 'V2'}) [${currentStartBlock}]...`);
            }
            // eslint-disable-next-line no-await-in-loop
            const allEvents = await this.scanAllEvents(currentStartBlock, endBlock);
            if (withinV3EventRange) {
                if (withinLegacyV3ShieldEventRange) {
                    // Legacy V3 Shield Event - Pre March 2023.
                    const eventsShieldLegacyV3 = RailgunSmartWalletContract.filterEventsByTopic(allEvents, legacyPreMar23EventFilterShield);
                    // eslint-disable-next-line no-await-in-loop
                    await V2_events_1.V2Events.processShieldEvents_LegacyShield_PreMar23(txidVersion, eventsCommitmentListener, eventsShieldLegacyV3);
                }
                if (withinNewV3ShieldEventRange) {
                    // New V3 Shield Event - After March 2023.
                    const eventsShield = RailgunSmartWalletContract.filterEventsByTopic(allEvents, eventFilterShield);
                    // eslint-disable-next-line no-await-in-loop
                    await V2_events_1.V2Events.processShieldEvents(txidVersion, eventsCommitmentListener, eventsShield);
                }
                const eventsNullifiers = RailgunSmartWalletContract.filterEventsByTopic(allEvents, eventFilterNullified);
                const eventsTransact = RailgunSmartWalletContract.filterEventsByTopic(allEvents, eventFilterTransact);
                const eventsUnshield = RailgunSmartWalletContract.filterEventsByTopic(allEvents, eventFilterUnshield);
                // eslint-disable-next-line no-await-in-loop
                await Promise.all([
                    V2_events_1.V2Events.processNullifiedEvents(txidVersion, eventsNullifierListener, eventsNullifiers),
                    V2_events_1.V2Events.processUnshieldEvents(txidVersion, eventsUnshieldListener, eventsUnshield),
                    V2_events_1.V2Events.processTransactEvents(txidVersion, eventsCommitmentListener, eventsTransact),
                ]);
            }
            if (withinLegacyEventRange) {
                const legacyEventsNullifiers = RailgunSmartWalletContract.filterEventsByTopic(allEvents, legacyEventFilterNullifiers);
                const legacyEventsGeneratedCommitmentBatch = RailgunSmartWalletContract.filterEventsByTopic(allEvents, legacyEventFilterGeneratedCommitmentBatch);
                const legacyEventsEncryptedCommitmentBatch = RailgunSmartWalletContract.filterEventsByTopic(allEvents, legacyEventFilterEncryptedCommitmentBatch);
                // eslint-disable-next-line no-await-in-loop
                await Promise.all([
                    (0, legacy_events_1.processLegacyNullifierEvents)(txidVersion, eventsNullifierListener, legacyEventsNullifiers),
                    (0, legacy_events_1.processLegacyGeneratedCommitmentEvents)(txidVersion, eventsCommitmentListener, legacyEventsGeneratedCommitmentBatch),
                    (0, legacy_events_1.processLegacyCommitmentBatchEvents)(txidVersion, eventsCommitmentListener, legacyEventsEncryptedCommitmentBatch),
                ]);
            }
            // eslint-disable-next-line no-await-in-loop
            await setLastSyncedBlock(endBlock);
            const nextStartBlockFromCurrentBlock = currentStartBlock + SCAN_CHUNKS + 1;
            const nextStartBlockFromLatestValidMerkletreeEntry = 
            // eslint-disable-next-line no-await-in-loop
            await getNextStartBlockFromValidMerkletree();
            // Choose greater of:
            // 1. currentStartBlock + scan chunk size
            // 2. Latest verified merkletree block
            // This optimizes the slow scan in case quicksync returns a single invalid merkleroot for a given block.
            // The other data is queued for merkletree, and will validate and enter the merkletree, providing a new starting block.
            // This skips slow scan for those intermediary blocks.
            if (nextStartBlockFromLatestValidMerkletreeEntry > nextStartBlockFromCurrentBlock) {
                currentStartBlock = nextStartBlockFromLatestValidMerkletreeEntry;
                startBlockForNext10000 = nextStartBlockFromLatestValidMerkletreeEntry;
                debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: Skipping ${nextStartBlockFromCurrentBlock - nextStartBlockFromLatestValidMerkletreeEntry} already processed/validated blocks from QuickSync...`);
            }
            else {
                currentStartBlock = nextStartBlockFromCurrentBlock;
            }
        }
        debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: Finished historical event scan`);
    }
    /**
     * GenerateShield populated transaction
     * @returns Populated transaction
     */
    generateShield(shieldRequests) {
        return this.contract.shield.populateTransaction(shieldRequests);
    }
    /**
     * Create transaction call for ETH
     * @param transactions - serialized railgun transaction
     * @returns - populated ETH transaction
     */
    generateTransact(transactions) {
        return this.contract.transact.populateTransaction(transactions);
    }
    async hashCommitment(commitment) {
        return this.contract.hashCommitment({
            ...commitment,
            npk: bytes_1.ByteUtils.formatToByteLength(commitment.npk, bytes_1.ByteLength.UINT_256, true),
        });
    }
    /**
     * Remove all listeners and shutdown contract instance
     */
    async unload() {
        await this.contract.removeAllListeners();
        await this.contractForListeners?.removeAllListeners();
    }
}
exports.RailgunSmartWalletContract = RailgunSmartWalletContract;
//# sourceMappingURL=railgun-smart-wallet.js.map