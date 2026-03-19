"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PoseidonMerkleAccumulatorContract = void 0;
const ethers_1 = require("ethers");
const events_1 = __importDefault(require("events"));
const abi_1 = require("../../../abi/abi");
const bytes_1 = require("../../../utils/bytes");
const debugger_1 = __importDefault(require("../../../debugger/debugger"));
const polling_util_1 = require("../../../provider/polling-util");
const event_types_1 = require("../../../models/event-types");
const poi_types_1 = require("../../../models/poi-types");
const V3_events_1 = require("./V3-events");
const promises_1 = require("../../../utils/promises");
const ethers_2 = require("../../../utils/ethers");
const SCAN_CHUNKS = 499;
const MAX_SCAN_RETRIES = 30;
const EVENTS_SCAN_TIMEOUT = 5000;
const SCAN_TIMEOUT_ERROR_MESSAGE = 'getLogs request timed out after 5 seconds.';
class PoseidonMerkleAccumulatorContract extends events_1.default {
    contract;
    contractForListeners;
    address;
    chain;
    txidVersion = poi_types_1.TXIDVersion.V3_PoseidonMerkle;
    eventTopic;
    constructor(address, provider, pollingProvider, chain) {
        super();
        this.address = address;
        this.contract = new ethers_1.Contract(address, abi_1.ABIPoseidonMerkleAccumulator, provider);
        this.eventTopic = this.contract.getEvent('AccumulatorStateUpdate').getFragment().topicHash;
        this.chain = chain;
        // Because of a 'stallTimeout' bug in Ethers v6, all providers in a FallbackProvider will get called simultaneously.
        // So, we'll use a single json rpc (the first in the FallbackProvider) to poll for the event listeners.
        (0, polling_util_1.assertIsPollingProvider)(pollingProvider);
        this.contractForListeners = new ethers_1.Contract(address, abi_1.ABIPoseidonMerkleAccumulator, pollingProvider);
    }
    /**
     * Get current merkle root
     */
    async merkleRoot() {
        return bytes_1.ByteUtils.hexlify(await this.contract.accumulatorRoot());
    }
    /**
     * Validates historical root
     */
    async validateMerkleroot(tree, root) {
        try {
            const isValidMerkleroot = await this.contract.rootHistory(tree, bytes_1.ByteUtils.formatToByteLength(root, bytes_1.ByteLength.UINT_256, true));
            // if (!isValidMerkleroot && EngineDebug.isTestRun()) {
            //   EngineDebug.error(
            //     new Error(`[TEST] Last valid merkleroot: ${await this.contract.accumulatorRoot()}`),
            //   );
            // }
            return isValidMerkleroot;
        }
        catch (cause) {
            const err = new Error('Failed to validate V3 Poseidon merkleroot', { cause });
            debugger_1.default.error(err);
            throw err;
        }
    }
    /**
     * Listens for update events.
     */
    async setTreeUpdateListeners(eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, triggerWalletBalanceDecryptions) {
        await this.contractForListeners.on(this.eventTopic, (event) => {
            try {
                if (event.log.topics.length !== 1) {
                    throw new Error('Requires one topic for railgun events');
                }
                // eslint-disable-next-line @typescript-eslint/no-floating-promises
                V3_events_1.V3Events.processAccumulatorEvent(this.txidVersion, event.args, event.log.transactionHash, event.log.blockNumber, eventsCommitmentListener, async (txidVersion, nullifiers) => {
                    // eslint-disable-next-line @typescript-eslint/no-floating-promises
                    eventsNullifierListener(txidVersion, nullifiers);
                    this.emit(event_types_1.EngineEvent.ContractNullifierReceived, nullifiers);
                }, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, triggerWalletBalanceDecryptions);
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
    async scanAllUpdateV3Events(startBlock, endBlock, retryCount = 0) {
        try {
            const events = await (0, promises_1.promiseTimeout)(this.contract.queryFilter(this.contract.filters.AccumulatorStateUpdate(), startBlock, endBlock), EVENTS_SCAN_TIMEOUT, SCAN_TIMEOUT_ERROR_MESSAGE);
            const eventsWithDecodedArgs = events.map((event) => ({
                ...event,
                args: (0, ethers_2.recursivelyDecodeResult)(event.args),
            }));
            return eventsWithDecodedArgs;
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                throw new Error('Non-error was thrown during scanAllUpdateV3Events', { cause });
            }
            const err = new Error('Failed to scan all V3 update events', { cause });
            if (retryCount < MAX_SCAN_RETRIES && cause.message === SCAN_TIMEOUT_ERROR_MESSAGE) {
                const retry = retryCount + 1;
                debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: Scan query error at block ${startBlock}. Retrying ${MAX_SCAN_RETRIES - retry} times.`);
                debugger_1.default.error(err);
                return this.scanAllUpdateV3Events(startBlock, endBlock, retry);
            }
            debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: Scan failed at block ${startBlock}. No longer retrying.`);
            debugger_1.default.error(err);
            throw err;
        }
    }
    /**
     * Gets historical events from block
     * @param startBlock - block to scan from
     * @param latestBlock - block to scan to
     */
    async getHistoricalEvents(initialStartBlock, latestBlock, getNextStartBlockFromValidMerkletree, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener, setLastSyncedBlock) {
        let currentStartBlock = initialStartBlock;
        const { txidVersion } = this;
        debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: [${txidVersion}] Scanning historical events from block ${currentStartBlock} to ${latestBlock}`);
        let startBlockForNext10000 = initialStartBlock;
        while (currentStartBlock < latestBlock) {
            // Process chunks of blocks for all events, serially.
            if ((currentStartBlock - startBlockForNext10000) % 10000 === 0) {
                debugger_1.default.log(`[Chain ${this.chain.type}:${this.chain.id}]: [${txidVersion}] Scanning next 10,000 events [${currentStartBlock}]...`);
            }
            const endBlock = Math.min(latestBlock, currentStartBlock + SCAN_CHUNKS);
            // eslint-disable-next-line no-await-in-loop
            const allUpdateV3EventLogs = await this.scanAllUpdateV3Events(currentStartBlock, endBlock);
            // eslint-disable-next-line no-await-in-loop
            await V3_events_1.V3Events.processAccumulatorUpdateEvents(this.txidVersion, allUpdateV3EventLogs, eventsCommitmentListener, eventsNullifierListener, eventsUnshieldListener, eventsRailgunTransactionsV3Listener);
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
     * Remove all listeners and shutdown contract instance
     */
    async unload() {
        await this.contract.removeAllListeners();
        await this.contractForListeners?.removeAllListeners();
    }
}
exports.PoseidonMerkleAccumulatorContract = PoseidonMerkleAccumulatorContract;
//# sourceMappingURL=poseidon-merkle-accumulator.js.map