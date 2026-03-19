"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BatchedPollingEventSubscriber = void 0;
const is_defined_1 = require("../utils/is-defined");
const DEFAULT_MAX_BATCH_BLOCKS = 500;
/**
 * A batched event subscriber that polls once per interval instead of per-block.
 * This dramatically reduces eth_getLogs calls.
 *
 * reasoning: ethers PollingEventSubscriber fires on every "block" event,
 * this subscriber uses a timer-based approach matching the pollingInterval.
 */
class BatchedPollingEventSubscriber {
    #provider;
    #filter;
    #running;
    #blockNumber;
    #pollTimer;
    #pollingInterval;
    #maxBatchBlocks;
    #polling;
    #errorBackoff = 0;
    constructor(provider, filter, pollingInterval) {
        if (pollingInterval <= 0)
            throw new Error('pollingInterval must be positive');
        this.#provider = provider;
        this.#filter = filter;
        this.#running = false;
        this.#blockNumber = -2;
        this.#pollTimer = null;
        this.#pollingInterval = pollingInterval;
        this.#maxBatchBlocks = DEFAULT_MAX_BATCH_BLOCKS;
        this.#polling = false;
    }
    async #poll() {
        if (!this.#running) {
            return;
        }
        if (this.#polling) {
            this.#schedulePoll();
            return;
        }
        this.#polling = true;
        try {
            const head = await this.#provider.getBlockNumber();
            if (this.#blockNumber === -2) {
                this.#blockNumber = head;
                this.#schedulePoll();
                return;
            }
            if (head <= this.#blockNumber) {
                this.#schedulePoll();
                return;
            }
            let currentFrom = this.#blockNumber + 1;
            while (currentFrom <= head) {
                if (!this.#running) {
                    break;
                }
                const currentTo = Math.min(currentFrom + this.#maxBatchBlocks - 1, head);
                const rangeFilter = {
                    ...this.#filter,
                    fromBlock: currentFrom,
                    toBlock: currentTo,
                };
                // eslint-disable-next-line no-await-in-loop
                const logs = await this.#provider.getLogs(rangeFilter);
                for (const log of logs) {
                    // eslint-disable-next-line @typescript-eslint/no-floating-promises
                    this.#provider.emit(this.#filter, log);
                }
                this.#blockNumber = currentTo;
                currentFrom = currentTo + 1;
            }
            this.#errorBackoff = 0;
        }
        catch (error) {
            // eslint-disable-next-line @typescript-eslint/no-floating-promises
            this.#provider.emit('error', error);
            this.#errorBackoff = Math.min((this.#errorBackoff || this.#pollingInterval) * 2, 30000);
        }
        finally {
            this.#polling = false;
        }
        this.#schedulePoll();
    }
    #schedulePoll() {
        if (!this.#running) {
            return;
        }
        if (this.#pollTimer != null) {
            clearTimeout(this.#pollTimer);
            this.#pollTimer = null;
        }
        this.#pollTimer = setTimeout(() => {
            // eslint-disable-next-line @typescript-eslint/no-floating-promises
            this.#poll();
        }, this.#errorBackoff || this.#pollingInterval);
    }
    start() {
        if (this.#running) {
            return;
        }
        this.#running = true;
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        this.#poll();
    }
    stop() {
        if (!this.#running) {
            return;
        }
        this.#running = false;
        if (this.#pollTimer != null) {
            clearTimeout(this.#pollTimer);
            this.#pollTimer = null;
        }
    }
    pause(dropWhilePaused) {
        this.stop();
        if ((0, is_defined_1.isDefined)(dropWhilePaused) && dropWhilePaused) {
            this.#blockNumber = -2;
        }
    }
    resume() {
        this.start();
    }
}
exports.BatchedPollingEventSubscriber = BatchedPollingEventSubscriber;
//# sourceMappingURL=batched-polling-event-subscriber.js.map