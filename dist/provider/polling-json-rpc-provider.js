"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PollingJsonRpcProvider = void 0;
const ethers_1 = require("ethers");
const batched_polling_event_subscriber_1 = require("./batched-polling-event-subscriber");
/**
 * Uses a setting in JsonRpcProvider to poll for events,
 * rather than using sparsely-implemented eth_filter events.
 *
 * Overrides _getSubscriber to use BatchedPollingEventSubscriber for events,
 * which polls once per pollingInterval instead of per-block.
 */
class PollingJsonRpcProvider extends ethers_1.JsonRpcProvider {
    isPollingProvider = true;
    #eventPollingInterval;
    #isPaused = false;
    constructor(url, chainId, pollingInterval = 10000, maxLogsPerBatch = 100) {
        const network = ethers_1.Network.from(chainId);
        const options = {
            polling: true,
            staticNetwork: network,
            batchMaxCount: maxLogsPerBatch,
        };
        super(url, network, options);
        this.pollingInterval = pollingInterval;
        this.#eventPollingInterval = pollingInterval;
    }
    get paused() {
        return this.#isPaused;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, no-underscore-dangle
    _getSubscriber(sub) {
        if (sub.type === 'event') {
            const newSub = new batched_polling_event_subscriber_1.BatchedPollingEventSubscriber(this, sub.filter, this.#eventPollingInterval);
            if (this.#isPaused) {
                newSub.pause(false);
            }
            return newSub;
        }
        // eslint-disable-next-line no-underscore-dangle
        return super._getSubscriber(sub);
    }
    pause() {
        this.#isPaused = true;
        // eslint-disable-next-line no-underscore-dangle
        this._forEachSubscriber((sub) => {
            sub.pause(false);
        });
    }
    resume() {
        this.#isPaused = false;
        // eslint-disable-next-line no-underscore-dangle
        this._forEachSubscriber((sub) => {
            sub.resume();
        });
    }
}
exports.PollingJsonRpcProvider = PollingJsonRpcProvider;
//# sourceMappingURL=polling-json-rpc-provider.js.map