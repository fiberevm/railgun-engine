import { EventFilter, Subscriber, AbstractProvider } from 'ethers';
/**
 * A batched event subscriber that polls once per interval instead of per-block.
 * This dramatically reduces eth_getLogs calls.
 *
 * reasoning: ethers PollingEventSubscriber fires on every "block" event,
 * this subscriber uses a timer-based approach matching the pollingInterval.
 */
export declare class BatchedPollingEventSubscriber implements Subscriber {
    #private;
    constructor(provider: AbstractProvider, filter: EventFilter, pollingInterval: number);
    start(): void;
    stop(): void;
    pause(dropWhilePaused?: boolean): void;
    resume(): void;
}
