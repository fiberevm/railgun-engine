import { JsonRpcProvider, Subscriber } from 'ethers';
/**
 * Uses a setting in JsonRpcProvider to poll for events,
 * rather than using sparsely-implemented eth_filter events.
 *
 * Overrides _getSubscriber to use BatchedPollingEventSubscriber for events,
 * which polls once per pollingInterval instead of per-block.
 */
export declare class PollingJsonRpcProvider extends JsonRpcProvider {
    #private;
    readonly isPollingProvider: boolean;
    constructor(url: string, chainId: number, pollingInterval?: number, maxLogsPerBatch?: number);
    get paused(): boolean;
    _getSubscriber(sub: any): Subscriber;
    pause(): void;
    resume(): void;
}
