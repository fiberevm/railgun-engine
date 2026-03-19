/// <reference types="node" />
import { FallbackProvider } from 'ethers';
import EventEmitter from 'events';
import { Chain } from '../../../models/engine-types';
import { PollingJsonRpcProvider } from '../../../provider/polling-json-rpc-provider';
import { PoseidonMerkleAccumulator } from '../../../abi/typechain/PoseidonMerkleAccumulator';
import { EventsCommitmentListener, EventsNullifierListener, EventsRailgunTransactionListenerV3, EventsUnshieldListener } from '../../../models/event-types';
import { TXIDVersion } from '../../../models/poi-types';
export declare class PoseidonMerkleAccumulatorContract extends EventEmitter {
    readonly contract: PoseidonMerkleAccumulator;
    readonly contractForListeners: PoseidonMerkleAccumulator;
    readonly address: string;
    readonly chain: Chain;
    readonly txidVersion = TXIDVersion.V3_PoseidonMerkle;
    private readonly eventTopic;
    constructor(address: string, provider: PollingJsonRpcProvider | FallbackProvider, pollingProvider: PollingJsonRpcProvider, chain: Chain);
    /**
     * Get current merkle root
     */
    merkleRoot(): Promise<string>;
    /**
     * Validates historical root
     */
    validateMerkleroot(tree: number, root: string): Promise<boolean>;
    /**
     * Listens for update events.
     */
    setTreeUpdateListeners(eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener, eventsRailgunTransactionsV3Listener: EventsRailgunTransactionListenerV3, triggerWalletBalanceDecryptions: (txidVersion: TXIDVersion) => Promise<void>): Promise<void>;
    private scanAllUpdateV3Events;
    /**
     * Gets historical events from block
     * @param startBlock - block to scan from
     * @param latestBlock - block to scan to
     */
    getHistoricalEvents(initialStartBlock: number, latestBlock: number, getNextStartBlockFromValidMerkletree: () => Promise<number>, eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener, eventsRailgunTransactionsV3Listener: EventsRailgunTransactionListenerV3, setLastSyncedBlock: (lastSyncedBlock: number) => Promise<void>): Promise<void>;
    /**
     * Remove all listeners and shutdown contract instance
     */
    unload(): Promise<void>;
}
