/// <reference types="node" />
import { ContractTransaction, FallbackProvider } from 'ethers';
import EventEmitter from 'events';
import { EventsCommitmentListener, EventsNullifierListener, EventsUnshieldListener } from '../../../models/event-types';
import { CommitmentPreimageStruct, ShieldRequestStruct, TokenDataStructOutput, TransactionStruct, RailgunSmartWallet } from '../../../abi/typechain/RailgunSmartWallet';
import { Chain } from '../../../models/engine-types';
import { PollingJsonRpcProvider } from '../../../provider/polling-json-rpc-provider';
import { TXIDVersion } from '../../../models/poi-types';
export declare class RailgunSmartWalletContract extends EventEmitter {
    readonly contract: RailgunSmartWallet;
    readonly contractForListeners: RailgunSmartWallet;
    readonly address: string;
    readonly chain: Chain;
    readonly txidVersion = TXIDVersion.V2_PoseidonMerkle;
    /**
     * Connect to Railgun instance on network
     * @param railgunSmartWalletContractAddress - address of Railgun instance (Proxy contract)
     * @param provider - Network provider
     */
    constructor(railgunSmartWalletContractAddress: string, defaultProvider: PollingJsonRpcProvider | FallbackProvider, pollingProvider: PollingJsonRpcProvider, chain: Chain);
    /**
     * Get current merkle root
     * @returns merkle root
     */
    merkleRoot(): Promise<string>;
    /**
     * Gets transaction fees
     * Shield and unshield fees are in basis points, NFT is in wei.
     */
    fees(): Promise<{
        shield: bigint;
        unshield: bigint;
        nft: bigint;
    }>;
    /**
     * Validate root
     * @param root - root to validate
     * @returns isValid
     */
    validateMerkleroot(tree: number, root: string): Promise<boolean>;
    /**
     * Get NFT token data from tokenHash.
     * @param tokenHash - tokenHash
     * @returns token data
     */
    getNFTTokenData(tokenHash: string): Promise<TokenDataStructOutput>;
    private handleNullifiedEvent;
    private handleShieldEvent;
    private handleTransactEvent;
    private handleUnshieldEvent;
    /**
     * Listens for tree update events
     * @param eventsCommitmentListener - commitment listener callback
     * @param eventsNullifierListener - nullifier listener callback
     * @param eventsUnshieldListener - unshield listener callback
     */
    setTreeUpdateListeners(eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener): Promise<void>;
    private scanAllEvents;
    static getEngineV2StartBlockNumber(chain: Chain): number;
    private static getEngineV2ShieldEventUpdate030923BlockNumber;
    private static getShieldPreMar23EventFilter;
    private static filterEventsByTopic;
    /**
     * Gets historical events from block
     * @param startBlock - block to scan from
     * @param latestBlock - block to scan to
     */
    getHistoricalEvents(initialStartBlock: number, latestBlock: number, getNextStartBlockFromValidMerkletree: () => Promise<number>, eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener, setLastSyncedBlock: (lastSyncedBlock: number) => Promise<void>): Promise<void>;
    /**
     * GenerateShield populated transaction
     * @returns Populated transaction
     */
    generateShield(shieldRequests: ShieldRequestStruct[]): Promise<ContractTransaction>;
    /**
     * Create transaction call for ETH
     * @param transactions - serialized railgun transaction
     * @returns - populated ETH transaction
     */
    generateTransact(transactions: TransactionStruct[]): Promise<ContractTransaction>;
    hashCommitment(commitment: CommitmentPreimageStruct): Promise<string>;
    /**
     * Remove all listeners and shutdown contract instance
     */
    unload(): Promise<void>;
}
