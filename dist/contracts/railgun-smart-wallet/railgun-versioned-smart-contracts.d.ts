import { ContractTransaction } from 'ethers';
import { ShieldRequestStruct, TokenDataStructOutput } from '../../abi/typechain/RailgunSmartWallet';
import { EventsCommitmentListener, EventsNullifierListener, EventsRailgunTransactionListenerV3, EventsUnshieldListener, HistoricalEventsScanOptions } from '../../models/event-types';
import { Chain } from '../../models/engine-types';
import { TXIDVersion } from '../../models/poi-types';
import { TransactionStructV2, TransactionStructV3 } from '../../models/transaction-types';
export declare class RailgunVersionedSmartContracts {
    private static zeroUnshieldChangeCiphertext;
    static getAccumulator(txidVersion: TXIDVersion, chain: Chain): import(".").RailgunSmartWalletContract | import("./V3/poseidon-merkle-accumulator").PoseidonMerkleAccumulatorContract;
    static getVerifier(txidVersion: TXIDVersion, chain: Chain): import(".").RailgunSmartWalletContract | import("./V3/poseidon-merkle-verifier").PoseidonMerkleVerifierContract;
    static getShieldApprovalContract(txidVersion: TXIDVersion, chain: Chain): import(".").RailgunSmartWalletContract | import("./V3/token-vault-contract").TokenVaultContract;
    static getRelayAdaptContract(txidVersion: TXIDVersion, chain: Chain): import("../relay-adapt/V2/relay-adapt-v2").RelayAdaptV2Contract | import("../relay-adapt/V3/relay-adapt-v3").RelayAdaptV3Contract;
    static getHistoricalEvents(txidVersion: TXIDVersion, chain: Chain, initialStartBlock: number, latestBlock: number, getNextStartBlockFromValidMerkletree: () => Promise<number>, eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener, eventsRailgunTransactionsV3Listener: EventsRailgunTransactionListenerV3, setLastSyncedBlock: (lastSyncedBlock: number) => Promise<void>, options?: HistoricalEventsScanOptions): Promise<void>;
    static setTreeUpdateListeners(txidVersion: TXIDVersion, chain: Chain, eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener, eventsRailgunTransactionsV3Listener: EventsRailgunTransactionListenerV3, triggerWalletBalanceDecryptions: (txidVersion: TXIDVersion) => Promise<void>): Promise<void>;
    static fees(txidVersion: TXIDVersion, chain: Chain): Promise<{
        shield: bigint;
        unshield: bigint;
    }>;
    static getNFTTokenData(txidVersion: TXIDVersion, chain: Chain, tokenHash: string): Promise<TokenDataStructOutput>;
    static generateShield(txidVersion: TXIDVersion, chain: Chain, shieldRequests: ShieldRequestStruct[]): Promise<ContractTransaction>;
    static generateTransact(txidVersion: TXIDVersion, chain: Chain, transactions: (TransactionStructV2 | TransactionStructV3)[]): Promise<ContractTransaction>;
    private static convertToV3TransactStructs;
}
