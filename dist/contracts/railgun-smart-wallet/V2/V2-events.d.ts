import { CommitmentCiphertextV2, Nullifier } from '../../../models/formatted-types';
import { CommitmentEvent, EventsCommitmentListener, EventsNullifierListener, EventsUnshieldListener, UnshieldStoredEvent } from '../../../models/event-types';
import { CommitmentCiphertextStructOutput, NullifiedEvent, ShieldEvent, TransactEvent, UnshieldEvent } from '../../../abi/typechain/RailgunSmartWallet';
import { ShieldEvent as ShieldEvent_LegacyShield_PreMar23 } from '../../../abi/typechain/RailgunSmartWallet_Legacy_PreMar23';
import { TXIDVersion } from '../../../models/poi-types';
export declare class V2Events {
    private static formatShieldCommitments;
    static formatShieldEvent(shieldEventArgs: ShieldEvent.OutputObject | ShieldEvent_LegacyShield_PreMar23.OutputObject, transactionHash: string, blockNumber: number, fees: Optional<bigint[]>, timestamp: Optional<number>): CommitmentEvent;
    static formatCommitmentCiphertext(commitmentCiphertext: CommitmentCiphertextStructOutput): CommitmentCiphertextV2;
    private static formatTransactCommitments;
    static formatTransactEvent(transactEventArgs: TransactEvent.OutputObject, transactionHash: string, blockNumber: number, timestamp: Optional<number>): CommitmentEvent;
    static formatUnshieldEvent(unshieldEventArgs: UnshieldEvent.OutputObject, transactionHash: string, blockNumber: number, eventLogIndex: number, timestamp: Optional<number>): UnshieldStoredEvent;
    static processShieldEvents(txidVersion: TXIDVersion, eventsListener: EventsCommitmentListener, logs: ShieldEvent.Log[]): Promise<void>;
    static processShieldEvents_LegacyShield_PreMar23(txidVersion: TXIDVersion, eventsListener: EventsCommitmentListener, logs: ShieldEvent_LegacyShield_PreMar23.Log[]): Promise<void>;
    static processTransactEvents(txidVersion: TXIDVersion, eventsListener: EventsCommitmentListener, logs: TransactEvent.Log[]): Promise<void>;
    static processUnshieldEvents(txidVersion: TXIDVersion, eventsUnshieldListener: EventsUnshieldListener, logs: UnshieldEvent.Log[]): Promise<void>;
    static formatNullifiedEvents(nullifierEventArgs: NullifiedEvent.OutputObject, transactionHash: string, blockNumber: number): Nullifier[];
    static processNullifiedEvents(txidVersion: TXIDVersion, eventsNullifierListener: EventsNullifierListener, logs: NullifiedEvent.Log[]): Promise<void>;
}
