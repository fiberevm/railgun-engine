import { Result } from 'ethers';
import { AccumulatorStateUpdateEvent } from '../../../abi/typechain/PoseidonMerkleAccumulator';
import { CommitmentEvent, EventsCommitmentListener, EventsNullifierListener, EventsRailgunTransactionListenerV3, EventsUnshieldListener, UnshieldStoredEvent } from '../../../models/event-types';
import { CommitmentCiphertextV3, Nullifier, RailgunTransactionV3 } from '../../../models/formatted-types';
import { TXIDVersion } from '../../../models/poi-types';
export declare class V3Events {
    static formatTransactEvent(transactionHash: string, blockNumber: number, commitmentHashes: string[], commitmentCiphertexts: {
        ciphertext: string;
        blindedSenderViewingKey: string;
        blindedReceiverViewingKey: string;
    }[], utxoTree: number, utxoStartingIndex: number, transactIndex: number, senderCiphertext: string, railgunTxid: string): CommitmentEvent;
    private static formatTransactCommitments;
    static formatCommitmentCiphertext(commitmentCiphertext: {
        ciphertext: string;
        blindedSenderViewingKey: string;
        blindedReceiverViewingKey: string;
    }): CommitmentCiphertextV3;
    static formatUnshieldEvent(transactionHash: string, blockNumber: number, unshieldPreimage: {
        npk: string;
        token: {
            tokenAddress: string;
            tokenType: bigint;
            tokenSubID: bigint;
        };
        value: bigint;
    }, transactIndex: number, fee: bigint, railgunTxid: string): UnshieldStoredEvent;
    static formatNullifiedEvents(transactionHash: string, blockNumber: number, spendAccumulatorNumber: number, nullifierHashes: string[]): Nullifier[];
    static formatRailgunTransactionEvent(transactionHash: string, blockNumber: number, commitments: string[], nullifiers: string[], unshieldPreimage: {
        npk: string;
        token: {
            tokenAddress: string;
            tokenType: bigint;
            tokenSubID: bigint;
        };
        value: bigint;
    }, boundParamsHash: string, utxoTreeIn: number, utxoTree: number, utxoBatchStartPosition: number, verificationHash: Optional<string>): RailgunTransactionV3;
    static formatShieldEvent(transactionHash: string, blockNumber: number, from: string, shieldPreImage: {
        npk: string;
        token: {
            tokenAddress: string;
            tokenType: bigint;
            tokenSubID: bigint;
        };
        value: bigint;
    }, shieldCiphertext: {
        encryptedBundle: [string, string, string];
        shieldKey: string;
    }, utxoTree: number, utxoIndex: number, fee: bigint): CommitmentEvent;
    private static formatShieldCommitment;
    static processAccumulatorUpdateEvents(txidVersion: TXIDVersion, logs: AccumulatorStateUpdateEvent.Log[], eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener, eventsRailgunTransactionsV3Listener: EventsRailgunTransactionListenerV3): Promise<void>;
    static processAccumulatorEvent(txidVersion: TXIDVersion, args: Result, transactionHash: string, blockNumber: number, eventsCommitmentListener: EventsCommitmentListener, eventsNullifierListener: EventsNullifierListener, eventsUnshieldListener: EventsUnshieldListener, eventsRailgunTransactionsV3Listener: EventsRailgunTransactionListenerV3, triggerWalletBalanceDecryptions: (txidVersion: TXIDVersion) => Promise<void>): Promise<void>;
}
