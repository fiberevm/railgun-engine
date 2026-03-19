import { EncryptedNoteAnnotationData, NoteAnnotationData, OutputType, SenderAnnotationDecrypted } from '../models/formatted-types';
export declare const LEGACY_MEMO_METADATA_BYTE_CHUNKS = 2;
export declare class Memo {
    static decryptNoteAnnotationData(annotationData: string, viewingPrivateKey: Uint8Array): Optional<NoteAnnotationData>;
    static decryptSenderCiphertextV3(senderCiphertext: string, viewingPrivateKey: Uint8Array, transactCommitmentBatchIndex: number): Optional<SenderAnnotationDecrypted>;
    static decryptSenderRandom: (annotationData: string, viewingPrivateKey: Uint8Array) => string;
    private static decodeWalletSource;
    static createEncryptedNoteAnnotationDataV2(outputType: OutputType, senderRandom: string, walletSource: string, viewingPrivateKey: Uint8Array): EncryptedNoteAnnotationData;
    static createSenderAnnotationEncryptedV3(walletSource: string, orderedOutputTypes: OutputType[], viewingPrivateKey: Uint8Array): EncryptedNoteAnnotationData;
    static encodeMemoText(memoText: Optional<string>): string;
    static decodeMemoText(encoded: string): Optional<string>;
}
