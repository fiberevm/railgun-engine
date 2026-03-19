/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import type { AbstractBatch, AbstractLevelDOWN } from 'abstract-leveldown';
import type { LevelUp } from 'levelup';
import EventEmitter from 'events';
import { BytesData } from '../models/formatted-types';
export type Encoding = 'utf8' | 'json' | 'binary' | 'hex' | 'ascii' | 'base64' | 'ucs2' | 'utf16le' | 'utf-16le';
export declare enum DatabaseNamespace {
    ChainSyncInfo = "chain_sync_info"
}
type Path = BytesData[];
/** These properties exist on the level-js instance in the browser. */
type LevelWithIndexedDB = {
    db: {
        db: {
            location: string;
            db: IDBDatabase;
        };
        codec: {
            encodings: Record<string, {
                decode: (value: ArrayBuffer) => any;
            }>;
        };
    };
};
type MaybeIndexedDB = {
    [Key1 in keyof LevelWithIndexedDB]?: {
        [Key2 in keyof LevelWithIndexedDB[Key1]]?: LevelWithIndexedDB[Key1][Key2];
    };
};
/** Database class */
declare class Database {
    readonly level: LevelUp & MaybeIndexedDB;
    private isClearingNamespace;
    /**
     * Create a Database object from levelDB store
     * @param leveldown - abstract-leveldown compatible store
     */
    constructor(leveldown: AbstractLevelDOWN);
    isClosed(): boolean;
    private usesIndexedDB;
    private getIndexedDBStore;
    /**
     * Parses path and returns key
     * @param path - path to convert
     * @returns key
     */
    static pathToKey(path: Path): string;
    /**
     * Set value in database
     * @param path - database path
     * @param value - value to set
     * @param encoding - data encoding to use
     * @returns complete
     */
    put(path: Path, value: any, encoding?: Encoding): Promise<void>;
    /**
     * Get value from database
     * @param path - database path
     * @param encoding - data encoding to use
     * @returns value
     */
    get(path: Path, encoding?: Encoding): Promise<any>;
    /**
     * Delete value from database
     * @param path - database path
     * @param encoding - data encoding to use
     * @returns complete
     */
    del(path: Path, encoding?: Encoding): Promise<void>;
    /**
     * Perform batch operation on database
     * @param ops - operations to perform
     * @param encoding - data encoding to use
     * @returns complete
     */
    batch(ops: AbstractBatch[], encoding?: Encoding): Promise<void>;
    /**
     * Set encrypted value in database
     * @param path - database path
     * @param encryptionKey - AES-256-GCM encryption key
     * @param value - value to encrypt and set
     */
    putEncrypted(path: Path, encryptionKey: string, value: string | Buffer): Promise<void>;
    /**
     * Get encrypted value in database
     * @param path - database path
     * @param encryptionKey - AES-256-GCM  encryption key
     * @return decrypted value
     */
    getEncrypted(path: Path, encryptionKey: string): Promise<string>;
    /**
     * @param value - value to decode
     * @param encoding - data encoding to use
     */
    private decode;
    /**
     * Gets stream of keys and/or values in namespace
     * @param namespace - namespace to stream from
     * @param keys - whether or not to include keys in results (default true)
     * @param values - whether or not to include values in results (default false)
     * @returns namespace "Emitter" stream
     */
    streamNamespace(namespace: string[], keys?: boolean, values?: boolean): NodeJS.ReadableStream;
    /**
     * Gets stream of values in range between two keys
     * @param start - start path (inclusive)
     * @param end - end path (inclusive)
     * @param encoding - data encoding to use
     * @returns namespace "Emitter" stream
     */
    streamRange(start: Path, end: Path, encoding?: Encoding): EventEmitter;
    /**
     * Gets all keys in namespace
     * @param namespace - namespace to stream from
     * @returns list of keys
     */
    getNamespaceKeys(namespace: string[]): Promise<string[]>;
    /**
     * Delete all keys in namespace
     * @param namespace - namespace to delete
     * @returns complete
     */
    clearNamespace(namespace: string[]): Promise<void>;
    /**
     * Counnts number of keys in namespace
     * @param namespace - namespace to count keys in
     * @returns number of keys in namespace
     */
    countNamespace(namespace: string[]): Promise<number>;
    /**
     * Closes DB connections and cleans up listeners
     */
    close(): Promise<void>;
}
export { Database };
