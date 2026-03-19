"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Database = exports.DatabaseNamespace = void 0;
const encoding_down_1 = __importDefault(require("encoding-down"));
const levelup_1 = __importDefault(require("levelup"));
const events_1 = __importDefault(require("events"));
const bytes_1 = require("../utils/bytes");
const aes_1 = require("../utils/encryption/aes");
const debugger_1 = __importDefault(require("../debugger/debugger"));
var DatabaseNamespace;
(function (DatabaseNamespace) {
    DatabaseNamespace["ChainSyncInfo"] = "chain_sync_info";
})(DatabaseNamespace || (exports.DatabaseNamespace = DatabaseNamespace = {}));
/** Database class */
class Database {
    level;
    isClearingNamespace = false;
    /**
     * Create a Database object from levelDB store
     * @param leveldown - abstract-leveldown compatible store
     */
    constructor(leveldown) {
        // Create levelDB database from leveldown store
        this.level = (0, levelup_1.default)((0, encoding_down_1.default)(leveldown));
    }
    isClosed() {
        return this.level.isClosed();
    }
    usesIndexedDB() {
        return typeof indexedDB !== 'undefined' && typeof this.level.db?.db?.db !== 'undefined';
    }
    getIndexedDBStore() {
        const { location } = this.level.db.db;
        const idb = this.level.db.db.db;
        const transaction = idb.transaction([location], 'readonly');
        return transaction.objectStore(location);
    }
    /**
     * Parses path and returns key
     * @param path - path to convert
     * @returns key
     */
    static pathToKey(path) {
        // Convert to hex string, pad to 32 bytes, and join with :
        return path.map((el) => bytes_1.ByteUtils.hexlify(el).toLowerCase().padStart(64, '0')).join(':');
    }
    /**
     * Set value in database
     * @param path - database path
     * @param value - value to set
     * @param encoding - data encoding to use
     * @returns complete
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async put(path, value, encoding = 'hex') {
        try {
            if (this.isClosed()) {
                return;
            }
            if (this.isClearingNamespace) {
                debugger_1.default.log('Database is clearing a namespace - put action is dangerous');
            }
            const key = Database.pathToKey(path);
            await this.level.put(key, value, { valueEncoding: encoding });
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                return;
            }
            if (debugger_1.default.isTestRun() && cause.message.includes('Database is not open')) {
                return;
            }
            throw new Error('Failed to put value in database', { cause });
        }
    }
    /**
     * Get value from database
     * @param path - database path
     * @param encoding - data encoding to use
     * @returns value
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    get(path, encoding = 'hex') {
        const key = Database.pathToKey(path);
        return this.level.get(key, { valueEncoding: encoding });
    }
    /**
     * Delete value from database
     * @param path - database path
     * @param encoding - data encoding to use
     * @returns complete
     */
    del(path, encoding = 'hex') {
        const key = Database.pathToKey(path);
        return this.level.del(key, { valueEncoding: encoding });
    }
    /**
     * Perform batch operation on database
     * @param ops - operations to perform
     * @param encoding - data encoding to use
     * @returns complete
     */
    async batch(ops, encoding = 'hex') {
        try {
            if (this.isClosed()) {
                return;
            }
            if (this.isClearingNamespace) {
                debugger_1.default.log('Database is clearing a namespace - batch action is dangerous');
            }
            await this.level.batch(ops, { valueEncoding: encoding });
        }
        catch (cause) {
            if (!(cause instanceof Error)) {
                return;
            }
            if (debugger_1.default.isTestRun() && cause.message.includes('Database is not open')) {
                return;
            }
            throw new Error('Failed to perform batch operation on database', { cause });
        }
    }
    /**
     * Set encrypted value in database
     * @param path - database path
     * @param encryptionKey - AES-256-GCM encryption key
     * @param value - value to encrypt and set
     */
    async putEncrypted(path, encryptionKey, value) {
        // Encrypt data
        const encrypted = aes_1.AES.encryptGCM(bytes_1.ByteUtils.chunk(value), encryptionKey);
        // Write to database
        await this.put(path, encrypted, 'json');
    }
    /**
     * Get encrypted value in database
     * @param path - database path
     * @param encryptionKey - AES-256-GCM  encryption key
     * @return decrypted value
     */
    async getEncrypted(path, encryptionKey) {
        // Read from database
        const encrypted = (await this.get(path, 'json'));
        // Decrypt and return
        return bytes_1.ByteUtils.combine(aes_1.AES.decryptGCM(encrypted, encryptionKey));
    }
    /**
     * @param value - value to decode
     * @param encoding - data encoding to use
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    decode(value, encoding) {
        const { encodings } = this.level.db.codec;
        if (typeof encodings[encoding] === 'undefined')
            throw new Error(`Unknown encoding ${encoding}`);
        // Special case for decoding already-decoded JSON objects:
        if (encoding === 'json' && !ArrayBuffer.isView(value) && typeof value === 'object') {
            return value;
        }
        return encodings[encoding].decode(Buffer.from(value));
    }
    /**
     * Gets stream of keys and/or values in namespace
     * @param namespace - namespace to stream from
     * @param keys - whether or not to include keys in results (default true)
     * @param values - whether or not to include values in results (default false)
     * @returns namespace "Emitter" stream
     */
    streamNamespace(namespace, keys = true, values = false) {
        const pathkey = Database.pathToKey(namespace);
        return this.level.createReadStream({
            gte: `${pathkey}`,
            lte: `${pathkey}~`,
            keys,
            values,
        });
    }
    /**
     * Gets stream of values in range between two keys
     * @param start - start path (inclusive)
     * @param end - end path (inclusive)
     * @param encoding - data encoding to use
     * @returns namespace "Emitter" stream
     */
    streamRange(start, end, encoding = 'hex') {
        const startKey = Database.pathToKey(start);
        const endKey = Database.pathToKey(end);
        if (this.usesIndexedDB()) {
            const store = this.getIndexedDBStore();
            const lower = new TextEncoder().encode(`${startKey}`);
            const upper = new TextEncoder().encode(`${endKey}`);
            const range = IDBKeyRange.bound(lower, upper);
            const request = store.getAll(range);
            const emitter = new events_1.default();
            request.onsuccess = (ev) => {
                const values = ev.target.result;
                for (const value of values) {
                    emitter.emit('data', this.decode(value, encoding));
                }
                emitter.emit('end');
            };
            request.onerror = (ev) => {
                emitter.emit('error', ev.target.error);
            };
            return emitter;
        }
        return this.level.createReadStream({
            gte: startKey,
            lte: endKey,
            keys: false,
            values: true,
            valueEncoding: encoding,
        });
    }
    /**
     * Gets all keys in namespace
     * @param namespace - namespace to stream from
     * @returns list of keys
     */
    getNamespaceKeys(namespace) {
        return new Promise((resolve, reject) => {
            if (this.usesIndexedDB()) {
                // Web-only (IndexedDB) optimization to use getAllKeys() (fast)
                const pathkey = Database.pathToKey(namespace);
                const store = this.getIndexedDBStore();
                const lower = new TextEncoder().encode(`${pathkey}`);
                const upper = new TextEncoder().encode(`${pathkey}~`);
                const range = IDBKeyRange.bound(lower, upper);
                const request = store.getAllKeys(range);
                request.onsuccess = (ev) => {
                    const keys = ev.target.result;
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    const keysStrings = keys;
                    for (let i = 0; i < keys.length; i += 1) {
                        keysStrings[i] = new TextDecoder().decode(keys[i]);
                    }
                    resolve(keysStrings);
                };
                request.onerror = (ev) => {
                    reject(ev.target.error);
                };
            }
            else {
                // Stream list of keys and resolve on end
                const keyList = [];
                this.streamNamespace(namespace)
                    .on('data', (key) => {
                    keyList.push(key);
                })
                    .on('end', () => {
                    resolve(keyList);
                });
            }
        });
    }
    /**
     * Delete all keys in namespace
     * @param namespace - namespace to delete
     * @returns complete
     */
    async clearNamespace(namespace) {
        try {
            this.isClearingNamespace = true;
            const pathkey = Database.pathToKey(namespace);
            debugger_1.default.log(`Clearing namespace: ${pathkey}`);
            await this.level.clear({
                gte: `${pathkey}`,
                lte: `${pathkey}~`,
            });
            this.isClearingNamespace = false;
        }
        catch (cause) {
            this.isClearingNamespace = false;
            throw new Error('Failed to clear database namespace', { cause });
        }
    }
    /**
     * Counnts number of keys in namespace
     * @param namespace - namespace to count keys in
     * @returns number of keys in namespace
     */
    countNamespace(namespace) {
        return new Promise((resolve, reject) => {
            if (this.usesIndexedDB()) {
                // Web-only (IndexedDB) optimization to use count() (fast)
                const pathkey = Database.pathToKey(namespace);
                const store = this.getIndexedDBStore();
                const lower = new TextEncoder().encode(`${pathkey}`);
                const upper = new TextEncoder().encode(`${pathkey}~`);
                const range = IDBKeyRange.bound(lower, upper);
                const request = store.count(range);
                request.onsuccess = () => {
                    resolve(request.result);
                };
                request.onerror = (ev) => {
                    reject(ev.target.error);
                };
            }
            else {
                // Stream list of keys for namespace* and counts them
                let keyNumber = 0;
                this.streamNamespace(namespace)
                    .on('data', () => {
                    // Increment keynumber
                    keyNumber += 1;
                })
                    .on('end', () => {
                    // Return keynumber
                    resolve(keyNumber);
                });
            }
        });
    }
    /**
     * Closes DB connections and cleans up listeners
     */
    async close() {
        await this.level.close();
    }
}
exports.Database = Database;
//# sourceMappingURL=database.js.map