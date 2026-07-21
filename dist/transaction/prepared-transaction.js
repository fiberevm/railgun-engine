"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deserializePreparedRailgunTransactionV2 = exports.serializePreparedRailgunTransactionV2 = exports.assertPreparedRailgunTransactionV2 = void 0;
const poi_types_1 = require("../models/poi-types");
const note_util_1 = require("../note/note-util");
const bytes_1 = require("../utils/bytes");
const bound_params_1 = require("./bound-params");
const PREPARED_TRANSACTION_FORMAT = 'railgun-prepared-transaction';
const PREPARED_TRANSACTION_FORMAT_VERSION = 1;
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const assertExactKeys = (value, expectedKeys, field) => {
    const actualKeys = Object.keys(value).sort();
    const sortedExpectedKeys = [...expectedKeys].sort();
    if (actualKeys.length !== sortedExpectedKeys.length ||
        actualKeys.some((key, index) => key !== sortedExpectedKeys[index])) {
        throw new Error(`${field} has invalid fields.`);
    }
};
const encodeValue = (value, field) => {
    if (value === null)
        return { type: 'null' };
    if (typeof value === 'boolean')
        return { type: 'boolean', value };
    if (typeof value === 'string')
        return { type: 'string', value };
    if (typeof value === 'bigint')
        return { type: 'bigint', value: value.toString(10) };
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) {
            throw new Error(`${field} contains a non-integer or unsafe number.`);
        }
        return { type: 'number', value };
    }
    if (value instanceof Uint8Array) {
        return { type: 'bytes', value: bytes_1.ByteUtils.fastBytesToHex(value) };
    }
    if (Array.isArray(value)) {
        return {
            type: 'array',
            value: value.map((entry, index) => encodeValue(entry, `${field}[${index}]`)),
        };
    }
    if (isRecord(value)) {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
            throw new Error(`${field} contains a non-plain object.`);
        }
        return {
            type: 'object',
            value: Object.keys(value)
                .sort()
                .map((key) => [key, encodeValue(value[key], `${field}.${key}`)]),
        };
    }
    throw new Error(`${field} contains an unsupported value.`);
};
const decodeValue = (encoded, field) => {
    if (!isRecord(encoded) || typeof encoded.type !== 'string') {
        throw new Error(`${field} is not a valid encoded value.`);
    }
    switch (encoded.type) {
        case 'null':
            assertExactKeys(encoded, ['type'], field);
            return null;
        case 'boolean':
            assertExactKeys(encoded, ['type', 'value'], field);
            if (typeof encoded.value !== 'boolean')
                throw new Error(`${field}.value is invalid.`);
            return encoded.value;
        case 'number':
            assertExactKeys(encoded, ['type', 'value'], field);
            if (typeof encoded.value !== 'number' || !Number.isSafeInteger(encoded.value)) {
                throw new Error(`${field}.value is invalid.`);
            }
            return encoded.value;
        case 'string':
            assertExactKeys(encoded, ['type', 'value'], field);
            if (typeof encoded.value !== 'string')
                throw new Error(`${field}.value is invalid.`);
            return encoded.value;
        case 'bigint':
            assertExactKeys(encoded, ['type', 'value'], field);
            if (typeof encoded.value !== 'string' || !/^-?(0|[1-9][0-9]*)$/.test(encoded.value)) {
                throw new Error(`${field}.value is not a canonical bigint.`);
            }
            return BigInt(encoded.value);
        case 'bytes':
            assertExactKeys(encoded, ['type', 'value'], field);
            if (typeof encoded.value !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(encoded.value)) {
                throw new Error(`${field}.value is not canonical bytes.`);
            }
            return bytes_1.ByteUtils.fastHexToBytes(encoded.value);
        case 'array':
            assertExactKeys(encoded, ['type', 'value'], field);
            if (!Array.isArray(encoded.value))
                throw new Error(`${field}.value is invalid.`);
            return encoded.value.map((entry, index) => decodeValue(entry, `${field}[${index}]`));
        case 'object': {
            assertExactKeys(encoded, ['type', 'value'], field);
            if (!Array.isArray(encoded.value))
                throw new Error(`${field}.value is invalid.`);
            const result = {};
            const seenKeys = new Set();
            for (const [index, entry] of encoded.value.entries()) {
                if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') {
                    throw new Error(`${field}.value[${index}] is invalid.`);
                }
                const [key, child] = entry;
                if (seenKeys.has(key))
                    throw new Error(`${field} contains duplicate key ${key}.`);
                seenKeys.add(key);
                Object.defineProperty(result, key, {
                    value: decodeValue(child, `${field}.${key}`),
                    enumerable: true,
                    configurable: true,
                    writable: true,
                });
            }
            return result;
        }
        default:
            throw new Error(`${field}.type is unsupported.`);
    }
};
const assertBigIntArray = (value, field) => {
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'bigint')) {
        throw new Error(`${field} must be a bigint array.`);
    }
};
const assertPreparedRailgunTransactionV2 = (value) => {
    if (!isRecord(value))
        throw new Error('Prepared transaction must be an object.');
    assertExactKeys(value, ['txidVersion', 'privateInputs', 'publicInputs', 'boundParams', 'unshieldPreimage'], 'preparedTransaction');
    if (value.txidVersion !== poi_types_1.TXIDVersion.V2_PoseidonMerkle) {
        throw new Error('Prepared transaction must use V2_PoseidonMerkle.');
    }
    if (!isRecord(value.privateInputs))
        throw new Error('privateInputs must be an object.');
    assertExactKeys(value.privateInputs, [
        'tokenAddress',
        'randomIn',
        'valueIn',
        'pathElements',
        'leavesIndices',
        'valueOut',
        'publicKey',
        'npkOut',
        'nullifyingKey',
    ], 'privateInputs');
    if (typeof value.privateInputs.tokenAddress !== 'bigint' ||
        typeof value.privateInputs.nullifyingKey !== 'bigint') {
        throw new Error('privateInputs scalar fields must be bigints.');
    }
    assertBigIntArray(value.privateInputs.randomIn, 'privateInputs.randomIn');
    assertBigIntArray(value.privateInputs.valueIn, 'privateInputs.valueIn');
    assertBigIntArray(value.privateInputs.leavesIndices, 'privateInputs.leavesIndices');
    assertBigIntArray(value.privateInputs.valueOut, 'privateInputs.valueOut');
    assertBigIntArray(value.privateInputs.publicKey, 'privateInputs.publicKey');
    assertBigIntArray(value.privateInputs.npkOut, 'privateInputs.npkOut');
    if (!Array.isArray(value.privateInputs.pathElements) ||
        value.privateInputs.pathElements.some((path) => {
            try {
                assertBigIntArray(path, 'privateInputs.pathElements');
                return false;
            }
            catch {
                return true;
            }
        })) {
        throw new Error('privateInputs.pathElements must be a bigint matrix.');
    }
    if (!isRecord(value.publicInputs))
        throw new Error('publicInputs must be an object.');
    assertExactKeys(value.publicInputs, ['merkleRoot', 'boundParamsHash', 'nullifiers', 'commitmentsOut'], 'publicInputs');
    if (typeof value.publicInputs.merkleRoot !== 'bigint' ||
        typeof value.publicInputs.boundParamsHash !== 'bigint') {
        throw new Error('publicInputs scalar fields must be bigints.');
    }
    assertBigIntArray(value.publicInputs.nullifiers, 'publicInputs.nullifiers');
    assertBigIntArray(value.publicInputs.commitmentsOut, 'publicInputs.commitmentsOut');
    if (!isRecord(value.boundParams))
        throw new Error('boundParams must be an object.');
    assertExactKeys(value.boundParams, [
        'treeNumber',
        'minGasPrice',
        'unshield',
        'chainID',
        'adaptContract',
        'adaptParams',
        'commitmentCiphertext',
    ], 'boundParams');
    if (typeof value.boundParams.treeNumber !== 'number' ||
        typeof value.boundParams.minGasPrice !== 'bigint' ||
        typeof value.boundParams.unshield !== 'bigint' ||
        typeof value.boundParams.chainID !== 'string' ||
        typeof value.boundParams.adaptContract !== 'string' ||
        typeof value.boundParams.adaptParams !== 'string' ||
        !Array.isArray(value.boundParams.commitmentCiphertext)) {
        throw new Error('boundParams contains invalid V2 fields.');
    }
    if (!isRecord(value.unshieldPreimage)) {
        throw new Error('unshieldPreimage must be an object.');
    }
    assertExactKeys(value.unshieldPreimage, ['npk', 'token', 'value'], 'unshieldPreimage');
    if (!(typeof value.unshieldPreimage.npk === 'string' ||
        value.unshieldPreimage.npk instanceof Uint8Array) ||
        typeof value.unshieldPreimage.value !== 'bigint' ||
        !isRecord(value.unshieldPreimage.token)) {
        throw new Error('unshieldPreimage contains invalid fields.');
    }
    assertExactKeys(value.unshieldPreimage.token, ['tokenType', 'tokenAddress', 'tokenSubID'], 'unshieldPreimage.token');
    if (typeof value.unshieldPreimage.token.tokenType !== 'number' ||
        typeof value.unshieldPreimage.token.tokenAddress !== 'string' ||
        typeof value.unshieldPreimage.token.tokenSubID !== 'string') {
        throw new Error('unshieldPreimage.token contains invalid fields.');
    }
    const preparedTransaction = value;
    if ((0, bound_params_1.hashBoundParamsV2)(preparedTransaction.boundParams) !==
        preparedTransaction.publicInputs.boundParamsHash) {
        throw new Error('Prepared transaction boundParamsHash mismatch.');
    }
    if (preparedTransaction.boundParams.unshield !== 0n) {
        const npk = typeof preparedTransaction.unshieldPreimage.npk === 'string'
            ? preparedTransaction.unshieldPreimage.npk
            : bytes_1.ByteUtils.fastBytesToHex(preparedTransaction.unshieldPreimage.npk);
        const unshieldCommitment = (0, note_util_1.getNoteHash)(npk, (0, note_util_1.serializeTokenData)(preparedTransaction.unshieldPreimage.token.tokenAddress.toString(), BigInt(preparedTransaction.unshieldPreimage.token.tokenType.toString()), preparedTransaction.unshieldPreimage.token.tokenSubID.toString()), BigInt(preparedTransaction.unshieldPreimage.value.toString()));
        if (preparedTransaction.publicInputs.commitmentsOut.at(-1) !== unshieldCommitment) {
            throw new Error('Prepared transaction unshield commitment mismatch.');
        }
    }
};
exports.assertPreparedRailgunTransactionV2 = assertPreparedRailgunTransactionV2;
/** Produces stable JSON for KMS encryption. Plaintext includes private proof witness data. */
const serializePreparedRailgunTransactionV2 = (preparedTransaction) => {
    (0, exports.assertPreparedRailgunTransactionV2)(preparedTransaction);
    const envelope = {
        format: PREPARED_TRANSACTION_FORMAT,
        version: PREPARED_TRANSACTION_FORMAT_VERSION,
        transaction: encodeValue(preparedTransaction, 'preparedTransaction'),
    };
    return JSON.stringify(envelope);
};
exports.serializePreparedRailgunTransactionV2 = serializePreparedRailgunTransactionV2;
/** Restores and validates a V2 witness. Corrupt or semantically inconsistent payloads fail closed. */
const deserializePreparedRailgunTransactionV2 = (serialized) => {
    let parsed;
    try {
        parsed = JSON.parse(serialized);
    }
    catch (cause) {
        throw new Error('Prepared transaction payload is not valid JSON.', {
            cause: cause,
        });
    }
    if (!isRecord(parsed))
        throw new Error('Prepared transaction envelope must be an object.');
    assertExactKeys(parsed, ['format', 'version', 'transaction'], 'preparedTransactionEnvelope');
    if (parsed.format !== PREPARED_TRANSACTION_FORMAT ||
        parsed.version !== PREPARED_TRANSACTION_FORMAT_VERSION) {
        throw new Error('Prepared transaction envelope version is unsupported.');
    }
    const preparedTransaction = decodeValue(parsed.transaction, 'preparedTransaction');
    (0, exports.assertPreparedRailgunTransactionV2)(preparedTransaction);
    return preparedTransaction;
};
exports.deserializePreparedRailgunTransactionV2 = deserializePreparedRailgunTransactionV2;
//# sourceMappingURL=prepared-transaction.js.map