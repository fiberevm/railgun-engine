"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.poseidonHex = exports.poseidon = exports.initPoseidonPromise = void 0;
const circomlibjs_1 = __importDefault(require("@railgun-community/circomlibjs"));
const debugger_1 = __importDefault(require("../debugger/debugger"));
const bytes_1 = require("./bytes");
const runtime_1 = require("./runtime");
const { default: initPoseidonWasm, poseidon: poseidonWasm, poseidonHex: poseidonHexWasm } = 
// eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
(runtime_1.isReactNative ? {} : require('@railgun-community/poseidon-hash-wasm'));
const initPoseidon = () => {
    try {
        // Try WASM implementation.
        return typeof initPoseidonWasm === 'function' ? initPoseidonWasm() : Promise.resolve();
    }
    catch (cause) {
        if (!(cause instanceof Error)) {
            throw new Error('Non-error thrown from initPoseidon', { cause });
        }
        // Fallback to Javascript. No init needed.
        debugger_1.default.log('poseidon-hash-wasm init failed: Fallback to JavaScript');
        debugger_1.default.error(cause);
        return Promise.resolve();
    }
};
exports.initPoseidonPromise = initPoseidon();
const poseidon = (args) => {
    if (runtime_1.isReactNative || !poseidonWasm) {
        // Fallback to JavaScript if this module is running directly in React Native
        return circomlibjs_1.default.poseidon(args);
    }
    try {
        // Try WASM implementation.
        return poseidonWasm(args);
    }
    catch (cause) {
        if (!(cause instanceof Error)) {
            throw new Error('Non-error thrown from poseidon', { cause });
        }
        // Fallback to Javascript.
        debugger_1.default.log('poseidon in WASM failed: Fallback to JavaScript');
        debugger_1.default.error(cause);
        return circomlibjs_1.default.poseidon(args);
    }
};
exports.poseidon = poseidon;
const poseidonHex = (args) => {
    if (runtime_1.isReactNative || !poseidonHexWasm) {
        return bytes_1.ByteUtils.nToHex(circomlibjs_1.default.poseidon(args.map((x) => bytes_1.ByteUtils.hexToBigInt(x))), bytes_1.ByteLength.UINT_256);
    }
    try {
        // We need to strip 0x prefix from hex strings before passing to WASM,
        // however, let's first make sure we actually need to do this, to avoid
        // creating an unnecessary copy of the array (via `map`)
        const needsStripping = args.some((arg) => arg.startsWith('0x'));
        const strippedArgs = needsStripping ? args.map((x) => bytes_1.ByteUtils.strip0x(x)) : args;
        return bytes_1.ByteUtils.padToLength(poseidonHexWasm(strippedArgs), bytes_1.ByteLength.UINT_256);
    }
    catch (cause) {
        if (!(cause instanceof Error)) {
            throw new Error('Non-error thrown from poseidonHex', { cause });
        }
        // Fallback to Javascript.
        debugger_1.default.log('poseidonHex in WASM failed: Fallback to JavaScript');
        debugger_1.default.error(cause);
        return bytes_1.ByteUtils.nToHex(circomlibjs_1.default.poseidon(args.map((x) => bytes_1.ByteUtils.hexToBigInt(x))), bytes_1.ByteLength.UINT_256);
    }
};
exports.poseidonHex = poseidonHex;
//# sourceMappingURL=poseidon.js.map