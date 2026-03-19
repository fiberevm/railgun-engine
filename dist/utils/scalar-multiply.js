"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scalarMultiplyJavascript = exports.scalarMultiplyWasmFallbackToJavascript = exports.initCurve25519Promise = void 0;
const ed25519_1 = require("@noble/ed25519");
const utils_1 = require("ethereum-cryptography/utils");
const debugger_1 = __importDefault(require("../debugger/debugger"));
const bytes_1 = require("./bytes");
const runtime_1 = require("./runtime");
const { default: initCurve25519wasm, scalarMultiply: scalarMultiplyWasm } = 
// eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
(runtime_1.isReactNative ? {} : require('@railgun-community/curve25519-scalarmult-wasm'));
const initCurve25519Wasm = () => {
    try {
        // Try WASM implementation.
        return typeof initCurve25519wasm === 'function' ? initCurve25519wasm() : Promise.resolve();
    }
    catch (cause) {
        if (!(cause instanceof Error)) {
            throw new Error('Non-error thrown from initCurve25519Wasm', { cause });
        }
        // Fallback to Javascript. No init needed.
        debugger_1.default.log('curve25519-scalarmult-wasm init failed: Fallback to JavaScript');
        debugger_1.default.error(cause);
        return Promise.resolve();
    }
};
exports.initCurve25519Promise = initCurve25519Wasm();
const scalarMultiplyWasmFallbackToJavascript = (point, scalar) => {
    if (runtime_1.isReactNative || !scalarMultiplyWasm) {
        // Fallback to JavaScript if this module is running directly in React Native
        return (0, exports.scalarMultiplyJavascript)(point, scalar);
    }
    try {
        // Try WASM implementation.
        const scalarUint8Array = bytes_1.ByteUtils.nToBytes(scalar, bytes_1.ByteLength.UINT_256);
        return scalarMultiplyWasm(point, scalarUint8Array);
    }
    catch (cause) {
        if (!(cause instanceof Error)) {
            throw new Error('Non-error thrown from scalarMultiplyWasmFallbackToJavascript', { cause });
        }
        if (cause.message.includes('invalid y coordinate')) {
            // Noble/ed25519 would also throw this error, so no need to call Noble
            throw new Error('scalarMultiply failed', { cause });
        }
        // Fallback to Javascript.
        debugger_1.default.log('curve25519-scalarmult-wasm scalarMultiply failed: Fallback to JavaScript');
        debugger_1.default.error(cause);
        return (0, exports.scalarMultiplyJavascript)(point, scalar);
    }
};
exports.scalarMultiplyWasmFallbackToJavascript = scalarMultiplyWasmFallbackToJavascript;
const scalarMultiplyJavascript = (point, scalar) => {
    const pk = ed25519_1.Point.fromHex((0, utils_1.bytesToHex)(point));
    return pk.multiply(scalar).toRawBytes();
};
exports.scalarMultiplyJavascript = scalarMultiplyJavascript;
//# sourceMappingURL=scalar-multiply.js.map