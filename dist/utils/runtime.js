"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isNodejs = exports.isReactNative = void 0;
exports.isReactNative = typeof navigator !== 'undefined' && navigator.product === 'ReactNative';
exports.isNodejs = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
//# sourceMappingURL=runtime.js.map