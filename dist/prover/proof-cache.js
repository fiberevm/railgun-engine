"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofCache = void 0;
const debugger_1 = __importDefault(require("../debugger/debugger"));
const stringify_1 = require("../utils/stringify");
class ProofCache {
    static cache = new Map();
    static get(transactionRequest) {
        try {
            const stringified = (0, stringify_1.stringifySafe)(transactionRequest);
            return ProofCache.cache.get(stringified);
        }
        catch (err) {
            if (err instanceof Error) {
                debugger_1.default.error(err);
            }
            return undefined;
        }
    }
    static store(transactionRequest, proof) {
        try {
            const stringified = (0, stringify_1.stringifySafe)(transactionRequest);
            ProofCache.cache.set(stringified, proof);
        }
        catch (err) {
            if (err instanceof Error) {
                debugger_1.default.error(err);
            }
        }
    }
}
exports.ProofCache = ProofCache;
//# sourceMappingURL=proof-cache.js.map