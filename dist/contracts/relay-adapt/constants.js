"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2 = void 0;
// A low (or undefined) gas limit can cause the Relay Adapt module to fail.
// Set a high default that can be overridden by a developer.
exports.MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2 = BigInt(3_200_000);
//# sourceMappingURL=constants.js.map