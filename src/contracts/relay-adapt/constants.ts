// A low (or undefined) gas limit can cause the Relay Adapt module to fail.
// Set a high default that can be overridden by a developer.
export const MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2 = BigInt(3_200_000);

// RelayAdapt checks gas after decoding and entering relay(), so bind the lower in-contract floor
// while the submitted transaction keeps the established 150k dispatch allowance.
export const RELAY_ADAPT_ACTION_MIN_GAS_LIMIT_V2 =
  MINIMUM_RELAY_ADAPT_CROSS_CONTRACT_CALLS_GAS_LIMIT_V2 - 150_000n;
