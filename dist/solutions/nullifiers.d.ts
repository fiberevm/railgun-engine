/**
 * CIRCUITS (V2)
 *
 * Valid, currently used:
 * All circuits with 1 - 10 inputs and 1 - 5 outputs, less the 10x5 circuit
 *
 * Valid, but currently unused:
 * 11x1, 12x1, 13x1
 * 1x10, 1x13
 */
export declare const VALID_INPUT_COUNTS: number[];
export declare const VALID_OUTPUT_COUNTS: number[];
export declare const MAX_INPUTS: number;
export declare const isValidNullifierCount: (utxoCount: number) => boolean;
