/**
 * JSON.stringify does not handle bigint values out-of-the-box.
 * This handler will safely stringify bigints into decimal strings.
 */
export declare const stringifySafe: (obj: object) => string;
