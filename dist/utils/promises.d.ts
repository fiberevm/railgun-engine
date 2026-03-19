export declare const delay: (delayInMS: number) => Promise<void>;
export declare function promiseTimeout<T>(promise: Promise<T>, ms: number, customError?: string): Promise<T>;
