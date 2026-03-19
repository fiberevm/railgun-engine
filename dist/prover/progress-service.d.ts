export declare class ProgressService {
    private startValue;
    private endValue;
    private totalMsec;
    private delayMsec;
    private stopped;
    constructor(startValue: number, endValue: number, totalMsec: number, delayMsec: number);
    /**
     * Calls progressCallback once every delayMsec msec.
     * Progresses linearly between startValue and endValue, until stop() is called.
     */
    progressSteadily(progressCallback: (progress: number) => void, iteration?: number): Promise<void>;
    stop(): void;
}
