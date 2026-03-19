"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProgressService = void 0;
const promises_1 = require("../utils/promises");
class ProgressService {
    startValue;
    endValue;
    totalMsec;
    delayMsec;
    stopped = false;
    constructor(startValue, endValue, totalMsec, delayMsec) {
        this.startValue = startValue;
        this.endValue = endValue;
        this.totalMsec = totalMsec;
        this.delayMsec = delayMsec;
    }
    /**
     * Calls progressCallback once every delayMsec msec.
     * Progresses linearly between startValue and endValue, until stop() is called.
     */
    async progressSteadily(progressCallback, iteration = 0) {
        if (this.stopped) {
            return;
        }
        const numTotalIterations = this.totalMsec / this.delayMsec;
        const currentValue = this.startValue + (iteration / numTotalIterations) * (this.endValue - this.startValue);
        if (currentValue > this.endValue) {
            return;
        }
        progressCallback(currentValue);
        await (0, promises_1.delay)(this.delayMsec);
        await this.progressSteadily(progressCallback, iteration + 1);
    }
    stop() {
        this.stopped = true;
    }
}
exports.ProgressService = ProgressService;
//# sourceMappingURL=progress-service.js.map