"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class EngineDebug {
    static engineDebugger;
    static init(engineDebugger) {
        this.engineDebugger = engineDebugger;
    }
    static log(msg) {
        if (this.engineDebugger) {
            this.engineDebugger.log(msg);
        }
    }
    static error(err, ignoreInTests = false) {
        if (this.engineDebugger) {
            this.engineDebugger.error(err);
        }
        if (this.isTestRun() && !ignoreInTests) {
            // eslint-disable-next-line no-console
            console.error(err);
        }
    }
    static isTestRun() {
        return process.env.NODE_ENV === 'test';
    }
    static verboseScanLogging() {
        return this.engineDebugger?.verboseScanLogging ?? false;
    }
}
exports.default = EngineDebug;
//# sourceMappingURL=debugger.js.map