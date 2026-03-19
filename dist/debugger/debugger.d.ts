import { EngineDebugger } from '../models/engine-types';
export default class EngineDebug {
    private static engineDebugger;
    static init(engineDebugger: EngineDebugger): void;
    static log(msg: string): void;
    static error(err: Error, ignoreInTests?: boolean): void;
    static isTestRun(): boolean;
    static verboseScanLogging(): boolean;
}
