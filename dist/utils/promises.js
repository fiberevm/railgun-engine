"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.promiseTimeout = exports.delay = void 0;
/* eslint-disable no-await-in-loop */
const delay = (delayInMS) => {
    return new Promise((resolve) => setTimeout(resolve, delayInMS));
};
exports.delay = delay;
function promiseTimeout(promise, ms, customError) {
    // Create a promise that rejects in <ms> milliseconds
    const timeout = new Promise((_resolve, reject) => {
        const id = setTimeout(() => {
            clearTimeout(id);
            reject(new Error(customError ?? `Timed out in ${ms} ms.`));
        }, ms);
    });
    // Returns a race between our timeout and the passed in promise
    return Promise.race([promise, timeout])
        .then((result) => result)
        .catch((err) => {
        throw err;
    });
}
exports.promiseTimeout = promiseTimeout;
//# sourceMappingURL=promises.js.map