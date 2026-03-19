"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.removeDuplicates = exports.removeUndefineds = exports.isDefined = void 0;
const isDefined = (a) => {
    return typeof a !== 'undefined' && a !== null;
};
exports.isDefined = isDefined;
const removeUndefineds = (a) => {
    const newArray = [];
    for (const item of a) {
        if ((0, exports.isDefined)(item)) {
            newArray.push(item);
        }
    }
    return newArray;
};
exports.removeUndefineds = removeUndefineds;
const removeDuplicates = (a) => {
    return a.filter((item, index) => a.indexOf(item) === index);
};
exports.removeDuplicates = removeDuplicates;
//# sourceMappingURL=is-defined.js.map