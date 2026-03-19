"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.binarySearchForString = exports.binarySearchForUpperBoundIndex = void 0;
const binarySearchForUpperBoundIndex = (array, pred) => {
    let l = 0;
    let r = array.length;
    while (l < r) {
        const mid = l + ((r - l) >> 1);
        const item = array[mid];
        if (pred(item)) {
            l = mid + 1;
        }
        else {
            r = mid;
        }
    }
    return l - 1;
};
exports.binarySearchForUpperBoundIndex = binarySearchForUpperBoundIndex;
const binarySearchForString = (array, str, getString) => {
    let startIndex = 0;
    let stopIndex = array.length - 1;
    let middle = Math.floor((stopIndex + startIndex) / 2);
    while (getString(array[middle]) !== str && startIndex < stopIndex) {
        if (str < getString(array[middle])) {
            stopIndex = middle - 1;
        }
        else if (str > getString(array[middle])) {
            startIndex = middle + 1;
        }
        middle = Math.floor((stopIndex + startIndex) / 2);
    }
    return getString(array[middle]) !== str ? -1 : middle;
};
exports.binarySearchForString = binarySearchForString;
//# sourceMappingURL=search.js.map