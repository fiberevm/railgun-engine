"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getGlobalTreePosition = exports.GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE = exports.GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE = void 0;
const merkletree_types_1 = require("../models/merkletree-types");
exports.GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE = 99999;
exports.GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE = 99999;
const getGlobalTreePosition = (tree, index) => {
    return BigInt(tree * merkletree_types_1.TREE_MAX_ITEMS + index);
};
exports.getGlobalTreePosition = getGlobalTreePosition;
//# sourceMappingURL=global-tree-position.js.map