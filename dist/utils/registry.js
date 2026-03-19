"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Registry = void 0;
const poi_types_1 = require("../models/poi-types");
const is_defined_1 = require("./is-defined");
/**
 * A simple nested datastructure that holds information per-chain and per
 * RailgunTXIDVersion.
 */
class Registry {
    v2Map;
    v3Map;
    anyMap;
    constructor() {
        this.v2Map = new Map();
        this.v3Map = new Map();
        this.anyMap = new Map();
    }
    selectMap(txidVersion) {
        switch (txidVersion) {
            case poi_types_1.TXIDVersion.V2_PoseidonMerkle:
                return this.v2Map;
            case poi_types_1.TXIDVersion.V3_PoseidonMerkle:
                return this.v3Map;
            default:
                return this.anyMap;
        }
    }
    static serializeChain(chain) {
        return `${chain.type}:${chain.id}`;
    }
    static deserializeChain(chainString) {
        const [type, id] = chainString.split(':').map(Number);
        return { type, id };
    }
    set(txidVersion, chain, value) {
        this.selectMap(txidVersion).set(Registry.serializeChain(chain), value);
    }
    has(txidVersion, chain) {
        return (0, is_defined_1.isDefined)(this.get(txidVersion, chain));
    }
    get(txidVersion, chain) {
        return this.selectMap(txidVersion).get(Registry.serializeChain(chain));
    }
    getOrThrow(txidVersion, chain) {
        const value = this.get(txidVersion, chain);
        if (!(0, is_defined_1.isDefined)(value)) {
            const chainStr = Registry.serializeChain(chain);
            throw new Error(`No value found for txidVersion=${String(txidVersion)} and chain=${chainStr}`);
        }
        return value;
    }
    del(txidVersion, chain) {
        this.selectMap(txidVersion).delete(Registry.serializeChain(chain));
    }
    forEach(callback) {
        const taggedMaps = [
            [poi_types_1.TXIDVersion.V2_PoseidonMerkle, this.v2Map],
            [poi_types_1.TXIDVersion.V3_PoseidonMerkle, this.v3Map],
            [null, this.anyMap],
        ];
        for (const [txidVersion, map] of taggedMaps) {
            for (const [chainStr, value] of map) {
                const chain = Registry.deserializeChain(chainStr);
                callback(value, txidVersion, chain);
            }
        }
    }
    map(callback) {
        const result = [];
        this.forEach((value, txidVersion, chain) => {
            result.push(callback(value, txidVersion, chain));
        });
        return result;
    }
}
exports.Registry = Registry;
//# sourceMappingURL=registry.js.map