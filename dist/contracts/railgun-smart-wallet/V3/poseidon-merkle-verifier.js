"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PoseidonMerkleVerifierContract = void 0;
const ethers_1 = require("ethers");
const abi_1 = require("../../../abi/abi");
class PoseidonMerkleVerifierContract {
    contract;
    address;
    constructor(address, provider) {
        this.address = address;
        this.contract = new ethers_1.Contract(address, abi_1.ABIPoseidonMerkleVerifier, provider);
    }
    generateExecute(transactions, shields, globalBoundParams, unshieldChangeCiphertext) {
        return this.contract.execute.populateTransaction(transactions, shields, globalBoundParams, unshieldChangeCiphertext);
    }
}
exports.PoseidonMerkleVerifierContract = PoseidonMerkleVerifierContract;
//# sourceMappingURL=poseidon-merkle-verifier.js.map