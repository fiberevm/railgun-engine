"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Prover = void 0;
const debugger_1 = __importDefault(require("../debugger/debugger"));
const bytes_1 = require("../utils/bytes");
const stringify_1 = require("../utils/stringify");
const proof_cache_1 = require("./proof-cache");
const progress_service_1 = require("./progress-service");
class Prover {
    artifactGetter;
    groth16;
    constructor(artifactGetter) {
        this.artifactGetter = artifactGetter;
    }
    /**
     * Used to set Groth16 implementation from snarkjs.min.js or snarkjs.
     */
    setSnarkJSGroth16(snarkJSGroth16) {
        const suppressDebugLogger = { debug: () => { } };
        this.groth16 = {
            fullProveRailgun: async (formattedInputs, wasm, zkey, 
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            _logger, 
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            _dat, progressCallback) => {
                const progressService = new progress_service_1.ProgressService(0, // startValue
                95, // endValue
                1500, // totalMsec
                250);
                // eslint-disable-next-line @typescript-eslint/no-floating-promises
                progressService.progressSteadily(progressCallback);
                try {
                    const proof = await snarkJSGroth16.fullProve(formattedInputs, wasm, zkey, suppressDebugLogger);
                    progressService.stop();
                    return proof;
                }
                catch (cause) {
                    progressService.stop();
                    throw new Error('SnarkJS failed to fullProveRailgun', { cause });
                }
            },
            verify: snarkJSGroth16.verify,
        };
    }
    /**
     * Used to set Groth16 implementation from RAILGUN Native Prover.
     */
    setNativeProverGroth16(nativeProveRailgun, circuits) {
        const circuitIdForInputsOutputs = (inputs, outputs) => {
            const circuitString = `${inputs}X${outputs}`;
            const circuitName = `JOINSPLIT_${circuitString}`;
            const circuitId = circuits[circuitName];
            if (circuitId == null) {
                throw new Error(`No circuit found for ${circuitString.toLowerCase()}`);
            }
            return circuitId;
        };
        const fullProveRailgun = (formattedInputs, _wasm, zkey, logger, dat, progressCallback) => {
            try {
                if (!dat) {
                    throw new Error('DAT artifact is required.');
                }
                const inputs = formattedInputs.nullifiers.length;
                const outputs = formattedInputs.commitmentsOut.length;
                const circuitId = circuitIdForInputsOutputs(inputs, outputs);
                const stringInputs = (0, stringify_1.stringifySafe)(formattedInputs);
                logger.debug(stringInputs);
                const jsonInputs = JSON.parse(stringInputs);
                const datBuffer = dat;
                const zkeyBuffer = zkey;
                const start = Date.now();
                const proof = nativeProveRailgun(circuitId, datBuffer, zkeyBuffer, jsonInputs, progressCallback);
                logger.debug(`Proof lapsed ${Date.now() - start} ms`);
                return Promise.resolve({ proof });
            }
            catch (cause) {
                if (!(cause instanceof Error)) {
                    throw new Error('Non-error thrown by native prover fullProveRailgun', { cause });
                }
                logger.debug(cause.message);
                throw new Error('Native-prover failed to fullProveRailgun', { cause });
            }
        };
        this.groth16 = {
            fullProveRailgun,
            // Proof will be verified during gas estimate, and on-chain.
            verify: undefined,
        };
    }
    async verifyRailgunProof(publicInputs, proof, artifacts) {
        if (!this.groth16) {
            throw new Error('Requires groth16 implementation');
        }
        if (!this.groth16.verify) {
            // Wallet-side verification is a fail-safe.
            // Snark verification will occur during gas estimate (and on-chain) regardless.
            return true;
        }
        // Return output of groth16 verify
        const publicSignals = [
            publicInputs.merkleRoot,
            publicInputs.boundParamsHash,
            ...publicInputs.nullifiers,
            ...publicInputs.commitmentsOut,
        ];
        return this.groth16.verify(artifacts.vkey, publicSignals, proof);
    }
    static get zeroProof() {
        const zero = bytes_1.ByteUtils.nToHex(BigInt(0), bytes_1.ByteLength.UINT_8);
        // prettier-ignore
        return {
            pi_a: [zero, zero],
            pi_b: [[zero, zero], [zero, zero]],
            pi_c: [zero, zero],
        };
    }
    dummyProveRailgun(publicInputs) {
        // Make sure we have valid artifacts for this number of inputs.
        // Note that the artifacts are not used in the dummy proof.
        this.artifactGetter.assertArtifactExists(publicInputs.nullifiers.length, publicInputs.commitmentsOut.length);
        return Prover.zeroProof;
    }
    async proveRailgun(txidVersion, unprovedTransactionInputs, progressCallback) {
        if (!this.groth16) {
            throw new Error('Requires groth16 full prover implementation');
        }
        const { publicInputs } = unprovedTransactionInputs;
        const existingProof = proof_cache_1.ProofCache.get(unprovedTransactionInputs);
        if (existingProof) {
            return { proof: existingProof, publicInputs };
        }
        // 1-2  1-3  2-2  2-3  8-2 [nullifiers, commitments]
        // Fetch artifacts
        progressCallback(5);
        const artifacts = await this.artifactGetter.getArtifacts(publicInputs);
        if (!artifacts.wasm && !artifacts.dat) {
            throw new Error('Requires WASM or DAT prover artifact');
        }
        // Get formatted inputs
        const formattedInputs = Prover.formatRailgunInputs(unprovedTransactionInputs);
        // Generate proof: Progress from 20 - 99%
        const initialProgressProof = 20;
        const finalProgressProof = 99;
        progressCallback(initialProgressProof);
        const { proof } = await this.groth16.fullProveRailgun(formattedInputs, artifacts.wasm, artifacts.zkey, { debug: (msg) => debugger_1.default.log(msg) }, artifacts.dat, (progress) => {
            progressCallback((progress * (finalProgressProof - initialProgressProof)) / 100 + initialProgressProof);
        });
        progressCallback(finalProgressProof);
        // Throw if proof is invalid
        if (!(await this.verifyRailgunProof(publicInputs, proof, artifacts))) {
            throw new Error('Proof verification failed');
        }
        proof_cache_1.ProofCache.store(unprovedTransactionInputs, proof);
        progressCallback(100);
        // Return proof with inputs
        return {
            proof,
            publicInputs,
        };
    }
    static formatProof(proof) {
        return {
            a: {
                x: BigInt(proof.pi_a[0]),
                y: BigInt(proof.pi_a[1]),
            },
            b: {
                x: [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
                y: [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
            },
            c: {
                x: BigInt(proof.pi_c[0]),
                y: BigInt(proof.pi_c[1]),
            },
        };
    }
    static formatRailgunInputs(transactionInputs) {
        const { publicInputs, privateInputs } = transactionInputs;
        return {
            merkleRoot: publicInputs.merkleRoot,
            boundParamsHash: publicInputs.boundParamsHash,
            nullifiers: publicInputs.nullifiers,
            commitmentsOut: publicInputs.commitmentsOut,
            token: privateInputs.tokenAddress,
            publicKey: privateInputs.publicKey,
            signature: transactionInputs.signature,
            randomIn: privateInputs.randomIn,
            valueIn: privateInputs.valueIn,
            pathElements: privateInputs.pathElements.flat(2),
            leavesIndices: privateInputs.leavesIndices,
            nullifyingKey: privateInputs.nullifyingKey,
            npkOut: privateInputs.npkOut,
            valueOut: privateInputs.valueOut,
        };
    }
}
exports.Prover = Prover;
//# sourceMappingURL=prover.js.map