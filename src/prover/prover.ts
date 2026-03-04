import EngineDebug from '../debugger/debugger';
import { ByteLength, ByteUtils } from '../utils/bytes';
import {
  ArtifactGetter,
  FormattedCircuitInputsRailgun,
  UnprovedTransactionInputs,
  Proof,
  PublicInputsRailgun,
  SnarkProof,
  NativeProverFormattedJsonInputsRailgun,
} from '../models/prover-types';
import { stringifySafe } from '../utils/stringify';
import { ProofCache } from './proof-cache';
import { TXIDVersion } from '../models';
import { ProgressService } from './progress-service';

type NativeProveRailgun = (
  circuitId: number,
  datBuffer: Buffer,
  zkeyBuffer: Buffer,
  inputJson: NativeProverFormattedJsonInputsRailgun,
  progressCallback: ProverProgressCallback,
) => Proof;

type Groth16FullProveRailgun = (
  formattedInputs: FormattedCircuitInputsRailgun,
  wasm: Optional<ArrayLike<number>>,
  zkey: ArrayLike<number>,
  logger: { debug: (log: string) => void },
  dat: Optional<ArrayLike<number>>,
  progressCallback: ProverProgressCallback,
) => Promise<{ proof: Proof; publicSignals?: string[] }>;

type Groth16Verify = Optional<
  (vkey: object, publicSignals: bigint[], proof: Proof) => Promise<boolean>
>;

export type SnarkJSGroth16 = {
  fullProve: (
    formattedInputs: Partial<Record<string, bigint | bigint[] | bigint[][]>>,
    wasm: Optional<ArrayLike<number>>,
    zkey: ArrayLike<number>,
    logger: { debug: (log: string) => void },
  ) => Promise<{ proof: Proof; publicSignals: string[] }>;
  verify: Groth16Verify;
};

export type Groth16Implementation = {
  fullProveRailgun: Groth16FullProveRailgun;
  verify: Groth16Verify;
};

export type ProverProgressCallback = (progress: number) => void;

export class Prover {
  private artifactGetter: ArtifactGetter;

  groth16: Optional<Groth16Implementation>;

  constructor(artifactGetter: ArtifactGetter) {
    this.artifactGetter = artifactGetter;
  }

  /**
   * Used to set Groth16 implementation from snarkjs.min.js or snarkjs.
   */
  setSnarkJSGroth16(snarkJSGroth16: SnarkJSGroth16) {
    const suppressDebugLogger = { debug: () => {} };

    this.groth16 = {
      fullProveRailgun: async (
        formattedInputs: FormattedCircuitInputsRailgun,
        wasm: Optional<ArrayLike<number>>,
        zkey: ArrayLike<number>,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        _logger: { debug: (log: string) => void },
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        _dat: ArrayLike<number> | undefined,
        progressCallback: ProverProgressCallback,
      ) => {
        const progressService = new ProgressService(
          0, // startValue
          95, // endValue
          1500, // totalMsec
          250, // delayMsec
        );
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        progressService.progressSteadily(progressCallback);
        try {
          const proof = await snarkJSGroth16.fullProve(
            formattedInputs,
            wasm,
            zkey,
            suppressDebugLogger,
          );
          progressService.stop();
          return proof;
        } catch (cause) {
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
  setNativeProverGroth16(
    nativeProveRailgun: NativeProveRailgun,
    circuits: { [name: string]: number },
  ) {
    const circuitIdForInputsOutputs = (inputs: number, outputs: number): number => {
      const circuitString = `${inputs}X${outputs}`;
      const circuitName = `JOINSPLIT_${circuitString}`;
      const circuitId = circuits[circuitName];
      if (circuitId == null) {
        throw new Error(`No circuit found for ${circuitString.toLowerCase()}`);
      }
      return circuitId;
    };

    const fullProveRailgun = (
      formattedInputs: FormattedCircuitInputsRailgun,
      _wasm: ArrayLike<number> | undefined,
      zkey: ArrayLike<number>,
      logger: { debug: (log: string) => void },
      dat: ArrayLike<number> | undefined,
      progressCallback: ProverProgressCallback,
    ): Promise<{
      proof: Proof;
    }> => {
      try {
        if (!dat) {
          throw new Error('DAT artifact is required.');
        }
        const inputs = formattedInputs.nullifiers.length;
        const outputs = formattedInputs.commitmentsOut.length;
        const circuitId = circuitIdForInputsOutputs(inputs, outputs);

        const stringInputs = stringifySafe(formattedInputs);
        logger.debug(stringInputs);

        const jsonInputs = JSON.parse(stringInputs) as NativeProverFormattedJsonInputsRailgun;

        const datBuffer = dat as Buffer;
        const zkeyBuffer = zkey as Buffer;

        const start = Date.now();

        const proof: Proof = nativeProveRailgun(
          circuitId,
          datBuffer,
          zkeyBuffer,
          jsonInputs,
          progressCallback,
        );

        logger.debug(`Proof lapsed ${Date.now() - start} ms`);

        return Promise.resolve({ proof });
      } catch (cause) {
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

  async verifyRailgunProof(
    publicInputs: PublicInputsRailgun,
    proof: Proof,
    artifacts: Artifact,
  ): Promise<boolean> {
    if (!this.groth16) {
      throw new Error('Requires groth16 implementation');
    }
    if (!this.groth16.verify) {
      // Wallet-side verification is a fail-safe.
      // Snark verification will occur during gas estimate (and on-chain) regardless.
      return true;
    }

    // Return output of groth16 verify
    const publicSignals: bigint[] = [
      publicInputs.merkleRoot,
      publicInputs.boundParamsHash,
      ...publicInputs.nullifiers,
      ...publicInputs.commitmentsOut,
    ];

    return this.groth16.verify(artifacts.vkey, publicSignals, proof);
  }

  private static get zeroProof(): Proof {
    const zero = ByteUtils.nToHex(BigInt(0), ByteLength.UINT_8);
    // prettier-ignore
    return {
      pi_a: [zero, zero],
      pi_b: [[zero, zero], [zero, zero]],
      pi_c: [zero, zero],
    };
  }

  dummyProveRailgun(publicInputs: PublicInputsRailgun): Proof {
    // Make sure we have valid artifacts for this number of inputs.
    // Note that the artifacts are not used in the dummy proof.
    this.artifactGetter.assertArtifactExists(
      publicInputs.nullifiers.length,
      publicInputs.commitmentsOut.length,
    );
    return Prover.zeroProof;
  }

  async proveRailgun(
    txidVersion: TXIDVersion,
    unprovedTransactionInputs: UnprovedTransactionInputs,
    progressCallback: ProverProgressCallback,
  ): Promise<{ proof: Proof; publicInputs: PublicInputsRailgun }> {
    if (!this.groth16) {
      throw new Error('Requires groth16 full prover implementation');
    }

    const { publicInputs } = unprovedTransactionInputs;

    const existingProof = ProofCache.get(unprovedTransactionInputs);
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
    const { proof } = await this.groth16.fullProveRailgun(
      formattedInputs,
      artifacts.wasm,
      artifacts.zkey,
      { debug: (msg: string) => EngineDebug.log(msg) },
      artifacts.dat,
      (progress: number) => {
        progressCallback(
          (progress * (finalProgressProof - initialProgressProof)) / 100 + initialProgressProof,
        );
      },
    );
    progressCallback(finalProgressProof);

    // Throw if proof is invalid
    if (!(await this.verifyRailgunProof(publicInputs, proof, artifacts))) {
      throw new Error('Proof verification failed');
    }

    ProofCache.store(unprovedTransactionInputs, proof);

    progressCallback(100);

    // Return proof with inputs
    return {
      proof,
      publicInputs,
    };
  }

  static formatProof(proof: Proof): SnarkProof {
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

  private static formatRailgunInputs(
    transactionInputs: UnprovedTransactionInputs,
  ): FormattedCircuitInputsRailgun {
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
