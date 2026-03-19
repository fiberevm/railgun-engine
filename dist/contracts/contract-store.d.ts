import { Registry } from '../utils/registry';
import { RailgunSmartWalletContract } from './railgun-smart-wallet/V2/railgun-smart-wallet';
import { PoseidonMerkleAccumulatorContract } from './railgun-smart-wallet/V3/poseidon-merkle-accumulator';
import { PoseidonMerkleVerifierContract } from './railgun-smart-wallet/V3/poseidon-merkle-verifier';
import { TokenVaultContract } from './railgun-smart-wallet/V3/token-vault-contract';
import { RelayAdaptV2Contract } from './relay-adapt/V2/relay-adapt-v2';
import { RelayAdaptV3Contract } from './relay-adapt/V3/relay-adapt-v3';
export declare class ContractStore {
    static readonly railgunSmartWalletContracts: Registry<RailgunSmartWalletContract>;
    static readonly relayAdaptV2Contracts: Registry<RelayAdaptV2Contract>;
    static readonly poseidonMerkleAccumulatorV3Contracts: Registry<PoseidonMerkleAccumulatorContract>;
    static readonly poseidonMerkleVerifierV3Contracts: Registry<PoseidonMerkleVerifierContract>;
    static readonly tokenVaultV3Contracts: Registry<TokenVaultContract>;
    static readonly relayAdaptV3Contracts: Registry<RelayAdaptV3Contract>;
}
