"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ABITokenVault = exports.ABIPoseidonMerkleVerifier = exports.ABIPoseidonMerkleAccumulator = exports.ABIRelayAdapt = exports.ABIRailgunSmartWallet = exports.ABIRailgunSmartWallet_Legacy_PreMar23 = exports.ABIRailgunLogic_LegacyEvents = void 0;
// V1
const RailgunLogic_LegacyEvents_json_1 = __importDefault(require("./V1/RailgunLogic_LegacyEvents.json"));
exports.ABIRailgunLogic_LegacyEvents = RailgunLogic_LegacyEvents_json_1.default;
// V2
const RailgunSmartWallet_Legacy_PreMar23_json_1 = __importDefault(require("./V2/RailgunSmartWallet_Legacy_PreMar23.json"));
exports.ABIRailgunSmartWallet_Legacy_PreMar23 = RailgunSmartWallet_Legacy_PreMar23_json_1.default;
const RelayAdapt_json_1 = __importDefault(require("./V2/RelayAdapt.json"));
exports.ABIRelayAdapt = RelayAdapt_json_1.default;
// V2.1
const RailgunSmartWallet_json_1 = __importDefault(require("./V2.1/RailgunSmartWallet.json"));
exports.ABIRailgunSmartWallet = RailgunSmartWallet_json_1.default;
// V3
const PoseidonMerkleAccumulator_json_1 = __importDefault(require("./V3/PoseidonMerkleAccumulator.json"));
exports.ABIPoseidonMerkleAccumulator = PoseidonMerkleAccumulator_json_1.default;
const PoseidonMerkleVerifier_json_1 = __importDefault(require("./V3/PoseidonMerkleVerifier.json"));
exports.ABIPoseidonMerkleVerifier = PoseidonMerkleVerifier_json_1.default;
const TokenVault_json_1 = __importDefault(require("./V3/TokenVault.json"));
exports.ABITokenVault = TokenVault_json_1.default;
//# sourceMappingURL=abi.js.map