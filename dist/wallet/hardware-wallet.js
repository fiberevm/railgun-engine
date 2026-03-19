"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HardwareWallet = void 0;
const view_only_wallet_1 = require("./view-only-wallet");
class HardwareWallet extends view_only_wallet_1.ViewOnlyWallet {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars, class-methods-use-this
    async sign(_publicInputs, _encryptionKey) {
        throw new Error('Signer not implemented for hardware wallet.');
    }
}
exports.HardwareWallet = HardwareWallet;
//# sourceMappingURL=hardware-wallet.js.map