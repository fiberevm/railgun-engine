"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MultisigWallet = void 0;
const view_only_wallet_1 = require("./view-only-wallet");
class MultisigWallet extends view_only_wallet_1.ViewOnlyWallet {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars, class-methods-use-this
    async sign(_publicInputs, _encryptionKey) {
        throw new Error('Signer not implemented for multisig.');
    }
}
exports.MultisigWallet = MultisigWallet;
//# sourceMappingURL=multisig-wallet.js.map