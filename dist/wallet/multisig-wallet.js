"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MultisigWallet = void 0;
const view_only_wallet_1 = require("./view-only-wallet");
class MultisigWallet extends view_only_wallet_1.ViewOnlyWallet {
    /* eslint-disable @typescript-eslint/no-unused-vars */
    // eslint-disable-next-line class-methods-use-this
    async sign(_publicInputs, _encryptionKey, _signingData) {
        throw new Error('Signer not implemented for multisig.');
    }
}
exports.MultisigWallet = MultisigWallet;
//# sourceMappingURL=multisig-wallet.js.map