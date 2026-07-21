import { Signature } from '@railgun-community/circomlibjs';
import { PublicInputsRailgun, RailgunTransactionSigningData } from '../models';
import { ViewOnlyWallet } from './view-only-wallet';

class HardwareWallet extends ViewOnlyWallet {
  /* eslint-disable @typescript-eslint/no-unused-vars */
  // eslint-disable-next-line class-methods-use-this
  async sign(
    _publicInputs: PublicInputsRailgun,
    _encryptionKey: string,
    _signingData?: RailgunTransactionSigningData,
  ): Promise<Signature> {
    throw new Error('Signer not implemented for hardware wallet.');
  }
  /* eslint-enable @typescript-eslint/no-unused-vars */
}

export { HardwareWallet };
