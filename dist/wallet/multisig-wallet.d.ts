/// <reference path="../../src/types/global.d.ts" />
import { Signature } from '@railgun-community/circomlibjs';
import { PublicInputsRailgun } from '../models';
import { ViewOnlyWallet } from './view-only-wallet';
declare class MultisigWallet extends ViewOnlyWallet {
    sign(_publicInputs: PublicInputsRailgun, _encryptionKey: string): Promise<Signature>;
}
export { MultisigWallet };
