import { ContractTransaction } from 'ethers';
import { RelayAdaptShieldERC20Recipient, RelayAdaptShieldNFTRecipient } from '../../models/formatted-types';
import { RelayAdapt, ShieldRequestStruct } from '../../abi/typechain/RelayAdapt';
import { TransactionStructV2, TransactionStructV3 } from '../../models/transaction-types';
declare class RelayAdaptHelper {
    static generateRelayShieldRequests(random: string, shieldERC20Recipients: RelayAdaptShieldERC20Recipient[], shieldNFTRecipients: RelayAdaptShieldNFTRecipient[]): Promise<ShieldRequestStruct[]>;
    private static createRelayShieldRequestsERC20s;
    private static createRelayShieldRequestsNFTs;
    private static valueForNFTShield;
    /**
     * Format action data field for relay call.
     */
    static getActionData(random: string, requireSuccess: boolean, calls: ContractTransaction[], minGasLimit: bigint): RelayAdapt.ActionDataStruct;
    /**
     * Get relay adapt params hash.
     * Hashes transaction data and params to ensure that transaction is not modified by MITM.
     *
     * @param transactions - serialized transactions
     * @param random - random value
     * @param requireSuccess - require success on calls
     * @param calls - calls list
     * @returns adapt params
     */
    static getRelayAdaptParams(transactions: (TransactionStructV2 | TransactionStructV3)[], random: string, requireSuccess: boolean, calls: ContractTransaction[], minGasLimit?: bigint): string;
    /**
     * Strips all unnecessary fields from populated transactions
     *
     * @param {object[]} calls - calls list
     * @returns {object[]} formatted calls
     */
    static formatCalls(calls: ContractTransaction[]): RelayAdapt.CallStruct[];
    static formatRandom(random: string): Uint8Array;
}
export { RelayAdaptHelper };
