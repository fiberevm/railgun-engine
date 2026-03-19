import { FallbackProvider } from 'ethers';
import { TokenDataStructOutput, TokenVault } from '../../../abi/typechain/TokenVault';
import { PollingJsonRpcProvider } from '../../../provider/polling-json-rpc-provider';
export declare class TokenVaultContract {
    readonly contract: TokenVault;
    readonly address: string;
    constructor(address: string, provider: PollingJsonRpcProvider | FallbackProvider);
    /**
     * Gets transaction fees in basis points.
     */
    fees(): Promise<{
        shield: bigint;
        unshield: bigint;
    }>;
    /**
     * Gets NFT token data from tokenHash.
     */
    getNFTTokenData(tokenHash: string): Promise<TokenDataStructOutput>;
}
