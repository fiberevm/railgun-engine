import { Database } from '../database/database';
import { Chain } from '../models/engine-types';
import { TokenData } from '../models/formatted-types';
import { TXIDVersion } from '../models/poi-types';
export declare class TokenDataGetter {
    private db;
    constructor(db: Database);
    getTokenDataFromHash(txidVersion: TXIDVersion, chain: Chain, tokenHash: string): Promise<TokenData>;
    getNFTTokenData(txidVersion: TXIDVersion, chain: Chain, tokenHash: string): Promise<TokenData>;
    private static structToTokenData;
    private static getNFTTokenDataPrefix;
    private static getNFTTokenDataPath;
    private cacheNFTTokenData;
    getCachedNFTTokenData(tokenHash: string): Promise<Optional<TokenData>>;
}
