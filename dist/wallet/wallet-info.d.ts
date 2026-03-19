export default class WalletInfo {
    static walletSource: string;
    static setWalletSource(walletSource: string): void;
    private static validateWalletSource;
    static getEncodedWalletSource(walletSource: string): string;
    /**
     * Encodes wallet source string into base 37 hex string.
     */
    private static encodeWalletSource;
    static decodeWalletSource(bytes: string): string;
}
