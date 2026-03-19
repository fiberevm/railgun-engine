import { BytesLike } from 'ethers';
/**
 * Calculates sha256 hash of bytes
 * @returns hash
 */
declare function sha256(preImage: BytesLike): string;
/**
 * Calculates sha512 hash of bytes
 * @param preImage - bytesdata
 * @returns hash
 */
declare function sha512(preImage: BytesLike): string;
/**
 * Calculates sha512 hmac
 * @returns hmac
 */
declare function sha512HMAC(key: BytesLike, data: BytesLike): string;
/**
 * Calculates keccak256 hash of bytes
 * @returns hash
 */
declare function keccak256(preImage: BytesLike): string;
export { sha256, sha512, sha512HMAC, keccak256 };
