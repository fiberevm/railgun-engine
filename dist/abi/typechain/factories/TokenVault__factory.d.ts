import { type ContractRunner } from "ethers";
import type { TokenVault, TokenVaultInterface } from "../TokenVault";
export declare class TokenVault__factory {
    static readonly abi: readonly [{
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "shieldFee";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "unshieldFee";
            readonly type: "uint256";
        }];
        readonly name: "FeeChange";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint8";
            readonly name: "version";
            readonly type: "uint8";
        }];
        readonly name: "Initialized";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: true;
            readonly internalType: "address";
            readonly name: "previousOwner";
            readonly type: "address";
        }, {
            readonly indexed: true;
            readonly internalType: "address";
            readonly name: "newOwner";
            readonly type: "address";
        }];
        readonly name: "OwnershipTransferred";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "contract IRegistry";
            readonly name: "registry";
            readonly type: "address";
        }];
        readonly name: "RegistryChange";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "address";
            readonly name: "treasury";
            readonly type: "address";
        }];
        readonly name: "TreasuryChange";
        readonly type: "event";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "vector";
            readonly type: "uint256";
        }];
        readonly name: "addVector";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "quotient";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "numerator";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "denominator";
            readonly type: "uint256";
        }];
        readonly name: "adjustByRatio";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint120";
            readonly name: "_shieldFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint120";
            readonly name: "_unshieldFee";
            readonly type: "uint120";
        }];
        readonly name: "changeFee";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "contract IRegistry";
            readonly name: "_registry";
            readonly type: "address";
        }];
        readonly name: "changeRegistry";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address payable";
            readonly name: "_treasury";
            readonly type: "address";
        }];
        readonly name: "changeTreasury";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "checkSafetyVectors";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "enum TokenType";
                readonly name: "tokenType";
                readonly type: "uint8";
            }, {
                readonly internalType: "address";
                readonly name: "tokenAddress";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "tokenSubID";
                readonly type: "uint256";
            }];
            readonly internalType: "struct TokenData";
            readonly name: "token";
            readonly type: "tuple";
        }];
        readonly name: "getBalances";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "_amount";
            readonly type: "uint256";
        }, {
            readonly internalType: "bool";
            readonly name: "_isInclusive";
            readonly type: "bool";
        }, {
            readonly internalType: "uint120";
            readonly name: "_feeBP";
            readonly type: "uint120";
        }];
        readonly name: "getFee";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "_tokenID";
            readonly type: "bytes32";
        }];
        readonly name: "getTokenData";
        readonly outputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "enum TokenType";
                readonly name: "tokenType";
                readonly type: "uint8";
            }, {
                readonly internalType: "address";
                readonly name: "tokenAddress";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "tokenSubID";
                readonly type: "uint256";
            }];
            readonly internalType: "struct TokenData";
            readonly name: "";
            readonly type: "tuple";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "enum TokenType";
                readonly name: "tokenType";
                readonly type: "uint8";
            }, {
                readonly internalType: "address";
                readonly name: "tokenAddress";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "tokenSubID";
                readonly type: "uint256";
            }];
            readonly internalType: "struct TokenData";
            readonly name: "_tokenData";
            readonly type: "tuple";
        }];
        readonly name: "getTokenID";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address payable";
            readonly name: "_treasury";
            readonly type: "address";
        }, {
            readonly internalType: "contract IRegistry";
            readonly name: "_registry";
            readonly type: "address";
        }, {
            readonly internalType: "address";
            readonly name: "_owner";
            readonly type: "address";
        }, {
            readonly internalType: "uint120";
            readonly name: "_shieldFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint120";
            readonly name: "_unshieldFee";
            readonly type: "uint120";
        }];
        readonly name: "initialize";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly name: "internalBalances";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }, {
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }, {
            readonly internalType: "uint256[]";
            readonly name: "";
            readonly type: "uint256[]";
        }, {
            readonly internalType: "uint256[]";
            readonly name: "";
            readonly type: "uint256[]";
        }, {
            readonly internalType: "bytes";
            readonly name: "";
            readonly type: "bytes";
        }];
        readonly name: "onERC1155BatchReceived";
        readonly outputs: readonly [{
            readonly internalType: "bytes4";
            readonly name: "";
            readonly type: "bytes4";
        }];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }, {
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }, {
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }, {
            readonly internalType: "bytes";
            readonly name: "";
            readonly type: "bytes";
        }];
        readonly name: "onERC1155Received";
        readonly outputs: readonly [{
            readonly internalType: "bytes4";
            readonly name: "";
            readonly type: "bytes4";
        }];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "owner";
        readonly outputs: readonly [{
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "registry";
        readonly outputs: readonly [{
            readonly internalType: "contract IRegistry";
            readonly name: "";
            readonly type: "address";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "vector";
            readonly type: "uint256";
        }];
        readonly name: "removeVector";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "renounceOwnership";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly name: "safetyVector";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "shieldFee";
        readonly outputs: readonly [{
            readonly internalType: "uint120";
            readonly name: "";
            readonly type: "uint120";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "enum TokenType";
                readonly name: "tokenType";
                readonly type: "uint8";
            }, {
                readonly internalType: "address";
                readonly name: "tokenAddress";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "tokenSubID";
                readonly type: "uint256";
            }];
            readonly internalType: "struct TokenData";
            readonly name: "_tokenData";
            readonly type: "tuple";
        }];
        readonly name: "storeTokenData";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bytes4";
            readonly name: "interfaceId";
            readonly type: "bytes4";
        }];
        readonly name: "supportsInterface";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly name: "tokenIDMapping";
        readonly outputs: readonly [{
            readonly internalType: "enum TokenType";
            readonly name: "tokenType";
            readonly type: "uint8";
        }, {
            readonly internalType: "address";
            readonly name: "tokenAddress";
            readonly type: "address";
        }, {
            readonly internalType: "uint256";
            readonly name: "tokenSubID";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "newOwner";
            readonly type: "address";
        }];
        readonly name: "transferOwnership";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_from";
            readonly type: "address";
        }, {
            readonly internalType: "uint120";
            readonly name: "_amount";
            readonly type: "uint120";
        }, {
            readonly components: readonly [{
                readonly internalType: "enum TokenType";
                readonly name: "tokenType";
                readonly type: "uint8";
            }, {
                readonly internalType: "address";
                readonly name: "tokenAddress";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "tokenSubID";
                readonly type: "uint256";
            }];
            readonly internalType: "struct TokenData";
            readonly name: "_token";
            readonly type: "tuple";
        }];
        readonly name: "transferTokenIn";
        readonly outputs: readonly [{
            readonly internalType: "uint120";
            readonly name: "";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_to";
            readonly type: "address";
        }, {
            readonly internalType: "uint120";
            readonly name: "_amount";
            readonly type: "uint120";
        }, {
            readonly components: readonly [{
                readonly internalType: "enum TokenType";
                readonly name: "tokenType";
                readonly type: "uint8";
            }, {
                readonly internalType: "address";
                readonly name: "tokenAddress";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "tokenSubID";
                readonly type: "uint256";
            }];
            readonly internalType: "struct TokenData";
            readonly name: "_token";
            readonly type: "tuple";
        }];
        readonly name: "transferTokenOut";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "treasury";
        readonly outputs: readonly [{
            readonly internalType: "address payable";
            readonly name: "";
            readonly type: "address";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "unshieldFee";
        readonly outputs: readonly [{
            readonly internalType: "uint120";
            readonly name: "";
            readonly type: "uint120";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }];
    static createInterface(): TokenVaultInterface;
    static connect(address: string, runner?: ContractRunner | null): TokenVault;
}
