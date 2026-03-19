import { type ContractRunner } from "ethers";
import type { RailgunSmartWallet_Legacy_PreMar23, RailgunSmartWallet_Legacy_PreMar23Interface } from "../RailgunSmartWallet_Legacy_PreMar23";
export declare class RailgunSmartWallet_Legacy_PreMar23__factory {
    static readonly abi: readonly [{
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: true;
            readonly internalType: "address";
            readonly name: "token";
            readonly type: "address";
        }];
        readonly name: "AddToBlocklist";
        readonly type: "event";
    }, {
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
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "nftFee";
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
            readonly indexed: false;
            readonly internalType: "uint16";
            readonly name: "treeNumber";
            readonly type: "uint16";
        }, {
            readonly indexed: false;
            readonly internalType: "bytes32[]";
            readonly name: "nullifier";
            readonly type: "bytes32[]";
        }];
        readonly name: "Nullified";
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
            readonly indexed: true;
            readonly internalType: "address";
            readonly name: "token";
            readonly type: "address";
        }];
        readonly name: "RemoveFromBlocklist";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "treeNumber";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "startPosition";
            readonly type: "uint256";
        }, {
            readonly components: readonly [{
                readonly internalType: "bytes32";
                readonly name: "npk";
                readonly type: "bytes32";
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
                readonly name: "token";
                readonly type: "tuple";
            }, {
                readonly internalType: "uint120";
                readonly name: "value";
                readonly type: "uint120";
            }];
            readonly indexed: false;
            readonly internalType: "struct CommitmentPreimage[]";
            readonly name: "commitments";
            readonly type: "tuple[]";
        }, {
            readonly components: readonly [{
                readonly internalType: "bytes32[3]";
                readonly name: "encryptedBundle";
                readonly type: "bytes32[3]";
            }, {
                readonly internalType: "bytes32";
                readonly name: "shieldKey";
                readonly type: "bytes32";
            }];
            readonly indexed: false;
            readonly internalType: "struct ShieldCiphertext[]";
            readonly name: "shieldCiphertext";
            readonly type: "tuple[]";
        }];
        readonly name: "Shield";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "treeNumber";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "startPosition";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "bytes32[]";
            readonly name: "hash";
            readonly type: "bytes32[]";
        }, {
            readonly components: readonly [{
                readonly internalType: "bytes32[4]";
                readonly name: "ciphertext";
                readonly type: "bytes32[4]";
            }, {
                readonly internalType: "bytes32";
                readonly name: "blindedSenderViewingKey";
                readonly type: "bytes32";
            }, {
                readonly internalType: "bytes32";
                readonly name: "blindedReceiverViewingKey";
                readonly type: "bytes32";
            }, {
                readonly internalType: "bytes";
                readonly name: "annotationData";
                readonly type: "bytes";
            }, {
                readonly internalType: "bytes";
                readonly name: "memo";
                readonly type: "bytes";
            }];
            readonly indexed: false;
            readonly internalType: "struct CommitmentCiphertext[]";
            readonly name: "ciphertext";
            readonly type: "tuple[]";
        }];
        readonly name: "Transact";
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
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "address";
            readonly name: "to";
            readonly type: "address";
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
            readonly indexed: false;
            readonly internalType: "struct TokenData";
            readonly name: "token";
            readonly type: "tuple";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "amount";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "fee";
            readonly type: "uint256";
        }];
        readonly name: "Unshield";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "nullifiers";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "commitments";
            readonly type: "uint256";
        }, {
            readonly components: readonly [{
                readonly internalType: "string";
                readonly name: "artifactsIPFSHash";
                readonly type: "string";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point";
                readonly name: "alpha1";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "beta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "gamma2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "delta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point[]";
                readonly name: "ic";
                readonly type: "tuple[]";
            }];
            readonly indexed: false;
            readonly internalType: "struct VerifyingKey";
            readonly name: "verifyingKey";
            readonly type: "tuple";
        }];
        readonly name: "VerifyingKeySet";
        readonly type: "event";
    }, {
        readonly inputs: readonly [];
        readonly name: "ZERO_VALUE";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address[]";
            readonly name: "_tokens";
            readonly type: "address[]";
        }];
        readonly name: "addToBlocklist";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
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
            readonly internalType: "uint120";
            readonly name: "_shieldFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint120";
            readonly name: "_unshieldFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint256";
            readonly name: "_nftFee";
            readonly type: "uint256";
        }];
        readonly name: "changeFee";
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
            readonly internalType: "uint136";
            readonly name: "_amount";
            readonly type: "uint136";
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
            readonly internalType: "uint120";
            readonly name: "";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint120";
            readonly name: "";
            readonly type: "uint120";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "_newCommitments";
            readonly type: "uint256";
        }];
        readonly name: "getInsertionTreeNumberAndStartingIndex";
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
            readonly internalType: "uint256";
            readonly name: "_nullifiers";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "_commitments";
            readonly type: "uint256";
        }];
        readonly name: "getVerificationKey";
        readonly outputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "string";
                readonly name: "artifactsIPFSHash";
                readonly type: "string";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point";
                readonly name: "alpha1";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "beta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "gamma2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "delta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point[]";
                readonly name: "ic";
                readonly type: "tuple[]";
            }];
            readonly internalType: "struct VerifyingKey";
            readonly name: "";
            readonly type: "tuple";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "uint16";
                readonly name: "treeNumber";
                readonly type: "uint16";
            }, {
                readonly internalType: "uint72";
                readonly name: "minGasPrice";
                readonly type: "uint72";
            }, {
                readonly internalType: "enum UnshieldType";
                readonly name: "unshield";
                readonly type: "uint8";
            }, {
                readonly internalType: "uint64";
                readonly name: "chainID";
                readonly type: "uint64";
            }, {
                readonly internalType: "address";
                readonly name: "adaptContract";
                readonly type: "address";
            }, {
                readonly internalType: "bytes32";
                readonly name: "adaptParams";
                readonly type: "bytes32";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32[4]";
                    readonly name: "ciphertext";
                    readonly type: "bytes32[4]";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "blindedSenderViewingKey";
                    readonly type: "bytes32";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "blindedReceiverViewingKey";
                    readonly type: "bytes32";
                }, {
                    readonly internalType: "bytes";
                    readonly name: "annotationData";
                    readonly type: "bytes";
                }, {
                    readonly internalType: "bytes";
                    readonly name: "memo";
                    readonly type: "bytes";
                }];
                readonly internalType: "struct CommitmentCiphertext[]";
                readonly name: "commitmentCiphertext";
                readonly type: "tuple[]";
            }];
            readonly internalType: "struct BoundParams";
            readonly name: "_boundParams";
            readonly type: "tuple";
        }];
        readonly name: "hashBoundParams";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "bytes32";
                readonly name: "npk";
                readonly type: "bytes32";
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
                readonly name: "token";
                readonly type: "tuple";
            }, {
                readonly internalType: "uint120";
                readonly name: "value";
                readonly type: "uint120";
            }];
            readonly internalType: "struct CommitmentPreimage";
            readonly name: "_commitmentPreimage";
            readonly type: "tuple";
        }];
        readonly name: "hashCommitment";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "_left";
            readonly type: "bytes32";
        }, {
            readonly internalType: "bytes32";
            readonly name: "_right";
            readonly type: "bytes32";
        }];
        readonly name: "hashLeftRight";
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
            readonly internalType: "uint120";
            readonly name: "_shieldFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint120";
            readonly name: "_unshieldFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint256";
            readonly name: "_nftFee";
            readonly type: "uint256";
        }, {
            readonly internalType: "address";
            readonly name: "_owner";
            readonly type: "address";
        }];
        readonly name: "initializeRailgunLogic";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "lastEventBlock";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "merkleRoot";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "nextLeafIndex";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "nftFee";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }, {
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly name: "nullifiers";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
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
        readonly inputs: readonly [{
            readonly internalType: "address[]";
            readonly name: "_tokens";
            readonly type: "address[]";
        }];
        readonly name: "removeFromBlocklist";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
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
        }, {
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly name: "rootHistory";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "_nullifiers";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "_commitments";
            readonly type: "uint256";
        }, {
            readonly components: readonly [{
                readonly internalType: "string";
                readonly name: "artifactsIPFSHash";
                readonly type: "string";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point";
                readonly name: "alpha1";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "beta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "gamma2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "delta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point[]";
                readonly name: "ic";
                readonly type: "tuple[]";
            }];
            readonly internalType: "struct VerifyingKey";
            readonly name: "_verifyingKey";
            readonly type: "tuple";
        }];
        readonly name: "setVerificationKey";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly internalType: "bytes32";
                    readonly name: "npk";
                    readonly type: "bytes32";
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
                    readonly name: "token";
                    readonly type: "tuple";
                }, {
                    readonly internalType: "uint120";
                    readonly name: "value";
                    readonly type: "uint120";
                }];
                readonly internalType: "struct CommitmentPreimage";
                readonly name: "preimage";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32[3]";
                    readonly name: "encryptedBundle";
                    readonly type: "bytes32[3]";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "shieldKey";
                    readonly type: "bytes32";
                }];
                readonly internalType: "struct ShieldCiphertext";
                readonly name: "ciphertext";
                readonly type: "tuple";
            }];
            readonly internalType: "struct ShieldRequest[]";
            readonly name: "_shieldRequests";
            readonly type: "tuple[]";
        }];
        readonly name: "shield";
        readonly outputs: readonly [];
        readonly stateMutability: "payable";
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
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly name: "snarkSafetyVector";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "a";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256[2]";
                        readonly name: "x";
                        readonly type: "uint256[2]";
                    }, {
                        readonly internalType: "uint256[2]";
                        readonly name: "y";
                        readonly type: "uint256[2]";
                    }];
                    readonly internalType: "struct G2Point";
                    readonly name: "b";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "c";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct SnarkProof";
                readonly name: "proof";
                readonly type: "tuple";
            }, {
                readonly internalType: "bytes32";
                readonly name: "merkleRoot";
                readonly type: "bytes32";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "nullifiers";
                readonly type: "bytes32[]";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "commitments";
                readonly type: "bytes32[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint16";
                    readonly name: "treeNumber";
                    readonly type: "uint16";
                }, {
                    readonly internalType: "uint72";
                    readonly name: "minGasPrice";
                    readonly type: "uint72";
                }, {
                    readonly internalType: "enum UnshieldType";
                    readonly name: "unshield";
                    readonly type: "uint8";
                }, {
                    readonly internalType: "uint64";
                    readonly name: "chainID";
                    readonly type: "uint64";
                }, {
                    readonly internalType: "address";
                    readonly name: "adaptContract";
                    readonly type: "address";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "adaptParams";
                    readonly type: "bytes32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes32[4]";
                        readonly name: "ciphertext";
                        readonly type: "bytes32[4]";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "annotationData";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "memo";
                        readonly type: "bytes";
                    }];
                    readonly internalType: "struct CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct BoundParams";
                readonly name: "boundParams";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32";
                    readonly name: "npk";
                    readonly type: "bytes32";
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
                    readonly name: "token";
                    readonly type: "tuple";
                }, {
                    readonly internalType: "uint120";
                    readonly name: "value";
                    readonly type: "uint120";
                }];
                readonly internalType: "struct CommitmentPreimage";
                readonly name: "unshieldPreimage";
                readonly type: "tuple";
            }];
            readonly internalType: "struct Transaction[]";
            readonly name: "_transactions";
            readonly type: "tuple[]";
        }];
        readonly name: "sumCommitments";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }];
        readonly name: "tokenBlocklist";
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
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "a";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256[2]";
                        readonly name: "x";
                        readonly type: "uint256[2]";
                    }, {
                        readonly internalType: "uint256[2]";
                        readonly name: "y";
                        readonly type: "uint256[2]";
                    }];
                    readonly internalType: "struct G2Point";
                    readonly name: "b";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "c";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct SnarkProof";
                readonly name: "proof";
                readonly type: "tuple";
            }, {
                readonly internalType: "bytes32";
                readonly name: "merkleRoot";
                readonly type: "bytes32";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "nullifiers";
                readonly type: "bytes32[]";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "commitments";
                readonly type: "bytes32[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint16";
                    readonly name: "treeNumber";
                    readonly type: "uint16";
                }, {
                    readonly internalType: "uint72";
                    readonly name: "minGasPrice";
                    readonly type: "uint72";
                }, {
                    readonly internalType: "enum UnshieldType";
                    readonly name: "unshield";
                    readonly type: "uint8";
                }, {
                    readonly internalType: "uint64";
                    readonly name: "chainID";
                    readonly type: "uint64";
                }, {
                    readonly internalType: "address";
                    readonly name: "adaptContract";
                    readonly type: "address";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "adaptParams";
                    readonly type: "bytes32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes32[4]";
                        readonly name: "ciphertext";
                        readonly type: "bytes32[4]";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "annotationData";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "memo";
                        readonly type: "bytes";
                    }];
                    readonly internalType: "struct CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct BoundParams";
                readonly name: "boundParams";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32";
                    readonly name: "npk";
                    readonly type: "bytes32";
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
                    readonly name: "token";
                    readonly type: "tuple";
                }, {
                    readonly internalType: "uint120";
                    readonly name: "value";
                    readonly type: "uint120";
                }];
                readonly internalType: "struct CommitmentPreimage";
                readonly name: "unshieldPreimage";
                readonly type: "tuple";
            }];
            readonly internalType: "struct Transaction[]";
            readonly name: "_transactions";
            readonly type: "tuple[]";
        }];
        readonly name: "transact";
        readonly outputs: readonly [];
        readonly stateMutability: "payable";
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
        readonly name: "treeNumber";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
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
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "bytes32";
                readonly name: "npk";
                readonly type: "bytes32";
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
                readonly name: "token";
                readonly type: "tuple";
            }, {
                readonly internalType: "uint120";
                readonly name: "value";
                readonly type: "uint120";
            }];
            readonly internalType: "struct CommitmentPreimage";
            readonly name: "_note";
            readonly type: "tuple";
        }];
        readonly name: "validateCommitmentPreimage";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "a";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256[2]";
                        readonly name: "x";
                        readonly type: "uint256[2]";
                    }, {
                        readonly internalType: "uint256[2]";
                        readonly name: "y";
                        readonly type: "uint256[2]";
                    }];
                    readonly internalType: "struct G2Point";
                    readonly name: "b";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "c";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct SnarkProof";
                readonly name: "proof";
                readonly type: "tuple";
            }, {
                readonly internalType: "bytes32";
                readonly name: "merkleRoot";
                readonly type: "bytes32";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "nullifiers";
                readonly type: "bytes32[]";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "commitments";
                readonly type: "bytes32[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint16";
                    readonly name: "treeNumber";
                    readonly type: "uint16";
                }, {
                    readonly internalType: "uint72";
                    readonly name: "minGasPrice";
                    readonly type: "uint72";
                }, {
                    readonly internalType: "enum UnshieldType";
                    readonly name: "unshield";
                    readonly type: "uint8";
                }, {
                    readonly internalType: "uint64";
                    readonly name: "chainID";
                    readonly type: "uint64";
                }, {
                    readonly internalType: "address";
                    readonly name: "adaptContract";
                    readonly type: "address";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "adaptParams";
                    readonly type: "bytes32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes32[4]";
                        readonly name: "ciphertext";
                        readonly type: "bytes32[4]";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "annotationData";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "memo";
                        readonly type: "bytes";
                    }];
                    readonly internalType: "struct CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct BoundParams";
                readonly name: "boundParams";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32";
                    readonly name: "npk";
                    readonly type: "bytes32";
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
                    readonly name: "token";
                    readonly type: "tuple";
                }, {
                    readonly internalType: "uint120";
                    readonly name: "value";
                    readonly type: "uint120";
                }];
                readonly internalType: "struct CommitmentPreimage";
                readonly name: "unshieldPreimage";
                readonly type: "tuple";
            }];
            readonly internalType: "struct Transaction";
            readonly name: "_transaction";
            readonly type: "tuple";
        }];
        readonly name: "validateTransaction";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "a";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256[2]";
                        readonly name: "x";
                        readonly type: "uint256[2]";
                    }, {
                        readonly internalType: "uint256[2]";
                        readonly name: "y";
                        readonly type: "uint256[2]";
                    }];
                    readonly internalType: "struct G2Point";
                    readonly name: "b";
                    readonly type: "tuple";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct G1Point";
                    readonly name: "c";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct SnarkProof";
                readonly name: "proof";
                readonly type: "tuple";
            }, {
                readonly internalType: "bytes32";
                readonly name: "merkleRoot";
                readonly type: "bytes32";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "nullifiers";
                readonly type: "bytes32[]";
            }, {
                readonly internalType: "bytes32[]";
                readonly name: "commitments";
                readonly type: "bytes32[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint16";
                    readonly name: "treeNumber";
                    readonly type: "uint16";
                }, {
                    readonly internalType: "uint72";
                    readonly name: "minGasPrice";
                    readonly type: "uint72";
                }, {
                    readonly internalType: "enum UnshieldType";
                    readonly name: "unshield";
                    readonly type: "uint8";
                }, {
                    readonly internalType: "uint64";
                    readonly name: "chainID";
                    readonly type: "uint64";
                }, {
                    readonly internalType: "address";
                    readonly name: "adaptContract";
                    readonly type: "address";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "adaptParams";
                    readonly type: "bytes32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes32[4]";
                        readonly name: "ciphertext";
                        readonly type: "bytes32[4]";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "annotationData";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes";
                        readonly name: "memo";
                        readonly type: "bytes";
                    }];
                    readonly internalType: "struct CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct BoundParams";
                readonly name: "boundParams";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32";
                    readonly name: "npk";
                    readonly type: "bytes32";
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
                    readonly name: "token";
                    readonly type: "tuple";
                }, {
                    readonly internalType: "uint120";
                    readonly name: "value";
                    readonly type: "uint120";
                }];
                readonly internalType: "struct CommitmentPreimage";
                readonly name: "unshieldPreimage";
                readonly type: "tuple";
            }];
            readonly internalType: "struct Transaction";
            readonly name: "_transaction";
            readonly type: "tuple";
        }];
        readonly name: "verify";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "string";
                readonly name: "artifactsIPFSHash";
                readonly type: "string";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point";
                readonly name: "alpha1";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "beta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "gamma2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "delta2";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point[]";
                readonly name: "ic";
                readonly type: "tuple[]";
            }];
            readonly internalType: "struct VerifyingKey";
            readonly name: "_verifyingKey";
            readonly type: "tuple";
        }, {
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point";
                readonly name: "a";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256[2]";
                    readonly name: "x";
                    readonly type: "uint256[2]";
                }, {
                    readonly internalType: "uint256[2]";
                    readonly name: "y";
                    readonly type: "uint256[2]";
                }];
                readonly internalType: "struct G2Point";
                readonly name: "b";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint256";
                    readonly name: "x";
                    readonly type: "uint256";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "y";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct G1Point";
                readonly name: "c";
                readonly type: "tuple";
            }];
            readonly internalType: "struct SnarkProof";
            readonly name: "_proof";
            readonly type: "tuple";
        }, {
            readonly internalType: "uint256[]";
            readonly name: "_inputs";
            readonly type: "uint256[]";
        }];
        readonly name: "verifyProof";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly name: "zeros";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "treeNumber";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "startPosition";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256[]";
            readonly name: "hash";
            readonly type: "uint256[]";
        }, {
            readonly components: readonly [{
                readonly internalType: "uint256[4]";
                readonly name: "ciphertext";
                readonly type: "uint256[4]";
            }, {
                readonly internalType: "uint256[2]";
                readonly name: "ephemeralKeys";
                readonly type: "uint256[2]";
            }, {
                readonly internalType: "uint256[]";
                readonly name: "memo";
                readonly type: "uint256[]";
            }];
            readonly indexed: false;
            readonly internalType: "struct RailgunLogic.CommitmentCiphertextLegacy[]";
            readonly name: "ciphertext";
            readonly type: "tuple[]";
        }];
        readonly name: "CommitmentBatch";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "treeNumber";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "startPosition";
            readonly type: "uint256";
        }, {
            readonly components: readonly [{
                readonly internalType: "uint256";
                readonly name: "npk";
                readonly type: "uint256";
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
                readonly internalType: "struct TokenDataLegacy";
                readonly name: "token";
                readonly type: "tuple";
            }, {
                readonly internalType: "uint120";
                readonly name: "value";
                readonly type: "uint120";
            }];
            readonly indexed: false;
            readonly internalType: "struct CommitmentPreimageLegacy[]";
            readonly name: "commitments";
            readonly type: "tuple[]";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256[2][]";
            readonly name: "encryptedRandom";
            readonly type: "uint256[2][]";
        }];
        readonly name: "GeneratedCommitmentBatch";
        readonly type: "event";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "treeNumber";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256[]";
            readonly name: "nullifier";
            readonly type: "uint256[]";
        }];
        readonly name: "Nullifiers";
        readonly type: "event";
    }];
    static createInterface(): RailgunSmartWallet_Legacy_PreMar23Interface;
    static connect(address: string, runner?: ContractRunner | null): RailgunSmartWallet_Legacy_PreMar23;
}
