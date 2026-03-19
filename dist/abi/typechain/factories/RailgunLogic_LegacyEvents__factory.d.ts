import { type ContractRunner } from "ethers";
import type { RailgunLogic_LegacyEvents, RailgunLogic_LegacyEventsInterface } from "../RailgunLogic_LegacyEvents";
export declare class RailgunLogic_LegacyEvents__factory {
    static readonly abi: readonly [{
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: true;
            readonly internalType: "address";
            readonly name: "token";
            readonly type: "address";
        }];
        readonly name: "AddToBlacklist";
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
            readonly internalType: "struct CommitmentCiphertext[]";
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
            readonly name: "depositFee";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "withdrawFee";
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
        readonly name: "RemoveFromBlacklist";
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
        readonly name: "SNARK_BYPASS";
        readonly outputs: readonly [{
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "ZERO_VALUE";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address[]";
            readonly name: "_tokens";
            readonly type: "address[]";
        }];
        readonly name: "addToBlacklist";
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
            readonly name: "_depositFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint120";
            readonly name: "_withdrawFee";
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
        readonly inputs: readonly [];
        readonly name: "depositFee";
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
                readonly internalType: "struct TokenData";
                readonly name: "token";
                readonly type: "tuple";
            }, {
                readonly internalType: "uint120";
                readonly name: "value";
                readonly type: "uint120";
            }];
            readonly internalType: "struct CommitmentPreimage[]";
            readonly name: "_notes";
            readonly type: "tuple[]";
        }, {
            readonly internalType: "uint256[2][]";
            readonly name: "_encryptedRandom";
            readonly type: "uint256[2][]";
        }];
        readonly name: "generateDeposit";
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
        readonly name: "getTokenField";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
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
                readonly internalType: "enum WithdrawType";
                readonly name: "withdraw";
                readonly type: "uint8";
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
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "_left";
            readonly type: "uint256";
        }, {
            readonly internalType: "uint256";
            readonly name: "_right";
            readonly type: "uint256";
        }];
        readonly name: "hashLeftRight";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
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
            readonly name: "_depositFee";
            readonly type: "uint120";
        }, {
            readonly internalType: "uint120";
            readonly name: "_withdrawFee";
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
        readonly name: "merkleRoot";
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
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
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
        readonly name: "removeFromBlacklist";
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
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
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
            readonly internalType: "address";
            readonly name: "";
            readonly type: "address";
        }];
        readonly name: "tokenBlacklist";
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
                readonly internalType: "uint256";
                readonly name: "merkleRoot";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256[]";
                readonly name: "nullifiers";
                readonly type: "uint256[]";
            }, {
                readonly internalType: "uint256[]";
                readonly name: "commitments";
                readonly type: "uint256[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint16";
                    readonly name: "treeNumber";
                    readonly type: "uint16";
                }, {
                    readonly internalType: "enum WithdrawType";
                    readonly name: "withdraw";
                    readonly type: "uint8";
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
                    readonly internalType: "struct CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct BoundParams";
                readonly name: "boundParams";
                readonly type: "tuple";
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
                    readonly internalType: "struct TokenData";
                    readonly name: "token";
                    readonly type: "tuple";
                }, {
                    readonly internalType: "uint120";
                    readonly name: "value";
                    readonly type: "uint120";
                }];
                readonly internalType: "struct CommitmentPreimage";
                readonly name: "withdrawPreimage";
                readonly type: "tuple";
            }, {
                readonly internalType: "address";
                readonly name: "overrideOutput";
                readonly type: "address";
            }];
            readonly internalType: "struct Transaction[]";
            readonly name: "_transactions";
            readonly type: "tuple[]";
        }];
        readonly name: "transact";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
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
                readonly internalType: "uint256";
                readonly name: "merkleRoot";
                readonly type: "uint256";
            }, {
                readonly internalType: "uint256[]";
                readonly name: "nullifiers";
                readonly type: "uint256[]";
            }, {
                readonly internalType: "uint256[]";
                readonly name: "commitments";
                readonly type: "uint256[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint16";
                    readonly name: "treeNumber";
                    readonly type: "uint16";
                }, {
                    readonly internalType: "enum WithdrawType";
                    readonly name: "withdraw";
                    readonly type: "uint8";
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
                    readonly internalType: "struct CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct BoundParams";
                readonly name: "boundParams";
                readonly type: "tuple";
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
                    readonly internalType: "struct TokenData";
                    readonly name: "token";
                    readonly type: "tuple";
                }, {
                    readonly internalType: "uint120";
                    readonly name: "value";
                    readonly type: "uint120";
                }];
                readonly internalType: "struct CommitmentPreimage";
                readonly name: "withdrawPreimage";
                readonly type: "tuple";
            }, {
                readonly internalType: "address";
                readonly name: "overrideOutput";
                readonly type: "address";
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
        readonly inputs: readonly [];
        readonly name: "withdrawFee";
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
        readonly name: "zeros";
        readonly outputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "";
            readonly type: "uint256";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }];
    static createInterface(): RailgunLogic_LegacyEventsInterface;
    static connect(address: string, runner?: ContractRunner | null): RailgunLogic_LegacyEvents;
}
