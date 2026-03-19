import { type ContractRunner } from "ethers";
import type { PoseidonMerkleVerifier, PoseidonMerkleVerifierInterface } from "../PoseidonMerkleVerifier";
export declare class PoseidonMerkleVerifier__factory {
    static readonly abi: readonly [{
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
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct BN254G1Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G1Point[]";
                    readonly name: "ic";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct Groth16.VerifyingKey";
                readonly name: "verifyingKey";
                readonly type: "tuple";
            }];
            readonly indexed: false;
            readonly internalType: "struct PoseidonMerkleVerifier.VerifyingKeyArtifact";
            readonly name: "verifyingKey";
            readonly type: "tuple";
        }];
        readonly name: "VerifyingKeySet";
        readonly type: "event";
    }, {
        readonly inputs: readonly [];
        readonly name: "accumulator";
        readonly outputs: readonly [{
            readonly internalType: "contract PoseidonMerkleAccumulator";
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
        readonly name: "addVector";
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
                    readonly internalType: "struct BN254G1Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G1Point";
                    readonly name: "c";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct Groth16.Proof";
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
                    readonly internalType: "uint32";
                    readonly name: "treeNumber";
                    readonly type: "uint32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes";
                        readonly name: "ciphertext";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }];
                    readonly internalType: "struct PoseidonMerkleAccumulator.CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct PoseidonMerkleVerifier.TransactionBoundParams";
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
            readonly internalType: "struct PoseidonMerkleVerifier.Transaction[]";
            readonly name: "_transactions";
            readonly type: "tuple[]";
        }, {
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly internalType: "bytes32[3]";
                    readonly name: "encryptedBundle";
                    readonly type: "bytes32[3]";
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "shieldKey";
                    readonly type: "bytes32";
                }];
                readonly internalType: "struct PoseidonMerkleAccumulator.ShieldCiphertext";
                readonly name: "ciphertext";
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
                readonly name: "preimage";
                readonly type: "tuple";
            }];
            readonly internalType: "struct PoseidonMerkleVerifier.ShieldRequest[]";
            readonly name: "_shieldRequests";
            readonly type: "tuple[]";
        }, {
            readonly components: readonly [{
                readonly internalType: "uint128";
                readonly name: "minGasPrice";
                readonly type: "uint128";
            }, {
                readonly internalType: "uint128";
                readonly name: "chainID";
                readonly type: "uint128";
            }, {
                readonly internalType: "bytes";
                readonly name: "senderCiphertext";
                readonly type: "bytes";
            }, {
                readonly internalType: "address";
                readonly name: "to";
                readonly type: "address";
            }, {
                readonly internalType: "bytes";
                readonly name: "data";
                readonly type: "bytes";
            }];
            readonly internalType: "struct PoseidonMerkleVerifier.GlobalBoundParams";
            readonly name: "_globalBoundParams";
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
            readonly internalType: "struct PoseidonMerkleAccumulator.ShieldCiphertext";
            readonly name: "unshieldChangeCiphertext";
            readonly type: "tuple";
        }];
        readonly name: "execute";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
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
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct BN254G1Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G1Point[]";
                    readonly name: "ic";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct Groth16.VerifyingKey";
                readonly name: "verifyingKey";
                readonly type: "tuple";
            }];
            readonly internalType: "struct PoseidonMerkleVerifier.VerifyingKeyArtifact";
            readonly name: "";
            readonly type: "tuple";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly components: readonly [{
                    readonly internalType: "uint32";
                    readonly name: "treeNumber";
                    readonly type: "uint32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes";
                        readonly name: "ciphertext";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }];
                    readonly internalType: "struct PoseidonMerkleAccumulator.CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct PoseidonMerkleVerifier.TransactionBoundParams";
                readonly name: "local";
                readonly type: "tuple";
            }, {
                readonly components: readonly [{
                    readonly internalType: "uint128";
                    readonly name: "minGasPrice";
                    readonly type: "uint128";
                }, {
                    readonly internalType: "uint128";
                    readonly name: "chainID";
                    readonly type: "uint128";
                }, {
                    readonly internalType: "bytes";
                    readonly name: "senderCiphertext";
                    readonly type: "bytes";
                }, {
                    readonly internalType: "address";
                    readonly name: "to";
                    readonly type: "address";
                }, {
                    readonly internalType: "bytes";
                    readonly name: "data";
                    readonly type: "bytes";
                }];
                readonly internalType: "struct PoseidonMerkleVerifier.GlobalBoundParams";
                readonly name: "global";
                readonly type: "tuple";
            }];
            readonly internalType: "struct PoseidonMerkleVerifier.BoundParams";
            readonly name: "_boundParams";
            readonly type: "tuple";
        }];
        readonly name: "hashBoundParams";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
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
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_accumulator";
            readonly type: "address";
        }, {
            readonly internalType: "address";
            readonly name: "_tokenVault";
            readonly type: "address";
        }, {
            readonly internalType: "address";
            readonly name: "_owner";
            readonly type: "address";
        }];
        readonly name: "initialize";
        readonly outputs: readonly [];
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
                    readonly components: readonly [{
                        readonly internalType: "uint256";
                        readonly name: "x";
                        readonly type: "uint256";
                    }, {
                        readonly internalType: "uint256";
                        readonly name: "y";
                        readonly type: "uint256";
                    }];
                    readonly internalType: "struct BN254G1Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G1Point[]";
                    readonly name: "ic";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct Groth16.VerifyingKey";
                readonly name: "verifyingKey";
                readonly type: "tuple";
            }];
            readonly internalType: "struct PoseidonMerkleVerifier.VerifyingKeyArtifact";
            readonly name: "_verifyingKey";
            readonly type: "tuple";
        }];
        readonly name: "setVerificationKey";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "tokenVault";
        readonly outputs: readonly [{
            readonly internalType: "contract TokenVault";
            readonly name: "";
            readonly type: "address";
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
            readonly name: "_preimage";
            readonly type: "tuple";
        }];
        readonly name: "validateCommitmentPreimage";
        readonly outputs: readonly [];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "uint128";
                readonly name: "minGasPrice";
                readonly type: "uint128";
            }, {
                readonly internalType: "uint128";
                readonly name: "chainID";
                readonly type: "uint128";
            }, {
                readonly internalType: "bytes";
                readonly name: "senderCiphertext";
                readonly type: "bytes";
            }, {
                readonly internalType: "address";
                readonly name: "to";
                readonly type: "address";
            }, {
                readonly internalType: "bytes";
                readonly name: "data";
                readonly type: "bytes";
            }];
            readonly internalType: "struct PoseidonMerkleVerifier.GlobalBoundParams";
            readonly name: "_globalBoundParams";
            readonly type: "tuple";
        }];
        readonly name: "validateGlobalBoundParams";
        readonly outputs: readonly [];
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
                    readonly internalType: "struct BN254G1Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G1Point";
                    readonly name: "c";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct Groth16.Proof";
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
                    readonly internalType: "uint32";
                    readonly name: "treeNumber";
                    readonly type: "uint32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes";
                        readonly name: "ciphertext";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }];
                    readonly internalType: "struct PoseidonMerkleAccumulator.CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct PoseidonMerkleVerifier.TransactionBoundParams";
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
            readonly internalType: "struct PoseidonMerkleVerifier.Transaction";
            readonly name: "_transaction";
            readonly type: "tuple";
        }, {
            readonly components: readonly [{
                readonly internalType: "uint128";
                readonly name: "minGasPrice";
                readonly type: "uint128";
            }, {
                readonly internalType: "uint128";
                readonly name: "chainID";
                readonly type: "uint128";
            }, {
                readonly internalType: "bytes";
                readonly name: "senderCiphertext";
                readonly type: "bytes";
            }, {
                readonly internalType: "address";
                readonly name: "to";
                readonly type: "address";
            }, {
                readonly internalType: "bytes";
                readonly name: "data";
                readonly type: "bytes";
            }];
            readonly internalType: "struct PoseidonMerkleVerifier.GlobalBoundParams";
            readonly name: "_globalBoundParams";
            readonly type: "tuple";
        }];
        readonly name: "validateTransaction";
        readonly outputs: readonly [{
            readonly internalType: "uint8";
            readonly name: "";
            readonly type: "uint8";
        }, {
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
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
                    readonly internalType: "struct BN254G1Point";
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
                    readonly internalType: "struct BN254G2Point";
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
                    readonly internalType: "struct BN254G1Point";
                    readonly name: "c";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct Groth16.Proof";
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
                    readonly internalType: "uint32";
                    readonly name: "treeNumber";
                    readonly type: "uint32";
                }, {
                    readonly components: readonly [{
                        readonly internalType: "bytes";
                        readonly name: "ciphertext";
                        readonly type: "bytes";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedSenderViewingKey";
                        readonly type: "bytes32";
                    }, {
                        readonly internalType: "bytes32";
                        readonly name: "blindedReceiverViewingKey";
                        readonly type: "bytes32";
                    }];
                    readonly internalType: "struct PoseidonMerkleAccumulator.CommitmentCiphertext[]";
                    readonly name: "commitmentCiphertext";
                    readonly type: "tuple[]";
                }];
                readonly internalType: "struct PoseidonMerkleVerifier.TransactionBoundParams";
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
            readonly internalType: "struct PoseidonMerkleVerifier.Transaction";
            readonly name: "_transaction";
            readonly type: "tuple";
        }, {
            readonly internalType: "bytes32";
            readonly name: "_boundParamsHash";
            readonly type: "bytes32";
        }];
        readonly name: "verifyTransactionProof";
        readonly outputs: readonly [{
            readonly internalType: "bool";
            readonly name: "";
            readonly type: "bool";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }];
    static createInterface(): PoseidonMerkleVerifierInterface;
    static connect(address: string, runner?: ContractRunner | null): PoseidonMerkleVerifier;
}
