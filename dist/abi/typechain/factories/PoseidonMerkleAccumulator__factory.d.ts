import { type ContractRunner } from "ethers";
import type { PoseidonMerkleAccumulator, PoseidonMerkleAccumulatorInterface } from "../PoseidonMerkleAccumulator";
export declare class PoseidonMerkleAccumulator__factory {
    static readonly abi: readonly [{
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly components: readonly [{
                readonly internalType: "bytes32[]";
                readonly name: "commitments";
                readonly type: "bytes32[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32[]";
                    readonly name: "nullifiers";
                    readonly type: "bytes32[]";
                }, {
                    readonly internalType: "uint8";
                    readonly name: "commitmentsCount";
                    readonly type: "uint8";
                }, {
                    readonly internalType: "uint32";
                    readonly name: "spendAccumulatorNumber";
                    readonly type: "uint32";
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
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "boundParamsHash";
                    readonly type: "bytes32";
                }];
                readonly internalType: "struct PoseidonMerkleAccumulator.TransactionConfiguration[]";
                readonly name: "transactions";
                readonly type: "tuple[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "address";
                    readonly name: "from";
                    readonly type: "address";
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
                    readonly name: "ciphertext";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct PoseidonMerkleAccumulator.ShieldConfiguration[]";
                readonly name: "shields";
                readonly type: "tuple[]";
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
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32";
                    readonly name: "tokenID";
                    readonly type: "bytes32";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "fee";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct PoseidonMerkleAccumulator.TreasuryFee[]";
                readonly name: "treasuryFees";
                readonly type: "tuple[]";
            }, {
                readonly internalType: "bytes";
                readonly name: "senderCiphertext";
                readonly type: "bytes";
            }];
            readonly indexed: false;
            readonly internalType: "struct PoseidonMerkleAccumulator.StateUpdate";
            readonly name: "update";
            readonly type: "tuple";
        }, {
            readonly indexed: false;
            readonly internalType: "uint32";
            readonly name: "accumulatorNumber";
            readonly type: "uint32";
        }, {
            readonly indexed: false;
            readonly internalType: "uint224";
            readonly name: "startPosition";
            readonly type: "uint224";
        }];
        readonly name: "AccumulatorStateUpdate";
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
        readonly inputs: readonly [];
        readonly name: "accumulatorNumber";
        readonly outputs: readonly [{
            readonly internalType: "uint32";
            readonly name: "";
            readonly type: "uint32";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "accumulatorRoot";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
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
            readonly internalType: "uint256";
            readonly name: "_newCommitments";
            readonly type: "uint256";
        }];
        readonly name: "getInsertionAccumulatorNumberAndStartingIndex";
        readonly outputs: readonly [{
            readonly internalType: "uint32";
            readonly name: "";
            readonly type: "uint32";
        }, {
            readonly internalType: "uint224";
            readonly name: "";
            readonly type: "uint224";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "address";
            readonly name: "_verifierRegistry";
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
        readonly name: "nextLeafIndex";
        readonly outputs: readonly [{
            readonly internalType: "uint224";
            readonly name: "";
            readonly type: "uint224";
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
        readonly name: "tokenVault";
        readonly outputs: readonly [{
            readonly internalType: "contract ITokenVault";
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
                readonly internalType: "bytes32[]";
                readonly name: "commitments";
                readonly type: "bytes32[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32[]";
                    readonly name: "nullifiers";
                    readonly type: "bytes32[]";
                }, {
                    readonly internalType: "uint8";
                    readonly name: "commitmentsCount";
                    readonly type: "uint8";
                }, {
                    readonly internalType: "uint32";
                    readonly name: "spendAccumulatorNumber";
                    readonly type: "uint32";
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
                }, {
                    readonly internalType: "bytes32";
                    readonly name: "boundParamsHash";
                    readonly type: "bytes32";
                }];
                readonly internalType: "struct PoseidonMerkleAccumulator.TransactionConfiguration[]";
                readonly name: "transactions";
                readonly type: "tuple[]";
            }, {
                readonly components: readonly [{
                    readonly internalType: "address";
                    readonly name: "from";
                    readonly type: "address";
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
                    readonly name: "ciphertext";
                    readonly type: "tuple";
                }];
                readonly internalType: "struct PoseidonMerkleAccumulator.ShieldConfiguration[]";
                readonly name: "shields";
                readonly type: "tuple[]";
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
            }, {
                readonly components: readonly [{
                    readonly internalType: "bytes32";
                    readonly name: "tokenID";
                    readonly type: "bytes32";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "fee";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct PoseidonMerkleAccumulator.TreasuryFee[]";
                readonly name: "treasuryFees";
                readonly type: "tuple[]";
            }, {
                readonly internalType: "bytes";
                readonly name: "senderCiphertext";
                readonly type: "bytes";
            }];
            readonly internalType: "struct PoseidonMerkleAccumulator.StateUpdate";
            readonly name: "_update";
            readonly type: "tuple";
        }];
        readonly name: "updateAccumulator";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
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
    }];
    static createInterface(): PoseidonMerkleAccumulatorInterface;
    static connect(address: string, runner?: ContractRunner | null): PoseidonMerkleAccumulator;
}
