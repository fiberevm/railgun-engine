import { type ContractRunner } from "ethers";
import type { RelayAdapt, RelayAdaptInterface } from "../RelayAdapt";
export declare class RelayAdapt__factory {
    static readonly abi: readonly [{
        readonly inputs: readonly [{
            readonly internalType: "contract RailgunSmartWallet";
            readonly name: "_railgun";
            readonly type: "address";
        }, {
            readonly internalType: "contract IWBase";
            readonly name: "_wBase";
            readonly type: "address";
        }];
        readonly stateMutability: "nonpayable";
        readonly type: "constructor";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "callIndex";
            readonly type: "uint256";
        }, {
            readonly internalType: "bytes";
            readonly name: "revertReason";
            readonly type: "bytes";
        }];
        readonly name: "CallFailed";
        readonly type: "error";
    }, {
        readonly anonymous: false;
        readonly inputs: readonly [{
            readonly indexed: false;
            readonly internalType: "uint256";
            readonly name: "callIndex";
            readonly type: "uint256";
        }, {
            readonly indexed: false;
            readonly internalType: "bytes";
            readonly name: "revertReason";
            readonly type: "bytes";
        }];
        readonly name: "CallError";
        readonly type: "event";
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
        }, {
            readonly components: readonly [{
                readonly internalType: "bytes31";
                readonly name: "random";
                readonly type: "bytes31";
            }, {
                readonly internalType: "bool";
                readonly name: "requireSuccess";
                readonly type: "bool";
            }, {
                readonly internalType: "uint256";
                readonly name: "minGasLimit";
                readonly type: "uint256";
            }, {
                readonly components: readonly [{
                    readonly internalType: "address";
                    readonly name: "to";
                    readonly type: "address";
                }, {
                    readonly internalType: "bytes";
                    readonly name: "data";
                    readonly type: "bytes";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "value";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct RelayAdapt.Call[]";
                readonly name: "calls";
                readonly type: "tuple[]";
            }];
            readonly internalType: "struct RelayAdapt.ActionData";
            readonly name: "_actionData";
            readonly type: "tuple";
        }];
        readonly name: "getAdaptParams";
        readonly outputs: readonly [{
            readonly internalType: "bytes32";
            readonly name: "";
            readonly type: "bytes32";
        }];
        readonly stateMutability: "pure";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "bool";
            readonly name: "_requireSuccess";
            readonly type: "bool";
        }, {
            readonly components: readonly [{
                readonly internalType: "address";
                readonly name: "to";
                readonly type: "address";
            }, {
                readonly internalType: "bytes";
                readonly name: "data";
                readonly type: "bytes";
            }, {
                readonly internalType: "uint256";
                readonly name: "value";
                readonly type: "uint256";
            }];
            readonly internalType: "struct RelayAdapt.Call[]";
            readonly name: "_calls";
            readonly type: "tuple[]";
        }];
        readonly name: "multicall";
        readonly outputs: readonly [];
        readonly stateMutability: "payable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "railgun";
        readonly outputs: readonly [{
            readonly internalType: "contract RailgunSmartWallet";
            readonly name: "";
            readonly type: "address";
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
        }, {
            readonly components: readonly [{
                readonly internalType: "bytes31";
                readonly name: "random";
                readonly type: "bytes31";
            }, {
                readonly internalType: "bool";
                readonly name: "requireSuccess";
                readonly type: "bool";
            }, {
                readonly internalType: "uint256";
                readonly name: "minGasLimit";
                readonly type: "uint256";
            }, {
                readonly components: readonly [{
                    readonly internalType: "address";
                    readonly name: "to";
                    readonly type: "address";
                }, {
                    readonly internalType: "bytes";
                    readonly name: "data";
                    readonly type: "bytes";
                }, {
                    readonly internalType: "uint256";
                    readonly name: "value";
                    readonly type: "uint256";
                }];
                readonly internalType: "struct RelayAdapt.Call[]";
                readonly name: "calls";
                readonly type: "tuple[]";
            }];
            readonly internalType: "struct RelayAdapt.ActionData";
            readonly name: "_actionData";
            readonly type: "tuple";
        }];
        readonly name: "relay";
        readonly outputs: readonly [];
        readonly stateMutability: "payable";
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
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly components: readonly [{
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
                readonly internalType: "address";
                readonly name: "to";
                readonly type: "address";
            }, {
                readonly internalType: "uint256";
                readonly name: "value";
                readonly type: "uint256";
            }];
            readonly internalType: "struct RelayAdapt.TokenTransfer[]";
            readonly name: "_transfers";
            readonly type: "tuple[]";
        }];
        readonly name: "transfer";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "_amount";
            readonly type: "uint256";
        }];
        readonly name: "unwrapBase";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly inputs: readonly [];
        readonly name: "wBase";
        readonly outputs: readonly [{
            readonly internalType: "contract IWBase";
            readonly name: "";
            readonly type: "address";
        }];
        readonly stateMutability: "view";
        readonly type: "function";
    }, {
        readonly inputs: readonly [{
            readonly internalType: "uint256";
            readonly name: "_amount";
            readonly type: "uint256";
        }];
        readonly name: "wrapBase";
        readonly outputs: readonly [];
        readonly stateMutability: "nonpayable";
        readonly type: "function";
    }, {
        readonly stateMutability: "payable";
        readonly type: "receive";
    }];
    static createInterface(): RelayAdaptInterface;
    static connect(address: string, runner?: ContractRunner | null): RelayAdapt;
}
