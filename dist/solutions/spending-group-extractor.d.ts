import { AddressData } from '../key-derivation/bech32';
import { SpendingSolutionGroup } from '../models/txo-types';
import { TokenData, TokenType } from '../models';
type ExtractedSpendingSolutionGroupsData = {
    utxoTxids: string[];
    utxoValues: bigint[];
    outputValues: bigint[];
    outputAddressDatas: AddressData[];
    tokenData: TokenData;
};
type SerializedSpendingSolutionGroupsData = {
    utxoTxids: string[];
    utxoValues: string[];
    outputValues: string[];
    outputAddresses: string[];
    tokenAddress: string;
    tokenType: TokenType;
    tokenSubID: string;
    tokenHash: string;
};
export declare const serializeExtractedSpendingSolutionGroupsData: (datas: ExtractedSpendingSolutionGroupsData[]) => SerializedSpendingSolutionGroupsData[];
export declare const extractSpendingSolutionGroupsData: (spendingSolutionGroups: SpendingSolutionGroup[]) => ExtractedSpendingSolutionGroupsData[];
export {};
