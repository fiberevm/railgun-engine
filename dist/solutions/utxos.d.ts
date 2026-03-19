import { TXO } from '../models/txo-types';
export declare const calculateTotalSpend: (utxos: TXO[]) => bigint;
export declare const filterZeroUTXOs: (utxos: TXO[]) => TXO[];
export declare const sortUTXOsByAscendingValue: (utxos: TXO[]) => void;
