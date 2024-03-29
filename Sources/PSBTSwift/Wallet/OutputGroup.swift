//
//  OutputGroup.swift
//
//
//  Created by 薛跃杰 on 2024/2/28.
//

import Foundation

public class OutputGroup {
    public var utxos: [BlockTransactionHashIndex] = []
    public let scriptType: ScriptType
    public let walletBlockHeight: Int
    public let inputWeightUnits: Int64
    public let feeRate: Double
    public let longTermFeeRate: Double
    public var value: Int64 = 0
    public var effectiveValue: Int64 = 0
    public var fee: Int64 = 0
    public var longTermFee: Int64 = 0
    public var depth: Int = Int.max
    public var allInputsFromWallet: Bool = true
    public var spendLast: Bool = false

    public init(scriptType: ScriptType, walletBlockHeight: Int, inputWeightUnits: Int64, feeRate: Double, longTermFeeRate: Double) {
        self.scriptType = scriptType
        self.walletBlockHeight = walletBlockHeight
        self.inputWeightUnits = inputWeightUnits
        self.feeRate = feeRate
        self.longTermFeeRate = longTermFeeRate
    }

    public func add(utxo: BlockTransactionHashIndex, allInputsFromWallet: Bool, spendLast: Bool) {
        utxos.append(utxo)
        value += utxo.value
        effectiveValue += utxo.value - Int64(Double(inputWeightUnits) * feeRate / Double(Transaction.WITNESS_SCALE_FACTOR))
        fee += Int64(Double(inputWeightUnits) * feeRate / Double(Transaction.WITNESS_SCALE_FACTOR))
        longTermFee += Int64(Double(inputWeightUnits) * longTermFeeRate / Double(Transaction.WITNESS_SCALE_FACTOR))
        depth = utxo.height <= 0 ? 0 : min(depth, walletBlockHeight - utxo.height + 1)
        self.allInputsFromWallet = self.allInputsFromWallet && allInputsFromWallet
        self.spendLast = self.spendLast || spendLast
    }

    public func remove(utxo: BlockTransactionHashIndex) {
        if let index = utxos.firstIndex(of: utxo) {
            utxos.remove(at: index)
            value -= utxo.value
            effectiveValue -= (utxo.value - Int64(Double(inputWeightUnits) * feeRate / Double(Transaction.WITNESS_SCALE_FACTOR)))
            fee -= Int64(Double(inputWeightUnits) * feeRate / Double(Transaction.WITNESS_SCALE_FACTOR))
            longTermFee -= Int64(Double(inputWeightUnits) * longTermFeeRate / Double(Transaction.WITNESS_SCALE_FACTOR))
        }
    }
}

public class Filter {
    private let minWalletConfirmations: Int
    private let minExternalConfirmations: Int
    private let includeSpendLast: Bool

    public init(minWalletConfirmations: Int, minExternalConfirmations: Int, includeSpendLast: Bool) {
        self.minWalletConfirmations = minWalletConfirmations
        self.minExternalConfirmations = minExternalConfirmations
        self.includeSpendLast = includeSpendLast
    }

    public func isEligible(outputGroup: OutputGroup) -> Bool {
        if outputGroup.allInputsFromWallet {
            return outputGroup.depth >= minWalletConfirmations && (includeSpendLast || !outputGroup.spendLast)
        }

        return outputGroup.depth >= minExternalConfirmations && (includeSpendLast || !outputGroup.spendLast)
    }
}
