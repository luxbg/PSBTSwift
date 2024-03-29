//
//  BlockTransaction.swift
//
//
//  Created by 薛跃杰 on 2024/2/28.
//

import Foundation

public class BlockTransaction: BlockTransactionHash, Comparable {
    public let transaction: Transaction?
    public let blockHash: Data?

    public var spending = Set<HashIndex>()
    public var funding = Set<HashIndex>()

    public init(hash: Data, height: Int, date: Date, fee: Int64?, transaction: Transaction?, blockHash: Data?, label: String?) {
        self.transaction = transaction
        self.blockHash = blockHash
        super.init(hash: hash, height: height, date: date, fee: fee, label: label ?? "")

        if let transaction = transaction {
            for txInput in transaction.inputs {
                spending.insert(HashIndex(hash: txInput.outpoint!.hashData, index: Int64(txInput.outpoint!.index)))
            }
            for txOutput in transaction.outputs {
                funding.insert(HashIndex(hash: hash, index: Int64(txOutput.getIndex())))
            }
        }
    }
    public func getFeeRate() -> Double? {
        if let fee = fee, let transaction = transaction {
            let vSize = Double(transaction.getVirtualSize())
            return Double(fee) / vSize
        }

        return nil
    }

    public static func < (lhs: BlockTransaction, rhs: BlockTransaction) -> Bool {
        let blockOrder = lhs.compareBlockOrder(to: rhs)
        if blockOrder != 0 {
            return blockOrder < 0
        }

        return lhs.compareTo(reference: rhs) < 0
    }

    public func compareBlockOrder(to blkTx: BlockTransaction) -> Int {
        if height != blkTx.height {
            return getComparisonHeight() - blkTx.getComparisonHeight()
        }

        if !Set(spending).isDisjoint(with: blkTx.funding) {
            return 1
        }

        if !Set(blkTx.spending).isDisjoint(with: funding) {
            return -1
        }

        return 0
    }
}
