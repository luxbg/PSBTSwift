//
//  BlockTransactionHashIndex.swift
//
//
//  Created by 薛跃杰 on 2024/2/28.
//

import Foundation

public class BlockTransactionHashIndex: BlockTransactionHash, Comparable {
    public let index: Int64
    public let value: Int64
    public var spentBy: BlockTransactionHashIndex?
    public var status: Status?

    public init(hash: Data, height: Int, date: Date, fee: Int64?, index: Int64, value: Int64, spentBy: BlockTransactionHashIndex?, label: String?) {
        self.index = index
        self.value = value
        self.spentBy = spentBy
        super.init(hash: hash, height: height, date: date, fee: fee, label: label ?? "")
    }

    public func isSpent() -> Bool {
        return spentBy != nil
    }
    
    public override func toString() -> String {
        return "\(hash.toHexString()):\(index)"
    }

    public static func == (lhs: BlockTransactionHashIndex, rhs: BlockTransactionHashIndex) -> Bool {
        return lhs.hash == rhs.hash && lhs.index == rhs.index && lhs.value == rhs.value && lhs.spentBy == rhs.spentBy
    }

    public override func hash(into hasher: inout Hasher) {
        hasher.combine(hash)
        hasher.combine(index)
        hasher.combine(value)
        hasher.combine(spentBy)
    }

    public static func < (lhs: BlockTransactionHashIndex, rhs: BlockTransactionHashIndex) -> Bool {
        let diff = lhs.compareTo(reference: rhs)
        if diff != 0 {
            return diff < 0
        }

        let diffIndex = lhs.index - rhs.index
        if diffIndex != 0 {
            return diffIndex < 0
        }

        let diffValue = lhs.value - rhs.value
        if diffValue != 0 {
            return diffValue < 0
        }

        if lhs.spentBy == nil {
            return rhs.spentBy != nil
        } else {
            return rhs.spentBy == nil || lhs.spentBy! < rhs.spentBy!
        }
    }

    public func copy() -> BlockTransactionHashIndex {
        let copy = BlockTransactionHashIndex(hash: hash, height: height, date: date, fee: fee, index: index, value: value, spentBy: spentBy?.copy(), label: label)
        copy.id = id
        return copy
    }
}
