//
//  BlockTransactionHash.swift
//
//
//  Created by 薛跃杰 on 2024/2/28.
//

import Foundation

public class BlockTransactionHash: Persistable, Hashable {
    
    public static let BLOCKS_TO_CONFIRM = 6
    public static let BLOCKS_TO_FULLY_CONFIRM = 100

    public let hash: Data
    public let height: Int
    public let date: Date
    public let fee: Int64?

    public var label: String

    public init(hash: Data, height: Int, date: Date, fee: Int64?, label: String) {
        self.hash = hash
        self.height = height
        self.date = date
        self.fee = fee
        self.label = label
        super.init(id: 0)
    }

    public func getHashAsString() -> String {
        return hash.toHexString()
    }
    public func getComparisonHeight() -> Int {
        return (height > 0 ? height : (height == -1 ? Int.max : Int.max - height - 1))
    }

    public func getConfirmations(currentBlockHeight: Int) -> Int {
        if height <= 0 {
            return 0
        }

        return currentBlockHeight - height + 1
    }

    public func toString() -> String {
        return hash.toHexString()
    }

    public func equals(o: Any?) -> Bool {
        if o == nil || type(of: self) != type(of: o) { return false }
        guard let that = o as? BlockTransactionHash else { return false }
        return hash == that.hash && height == that.height
    }


    public func hashCode() -> Int {
        return  hash.hashValue ^ height
    }

    public func compareTo(reference: BlockTransactionHash) -> Int {
        if height != reference.height {
            return getComparisonHeight() - reference.getComparisonHeight()
        }

        for i in stride(from: hash.count - 1, through: 0, by: -1) {
            let thisByte = Int(hash.bytes[i] & 0xff)
            let otherByte = Int(reference.hash.bytes[i] & 0xff)
            if thisByte > otherByte {
                return 1
            }
            if thisByte < otherByte {
                return -1
            }
        }
        return 0
    }
    
    public static func == (lhs: BlockTransactionHash, rhs: BlockTransactionHash) -> Bool {
        return lhs.hash == rhs.hash && lhs.height == rhs.height && lhs.date == rhs.date && lhs.fee == rhs.fee
    }
    
    public var hashValue: Int {
        return hashCode()
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.hash)
        hasher.combine(self.height)
        hasher.combine(self.date)
        hasher.combine(self.fee)
        hasher.combine(self.label)
    }
}
