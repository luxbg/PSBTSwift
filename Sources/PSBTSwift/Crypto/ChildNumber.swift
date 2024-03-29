//
//  ChildNumber.swift
//
//
//  Created by 薛跃杰 on 2024/2/19.
//

import Foundation

public struct ChildNumber: Hashable, Equatable {
    public static let HARDENED_BIT = 0x80000000
    public static let ZERO = try! ChildNumber(childNumber: 0, isHardened: false)
    public static let ZERO_HARDENED = try! ChildNumber(childNumber: 0, isHardened: true)
    public static let ONE = try! ChildNumber(childNumber: 1, isHardened: false)
    public static let ONE_HARDENED = try! ChildNumber(childNumber: 1, isHardened: true)

    public let i: Int

    public init(childNumber: Int, isHardened: Bool) throws {
        if ChildNumber.hasHardenedBit(a: childNumber) {
            throw PSBTError.message("Most significant bit is reserved and shouldn't be set: \(childNumber)")
        }
        i = isHardened ? (childNumber | ChildNumber.HARDENED_BIT) : childNumber
    }

    public init(i: Int) {
        self.i = i
    }

    public static func hasHardenedBit(a: Int) -> Bool {
        return (a & HARDENED_BIT) != 0
    }

    public func isHardened() -> Bool {
        return ChildNumber.hasHardenedBit(a: i)
    }

    public func num() -> Int {
        return i & (~0x80000000)
    }

    public func toString(useApostrophes: Bool = true) -> String {
        let num = num()
        return "\(num)" + (isHardened() ? (useApostrophes ? "'" : "h") : "")
    }

    func equals(_ o: Any?) -> Bool {
        if let o = o as? ChildNumber {
            return i == o.i
        }
        return false
    }

    public var hashValue: Int {
        return i
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.i)
    }
}
