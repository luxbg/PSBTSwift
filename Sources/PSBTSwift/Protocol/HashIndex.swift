//
//  HashIndex.swift
//
//
//  Created by 薛跃杰 on 2024/2/28.
//

import Foundation

public class HashIndex: Hashable {
    private let hash: Data
    private let index: Int64

    public init(hash: Data, index: Int64) {
        self.hash = hash
        self.index = index
    }

    public func toString() -> String {
        return "\(hash.toHexString()):\(index)"
    }

    public static func == (lhs: HashIndex, rhs: HashIndex) -> Bool {
        return lhs.hash == rhs.hash && lhs.index == rhs.index
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(hash)
        hasher.combine(index)
    }
}
