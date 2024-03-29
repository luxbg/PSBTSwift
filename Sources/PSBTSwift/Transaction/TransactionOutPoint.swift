//
//  TransactionOutPoint.swift
//
//
//  Created by 薛跃杰 on 2024/1/18.
//

import Foundation

public class TransactionOutPoint: ChildMessage, Hashable {
    static let MESSAGE_LENGTH = 36

    public var hashData: Data
    public var index: UInt64
    public var addresses: [Address] = []

    public init(hash: Data, index: UInt64) {
        self.hashData = hash
        self.index = index
        super.init()
        self.length = TransactionOutPoint.MESSAGE_LENGTH
    }

    public init(rawtx: [UInt8], offset: Int, parent: Message) throws {
        self.hashData = Data()
        self.index = 0
        super.init(rawtx: rawtx, offset: offset)
        self.setParent(parent: parent)
    }

    public override func parse() throws {
        length = TransactionOutPoint.MESSAGE_LENGTH
        hashData = try readHash()
        let i = readUint32()
        index = UInt64(i)
    }
    public func getAddresses() -> [Address] {
        return addresses
    }

    public func setAddresses(addresses: [Address]) {
        self.addresses = addresses
    }

    public func bitcoinSerialize() throws -> [UInt8] {
        var data = Data()
        try bitcoinSerializeToData(data: &data)
        return data.bytes
    }

    public override func bitcoinSerializeToData(data: inout Data) throws {
        data.append(Data(hashData.reversed()))
        try Utils.uint32ToDataLE(val: Int(index), outData: &data)
    }

    public func equals(o: Any?) -> Bool {
        guard let other = o as? TransactionOutPoint else {
            return false
        }
        return index == other.index && hashData == other.hashData
    }

    public func hashCode() -> Int {
        var hasher = Hasher()
        hasher.combine(index)
        hasher.combine(hashData)
        return hasher.finalize()
    }
    
    public static func == (lhs: TransactionOutPoint, rhs: TransactionOutPoint) -> Bool {
        return lhs.hashData == rhs.hashData && lhs.index == rhs.index
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(hashData)
        hasher.combine(index)
    }
}
