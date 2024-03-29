//
//  SchnorrSignature.swift
//
//
//  Created by 薛跃杰 on 2024/3/29.
//

import Foundation

public struct SchnorrSignature:Equatable, Hashable {
    public let r: [UInt8]
    public let s: [UInt8]
    
    public init(r: [UInt8], s: [UInt8]) {
        self.r = r
        self.s = s
    }
    
    public func encode() -> [UInt8] {
        var bytes = [UInt8]()
        bytes.append(contentsOf: r)
        bytes.append(contentsOf: s)
        return bytes
    }

    public static func decode(bytes: [UInt8]) throws -> SchnorrSignature {
        guard bytes.count == 64 else {
            throw PSBTError.message("SchnorrSignature decode error")
        }
        let rData = Array(bytes[..<32])
        let sData = Array(bytes[32...])
        return SchnorrSignature(r: rData, s: sData)
    }
    
    public func decodeFromBitcoin(bytes: Data) throws -> TransactionSignature {
        guard bytes.count >= 64 && bytes.count <= 65 else {
            throw PSBTError.message("SchnorrSignature decodeFromBitcoin error")
        }

        let rData = Array(bytes[..<32])
        let sData = Array(bytes[32...])

        if bytes.count == 65 {
            return TransactionSignature(r: r, s: s, type: TransactionType.schnorr, sigHahsFlags: bytes[64])
        }

        return TransactionSignature(r: r, s: s, type: TransactionType.schnorr, sigHahsFlags: 0)
    }

    public func verify(data: Data, pub: Data) throws -> Bool {
       return true
    }
    
    
}
