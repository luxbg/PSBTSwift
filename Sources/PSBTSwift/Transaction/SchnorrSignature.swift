//
//  SchnorrSignature.swift
//
//
//  Created by 薛跃杰 on 2024/3/29.
//

import Foundation
import CSecp256k1

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
    
    public static func decodeFromBitcoin(bytes: [UInt8]) throws -> TransactionSignature {
        guard bytes.count >= 64 && bytes.count <= 65 else {
            throw PSBTError.message("SchnorrSignature decodeFromBitcoin error")
        }

        let rData = Array(bytes[..<32])
        let sData = Array(bytes[32...])

        if bytes.count == 65 {
            return TransactionSignature(r: rData, s: sData, type: TransactionType.schnorr, sigHahsFlags: bytes[64])
        }

        return TransactionSignature(r: rData, s: sData, type: TransactionType.schnorr, sigHahsFlags: 0)
    }
    
    public static func sign(data: Data, privateKey: Data, isOldVersion: Bool) throws -> SchnorrSignature {
        let signature = try SchnorrHelper.sign(data: data, privateKey: privateKey, isOldVersion: isOldVersion)
        return try SchnorrSignature.decode(bytes: signature.bytes)
    }

    public func verify(data: Data, pub: Data) throws -> Bool {
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        var sig = encode()
        var message = data.bytes
        var pubkey = secp256k1_xonly_pubkey()

        if (pub.withUnsafeBytes { (pointer: UnsafeRawBufferPointer) -> Int32 in
            let uint8Pointer = pointer.bindMemory(to: UInt8.self).baseAddress
            return secp256k1_xonly_pubkey_parse(ctx, &pubkey, uint8Pointer!)
        }) != 1 {
            return false
        }
        
        if secp256k1_schnorrsig_verify(ctx, &sig, &message, data.count, &pubkey) == 1 {
            return true
        }
       return false
    }
    
    
}
