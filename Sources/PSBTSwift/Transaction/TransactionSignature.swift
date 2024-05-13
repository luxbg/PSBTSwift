//
//  TransactionSignature.swift
//
//
//  Created by 薛跃杰 on 2024/3/29.
//

import Foundation
import ASN1

public struct TransactionSignature: Hashable {
    public let type: TransactionType
    public let ecdsaSignature: ECDSASignature?
    public let schnorrSignature: SchnorrSignature?
    public let sigHashFlags: UInt8
    
    
    public init(r: [UInt8], s: [UInt8], type: TransactionType) {
        self.init(r: r, s: s, type: type, sigHahsFlags: type == TransactionType.ecdsa ? SigHash.ALL.rawValue : SigHash.DEFAULTType.rawValue)
    }

    public init(signature: ECDSASignature, sigHashFlags: UInt8) {
        self.init(r: signature.r, s: signature.s, type: TransactionType.ecdsa, sigHahsFlags: sigHashFlags)
    }

    public init(signature: SchnorrSignature, sigHashFlags: UInt8) {
        self.init(r: signature.r, s: signature.s, type: TransactionType.schnorr, sigHahsFlags: sigHashFlags)
    }

    public init(r: [UInt8], s: [UInt8], type: TransactionType, sigHahsFlags: UInt8) {
        self.ecdsaSignature = type == TransactionType.ecdsa ? ECDSASignature(r: r, s: s) : nil
        self.schnorrSignature = type == TransactionType.schnorr ? SchnorrSignature(r: r, s: s) : nil
        self.sigHashFlags = sigHahsFlags
        self.type = type
    }
    
    public func anyoneCanPay() -> Bool {
        return (sigHashFlags & SigHash.ANYONECANPAY.rawValue) != 0
    }

    private func getSigHash() -> SigHash {
        if sigHashFlags == SigHash.DEFAULTType.rawValue {
            return SigHash.DEFAULTType
        }

        let anyoneCanPay = self.anyoneCanPay()
        let mode = sigHashFlags & 0x1f
        if mode == SigHash.NONE.rawValue {
            return anyoneCanPay ? SigHash.ANYONECANPAY_NONE : SigHash.NONE
        } else if mode == SigHash.SINGLE.rawValue {
            return anyoneCanPay ? SigHash.ANYONECANPAY_SINGLE : SigHash.SINGLE
        } else {
            return anyoneCanPay ? SigHash.ANYONECANPAY_ALL : SigHash.ALL
        }
    }
    
    public func encodeToBitcoin() throws -> [UInt8] {
        if ecdsaSignature != nil {
            var data = self.ecdsaSignature!.derByteArray()
            data.append(contentsOf: [sigHashFlags])
            return data
        } else if let _schnorrSignature = schnorrSignature {
            let sigHash = getSigHash()
            var buffer = [UInt8]()
            buffer.append(contentsOf: _schnorrSignature.encode())
            if sigHash != .DEFAULTType {
                buffer.append(contentsOf: [sigHashFlags])
            }
            return buffer
        } else {
            throw PSBTError.message("TransactionSignature encodeToBitcoin error")
        }
    }
    
    public static func decodeFromBitcoin(data: [UInt8], requireCanonicalEncoding: Bool) throws -> TransactionSignature{
        if data.count == 64 || data.count == 65 {
            return try decodeFromBitcoin(type: TransactionType.ecdsa, data: data, requireCanonicalEncoding: requireCanonicalEncoding)
        }
        return try decodeFromBitcoin(type: TransactionType.schnorr, data: data, requireCanonicalEncoding: requireCanonicalEncoding)
    }
    
    public static func decodeFromBitcoin(type: TransactionType, data: [UInt8], requireCanonicalEncoding: Bool) throws -> TransactionSignature{
        if type == TransactionType.ecdsa {
            return try ECDSASignature.decodeFromBitcoin(bytes: data, requireCanonicalEncoding: requireCanonicalEncoding, requireCanonicalSValue: false)
        }
        return try SchnorrSignature.decodeFromBitcoin(bytes: data)
    }
    
    public func hash(into hasher: inout Hasher) {
        if let _ecdsa = ecdsaSignature {
            hasher.combine(_ecdsa)
        } else {
            hasher.combine(schnorrSignature!)
        }
        hasher.combine(sigHashFlags)
    }
    
    public static func == (lhs: TransactionSignature, rhs: TransactionSignature) -> Bool {
        if lhs.type == rhs.type {
            if let _lhsecdsa = lhs.ecdsaSignature {
                if let _rhsecdsa = rhs.ecdsaSignature {
                    return _lhsecdsa.s == _rhsecdsa.s && _lhsecdsa.r == _rhsecdsa.r
                }
            } else {
                if let _lhschnorr = lhs.schnorrSignature, let _rhsschnorr = rhs.schnorrSignature {
                    return _lhschnorr.s == _rhsschnorr.s && _lhschnorr.r == _rhsschnorr.r
                }
            }
        }
        return false
    }
    
    public static func sign(privateKey: Data, input: Data, sigHash: SigHash, type: SignatureType, isOldVersion: Bool) throws -> TransactionSignature {
        var transactionSignature: TransactionSignature
        if type == SignatureType.SCHNORR {
            let schnorrSignature = try SchnorrSignature.sign(data: input, privateKey: privateKey, isOldVersion: isOldVersion)
            transactionSignature = TransactionSignature(signature: schnorrSignature, sigHashFlags: sigHash.rawValue)
        } else {
            let ecdsaSignature = try ECDSASignature.sign(data: input, privateKey: privateKey)
            transactionSignature = TransactionSignature(signature: ecdsaSignature, sigHashFlags: sigHash.rawValue)
        }
        
        return transactionSignature
    }
    
    public func verify(hash: Data, pub: Data) throws -> Bool {
        if let _ecdsaSignature = ecdsaSignature {
            return try _ecdsaSignature.verify(data: hash, pub: pub)
        } else if let _schnorrSignature = schnorrSignature {
            return try _schnorrSignature.verify(data: hash, pub: pub)
        } else {
            throw PSBTError.message("TransactionSignature verify error")
        }
    }
}

public enum TransactionType: UInt8 {
    case ecdsa = 0
    case schnorr = 1
}
