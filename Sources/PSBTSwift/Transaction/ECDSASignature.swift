//
//  ECDSASignature.swift
//
//
//  Created by 薛跃杰 on 2024/3/29.
//

import Foundation
import BigInt
import ASN1

public struct ECDSASignature: Equatable, Hashable {
    public let r: [UInt8]
    public let s: [UInt8]
    
    public init(r: [UInt8], s: [UInt8]) {
        self.r = r
        self.s = s
    }
    
    public var isCanonical: Bool {
        return BigInt(Data(s)) <= BigInt(Data(hex: "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"))
    }
    
    public func toCanonicalised() -> ECDSASignature {
        if !isCanonical {
            let news = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)! - BigUInt(Data(s))
            return ECDSASignature(r: r, s: news.serialize().bytes)
        } else {
            return self
        }
    }
    
    public func encodeToDER() -> [UInt8] {
        return derByteArray()
    }
    
    public static func decodeFromDER(bytes: [UInt8]) throws -> ECDSASignature {
        do {
            let decoder = try ASN1.build(Data(bytes))
            guard let seqObj = decoder as? ASN1Sequence else {
                throw PSBTError.message("Reached past end of ASN.1 stream.")
            }
            guard seqObj.getValue().count == 2, let r = seqObj.getValue()[0] as? ASN1Integer, let s = seqObj.getValue()[1] as? ASN1Integer else {
                throw PSBTError.message("Reached ASN.1 stream error")
            }
            return ECDSASignature(r: r.value.serialize().bytes, s: s.value.serialize().bytes)
        } catch {
            throw PSBTError.message("Failed to decode ASN.1 data.")
        }
    }
    
    public func verify(data: Data, pub: Data) throws -> Bool {
//        do {
//            let signer = ECDSASigner(hash: .sha256)
//            
//            guard let publicKey = try? Curve25519.PublicKey(raw: pub) else {
//                throw SignatureVerificationException()
//            }
//            
//            let signature = try ECDSASignature(r: r, s: s)
//            
//            return try signer.verify(signature: signature, input: data, publicKey: publicKey)
//        } catch {
//            print("Caught exception: \(error)")
//            return false
//        }
        return false
    }
    
    public func hasLowR() -> Bool {
        // A low R signature will have less than 71 bytes when encoded to DER
        return toCanonicalised().encodeToDER().count < 71
    }
    
    public func derByteArray() -> [UInt8] {
        let rASN1 = ASN1Integer(BigInt(Data(r)))
        let sASN1 = ASN1Integer(BigInt(Data(s)))
        let sequence = ASN1Sequence([rASN1,sASN1])
        let encodedData = sequence.encode()
        return encodedData
    }
    
    public static func decodeFromBitcoin(bytes: [UInt8], requireCanonicalEncoding: Bool, requireCanonicalSValue: Bool) throws -> TransactionSignature {
        if requireCanonicalEncoding && !ECDSASignature.isEncodingCanonical(signature: bytes) {
            throw PSBTError.message("ECDSASignature decodeFromBitcoin error")
        }
        
        let sig = try ECDSASignature.decodeFromDER(bytes: bytes)
        
        if requireCanonicalSValue && !sig.isCanonical {
            throw PSBTError.message("ECDSASignature decodeFromBitcoin error")
        }
        
        let lastByte = bytes[bytes.count - 1]
        
        return TransactionSignature(r: sig.r, s: sig.s, type: TransactionType.ecdsa, sigHahsFlags: lastByte)
    }
    
    public static func isEncodingCanonical(signature: [UInt8]) -> Bool {
        if signature.isEmpty {
            return true
        }

        if signature.count < 9 || signature.count > 73 {
            return false
        }

        let hashType = (signature.last! & 0xff) & ~SigHash.ANYONECANPAY.rawValue
        if hashType < SigHash.ALL.rawValue || hashType > SigHash.SINGLE.rawValue {
            return false
        }

        if (signature[0] & 0xff) != 0x30 || (signature[1] & 0xff) != signature.count - 3 {
            return false
        }

        let lenR = signature[3] & 0xff
        if 5 + lenR >= signature.count || lenR == 0 {
            return false
        }
        let lenS = signature[5 + Int(lenR)] & 0xff
        if lenR + lenS + 7 != signature.count || lenS == 0 {
            return false
        }

        if signature[4 - 2] != 0x02 || (signature[4] & 0x80) == 0x80 {
            return false
        }
        if lenR > 1 && signature[4] == 0x00 && (signature[4 + 1] & 0x80) != 0x80 {
            return false
        }

        if signature[6 + Int(lenR) - 2] != 0x02 || (signature[6 + Int(lenR)] & 0x80) == 0x80 {
            return false
        }
        if lenS > 1 && signature[6 + Int(lenR)] == 0x00 && (signature[6 + Int(lenR) + 1] & 0x80) != 0x80 {
            return false
        }

        return true
    }
}
