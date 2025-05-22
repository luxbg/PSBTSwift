//
//  ECDSASignature.swift
//
//
//  Created by 薛跃杰 on 2024/3/29.
//

import ASN1
import Asn1BInt
@_implementationOnly import CSecp256k1
import Foundation

public struct ECDSASignature: Equatable, Hashable {
    public let r: [UInt8]
    public let s: [UInt8]

    public init(r: [UInt8], s: [UInt8]) {
        self.r = r
        self.s = s
    }

    public var isCanonical: Bool {
        return BInt(signed: s) <= BInt(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
            radix: 16
        )!
    }

    public func toCanonicalised() -> ECDSASignature {
        if !isCanonical {
            let news =
                BInt(
                    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                    radix: 16
                )! - BInt(signed: s)
            return ECDSASignature(r: r, s: news.asSignedBytes())
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
            guard seqObj.getValue().count == 2,
                let r = seqObj.getValue()[0] as? ASN1Integer,
                let s = seqObj.getValue()[1] as? ASN1Integer
            else {
                throw PSBTError.message("Reached ASN.1 stream error")
            }
            return ECDSASignature(
                r: r.value.asSignedBytes(),
                s: s.value.asSignedBytes()
            )
        } catch {
            throw PSBTError.message("Failed to decode ASN.1 data.")
        }
    }

    public static func sign(data: Data, privateKey: Data) throws
        -> ECDSASignature
    {
        precondition(data.count > 0, "Data must be non-zero size")
        precondition(privateKey.count > 0, "PrivateKey must be non-zero size")

        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>
            .allocate(capacity: 1)
        let status = data.withUnsafeBytes { ptr in
            privateKey.withUnsafeBytes {
                secp256k1_ecdsa_sign(
                    ctx,
                    signature,
                    ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    $0.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    nil,
                    nil
                )
            }
        }
        guard status == 1 else { throw PSBTError.message("EcdsaSign error") }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>
            .allocate(capacity: 1)
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length: size_t = 128
        var der = Data(count: length)
        guard
            der.withUnsafeMutableBytes({
                return secp256k1_ecdsa_signature_serialize_der(
                    ctx,
                    $0.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    &length,
                    normalizedsig
                )
            }) == 1
        else { throw PSBTError.message("EcdsaSign error") }
        der.count = length

        return try ECDSASignature.decodeFromDER(bytes: der.bytes)
    }

    public func verify(data: Data, pub: Data) throws -> Bool {
        let signature = Data(encodeToDER())
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(ctx) }

        let signaturePointer = UnsafeMutablePointer<secp256k1_ecdsa_signature>
            .allocate(capacity: 1)
        defer { signaturePointer.deallocate() }
        guard
            signature.withUnsafeBytes({
                secp256k1_ecdsa_signature_parse_der(
                    ctx,
                    signaturePointer,
                    $0,
                    signature.count
                )
            }) == 1
        else {
            throw PSBTError.message("ecdsasignature verify error")
        }

        let pubkeyPointer = UnsafeMutablePointer<secp256k1_pubkey>.allocate(
            capacity: 1
        )
        defer { pubkeyPointer.deallocate() }
        guard
            pub.withUnsafeBytes({
                secp256k1_ec_pubkey_parse(ctx, pubkeyPointer, $0, pub.count)
            }) == 1
        else {
            throw PSBTError.message("ecdsasignature verify error")
        }

        guard
            data.withUnsafeBytes({
                secp256k1_ecdsa_verify(ctx, signaturePointer, $0, pubkeyPointer)
            }) == 1
        else {
            return false
        }
        return true
    }

    public func hasLowR() -> Bool {
        // A low R signature will have less than 71 bytes when encoded to DER
        return toCanonicalised().encodeToDER().count < 71
    }

    public func derByteArray() -> [UInt8] {
        let rASN1 = ASN1Integer(BInt(signed: r))
        let sASN1 = ASN1Integer(BInt(signed: s))
        let sequence = ASN1Sequence([rASN1, sASN1])
        let encodedData = sequence.encode()
        return encodedData
    }

    public static func decodeFromBitcoin(
        bytes: [UInt8],
        requireCanonicalEncoding: Bool,
        requireCanonicalSValue: Bool
    ) throws -> TransactionSignature {
        if requireCanonicalEncoding
            && !ECDSASignature.isEncodingCanonical(signature: bytes)
        {
            throw PSBTError.message("ECDSASignature decodeFromBitcoin error")
        }

        let sig = try ECDSASignature.decodeFromDER(bytes: bytes)

        if requireCanonicalSValue && !sig.isCanonical {
            throw PSBTError.message("ECDSASignature decodeFromBitcoin error")
        }

        let lastByte = bytes[bytes.count - 1]

        return TransactionSignature(
            r: sig.r,
            s: sig.s,
            type: TransactionType.ecdsa,
            sigHahsFlags: lastByte
        )
    }

    public static func isEncodingCanonical(signature: [UInt8]) -> Bool {
        if signature.isEmpty {
            return true
        }

        if signature.count < 9 || signature.count > 73 {
            return false
        }

        let hashType = (signature.last! & 0xff) & ~SigHash.ANYONECANPAY.rawValue
        if hashType < SigHash.ALL.rawValue || hashType > SigHash.SINGLE.rawValue
        {
            return false
        }

        if (signature[0] & 0xff) != 0x30
            || (signature[1] & 0xff) != signature.count - 3
        {
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
        if lenR > 1 && signature[4] == 0x00 && (signature[4 + 1] & 0x80) != 0x80
        {
            return false
        }

        if signature[6 + Int(lenR) - 2] != 0x02
            || (signature[6 + Int(lenR)] & 0x80) == 0x80
        {
            return false
        }
        if lenS > 1 && signature[6 + Int(lenR)] == 0x00
            && (signature[6 + Int(lenR) + 1] & 0x80) != 0x80
        {
            return false
        }

        return true
    }
}
