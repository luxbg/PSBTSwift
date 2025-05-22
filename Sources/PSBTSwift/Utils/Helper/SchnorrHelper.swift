import BigInt
@_implementationOnly import CSecp256k1
import CryptoSwift
import Foundation
import PSBTCryptoKit

public struct InternalPublicKey {
    let raw: secp256k1_pubkey
}

public struct SchnorrHelper {
    static var magic: (UInt8, UInt8, UInt8, UInt8) { (218, 111, 179, 140) }
    static var context: OpaquePointer! = secp256k1_context_create(
        UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
    )
    // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
    public static func liftX(x: Data) throws -> Data {
        let x = BigUInt(x)
        let p = BigUInt(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            radix: 16
        )!  // secp256k1 field size

        guard x < p else {
            throw SchnorrError.liftXError
        }

        let c = (x.power(3, modulus: p) + BigUInt(7)) % p
        let y = c.power((p + BigUInt(1)) / BigUInt(4), modulus: p)

        guard c == y.power(2, modulus: p) else {
            throw SchnorrError.liftXError
        }

        let xCoordinate = x
        let yCoordinate = (y % 2 == 0) ? y : p - y

        let xBytes = xCoordinate.serialize().bytes
        let yBytes = yCoordinate.serialize().bytes
        let xCoordinateBytes =
            [UInt8](repeating: 0, count: 32 - xBytes.count) + xBytes
        let yCoordinateBytes =
            [UInt8](repeating: 0, count: 32 - yBytes.count) + yBytes
        var xCoordinateField = secp256k1_psbt_fe()
        var yCoordinateField = secp256k1_psbt_fe()

        defer {
            secp256k1_psbt_fe_clear(&xCoordinateField)
            secp256k1_psbt_fe_clear(&yCoordinateField)
        }

        guard
            xCoordinateBytes.withUnsafeBytes({ rawBytes -> Bool in
                guard
                    let rawPointer = rawBytes.bindMemory(to: UInt8.self)
                        .baseAddress
                else { return false }
                return secp256k1_psbt_fe_set_b32(&xCoordinateField, rawPointer)
                    == 1
            })
        else {
            throw SchnorrError.liftXError
        }

        guard
            yCoordinateBytes.withUnsafeBytes({ rawBytes -> Bool in
                guard
                    let rawPointer = rawBytes.bindMemory(to: UInt8.self)
                        .baseAddress
                else { return false }
                return secp256k1_psbt_fe_set_b32(&yCoordinateField, rawPointer)
                    == 1
            })
        else {
            throw SchnorrError.liftXError
        }

        secp256k1_psbt_fe_normalize_var(&xCoordinateField)
        secp256k1_psbt_fe_normalize_var(&yCoordinateField)

        var keyBytes = [UInt8](repeating: 0, count: 64)

        secp256k1_psbt_fe_get_b32(&keyBytes[0], &xCoordinateField)
        secp256k1_psbt_fe_get_b32(&keyBytes[32], &yCoordinateField)

        return Data([0x04]) + Data(keyBytes)
    }

    public static func hashTweak(data: Data, tag: String) throws -> Data {
        let tagBytes = tag.data(using: .utf8)!.bytes

        return Data(try SchnorrHelper.taggedHash(tag: tagBytes, data: data))
    }

    // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#address-derivation
    public static func tweakedOutputKey(
        publicKey: Data,
        compressed: Bool = true
    ) throws -> Data {
        // internal_key = lift_x(derived_key)
        // hashTapTweak(bytes(P))
        let internalKeyBytes = try liftX(x: publicKey[1..<33]).bytes
        let tweakedHash = try hashTweak(
            data: Data(internalKeyBytes[1..<33]),
            tag: "TapTweak"
        )

        // int(hashTapTweak(bytes(P)))G
        var tweakedPublicKey = secp256k1_pubkey()
        guard
            secp256k1_ec_seckey_verify(SchnorrHelper.context, tweakedHash.bytes)
                == 1,
            secp256k1_ec_pubkey_create(
                SchnorrHelper.context,
                &tweakedPublicKey,
                tweakedHash.bytes
            ) == 1
        else {
            throw SchnorrError.keyTweakError
        }

        // P + int(hashTapTweak(bytes(P)))G
        var internalKey = secp256k1_pubkey()
        guard
            internalKeyBytes.withUnsafeBytes({ rawBytes -> Int32 in
                guard
                    let rawPointer = rawBytes.bindMemory(to: UInt8.self)
                        .baseAddress
                else { return 0 }
                return secp256k1_ec_pubkey_parse(
                    SchnorrHelper.context,
                    &internalKey,
                    rawPointer,
                    internalKeyBytes.count
                )
            }) == 1
        else {
            throw SchnorrError.keyTweakError
        }

        var outputKey = try SchnorrHelper.addEllipticCurvePoints(
            a: InternalPublicKey(raw: internalKey),
            b: InternalPublicKey(raw: tweakedPublicKey)
        ).raw
        var pubKeyLen = 33
        var outputKeyBytes = [UInt8](repeating: 0, count: pubKeyLen)

        guard
            secp256k1_ec_pubkey_serialize(
                SchnorrHelper.context,
                &outputKeyBytes,
                &pubKeyLen,
                &outputKey,
                UInt32(
                    compressed
                        ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED
                )
            ) == 1
        else {
            throw SchnorrError.keyTweakError
        }

        return Data(outputKeyBytes[1..<33])
    }

    public static func tweakedPrivateKey(privateKey: Data, publicKey: Data)
        throws -> Data
    {
        // internal_key = lift_x(derived_key)
        // hashTapTweak(bytes(P))
        let internalKeyBytes = try liftX(x: publicKey[1..<33]).bytes
        let tweakedHash = try hashTweak(
            data: Data(internalKeyBytes[1..<33]),
            tag: "TapTweak"
        )

        // int(hashTapTweak(bytes(P)))G
        var tweakedPublicKey = secp256k1_pubkey()
        guard
            secp256k1_ec_seckey_verify(SchnorrHelper.context, tweakedHash.bytes)
                == 1,
            secp256k1_ec_pubkey_create(
                SchnorrHelper.context,
                &tweakedPublicKey,
                tweakedHash.bytes
            ) == 1
        else {
            throw SchnorrError.privateKeyTweakError
        }

        // P + int(hashTapTweak(bytes(P)))G
        var internalKey = secp256k1_pubkey()
        guard
            internalKeyBytes.withUnsafeBytes({ rawBytes -> Int32 in
                guard
                    let rawPointer = rawBytes.bindMemory(to: UInt8.self)
                        .baseAddress
                else { return 0 }
                return secp256k1_ec_pubkey_parse(
                    SchnorrHelper.context,
                    &internalKey,
                    rawPointer,
                    internalKeyBytes.count
                )
            }) == 1
        else {
            throw SchnorrError.privateKeyTweakError
        }

        let outputKey = try self.addEllipticCurvePoints(
            a: InternalPublicKey(raw: internalKey),
            b: InternalPublicKey(raw: tweakedPublicKey)
        )
        var privateBytes = privateKey.bytes
        guard
            secp256k1_ec_seckey_tweak_add(
                SchnorrHelper.context,
                &privateBytes,
                tweakedHash.bytes
            ) == 1,
            secp256k1_ec_seckey_verify(SchnorrHelper.context, privateBytes) == 1
        else {
            throw SchnorrError.privateKeyTweakError
        }

        var _outputKey = secp256k1_pubkey()
        guard
            secp256k1_ec_pubkey_create(
                SchnorrHelper.context,
                &_outputKey,
                privateBytes
            ) == 1
        else {
            throw SchnorrError.privateKeyTweakError
        }

        let keysEqual = withUnsafePointer(to: outputKey.raw) { outputKeyPointer in
            withUnsafePointer(to: _outputKey) { _outputKeyPointer in
                secp256k1_ec_pubkey_cmp(
                    SchnorrHelper.context,
                    outputKeyPointer,
                    _outputKeyPointer
                )
            }
        }

        if keysEqual != 0 {
            privateBytes = privateKey.bytes
            guard
                secp256k1_ec_seckey_negate(SchnorrHelper.context, &privateBytes)
                    == 1
            else {
                throw SchnorrError.privateKeyTweakError
            }

            guard
                secp256k1_ec_seckey_tweak_add(
                    SchnorrHelper.context,
                    &privateBytes,
                    tweakedHash.bytes
                ) == 1,
                secp256k1_ec_seckey_verify(SchnorrHelper.context, privateBytes)
                    == 1
            else {
                throw SchnorrError.privateKeyTweakError
            }
        }

        return Data(privateBytes)
    }

    public static func sign(data: Data, privateKey: Data, isOldVersion: Bool)
        throws -> Data
    {
        var message = data.bytes
        var keypair = secp256k1_keypair()
        guard
            secp256k1_keypair_create(
                SchnorrHelper.context,
                &keypair,
                privateKey.bytes
            ) == 1
        else {
            throw SchnorrError.signError
        }
        var signature = [UInt8](repeating: 0, count: 64)
        if isOldVersion {
            guard
                secp256k1_schnorrsig_sign32(
                    SchnorrHelper.context,
                    &signature,
                    &message,
                    &keypair,
                    nil
                ) == 1
            else {
                throw SchnorrError.signError
            }
        } else {
            let auxRandPointer = UnsafeMutableRawPointer.allocate(
                byteCount: 32,
                alignment: MemoryLayout<UInt8>.alignment
            )
            for i in 0..<32 {
                auxRandPointer.storeBytes(
                    of: 0x00,
                    toByteOffset: i,
                    as: UInt8.self
                )
            }
            var extraParams = secp256k1_schnorrsig_extraparams(
                magic: magic,
                noncefp: nil,
                ndata: auxRandPointer
            )
            guard
                secp256k1_schnorrsig_sign_custom(
                    SchnorrHelper.context,
                    &signature,
                    &message,
                    message.count,
                    &keypair,
                    &extraParams
                ) == 1
            else {
                throw SchnorrError.signError
            }
        }

        return Data(signature)
    }

    struct InternalPublicKey {
        let raw: secp256k1_pubkey
    }

    static func addEllipticCurvePoints(
        a: InternalPublicKey,
        b: InternalPublicKey
    ) throws -> InternalPublicKey {
        var storage = ContiguousArray<secp256k1_pubkey>()
        let pointers = UnsafeMutablePointer<UnsafePointer<secp256k1_pubkey>?>
            .allocate(capacity: 2)
        defer {
            pointers.deinitialize(count: 2)
            pointers.deallocate()
        }
        storage.append(a.raw)
        storage.append(b.raw)

        for i in 0..<2 {
            withUnsafePointer(to: &storage[i]) { ptr in
                pointers.advanced(by: i).pointee = ptr
            }
        }

        let immutablePointer = UnsafePointer(pointers)
        var combinedKey = secp256k1_pubkey()
        let result = withUnsafeMutablePointer(to: &combinedKey) {
            combinedKeyPtr in
            secp256k1_ec_pubkey_combine(
                SchnorrHelper.context,
                combinedKeyPtr,
                immutablePointer,
                2
            )
        }

        if result == 0 {
            throw SchnorrError.keyTweakError
        }

        return InternalPublicKey(raw: combinedKey)
    }

    public static func taggedHash<D: DataProtocol>(tag: [UInt8], data: D) throws
        -> [UInt8]
    {
        let messageBytes = Array(data)
        var output = [UInt8](repeating: 0, count: 32)
        guard
            secp256k1_tagged_sha256(
                SchnorrHelper.context,
                &output,
                tag,
                tag.count,
                messageBytes,
                messageBytes.count
            ) != 0
        else {
            throw SchnorrError.liftXError
        }
        return output
    }

    public enum SchnorrError: Error {
        case liftXError
        case privateKeyTweakError
        case keyTweakError
        case signError
    }

}
