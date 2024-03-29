//
//  HDKeyDerivation.swift
//
//
//  Created by 薛跃杰 on 2024/3/14.
//

import Foundation
import BIP32Swift
import BigInt

public class HDKeyDerivation {
    public static var curveOrder = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
    public static let BITCOIN_SEED_KEY = "Bitcoin seed"
    
    public static func createMasterPrivateKey(seed: Data) throws -> DeterministicKey {
        guard let hdnode = HDNode(seed: seed), let privateKey = hdnode.privateKey else {
            throw PSBTError.message("seed error")
        }
        let masterPrivKey = try createMasterPrivKeyFromBytes(privKeyBytes: privateKey.bytes, chainCode: hdnode.chaincode.bytes)
        return masterPrivKey
    }
    
    public static func createMasterPrivKeyFromBytes(privKeyBytes: [UInt8], chainCode: [UInt8]) throws -> DeterministicKey {
        // childNumberPath is an empty list because we are creating the root key.
        return try createMasterPrivKeyFromBytes(privKeyBytes: privKeyBytes, chainCode: chainCode, childNumberPath: [])
    }
    
    public static func createMasterPrivKeyFromBytes(privKeyBytes: [UInt8], chainCode: [UInt8], childNumberPath: [ChildNumber]) throws -> DeterministicKey {
//        let priv = BigInt(bytes: privKeyBytes)
//        if priv == BigInt(0) || priv > ECKey.CURVE.getN() {
//            throw HDDerivationException("Private key bytes are not valid")
//        }

        return DeterministicKey(parent: nil, priv: Data(privKeyBytes), childNumberPath: childNumberPath, chainCode: chainCode)
    }
    
    public static func createMasterPubKeyFromBytes(pubKeyBytes: [UInt8], chainCode: [UInt8]) -> DeterministicKey {
        return  DeterministicKey(parent: nil, publicKey: Data(pubKeyBytes), priv: nil, childNumberPath: [ChildNumber](), chainCode: chainCode)
        
//        DeterministicKey(childNumberPath: [], chainCode: chainCode, pub: LazyECPoint(curve: ECKey.CURVE.getCurve(), pubKeyBytes: pubKeyBytes), priv: nil)
    }
    
    public static func deriveChildKey(parent: DeterministicKey, childNumber: ChildNumber) throws -> DeterministicKey {
        if parent.isPublicKeyOnly() {
            let rawKey = try deriveChildKeyBytesFromPublic(parent: parent, childNumber: childNumber)
            return DeterministicKey(parent: parent, publicKey: Data(rawKey.keyBytes), priv: nil, childNumberPath: Utils.appendChild(path: parent.childNumberPath, childNumber: childNumber), chainCode: rawKey.chainCode)
        } else {
            let rawKey = try deriveChildKeyBytesFromPrivate(parent: parent, childNumber: childNumber)
            let priv = BigInt(sign: BigInt.Sign.plus, magnitude: BigUInt(Data(rawKey.keyBytes))).serialize()
            
            return  DeterministicKey(parent: parent, publicKey: Data(rawKey.keyBytes), priv: priv, childNumberPath: Utils.appendChild(path: parent.childNumberPath, childNumber: childNumber), chainCode: rawKey.chainCode)
        }
    }
    
    public static func deriveChildKeyBytesFromPrivate(parent: DeterministicKey, childNumber: ChildNumber) throws -> RawKeyBytes {
        if parent.isPublicKeyOnly() {
            throw PSBTError.message("Parent key must have private key bytes for this method")
        }

        let parentPublicKey = parent.getPublickey()
        if parentPublicKey.count != 33 {
            throw PSBTError.message("Parent pubkey must be 33 bytes, but is \(parentPublicKey.count)")
        }

        var data = Data(capacity: 37)
        if childNumber.isHardened() {
            data.append(parent.getPrivKeyBytes33()!)
        } else {
            data.append(parentPublicKey)
        }
        let childNumberi = [UInt8(childNumber.i)]
        data.append(Data(childNumberi))
        guard let i = Utils.getHmacSha512Hash(key: parent.chainCode, data: data.bytes) else {
            throw PSBTError.message("HmacSHA512 error")
        }
        if i.count != 64 {
            throw PSBTError.message("HmacSHA512 output must be 64 bytes, is \(i.count)")
        }

        let il = i[0..<32]
        let chainCode = i[32..<64]
        let ilInt = BigUInt(Data(il))
        if BigUInt(ilInt) > HDKeyDerivation.curveOrder {
            throw PSBTError.message("Illegal derived key: I_L >= n")
        }

        guard let priv = parent.node?.privateKey else {
            throw PSBTError.message("privateKey error")
        }
        let ki = ilInt +  BigUInt(priv) % HDKeyDerivation.curveOrder
        if ki == BigInt(0) {
            throw PSBTError.message("Illegal derived key: derived private key equals 0")
        }
        
        return RawKeyBytes(keyBytes: ki.serialize().bytes, chainCode: Data(chainCode).bytes)
    }
    
    public static func deriveChildKeyBytesFromPublic(parent: DeterministicKey, childNumber: ChildNumber) throws -> RawKeyBytes {
        if childNumber.isHardened() {
            throw PSBTError.message("Can't use private derivation with public keys only")
        }

        let node = HDNode(seed: Data(hex: "d0479e10e22dd60cf4f8aaf405b009343ddb56238a20ec50cb237f4950443e8e0c18ab36379e89324721c46fcd0219160783cbd52fbc8d7937967209de9f645b"))!
        node.publicKey = parent.getPublickey()
        node.chaincode = Data(parent.chainCode)
        node.depth = UInt8(parent.depth)
        
        guard let newNode = node.derive(index: UInt32(childNumber.i), derivePrivateKey: false, hardened: childNumber.isHardened()) else {
            throw PSBTError.message("Failed to derive child public key")
        }
        return RawKeyBytes(keyBytes: newNode.publicKey.bytes, chainCode: newNode.chaincode.bytes)
        
        
//        if childNumber.isHardened() {
//            throw PSBTError.message("Can't use private derivation with public keys only")
//        }
//
//        let parentPublicKey = parent.getPublickey()
//        if parentPublicKey.count != 33 {
//            throw PSBTError.message("Parent pubkey must be 33 bytes, but is \(parentPublicKey.count)")
//        }
//
//        var data = Data(capacity: 37)
//        data.append(parentPublicKey)
//        let arrayData = Data([UInt8(childNumber.i)])
//        data.append(arrayData)
//        guard let i = Utils.getHmacSha512Hash(key: parent.chainCode, data: data.bytes) else {
//            throw PSBTError.message("HmacSHA512 error")
//        }
//        if i.count != 64 {
//            throw PSBTError.message("HmacSHA512 output must be 64 bytes, is \(i.count)")
//        }
//
//        let il = i[0..<32]
//        let chainCode = i[32..<64]
//        let ilInt = BigInt(sign: BigInt.Sign.plus, magnitude: BigUInt(Data(il)))
//        if BigUInt(ilInt) > HDKeyDerivation.curveOrder {
//            throw PSBTError.message("Illegal derived key: I_L >= n")
//        }
//
//        let N = HDKeyDerivation.curveOrder
//        let Ki = ECKey.publicPointFromPrivate(ilInt).add(parent.getPubKeyPoint())
//        if Ki == ECKey.CURVE.getCurve().getInfinity() {
//            throw PSBTError.message("Illegal derived key: derived public key equals infinity")
//        }
//
//        return RawKeyBytes(keyBytes: Ki.getEncoded(true), chainCode: Data(chainCode).bytes)
    }
    
    public struct RawKeyBytes {
        public let keyBytes: [UInt8]
        public let chainCode: [UInt8]

        public init(keyBytes: [UInt8], chainCode: [UInt8]) {
            self.keyBytes = keyBytes
            self.chainCode = chainCode
        }
    }
}
