//
//  PSBTEntry.swift
//
//
//  Created by 薛跃杰 on 2024/1/8.
//

import Foundation
import NIOCore

public struct PSBTEntry {
    public var key: [UInt8]?
    public var keyType: UInt8
    public var keyData: [UInt8]?
    public var data: [UInt8]?
    
    public init(key: [UInt8]?, keyType: UInt8, keyData: [UInt8]?, data: [UInt8]?) {
        self.key = key
        self.keyType = keyType
        self.keyData = keyData
        self.data = data
    }
    
    public init(psbtData: Data) throws {
        let keyLen = try PSBTEntry.readCompactInt(psbtData: psbtData)
        
        if keyLen == 0x00 {
            key = nil
            keyType = 0x00
            keyData = nil
            data = nil
        } else {
            var key = [UInt8](repeating: 0, count: keyLen)
            psbtData.copyBytes(to: &key, count: keyLen)
            
            let keyType = key[0]
            
            var keyData: [UInt8]?
            if key.count > 1 {
                keyData = Array(key[1...])
            }
            
            let dataLen = try PSBTEntry.readCompactInt(psbtData: psbtData)
            var data = [UInt8](repeating: 0, count: dataLen)
            psbtData.copyBytes(to: &data, count: dataLen)
            
            self.key = key
            self.keyType = keyType
            self.keyData = keyData
            self.data = data
        }
    }
    
    public init(psbtByteBuffer: inout ByteBuffer) throws {
        let keyLen = try PSBTEntry.readCompactInt(psbtByteBuffer: &psbtByteBuffer)
        
        if keyLen == 0x00 {
            key = nil
            keyType = 0x00
            keyData = nil
            data = nil
        } else {
            guard let key = psbtByteBuffer.readBytes(length: keyLen), let keyType = key.first else {
                throw PSBTError.message("psbtByteBuffer too short")
            }
            
            var keyData: [UInt8]?
            if key.count > 1 {
                keyData = Array(key[1...])
            }
            
            let dataLen = try PSBTEntry.readCompactInt(psbtByteBuffer: &psbtByteBuffer)
            guard let data = psbtByteBuffer.readBytes(length: dataLen) else {
                throw PSBTError.message("dataLen error")
            }
            
            self.key = key
            self.keyType = keyType
            self.keyData = keyData
            self.data = data
        }
    }
    
    public static func parseTaprootKeyDerivation(data: Data) throws -> [KeyDerivation: [Data]] {
        if data.count < 1 {
            throw PSBTError.message("Invalid taproot key derivation: no bytes")
        }
        let varInt = VarInt(buf: data.bytes, offset: 0)
        var offset = varInt.originallyEncodedSize
        
        if data.count < offset + (Int(varInt.value) * 32) {
            throw PSBTError.message("Invalid taproot key derivation: not enough bytes for leaf hashes")
        }
        var leafHashes = [Data]()
        for i in 0..<varInt.value {
            let offlength = offset + (Int(i) * 32)
            let range = offlength..<(offlength + 32)
            let hashData = data.subdata(in: range)
            leafHashes.append(hashData)
        }
        
        let keyDerivationData = data.subdata(in: offset + (leafHashes.count * 32)..<data.count)
        let keyDerivation = try parseKeyDerivation(data: keyDerivationData)
        return [keyDerivation: leafHashes]
    }
    
    public static func parseKeyDerivation(data: Data) throws -> KeyDerivation {
        if data.count < 4 {
            throw PSBTError.message("Invalid master fingerprint specified: not enough bytes")
        }
        let masterFingerprintData = data.subdata(in: 0..<4)
        let masterFingerprint = PSBTEntry.getMasterFingerprint(data: masterFingerprintData)
        if masterFingerprint.count != 8 {
            throw PSBTError.message("Invalid master fingerprint specified: \(masterFingerprint)")
        }
        if data.count < 8 {
            return try KeyDerivation(masterFingerprint: masterFingerprint, derivationPath: "m")
        }
        let bip32pathData = data[4..<data.count]
        let bip32pathList = readBIP32Derivation(data: bip32pathData)
        let bip32path = KeyDerivation.writePath(pathList: bip32pathList)
        return try KeyDerivation(masterFingerprint: masterFingerprint, derivationPath: bip32path)
    }
    
    public static func getMasterFingerprint(data: Data) -> String {
        return data.toHexString()
    }
    
    public static func readBIP32Derivation(data: Data) -> [ChildNumber] {
        var path = [ChildNumber]()
        var bb = ByteBuffer(bytes: data.bytes)
        
        while bb.readableBytes > 0 {
            var buf = bb.readBytes(length: 4)!
            Utils.reverse(&buf)
            var pbuf = ByteBuffer(bytes: buf)
            let number = pbuf.readInteger(as: Int32.self)!
            path.append(ChildNumber(i: Int(number)))
        }
        return path
    }
    
    public static func serializeTaprootKeyDerivation(leafHashes: [Data], keyDerivation: KeyDerivation) throws -> Data {
        var data = Data()

        let hashesLen = VarInt(value: Int64(leafHashes.count))
        data.append(Data(hashesLen.encode()))
        for leafHash in leafHashes {
            data.append(leafHash)
        }
        let derivationData = try serializeKeyDerivation(keyDerivation: keyDerivation)
        data.append(derivationData)
        return data
    }

    public static func serializeKeyDerivation(keyDerivation: KeyDerivation) throws -> Data {
        var data = Data()
        guard let keyDerivationHex =  keyDerivation.getMasterFingerprint() else {
            throw PSBTError.message("Invalid master fingerprint")
        }
        let fingerprintBytes = Data(hex: keyDerivationHex)
        if fingerprintBytes.count != 4 {
            throw PSBTError.message("Invalid number of fingerprint bytes: \(fingerprintBytes.count)")
        }
        data.append(fingerprintBytes)
        
        guard let derivationArray =  try? keyDerivation.getDerivation() else {
            throw PSBTError.message("Invalid derivation")
        }
        
        for childNumber in derivationArray {
            var indexBytes = [UInt8](repeating: 0, count: 4)
            Utils.uint32ToByteArrayLE(val: UInt32(childNumber.i), out: &indexBytes, offset: 0)
            data.append(Data(indexBytes))
        }
        return data
    }
    
    public static func populateEntry(type: UInt8, keyData: [UInt8]?, data: [UInt8]?) -> PSBTEntry {
        return PSBTEntry(key: nil, keyType: type, keyData: keyData, data: data)
    }

    public func serializeToStream() -> Data {
        var data = Data()
        var keyLen = 1
        if let keyData = self.keyData {
            keyLen += keyData.count
        }

        data.append(PSBTEntry.writeCompactInt(UInt64(keyLen)))
        data.append(Data([self.keyType]))
        if let keyData = self.keyData {
            data.append(Data(keyData))
        }
        if let _data = self.data {
            data.append(Data(_data))
            data.append(PSBTEntry.writeCompactInt(UInt64(_data.count)))
        }
        return data
    }
    
    public static func readCompactInt(psbtData: Data) throws -> Int {
        var varpsbtData = psbtData
        guard !varpsbtData.isEmpty else {
            throw PSBTError.message("Data is empty")
        }

        let b = varpsbtData.removeFirst()

        switch b {
        case 0xfd:
            guard varpsbtData.count >= 2 else {
                throw PSBTError.message("Data too short")
            }
            let value = varpsbtData.withUnsafeBytes { $0.load(as: UInt16.self) }
            varpsbtData.removeFirst(2)
            return Int(value.littleEndian)
        case 0xfe:
            guard varpsbtData.count >= 4 else {
                throw PSBTError.message("Data too short")
            }
            let value = varpsbtData.withUnsafeBytes { $0.load(as: UInt32.self) }
            varpsbtData.removeFirst(4)
            return Int(value.littleEndian)
        case 0xff:
            guard varpsbtData.count >= 8 else {
                throw PSBTError.message("Data too short")
            }
            let value = varpsbtData.withUnsafeBytes { $0.load(as: UInt64.self) }
            varpsbtData.removeFirst(8)
            throw PSBTError.message("Data too long: \(value.littleEndian)")
        default:
            return Int(b)
        }
    }
    
    public static func readCompactInt(psbtByteBuffer: inout ByteBuffer) throws -> Int {
        guard let b = psbtByteBuffer.readBytes(length: 1)?.first else {
            throw PSBTError.message("psbtByteBuffer error")
        }

        switch b {
        case 0xfd:
            guard let buf = psbtByteBuffer.readBytes(length: 2) else {
                throw PSBTError.message("psbtByteBuffer too short")
            }
            
            let value = buf.withUnsafeBytes { $0.load(as: UInt16.self) }
            return Int(value.littleEndian)
        case 0xfe:
            guard let buf = psbtByteBuffer.readBytes(length: 4) else {
                throw PSBTError.message("psbtByteBuffer too short")
            }
            
            let value = buf.withUnsafeBytes { $0.load(as: UInt16.self) }
            return Int(value.littleEndian)
        case 0xff:
            guard let buf = psbtByteBuffer.readBytes(length: 8) else {
                throw PSBTError.message("psbtByteBuffer too short")
            }
            
            let value = buf.withUnsafeBytes { $0.load(as: UInt16.self) }
            return Int(value.littleEndian)
        default:
            return Int(b)
        }
    }

    public static func writeCompactInt(_ val: UInt64) -> Data {
        var data = Data()

        if val < 0xfd {
            data.append(UInt8(val))
        } else if val < 0xffff {
            data.append(0xfd)
            data.append(contentsOf: withUnsafeBytes(of: UInt16(val).littleEndian) { Data($0) })
        } else if val < 0xffffffff {
            data.append(0xfe)
            data.append(contentsOf: withUnsafeBytes(of: UInt32(val).littleEndian) { Data($0) })
        } else {
            data.append(0xff)
            data.append(contentsOf: withUnsafeBytes(of: val.littleEndian) { Data($0) })
        }
        return data
    }
    
    public func checkOneByteKey() throws {
        guard let _key = self.key, _key.count == 1 else {
            throw PSBTError.message("PSBT key type must be one byte")
        }
    }

    public func checkOneBytePlusXpubKey() throws {
        guard let _key = self.key, _key.count == 79 else {
            throw PSBTError.message("PSBT key type must be one byte plus xpub")
        }
    }

    public func checkOneBytePlusPubKey() throws {
        guard let _key = self.key, _key.count == 34 else {
            throw PSBTError.message("PSBT key type must be one byte plus pub key")
        }
    }

    public func checkOneBytePlusXOnlyPubKey() throws {
        guard let _key = self.key, _key.count == 33 else {
            throw PSBTError.message("PSBT key type must be one byte plus x only pub key")
        }
    }
}
